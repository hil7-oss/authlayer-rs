# AuthLayer deployment

Two supported layouts on Ubuntu 24.04:

1. **Docker Compose** (recommended): AuthLayer + Caddy, both containers.
2. **Plain systemd**: AuthLayer as a hardened service, Caddy on the host.

Both assume a single node. SQLite and the in-memory rate limiter/challenge
store mean AuthLayer must run as one process, not a horizontally scaled fleet.

> **Production defaults are fail-closed.** Compose defaults to
> `EMAIL_PROVIDER=smtp`, and AuthLayer refuses to start until SMTP and a valid
> `OTP_SECRET` are configured. `EMAIL_PROVIDER=outbox` is local-development
> only: it sends no email and is rejected when `DEV_MODE=false` unless the
> unsafe `ALLOW_OUTBOX_WITHOUT_DEV=true` escape hatch is set. Do **not** enable
> `DEV_MODE` on the public internet: it publishes OTP codes at `/dev/outbox`.
>
> Production also requires `APP_URL=https://...`, `COOKIE_SECURE=true`, a
> `COOKIE_NAME` starting with `__Host-` (default `__Host-al_session`), and
> `RP_ID` exactly equal to the `APP_URL` host unless `ALLOW_RP_ID_PARENT=true`.

## Files

| File | Purpose |
| --- | --- |
| `Dockerfile` | Multi-stage build; non-root UID/GID 10001; `/data` volume |
| `docker-compose.yml` | AuthLayer + Caddy + named volumes |
| `.env.example` | Complete environment contract (copy to `.env`) |
| `deploy/Caddyfile` | TLS, reverse proxy, security headers |
| `deploy/authlayer.service` | Hardened systemd unit |
| `deploy/README.md` | This guide |

---

## Docker Compose quickstart

### 1. Prerequisites

- Ubuntu 24.04 with Docker Engine and the Compose v2 plugin.
- A public DNS **A** (and optionally **AAAA**) record pointing at the server.
- Inbound TCP 80 and TCP/UDP 443 reachable. Caddy uses them for ACME
  certificate issuance and HTTPS/HTTP3.
- No other process using ports 80/443.

Firewall example (UFW):

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 443/udp
sudo ufw enable
```

Do **not** open 8080. Only Caddy publishes ports; AuthLayer is reachable only
on the Compose network.

Compose attaches AuthLayer and Caddy to a dedicated bridge network,
`172.28.0.0/16`. AuthLayer trusts forwarding headers only from that CIDR, and
Caddy overwrites them with the direct client address. Keep
`TRUSTED_PROXY_CIDRS` equal to the network subnet, and do not attach other
containers to this network. If you change the subnet (for example to avoid a VPN
or Docker network overlap), change both the Compose `ipam` subnet and
`TRUSTED_PROXY_CIDRS`.

### 2. Configure

From the repository root (`authlayer/`):

```bash
cp .env.example .env
chmod 600 .env

# Generate OTP_SECRET (required), and optionally ADMIN_TOKEN.
openssl rand -hex 32
```

Edit `.env` and set at minimum:

```dotenv
APP_URL=https://auth.example.com
RP_ID=auth.example.com
ALLOW_RP_ID_PARENT=false
OTP_SECRET=<32+ character random value, e.g. 64 hex chars>
ADMIN_TOKEN=<32+ character random value, or empty to disable /admin>
COOKIE_NAME=__Host-al_session
COOKIE_SECURE=true
SESSION_IDLE_HOURS=24
RECOVERY_CODE_TTL_DAYS=365
DEV_MODE=false
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp.example.com
SMTP_FROM="AuthLayer <no-reply@example.com>"
SMTP_TLS=required
TRUST_PROXY=true
TRUSTED_PROXY_CIDRS=172.28.0.0/16
```

- `APP_URL` is the exact public origin, including `https://`, with no trailing
  slash. Production requires HTTPS and `COOKIE_SECURE=true`.
- `RP_ID` is the hostname only: no scheme, port, or path. In production it must
  equal the `APP_URL` host. Leave `ALLOW_RP_ID_PARENT=false`; set it to `true`
  only when deliberately scoping passkeys to a parent domain.
- `OTP_SECRET` must be at least 32 characters and must not be a known
  placeholder. It signs OTPs and recovery codes. The placeholder in
  `.env.example` is deliberately rejected.
- `COOKIE_NAME` must start with `__Host-` in production. Use
  `__Host-al_session`; local HTTP development uses `al_session` with
  `COOKIE_SECURE=false`.
- `ADMIN_TOKEN` is optional. Leave it empty to disable `/admin`, or set a random
  value of at least 32 characters. Admin sign-in is at `/admin/login` and uses
  a server-side session, not a URL token.
- Email: Compose defaults to `EMAIL_PROVIDER=smtp` and startup fails until
  `SMTP_HOST`, `SMTP_FROM`, and credentials are filled in. Production requires
  `SMTP_TLS=required`. See [Email delivery (SMTP)](#email-delivery-smtp).
  `outbox` is for local development only.
- Proxy trust: keep `TRUST_PROXY=true` and
  `TRUSTED_PROXY_CIDRS=172.28.0.0/16`, matching the dedicated Compose network.
- Session defaults: `SESSION_IDLE_HOURS=24` and
  `RECOVERY_CODE_TTL_DAYS=365`; review both for your policy.
- Production browser POSTs send `Origin` automatically. API clients and curl
  must add `Origin: https://auth.example.com` exactly; the server rejects
  missing/mismatched Origins with 403.
- WebAuthn API clients must preserve cookies: the `al_ceremony` cookie binds the
  challenge to the client, and the session cookie is required afterwards.

> `.env.example` is intentionally fail-closed. `docker compose config` parses
> it, but `docker compose up` will restart the app until the placeholder secret
> and SMTP/domain values are replaced. That is expected validation behavior,
> not a Compose syntax error.

Edit `deploy/Caddyfile` and replace **every** `auth.example.com` with your real
hostname. The domain must match `APP_URL`/`RP_ID`. Compose `build` uses the
Dockerfile automatically.

> Compose reads `.env` from the current directory for `${VAR}` interpolation.
> Variables are also injected explicitly in `docker-compose.yml`.

### 3. Start

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f --tail=200
```

The first build compiles the Rust service and can take a while. Wait for the
`authlayer` health status to become `healthy` and for Caddy to obtain a
certificate (visible in `docker compose logs caddy`).

If `authlayer` restarts or remains unhealthy, check the configuration error in
`docker compose logs authlayer`. Caddy waits for a healthy AuthLayer, so the
site will not come up until the startup error is fixed.

### 4. Verify

```bash
curl -fsS https://auth.example.com/healthz
```

Expected JSON contains `"ok":true`. Then open `https://auth.example.com/` in a
browser. A passkey prompt/cookie requires HTTPS (or `localhost`); plain HTTP on
a public host will not work for WebAuthn.

For production API/curl calls that change state, add the exact origin:

```bash
curl -H "Origin: https://auth.example.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com"}' \
  https://auth.example.com/api/auth/start
```

Browsers add `Origin` automatically. API clients driving WebAuthn manually must
also preserve cookies, including `al_ceremony`.

The runtime image contains only `ca-certificates` and `curl`; `curl` exists
solely for the `HEALTHCHECK` against `/healthz`. There are no compilers or build
tools in the final image.

### 5. Operations

```bash
docker compose logs -f authlayer
docker compose logs -f caddy
docker compose restart authlayer
docker compose down          # keeps named volumes (data)
docker compose down -v       # DESTROYS authlayer_data and caddy_data
docker compose up -d --build # update after pulling new source
```

`docker compose down -v` deletes the SQLite database. Use it only for a
deliberate reset.

---

## Plain systemd quickstart

Use this when Docker is not desired. Caddy runs directly on the host.

### 1. Build

On Ubuntu 24.04 with Rust **1.100+** (rustup) and build tools:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config sqlite3
cargo build --locked --release
```

The binary is `target/release/authlayer`. (`libsqlite3` is bundled and compiled
from source, hence `build-essential`.)

### 2. Install binary, user, directories

```bash
sudo install -m 0755 target/release/authlayer /usr/local/bin/authlayer

sudo groupadd --system authlayer
sudo useradd --system --gid authlayer \
  --home-dir /var/lib/authlayer --no-create-home \
  --shell /usr/sbin/nologin authlayer

sudo install -d -o authlayer -g authlayer -m 0700 /var/lib/authlayer
sudo install -d -o root -g root -m 0755 /etc/authlayer
```

### 3. Environment file

```bash
sudo install -m 0600 -o root -g root .env.example /etc/authlayer/authlayer.env
sudoedit /etc/authlayer/authlayer.env
```

For this layout use these values (the rest can stay as documented):

```dotenv
BIND_ADDR=127.0.0.1:8080
APP_URL=https://auth.example.com
RP_ID=auth.example.com
ALLOW_RP_ID_PARENT=false
DATABASE_URL=sqlite:///var/lib/authlayer/authlayer.db?mode=rwc
OTP_SECRET=<openssl rand -hex 32>
ADMIN_TOKEN=<openssl rand -hex 32, or empty to disable /admin>
COOKIE_NAME=__Host-al_session
COOKIE_SECURE=true
SESSION_TTL_DAYS=7
SESSION_IDLE_HOURS=24
OTP_TTL_MINUTES=10
RECOVERY_CODE_TTL_DAYS=365
DEV_MODE=false
ALLOW_INSECURE_DEV_MODE=false
ALLOW_OUTBOX_WITHOUT_DEV=false
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=<smtp username>
SMTP_PASSWORD=<smtp password>
SMTP_FROM="AuthLayer <no-reply@example.com>"
SMTP_TLS=required
TRUST_PROXY=true
TRUSTED_PROXY_CIDRS=127.0.0.1/32
```

`BIND_ADDR` stays on loopback because Caddy terminates TLS on the same host.
The loopback CIDR trusts only the local Caddy process to supply forwarding
headers. If Caddy runs on a different host, replace it with Caddy's actual
source subnet and firewall 8080 so only Caddy can reach it.

The file is readable only by root; systemd passes the variables to the service.
Do not put secret values in `deploy/authlayer.service` itself.

### 4. Install and start the unit

```bash
sudo install -m 0644 deploy/authlayer.service /etc/systemd/system/authlayer.service
sudo systemctl daemon-reload
sudo systemctl enable --now authlayer
sudo systemctl status authlayer
sudo journalctl -u authlayer -f
```

The unit creates `/var/lib/authlayer` via `StateDirectory=authlayer`, runs as
`authlayer:authlayer`, and uses `UMask=0077`, so the database is private.

### 5. Caddy on the host

Install Caddy 2.x from the official Caddy package repository, then:

```bash
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile
sudo sed -i 's/auth\.example\.com/your.real.domain/g' /etc/caddy/Caddyfile
sudo sed -i 's/authlayer:8080/127.0.0.1:8080/' /etc/caddy/Caddyfile
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

The second `sed` changes the Docker service upstream to the loopback listener.
Verify:

```bash
curl -fsS http://127.0.0.1:8080/healthz   # direct, bypasses Caddy
curl -fsS https://your.real.domain/healthz
```

---

## Email delivery (SMTP)

`EMAIL_PROVIDER` selects how OTP mail is handled:

| Value | Behavior |
| --- | --- |
| `outbox` (application default; local development only) | Writes the message to the local `outbox` table and sends nothing. Use with `DEV_MODE=true` and `/dev/outbox`. |
| `smtp` (Compose default; production) | Delivers through the configured SMTP server. Required when `DEV_MODE=false`. |

> `EMAIL_PROVIDER=outbox` with `DEV_MODE=false` is a **startup error**, unless
> `ALLOW_OUTBOX_WITHOUT_DEV=true`. Even with that escape hatch, no email leaves
> the server and users cannot sign in. Production must use `smtp`.
>
> Compose and `.env.example` default to `smtp`. SMTP values are intentionally
> left empty in the template: `docker compose config` succeeds, but the app
> exits at startup with `SMTP_HOST is required when EMAIL_PROVIDER=smtp` (or
> the matching `SMTP_FROM` error) until you fill them in.

### Generic SMTP configuration

Set these in `.env` for Compose, or in `/etc/authlayer/authlayer.env` for the
systemd layout:

```dotenv
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=authlayer
SMTP_PASSWORD=<provider SMTP password or API token>
SMTP_FROM="AuthLayer <no-reply@yourdomain.example>"
SMTP_TLS=required
```

- `SMTP_HOST` and `SMTP_FROM` are required when `EMAIL_PROVIDER=smtp`; the
  service refuses to start without them.
- `SMTP_HOST` is a bare hostname: no `smtp://` scheme, path, or embedded port.
  The port belongs in `SMTP_PORT`.
- `SMTP_FROM` is parsed as a mailbox: `no-reply@example.com` or
  `AuthLayer <no-reply@example.com>`. Use a sender address/domain that your
  provider has verified, or mail will be rejected or spam-filtered.
- `SMTP_USERNAME` and `SMTP_PASSWORD` are optional for internal relays that do
  not require authentication, but must be set together. Setting only one is a
  startup error.
- If the password contains spaces, `#`, or `$`, single-quote the value in
  `.env` so Compose parses it literally. Never commit the real password or paste
  it into logs, tickets, or chat.
- The application does not print `SMTP_PASSWORD`; the config type redacts it
  from debug output. It is still visible in `docker inspect`, in
  `docker compose config`, and to root on the host, so protect the Docker
  socket and the `0600` env file.

### Provider examples

| Provider | SMTP host / port | Credentials | Notes |
| --- | --- | --- | --- |
| Postmark | `smtp.postmarkapp.com`, port `587` (also `2525`) | Use the Server API token as **both** username and password | `SMTP_FROM` must be a verified Sender Signature or domain. |
| Amazon SES | `email-smtp.<region>.amazonaws.com`, port `587` (STARTTLS) or `465` (implicit TLS) | SES SMTP username/password, **not** IAM access keys | Verify the sender/domain. SES sandbox accounts can only send to verified recipients until production access is granted. |
| Mailgun | `smtp.mailgun.org` (US) or `smtp.eu.mailgun.org` (EU), port `587` or `465` | SMTP user (often `postmaster@yourdomain`) and password | Verify the sending domain first. |
| Generic | Your provider's host, `587` or `465` | Optional username/password pair | Use `SMTP_TLS=required`; see ports below. |

Port `25` is often blocked by hosting providers; prefer `587` or `465`. Provider
hostnames, ports, and credential rules can change, so confirm them in the
provider's current documentation.

### TLS modes and ports

| `SMTP_TLS` | Behavior | Recommendation |
| --- | --- | --- |
| `required` (default), port **465** | Implicit TLS from the first byte (`Tls::Wrapper`) | Use for providers that offer an SSL/TLS port 465. |
| `required`, any other port (normally **587**) | STARTTLS is required before authentication and mail | Use for standard submission with STARTTLS. |
| `opportunistic` | Uses STARTTLS only if the server advertises it; may fall back to plaintext | **DEV_MODE only**; rejected with credentials or outside dev. |
| `none` | No TLS at all | **Rejected when `DEV_MODE=false`**; never on a public network. |

- Port 465 uses implicit TLS only when `SMTP_TLS=required` and
  `SMTP_PORT=465`. Do not combine port 465 with `opportunistic` or `none`.
- Port 587 with `SMTP_TLS=required` enforces STARTTLS. If the server does not
  offer STARTTLS, delivery fails instead of downgrading to plaintext.
- `SMTP_TLS=opportunistic` is rejected when `DEV_MODE=false` or when
  `SMTP_USERNAME`/`SMTP_PASSWORD` are present. Production must use `required`.
- `SMTP_TLS=none` is rejected at startup when `DEV_MODE=false`. In development
  it is allowed and warns when credentials are configured; it sends plaintext.
  Never use it with real credentials.
- SMTP certificate validation uses the bundled public (Mozilla) root store.
  Self-signed or private-CA SMTP endpoints are not supported without code
  changes.

### Delivery test

After configuring SMTP, restart AuthLayer and request a code for a real mailbox
outside your infrastructure. A delivery failure returns HTTP 500
(`email_delivery_failed`) and logs `OTP email delivery failed` with the provider
error. Check the AuthLayer logs before changing provider or DNS settings.

---

## Admin access

Set `ADMIN_TOKEN` to a random value of at least 32 characters
(`openssl rand -hex 32`), or leave it empty to disable admin entirely. All
`/admin*` routes return 404 when it is unset. Admin login is rate-limited to
5 attempts per minute per client IP.

Open `https://auth.example.com/admin/login` and submit the token in the form.
The admin routes are `GET/POST /admin/login`, `GET /admin`, and
`POST /admin/logout`. Successful login creates a **server-side** admin session:
the opaque `al_admin` cookie is random, and only its hash is stored in the
`admin_sessions` table.

- `HttpOnly`
- `SameSite=Strict`
- `Path=/admin`
- one-hour TTL
- `Secure` when `COOKIE_SECURE=true`

The token is never accepted in the URL, so old `/admin?token=...` links do not
work. **Sign out** posts to `/admin/logout`, which revokes the database row and
clears the cookie. Old pre-hardening HMAC admin cookies are invalid. Changing
`ADMIN_TOKEN` does **not** revoke already-created admin sessions; log out, wait
for the one-hour TTL, or revoke the rows directly.

Admin login/logout are state-changing POSTs, so production requires an `Origin`
header matching `APP_URL`; browsers send it automatically.

---

## Startup validation and failure modes

`docker compose config` checks only YAML and interpolation. AuthLayer validates
its configuration at startup and exits with a specific error. A configuration
can therefore pass `docker compose config` and still fail to start. With
`restart: unless-stopped`, the container restart-loops until it is fixed, and
Caddy does not start because it waits for `service_healthy`.

| Condition | Startup result / fix |
| --- | --- |
| `EMAIL_PROVIDER=outbox` with `DEV_MODE=false` | Exits unless `ALLOW_OUTBOX_WITHOUT_DEV=true`. Use `smtp` for real deployments. |
| `EMAIL_PROVIDER=smtp` with empty `SMTP_HOST` or `SMTP_FROM` | Exits with `SMTP_HOST is required when EMAIL_PROVIDER=smtp` or the `SMTP_FROM` equivalent. Fill both in. |
| `OTP_SECRET` missing/short when `DEV_MODE=false`, or any known placeholder | Exits. In development, missing/short only warns, but known placeholders are always rejected. Generate with `openssl rand -hex 32`. |
| `ADMIN_TOKEN` set but shorter than 32 characters or a known placeholder | Exits. Use a longer random value, or leave it empty to disable admin. |
| `RP_ID` differs from the `APP_URL` host while `ALLOW_RP_ID_PARENT=false` | Exits. Set `RP_ID` to the exact `APP_URL` host, or explicitly opt into parent scope with `ALLOW_RP_ID_PARENT=true`. |
| `DEV_MODE=true` with non-loopback `BIND_ADDR` or `APP_URL` | Exits unless `ALLOW_INSECURE_DEV_MODE=true`. Compose binds `0.0.0.0`, so do not use dev mode there without that unsafe opt-in. |
| `DEV_MODE=false` with `COOKIE_SECURE=false`, non-HTTPS `APP_URL`, or `COOKIE_NAME` without `__Host-` | Exits. Use `COOKIE_SECURE=true`, an HTTPS `APP_URL`, and `COOKIE_NAME=__Host-al_session`. |
| `TRUST_PROXY=true` but `TRUSTED_PROXY_CIDRS` is empty or invalid | Exits. Use a comma-separated CIDR list such as `172.28.0.0/16` (Compose) or `127.0.0.1/32` (host Caddy). |
| `SMTP_TLS=opportunistic` outside `DEV_MODE` or with SMTP credentials | Exits. Production must use `required`. |
| `SMTP_TLS=none` with `DEV_MODE=false` | Exits. Use `required` (587 STARTTLS or 465 implicit TLS). |
| Non-positive `SESSION_*` or `RECOVERY_CODE_TTL_DAYS` | Exits. Use positive integers. |

Check the exact error with `docker compose logs authlayer` or
`journalctl -u authlayer -n 200 --no-pager`.

---

## Environment contract

All variables below are read by `src/config.rs`, except `RUST_LOG`, which is
read by the tracing subscriber. Defaults shown are the application defaults;
Docker Compose overrides several of them.

| Variable | Example / default | Notes |
| --- | --- | --- |
| `BIND_ADDR` | `0.0.0.0:8080` (Compose), app default `127.0.0.1:8080` | Socket address. Use `127.0.0.1:8080` for systemd behind host Caddy. |
| `APP_URL` | `https://auth.example.com` | Exact public origin. Must be HTTPS in production. No trailing slash. |
| `RP_ID` | `auth.example.com` | WebAuthn relying-party ID: hostname only. Must equal the `APP_URL` host unless `ALLOW_RP_ID_PARENT=true`. Changing it invalidates passkeys. |
| `ALLOW_RP_ID_PARENT` | `false` | Non-dev escape hatch for an intentional parent RP ID. Enabling it broadens WebAuthn scope and logs a warning. |
| `RP_NAME` | `AuthLayer` | Name shown in passkey prompts. |
| `DATABASE_URL` | `sqlite:///data/authlayer.db?mode=rwc` | Docker uses the named volume. systemd: `sqlite:///var/lib/authlayer/authlayer.db?mode=rwc`. |
| `OTP_SECRET` | **required when dev is off**, `openssl rand -hex 32` | At least 32 characters; known placeholders are rejected. HMAC key for OTP and recovery codes. In development, missing is allowed with a warning and an ephemeral key. |
| `COOKIE_NAME` | `__Host-al_session` (prod); `al_session` (dev/HTTP) | Non-dev must start with `__Host-`. The session cookie is HttpOnly, SameSite=Strict, Path=/. Local dev only: `al_session`. |
| `COOKIE_SECURE` | `true` | Non-dev requires `true` and an HTTPS `APP_URL`. Also sets `Secure` on the `al_ceremony` and `al_admin` cookies. |
| `DEV_MODE` | `false` | Explicit; never auto-enabled. `true` exposes `/dev/outbox` and requires loopback `BIND_ADDR`/`APP_URL` unless `ALLOW_INSECURE_DEV_MODE=true`. |
| `ALLOW_INSECURE_DEV_MODE` | `false` | Allows `DEV_MODE=true` with a non-loopback bind/origin. Isolated development only; never production. |
| `ALLOW_OUTBOX_WITHOUT_DEV` | `false` | Allows outbox email while `DEV_MODE=false`. Sends nothing; staging escape hatch only. |
| `ADMIN_TOKEN` | empty (disabled) | Optional. If set, at least 32 characters and not a known placeholder. Enables form login at `/admin/login` with a server-side session; empty makes all `/admin*` routes 404. |
| `SESSION_TTL_DAYS` | `7` | Absolute session lifetime in days. |
| `SESSION_IDLE_HOURS` | `24` | Reject a session after this many hours without an authenticated request. |
| `OTP_TTL_MINUTES` | `10` | OTP lifetime in minutes. |
| `RECOVERY_CODE_TTL_DAYS` | `365` | Recovery-code lifetime in days from generation. |
| `EMAIL_PROVIDER` | `smtp` (Compose); app default `outbox` | `smtp` is required in production. `outbox` sends nothing and fails startup when `DEV_MODE=false` unless explicitly allowed. |
| `SMTP_HOST` | empty | Required when `EMAIL_PROVIDER=smtp`; ignored for outbox. Bare hostname, no scheme or port. |
| `SMTP_PORT` | `587` | `587` uses STARTTLS; `465` uses implicit TLS (with `SMTP_TLS=required`). |
| `SMTP_USERNAME` | empty | Optional. Must be paired with `SMTP_PASSWORD`, or both omitted. |
| `SMTP_PASSWORD` | empty | Optional SMTP secret; never commit or log it. Must be paired with `SMTP_USERNAME`. |
| `SMTP_FROM` | empty | Required when `EMAIL_PROVIDER=smtp`; parsed as a mailbox at startup. |
| `SMTP_TLS` | `required` | `required` is production. `opportunistic` is DEV_MODE-only and rejected with credentials. `none` is rejected when `DEV_MODE=false`. |
| `TRUST_PROXY` | `true` (Compose); app default `false` | Honor `X-Forwarded-For`/`X-Real-IP` only from `TRUSTED_PROXY_CIDRS`. Required behind Caddy for real client IPs. |
| `TRUSTED_PROXY_CIDRS` | `172.28.0.0/16` (Compose); `127.0.0.1/32` for host Caddy | Required when `TRUST_PROXY=true`. Comma-separated IPv4/IPv6 CIDRs. Must match the actual proxy source network. |
| `RUST_LOG` | `authlayer=info,tower_http=info` | Optional tracing filter; `debug` is noisy, avoid in production. |

All 26 configuration variables used by `src/config.rs` are listed above; the
only extra is `RUST_LOG`. With `DEV_MODE=false`, a missing/short/placeholder
`OTP_SECRET`, short/placeholder `ADMIN_TOKEN`, insecure cookie settings, or an
RP ID/host mismatch abort startup. In development, a missing `OTP_SECRET` is
replaced by an ephemeral key and logs a warning.

Production state-changing requests require `Origin` exactly equal to the
`APP_URL` origin. The session and ceremony cookies are `SameSite=Strict`; the
WebAuthn `al_ceremony` cookie has a 10-minute TTL and must be preserved by any
API client driving the ceremony manually.

---

## Upgrades, migration, and cleanup

Migration `0003_legacy_and_cookie.sql` runs automatically on startup:

- Legacy sessions created before passkey binding (`passkey_id IS NULL`) are
  revoked, so affected users must sign in again.
- The production session cookie is now `__Host-al_session`; old `al_session`
  cookies are no longer read.
- Legacy recovery codes with no expiry are invalidated. Users must regenerate
  their recovery codes after upgrading.
- Pre-hardening HMAC admin cookies are invalid. Admin sign-in now uses
  server-side `admin_sessions`; sign in again at `/admin/login`.

Back up the SQLite database before upgrading. No manual SQL is required.

Cleanup runs at startup and every five minutes. It deletes:

- expired OTP rows;
- expired session rows;
- expired or legacy `NULL`-expiry recovery codes;
- expired or revoked admin sessions;
- outbox rows older than 24 hours.

---

## SQLite backup and restore

### systemd (live-safe)

The `sqlite3` CLI uses the online backup API and is safe while AuthLayer runs:

```bash
sudo install -d -m 0700 /var/backups/authlayer
sudo sqlite3 /var/lib/authlayer/authlayer.db \
  ".backup '/var/backups/authlayer/authlayer-$(date +%F-%H%M%S).db'"
sudo chmod 600 /var/backups/authlayer/*.db
```

Restore:

```bash
sudo systemctl stop authlayer
sudo rm -f /var/lib/authlayer/authlayer.db-wal /var/lib/authlayer/authlayer.db-shm
sudo install -o authlayer -g authlayer -m 0600 \
  /var/backups/authlayer/authlayer-YYYY-MM-DD-HHMMSS.db \
  /var/lib/authlayer/authlayer.db
sudo systemctl start authlayer
```

### Docker (stop-copy)

The runtime image intentionally has no `sqlite3` CLI, so use a clean shutdown
and copy the volume:

```bash
# Find the volume mountpoint (project is named "authlayer").
VOL=$(docker volume inspect authlayer_authlayer_data --format '{{.Mountpoint}}')
sudo install -d -m 0700 /var/backups/authlayer
docker compose stop authlayer
sudo cp -a "$VOL/." "/var/backups/authlayer/data-$(date +%F-%H%M%S)"
docker compose start authlayer
```

Restore:

```bash
VOL=$(docker volume inspect authlayer_authlayer_data --format '{{.Mountpoint}}')
docker compose down
sudo rm -f "$VOL/authlayer.db-wal" "$VOL/authlayer.db-shm"
sudo install -o 10001 -g 10001 -m 0600 \
  /var/backups/authlayer/data-YYYY-MM-DD-HHMMSS/authlayer.db \
  "$VOL/authlayer.db"
docker compose up -d
```

`docker compose down` without `-v` preserves the volumes. Backups contain user
emails, passwordless credential data, session hashes, audit logs, and outbox
messages (which can contain OTP codes). Encrypt them and restrict access
(`0600`, off-host copy).

Caddy's `caddy_data` volume stores ACME certificates/account keys. It can be
backed up the same way, but Caddy re-issues certificates automatically after
data loss; backing it up avoids issuance rate limits.

---

## File permissions

| Path | Owner | Mode |
| --- | --- | --- |
| `.env` (Compose) | deploying user | `0600` |
| `/etc/authlayer/authlayer.env` | `root:root` | `0600` |
| `/var/lib/authlayer` | `authlayer:authlayer` | `0700` (`StateDirectoryMode`) |
| `/var/lib/authlayer/authlayer.db` | `authlayer:authlayer` | `0600` (`UMask=0077`) |
| `/usr/local/bin/authlayer` | `root:root` | `0755` |
| `/etc/systemd/system/authlayer.service` | `root:root` | `0644` |
| `/etc/caddy/Caddyfile` | `root:root` | `0644` |
| Backups | `root` | `0600` |

The Docker named volume is initialized with `/data` owned by UID/GID 10001, and
the container runs as `10001:10001`. If you switch to a bind mount, fix
ownership explicitly:

```bash
sudo chown -R 10001:10001 ./data
```

Never use `chmod 777`. If an existing volume has the wrong owner:

```bash
docker compose down
docker run --rm -v authlayer_authlayer_data:/data \
  debian:bookworm-slim chown -R 10001:10001 /data
docker compose up -d
```

---

## Resource limits

Compose applies conservative limits and a read-only app filesystem:

| Service | Memory | PIDs | Filesystem / capabilities |
| --- | --- | --- | --- |
| `authlayer` | 256 MiB | 100 | Read-only root; writable `authlayer_data` at `/data`; 16 MiB tmpfs at `/tmp`; all capabilities dropped; `no-new-privileges` |
| `caddy` | 128 MiB | 100 | Writable root; `/data` and `/config` volumes; all capabilities dropped except `NET_BIND_SERVICE`; `no-new-privileges` |

Both services use the `json-file` log driver with a 10 MiB maximum per file and
three files (30 MiB maximum per service).

The app writes only to `/data` (the SQLite database) and `/tmp` (SQLite scratch
space). If a future feature needs another write path, add a volume or tmpfs for
it instead of disabling `read_only`. Raise `mem_limit` or `pids_limit` if you
add heavier features or observe OOM kills, and increase the `/tmp` size if
SQLite temp work grows. Caddy is deliberately not read-only because it manages
ACME state under `/data` and `/config`.

---

## Logs and health

```bash
# Docker
docker compose ps                       # health of each service
docker compose logs -f authlayer
docker compose logs -f caddy
docker inspect --format '{{json .State.Health}}' "$(docker compose ps -q authlayer)"

# systemd
systemctl status authlayer
journalctl -u authlayer -f
journalctl -u authlayer -n 200 --no-pager
journalctl -u caddy -f
systemd-analyze security authlayer      # optional hardening score
```

Set `RUST_LOG=authlayer=debug,tower_http=debug` temporarily when diagnosing.
Do not leave `debug` on in production if logs are retained. SMTP delivery
failures appear as `OTP email delivery failed` with the provider's error.

Startup logs redact the database URL (userinfo and query string), and cleanup
runs are logged with row counts. The application does not intentionally log
secrets or session/ceremony tokens.

---

## Production checklist

- [ ] `APP_URL`, `RP_ID`, and the Caddy site address are the real HTTPS domain.
      `RP_ID` equals the `APP_URL` host and `ALLOW_RP_ID_PARENT=false`.
- [ ] `DEV_MODE=false`, `ALLOW_INSECURE_DEV_MODE=false`,
      `ALLOW_OUTBOX_WITHOUT_DEV=false`, `COOKIE_SECURE=true`, and
      `COOKIE_NAME=__Host-al_session`.
- [ ] `OTP_SECRET` is at least 32 random characters from
      `openssl rand -hex 32`, is not a placeholder, and is stored in a secrets
      manager plus backup vault.
- [ ] `ADMIN_TOKEN` is at least 32 random characters or intentionally empty.
      `/admin/login` and sign-out have been tested; logout revokes the
      server-side session, and no token appears in a URL or log.
- [ ] `EMAIL_PROVIDER=smtp`, `SMTP_TLS=required`, an end-to-end OTP has reached
      a mailbox outside your infrastructure, and the provider has verified your
      sender/domain. Any Amazon SES sandbox restriction has been lifted.
- [ ] **Email deliverability:** the sending domain has SPF, DKIM, and DMARC
      records. Publish the provider's SPF include and DKIM selector, align the
      `SMTP_FROM` domain with the authenticated domain, start DMARC at
      `p=none`, review reports, then move toward `quarantine`/`reject`.
- [ ] `TRUST_PROXY=true` and `TRUSTED_PROXY_CIDRS` exactly match the trusted
      proxy network: `172.28.0.0/16` for Compose, or `127.0.0.1/32` for Caddy
      on the same host. Only Caddy can reach the app.
- [ ] Browser POSTs succeed with `Origin`; any API/curl client sends the exact
      `APP_URL` origin and preserves the `al_ceremony` WebAuthn cookie.
- [ ] `SESSION_IDLE_HOURS` and `RECOVERY_CODE_TTL_DAYS` match your security
      policy (defaults: 24 hours and 365 days).
- [ ] Edge rate limiting/CAPTCHA is configured for public signup, since there is
      no hard account lockout.
- [ ] If upgrading, the database was backed up and forced re-login/recovery-code
      regeneration was expected from migration 0003.
- [ ] Only SSH, TCP 80/443, and UDP 443 are exposed; port 8080 is not
      published.
- [ ] Backups are encrypted, stored off-host, and a restore drill has been run.

---

## Security notes

- **TLS is mandatory for WebAuthn.** Use `APP_URL=https://...` and
  `COOKIE_SECURE=true`. The `http://localhost` exception is for development
  only. Caddy handles certificate issuance/renewal.
- **`RP_ID` must equal the `APP_URL` host in production.** It is a hostname (no
  scheme, port, path). Non-dev startup rejects a mismatch unless
  `ALLOW_RP_ID_PARENT=true`, which deliberately broadens WebAuthn scope to a
  parent domain. Changing it makes existing passkeys unusable for that RP ID.
- **Production cookies are locked down.** The session cookie is
  `__Host-al_session`: Secure, HttpOnly, SameSite=Strict, Path=/, no Domain.
  Non-dev startup rejects `COOKIE_SECURE=false`, a non-HTTPS `APP_URL`, or a
  cookie name without the `__Host-` prefix. The admin cookie is `al_admin`
  (Path=/admin) and the WebAuthn ceremony cookie is `al_ceremony`
  (HttpOnly, SameSite=Strict, 10 minutes).
- **Never enable `DEV_MODE` in production.** It exposes `/dev/outbox`, which is
  effectively a public OTP feed. It also requires loopback `BIND_ADDR` and
  `APP_URL`; `ALLOW_INSECURE_DEV_MODE=true` removes that guard and is only for
  isolated development. `ALLOW_OUTBOX_WITHOUT_DEV=true` only suppresses the
  startup error; it does not deliver email.
- **Protect `OTP_SECRET`.** Use at least 32 random characters and never a known
  placeholder. Rotate it only intentionally: pending OTPs and all unused
  recovery codes become invalid. Existing sessions and registered passkeys are
  unaffected. Store it in the `0600` env file and in your secrets
  manager/backup vault.
- **SMTP credentials and TLS.** Keep `SMTP_PASSWORD` out of git, shell history,
  logs, and chat. Set `SMTP_USERNAME` and `SMTP_PASSWORD` together. Use
  `SMTP_TLS=required`: port 587 enforces STARTTLS, and port 465 uses implicit
  TLS. `opportunistic` is DEV_MODE-only and rejected when credentials are set;
  `none` is rejected when `DEV_MODE=false`.
- **Admin is a server-side form login, not a URL token.** Open `/admin/login`
  and submit the token there. A successful login creates an `admin_sessions`
  row and sets an opaque `al_admin` cookie: HttpOnly, SameSite=Strict,
  Path=/admin, one-hour TTL, and Secure when `COOKIE_SECURE=true`. Logout
  revokes the row. Old HMAC cookies are invalid. The token itself must be at
  least 32 random characters, or `ADMIN_TOKEN` must be empty to disable
  `/admin*` entirely. Changing it does not revoke existing admin sessions.
- **Production state-changing requests require `Origin`.** It must exactly equal
  the `APP_URL` origin. Browsers send it automatically; curl and API clients
  must add it or receive 403. Caddy forwards it unchanged.
- **API-driven WebAuthn needs the ceremony cookie.** The 10-minute
  `al_ceremony` cookie binds the challenge ID to the client. Preserve the cookie
  jar between the options response and the verify/register request, or the
  server returns `challenge_not_found`.
- **Do not publish port 8080.** In Compose, only Caddy maps host ports, and both
  services share a dedicated network. With systemd, bind `127.0.0.1:8080`. If
  app and Caddy are on different hosts, use a private network/firewall rule and
  TLS between them. Publishing 8080 while trusting the Docker CIDR is unsafe:
  Docker's gateway falls inside that CIDR, so direct clients could spoof
  forwarding headers and rate-limit IPs.
- **Forwarding headers are trusted by CIDR.** Caddy overwrites both
  `X-Forwarded-For` and `X-Real-IP` with the direct peer. AuthLayer honors them
  only when the socket peer is in `TRUSTED_PROXY_CIDRS`, so keep that list equal
  to the actual proxy network and never attach untrusted containers to the
  Compose network. If you add a CDN/load balancer in front of Caddy, configure
  Caddy `trusted_proxies` and use `{client_ip}` for both headers; otherwise
  every request appears to come from the CDN/proxy.
- **HSTS.** The example sends `includeSubDomains` for one year. Remove
  `includeSubDomains` if any other subdomain is not HTTPS-only. Do not enable
  preload without a deliberate, long-term commitment.
- **CSP.** `script-src 'self'` forbids inline JavaScript; the UI loads
  `/app.js`. `style-src` allows inline styles because the optional admin/dev
  pages embed a `<style>` block. If the frontend starts using inline scripts,
  use nonces/hashes instead of adding `'unsafe-inline'` to `script-src`.
- **No hard account lockout.** `failed_attempts` is advisory and `locked_until`
  is unused. Brute-force protection is per-OTP attempt limits (5), per-email/IP
  rate limits, and edge CAPTCHA/rate limiting for public signup. Monitor repeated
  failure warnings.
- **Rate limiting is in-memory and per-process.** A restart clears it; there is
  no distributed limiter. Admin login is limited to 5 attempts/minute per IP.
  Keep one instance and consider Caddy/proxy-level limits for public deployments.
- **Restart behavior.** WebAuthn ceremonies and recovery challenges live in
  memory. Restarting during a ceremony invalidates that ceremony; users simply
  retry. Sessions and passkeys are in SQLite and survive restarts.
- **Secrets in Docker metadata.** `docker inspect` and `docker compose config`
  can reveal `OTP_SECRET`, `ADMIN_TOKEN`, and `SMTP_PASSWORD`. Restrict Docker
  socket access; do not paste `docker compose config` output into tickets or
  chat.

---

## Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| `docker compose` errors about `OTP_SECRET` | Set a non-empty `OTP_SECRET` in `.env` (`openssl rand -hex 32`). |
| `authlayer` exits or restart-loops at startup | Read the exact error in `docker compose logs authlayer` or `journalctl -u authlayer`. Common causes: outbox without dev, missing `SMTP_HOST`/`SMTP_FROM`, short/placeholder `OTP_SECRET`, short/placeholder `ADMIN_TOKEN`, missing/invalid `TRUSTED_PROXY_CIDRS`, non-loopback `DEV_MODE`, `RP_ID` not matching `APP_URL`, insecure cookie settings, or `SMTP_TLS=none`/`opportunistic`. |
| Caddy cannot obtain a certificate | DNS does not resolve to the host, or TCP 80/443 is blocked. Check `docker compose logs caddy`; verify with an external DNS lookup. |
| `502 Bad Gateway` from Caddy | AuthLayer is not healthy or crashed. `docker compose ps`, then `docker compose logs authlayer`. |
| Container is `unhealthy` | Check logs; typical causes are a startup config error, a bad `BIND_ADDR`, unreadable `/data`, or failed SQLite migration. |
| Permission denied writing the DB (Docker) | Volume owned by the wrong UID. Fix `/data` to `10001:10001` (see above). |
| Passkey registration/login fails | `APP_URL`/`RP_ID` mismatch, non-HTTPS origin, clock skew, missing `Origin` (403), or a missing/expired `al_ceremony` cookie. `APP_URL` must be the exact browser origin. |
| 403 Forbidden on a POST/API call | Production requires `Origin` exactly equal to `APP_URL`'s origin. Browsers send it; curl/API clients must add `-H "Origin: https://auth.example.com"`. |
| `challenge_not_found` during WebAuthn | The client did not preserve the `al_ceremony` cookie (10-minute TTL) or the challenge expired (2–5 minutes). Keep one cookie jar across options and verify/register calls. |
| Session cookie not set or rejected | Production needs HTTPS, `COOKIE_SECURE=true`, and a `COOKIE_NAME` beginning with `__Host-` (default `__Host-al_session`). Browsers reject `__Host-` cookies without Secure/Path=/ and no Domain. |
| OTP flow cannot complete | Outbox sends nothing; it is rejected when `DEV_MODE=false` unless `ALLOW_OUTBOX_WITHOUT_DEV=true`. Set `EMAIL_PROVIDER=smtp`. |
| HTTP 500 / `OTP email delivery failed` | SMTP host, port, TLS mode, credentials, or `SMTP_FROM` was rejected. Port 587 needs STARTTLS; port 465 needs `SMTP_TLS=required`. Check `docker compose logs authlayer` or `journalctl -u authlayer`. |
| SMTP authentication fails | Check the username/password pair. Some providers are special: Postmark uses the Server API token as both, and Amazon SES needs SES SMTP credentials rather than IAM access keys. |
| OTP mail lands in spam | Configure SPF, DKIM, and DMARC for the sending domain; verify the sender/domain with the provider. See the production checklist. |
| `/admin` returns 404 | `ADMIN_TOKEN` is empty (admin disabled) or the URL is wrong. Set a 32+ character token and open `/admin/login`; `?token=...` is no longer accepted. |
| Admin login succeeds but redirects back to login | Clear old cookies after upgrading: pre-hardening HMAC `al_admin` cookies are invalid. Use HTTPS, keep `COOKIE_SECURE` consistent, and allow the Path=/admin cookie. If a token was rotated, existing server-side sessions remain valid until logout or the one-hour TTL. |
| User appears “locked out” | There is no hard account lockout. Check the per-OTP 5-attempt limit and per-email/IP rate-limit windows; request a fresh code after the window. Configure edge CAPTCHA/rate limiting for public signup. |
| Users were signed out or recovery codes stopped working after upgrade | Expected from migration 0003: legacy passkey-less sessions and NULL-expiry recovery codes are invalidated. Re-login and regenerate recovery codes. |
| Everyone shares one client IP / rate limits hit all users | `TRUST_PROXY` or `TRUSTED_PROXY_CIDRS` is wrong. The app sees Caddy's container IP until the CIDR matches the proxy network (`172.28.0.0/16` for Compose, `127.0.0.1/32` for host Caddy). Do not publish 8080. |
| `docker compose config` exposes the secret | Expected: interpolation is resolved locally. Do not share the output. |

Always run a restore drill before relying on backups. The deployment config
does not make the application production-ready on its own: the backend must
compile, the frontend must be complete, and email delivery must be configured
for real users.
