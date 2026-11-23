# AuthLayer smoke test

Dependency-free HTTP smoke test for the AuthLayer server. It uses Node's built-in
`fetch` and needs no `npm install`.

The script exercises the public HTTP surface, checks hardening headers and
unauthenticated 401 behavior, reads the dev outbox to complete the email OTP step,
and never automates WebAuthn.

## Requirements

- Node.js 18 or newer with global `fetch` (Node 24 is used in this repository).
- A running AuthLayer server, local or remote.

## Start the server

From the repository root, in PowerShell:

```powershell
cd authlayer
$env:APP_URL = "http://localhost:8080"
$env:RP_ID = "localhost"
$env:DATABASE_URL = "sqlite://authlayer.db?mode=rwc"
$env:DEV_MODE = "true"
$env:OTP_SECRET = "dev-secret-change-me"
# Optional: enables the wrong-admin-token check.
$env:ADMIN_TOKEN = "dev-admin-token"
cargo run
```

Bash equivalent:

```bash
cd authlayer
APP_URL=http://localhost:8080 \
RP_ID=localhost \
DATABASE_URL='sqlite://authlayer.db?mode=rwc' \
DEV_MODE=true \
OTP_SECRET=dev-secret-change-me \
cargo run
```

Add `ADMIN_TOKEN=dev-admin-token` to the command above to enable the optional
admin cookie-login checks; use the same value when running the smoke test.

`DEV_MODE=true` is recommended. It exposes `/api/dev/outbox`, which the smoke test
uses to read the one-time code. With `DEV_MODE=false` the server still runs the
non-OTP checks, but the three OTP-dependent checks are reported as `SKIP`.

`ADMIN_TOKEN` is optional. If it is set in the smoke-test process, the script tests
the cookie-based admin flow: the login page, wrong-token rejection, correct-token
login with an `al_admin` cookie, the authenticated admin page, and logout clearing
the cookie. Set the same value on the server. Without it, those five admin-flow
checks are skipped; the unauthenticated `/admin` denial check still runs.

The server limits admin login attempts to 5 per minute per IP. The script makes two
attempts (one wrong, one correct), so very rapid repeated runs can be rate-limited.

## Run the smoke test

From the repository root:

```powershell
node scripts/smoke.mjs
```

Against another host or port:

```powershell
$env:BASE_URL = "http://localhost:8080"
node scripts/smoke.mjs
```

Bash:

```bash
BASE_URL=http://localhost:8080 node scripts/smoke.mjs
```

Optional environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `BASE_URL` | `http://localhost:8080` | Server origin. |
| `ADMIN_TOKEN` | unset | Enables the admin cookie-login checks. Must match the server. |
| `SMOKE_TIMEOUT_MS` | `10000` | Per-request timeout in milliseconds. |

Do not point this at production with `DEV_MODE=true`: the dev outbox exposes OTP codes.

## What is covered

1. `GET /healthz` returns 200 with `ok: true`, confirming the database probe.
   A failed database probe returns 503 and fails this check.
2. `GET /` returns 200 and contains `AuthLayer`.
3. `GET /style.css` and `GET /app.js` return 200 with non-empty bodies.
4. `GET /api/me` without a cookie returns 200 with `authenticated: false`.
5. `Cache-Control` contains `no-store` on `/healthz`, `/api/me`, `/`, and
   `/app.js`.
6. `POST /api/auth/start` with an invalid email returns 400.
7. `POST /api/auth/start` with a unique email returns 200 with `flow: "code"`.
8. `GET /api/dev/outbox` returns the OTP for that email when dev mode is on.
   If it returns 404, the OTP checks are skipped.
9. `POST /api/auth/verify-code` with a wrong code returns 400.
10. `POST /api/auth/verify-code` with a non-existent user returns 400. This uses
    a separate `missing-...@example.test` address, so it cannot consume the real
    OTP created for the smoke-test user.
11. `POST /api/auth/verify-code` with the real code returns 200 with
    `flow: "register_passkey"` and a WebAuthn challenge.
12. `GET /api/sessions` without a cookie returns 401.
13. `POST /api/auth/stepup/start` without a cookie returns 401.
14. `POST /api/auth/stepup/finish` without a cookie returns 401. The request
    includes a structurally valid JSON body so the session check is reached.
15. `POST /api/sessions/revoke-all` without a cookie returns 401.
16. `POST /api/passkeys/add/start` without a cookie returns 401.
17. `POST /api/passkeys/add/finish` without a cookie returns 401. The request
    includes a structurally valid JSON body so the session check is reached.
18. `POST /api/auth/logout` without a cookie returns 200 or 401, never 500.
19. `GET /admin` without a valid `al_admin` cookie returns a 302/303 redirect to
    `/admin/login` (or 404 if admin is disabled), never 200. The script uses
    `redirect: "manual"` so an automatic redirect cannot mask a 200.
20. When `ADMIN_TOKEN` is set in the smoke-test process:
    - `GET /admin/login` returns 200 with the login form.
    - `POST /admin/login` with a wrong token in JSON returns 403.
    - `POST /admin/login` with the correct token in JSON returns 200 `{ok:true}`
      and a `Set-Cookie` containing `al_admin`.
    - `GET /admin` with that cookie returns 200 and contains `AuthLayer admin`.
    - `POST /admin/logout` with that cookie returns 2xx/3xx and a `Set-Cookie`
      clearing `al_admin`.
    These five checks are skipped with a clear `SKIP` when `ADMIN_TOKEN` is not
    set in the test process.
21. `GET /api/dev/outbox` matches the health endpoint's `dev_mode`: 200 in dev
    mode, 404 otherwise.

A full dev-mode run without `ADMIN_TOKEN` executes 26 checks: 21 `PASS` and 5
`SKIP` for the admin cookie-login flow.

Every run uses a fresh `smoke-<timestamp>-<random>@example.test` address, so runs do
not hit the per-email rate limit or share OTP state. There is no account deletion
endpoint, so the test user is left in the database.

The script does not print email bodies, OTP codes, session tokens, admin tokens, or
admin cookies. It prints one `PASS`, `FAIL`, or `SKIP` line per check, plus a final
summary.

## What is not covered

- **WebAuthn / passkeys.** Registration, adding a second passkey, and login require
  a browser, an authenticator, and user interaction. The script stops after the
  server issues the registration challenge. It tests only the unauthenticated 401
  behavior of `/api/passkeys/add/start` and `/api/passkeys/add/finish`; it does not
  call `/api/auth/passkey/register` or `/api/auth/passkey/login`, and does not
  complete an add-passkey ceremony.
- Authenticated endpoints that need a session cookie: session listing/revocation,
  revoke-all, passkey listing/revocation, recovery-code regeneration, step-up, and
  `/api/me` as a logged-in user. **Add-passkey, step-up, and authenticated revoke
  behavior still need a real browser session/authenticator.**
- Recovery flow (`/api/auth/recover/*`) and recovery codes.
- Real email delivery, SMTP, or outbox rendering in a browser.
- Rate-limit exhaustion. The script deliberately makes only one valid
  `/api/auth/start` call.
- CSRF/Origin enforcement. The script sends no `Origin` header; the server only
  checks Origin when it is present.
- Admin behavior beyond cookie login/view/logout: the form-encoded login path,
  cookie expiry/tampering, admin data correctness, and authenticated admin
  CSRF/Origin enforcement.
- Database migrations, persistence, concurrency, and multi-user behavior.
- Frontend behavior, JavaScript errors, accessibility, and visual layout.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | All executed checks passed. `SKIP`s are allowed. |
| `1` | Any check failed, the server was unreachable, a request timed out, or the script hit an unexpected error. |

The script fails fast: it stops at the first failed check. Earlier `PASS`/`SKIP`
lines remain visible, and the summary reports the counts.

## Expected output

A typical dev-mode run without `ADMIN_TOKEN`:

```text
AuthLayer smoke test
Base URL: http://localhost:8080

PASS  GET /healthz (DB-backed) returns 200 with ok:true - HTTP 200, ok=true (DB probe passed), dev_mode=true
PASS  GET / returns 200 and contains AuthLayer - HTTP 200, marker found
PASS  GET /style.css returns 200 and is non-empty - HTTP 200, 219 bytes
PASS  GET /app.js returns 200 and is non-empty - HTTP 200, 67 bytes
PASS  GET /api/me without a cookie is anonymous - HTTP 200, authenticated=false
PASS  Cache-Control: no-store is present on /healthz, /api/me, / and /app.js - no-store on all 4 endpoints
PASS  POST /api/auth/start rejects an invalid email - HTTP 400, error=bad_request
PASS  POST /api/auth/start accepts a unique email - HTTP 200, flow=code
PASS  GET /api/dev/outbox exposes the OTP - HTTP 200, 1 message(s), 6-digit code found
PASS  POST /api/auth/verify-code rejects a wrong code - HTTP 400, error=bad_request
PASS  POST /api/auth/verify-code rejects a non-existent user - HTTP 400, error=bad_request
PASS  POST /api/auth/verify-code accepts the real code - HTTP 200, flow=register_passkey (WebAuthn ceremony not automated)
PASS  GET /api/sessions without a cookie returns 401 - HTTP 401
PASS  POST /api/auth/stepup/start without a cookie returns 401 - HTTP 401
PASS  POST /api/auth/stepup/finish without a cookie returns 401 - HTTP 401
PASS  POST /api/sessions/revoke-all without a cookie returns 401 - HTTP 401
PASS  POST /api/passkeys/add/start without a cookie returns 401 - HTTP 401
PASS  POST /api/passkeys/add/finish without a cookie returns 401 - HTTP 401
PASS  POST /api/auth/logout without a cookie does not return 500 - HTTP 200, not 500
PASS  GET /admin without an admin cookie is denied - HTTP 404, not 200
SKIP  GET /admin/login returns 200 with the login form - ADMIN_TOKEN is not set in this process
SKIP  POST /admin/login rejects a wrong token - ADMIN_TOKEN is not set in this process
SKIP  POST /admin/login accepts the correct token - ADMIN_TOKEN is not set in this process
SKIP  GET /admin with a valid admin cookie returns the admin page - ADMIN_TOKEN is not set in this process
SKIP  POST /admin/logout clears the al_admin cookie - ADMIN_TOKEN is not set in this process
PASS  GET /api/dev/outbox behavior matches DEV_MODE - dev_mode=true, HTTP 200 with 1 message(s)

----------------------------------------
Summary: 21 passed, 0 failed, 5 skipped
Base URL: http://localhost:8080
Duration: 0.3s
Skipped checks are optional or depend on DEV_MODE/ADMIN_TOKEN.
```

With a matching `ADMIN_TOKEN`, the five admin `SKIP` lines become `PASS` lines
and the summary is 26 passed, 0 failed, 0 skipped.

When the server is not running:

```text
AuthLayer smoke test
Base URL: http://localhost:8080

FAIL  Server reachable
      request to http://localhost:8080/healthz failed (ECONNREFUSED). Is the server running?
      Start the server first; see scripts/README.md.

----------------------------------------
Summary: 0 passed, 1 failed, 0 skipped
Base URL: http://localhost:8080
Duration: 0.0s
```

Actual byte counts and durations vary. Expected totals:

| `DEV_MODE` | `ADMIN_TOKEN` in test process | Result |
| --- | --- | --- |
| `true` | unset | 21 passed, 5 skipped |
| `true` | set and matching the server | 26 passed, 0 skipped |
| `false` | unset | 18 passed, 8 skipped |
| `false` | set and matching the server | 23 passed, 3 skipped |

A `SKIP` is not a failure: the exit code stays 0 when all executed checks pass.
