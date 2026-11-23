# AuthLayer Security Review (Round 1)

> **Historical document.** This is the first review, before the security hardening wave. Many findings are fixed. See `SECURITY_REVIEW_ROUND2.md` and `SECURITY_REVIEW_ROUND3.md` for the current status. Do not use this file as the current security verdict.

**Review date:** 2026-11-23  
**Scope:** `authlayer/` Rust server (`src/`), migrations, static assets, `Cargo.toml`/`Cargo.lock`, Docker/systemd/Caddy deployment files, and the project/security documentation.  
**Review type:** Static, read-only source review. No code was modified. This report is the only file created.  
**Review basis:** Current working tree, re-checked while other work was actively editing it. The code gained rate limits, transactions, a global `Cache-Control: no-store`, an SMTP module, and a passkey-add endpoint during this review. Findings below reflect the latest snapshot I inspected; because the tree is still moving, re-check the cited lines before publishing.  
**Not a penetration test:** I did not run the server, `cargo check`, `cargo test`, `cargo audit`, Docker, Caddy, SMTP delivery, WebAuthn browser ceremonies, or exploit code. See "Not reviewed" at the end.

---

## Executive summary

The implementation has a solid foundation: 256-bit `OsRng` session tokens, SHA-256 token hashes, HMAC-SHA-256 OTP/recovery codes, constant-time comparisons for OTP/recovery/admin secrets, OTP purpose separation, conditional `used_at` updates for OTP and recovery codes, one-time removal of WebAuthn/recovery challenges, global credential-ID uniqueness, bound SQL parameters, HTML escaping, WebAuthn user verification required by `webauthn-rs` 0.6.2, transactions around the main multi-step writes, a global `Cache-Control: no-store`, a non-root Docker image, a hardened systemd unit, and a Caddy configuration with TLS/HSTS/CSP/nosniff/frame/referrer headers.

It is **not yet safe to expose as a public self-hosted v0.1**. The highest-risk problems are now:

1. **The dev outbox still publishes live OTPs** and `DEV_MODE` still auto-enables for `localhost`/loopback `APP_URL` (`config.rs:111-119`). The plaintext OTP is also still written to `outbox` even when SMTP is configured.
2. **A stolen session can add a new passkey, mint new recovery codes, and revoke the user's existing passkey without re-authentication** (`/api/passkeys/add/start|finish`, `/api/recovery/regenerate`, `/api/passkeys/{id}/revoke`). Adding a passkey gives the attacker a persistent credential that survives session expiry.
3. **Sessions are 7-day bearer tokens with no passkey binding, idle timeout, revoke-all, or cascade on passkey revocation.** Revoking a credential does not terminate the sessions created with it.
4. **The admin token is still in the query string**, and `/admin` has no rate limit, IP restriction, or access audit. The page exposes all user emails, session IPs/user-agents, and audit IPs.
5. **Recovery has no delay, notification, or credential/session revocation, and recovery codes never expire.** A leaked code plus email access is a long-lived backdoor.
6. **OTP hashes are still global (`HMAC(secret, code)`) and not bound to user/purpose/expiry**, and a placeholder/weak `OTP_SECRET` is accepted. If `OTP_SECRET` is unset, a random key is generated at each start, silently invalidating all unused recovery codes after a restart.
7. **SMTP is implemented (`email.rs`) but is not in the deployment contract**: `.env.example`, Compose, and `deploy/README.md` still default to the outbox and still say there is no email provider. A user following the provided deployment will not deliver OTPs with `DEV_MODE=false`.

Rate limiting on verification endpoints, transactions, conditional one-time updates, and `no-store` are welcome improvements, but they do not close the credential-persistence, session-revocation, recovery, admin, and deployment gaps above.

**Overall verdict:** Do not expose this build to the public internet as a production authentication service. The provided Docker/Caddy/systemd configuration mitigates some issues if used exactly as documented (`DEV_MODE=false`, `COOKIE_SECURE=true`, TLS, no published 8080, 0600 database), but the application-level controls are still insufficient for public v0.1.

---

## Findings at a glance

| ID | Severity | Finding | Public v0.1 blocker? |
|---|---|---|---|
| C-1 | Critical | Unauthenticated dev outbox / auto `DEV_MODE` exposes live OTPs | Yes for manual deployments |
| H-1 | High | Plaintext OTPs persisted in `outbox` even with SMTP | Yes |
| H-2 | Medium | OTP brute-force controls improved, but no account lockout/backoff; 6-digit code remains weak | Yes for public email OTP |
| H-3 | High | Stolen session can add a passkey, mint recovery codes, revoke credentials | Yes |
| H-4 | High | 7-day bearer sessions; no binding/idle/revoke-all/cascade | Yes |
| H-5 | High | Admin token in query string; no rate limit/IP/audit | Yes if admin enabled |
| H-6 | High | Recovery has no delay/notification/revocation; codes never expire | Yes if recovery enabled |
| H-7 | High | OTP HMAC not context-bound; weak/placeholder/random-at-restart secret | Yes |
| H-8 | High | Client IP trusts `X-Forwarded-For` first value | Yes without trusted proxy |
| H-9 | Medium | Unbounded challenge/rate-limit maps; no GC | No, but recommended |
| H-10 | High | SMTP implemented but not wired into deployment/docs; default is outbox | Yes (functional) |
| M-1 | Medium | User enumeration | No |
| M-2 | Medium | Fail-open Origin check; no CSRF token | No (modern browsers) |
| M-3 | Medium | Challenge IDs not bound to browser/session | No |
| M-4 | Medium | Counter regression accepted; clone detection missing | No |
| M-5 | Medium | Disabled status not checked at login/recovery | No (latent) |
| M-6 | Medium | Residual races and email-send/outbox ordering | No, but fix before public |
| M-7 | Medium | Success-only/best-effort audit; PII retention | No |
| M-8 | Medium | SQLite FK/WAL/timestamps/cleanup gaps | No |
| M-9 | Medium | Placeholder secret, no `__Host-`, SMTP env/TLS gaps, resource limits | Partially |
| L-1 | Low | WebAuthn/serde error leakage | No |
| L-2 | Low | Custom constant-time, panic paths, config/email/body bounds | No |
| L-3 | Low/Info | Documentation drift/stale security claims | No |
| L-4 | Low | `RP_ID` parent domain broadens passkey scope | No |
| L-5 | Low | `db_url`/Config logging can expose secrets | No |

---

## Threat model summary

**Assets:** account access (passkeys and sessions), recovery codes, user emails, session IP/user-agent, audit events, admin view, SMTP credentials, and the integrity of the login/recovery flow.

**Relevant actors:**

- Remote unauthenticated attacker (enumeration, OTP guessing, email bombing, DoS, admin token guessing).
- Attacker with access to a victim's email inbox (OTP interception, recovery initiation, phishing).
- Network attacker or malicious reverse proxy (cookie/OTP theft, header spoofing, TLS downgrade if misconfigured, SMTP MITM if TLS is disabled).
- Attacker controlling a sibling subdomain, an XSS on the auth origin, or a shared/public browser (cookie tossing, ceremony hijack, same-site CSRF).
- Attacker with a stolen session cookie or a stolen/unlocked device (bearer replay, new-passkey enrollment, recovery-code minting, passkey revocation, lockout).
- Attacker with read access to the SQLite file or a backup (emails, IPs, plaintext OTPs in outbox, OTP/recovery hashes, passkey public keys).
- Malicious or compromised administrator (admin token, database access, SMTP credentials).
- Spammer/botnet (email bombing, memory/DB growth, resource exhaustion).

**Trust boundaries:**

- Browser -> TLS reverse proxy -> Axum app. The app itself speaks plain HTTP and assumes a trusted proxy.
- App -> SQLite file/volume. The DB contains PII and, currently, plaintext OTPs in `outbox`.
- App -> email channel. Email is treated as an untrusted delivery channel, but for users without a passkey the email OTP is effectively the only bootstrap factor. SMTP TLS is configurable.
- Browser/authenticator -> WebAuthn ceremony. The RP ID/origin and challenge state are security-critical.
- Admin browser -> `/admin?token=...`. The token is a bearer secret in a URL.

**Assumptions used for severity:** TLS terminates at a trusted proxy that overwrites client-supplied forwarding headers; `APP_URL` and `RP_ID` are correct and HTTPS; the host, SQLite file, backups, and environment secrets are not already compromised; the deployment is a single process (the in-memory challenge/rate-limit state requires that); users' devices/authenticators are not already malware-compromised. If these assumptions do not hold, many findings become worse.

**Out of scope for this review:** malware on user devices, compromised authenticators, full server root compromise, supply-chain compromise, network-level DDoS, SMTP provider deliverability/DKIM/SPF, Postgres, native/CLI/SSH/broker/OIDC components, and the unimplemented frontend.

---

## Findings

### C-1 -- Critical -- Unauthenticated dev outbox can publish live OTPs; `DEV_MODE` auto-enables for loopback `APP_URL`

**Files/lines:** `src/config.rs:111-119` (`dev_mode` auto-detection); `src/routes.rs:29` and `:47` (unconditional route registration); `src/routes.rs:1163-1166` and `:1208-1211` (the only guard is `dev_mode`); `src/routes.rs:1168-1186` and `:1213-1229` (reads and renders/serializes all outbox messages); `src/routes.rs:277` and `:988` (returns the outbox link); `src/auth.rs:157-166` (writes the plaintext code into `outbox`); `migrations/0001_init.sql:61-67` (outbox table).

**Attack scenario:** A self-hoster runs the binary with `APP_URL=http://localhost:8080` behind a public tunnel/reverse proxy, or sets `DEV_MODE=true` for debugging. `dev_mode` becomes true because the `APP_URL` host is `localhost`/`127.0.0.1`/`::1` (`config.rs:111-119`). The attacker requests `GET /dev/outbox` or `GET /api/dev/outbox` with no authentication. The page/API returns the last 50 messages, including `to_email` and the plaintext `body` containing the 6-digit OTP. The attacker then calls `POST /api/auth/start` for a victim email that has no passkey and `POST /api/auth/verify-code` with the code read from the outbox, receives a WebAuthn registration challenge, and registers their own authenticator. They now have a session for the victim and, on first passkey, a fresh set of recovery codes.

**Impact:** Full account takeover for any account without a registered passkey, plus disclosure of all recent email addresses and OTPs. For accounts with passkeys, the OTP still allows the recovery email step (the attacker additionally needs a recovery code). The route has no authentication and no rate limit; the page auto-refreshes every 5 seconds (`routes.rs:1193`), continuing to leak new codes. The global `no-store` middleware (`main.rs:22-28`, `:74-76`) prevents caching but not disclosure.

**Recommended fix:** Remove the outbox routes from production builds or require an explicit, separate `DEV_OUTBOX=1` plus loopback-only binding. Never derive `dev_mode` from `APP_URL`; default to false and require `DEV_MODE=true` explicitly. Refuse to start if `dev_mode` is true while `BIND_ADDR` is non-loopback or while `APP_URL` is publicly reachable. Do not store plaintext OTPs at all in production. Gate any dev outbox behind a local-only listener and an additional local secret.

**Blocker for public v0.1:** **Yes** for manual/alternative deployments. The provided Docker Compose sets `DEV_MODE=false` (`docker-compose.yml:34`) and the systemd guide uses `DEV_MODE=false`, which mitigates the documented path, but the code default remains unsafe. This should be fail-closed in code, not only in deployment files.

---

### H-1 -- High -- Plaintext OTPs are persisted in `outbox` even when SMTP is configured

**Files/lines:** `src/auth.rs:143-167` (transaction inserts the OTP hash and then a plaintext outbox row; `format!("Your one-time code is: {code}...")` at `:141`); `src/auth.rs:169-176` (SMTP send happens after the plaintext row is committed); `migrations/0001_init.sql:61-67` (`outbox.body`); `src/routes.rs:1168-1186` and `:1213-1229` (read paths). There is no cleanup/retention job for `outbox` anywhere in `src/`.

**Attack scenario:** An attacker obtains a read-only copy of `authlayer.db` or a backup (misconfigured volume permissions, stolen backup, snapshot, hosting-provider access). The outbox contains plaintext OTPs for every recent `start` and `recover_start`, including codes that are still within the 10-minute TTL. This is true even when `EMAIL_PROVIDER=smtp`: the outbox row is written unconditionally before the email is sent. The attacker uses `POST /api/auth/verify-code` for a non-passkey account, or `POST /api/auth/recover/verify-email` for a passkey account, within the TTL. Backups include the SQLite database (`deploy/README.md:301-303`), so backup theft is a realistic path.

**Impact:** Account takeover for accounts without passkeys; recovery-email verification for passkey accounts (still requires a recovery code); disclosure of email addresses and account activity. The plaintext OTP defeats the purpose of hashing OTPs in `otp_codes`.

**Recommended fix:** Do not persist the OTP plaintext when a real email provider is configured. Send it directly to the provider and store only the HMAC hash. If a dev outbox is needed, keep it in memory or encrypt it with an ephemeral key and purge it after first read/TTL. Add a retention job that deletes outbox rows older than the OTP TTL. Never include OTP plaintext in backups.

**Blocker for public v0.1:** **Yes.** This is a direct secret-at-rest problem and is especially important given the documented backup procedure.

---

### H-2 -- Medium -- OTP brute-force controls improved, but there is no account lockout/backoff; 6-digit codes remain weak

**Files/lines:** `src/routes.rs:211-214` (`start`: 5/min/email + 30/min/IP); `src/routes.rs:291-304` (`verify-code`: 10/min/email + 20/min/IP); `src/routes.rs:370-377` (`passkey-register`: 20/min/IP); `src/routes.rs:490-497` (`passkey-login`: 20/min/IP); `src/routes.rs:736-743` and `:800-802` (passkey add: 20/min/IP); `src/routes.rs:953-958` (`recover-start`: 3/5min/email, no IP); `src/routes.rs:1002-1015` (`recover-verify-email`: 5/min/email + 10/min/IP); `src/routes.rs:1070-1095` (`recover-verify-code`: 10/min/IP + 5/min/email); `src/auth.rs:210-225` (attempt check and increment; OTP `used_at` is now conditional, but attempts are not atomic).

**Attack scenario:** A 6-digit OTP is about 20 bits. The server allows 5 wrong attempts per code (`auth.rs:210-211`) and then increments `attempts` on each wrong guess (`auth.rs:221-225`). The attacker can request a new code (5/min per email for login, 3/5min for recovery), and the new code has `attempts=0`. Verification is now rate-limited to 10/min per email for login and 5/min per email for recovery, so the old unlimited-guessing problem is gone. However, there is no account-level lockout or exponential backoff, and the per-code attempt limit resets with each new code. At 10 guesses/min, a 1,000,000-code space takes roughly 48 days for a 50% chance at a fixed email (about 69 days to exhaust the space), and the attacker can keep trying indefinitely. A concurrent burst can still exceed 5 attempts per code because the check and increment are not atomic. IP limits are keyed to a spoofable header (H-8), though the per-email limit still applies. `recover-start` has no IP limit and can be used for email bombing; alias addresses (`user+1@...`) are not canonicalized (L-2).

**Impact:** Targeted online brute force remains feasible over weeks, especially against accounts without passkeys; email bombing/abuse; noisy probing. The rate limits materially reduce the risk compared with the earlier build, but 6 digits + no account lockout is not a strong public control.

**Recommended fix:** Add an account-level failed-attempt counter with exponential backoff and temporary lockout across codes; make the per-code attempt reservation atomic (`UPDATE ... WHERE attempts < 5` and check `rows_affected`); consider 8-digit OTPs; add CAPTCHA/proof-of-work on code issuance; keep per-email and per-IP limits; add edge/proxy rate limits; alert on repeated failures. Do not let a new code reset the account-level failure count without a cooldown.

**Blocker for public v0.1:** **Yes** for public email OTP onboarding with 6 digits and no account lockout. At minimum, add account-level backoff and edge limits.

---

### H-3 -- High -- A stolen session can add a new passkey, mint recovery codes, and revoke credentials without re-authentication

**Files/lines:** `src/routes.rs:728-789` (`POST /api/passkeys/add/start`: only `require_session`, returns a WebAuthn registration challenge); `src/routes.rs:791-872` (`POST /api/passkeys/add/finish`: only `require_session`, inserts a new passkey); `src/routes.rs:923-944` (`POST /api/recovery/regenerate`: only `require_session`, returns 8 new recovery codes); `src/routes.rs:874-921` (`POST /api/passkeys/{id}/revoke`: only `require_session`, last-credential check, delete); `src/routes.rs:671-700` (`POST /api/sessions/{id}/revoke`: only `require_session`); `src/auth.rs:362-400` (`create_recovery_codes` deletes all unused codes, then inserts 8 new ones).

**Attack scenario:** An attacker steals a session cookie (XSS on the origin, malicious extension, shared browser, cookie/log leak, or a stolen device). They call `POST /api/passkeys/add/start` and `POST /api/passkeys/add/finish` with their own authenticator, registering a new passkey for the victim. No re-authentication is required beyond the stolen session. If they can run WebAuthn at the RP origin (XSS, a browser they control at `https://auth.example.com`, or a browser/extension that can execute at that origin), they obtain a persistent credential that survives session expiry and session revocation. They can also call `POST /api/recovery/regenerate` to receive 8 new recovery codes, deleting the victim's existing unused codes, and `POST /api/passkeys/{id}/revoke` to delete the victim's only passkey once the recovery count is nonzero. The victim can re-enroll via email OTP if they still control the inbox, but the attacker keeps the stolen session and may have minted recovery codes or enrolled a passkey.

**Impact:** Persistent account takeover from a bearer-session theft, plus credential/recovery lockout. The new `passkey_add` endpoint turns a 7-day cookie theft into a long-lived new credential if the attacker can complete the WebAuthn ceremony at the origin. The recovery regeneration and passkey revocation paths need only HTTP requests with the stolen cookie.

**Recommended fix:** Require a fresh WebAuthn assertion (step-up) for adding a passkey, `/api/recovery/regenerate`, passkey revocation, revoking other sessions, and any future email/credential change. Bind the step-up to the session and a short TTL. Notify the user by email on new passkey, recovery-code regeneration, passkey revocation, and recovery. Revoke all sessions when a credential is added/revoked. Rate-limit these endpoints and audit failures.

**Blocker for public v0.1:** **Yes** for a security-sensitive passwordless service. At minimum, add step-up for passkey add and recovery regeneration, and revoke sessions on credential changes.

---

### H-4 -- High -- Sessions are 7-day bearer tokens with no passkey binding, no idle timeout, no revoke-all, and no cascade on passkey revocation

**Files/lines:** `src/auth.rs:252-281` (session creation, 32-byte token, SHA-256 hash, fixed expiry); `src/auth.rs:291-337` (validation checks `revoked_at`, `users.status`, `expires_at`; updates `last_seen_at`; no idle check, no rotation, no binding); `src/routes.rs:140-148` (cookie: `HttpOnly`, `SameSite=Lax`, conditional `Secure`, no `__Host-`); `src/routes.rs:874-921` (passkey revocation does not revoke sessions); `src/routes.rs:923-944` (recovery regeneration does not revoke sessions); `src/routes.rs:671-700` (only per-session revoke, no revoke-all); `src/config.rs:125-133` (`SESSION_TTL_DAYS` default 7). The docs acknowledge the bearer/no-binding/no-idle/no-revoke-all gaps at `docs/IMPLEMENTATION.md:436-444` and `:604-608`.

**Attack scenario:** An attacker steals a session cookie (XSS, malicious extension, shared computer, proxy/log leak, stolen laptop). Because the cookie is a bearer token, it works from any IP/user-agent until `expires_at` (7 days). The legitimate user discovers a stolen/lost passkey and revokes it; the attacker's existing session remains valid because sessions are not linked to credentials and passkey revocation does not touch them. The user can revoke individual sessions in the dashboard, but there is no "sign out everywhere" and no idle timeout. If the user only revokes the passkey, the attacker keeps access for up to 7 days. The new passkey-add endpoint (H-3) can also create a credential without revoking any existing session.

**Impact:** Session hijack persistence; revocation is incomplete; a stolen cookie is equivalent to full account access. If a passkey is compromised and revoked, the attacker's session survives. This is a serious incident-response failure for a passwordless product whose value proposition includes device/credential control. Session fixation is largely mitigated because every login mints a new random token (`auth.rs:259-280`), but concurrent sessions are unlimited and logout revokes only the current session; the remaining fixation-adjacent risk is cookie tossing because the cookie lacks `__Host-`. Session lookup is by indexed `token_hash` equality (`auth.rs:291-301`), not a constant-time compare; the token is 256-bit random, so this is not practically exploitable, but the same pattern must not be reused for low-entropy tokens.

**Recommended fix:** Store a `passkey_id`/credential binding and/or device binding on sessions; revoke all sessions for a credential when it is added/revoked; add "revoke all sessions" and "sign out everywhere"; enforce an idle timeout (docs recommend 24h) in `session_from_token`; rotate the session token on privilege changes/step-up; shorten the default TTL (e.g., 24h-3 days) and document the tradeoff; add `__Host-` and `Secure` enforcement (see M-9); consider DPoP/DBSC in v0.2 as planned.

**Blocker for public v0.1:** **Yes** for passkey revocation/add to be meaningful. The bearer/no-binding gap is acknowledged as a v0.1 limitation; if it is accepted, the TTL must be much shorter and step-up/revoke-all controls added.

---

### H-5 -- High -- Admin token is a bearer secret in a query string; admin has no rate limit, IP restriction, or access audit

**Files/lines:** `src/routes.rs:30` (`GET /admin` route); `src/routes.rs:80-83` (`AdminQuery { token: Option<String> }`); `src/routes.rs:1234-1248` (token read from query and compared with `auth::constant_time_eq` -- the comparison itself is good); `src/routes.rs:1250-1269` (queries all users, sessions, audit data); `src/routes.rs:1314-1336` (HTML with meta-refresh every 10s); `deploy/.env.example:43-48` (query-string warning). The global no-store middleware (`main.rs:22-28`, `:74-76`) now prevents caching.

**Attack scenario:** The admin opens `/admin?token=<64-hex>` in a browser. The token is stored in browser history, possibly in screenshots, and can be exposed to reverse-proxy/access logs, browser extensions, or a `Referer` header if the page ever links to another same-origin URL. Anyone who obtains the token can load the admin page and read all user emails, user IDs, session IPs/user-agents, and audit IPs. There is no rate limit, no IP allowlist/VPN requirement, no audit event for admin access, and no token expiry/rotation. If the token is weak (the config accepts any non-empty string; `src/config.rs:121-123`), it can be guessed. Caddy does not log by default, but the application's `TraceLayer` will log the URI at debug level (`src/main.rs:76`), and the docs warn about `RUST_LOG=debug` (`deploy/README.md:360-361`).

**Impact:** Disclosure of all user PII and session metadata to anyone with the URL; reconnaissance for targeted attacks; no mutation capability in v0.1, so not direct account takeover. The token is effectively a permanent global read secret.

**Recommended fix:** Move the admin credential out of the query string: use an `Authorization: Bearer` header over a localhost/VPN-only admin listener, or a separate admin session cookie with `HttpOnly`, `Secure`, `SameSite=Strict`, and a short TTL. Keep constant-time comparison. Add per-IP and global rate limiting/lockout, bind admin to loopback or an allowlisted network, require TLS, add an audit event for every admin view and failed attempt, support token rotation/expiry, and add audited admin revocation/disable actions for incident response (currently only the user dashboard can revoke).

**Blocker for public v0.1:** **Yes if `/admin` is enabled.** It is disabled when `ADMIN_TOKEN` is empty (default), which is the safer choice; leave it disabled for public v0.1 or fix the handling first.

---

### H-6 -- High -- Recovery flow lacks delay/notification/credential revocation; recovery codes never expire

**Files/lines:** `src/routes.rs:946-990` (`recover_start`: email limit only, `user_not_found` on unknown email, creates `purpose="recovery"` OTP); `src/routes.rs:992-1060` (`recover_verify_email`: verifies OTP, creates 10-minute recovery challenge with email); `src/routes.rs:1062-1161` (`recover_verify_code`: verifies recovery code, creates passkey registration challenge); `src/routes.rs:435-439` (recovery codes generated on first passkey); `src/routes.rs:923-944` (`regenerate` replaces codes); `src/auth.rs:362-431` (create/verify recovery codes, no expiry); `migrations/0001_init.sql:50-56` (`recovery_codes` has no `expires_at`); `docs/IMPLEMENTATION.md:410-418` acknowledges that recovery does not revoke passkeys/sessions, has no delay, and recovery codes do not expire.

**Attack scenario:** An attacker who obtains a recovery code (from a backup, a password manager, an email archive, a screenshot, or a previous device compromise) and can receive/read the victim's email OTP starts recovery. The server verifies the code and immediately issues a new passkey registration challenge; there is no delay, no notification to the legitimate user, no requirement to confirm from an existing passkey, and no revocation of old sessions or passkeys. The attacker registers a new passkey and gets a session. The victim's existing passkey still works, so the UI may not visibly change; the attacker now has a persistent credential. Recovery codes have no expiry and are only invalidated when used or regenerated.

**Impact:** Account takeover/persistence from a leaked recovery code plus email access; the legitimate user may not notice. This is a deliberate fallback, but the lack of notification/delay/revocation turns a single leaked code into a long-lived backdoor.

**Recommended fix:** Notify the user by email on recovery start, recovery success, and recovery-code regeneration. Add a delay (e.g., 24h) or a second confirmation channel for recovery from a new device/location. On successful recovery, revoke all sessions and optionally all old passkeys, or mark the new passkey as "recovered" and require the user to review it. Give recovery codes an expiry (e.g., 12 months), one-time atomic use, and a per-user attempt limit. Require step-up to regenerate codes. Audit failed recovery-code attempts and alert after a threshold.

**Blocker for public v0.1:** **Yes** if recovery is enabled. The docs already list this as a P0 item; it should be fixed before public use.

---

### H-7 -- High -- OTP HMAC is global and not bound to user/purpose/expiry; weak, placeholder, or random-at-start `OTP_SECRET`

**Files/lines:** `src/auth.rs:39-43` (`hmac_hex`), `:137` (`hmac_hex(secret, code.as_bytes())`), `:220` (same on verify); `src/auth.rs:74-76` (recovery HMAC also over normalized code only); `src/config.rs:90-102` (`OTP_SECRET` is SHA-256 of any non-empty env string, or random if unset); `deploy/.env.example:35-41` (`OTP_SECRET=CHANGE_ME_generate_with_openssl_rand_hex_32`); `docker-compose.yml:29-31` (Compose requires non-empty but accepts the placeholder); `README.md:173` claims the OTP HMAC is bound to `user_id + purpose`; `docs/IMPLEMENTATION.md:106-107` shows the actual `HMAC(secret, code_ascii)` construction.

**Attack scenario:** A self-hoster copies `.env.example` without replacing the placeholder, or uses a low-entropy/human-chosen `OTP_SECRET` (the dev examples use `dev-secret-change-me`). An attacker obtains a database copy/backup. The OTP hash is `HMAC-SHA256(secret, 6-digit-code)` with no user/purpose/expiry context. For each candidate code (only 1,000,000 possibilities), the attacker computes the HMAC and matches it against `otp_codes.code_hash`. Identical codes across users produce identical hashes. If the secret is the known placeholder or guessable, the attacker can reverse all unexpired OTPs and use them to take over accounts without passkeys (or pass recovery email for passkey accounts). Even with a strong secret, the lack of context enables precomputation and cross-user hash equality; a slow KDF/per-record salt is not used. Separately, if `OTP_SECRET` is unset, `config.rs:97-101` generates a random key at each start; every pending OTP and every unused recovery code hashed with the old key becomes unusable after a restart. Compose requires the variable, but a direct `cargo run` does not.

**Impact:** Mass OTP recovery from a DB/backup leak when the secret is weak/known; account takeover for non-passkey accounts; documentation gives a false assurance that the hash is bound to user/purpose. The OTP is only 20 bits, so the HMAC's security depends heavily on the secret and on preventing offline precomputation. If the secret is random-at-start, a restart silently invalidates all unused recovery codes, which is a recovery/availability failure.

**Recommended fix:** Require a high-entropy `OTP_SECRET` (e.g., 32 random bytes; reject the known placeholder, short strings, and dev examples at startup). Use separate derived keys for OTP and recovery (`HKDF`/HMAC with `"otp"`/`"recovery"` context). Bind the OTP hash to at least `user_id`, `purpose`, `otp_id`/random salt, and expiry: `HMAC(secret, user_id || purpose || otp_id || code)`. Consider Argon2id or a server-side pepper for a 6-digit secret if offline guessing is in scope. Add key versioning/rotation so a secret change does not silently invalidate all recovery codes. Make the application refuse to start in production without a persistent high-entropy `OTP_SECRET`; do not rely on Compose interpolation alone.

**Blocker for public v0.1:** **Yes** for the startup secret validation and hash context. The placeholder in `.env.example` is a live footgun.

---

### H-8 -- High -- `client_ip` blindly trusts `X-Forwarded-For`/`X-Real-IP` and takes the first value

**Files/lines:** `src/auth.rs:446-458` (`client_ip`: first `X-Forwarded-For` value, else `X-Real-IP`); used for rate limits and audit/session IPs at `src/routes.rs:208-214`, `:291-304`, and throughout the handlers; `src/main.rs:83` uses `axum::serve(listener, app)` without `ConnectInfo`/peer address. The provided Caddyfile sets `header_up X-Real-IP {remote_host}` and comments that Caddy overwrites `X-Forwarded-For` (`deploy/Caddyfile:32-42`); the deployment docs warn about direct exposure and CDN/trusted proxies (`deploy/README.md:386-390`).

**Attack scenario:** If the app is exposed directly, behind a proxy that preserves client-supplied `X-Forwarded-For`, or behind a CDN without proper `trusted_proxies`, the attacker sends `X-Forwarded-For: 203.0.113.7` (or a new value per request). `client_ip` takes the first value, so every request appears to come from a different IP. The IP limits on `start`, `verify-code`, passkey login/register/add, and recovery are bypassed, audit/session IPs are forged, and IP-based investigation is poisoned. Email-based limits remain. If the app is behind the provided Caddy and Caddy overwrites XFF as documented, this is mitigated; I did not run Caddy to verify the exact version behavior.

**Impact:** Rate-limit bypass, audit-log integrity loss, forged session metadata, and easier email bombing/DoS. If an operator exposes `BIND_ADDR=0.0.0.0:8080` directly (the Dockerfile uses 0.0.0.0 inside the container; only `expose`, not `ports`, in Compose), this becomes directly exploitable.

**Recommended fix:** Use the actual socket peer address via `ConnectInfo<SocketAddr>` and `into_make_service_with_connect_info`. Only trust forwarding headers when the direct peer is in a configured trusted-proxy CIDR list; parse the header from the trusted end (rightmost untrusted hop), validate it as an IP, and reject malformed values. Make the Caddy/edge behavior explicit and fail closed if no trusted proxy is configured. Do not use the first (client-controlled) XFF value.

**Blocker for public v0.1:** **Yes** for deployments not using the provided Caddy (or using a CDN/another proxy). The provided Caddy mostly mitigates it, but the application should not rely on an external component for this security decision.

---

### H-9 -- Medium -- Unbounded in-memory challenge and rate-limit maps are never garbage-collected

**Files/lines:** `src/state.rs:38-41` (three `HashMap` challenge stores); `src/state.rs:59-76` (`RateLimiter` `HashMap<String, Vec<Instant>>`); insertion points at `src/routes.rs:226-234` (auth challenge), `:334-342` (registration challenge), `:765-773` (passkey-add registration challenge), `:1036-1044` (recovery challenge), `:1136-1144` (registration challenge from recovery). Entries are removed only when the matching ceremony is completed (`routes.rs:379-384`, `:499-504`, `:806-820`, `:1097-1102`); expired entries are not swept. The rate-limiter map keeps one entry per unique email/IP key forever; `retain` prunes timestamps only for the key being checked (`state.rs:69`). The docs acknowledge the missing GC at `docs/IMPLEMENTATION.md:174-180`.

**Attack scenario:** An unauthenticated attacker enumerates emails with passkeys (see M-1), then repeatedly calls `POST /api/auth/start` for those emails, or uses many unique emails/IPs if forwarding headers are spoofable (H-8). Each call inserts an `AuthChallenge` containing a `PasskeyAuthentication` state, and each unique `start:email`/`start:ip` key adds a `Vec<Instant>` to the rate limiter. Nothing evicts expired challenges or empty rate-limit keys. With enough requests, memory grows until the process is OOM-killed. The documented Caddy config does not add a global rate limit.

**Impact:** Remote denial of service (process crash/OOM), degraded availability, and loss of in-memory WebAuthn ceremonies. The attack is unauthenticated; the challenge map is only populated for accounts with passkeys, but the rate-limiter map is populated by any email.

**Recommended fix:** Cap each map at a maximum size and evict the oldest/expired entries; run a periodic `tokio` cleanup task that removes entries past `expires_at` and empty/old rate-limit keys; use a TTL cache/LRU; add a global per-IP and per-process request limit; use a persistent/shared store for multi-instance deployments (not v0.1). Consider storing only a compact challenge handle server-side and keeping the WebAuthn state in a bounded store.

**Blocker for public v0.1:** **No, but recommended before public exposure.** It becomes High if the app is directly exposed or forwarding headers are spoofable.

---

### H-10 -- High -- SMTP exists in code but is not wired into the deployment contract; default is still the outbox

**Files/lines:** `src/email.rs:17-114` (SMTP/Outbox `EmailSender`, TLS modes, mailbox parsing, timeout); `src/config.rs:135-191` (`EMAIL_PROVIDER` defaults to `outbox`; SMTP settings are only read when `smtp`); `src/main.rs:58-63` (constructs the sender); `src/auth.rs:169-176` (send failure returns 500 after the OTP/outbox commit); `.env.example` has no `EMAIL_PROVIDER`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, or `SMTP_TLS` lines; `docker-compose.yml:21-38` passes no SMTP environment; `deploy/README.md:11-17` and `:420` still say there is no email provider; `README.md:34-36` says the same.

**Attack scenario / operational impact:** A user follows `.env.example`/Compose, sets `DEV_MODE=false`, and deploys. `EMAIL_PROVIDER` defaults to `outbox`, so `EmailSender::Outbox` returns `Ok(())` without sending anything. The OTP is written to the outbox table, which is not exposed in production, so users cannot receive codes and onboarding/recovery is non-functional. The operator may be tempted to set `DEV_MODE=true`, which triggers C-1. If they discover the undocumented SMTP variables and set `SMTP_TLS=none`, the config allows it and only warns when credentials are present (`config.rs:160-171`, `email.rs:44-70`), so OTPs (and credentials) can traverse the network in cleartext.

**Impact:** Production onboarding is broken under the documented deployment; operational pressure to expose the dev outbox; possible cleartext OTP/SMTP credential exposure with `SMTP_TLS=none`. This is a functional/availability blocker, not a remote code-execution issue.

**Recommended fix:** Add the complete SMTP/`EMAIL_PROVIDER` contract to `.env.example`, Compose, systemd docs, and `deploy/README.md`; default production to a real provider or fail startup if `EMAIL_PROVIDER=outbox` while `dev_mode=false` and a public URL is configured. Reject `SMTP_TLS=none` in production or when credentials are set; require TLS (or a localhost relay). Add SMTP retry/backoff, delivery status, and DKIM/SPF guidance. Do not write plaintext OTPs to the outbox when using SMTP (H-1).

**Blocker for public v0.1:** **Yes, functional blocker.** The code has SMTP, but the provided deployment does not expose it and the docs still say email is unavailable.

---

### M-1 -- Medium -- User enumeration through `user_not_found`, `use_passkey`, and `flow: "passkey"`

**Files/lines:** `src/routes.rs:244-248` (`start` returns `flow: "passkey"` for an existing user with a passkey; `flow: "code"` otherwise); `src/routes.rs:306-313` (`verify_code` returns `user_not_found` or `use_passkey` before verifying the OTP); `src/routes.rs:960-962` (`recover_start` returns `user_not_found` for an unknown email); `src/routes.rs:1017-1019` (`recover_verify_email` returns `user_not_found`).

**Attack scenario:** An attacker submits a list of emails to `/api/auth/start`: a `passkey` flow reveals that the account exists and has a passkey; a `code` flow is ambiguous (new or existing non-passkey). `/api/auth/recover/start` directly distinguishes existing accounts (`200`) from unknown (`400 user_not_found`). `/api/auth/verify-code` reveals `use_passkey` without requiring a valid code. The attacker can build a list of registered accounts and know which are protected by passkeys (harder targets) versus OTP-only (easier targets), then target phishing/email bombing.

**Impact:** Privacy loss; targeted phishing and account enumeration; aids OTP brute force and recovery attacks. Not a direct takeover by itself.

**Recommended fix:** Make responses uniform: always return a generic `200` from `recover/start` and send email only if the account exists (with equalized timing); do not reveal `use_passkey` until after OTP verification; return a generic "if the account exists, a code was sent" message; avoid distinct error strings for unknown users. Add rate limits and monitoring for enumeration patterns.

**Blocker for public v0.1:** **No**, but easy to fix and should be done before broad public exposure.

---

### M-2 -- Medium -- CSRF relies on a fail-open `Origin` check and `SameSite=Lax`; no CSRF token

**Files/lines:** `src/routes.rs:176-184` (`check_origin` only compares if the `Origin` header is present; if absent, it returns `Ok(())`); `src/routes.rs:140-148` (session cookie `SameSite=Lax`, `HttpOnly`, conditional `Secure`); all state-changing handlers call `check_origin`, but there is no CSRF token. `scripts/README.md:123-124` explicitly notes that the smoke test sends no `Origin` header and the server only checks when present.

**Attack scenario:** Modern browsers send `Origin` on cross-site POSTs and `SameSite=Lax` does not send the session cookie on cross-site POST, so the common CSRF path is blocked. Residual paths: a malicious same-site sibling subdomain (same-site cookie is sent; if an old browser/WebView omits `Origin`, the fail-open check passes), a client that can omit `Origin`, or a future GET endpoint with side effects. If the attacker can send a state-changing request with the cookie, they can force logout, add/revoke passkeys, revoke sessions, or regenerate recovery codes. The JSON content-type requirement blocks classic form-based CSRF for JSON endpoints; `logout` has no body but is still POST.

**Impact:** Limited in modern browsers, but the intended control is incomplete. A same-site subdomain takeover/XSS or a legacy client could perform authenticated actions. This is a defense-in-depth gap, not currently a trivial remote CSRF.

**Recommended fix:** Reject state-changing requests when `Origin` is missing (do not fail open); validate `Origin`/`Referer` and `Sec-Fetch-Site` (`same-origin`/`same-site` allowlist); add a double-submit or synchronizer CSRF token bound to the session and require it on all cookie-authenticated POSTs; consider `SameSite=Strict` for the session cookie; never add state-changing GETs.

**Blocker for public v0.1:** **No** if all mutations remain POST+JSON and the app is used in modern browsers, but it should be fixed before v1.0 and before adding any GET mutation.

---

### M-3 -- Medium -- WebAuthn/recovery challenge IDs are bearer-like and not bound to the browser/session

**Files/lines:** `src/routes.rs:226-234` (auth challenge ID returned to the client); `src/routes.rs:334-342` (registration challenge ID returned); `src/routes.rs:1036-1044` (recovery challenge ID returned); `src/routes.rs:1136-1144` (registration challenge ID returned after recovery); `src/state.rs:14-30` (challenge structs contain `user_id`, state, expiry; recovery also stores email); `src/routes.rs:806-820` (the new passkey-add finish correctly checks that the challenge user matches the session); `docs/IMPLEMENTATION.md:155-157` acknowledges that general challenge IDs are not bound to a cookie, IP, or User-Agent.

**Attack scenario:** The challenge ID is a UUID v4 (unguessable), but it is returned in JSON and is the sole handle for finishing the ceremony. If it leaks through XSS, a shared/public browser, a proxy/log that records response bodies, or a malicious extension, an attacker who can execute WebAuthn at the legitimate RP origin (or who controls the browser) can finish registration with their own authenticator for the challenge's `user_id`. For login, the attacker also needs the user's authenticator; for registration/recovery, a leaked challenge plus the ability to run `navigator.credentials.create` at the RP origin can register a new credential. The challenge is bound to the user server-side and is removed before verification (good), and TTLs are 2-10 minutes (good), but it is not bound to the client that started the ceremony. The new passkey-add endpoint is a partial improvement: it binds the challenge to the session user at finish, but it is still a bearer challenge ID for the select/remove step.

**Impact:** Ceremony hijack/account takeover if the challenge ID leaks and the attacker can act at the RP origin; more likely with an XSS on the auth origin (the app does not set CSP itself; Caddy adds CSP only when used). Without XSS/origin access, the WebAuthn ceremony itself still requires the legitimate origin and an authenticator.

**Recommended fix:** On ceremony start, set a short-lived `HttpOnly`, `Secure`, `SameSite=Strict` cookie containing a random ceremony token (separate from the challenge ID), store the challenge under that token, and require the cookie at finish. Bind the ceremony to the session/user and optionally to the client IP/UA (as a risk signal, not sole auth). Keep one-time removal and short TTLs. Add a CSP at the app layer for direct deployments.

**Blocker for public v0.1:** **No**, but fix before v1.0 or before relying on the frontend/XSS surface.

---

### M-4 -- Medium -- Credential counter regression is accepted; cloned-authenticator detection is not enforced

**Files/lines:** `src/routes.rs:533-548` (`passkey.update_credential(&result).unwrap_or(false)`: if it returns `Some(false)` because the counter did not increase, the code still creates a session and only updates `last_used_at`); `webauthn-rs` 0.6.2 `src/interface.rs:87-108` documents that `Some(false)` means the credential was not updated (counter not greater / no backup-state change); `docs/IMPLEMENTATION.md:331-332` describes updating only when `true`.

**Attack scenario:** An attacker clones a passkey/authenticator (or copies a syncable passkey) and authenticates. The assertion counter is equal to or lower than the stored counter. `update_credential` returns `Some(false)`; the application treats that as success and issues a session. The server never rejects a counter regression, so it cannot detect this class of clone/replay. Synced passkeys commonly have counter 0 and are legitimately cloned by design, so a blanket rejection can break users; the issue is the lack of policy/audit, not necessarily a hard reject for counter 0.

**Impact:** Cloned-credential detection is effectively absent; a cloned authenticator with a non-increasing counter is accepted. The practical impact depends on whether the credential is device-bound and whether an attacker can clone it.

**Recommended fix:** Inspect `AuthenticationResult::counter()` and `needs_update()`. If the stored counter is greater than 0 and the asserted counter is <= stored, reject the assertion, audit it, and consider revoking/flagging the credential. If the stored/asserted counter is 0 (synced passkey), accept per an explicit policy and log it. Add an admin/audit signal for counter anomalies.

**Blocker for public v0.1:** **No**; document the synced-passkey policy. Fix before v1.0 for higher-assurance deployments.

---

### M-5 -- Medium -- Disabled/non-active users are not checked at login, registration, or recovery entry points

**Files/lines:** `src/auth.rs:307-312` checks `users.status != "active"` only when validating an existing session; `src/routes.rs:306-322` (`verify_code`), `:425-440` (`passkey_register` creates a session), `:550-557` (`passkey_login` creates a session), `:960-962` (`recover_start`), `:1017-1021` (`recover_verify_email`), `:1108-1128` (`recover_verify_code`), `:745-757` (`passkey_add_start` uses a session) do not check status. The only status value currently written is `'active'` (`src/auth.rs:107-109`), and there is no admin status-change endpoint, so this is currently latent.

**Attack scenario:** If a future/admin or manual DB operation sets `users.status='disabled'`, the user can still request OTPs, register a new passkey, add a passkey, and receive a session cookie. `session_from_token` will reject the cookie on subsequent requests because status is not active, but the passkey and recovery codes are persisted. If the account is later re-enabled, the newly registered passkey remains. Recovery can also be initiated for a disabled account. This violates the intended account-status control and complicates incident response.

**Impact:** Policy bypass/latent account takeover after re-enable; disabled users can still modify credentials. Not currently exploitable because no status-change path exists, but the invariant is not enforced.

**Recommended fix:** Check `users.status == "active"` in every authentication/registration/recovery entry point and return a generic error. Do not issue a session for a non-active user. Audit status-based rejections. If status changes are added, revoke all sessions/passkeys/recovery codes on disable.

**Blocker for public v0.1:** **No** currently, but fix before adding account lifecycle/admin status actions.

---

### M-6 -- Medium -- Residual races and email-send/outbox ordering; some transactions were added but not all invariants are atomic

**Files/lines:** `src/auth.rs:143-167` (OTP+outbox transaction; good), `:169-176` (SMTP send after commit; failure leaves OTP/outbox), `:210-225` (attempt check/increment still non-atomic), `:362-371` and `:373-400` (recovery-code delete/insert transaction; good), `:402-431` (recovery-code use now conditional; good); `src/routes.rs:411-440` (passkey insert + session + recovery codes in a transaction; good); `src/routes.rs:893-905` (revoke-passkey count then delete; still racy); `src/routes.rs:848-859` (passkey-add insert is a single statement; no multi-step transaction needed). `ensure_user` is race-safe via `ON CONFLICT` (`auth.rs:101-125`).

**Attack scenario:** Concurrent requests can still make more than 5 OTP guesses on one code because multiple requests pass `attempts >= 5` before the increments commit. Two concurrent `revoke_passkey` requests when `passkeys=2` and `recovery=0` can both see 2 and delete, leaving 0 credentials and locking the user out. A SMTP send failure after the OTP/outbox commit returns 500 but leaves a usable OTP row and a plaintext outbox row; the user may retry, and the old code remains latest until a new one is issued. The recovery-code delete/insert and conditional use are now transactional/atomic, which is an improvement.

**Impact:** Weakened attempt limits; possible lockout; orphaned OTP/outbox rows on SMTP failure. Not a direct remote takeover without additional access, but these are core security invariants.

**Recommended fix:** Make the OTP attempt reservation atomic (`UPDATE ... WHERE attempts < 5` and check `rows_affected`). Wrap the last-credential count/delete in an immediate transaction or enforce the invariant with a DB constraint. Decide whether to send email before or after committing; if after, record delivery status and avoid leaving a usable code when delivery fails (or allow retry idempotently). Add concurrency tests.

**Blocker for public v0.1:** **No** for basic operation, but fix before public if one-time/attempt guarantees are part of the security claim.

---

### M-7 -- Medium -- Audit logging is success-only and best-effort; PII retention is indefinite

**Files/lines:** `src/db.rs:27-47` (`audit` discards errors with `let _ = ...`); route audits only on success (`routes.rs:235-243`, `:264-272`, `:344-352`, `:442-450`, `:559-567`, `:581-589`, `:684-692`, `:910-918`, `:933-941`, `:975-983`, `:1046-1054`, `:1146-1154`); failed OTP/recovery/passkey/admin attempts and rate-limit/CSRF rejections are not audited; `migrations/0001_init.sql:69-77` stores `user_id`, `ip`, `user_agent`, `metadata` with no retention; `outbox` also stores PII/plaintext OTPs indefinitely.

**Attack scenario / impact:** An attacker can brute force OTPs/recovery codes, probe admin tokens, or enumerate emails without creating an audit trail. If the DB has an issue, audit writes fail silently. User emails, full IPs, and user agents are retained indefinitely, creating privacy/compliance risk and increasing the impact of a DB leak. There is no tamper-evidence; a DB administrator can delete audit rows.

**Recommended fix:** Audit failed authentication/recovery/passkey/admin attempts and rate-limit/CSRF rejects; include a result/reason code without secrets. Do not silently discard audit failures for security events; at least log to stderr/metrics and consider failing closed for high-value events. Add a retention policy and cleanup job (e.g., 90-365 days), minimize/truncate IPs if full IPs are not required, and document an immutable/off-host audit sink for production. Purge expired OTP/outbox rows.

**Blocker for public v0.1:** **No**, but needed for incident response and privacy before v1.0.

---

### M-8 -- Medium -- SQLite hardening is incomplete: foreign keys, WAL/busy timeout, text timestamps, cleanup

**Files/lines:** `src/db.rs:8-21` (no `PRAGMA foreign_keys=ON`, no `journal_mode=WAL`, no explicit `busy_timeout`; max 5 connections); `migrations/0001_init.sql:10`, `:24`, `:37`, `:52` (`REFERENCES ... ON DELETE CASCADE` but no enforcement); `src/routes.rs:617-626` and `:639-650` (SQL string comparisons on RFC3339 `expires_at`); `docs/IMPLEMENTATION.md:127-132` acknowledges RFC3339 string comparison/foreign-key concerns, and `:621` acknowledges missing WAL/busy timeout.

**Attack scenario / impact:** With foreign keys off, `ON DELETE CASCADE` is not enforced; if account deletion is added, orphaned OTP/passkey/session/recovery rows remain. Without WAL/busy timeout, concurrent writes can return `database is locked` and surface as 500s under load. Text timestamps with variable fractional seconds can make SQL comparisons (used for counts/lists) slightly inconsistent near expiry; the authentication checks parse timestamps in Rust (`auth.rs:313-318`, `:213-218`), so this is not currently an auth bypass. Expired OTPs, sessions, outbox, and audit rows are never purged, causing unbounded growth.

**Recommended fix:** Run `PRAGMA foreign_keys=ON`, `PRAGMA journal_mode=WAL`, and a suitable `busy_timeout` at connection setup; verify with tests. Store timestamps as integer Unix epoch or SQLite `DATETIME` and compare numerically. Add cleanup jobs for expired OTPs/sessions/outbox and a retention policy for audit. Enable `secure_delete` if deleted secrets must not persist in free pages. For public deployments, document/verify SQLite file permissions (Docker/systemd already do this) and encrypt backups.

**Blocker for public v0.1:** **No** for correctness of current auth checks; fix before v1.0 and before account deletion/high concurrency.

---

### M-9 -- Medium -- Deployment hardening gaps: placeholder secret, no `__Host-`, SMTP env/TLS gaps, missing resource limits

**Files/lines:** `deploy/.env.example:41` (`OTP_SECRET=CHANGE_ME_generate_with_openssl_rand_hex_32`); `docker-compose.yml:29-31` (requires non-empty but accepts the placeholder); `deploy/.env.example:51` and `docker-compose.yml:32` (`COOKIE_NAME=al_session`, no `__Host-`); `src/routes.rs:140-148` (no `__Host-`); `docker-compose.yml:13-52` (no `read_only`, `tmpfs`, `pids_limit`, `mem_limit`, log limits; Caddy service at `:54-69` has no `user`/`cap_drop`); `deploy/Caddyfile:18-30` (good HSTS/CSP/nosniff/frame/referrer); `src/config.rs:160-171` and `src/email.rs:44-70` (`SMTP_TLS=none` is accepted and only warns when credentials are set); `.env.example`/Compose have no SMTP variables (H-10).

**Attack scenario / impact:** A user copies `.env.example` and deploys without replacing the placeholder; the HMAC secret is public/known (H-7). The session cookie name lacks `__Host-`, allowing a sibling-subdomain cookie-tossing attack if an attacker controls another subdomain (`Domain=.example.com` cookie with the same name; browsers may send both). `SMTP_TLS=none` with credentials sends OTPs and SMTP credentials in cleartext; the warning is easy to miss. The Compose services have no memory/PID/log limits; an authenticated or unauthenticated DoS can exhaust the host. The Caddy container commonly runs as root unless overridden; it is internet-facing. The global `no-store` middleware now addresses response caching, so that earlier gap is fixed.

**Recommended fix:** Reject the known placeholder and require a 64-hex/32-byte random `OTP_SECRET` at startup; do the same for `ADMIN_TOKEN` if set. Change the default cookie name to `__Host-al_session` and enforce `Secure`/`Path=/`/no `Domain` in production (and reject `COOKIE_SECURE=false` when `APP_URL` is HTTPS/public). Reject `SMTP_TLS=none` in production or when credentials are set; add the SMTP variables to `.env.example`/Compose/docs. Add Compose resource limits (`mem_limit`, `pids_limit`, `cpus`, log rotation) and `read_only: true` plus a tmpfs for the app if compatible; run Caddy as a non-root user with `cap_drop: ALL` and only `NET_BIND_SERVICE` if needed. Pin base images by digest for reproducibility.

**Blocker for public v0.1:** **Partially.** The placeholder secret, `__Host-`, and SMTP deployment/TLS gaps should be fixed before public; resource limits and Caddy user are hardening (recommended, not strictly blocking).

---

### L-1 -- Low -- Raw WebAuthn/serde error messages are returned to clients

**Files/lines:** `src/error.rs:60-62` (`AppError::Webauthn(message)` returns the library error string); `src/routes.rs:390-391` and `:510-511` (serde parse errors converted to `BadRequest(e.to_string())`); `src/routes.rs:108-137` (`/healthz` exposes `dev_mode`, version, and a database probe).

**Attack scenario / impact:** Error responses can reveal RP ID/origin expectations, credential parsing details, or whether a credential exists. This aids reconnaissance and debugging by an attacker. `dev_mode` on `/healthz` tells an attacker whether the outbox is open. Severity is low because the information is not a secret and the app is not verbose about SQL/secrets.

**Recommended fix:** Return stable, generic error codes for WebAuthn/serde failures; log details server-side with a correlation ID. Keep `/healthz` minimal in production (or restrict it to the proxy/healthcheck network) and do not expose `dev_mode`.

**Blocker for public v0.1:** No.

---

### L-2 -- Low -- Custom constant-time comparison, panic paths, config bounds, email canonicalization, body limit

**Files/lines:** `src/auth.rs:78-87` (`constant_time_eq` custom, early return on length mismatch); `src/state.rs:67` (`RateLimiter` `.expect("rate limiter lock")` can panic on a poisoned mutex; challenge locks return 500 instead); `src/config.rs:125-133` (`SESSION_TTL_DAYS`/`OTP_TTL_MINUTES` accept negative/zero/huge values; `ChronoDuration::days`/`time::Duration::days` may panic or create unusable cookies); `src/auth.rs:18-36` (`normalize_email` allows `+` aliases, non-whitespace control characters, and Unicode variants; no IDNA/canonicalization).

**Attack scenario / impact:** The custom constant-time comparison is logically correct for fixed-length hex strings but is not guaranteed constant-time by the compiler; use `subtle::ConstantTimeEq` for assurance. A poisoned rate-limiter mutex would panic the handler/task (only if a panic occurs while holding the lock; low likelihood). Negative/huge TTLs can break login or crash startup (env-controlled, not remote). Plus-alias addresses can bypass the per-email `start` limit for email bombing against the same human, while the exact victim address still has its own limit. Control characters in email local parts are not ideal for future SMTP header handling; CRLF is blocked by the whitespace check, but other control bytes are not. Case/whitespace normalization itself is correct (`trim` + lowercase), so case/whitespace cannot bypass the per-email limit; plus aliases and Unicode variants are not canonicalized, so they can be used for bombing. No custom Axum `DefaultBodyLimit` is set; the default is about 2 MB, and `verify_otp` HMACs the submitted code before checking its length (`auth.rs:220`), so a multi-megabyte code string costs CPU.

**Recommended fix:** Use `subtle` for constant-time comparisons. Replace `.expect` with a handled poison error or `parking_lot`/`tokio::sync` lock. Validate/clamp TTLs at startup (e.g., session 1-30 days, OTP 1-30 minutes) and reject invalid values. Use a stricter email parser/canonicalization (reject control characters and angle brackets, normalize IDNA, document plus-alias behavior). Add a small Axum `DefaultBodyLimit` and exact 6-digit validation before HMAC. This is low priority relative to the High findings.

**Blocker for public v0.1:** No.

---

### L-3 -- Low/Info -- Documentation drift and stale security claims

**Files/lines:** `README.md:173` claims the OTP HMAC is bound to `user_id + purpose`, but `src/auth.rs:137` uses only the code; `README.md:177` claims 72-bit recovery codes, but `normalize_recovery_code` (`auth.rs:60-65`) uppercases and strips hyphens, reducing the effective space to roughly 63 bits and stripping payload hyphens; `README.md:180` and `:190` still say rate limiting only covers `start`/`recover-start` and that verify/passkey endpoints have none, while the current routes add limits to those endpoints; `README.md:15`/`:188`, `docs/IMPLEMENTATION.md:88`, and `deploy/README.md:11-17`/`:420` still say SMTP is absent even though `src/email.rs` exists and the deployment contract omits its environment variables.

**Impact:** Operators and future contributors may rely on controls that are not implemented, or may miss controls that are implemented. The OTP-binding claim is security-relevant (H-7); the recovery entropy claim is a moderate overstatement (still strong, but not 72 bits after normalization); the stale rate-limit/SMTP text can cause operators to make the wrong deployment choice or to believe SMTP is unavailable when it exists.

**Recommended fix:** Update the docs to match the code after the security fixes; add a "security claims verified by test" checklist. Consider using a case-preserving, separator-safe recovery alphabet (e.g., Crockford Base32) so normalization does not reduce entropy; or document the effective entropy. Document the SMTP variables and current defaults. Keep line references current.

**Blocker for public v0.1:** No, but the OTP-binding/SMTP claims should be corrected before release.

---

### L-4 -- Low -- `RP_ID` can be configured to a parent domain, broadening passkey scope

**Files/lines:** `src/config.rs:82-83` (`RP_ID` defaults to `APP_URL` host, but any env value is accepted); `src/main.rs:67-71` (passes `rp_id`/`app_url` to `WebauthnBuilder`); `deploy/.env.example:21-25` explicitly allows "a parent registrable domain" and warns that changing it invalidates passkeys.

**Attack scenario:** An operator sets `RP_ID=example.com` while `APP_URL=https://auth.example.com`. WebAuthn credentials are then scoped to the parent RP ID `example.com`. An attacker who compromises any other subdomain under `example.com` (or achieves XSS on it) may be able to create/use credentials for the same RP ID, depending on browser scoping and the compromised page's ability to run WebAuthn. This is a deliberate WebAuthn feature, but it widens the trust boundary from `auth.example.com` to every subdomain under the parent. The default (exact `APP_URL` host) is safer.

**Impact:** Broader passkey scope and a larger attack surface if a sibling subdomain is compromised. Low/medium depending on the domain's subdomain hygiene.

**Recommended fix:** Default to the exact `APP_URL` host and require an explicit opt-in (e.g., `RP_ID_ALLOW_PARENT=true`) for a parent domain. Document the subdomain-trust implication clearly; for high-assurance deployments, keep `RP_ID` equal to the auth host.

**Blocker for public v0.1:** No.

---

### L-5 -- Low -- Logging/config can expose the database URL and secrets

**Files/lines:** `src/main.rs:41-47` logs `db_url` at info; `src/config.rs:40-61` derives `Debug` for `Config`, which contains `otp_secret` and `admin_token` (the SMTP password is now a redacted `SecretString`); `src/error.rs:63-69` logs internal errors; `deploy/README.md:360-361` warns about debug logging but not `db_url`.

**Attack scenario:** A future Postgres `DATABASE_URL` contains a password; the startup log writes it to journald/container logs. A debug-level `Config` dump or a future error that includes config would expose `otp_secret`/`admin_token`. `RUST_LOG=debug` also logs request URIs, which can include the admin token in the query string (H-5). Logs are often shipped to third-party systems with broader access than the auth server.

**Impact:** Credential/secret disclosure through logs. Low likelihood today (SQLite URL is a path), but a latent high-impact issue for Postgres/ops.

**Recommended fix:** Redact `db_url` or log only the scheme/host; do not derive `Debug` for `Config` (or use a redacted wrapper for `otp_secret`/`admin_token`); avoid logging query strings; document a no-debug production policy and log redaction. Keep the admin token out of URLs (H-5).

**Blocker for public v0.1:** No.

---

## Top 5 fixes before any public deployment

1. **Remove the production OTP leak path and wire the real email provider.** Do not persist plaintext OTPs; remove/gate the dev outbox; make `DEV_MODE` explicit and fail closed for non-loopback/public deployments; add the SMTP/`EMAIL_PROVIDER` contract to `.env.example`, Compose, and the deployment docs, and fail if production is left on `outbox`. (C-1, H-1, H-10)
2. **Complete brute-force controls.** Add account-level lockout/backoff, atomic attempt reservation, 8-digit OTPs or equivalent, CAPTCHA/proof-of-work, real client IP via `ConnectInfo`/trusted proxies, and cap/GC the in-memory maps. (H-2, H-8, H-9, M-6)
3. **Require step-up and cascade revocation.** WebAuthn step-up for adding a passkey, recovery regeneration, passkey revocation, and revoke-all; revoke all sessions on credential add/revoke and after recovery; add "sign out everywhere" and an idle timeout; reduce the 7-day bearer TTL or add device binding. (H-3, H-4, H-6)
4. **Harden the session/transport/CSRF layer.** `__Host-` cookie name, enforce `Secure` in production, HSTS/TLS, CSP/nosniff/frame/referrer, CSRF token and strict Origin/`Sec-Fetch-Site`; ensure the app is not reachable except through the trusted proxy. (H-4, H-5, M-2, M-9)
5. **Fix admin, recovery, and secret/config handling.** Move the admin token out of the query string, rate-limit and audit admin access, restrict to localhost/VPN; add recovery delay/notification/credential revocation and recovery-code expiry; reject placeholder/weak `OTP_SECRET`/`ADMIN_TOKEN`; reject `SMTP_TLS=none` in production; keep SQLite 0600 and encrypted backups. (H-5, H-6, H-7, M-9)

---

## Acceptable for v0.1 but fix before v1.0

These are acceptable only with the compensating controls noted; they are not endorsements for a high-assurance deployment:

- **No DPoP/DBSC device binding.** The session is a bearer cookie. For v0.1, require TLS, `HttpOnly`, `Secure`, a short TTL (prefer 24h-3 days, not 7 days), an idle timeout, and step-up for sensitive actions. Add proof-of-possession in v0.2/v1.0 as planned.
- **No CSRF token.** Acceptable only if all mutations stay POST+JSON, `Origin`/`Sec-Fetch-Site` are strictly enforced (including rejecting missing `Origin`), `SameSite=Lax`/`Strict` is set, and no state-changing GETs exist. Add a token before v1.0.
- **No WebAuthn attestation policy and no hard counter-regression rejection.** Acceptable for consumer synced passkeys if documented; add an enterprise/attestation policy and counter-anomaly handling before v1.0.
- **No recovery-code expiry/notification/old-credential revocation.** Acceptable only for a limited v0.1 if recovery is disabled or clearly documented; add expiry, notification, delay, and revoke-all before v1.0.
- **No account deletion/email change.** Add data lifecycle controls before v1.0 (privacy/compliance).
- **No admin mutation/revocation actions.** Keep admin read-only and use a documented DB/runbook procedure; add audited admin actions before v1.0.
- **No Postgres/multi-instance/multi-tenancy/OIDC/SSH/broker.** Out of scope for v0.1; single-process SQLite is fine if the deployment is one instance.
- **No CAPTCHA/email-bombing protection.** Add edge rate limits/provider caps for v0.1; add CAPTCHA/proof-of-work before broad public signup.
- **No audit retention/immutability.** Add retention and an off-host/immutable sink before v1.0.
- **No automated tests/CI/dependency audit.** Not a runtime control, but a release blocker for a security product; add unit/integration tests for OTP/session/recovery, `cargo audit`/`cargo deny`, and a build pipeline before public release.
- **No `__Host-`/security headers at the app layer** are **not** acceptable if the app can be reached without Caddy; they are acceptable only when Caddy is the sole ingress and the app is bound to a private network/loopback. `Cache-Control: no-store` is now implemented globally (`main.rs:22-28`, `:74-76`), which is good.

---

## Not reviewed / limitations

- **No runtime testing.** I did not run `cargo check`, `cargo test`, `cargo audit`, the server, Docker, Caddy, SMTP delivery, WebAuthn browser ceremonies, concurrency tests, or exploit code. The code may still have compile/runtime issues; the project README says it is pre-release and `cargo check`/`cargo test` had not been completed at the time of writing.
- **Compiled binary and container image not reviewed.** The `target/` directory and any built image were not audited. The Dockerfile/compose/Caddyfile/systemd files were reviewed as text only; Caddy's exact `X-Forwarded-For`/`trusted_proxies` behavior and SMTP TLS handshakes were not executed/verified in this environment.
- **Frontend reviewed only at source/grep level.** `static/app.js` is now a substantial (about 2.7k line) browser client. I checked for `innerHTML`/`outerHTML`/`document.write`/`eval`/`new Function`/`localStorage`/`sessionStorage`/`document.cookie` and for unsafe URL sinks; none were found, and user-controlled values are rendered through `textContent`/`createTextNode`. I did not run browser WebAuthn ceremonies, test CSP compatibility, fuzz the UI, or verify clipboard/recovery-code handling end to end.
- **SMTP implementation reviewed at source level only.** `src/email.rs` was read (mailbox parsing, TLS modes, credentials, timeout), but I did not test SMTP delivery, STARTTLS certificate validation, DNS, SPF/DKIM/DMARC, bounce handling, retries, or provider rate limits. `SMTP_TLS=none` and `Opportunistic` deserve a live security test.
- **Postgres not reviewed.** Only SQLite SQL was reviewed. The docs describe a future Postgres migration; parameter style, timestamp types, `CITEXT`, and migrations would need a separate review.
- **Native/CLI/SSH/broker/OIDC/multi-tenancy** are out of scope for v0.1 and were not reviewed.
- **OS/host/TLS/backup/monitoring runtime** was not reviewed. The deployment docs describe good practices (TLS via Caddy, non-root, 0600 DB, backups), but I did not verify certificates, firewall rules, Docker volume ownership, backup encryption, restore drills, log rotation, or monitoring.
- **WebAuthn library internals** were only inspected enough to confirm `webauthn-rs` 0.6.2 sets `UserVerificationPolicy::Required` for passkey registration/authentication and to confirm `Passkey::update_credential` semantics. This is not a full audit of `webauthn-rs`/`webauthn-rs-core`.
- **Dependency/supply-chain audit** was not performed. `Cargo.lock` pins versions, but I did not check advisories, licenses, SBOM, or reproducible-build properties.
- **Privacy/legal review** was not performed. The report notes PII retention and logging issues but is not legal advice.
- **No penetration test or fuzzing.** The findings are based on source reading; exploitability in a specific deployment depends on proxy behavior, browser versions, SMTP configuration, and operational choices.
- **Moving target.** The tree was actively edited during the review (rate limits, transactions, no-store, SMTP, passkey-add were added while I was reading). Re-run a focused review after the tree stabilizes and before tagging a release.

---

## Positive controls / things done well

These reduce risk and should be preserved while fixing the findings:

- **Session token entropy and storage:** 32 random bytes from `OsRng`, URL-safe base64 (`auth.rs:49-53`); only SHA-256 hash in DB (`auth.rs:45-47`, `:259-280`); `token_hash` is UNIQUE (`migrations:38`).
- **OTP/recovery cryptography:** HMAC-SHA-256 (`auth.rs:39-43`); constant-time comparison for OTP/recovery (`auth.rs:78-87`, `:220-226`, `:419-427`); purpose separation (`login` vs `recovery`, `auth.rs:188-199`); 6-digit CSPRNG code with leading zeros (`auth.rs:55-58`); TTL and 5-attempt check (`auth.rs:210-218`); conditional `used_at` update for OTP and recovery (`auth.rs:229-236`, `:420-427`).
- **One-time ceremony handling:** WebAuthn/recovery challenges are removed before verification (`routes.rs:379-384`, `:499-504`, `:806-820`, `:1097-1102`), with 2-10 minute TTLs (`routes.rs:231`, `:339`, `:770`, `:1041`, `:1141`). Challenge IDs are UUID v4. The new passkey-add finish also checks that the challenge user matches the session (`routes.rs:806-820`).
- **WebAuthn:** `webauthn-rs` 0.6.2 uses `UserVerificationPolicy::Required` for passkey registration and authentication (`webauthn-rs-0.6.2/src/lib.rs:571`, `:683`), so UV is enforced by the library. RP ID/origin are wired through `WebauthnBuilder` (`main.rs:67-71`), and credential IDs are globally UNIQUE with a pre-check (`routes.rs:397-406`, `migrations:25`). Credential lookup is scoped to the challenge user (`routes.rs:517-526`).
- **Rate limiting:** login `start` 5/min/email + 30/min/IP; `verify-code` 10/min/email + 20/min/IP; passkey register/login/add 20/min/IP; recovery start 3/5min/email; recovery email verify 5/min/email + 10/min/IP; recovery code verify 10/min/IP + 5/min/email (`routes.rs:211-214`, `:291-304`, `:370-377`, `:490-497`, `:736-743`, `:800-802`, `:953-958`, `:1002-1015`, `:1070-1095`). This is a major improvement over the earlier build.
- **Transactions/atomic updates:** OTP+outbox (`auth.rs:143-167`), first passkey+session+recovery codes (`routes.rs:411-440`), recovery-code delete/insert (`auth.rs:362-371`), conditional recovery-code use (`auth.rs:420-427`), and `revoke_session` rows-affected check (`auth.rs:339-347`). `ensure_user` is race-safe via `ON CONFLICT` (`auth.rs:101-125`).
- **No-store:** global `Cache-Control: no-store` middleware (`main.rs:22-28`, `:74-76`).
- **Admin comparison:** current code uses `auth::constant_time_eq` (`routes.rs:1241-1245`), even though older docs say `==`.
- **SQL injection:** all reviewed SQL uses `?` bind parameters; no dynamic SQL/string interpolation of user values was found.
- **XSS in server-rendered pages:** admin and dev outbox values are escaped with `html_escape::encode_text` (`routes.rs:1180-1186`, `:1273-1279`, `:1285-1296`, `:1301-1311`); all interpolations are in text nodes, not attributes. JSON responses use `application/json`.
- **No state-changing GETs:** all mutations are POST (`routes.rs:31-47`); admin is read-only. This limits CSRF impact.
- **No CORS:** no permissive CORS layer; same-origin only is the safer default.
- **Frontend DOM safety:** `static/app.js` builds nodes with `createElement`/`createTextNode` and a small `h()` helper (`app.js:110-149`), uses no `innerHTML`/`eval`/web storage, sets `credentials: same-origin` and `cache: no-store` in API calls (`app.js:429-446`), restricts the dev-outbox link with `safeInternalPath` (`app.js:614-619`) and uses `rel="noopener noreferrer"` for the new tab (`app.js:976-980`). This is a good baseline, but it is not a browser-level XSS test.
- **SMTP hygiene:** `EmailSender` uses `lettre` mailbox parsing (no raw header interpolation), a 10-second timeout, TLS required by default, and a redacted `SecretString` for the SMTP password (`email.rs:17-114`, `config.rs:21-38`, `:160-191`). It is not yet documented in the deployment contract (H-10), and `TLS=none` is allowed with a warning (M-9).
- **Deployment:** Docker runs as UID/GID 10001 with `/data` 0700 (`Dockerfile:40-43`, `:62`), `no-new-privileges`/`cap_drop: ALL` for the app (`docker-compose.yml:49-52`), `DEV_MODE=false`/`COOKIE_SECURE=true` (`Dockerfile:54-58`, `docker-compose.yml:33-34`), and no published 8080 (`docker-compose.yml:41-42`). The systemd unit has `StateDirectoryMode=0700`, `UMask=0077`, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `CapabilityBoundingSet=` empty, and address-family restrictions (`deploy/authlayer.service:17-46`). Caddy provides TLS/HSTS/CSP/nosniff/frame/referrer/Permissions-Policy and overwrites `X-Real-IP` (`deploy/Caddyfile:18-42`). Backups and file permissions are documented (`deploy/README.md:251-340`).
- **Secrets documentation:** Compose requires a non-empty `OTP_SECRET` (`docker-compose.yml:29-31`), `.env` is 0600, and the docs warn about `DEV_MODE`, admin query tokens, Docker metadata secrets, and debug logging (`deploy/README.md:365-406`). The gap is that the placeholder is accepted and the app does not enforce strength.

---

## Minimal release gate for a public v0.1 (suggested)

A public v0.1 should not be tagged until all of the following are true:

- [ ] `DEV_MODE=false` is the only possible production mode; outbox routes are absent or local-only; no plaintext OTPs at rest; SMTP/`EMAIL_PROVIDER` is documented and works with TLS/retries.
- [ ] Every verification endpoint is rate-limited per account/email/IP with account lockout/backoff and atomic attempts; 6-digit codes are accepted only if exactly 6 digits; maps are capped/GC'd; real client IP is derived from `ConnectInfo`/trusted proxy.
- [ ] Adding a passkey, recovery regeneration, passkey revocation, session revoke-all, and recovery completion require step-up; all sessions are revoked on credential add/revoke/recovery; idle timeout and revoke-all exist; TTL is reduced or device binding is added.
- [ ] `__Host-` cookie, `Secure` enforced, TLS/HSTS, CSP/nosniff/frame/referrer, `Cache-Control: no-store`, CSRF token + strict Origin/`Sec-Fetch-Site`.
- [ ] Admin token is out of the URL, rate-limited, IP-restricted, audited, and `no-store`; placeholder/weak `OTP_SECRET`/`ADMIN_TOKEN` are rejected at startup; `SMTP_TLS=none` is rejected in production.
- [ ] SQLite foreign keys/WAL/busy timeout/cleanup/backup encryption and DB 0600 are verified; container/systemd resource limits are set.
- [ ] Failed OTP/recovery/passkey/admin attempts are audited; PII retention/account deletion policy exists.
- [ ] Tests cover OTP expiry/attempts/one-time, recovery one-time, session expiry/revoke/revoke-all, CSRF/Origin, rate limits, admin auth, SMTP failure, and WebAuthn errors; `cargo audit`/CI is green.
