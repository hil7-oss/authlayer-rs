# AuthLayer Security Review -- Round 3 (Final Delta)

**Review date:** 2026-11-23  
**Scope:** Current `authlayer/` tree after `migrations/0003_legacy_and_cookie.sql`: `src/**`, migrations, `Cargo.toml`, relevant deploy files, and `SECURITY_REVIEW_ROUND2.md`.  
**Method:** Static, read-only focused delta review. No builds, tests, Docker/Caddy runs, SMTP delivery, or WebAuthn browser runs. No code was modified; this report is the only file created.  
**Snapshot:** The tree was still being edited during the review. Line numbers refer to the current files; re-check before publishing.

**Bottom line:** The round-2 top blockers are fixed for fresh deployments and for upgrades that run migration 0003. The legacy recovery/session holes are closed, the lockout DoS is removed, recovery challenge ordering is corrected, ceremony-cookie binding is present on all challenge flows, cookies are `__Host-`/Strict/Secure in production, admin sessions are DB-backed with logout revocation, SMTP opportunistic is rejected outside dev, audit failures are logged, `db_url` is redacted, and cleanup/resource limits were added. Remaining work is mostly abuse resistance, recovery UX/security depth, admin token-rotation semantics, and upgrade backfill details, not a return of the previous Critical/High findings.

---

## Delta: R2-1 through R2-17

| ID | Status | Evidence / note |
|---|---|---|
| R2-1 | **Fixed** | Global `check_account_lock` is gone; `record_auth_failure` is advisory only (`auth.rs:169-196`). Atomic `attempts < 5` reservation remains (`auth.rs:310-328`); rate limits remain. Residual: no hard account lockout means a targeted 6-digit OTP brute force can run for weeks (R3-1). |
| R2-2 | **Fixed** | `0003_legacy_and_cookie.sql:1-5` sets legacy NULL `expires_at` to 1970; `verify_recovery_code` requires `expires_at IS NOT NULL AND expires_at > now` (`auth.rs:581-618`); counts use the same filter (`routes.rs:1100-1109`, `:1406-1415`); cleanup deletes NULL/expired rows (`db.rs:78-84`). Legacy global-HMAC path removed. |
| R2-3 | **Fixed** | `0003:7-11` revokes all sessions with NULL `passkey_id`; all new sessions are created with a passkey ID (`routes.rs:647-654`, `:842-850`; only those two creation sites); passkey revocation cascades by `passkey_id` (`routes.rs:1423-1432`). |
| R2-4 | **Fixed** | Registration challenge/state is created before credential revocation (`routes.rs:1803-1825`); if `revoke_all_credentials` fails, the challenge is removed and the error returned (`:1827-1836`); recovery code use is atomic (`auth.rs:609-621`). Residual: if process/response fails after revocation commit, the in-memory challenge is lost, but another code/email OTP can recover; no credential-destruction-before-challenge bug. |
| R2-5 | **Fixed** | `SMTP_TLS=opportunistic` is rejected unless `DEV_MODE=true` and no SMTP credentials (`config.rs:358-367`); `none` is rejected non-dev (`:346-348`). |
| R2-6 | **Fixed (mitigated)** | `check_origin` now requires `Origin` outside dev (`routes.rs:321-340`); session cookie is `SameSite=Strict` (`:150-157`); ceremony/admin cookies are Strict. No CSRF token remains, but Origin + Strict + JSON + POST-only mutations is a defensible v0.1 posture. |
| R2-7 | **Fixed** | Ceremony cookie helpers (`routes.rs:170-205`); set on `start` (`:423`), `verify_code` (`:568`), `stepup_start` (`:920`), `passkey_add_start` (`:1263`), `recover_verify_email` (`:1699`), `recover_verify_code` registration (`:1870`); required on `passkey_login` (`:811`), `passkey_register` (`:596`), `stepup_finish` (`:948`), `passkey_add_finish` (`:1292`), `recover_verify_code` (`:1744`); cleared on successful finish. |
| R2-8 | **Partially fixed** | Counter policy is now explicit: reject stored>0 and asserted<=stored, audit it; accept/audit 0/0 synced (`routes.rs:719-789`), applied to login and step-up (`:833`, `:978`), `passkeys.counter` added (`0003:14`). Upgrade gap: migration defaults existing passkeys to 0 without backfilling the old counter from `data`, so clone detection is weakened for one assertion per pre-existing passkey (R3-2). |
| R2-9 | **Fixed** | Production defaults to `__Host-al_session`; non-dev rejects `COOKIE_SECURE=false`, non-HTTPS `APP_URL`, or a cookie name without `__Host-` (`config.rs:255-279`); session cookie is HttpOnly/Strict/Secure/Path=/ (`routes.rs:150-157`); Compose defaults match (`docker-compose.yml:42-43`). |
| R2-10 | **Not fixed** | `start` still returns `flow: "passkey"` for passkey accounts (`routes.rs:395-429`), so passkey-account enumeration remains. Unknown/non-passkey and recovery paths are otherwise generic. |
| R2-11 | **Fixed** | Admin sessions are DB-backed (`0003:17-29`); login creates a random token, stores only SHA-256 hash, expiry/IP/UA (`routes.rs:2043-2061`); validation checks hash/revoked/expiry (`:235-255`); logout revokes the row (`:2079-2114`); admin view/login/denial audited. Residual: rotating `ADMIN_TOKEN` does not revoke existing admin sessions (R3-3); admin cookie lacks `__Host-`/`__Secure-` (R3-4). |
| R2-12 | **Partially fixed** | Caps and 5-minute cleanup remain (`state.rs:14-16`, `:64-96`); `RateLimiter` still uses `.expect` and arbitrary over-cap eviction (`:104-130`); the challenge cap can evict unexpired legitimate challenges. Low risk. |
| R2-13 | **Not fixed** | `create_otp` commits OTP+outbox before SMTP send; send failure returns 500 but leaves a valid OTP row (`auth.rs:237-270`). No delivery status/retry/rollback. Low/Medium usability/ambiguity, not takeover. |
| R2-14 | **Partially fixed** | `db::audit` now logs write failures (`db.rs:100-122`); expired OTP/session/recovery/admin rows are cleaned (`:64-98`). Audit rows themselves still have no retention/tamper-evidence, and CSRF/Origin rejects are not audited. Low/Medium. |
| R2-15 | **Partially fixed** | `db_url` is redacted in logs/errors (`config.rs:439-455`, `main.rs:43-49`, `db.rs:13-26`); raw `Webauthn` errors still returned (`error.rs:67-69`); `/healthz` still exposes `dev_mode`. Low. |
| R2-16 | **Partially fixed** | Most test DBs are gone, but `release-smoke.db-shm` remains and `e2e/node_modules` is present; no `authlayer/.gitignore` (only `.dockerignore`). Low/Info. |
| R2-17 | **Partially fixed** | Rate limits improved (`start` 5/min/email + 30/min/IP; recovery 3/5min/email + 20/5min/IP; verify paths 10/min/email etc.), but there is still no CAPTCHA/global per-ASN cap, `start` creates accounts for arbitrary emails, and SMTP can be abused for email bombing. Medium for open signup; mitigated for invite-only/small deployments. |

---

## Verified fixes (brief)

- **Legacy:** 0003 invalidates NULL-expiry recovery codes and NULL-passkey sessions; verifier/counts agree on non-NULL, unexpired rows.
- **Lockout:** advisory `failed_attempts` only; no `locked_until` blocking; atomic OTP attempt reservation remains.
- **Origin/cookies:** production requires `Origin`; session/ceremony/admin cookies are `SameSite=Strict`; session is `__Host-`, Secure, HTTPS-enforced.
- **Recovery:** registration challenge before revocation; rollback removes challenge on revocation failure; code use is atomic.
- **Ceremony:** all initial/login/add/step-up/recovery challenges use the ceremony cookie; one-time removal and clear-on-success.
- **Admin:** DB-backed sessions, hash-only storage, logout revocation, 1h expiry, IP rate limit, and audit.
- **Ops:** SMTP opportunistic rejected, audit write failures logged, `db_url` redacted, RP_ID exact-host gate, expired-row cleanup, Compose read-only/resource limits/cap drops.

---

## Specific checks from the request

- **Origin and admin:** production `check_origin` now requires `Origin` (`routes.rs:321-340`); admin login/logout are same-origin form POSTs and Caddy explicitly forwards `Origin` (`deploy/Caddyfile:33-34`). No static regression was found; non-browser clients/tests must send `Origin`.
- **Step-up timestamp:** 5-minute window, future timestamps rejected, and the session update is conditional on not revoked (`routes.rs:257-271`, `:987-999`); no new timestamp bug found.
- **Recovery state:** registration challenge is created before credential revocation; revocation failure removes the challenge; code use is atomic (`routes.rs:1803-1836`, `auth.rs:609-621`). Residual: process/response loss after revocation commit leaves an in-memory-only challenge; another code/email OTP can recover.
- **Migration ordering:** `0003` runs after `0002`; it invalidates NULL recovery/legacy sessions and creates `admin_sessions`/`passkeys.counter` without conflicting with the prior migrations. Counter backfill gap is R3-2.
- **SQL/lock/transaction:** touched SQL remains parameterized; key writes are transactional; no new injection path found. `RateLimiter` still has the `.expect` poison path (R2-12).
- **Admin cookie flow:** DB-backed random token with hash-only storage, expiry, logout revocation, rate limiting, and audit; the only new issue is token rotation not revoking existing rows (R3-3).

---

## New / residual findings

### R3-1 -- Medium -- OTP-only accounts remain exposed to long-term 6-digit guessing and email bombing after lockout removal

**Files/lines:** `src/auth.rs:169-196` (failures advisory only, no block); `src/auth.rs:310-328` (5-attempt atomic cap per code); `src/routes.rs:370-373` (`start`: 5/min/email + 30/min/IP), `:476-484` (`verify-code`: 10/min/email + 20/min/IP), `:1512-1525` (`recover-start`: 3/5min/email + 20/5min/IP), `:1611-1624` (`recover-verify-email`: 5/min/email + 10/min/IP); `src/auth.rs:206-273` (OTP creation/send); no CAPTCHA or global/ASN budget.

**Attack scenario:** An attacker targets a known OTP-only email. `start` creates a fresh 6-digit OTP; `verify-code` allows 10 guesses/min/email with no account lockout. At 10/min, ~48 days gives a 50% chance of hitting the code; the attacker can run indefinitely. A botnet can also submit arbitrary victim addresses to `start`/`recover-start`, creating accounts and sending mail (email bombing/SMTP quota/reputation). The per-IP limits can be distributed; there is no CAPTCHA.

**Impact:** Targeted long-term OTP brute force (especially OTP-only accounts), email-bombing abuse, SMTP cost/reputation damage, and user harassment. No immediate mass takeover; the per-email limit is the main brake.

**Recommended fix:** Add CAPTCHA/proof-of-work or an invite/allowlist for `start`; enforce global/per-ASN send budgets and per-address cooldowns; consider 8-digit OTPs or a soft account/IP backoff (without a global hard lock); alert on repeated failures and SMTP abuse. This is an edge/anti-abuse control, not a reason to reintroduce the lockout DoS.

**Blocker for public v0.1:** **No for an invite-only/small deployment with edge rate limits; Yes for unrestricted open signup.** A conditional deployment should put CAPTCHA/rate limits in front.

---

### R3-2 -- Low/Medium (upgrade) -- `passkeys.counter` is not backfilled from existing serialized passkeys

**Files/lines:** `migrations/0003_legacy_and_cookie.sql:13-14` adds `counter INTEGER NOT NULL DEFAULT 0`; `src/routes.rs:719-738` reads only the `counter` column; new records insert 0 (`routes.rs:635-636`, `:1335-1337`). The existing `passkeys.data` is the serialized `Passkey` and includes its prior counter, but the migration does not extract it.

**Attack scenario:** After upgrade, every existing passkey has `counter = 0`. The first assertion for such a credential is treated as a synced/counter-0 case (or accepted if asserted > 0), so a cloned pre-upgrade passkey with a non-increasing counter can authenticate once before the column is updated. After that first assertion the new policy works normally. Device-bound passkeys only; synced passkeys intentionally use 0.

**Impact:** A one-assertion window of weakened clone detection for pre-existing passkeys after upgrade. Fresh installs and newly registered passkeys are fine.

**Recommended fix:** Backfill the column from the serialized passkey (SQLite `json_extract(data,'$.counter')` where available, or an application startup migration), or force re-registration of legacy passkeys if the old counter cannot be recovered. Verify with an upgrade test.

**Blocker for public v0.1:** **No for fresh installs; Yes for upgrades if clone detection is a requirement.** Document the forced re-registration/backfill.

---

### R3-3 -- Medium (admin, regression) -- Rotating `ADMIN_TOKEN` does not revoke existing DB-backed admin sessions

**Files/lines:** `migrations/0003_legacy_and_cookie.sql:17-25` (`admin_sessions` has no token version/hash); `src/routes.rs:235-255` validates only the random session hash/expiry/revoked; `:2043-2061` creates a random admin session token independent of `ADMIN_TOKEN`; `.env.example:60-64` explicitly notes that changing `ADMIN_TOKEN` does not revoke existing sessions.

**Attack scenario:** An admin token leaks. The operator rotates `ADMIN_TOKEN` and restarts. New logins require the new token, but any existing stolen admin cookie remains valid until its 1h expiry or explicit logout/DB cleanup. This is a regression from the round-2 HMAC-cookie design, where changing the token invalidated every admin cookie. Admin is read-only in v0.1, but the page exposes all user emails, session IPs/UAs, and audit IPs.

**Impact:** Rotation does not fully contain admin-session theft; up to one hour of continued PII access. Not account takeover.

**Recommended fix:** Store a token version or a hash of `ADMIN_TOKEN` in `admin_sessions` and reject rows from an older version; on startup, revoke all admin sessions when the configured token hash changes. Provide a documented revoke-all/expire-now procedure. Add an audit event for forced admin-session revocation.

**Blocker for public v0.1:** **No** if admin is disabled or restricted; **Yes for an admin-enabled public deployment** where token rotation is part of incident response.

---

### R3-4 -- Low -- Ceremony and admin cookies lack `__Host-`/`__Secure-` prefixes

**Files/lines:** `src/routes.rs:170-181` (`al_ceremony`, Path=/, HttpOnly, Strict, Secure conditional), `:207-229` (`al_admin`, Path=/admin, HttpOnly, Strict, Secure conditional). The session cookie is now `__Host-` by default/enforced.

**Attack scenario:** A compromised sibling subdomain can set a `Domain=.example.com` cookie named `al_ceremony` or `al_admin`; browsers may send both, and the app may read the attacker-controlled one first. This can deny in-flight ceremonies or admin login (DoS) and, in theory, interfere with cookie selection. It cannot forge a session/admin token or a valid challenge ID.

**Impact:** Low; cookie-tossing/DoS against ceremony/admin flows. Session fixation on the main session is mitigated by `__Host-`.

**Recommended fix:** Rename the ceremony cookie to `__Host-al_ceremony` (Path=/, Secure, no Domain). Use `__Secure-` for `al_admin` (Path=/admin allowed) or move admin to Path=/ with `__Host-`. Add tests for the final cookie attributes.

**Blocker for public v0.1:** **No**.

---

### R3-5 -- Medium (design residual) -- Recovery is still an immediate email-OTP-plus-recovery-code takeover path with no delay or step-up

**Files/lines:** `src/routes.rs:1707-1876` (recovery success: verify recovery code, create registration challenge, revoke all sessions/passkeys, return new passkey challenge); `src/config.rs:293-296` (default recovery-code TTL 365 days); `src/routes.rs:1851-1857` (notification after completion).

**Attack scenario:** An attacker with a leaked recovery code and access to the victim's email inbox completes recovery immediately: the server revokes all existing sessions/passkeys and lets the attacker register a new passkey. There is no delay, no confirmation from an existing passkey/device, and no additional approval channel; the victim only receives a post-event notification. Recovery codes are valid for a year.

**Impact:** High-impact account takeover/persistence if a recovery code and email access are both compromised. This is the intended recovery model (email OTP + recovery code), but it is an immediate path with no cooling-off period.

**Recommended fix:** Add a delay/notification window for recovery from a new device/location, require WebAuthn step-up from an existing passkey when one is available, or require an additional out-of-band confirmation; consider shorter recovery-code TTL/one-time display acknowledgment. Keep the new ordering/rollback behavior.

**Blocker for public v0.1:** **No** with a small/trusted user base and notification; **consider before broad public use** where email compromise is a primary threat.

---

## Other residuals (not release blockers for a conditional fresh deployment)

| Item | Severity | File/line | Note / fix |
|---|---|---|---|
| OTP email after commit | Low/Medium | `auth.rs:237-270` | OTP/outbox commit then SMTP send; failure returns 500 but leaves a valid OTP. Add delivery status/retry or invalidate on send failure. |
| Audit retention/tamper-evidence | Low/Medium | `db.rs:64-98`, `:100-122` | Audit write failures are now logged, but `audit_events` have no retention/immutable sink and CSRF/Origin rejects are not audited. v1.0. |
| `start` passkey enumeration | Low/Medium | `routes.rs:395-429` | `flow: "passkey"` reveals passkey-account existence; unknown/OTP paths are generic. v0.2 privacy. |
| Map eviction/poison panic | Low | `state.rs:83-96`, `:104-130` | Caps/cleanup exist; over-cap eviction is arbitrary and `.expect` can panic on a poisoned lock. Low. |
| Systemd resource limits | Low | `deploy/authlayer.service` | Compose now has read-only/mem/pids/log limits; systemd has `LimitNOFILE` but no `MemoryMax`/`TasksMax`. Add for parity. |
| Test artifact/repo hygiene | Low/Info | `authlayer/release-smoke.db-shm`, `authlayer/e2e/node_modules`, no `authlayer/.gitignore` | Remove artifacts and add a `.gitignore`; `.dockerignore` already excludes DBs. |
| Raw WebAuthn errors / health dev_mode | Low | `error.rs:67-69`, `routes.rs:118-145` | Return generic WebAuthn errors; restrict health details in production. |
| Ceremony/admin cookie prefixes | Low | `routes.rs:170-181`, `:207-229` | See R3-4. |

---

## Top 3 remaining risks for a fresh single-instance deployment behind Caddy

1. **Open-signup OTP abuse.** No CAPTCHA/global send budget; 6-digit OTPs at 10/min/email without account lockout; arbitrary-email `start` enables email bombing and a long-term targeted guessing campaign. Put CAPTCHA/edge limits in front, use 8-digit/invite if open to the internet.
2. **Recovery remains an immediate email-OTP-plus-recovery-code takeover.** A leaked recovery code plus email access immediately revokes all sessions/passkeys and adds an attacker passkey; no delay/step-up. Add a delay/existing-passkey confirmation before broad public exposure.
3. **Bearer sessions are still the root of session risk.** The session is a 7-day `__Host-` cookie with idle timeout and revocation, but no DPoP/DBSC proof-of-possession. A stolen cookie is usable until revocation/expiry; device binding remains a v0.2 item.

(If admin is enabled, add **R3-3 admin token rotation** as a conditional risk: rotate/revoke DB admin sessions when the token changes.)

---

## Go/no-go

**Unrestricted public v0.1: NO-GO today.** The remaining blockers are abuse resistance (R3-1) and recovery depth (R3-5), not the previous legacy/lockout/cookie/counter top findings. Open internet signup without CAPTCHA/edge controls is not defensible for a 6-digit OTP service.

**Conditional GO for a fresh, single-instance deployment behind the provided Caddy** only when all of the following hold:

- Caddy is the sole ingress; port 8080 is not published; `TRUST_PROXY=true` with a narrow `TRUSTED_PROXY_CIDRS`; TLS/HSTS active.
- `DEV_MODE=false`; `APP_URL=https://...`; `COOKIE_NAME=__Host-al_session`; `COOKIE_SECURE=true`; `RP_ID` exactly the APP_URL host (no `ALLOW_RP_ID_PARENT`).
- `EMAIL_PROVIDER=smtp`; `SMTP_TLS=required`; `SMTP_HOST`/`SMTP_FROM` configured; `OTP_SECRET` and `ADMIN_TOKEN` (if used) are 32+ random characters; `DEV_MODE`/`ALLOW_INSECURE_DEV_MODE`/`ALLOW_OUTBOX_WITHOUT_DEV` are false.
- Migration 0003 is applied with a verified backup; no legacy NULL recovery/session rows remain; for upgrades, backfill/re-register passkeys or accept the one-assertion counter gap (R3-2).
- `ADMIN_TOKEN` is empty or `/admin` is network-restricted; if admin is enabled, token rotation includes revoking `admin_sessions` (R3-3).
- Edge CAPTCHA/rate limits and SMTP abuse monitoring protect `start`/`recover-start` (R3-1); accept the bearer-session/recovery-delay/audit-retention residuals as documented v0.2 items.

**Upgrade:** conditional GO after 0003 with backup; verify legacy sessions/recovery invalidation and address the counter backfill if clone detection matters.

**Do not block on** the remaining v1.0 hardening: CSRF token, ceremony/admin cookie prefixes, audit retention/immutability, email delivery status, map poison/eviction, systemd memory limits, passkey-account enumeration, and test-artifact cleanup. They are real but not justification to withhold a tightly configured, edge-protected v0.1.

---

## v0.2 / v1.0 backlog

- **v0.2:** DPoP/DBSC device binding; CAPTCHA/proof-of-work and global send budget; recovery delay/existing-passkey step-up; admin actions and admin-session revocation on token rotation; passkey counter backfill for upgrades; cookie prefixes for ceremony/admin.
- **v1.0:** audit retention/immutable sink and full failure coverage; email delivery status/retry/idempotency; systemd resource limits; remove test artifacts/add `.gitignore`; generic WebAuthn error mapping; enumeration timing/response uniformity; optional parent-RP-ID administrative policy.

---

## Not reviewed / uncertainty

- Static review only: no `cargo check`/`cargo test`/`cargo audit`, no Docker/Caddy, no SMTP TLS/deliverability, no WebAuthn browser E2E, no concurrency/fuzz/pen test.
- The tree was moving during the review; line numbers are snapshot-specific.
- `passkeys.data` is assumed to contain the old serialized counter (as `webauthn-rs` does); verify the exact JSON path before writing a SQL backfill.
- No review of OS/host, backup/restore, monitoring, Postgres, native/CLI/SSH/broker/OIDC, or multi-tenancy.
