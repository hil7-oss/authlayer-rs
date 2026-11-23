# AuthLayer Security Review -- Round 2

> **Historical document.** This was the round-2 review. The current delta/verdict is in `SECURITY_REVIEW_ROUND3.md`. Many round-2 blockers are fixed; do not use this file as the current release verdict.

**Review date:** 2026-11-23  
**Scope:** Current `authlayer/` tree: `src/**`, `migrations/**`, `static/**`, `Cargo.toml`/`Cargo.lock`, Docker/systemd/Caddy deployment files, and the previous `SECURITY_REVIEW.md`.  
**Method:** Static, read-only re-review. No builds, tests, Docker/Caddy runs, SMTP delivery, or WebAuthn browser runs. No code was modified; this report is the only file created.  
**Snapshot:** The tree was actively edited during the first review and this one. Line numbers refer to the current files at the time of writing; re-check before publishing. The current tree includes `migrations/0002_security_hardening.sql`, an SMTP module, step-up endpoints, an admin cookie flow, and a substantial frontend.

**Executive summary:** The security wave fixed most of the previous Critical/High findings. `DEV_MODE` is explicit and loopback-guarded, production outbox bodies are redacted and retained for one day, step-up is required for the sensitive credential/recovery actions, admin uses a form login with an HMAC cookie, client IPs use `ConnectInfo` plus trusted-proxy CIDRs, in-memory maps are capped and cleaned, SMTP is fail-closed in the deployment contract, and SQLite now enables foreign keys/WAL/busy timeout. The previous C-1, H-1, H-3, H-5, H-8, H-9, H-10, M-5, and most of M-8 are fixed for fresh deployments.

The remaining issues are narrower but real: **legacy recovery codes with NULL expiry never expire and still use the old global HMAC**; **legacy sessions have NULL `passkey_id` and survive passkey revocation**; the new **account lockout enables an unauthenticated lockout DoS**; recovery deletes all passkeys/sessions before the replacement registration challenge exists; CSRF still fails open when `Origin` is absent; the session cookie still lacks `__Host-`; challenge binding and counter-regression handling are incomplete; and SMTP `opportunistic` is still allowed outside development. A fresh, tightly configured single-instance deployment is close to a conditional go; **upgrades from a pre-hardening database are not safe without a data migration**, and a broad public launch should wait for the top fixes below.

---

## Delta: previous findings

| Previous ID | Status | Evidence / note |
|---|---|---|
| C-1 | **Fixed** | `config.rs:182-201` makes `DEV_MODE` explicit and requires loopback bind/URL unless `ALLOW_INSECURE_DEV_MODE=true`; `config.rs:203-229` validates `OTP_SECRET`; `auth.rs:269-273` stores plaintext only for `DEV_MODE && outbox`; `routes.rs:1755-1758`/`:1800-1803` gate the outbox. Residual: explicit unsafe escape hatches and a deliberate dev outbox. |
| H-1 | **Fixed (production)** | Outbox body is redacted unless dev+outbox (`auth.rs:269-273`); outbox rows older than one day are deleted (`db.rs:39-47`) at startup and every five minutes (`main.rs:64-86`). Residual: dev outbox plaintext and legacy test/backup DBs. |
| H-2 | **Partially fixed** | Atomic attempt reservation (`auth.rs:350-378`) and account lockout (`auth.rs:177-234`, 10 failures/15 min) were added. But 6-digit OTPs remain, and the global lockout is a new DoS (R2-1). |
| H-3 | **Fixed** | Step-up endpoints (`routes.rs:742-906`); add passkey, recovery regeneration, passkey revoke, and revoke-all require step-up (`:1111-1112`, `:1177-1178`, `:1263-1264`, `:1353-1354`, `:915-916`); passkey removal revokes sessions bound to it (`:1306-1315`); recovery success revokes all sessions/passkeys (`:1680-1693`). Residual: legacy sessions and challenge binding (R2-3/R2-7). |
| H-4 | **Partially fixed** | Idle timeout (`auth.rs:482-489`), `passkey_id` on sessions (`:405-435`), revoke-all (`:531-539`), and passkey-revocation cascade (`routes.rs:1306-1315`) were added. Residual: legacy sessions with NULL `passkey_id`; bearer token still has no proof-of-possession; no `__Host-`. |
| H-5 | **Fixed** | Admin form login (`routes.rs:1826-1939`) with HMAC cookie (`:168-217`: HttpOnly, SameSite=Strict, Path=/admin, Secure conditional, 1h TTL), rate limit (`:1868-1873`), audit on login/view/denial (`:1874-1931`, `:1975-1995`), and no query token (`:1965-1974`). Residual: stateless logout/no server-side admin revocation, no `__Secure-` prefix. |
| H-6 | **Partially fixed** | New codes have TTL (`auth.rs:577-599`), atomic conditional use (`:644-653`), notification (`routes.rs:1708-1714`), and recovery revokes all sessions/passkeys (`:1680-1693`). Residual: legacy NULL-expiry codes never expire; no delay/high-risk step-up; recovery destroys credentials before registration challenge creation (R2-2/R2-4). |
| H-7 | **Partially fixed** | New OTP/recovery hashes include user, purpose/id, expiry (`auth.rs:81-108`); `OTP_SECRET` length/placeholder checks (`config.rs:203-229`); production requires a secret. Residual: legacy recovery codes use the old global HMAC and NULL expiry (R2-2). |
| H-8 | **Fixed** | `ConnectInfo` is used (`main.rs:96-99`); `client_ip` uses trusted-proxy CIDRs and rightmost-untrusted parsing (`auth.rs:675-719`); CIDRs are parsed/validated (`config.rs:24-87`, `:335-357`); Compose sets a dedicated bridge/CIDR. Residual: all-trusted-hop fallback and broad CIDR (see Other residual items). |
| H-9 | **Fixed (mitigated)** | Caps and periodic cleanup (`state.rs:14-16`, `64-96`, `116-130`) cover all challenge maps and the rate limiter. Residual: arbitrary eviction and `.expect` panic (R2-12). |
| H-10 | **Fixed** | `EMAIL_PROVIDER` defaults to SMTP in Compose/`.env.example`; SMTP host/from required; outbox non-dev fails unless explicit `ALLOW_OUTBOX_WITHOUT_DEV`; `SMTP_TLS=none` rejected non-dev (`config.rs:263-333`); deployment docs updated. Residual: `opportunistic` still allowed (R2-5). |
| M-1 | **Partially fixed** | Unknown/non-passkey responses are generic (`verify_code` returns `invalid_code`; `recover_start` always returns code flow). `start` still returns `flow: "passkey"` for passkey accounts (`routes.rs:324-372`), so passkey-account enumeration remains (R2-10). |
| M-2 | **Not fixed** | `check_origin` still returns `Ok(())` when `Origin` is absent (`routes.rs:283-291`); no CSRF token; `SameSite=Lax` session cookie (`:148-155`); admin login form has no CSRF token (R2-6). |
| M-3 | **Partially fixed** | Step-up and passkey-add check that the challenge user matches the session (`routes.rs:819-833`, `:1179-1193`). Initial registration/login/recovery challenges are still bearer IDs not bound to a ceremony cookie/session (R2-7). |
| M-4 | **Not fixed** | `update_credential(...).unwrap_or(false)` still accepts a non-increasing counter and issues a session/step-up (`routes.rs:701-716`, `:861-876`) (R2-8). |
| M-5 | **Fixed** | Status is checked at start/verify/register/login/step-up/recovery (`routes.rs:325-340`, `:437-448`, `:542-544`, `:674-676`, `:838-840`, `:1411-1412`, `:1520-1531`, `:1632-1643`); `is_active_user` at `auth.rs:141-149`. |
| M-6 | **Partially fixed** | Transactions now cover OTP+outbox (`auth.rs:275-299`), first passkey+session+recovery (`routes.rs:567-604`), recovery delete/insert (`auth.rs:566-599`), and last-credential removal (`routes.rs:1269-1316`); recovery use is conditional. Residual: email send after commit (R2-13) and notification task fan-out. |
| M-7 | **Partially fixed** | Failed OTP/recovery/admin attempts and admin views are audited; `db::audit` still discards errors (`db.rs:49-68`), no retention/tamper-evidence, and CSRF/Origin rejects are not audited (R2-14). |
| M-8 | **Partially fixed** | `foreign_keys(true)`, WAL, and busy timeout are set (`db.rs:13-19`); outbox has a 1-day cleanup. Residual: OTP/session/audit rows are not cleaned; RFC3339 text comparisons remain for counts/lists. |
| M-9 | **Partially fixed** | Placeholder/weak secrets, DEV_MODE, SMTP, and trusted proxy contracts are much better. Still: no `__Host-` default (`routes.rs:148-155`, `.env.example:56`), `COOKIE_SECURE=false`/HTTP `APP_URL` are not rejected, Compose has no resource limits, Caddy runs without an explicit non-root/cap_drop override (R2-9). |
| L-1 | **Not fixed** | Raw `Webauthn` error strings are still returned (`error.rs:74-76`); `/healthz` exposes `dev_mode` (`routes.rs:116-145`). |
| L-2 | **Partially fixed** | TTL/positive validation and secret validation improved (`config.rs:395-406`), but custom `constant_time_eq`, `.expect` on the rate-limit lock, email canonicalization gaps, and no custom body limit remain. |
| L-3 | **Mostly fixed** | Docs now describe SMTP, step-up, admin cookie, trusted proxy, legacy NULL recovery codes, and dev safeguards. Residual: README still calls recovery codes 72-bit although normalization reduces effective entropy (see Other residual items). |
| L-4 | **Not fixed** | `RP_ID` can still be a parent domain (`config.rs:231-232`, `.env.example:23-27`), broadening passkey scope to sibling subdomains. |
| L-5 | **Partially fixed** | `Config` no longer derives `Debug`, and SMTP passwords use redacted `SecretString` (`config.rs:89-108`). `db_url` is still logged at info (`main.rs:43-49`). |

---

## Verified fixes (brief)

- **DEV_MODE / outbox:** explicit and loopback-guarded; production outbox bodies are redacted; dev outbox is gated. C-1/H-1 are fixed for production.
- **Step-up:** WebAuthn step-up is required for add-passkey start/finish, recovery regeneration, passkey revocation, and revoke-all. The step-up timestamp is per session, stored in DB, and checked with a 5-minute window (`routes.rs:219-233`, `:878-890`).
- **Admin:** token is accepted only by POST `/admin/login`; cookie is HMAC-SHA256 over expiry (`routes.rs:172-217`), HttpOnly/SameSite=Strict/Path=/admin/1h; login rate limit and audit exist. The HMAC construction was checked: payload `admin:v1:{expires_at}`, expiry checked before the constant-time MAC compare, no query token. Logout remains stateless (R2-11).
- **Proxy/IP:** `ConnectInfo` plus configured CIDRs; direct peers are not trusted for forwarding headers.
- **Maps:** 10k caps and 5-minute cleanup for all challenge maps and the rate limiter.
- **SMTP:** startup fails if SMTP is selected without host/from, or if outbox is selected non-dev without the unsafe flag; `TLS=none` is rejected non-dev.
- **Recovery:** new codes are context-bound, TTL-limited, atomically consumed, and recovery revokes all sessions/passkeys with notification.
- **SQLite:** foreign keys, WAL, and busy timeout are enabled.
- **Frontend:** still uses safe DOM construction (`createTextNode`, no `innerHTML`/web storage) and same-origin `fetch`; no new obvious DOM XSS sink found.
- **Checks on new logic:** step-up rejects future timestamps and updates only non-revoked sessions (`routes.rs:219-233`, `:878-890`); recovery count and verification both filter expiry (legacy NULL is the exception, R2-2); reviewed SQL uses bound parameters; admin/dev-outbox HTML is escaped; no new stored-XSS sink was found in the static admin/login pages.

---

## Findings

### R2-1 -- High (availability) -- New global account lockout lets an unauthenticated attacker lock any OTP user for 15 minutes

**Files/lines:** `src/auth.rs:21-23` (10 failures, 15-minute lock); `src/auth.rs:177-206` (`check_account_lock`); `src/auth.rs:208-234` (`record_auth_failure`); `src/auth.rs:313-390` (`verify_otp` checks the lock and records failures); `src/auth.rs:601-659` (`verify_recovery_code` similarly); `src/routes.rs:319-322` (start rate limit), `:415-423` (verify-code 10/min/email), `:1395-1408` and `:1493-1506` and `:1595-1620` (recovery limits).

**Attack scenario:** For a known OTP-only account, the attacker calls `POST /api/auth/start` (rate limit 5/min/email) to create a login OTP, then submits 10 wrong codes to `POST /api/auth/verify-code` (10/min/email). `record_auth_failure` increments `users.failed_attempts`; at 10 it sets `locked_until = now + 15 minutes`. `check_account_lock` then returns `AccountLocked` for every OTP/recovery attempt. The attacker repeats after the lock expires; 10 requests per 15 minutes are enough to keep a target locked indefinitely. The same applies to recovery OTP/code failures. The victim can still use an existing passkey for login, but cannot use email OTP or recovery while locked.

**Impact:** Targeted denial of service against any known email account, especially OTP-only accounts. No CAPTCHA or email-proof requirement gates the lock; the attacker does not need to know the OTP. The lockout is also a potential support burden and can be triggered by a legitimate user mistyping codes.

**Recommended fix:** Do not apply a hard global lock from unauthenticated failures alone. Use per-IP + per-account progressive delays/backoff, require email proof or a passkey to hard-lock, allow passkey login to reset/soften the lock, cap lock duration, notify the user, and audit lock/unlock events. Add CAPTCHA/proof-of-work or edge rate limits before public OTP use.

**Blocker for public v0.1:** **Yes for OTP-only public deployments.** Passkey-only users retain login, but recovery is still lockable. At minimum, add per-IP throttling and avoid indefinite repeat-lock.

---

### R2-2 -- High (upgrades) -- Legacy recovery codes with NULL `expires_at` never expire and still use the old global HMAC

**Files/lines:** `src/auth.rs:110-116` (`legacy_recovery_hash`); `src/auth.rs:625-628` (NULL expiry uses legacy hash); `src/auth.rs:644-653` (update allows `expires_at IS NULL`); `migrations/0002_security_hardening.sql:7` adds `recovery_codes.expires_at` but does not backfill it; `src/routes.rs:988-999` and `:1289-1297` count NULL-expiry codes as valid.

**Attack scenario:** A deployment upgrades from the pre-hardening schema. Existing unused recovery codes have `expires_at = NULL` and a hash of `HMAC(secret, normalize(code))` with no user/id/expiry context. The verifier intentionally treats NULL expiry as non-expiring, so those codes remain valid forever. An attacker who obtained a pre-upgrade recovery code (old backup, password manager, screenshot, leaked DB) and who can read the victim's email OTP can complete recovery at any future time. Recovery then revokes all sessions/passkeys and lets the attacker register a new passkey, so this is a permanent backdoor for upgraded accounts.

**Impact:** Complete bypass of the new recovery-code TTL and context binding for legacy rows; long-lived account takeover for upgraded deployments. Fresh v0.1 databases are not affected.

**Recommended fix:** Add a migration that invalidates all NULL-expiry recovery rows (`expires_at = now` or `used_at = now`) and force affected users to regenerate; do not accept legacy NULL codes indefinitely. If a compatibility window is required, gate it behind an explicit short-lived config flag, notify users, and log use. Consider rehashing impossible without plaintext, so invalidation is the safe option.

**Blocker for public v0.1:** **Yes for any upgrade** from a pre-hardening database. Fresh installs are unaffected but should still verify no NULL rows exist.

---

### R2-3 -- Medium/High (upgrades) -- Legacy sessions have NULL `passkey_id` and survive passkey revocation

**Files/lines:** `migrations/0002_security_hardening.sql:4` adds `sessions.passkey_id` without backfilling existing rows; `src/auth.rs:405-435` stores `passkey_id` only for new sessions; `src/routes.rs:1306-1315` revokes sessions only where `passkey_id = target`; `src/routes.rs:1680-1693` (recovery) does revoke all sessions, but normal passkey revocation does not cover NULL rows.

**Attack scenario:** A session created before the hardening migration has `passkey_id = NULL`. The user later revokes the compromised passkey. `revoke_passkey` deletes the passkey and revokes sessions bound to that passkey, but the legacy session is not bound and remains valid until its absolute expiry (up to 7 days) or the 24h idle timeout. An attacker with that legacy cookie keeps access despite the credential revocation. The same applies to any session created outside the new passkey-bound paths.

**Impact:** Incomplete revocation after credential compromise in upgraded deployments; the core promise that revoking a lost/stolen passkey terminates its sessions is not met for legacy sessions. Fresh installs are fine.

**Recommended fix:** In the migration, revoke all existing sessions (force re-login) or add a server-side "legacy session invalidation" cutoff. Alternatively, when revoking a passkey, also revoke sessions with NULL `passkey_id` for that user (more disruptive but safe). Add an upgrade test that creates a pre-migration session and verifies it cannot survive passkey revocation.

**Blocker for public v0.1:** **Yes for upgraded deployments**; no for fresh installs. Document the forced re-login.

---

### R2-4 -- Medium -- Recovery deletes all sessions/passkeys before the replacement registration challenge exists

**Files/lines:** `src/routes.rs:1680-1693` starts a transaction, revokes all sessions, deletes all passkeys, and commits; `src/routes.rs:1716-1736` then calls `start_passkey_registration` and inserts the registration challenge in memory. The revocation is committed before the WebAuthn challenge is created.

**Attack scenario / failure mode:** A user completes recovery (email OTP + valid recovery code). The server commits revocation of all sessions and deletion of all passkeys, then calls `start_passkey_registration`. If that call fails (RP configuration error, library error, lock poisoning, process restart, OOM), or the registration challenge cannot be inserted, the user has no passkeys and no sessions, and the recovery code is already consumed. A second recovery code or email OTP login (no passkeys) may be required to recover again. This is an availability failure and a destructive surprise, not a direct takeover.

**Impact:** Account lockout/denial after a recovery error; user loses all credentials before the replacement exists. If only one recovery code remained, the path is especially painful.

**Recommended fix:** Create and store the WebAuthn registration state/challenge first, then commit revocation, then return the challenge; or use a staging state so the old passkeys/sessions remain until the new passkey is successfully registered. Add a recovery transaction/regression test that injects a registration failure and verifies the account is not left with zero credentials.

**Blocker for public v0.1:** **No**, but fix before public recovery is relied on.

---

### R2-5 -- Medium -- `SMTP_TLS=opportunistic` is still allowed outside development, enabling STARTTLS downgrade

**Files/lines:** `src/config.rs:299-313` rejects `SMTP_TLS=none` when `DEV_MODE=false`, but accepts `opportunistic`; `src/email.rs:44-58` maps it to `Tls::Opportunistic`; `.env.example:109-114` documents it as "not recommended" but not rejected.

**Attack scenario:** A self-hoster sets `SMTP_TLS=opportunistic` (or copies a provider recipe that uses it) in a production deployment. A network attacker between the app and the SMTP server strips the STARTTLS advertisement. `lettre` then sends the OTP email and, if credentials are configured, the SMTP username/password in cleartext. The attacker can read live OTPs or reuse the SMTP credentials to send phishing mail.

**Impact:** OTP and SMTP credential theft; account takeover for OTP-only users; mail reputation compromise. The default is `required`, so this is a misconfiguration path, not the default.

**Recommended fix:** Reject `opportunistic` when `DEV_MODE=false` or when SMTP credentials are present; require `required` (with port 465 wrapper or 587 STARTTLS) for production. Keep `opportunistic` only behind an explicit unsafe-development flag. Add a startup warning/log for any non-required mode.

**Blocker for public v0.1:** **No** with the default `required`; **Yes** for any deployment using `opportunistic` with real OTPs.

---

### R2-6 -- Medium -- CSRF still fails open when `Origin` is absent; no CSRF token

**Files/lines:** `src/routes.rs:283-291` (`check_origin` returns `Ok(())` if `Origin` is absent); `src/routes.rs:148-155` (session cookie `SameSite=Lax`); all state-changing handlers call `check_origin`, but none require a CSRF token; `src/routes.rs:1846-1849` (admin login form has no CSRF field).

**Attack scenario:** Modern browsers send `Origin` on cross-site POSTs and `SameSite=Lax` blocks cross-site POST cookies, so the common path is blocked. Residual paths remain: a compromised same-site sibling subdomain (same-site cookie is sent; an old browser/WebView or a client that omits `Origin` passes the fail-open check), a future state-changing GET, or a same-site injected form. If an attacker can trigger a state-changing request with the user's cookie, they can revoke sessions/passkeys, add a passkey (step-up still required), regenerate recovery codes (step-up still required), or force logout. The step-up requirement greatly limits the most damaging actions, but single-session revocation and logout do not require step-up.

**Impact:** Limited in modern browsers; the intended defense is incomplete. The admin flow uses `SameSite=Strict` and login CSRF is not meaningful without the token, but the general API remains fail-open.

**Recommended fix:** Reject state-changing requests when `Origin` is missing; validate `Origin`/`Referer` and `Sec-Fetch-Site`; add a double-submit or synchronizer CSRF token bound to the session; consider `SameSite=Strict`; keep all mutations POST and never add state-changing GETs. Add a CSRF token to the admin login/logout forms.

**Blocker for public v0.1:** **No** for modern-browser use with all mutations POST+JSON; fix before v1.0 and before any same-site subdomain is trusted.

---

### R2-7 -- Medium -- Initial registration/login/recovery challenges are still not bound to the browser or session

**Files/lines:** `src/routes.rs:344-357` (auth challenge ID returned); `src/routes.rs:480-493` (registration challenge ID returned); `src/routes.rs:1554-1567` (recovery challenge ID returned); `src/state.rs:18-34` (challenge structs contain only user/state/expiry plus email for recovery). Step-up and passkey-add finish do check that the challenge user matches the session (`routes.rs:819-833`, `:1179-1193`), which is an improvement, but the initial registration/login/recovery ceremonies still use a bearer challenge ID.

**Attack scenario:** The challenge ID is returned in JSON and is the sole handle for finishing the ceremony. If it leaks through XSS, a shared/public browser, a proxy/log that records response bodies, or a malicious extension, an attacker who can execute WebAuthn at the legitimate RP origin (or who controls the browser) can finish registration with their own authenticator for that user, or complete a recovery flow (recovery still requires the recovery code). TTLs and one-time removal are good, but there is no ceremony cookie or session binding for the initial challenge.

**Impact:** Ceremony hijack/account takeover if the challenge leaks and the attacker can act at the RP origin; more likely with XSS on the auth origin. Without XSS/origin access, WebAuthn still requires the legitimate origin and an authenticator.

**Recommended fix:** On ceremony start, set a short-lived `HttpOnly`, `Secure`, `SameSite=Strict` ceremony cookie (separate from the challenge ID), store the challenge under that token, and require the cookie at finish. Bind it to the session where one exists. Keep one-time removal and short TTLs. Add a CSP at the app layer for direct deployments.

**Blocker for public v0.1:** **No**, but fix before v1.0 or before relying on the frontend/XSS surface.

---

### R2-8 -- Medium -- Credential counter regression is still accepted; cloned-authenticator detection is not enforced

**Files/lines:** `src/routes.rs:701-716` (passkey login accepts `update_credential(...).unwrap_or(false)` and creates a session); `src/routes.rs:861-876` (step-up does the same); `webauthn-rs` 0.6.2 `src/interface.rs:87-108` documents `Some(false)` when the counter did not increase. No check compares the asserted counter against the stored counter before accepting.

**Attack scenario:** An attacker clones a passkey/authenticator (or copies a syncable passkey) and authenticates. The assertion counter is equal to or lower than the stored counter; `update_credential` returns `Some(false)`, the application treats it as success, and issues a session or step-up. The server never rejects a counter regression, so a cloned credential with a non-increasing counter is accepted. Synced passkeys commonly use counter 0 and are legitimately cloned by design, so a blanket reject would break users; the problem is the absence of policy/audit.

**Impact:** Cloned-credential detection is absent for device-bound authenticators; a cloned key can log in or satisfy step-up. Synced-passkey behavior is a deliberate tradeoff but should be explicit.

**Recommended fix:** Inspect `AuthenticationResult::counter()`/`needs_update()`. If the stored counter is greater than 0 and the asserted counter is <= stored, reject, audit, and consider flagging/revoking the credential. Define and document a counter-0 (synced passkey) policy. Add an audit event for counter anomalies.

**Blocker for public v0.1:** **No**; document the synced-passkey policy and fix before v1.0 for higher-assurance deployments.

---

### R2-9 -- Medium -- Session cookie still lacks `__Host-`; `Secure`/HTTPS are not enforced by the app

**Files/lines:** `src/routes.rs:148-155` (cookie uses configured name, Path=/, HttpOnly, SameSite=Lax, conditional Secure, max-age session TTL); `src/config.rs:239-244` (`COOKIE_NAME` default `al_session`; `COOKIE_SECURE` may be explicitly false; no APP_URL https requirement); `.env.example:55-59` (`COOKIE_NAME=al_session`, `COOKIE_SECURE=true`).

**Attack scenario:** Two related risks. (1) Without `__Host-`, a compromised sibling subdomain can set a `Domain=.example.com` cookie named `al_session`; browsers may send both host-only and domain cookies, enabling cookie tossing/session fixation or denial. (2) An operator can set `COOKIE_SECURE=false` or use `APP_URL=http://...` outside development; the app starts, and the bearer session cookie can cross plaintext HTTP. The provided Caddy/TLS config mitigates the network path, but the app does not enforce it.

**Impact:** Session theft or fixation; the session is a 7-day bearer token with no proof-of-possession. With the supplied Caddy and `COOKIE_SECURE=true`, the transport risk is mitigated; the `__Host-`/cookie-tossing defense is still absent.

**Recommended fix:** Default to `__Host-al_session` (Path=/, Secure, no Domain) and enforce those attributes in non-dev. Reject `COOKIE_SECURE=false` when `APP_URL` is HTTPS or non-loopback. Require HTTPS `APP_URL` outside development. Keep HSTS at Caddy.

**Blocker for public v0.1:** **Partially.** Defaults are usable behind Caddy, but `__Host-` and configuration enforcement should be fixed before a broad public launch; **Yes** for deployments that set `COOKIE_SECURE=false` or serve HTTP.

---

### R2-10 -- Low/Medium -- Passkey-account enumeration still exists through `start`'s flow value

**Files/lines:** `src/routes.rs:324-372` (`start` returns `flow: "passkey"` when the account has a passkey, `flow: "code"` otherwise); `src/routes.rs:425-435` and `:1508-1519` now return generic `invalid_code` for unknown/inactive users; `src/routes.rs:1410-1479` now returns a uniform recovery-start response.

**Attack scenario:** An attacker submits an email to `/api/auth/start`. A `passkey` flow reveals that the account exists and has a passkey; a `code` flow is ambiguous (unknown or existing without a passkey). This can be used to map accounts and target phishing/credential attacks. The recovery and OTP verification paths are now much better; this is the main remaining oracle.

**Impact:** Privacy/targeting; not a direct takeover. It aids decisions about which accounts are OTP-only (easier targets) versus passkey-protected.

**Recommended fix:** Return a uniform response and reveal the passkey ceremony only after an additional check (or use a generic "if this account exists, continue" flow), equalize timing, and rate-limit enumeration patterns. If the passkey flow must be visible for UX, accept and document the oracle.

**Blocker for public v0.1:** **No**.

---

### R2-11 -- Low -- Admin cookie is stateless and not revoked by logout; not bound to IP/UA and has no `__Secure-` prefix

**Files/lines:** `src/routes.rs:168-217` (admin cookie HMAC construction/validation; `HttpOnly`, `SameSite=Strict`, `Path=/admin`, `Secure` conditional, 1h TTL); `src/routes.rs:1941-1963` (`admin_logout` only clears the browser cookie); `src/routes.rs:1952-1960` audits logout but does not blacklist the cookie.

**Attack scenario:** An attacker steals the admin cookie (browser malware, shared machine, proxy/extension). The admin signs out. Because validation is stateless HMAC over `expires_at`, the stolen cookie remains valid until its original one-hour expiry; logout only clears the victim's browser. The cookie is not bound to IP/UA, so it can be replayed from anywhere. The admin page is read-only, limiting impact, but it exposes all user emails, session IPs/UAs, and audit IPs.

**Impact:** Up to one hour of continued admin read access after logout from a stolen cookie; PII exposure. No mutation capability in v0.1.

**Recommended fix:** Keep a server-side admin session/revocation table or a token version/denylist, or shorten the admin TTL. Bind the cookie to IP/UA as a risk signal, use a `__Secure-` prefix with Path=/ if practical, rotate the admin token on logout/incident, and add a CSRF token to admin forms. Keep admin disabled by default.

**Blocker for public v0.1:** **No**; admin is optional and read-only. Fix before using admin on a public host.

---

### R2-12 -- Low -- Challenge/rate-limit caps evict arbitrary entries and the limiter still panics on a poisoned lock

**Files/lines:** `src/state.rs:83-96` (`prune_challenges` retains unexpired entries, then removes arbitrary keys over 10k); `src/state.rs:104-130` (`RateLimiter::check` uses `.expect("rate limiter lock")`; `prune` removes arbitrary keys over 10k); `src/state.rs:14-16` caps.

**Attack scenario:** An attacker fills a map/rate-limiter with >10k unique keys. Cleanup removes arbitrary entries, potentially evicting a legitimate in-progress challenge or a target's rate-limit history. Evicting rate-limit history can reset a limit; evicting a challenge causes a legitimate ceremony to fail. A panic while holding the mutex poisons it and crashes subsequent rate-limit calls. The caps prevent unbounded memory, but eviction is not fairness-aware.

**Impact:** Limited DoS/rate-limit bypass; no memory exhaustion. The `.expect` is a low-probability panic path.

**Recommended fix:** Use a bounded TTL/LRU cache with deterministic eviction (oldest/expired first), never evict unexpired entries before expired ones, and handle mutex poisoning with an error rather than `expect`. Add metrics for map size/evictions.

**Blocker for public v0.1:** **No**.

---

### R2-13 -- Low/Medium -- OTP/outbox transaction commits before SMTP send; delivery failure leaves a valid OTP and a 500

**Files/lines:** `src/auth.rs:275-299` (OTP + outbox transaction commits); `src/auth.rs:301-308` (SMTP send after commit; failure returns `Internal("email_delivery_failed")`); `src/routes.rs:377-385` and `:1412-1451` surface the error.

**Attack scenario / failure mode:** SMTP is down or times out. The OTP row and redacted outbox row are committed, then the send fails and the API returns 500. The user retries, creating another OTP; the old OTP remains the latest until the new one is created (and is still valid for its TTL if the first email was actually delivered). The user may see an error while a usable code exists, or receive a code after an error. This is availability/ambiguity, not a direct takeover.

**Impact:** Confusing failures, stale valid codes, retry noise; no data compromise. The plaintext OTP is still not stored in production (redacted body).

**Recommended fix:** Record delivery status and make delivery asynchronous/idempotent; on immediate send failure, delete/mark the OTP invalid or return a "queued" response; add retry/backoff and metrics. Keep the OTP hash transaction separate from delivery status.

**Blocker for public v0.1:** **No**, but production usability depends on reliable SMTP.

---

### R2-14 -- Medium -- Audit writes still fail silently and audit retention/tamper-evidence are absent

**Files/lines:** `src/db.rs:49-68` (`audit` discards errors with `let _ = ...`); audit calls throughout `src/routes.rs` now cover failed OTP/recovery/admin attempts and admin views; no retention/cleanup for `audit_events`; no audit for `check_origin`/CSRF rejects or rate-limit lock transitions.

**Attack scenario / failure mode:** A database issue, disk full, or schema problem silently drops security events. An attacker can brute force/probe without a reliable trail. Audit PII (email/IP/UA) is retained indefinitely; a DB administrator can delete rows. The new failure audits are a real improvement, but the sink is still best-effort.

**Impact:** Reduced detection/forensics; privacy/compliance exposure. Not a direct auth bypass.

**Recommended fix:** Log/alert audit write failures, use an outbox/durable sink, add retention (for example 90-365 days), consider an append-only/off-host sink for production, and audit CSRF/Origin/step-up/rate-limit transitions. Minimize IP/UA retention if not required.

**Blocker for public v0.1:** **No**, but required for incident response and privacy before v1.0.

---

### R2-15 -- Low -- `db_url` is still logged at info; raw WebAuthn errors and `dev_mode` health data leak details

**Files/lines:** `src/main.rs:43-49` logs `db_url`; `src/error.rs:74-76` returns the raw `WebauthnError` string; `src/routes.rs:116-145` exposes `dev_mode` and version on `/healthz`.

**Attack scenario:** A future Postgres URL contains a password; the startup log writes it to journald/container logs. Raw WebAuthn errors can reveal RP ID/origin or credential details. `dev_mode` tells an attacker whether the outbox is open. Logs are often shipped to systems with broader access than the app.

**Impact:** Secret/reconnaissance leakage. Currently SQLite `db_url` is a path, so the credential risk is latent.

**Recommended fix:** Redact `db_url` to scheme/host; return stable generic WebAuthn errors and log details with a correlation ID; keep `/healthz` minimal or restrict it to the proxy/healthcheck network; ensure no query strings/tokens are logged.

**Blocker for public v0.1:** **No**.

---

### R2-16 -- Low/Info -- Test databases and `e2e/node_modules` are present in the working tree; no `.gitignore`

**Files/lines:** `authlayer/final-smoke.db`, `final-smoke.db-wal`, `final-smoke.db-shm`, `smoke-integration.db`, `smoke-integration2.db`; `authlayer/e2e/node_modules/**`; no `authlayer/.gitignore` (only `.dockerignore`).

**Attack scenario / impact:** If the tree is committed/published as-is, test databases may contain test emails, session hashes, audit events, and possibly plaintext dev OTPs/security notifications. `e2e/node_modules` bloats the repository and supply-chain surface. `.dockerignore` excludes `*.db` from the image, which is good.

**Recommended fix:** Add a `.gitignore` covering `.env`, `*.db`, `*.db-shm`, `*.db-wal`, `target/`, `e2e/node_modules/`, and local data; remove test artifacts; verify no real PII is in them. Keep the `.dockerignore` exclusions.

**Blocker for public v0.1:** **No**.

---

### R2-17 -- Medium -- Email bombing and account-creation abuse remain possible

**Files/lines:** `src/routes.rs:319-322` (`start` limits), `:1395-1408` (`recover-start` limits), `:377-385`/`:1412-1451` (email send path); `src/auth.rs:151-175` (`ensure_user` creates an account for any email), `:244-308` (`create_otp` sends the email). There is no CAPTCHA, global per-ASN cap, or per-address cooldown beyond the in-memory limits; `recover-start` still returns success for unknown addresses and only sends for existing accounts.

**Attack scenario:** A botnet (or a single IP with alias addresses) submits arbitrary victim emails to `POST /api/auth/start` (5/min/email, 30/min/IP) and `POST /api/auth/recover/start` (3/5min/email, 20/5min/IP). Each accepted request creates a user row for a new address and/or sends an OTP through the configured SMTP provider. This enables harassment/spam, burns SMTP quota, damages sender reputation, and grows the `users`/`outbox` tables. The per-IP limits can be distributed; plus-aliases and Unicode variants are not canonicalized.

**Impact:** Email-bombing/abuse, deliverability and cost damage, DB growth; no account takeover by itself. A public signup endpoint without CAPTCHA is an abuse target.

**Recommended fix:** Add CAPTCHA/proof-of-work or an invite/allowlist for `start`; enforce global/per-ASN and per-address cooldowns; suppress duplicate sends; canonicalize plus-aliases if acceptable; use provider feedback loops and bounce handling; add a global send budget. Keep recovery-start generic.

**Blocker for public v0.1:** **No** for a small, invite-only self-host; **Yes** for open public signup without edge CAPTCHA/limits.

---

## Other residual items (not separate high-risk findings)

| Item | Severity | File/line | Note / fix |
|---|---|---|---|
| Expired OTP/session/audit cleanup | Low/Medium | `db.rs:39-47` only cleans outbox | Add scheduled cleanup for expired `otp_codes`, `sessions`, `recovery_codes` used/expired, and audit retention. |
| SQLite RFC3339 text comparisons | Low | `routes.rs:976-999`, `:1289-1297` | Auth decisions parse timestamps in Rust; SQL counts/lists can be slightly inconsistent near expiry. Prefer integer epoch. |
| Compose resource limits / read-only root | Low/Medium | `docker-compose.yml:17-98` | No `mem_limit`, `pids_limit`, `read_only`, tmpfs, log rotation; Caddy has no `user`/`cap_drop` override. Add limits and run Caddy non-root with minimal caps. |
| App-level security headers | Low | `main.rs:87-89`; `deploy/Caddyfile:18-30` | Headers are provided by Caddy, not the app. Direct app exposure lacks CSP/HSTS/frame/referrer. Keep app private or add `tower-http` header layers. |
| Admin read-only / no revocation actions | Low/Medium | `routes.rs:1965-2085` | Admin cannot revoke sessions/passkeys or disable users; incident response requires the user dashboard/DB. Add audited admin actions before v1.0. |
| Single-session revoke lacks step-up | Low | `routes.rs:1035-1065` | A stolen session can revoke other sessions (DoS) without step-up; require step-up for revoking other sessions or accept the risk. |
| `__Host-`/cookie config validation | Medium | `routes.rs:148-155`, `config.rs:239-244` | Covered in R2-9; default is still `al_session`. |
| SMTP `opportunistic` | Medium | `config.rs:299-313`, `email.rs:44-58` | Covered in R2-5. |
| `RP_ID` parent-domain scope | Low | `config.rs:231-232`, `.env.example:23-27` | Default is exact host; a parent domain broadens passkey scope to sibling subdomains. Require explicit opt-in. |
| Trusted-proxy fallback/broad CIDR | Low | `auth.rs:699-706`, `config.rs:335-357`, `docker-compose.yml:57-62` | If every XFF hop is trusted, `client_ip` returns the leftmost hop; the 172.28.0.0/16 CIDR includes the Docker gateway. Keep 8080 unpublished; prefer the narrowest Caddy/peer CIDR and set `TRUST_PROXY=false` for direct exposure. |
| README 72-bit recovery claim | Info | `README.md:231` recovery table | New codes are ~63 bits after case/hyphen normalization; still strong. Update the claim or use a case-preserving alphabet. |
| Passkey-user login OTP consumption | Low | `routes.rs:450-474` | `verify_code` verifies/consumes the OTP before checking passkeys; a passkey user gets `use_passkey` but the code is used and failures reset. Check passkeys first while keeping the response generic, or avoid consuming/resetting for the passkey path. |
| Recovery start hides delivery failure | Low | `routes.rs:1440-1451` | `recover_start` audits an email-delivery error but still returns 200. Add metrics/retry and a generic message; do not reveal account existence. |
| Notification task fan-out | Low | `routes.rs:235-265` | One `tokio::spawn` per security notification; bounded by rate limits, but add a queue/backpressure if notifications grow. |

---

## Top 5 remaining blockers

1. **Legacy data migration (upgrade safety).** Invalidate legacy NULL-expiry recovery codes and legacy sessions (`R2-2`, `R2-3`). Without this, an upgraded deployment has permanent recovery backdoors and sessions that survive passkey revocation. Fresh installs should verify no NULL rows exist.
2. **Account-lockout DoS.** Replace the unauthenticated global lock with per-IP/per-account progressive backoff, email-proof or passkey-based unlock, CAPTCHA/edge limits, and user notification (`R2-1`).
3. **CSRF and cookie hardening.** Reject missing `Origin`, add a CSRF token/Sec-Fetch-Site check, default to `__Host-al_session`, enforce Secure/HTTPS, and reject `COOKIE_SECURE=false` outside local dev (`R2-6`, `R2-9`).
4. **Recovery ordering and legacy TTL.** Create the replacement registration challenge before destroying all credentials, and remove/limit legacy NULL-expiry recovery codes (`R2-2`, `R2-4`). Add delay/notification/step-up for high-risk recovery.
5. **Credential and challenge robustness.** Enforce counter-regression policy, bind initial ceremonies to a ceremony cookie/session, and add server-side admin session revocation (`R2-7`, `R2-8`, `R2-11`). Add Compose/systemd resource limits and clean up test DBs.

---

## Go/no-go verdict

**No-go for an unrestricted public self-hosted v0.1 today.**

A **conditional go** is defensible for a **fresh, single-instance** deployment only when all of the following hold:

- The provided Caddy is the sole ingress; the app port is not published; `TRUST_PROXY`/`TRUSTED_PROXY_CIDRS` match the actual network; TLS/HSTS are active.
- `DEV_MODE=false`; `EMAIL_PROVIDER=smtp`; `SMTP_TLS=required`; `SMTP_HOST`/`SMTP_FROM` configured; no `ALLOW_OUTBOX_WITHOUT_DEV`.
- `OTP_SECRET` and `ADMIN_TOKEN` are long random values; admin is empty or protected; `COOKIE_SECURE=true`; no legacy database.
- Account lockout and open-signup email abuse are mitigated at the edge (CAPTCHA/rate limits) or accepted for a small user base; CSRF/`__Host-` and the remaining medium items are tracked with an explicit risk acceptance.

**No-go for upgrades** from a pre-hardening database until R2-2/R2-3 are migrated or all legacy sessions/recovery codes are invalidated.

**No-go for a broad public/multi-user launch** until the top five are fixed; the remaining bearer-session, CSRF, counter, challenge-binding, admin-session, and resource-limit issues should be closed before v1.0.

---

## Not reviewed / limitations

- Static review only: no `cargo check`/`cargo test`/`cargo audit`, no Docker/Caddy run, no SMTP delivery/TLS handshake, no WebAuthn browser ceremony, no concurrency/fuzz/pen test.
- Frontend was grep-reviewed for DOM sinks/storage only; no full browser XSS/CSP/WebAuthn E2E review.
- SMTP behavior reviewed at source level; live STARTTLS/certificate/DKIM/SPF/deliverability not tested.
- No Postgres, native/CLI/SSH/broker/OIDC/multi-tenancy, OS/host hardening, backup/restore drill, or monitoring review.
- The tree is moving; re-run this focused review after the legacy migration, lockout, CSRF/cookie, and recovery-ordering changes land.
