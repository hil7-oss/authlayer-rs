# AuthLayer — agent control log

Role: project director / integrator.
Working root: `C:\Users\AMG\Desktop\autorization`
Product root: `C:\Users\AMG\Desktop\autorization\authlayer`

## Current stage

**Stage 2 — first working build.** Architecture is decided; the v0.1 Rust server, frontend, deployment, docs, tests, and security review are being produced in parallel. Integration and live verification come next.

## File ownership (no overlaps)

| Workstream | Agent session | Owns | Must not touch |
|---|---|---|---|
| Backend compile/fix | `ses_df9db9bc3ffel63gGJ4D946cOf` | `authlayer/src/**`, `authlayer/Cargo.toml`, `authlayer/migrations/**` | `static/**`, `deploy/**`, docs |
| Frontend | `ses_df9db9bc2ffe1hYMjy1HtB8D3c` | `authlayer/static/index.html`, `app.js`, `style.css` | Rust, deploy, docs |
| DevOps | `ses_df9db9bbdffdP4VWttIUaeE3fs` | `Dockerfile`, `.dockerignore`, `docker-compose.yml`, `.env.example`, `deploy/**` | Rust, static, docs |
| Docs | `ses_df9db9bb7ffeSwqvBbs3mNRr7U` | `authlayer/README.md`, `authlayer/docs/IMPLEMENTATION.md` | Rust, static, deploy |
| QA / smoke | `ses_df9db9bb6ffeUugqoCUtdZU3Ft` | `authlayer/scripts/**` | Rust, static, deploy |
| Security review | `ses_df9db9bb5ffeQ7w8nYCmy8n9JM` | `authlayer/SECURITY_REVIEW.md` (new file only) | everything else |

## Agent reports

### QA / smoke — completed

- Files: `authlayer/scripts/smoke.mjs`, `authlayer/scripts/README.md`.
- `node --check scripts/smoke.mjs` -> exit 0.
- Live run blocked: no compiled server was running (`ECONNREFUSED`).
- Harness validated against a temporary mock API: dev on -> 14 passed / 1 skipped; dev off -> 11 passed / 4 skipped.
- Backend bug found: admin users heading uses `users_html.len()` instead of user count. Sent to backend agent.
- Not covered: WebAuthn ceremonies, authenticated dashboard endpoints, recovery, real email, rate-limit exhaustion, Origin/CSRF, frontend.

### DevOps — completed

- Files: `authlayer/Dockerfile`, `.dockerignore`, `docker-compose.yml`, `.env.example`, `deploy/Caddyfile`, `deploy/authlayer.service`, `deploy/README.md`.
- `docker compose --env-file .env.example config --quiet` -> OK.
- `docker build --check .` -> no warnings.
- Caddy config validated in a container; forged `X-Forwarded-For` replaced correctly.
- `systemd-analyze verify` parsed the unit; only expected missing-binary error.
- Not tested: full image build (waits on Rust compile), live container, ACME/DNS, real Ubuntu systemd start.
- Blocker for real users: no SMTP provider; with `DEV_MODE=false` the OTP is only in the outbox and cannot be read. SMTP is the next backend feature.

### Backend — completed

- `cargo check` -> exit 0, zero warnings.
- `cargo test` -> exit 0, 0 tests.
- `cargo fmt --check` -> exit 0.
- `cargo build` -> exit 0, MSVC linked.
- Runtime smoke: health, start, dev outbox, verify-code, OTP replay rejected, malformed/reused WebAuthn challenge rejected, unauth sessions 401, admin 404/403/200, bad email 400, foreign Origin 403, logout cookie cleared.
- Fixed admin user count, atomic OTP consumption, deterministic OTP lookup, user-creation race.
- Remaining risks: unbounded challenge/rate maps, no `Cache-Control: no-store`, no transactional OTP+outbox, no finish-endpoint rate limits, XFF trust.

### Docs — completed

- Files: `authlayer/README.md`, `authlayer/docs/IMPLEMENTATION.md` (Russian; API/paths in English).
- Covers all 21 routes and 12 env vars, current v0.1 behavior, limitations, data model, flows, extension guides.
- Found stale top-level docs and P0/P1 gaps: no SMTP, no add-passkey endpoint, recovery consumption not atomic, missing transactions, no `Cache-Control: no-store`, no app security headers, empty `OTP_SECRET` warning bug, revoke semantics, rate limits, trusted proxy, admin hardening, health DB check, outbox retention.
- PROJECT_STATE.md updated by director; top-level README status update pending.

### Backend — round 2 (in progress)

Scoped follow-up:
- real SMTP sender via `lettre` (`EMAIL_PROVIDER`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TLS`);
- empty `OTP_SECRET` warning;
- atomic recovery-code consumption;
- `Cache-Control: no-store`;
- rate limits on verify/passkey/recovery;
- DB health check;
- 404 semantics for revoke;
- transactions for OTP+outbox and recovery batches;
- authenticated add-passkey endpoints (`/api/passkeys/add/start`, `/finish`).

### Backend — round 2 completed

- Real SMTP via `lettre`: `EMAIL_PROVIDER=outbox|smtp`; `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TLS`; startup validation; 10s timeout; secrets redacted.
- Atomic recovery-code consumption; OTP+outbox and recovery-batch transactions.
- `Cache-Control: no-store` on all responses.
- Rate limits on verify/passkey/recovery.
- DB-backed `/healthz` (503 on failure).
- 404 for unknown/foreign revokes.
- Add-passkey endpoints: `POST /api/passkeys/add/start`, `POST /api/passkeys/add/finish`.
- `cargo fmt`, `check`, `test`, `build` -> all pass.
- Live smoke: 14 passed, 1 skipped (admin token unset), exit 0.
- Tested: SMTP config validation, outbox mode, SMTP failure path, headers, rate limits, add-passkey auth/binding/one-time, recovery race, 404 revokes, current-session revoke.
- Not tested: real external SMTP, browser WebAuthn ceremonies, DB-failure 503 path.

### Security review — completed (snapshot before latest round)

- Report: `authlayer/SECURITY_REVIEW.md`.
- Verdict: not ready for public self-hosted v0.1.
- Critical: dev outbox can expose live OTPs; `DEV_MODE` auto-enables on loopback; plaintext OTPs persisted in outbox.
- High: stolen session can add passkey / mint recovery codes / revoke credentials without step-up; 7-day bearer sessions with no idle/binding/revoke-all/cascade; admin token in query string; recovery has no delay/notification/revocation and codes never expire; OTP HMAC not context-bound; weak/placeholder `OTP_SECRET`; XFF trusted blindly; SMTP not wired into deployment docs (being fixed by DevOps/docs).
- Positive: 256-bit session tokens, hashes, HMAC, constant-time compares, one-time updates, transactions, no-store, non-root Docker, hardened systemd, Caddy headers, safe frontend DOM.
- Director triage: fix Critical + High before calling v0.1 public-ready.

### QA — round 2 completed

- `scripts/smoke.mjs` now has 19 checks: added `Cache-Control: no-store` on four endpoints, add-passkey unauth 401 on start/finish, DB-backed health, and non-existent-user verify-code 400.
- `node --check` -> exit 0.
- Mock API validation: dev on 18 passed/1 skipped; dev off 15 passed/4 skipped; missing no-store and admin mismatch fail as expected.
- Live not run because no server was running at that moment; director will re-run after backend security wave.
- Admin cookie-auth change will require another smoke update; noted.

### Frontend — initial build completed

- Files: `static/index.html`, `static/app.js`, `static/style.css`.
- Implements email code, passkey registration/login, recovery, dashboard, passkey/session revoke, recovery regeneration, logout, add-passkey.
- `node --check` -> exit 0.
- Mock API + Chrome virtual authenticator: 50 checks passed, 0 console errors, 320/360/390 mobile overflow checks passed.
- No `innerHTML`, `localStorage`, `sessionStorage`, `eval`, or secret logging.
- Step-up re-auth UI is now being added in a follow-up; no live compiled-backend test yet.

### DevOps — SMTP deployment surface completed

- Updated `.env.example`, `docker-compose.yml`, `deploy/README.md`.
- Added `EMAIL_PROVIDER` + all `SMTP_*` vars; outbox default; TLS/465/587 guidance; SPF/DKIM/DMARC checklist.
- `docker compose --env-file .env.example config --quiet` -> OK.
- SMTP not live-tested; no real credentials.
- Caveats: Compose does not validate SMTP completeness; app startup does. `SMTP_TLS=opportunistic/none` can be insecure; private-CA SMTP unsupported.
- Pending: security-wave env vars (`TRUST_PROXY`, `SESSION_IDLE_HOURS`, `ALLOW_INSECURE_DEV_MODE`, `ALLOW_OUTBOX_WITHOUT_DEV`, admin cookie) must be added after backend report.

### Browser E2E — completed (pre-final)

- Files: `authlayer/e2e/passkey.mjs`, `README.md`, `.gitignore`, `package.json`, `package-lock.json`; `playwright-core@1.65.1`, system Chrome 157.
- `node --check` -> OK; `npm install` -> OK.
- Real headless Chrome + CDP virtual WebAuthn authenticator against the compiled binary: **PASS 17 | FAIL 0 | SKIP 0**.
- Covered: email OTP from dev outbox, passkey registration, recovery codes, dashboard, HttpOnly/SameSite cookies, logout, passkey login, step-up `/api/auth/stepup/start|finish`, second passkey add, passkey revoke, no console/page errors.
- Cleanup verified: no server/Chrome processes, temp DB/logs removed.
- Must re-run after backend security wave finalizes and after frontend visible step-up UI, with a freshly rebuilt binary.
- Limitations: virtual authenticator is not a hardware key; no real SMTP; `Secure=false` expected over local HTTP; selectors depend on current UI labels.

### Frontend — step-up UI completed

- Files: `static/index.html`, `static/app.js`, `static/style.css`.
- `performStepUp()` + `withStepUp()` wrapper; handles 403 `stepup_required`, retries once, deduplicates concurrent prompts.
- Protected: add passkey (start/finish), recovery regeneration, passkey revoke, sign-out-everywhere.
- New `POST /api/sessions/revoke-all` UI with confirmation and cookie-clear handling.
- Visible “Confirm with your passkey” status panel, `aria-live`.
- Handles no-passkey, missing endpoints, revoked-session-after-passkey-removal, cancellation, 401.
- `node --check` -> PASS.
- Mock step-up-gated API + Chrome virtual authenticators: 60 checks passed, 0 console errors, mobile 320/360/390 checks passed.
- No `innerHTML`/storage/eval/console.
- Needs re-run against freshly rebuilt Rust backend.

### Docs — round 2 completed

- Updated `authlayer/README.md` and `authlayer/docs/IMPLEMENTATION.md` for SMTP, admin cookie login, step-up, add-passkey, sessions/recovery/TTL, trusted proxy, rate limits, 28 routes, 25 config vars.
- Docs now reflect migration `0002_security_hardening.sql`.
- Found backend issues: expired recovery codes counted as available (can allow deleting last passkey); step-up window effectively ~10 min; admin query-token docs stale in deploy/scripts; `PROJECT_STATE` needs final update.
- Backend follow-up sent for the two correctness bugs.
- Remaining doc caveats: external SMTP and browser WebAuthn are not claimed as tested; `cargo test` has 0 tests; security review is internal.

### QA — round 3 (in progress)

- Smoke script being updated for admin cookie login (`/admin/login`, `al_admin`, manual redirects), step-up unauth 401, and revoke-all unauth 401.
- Old `?token=` admin checks are stale and must be replaced.

### Backend — security hardening wave completed

- Critical/High fixes implemented: explicit `DEV_MODE` + loopback guard, outbox redaction/retention, context-bound OTP/recovery HMAC, secret validation, atomic attempts + account lockout, step-up for sensitive actions, session idle timeout/passkey binding/revoke-all, recovery TTL + old credential revocation + notifications, admin cookie login, trusted-proxy CIDRs, WAL/FK/busy-timeout, status checks, cleanup.
- Migration `0002_security_hardening.sql`.
- `cargo fmt/check/test/build` -> all pass.
- Live smoke: 21 passed/5 skipped without admin token; 26 passed/0 failed/0 skipped with admin token.
- Fixed expired recovery counts and step-up 5-minute window after docs review.
- Remaining: docs line corrections (sent), legacy NULL-expiry recovery rows use old HMAC until regenerated, external SMTP not tested.

### Browser E2E — final run after security wave

- `node passkey.mjs` with `E2E_START_SERVER=1` -> **PASS 17 | FAIL 0 | SKIP 0**.
- Covered registration, recovery codes, dashboard, cookies, logout, passkey login, step-up, second passkey, passkey revoke, zero console/page errors.
- Cleanup verified.
- Still to add: a UI-only assertion that the visible step-up panel appears (the harness currently completes step-up through the API); frontend mock covers the visible path.

### QA — round 3 completed

- `scripts/smoke.mjs` now 26 checks: admin cookie login, manual redirects, step-up unauth 401, revoke-all unauth 401, DB health, no-store, add-passkey 401.
- `node --check` -> exit 0.
- **Director live run against final binary:** 26 passed, 0 failed, 0 skipped with a 32+ char `ADMIN_TOKEN`; admin page loaded with cookie; logout cleared it.
- Expected non-admin mode: 21 passed, 5 skipped.
- Caveat: admin login is 5/min/IP; repeated rapid runs can rate-limit.

### DevOps — final security deployment completed

- `.env.example`, `docker-compose.yml`, `deploy/Caddyfile`, `deploy/README.md`, `deploy/authlayer.service` updated.
- All 25 config vars present; fail-closed production defaults: `DEV_MODE=false`, `EMAIL_PROVIDER=smtp`, empty SMTP host/from, `OTP_SECRET` placeholder rejected, `ADMIN_TOKEN` disabled by default.
- Dedicated `172.28.0.0/16` bridge; app has no published ports; `TRUST_PROXY=true` + `TRUSTED_PROXY_CIDRS=172.28.0.0/16`; Caddy overwrites `X-Forwarded-For`/`X-Real-IP`.
- Admin login via `/admin/login` + `al_admin` cookie; no query token.
- `docker compose --env-file .env.example config --quiet` -> OK; Caddy config valid; secret scan clean.
- Caveats: Compose parses but app fails until SMTP + real OTP_SECRET configured; full image build/live startup not run by DevOps; CDN/LB needs Caddy `trusted_proxies`; systemd proxy CIDR differs; SMTP not live-tested.

### Director verification — Docker image bug found

- `docker build -t authlayer:local .` completed.
- Container exited 0 immediately with no logs.
- `/usr/local/bin/authlayer` was 437,752 bytes, consistent with the dummy `fn main() {}` dependency-cache binary.
- Root cause: Dockerfile builds a dummy main, deletes `src`, copies real `src`, then relies on Cargo mtimes; the authlayer crate was not rebuilt and the dummy binary was copied.
- DevOps follow-up sent: remove the dummy cache trick or force `touch`/`cargo clean -p authlayer`, rebuild, verify binary size and live `/healthz`.
- This is a blocker for saying the Docker image works.

### Docs — final corrections completed

- `authlayer/README.md` and `authlayer/docs/IMPLEMENTATION.md` corrected for real 5-minute step-up, expired recovery filtering, legacy NULL-expiry behavior, smoke 26/26, E2E 17/17, Apache-2.0.
- PROJECT_STATE.md rewritten by director to current state.
- Remaining stale doc: `SECURITY_REVIEW.md` describes pre-fix code; round 2 report will supersede it.

### Backend — clippy cleanup (in progress)

- `cargo clippy --all-targets -- -D warnings` found 7 style issues: 4 explicit auto-derefs, 1 collapsible if, 1 large enum variant, 1 related.
- Backend follow-up sent; CI now includes clippy `-D warnings`.
- No security/logic findings from clippy.

### Backend — clippy cleanup completed

- Fixed 7 clippy warnings: explicit auto-derefs, collapsible if, large SMTP enum variant (boxed).
- `cargo fmt`, `clippy -D warnings`, `check`, `test`, `build` -> all pass.
- Live smoke without admin: 21 passed, 5 skipped.
- No behavior changes.

### DevOps — Docker dummy-binary fixed

- Removed the dummy dependency-cache stage; builder now compiles the real source once.
- Rebuilt `authlayer:local`: binary is **13,685,440 bytes** (was 437,752 dummy), image 153 MB.
- Container without env now exits 1 with a clear config error, not silent 0.
- Live container with dev/outbox env: Docker health **healthy**, `/healthz` 200, `/api/me` 200, real startup logs.
- `docker compose --env-file .env.example config --quiet` -> OK.
- Caveat: dependency caching removed for correctness; slower rebuilds. SMTP/TLS/trusted-proxy paths not exercised in the container test.

### Director — final smoke after Docker/clippy

- Live smoke against current binary with admin token: **26 passed, 0 failed, 0 skipped**.
- Docker image health verified by DevOps; container cleaned up.

### Browser E2E — visible step-up completed

- `e2e/passkey.mjs` now drives step-up through the visible UI, not API.
- Final result: **PASS 18 | FAIL 0 | SKIP 0**.
- Visible `#stepup-status` with "Confirm with your passkey" exercised for add-passkey and sign-out-everywhere.
- Sign-out-everywhere clears the session cookie and returns to signed-out state.
- No unexpected console/page errors; cleanup verified.

### Director — SMTP delivery verified with Mailpit

- Ran real `EMAIL_PROVIDER=smtp` against a local Mailpit SMTP sink (port 1025).
- `POST /api/auth/start` created the OTP; Mailpit received "Your AuthLayer sign-in code"; the 6-digit code was read from the message and accepted by `/api/auth/verify-code` -> `flow=register_passkey`.
- Result: **SMTP_E2E=PASS**. External provider (Postmark/SES/Mailgun) still not tested; same code path, provider handles delivery.

### Security review — round 2 completed

- Report: `authlayer/SECURITY_REVIEW_ROUND2.md`.
- Verdict: **no-go for unrestricted public v0.1**; conditional go only for a fresh single-instance deployment behind Caddy with `DEV_MODE=false`, SMTP TLS required, strong secrets, secure cookies, no published port, admin disabled/protected, no legacy DB.
- Fixed: C-1, H-1 production, H-3, H-5, H-8, H-9, H-10, M-5, most M-8.
- Remaining top blockers: legacy NULL-expiry recovery/legacy sessions; account-lockout DoS; recovery ordering; CSRF/Origin + `__Host-`/Secure enforcement; counter regression; unbound initial challenges; stateless admin logout; SMTP opportunistic; audit failures; test DB artifacts.
- Director launched final backend security round and DevOps resource limits. Test DB artifacts removed; root `.gitignore` covers DBs/target/env/e2e node_modules.
- Final release gate: fresh deployment conditional go or better; no upgrade path until migration invalidates legacy credentials.

### DevOps — container resource limits completed

- App: read-only root, `/tmp` tmpfs 16m, `TMPDIR`/`SQLITE_TMPDIR=/tmp`, `mem_limit=256m`, `pids_limit=100`, `cap_drop=ALL`, no-new-privileges, log rotation, `/data` writable, no published port.
- Caddy: `cap_drop=ALL`, `cap_add=NET_BIND_SERVICE`, `mem_limit=128m`, `pids_limit=100`, log rotation, `/data`+`/config` writable.
- `docker compose --env-file .env.example config` -> OK.
- Not runtime-verified with read-only root/caps; must test after final image/backend round.

### Backend — final security round completed

- Migration `0003_legacy_and_cookie.sql`: invalidates legacy NULL-expiry recovery codes and legacy sessions; adds `passkeys.counter` and `admin_sessions`.
- Removed legacy recovery path; account hard-lockout removed (advisory counter only).
- Origin required outside dev; session `SameSite=Strict`; `__Host-al_session` + Secure/HTTPS enforcement.
- Recovery challenge created before credential revocation.
- Passkey counter-regression policy implemented.
- `al_ceremony` cookie binds initial/recovery/add-passkey/step-up challenges.
- Admin auth is DB-backed `admin_sessions` with logout revocation.
- SMTP opportunistic rejected outside dev/with credentials; audit failures logged; DB URL redacted; `ALLOW_RP_ID_PARENT`; expired-row cleanup.
- `cargo fmt`, `clippy -D warnings`, `check`, `test`, `build` -> all pass.
- Live dev smoke 26/26 with admin token; additional production cookie/Origin/admin-session/recovery/counter/ceremony tests passed.
- Remaining: E2E SameSite assertion fix/re-run (agent running), docs/deploy sync (agents running), Docker rebuild, real-provider SMTP, real-device matrix.

### Browser E2E — final Strict/cookie run completed

- `e2e/passkey.mjs` updated to `SameSite=Strict` and `al_ceremony` diagnostics.
- **PASS 18 | FAIL 0 | SKIP 0** against current binary.
- Visible step-up exercised for add-passkey and sign-out-everywhere.
- Registration/login session cookies: HttpOnly, SameSite=Strict; `Secure=false` only on local HTTP.
- `al_ceremony` present during registration/login/add/step-up ceremonies, absent after completion; does not break flows.
- Cleanup verified; no stale Lax references.

### Director — final Docker runtime verification

- Rebuilt `authlayer:local` on final code.
- Ran with `--read-only`, `/tmp` tmpfs 16m, `cap-drop ALL`, `no-new-privileges`, `memory=256m`, `pids-limit=100`, `/data` volume, dev/outbox env.
- `/healthz` 200, `/api/me` anonymous, `POST /api/auth/start` -> `flow=code`.
- Docker healthcheck after start period: **healthy**.
- Cleaned container and volume.
- This verifies read-only root + SQLite `/data` + tmpfs behavior.

### DevOps — final env/deploy sync completed

- `.env.example`, `docker-compose.yml`, `deploy/README.md`, `deploy/Caddyfile` comments, `deploy/authlayer.service` comments updated.
- 26 config vars present; production `COOKIE_NAME=__Host-al_session`, `COOKIE_SECURE=true`, `DEV_MODE=false`, `SMTP_TLS=required`, `ALLOW_RP_ID_PARENT=false`, trusted proxy CIDR.
- Admin server-side sessions, Origin requirement, `al_ceremony`, migration/upgrade warning, lockout removal documented.
- `docker compose config` -> OK; Caddy config valid; no secrets.
- Caveats: app still fails closed with template SMTP/OTP placeholder; manual WebAuthn clients must preserve `al_ceremony`; changing `ADMIN_TOKEN` does not revoke existing admin sessions.

### Director — production-mode Origin/cookie verification

- Ran non-dev server with `APP_URL=https://localhost:8082`, `COOKIE_SECURE=true`, `COOKIE_NAME=__Host-al_session`, outbox allowed explicitly.
- `POST /api/auth/start` without `Origin` -> 403.
- With exact `Origin: https://localhost:8082` -> 200 `flow=code`.
- With `Origin: https://evil.example` -> 403.
- Confirms fail-closed Origin behavior outside dev. Cleanup done.

### Security review — round 3 completed

- Report: `authlayer/SECURITY_REVIEW_ROUND3.md`.
- Verdict: unrestricted public v0.1 **NO-GO**; conditional GO for a fresh single-instance behind Caddy with strict config, migration 0003, no legacy DB; upgrades conditional on 0003 + counter backfill/re-registration.
- Fixed: R2-1, R2-2/R2-3, R2-4, R2-5, R2-6, R2-7, R2-9, R2-11.
- Partial: R2-8 (counter policy works; existing passkeys default 0), R2-12, R2-14, R2-15, R2-16, R2-17.
- Not fixed: R2-10 (passkey-account enumeration), R2-13 (OTP committed before SMTP send).
- New: R3-1 OTP/email abuse without CAPTCHA, R3-2 counter backfill on upgrade, R3-3 admin token rotation does not revoke existing admin sessions, R3-4 admin/ceremony cookie prefixes, R3-5 immediate recovery design.
- Release gate: conditional self-hosted v0.1.0; not open public launch.

### Director — final SMTP E2E after security round

- Mailpit SMTP sink + final binary: `START_FLOW=code`, message received, 6-digit code accepted, `VERIFY_FLOW=register_passkey`, **FINAL_SMTP_E2E=PASS**.
- Confirms the final OTP/email path after security changes. External provider still untested.

## Integration checklist

- [x] Backend agent reports `cargo check` = 0 and `cargo test` = 0.
- [x] Frontend agent reports `node --check static/app.js` = 0; step-up UI added.
- [x] DevOps agent reports `docker compose config` result (SMTP update); final security-env update pending.
- [x] Docs agent reports docs written and code/doc mismatches (round 2 done; final corrections pending).
- [x] QA agent reports smoke script syntax and live result (26/26 with admin token).
- [x] Security review delivered; Critical/High triage done; hardening wave implemented.
- [x] Director ran live HTTP smoke: **26 passed, 0 failed, 0 skipped** against `target/debug/authlayer.exe` on `127.0.0.1:8080` with admin token.
- [x] Browser E2E core: **17/17 PASS** with Chrome virtual authenticator (registration, login, recovery codes, cookies, logout, step-up, add/revoke passkey).
- [x] `/healthz`, dev outbox, wrong/real code, passkey registration API, session cookie flags, dashboard, recovery codes, logout, admin cookie.
- [x] Visible step-up panel E2E: 18/18 PASS, including sign-out-everywhere.
- [x] Security re-review round 2 and round 3 (Delta) completed.
- [x] Docker image fixed, real binary, container healthy with read-only root/limits; final rebuild done.
- [x] Final docs/Deploy update for 26 env vars/admin login.
- [x] SMTP delivery verified with Mailpit end-to-end.
- [x] Clean test DB artifacts; root and authlayer `.gitignore`.
- [ ] Final docs round-3 sync (agent running).
- [ ] `v0.1.0` git commit/tag.
- [x] Note: local server bound `127.0.0.1`; E2E used `http://localhost:8080` and Chrome resolved it correctly. Production must bind behind Caddy, not expose 8080.
- [ ] Fix Critical/High security findings.
- [ ] Re-run smoke tests.
- [ ] Write final `STATUS.md` with what works, what doesn't, how to run.
- [ ] Optional: `git init`, baseline commit, tag `v0.1.0`.

## Director decisions locked so far

- Rust + Axum + SQLite for v0.1.
- Email OTP bootstrap + WebAuthn passkeys.
- No passwords, no password reset.
- 7-day server-side sessions, HttpOnly cookie.
- Recovery codes.
- Dev outbox for local email.
- No ML in the auth path.
- No legacy password broker / SSH in v0.1.
- Docker + Caddy for deployment.
- Target license: Apache-2.0.

## Known integration risks

1. `webauthn-rs` 0.6 API differences may require backend changes.
2. WebAuthn on `http://localhost` is a secure context in browsers, but `RP_ID` must be exactly `localhost`; production must use HTTPS and the exact domain.
3. The frontend must serialize WebAuthn responses with base64url and camelCase fields expected by `webauthn-rs`.
4. SQLite absolute path in Docker must be `sqlite:///data/authlayer.db?mode=rwc`.
5. `COOKIE_SECURE=true` will prevent cookies on plain HTTP; local dev must use `COOKIE_SECURE=false`.
6. `OTP_SECRET` unset means random per process; codes break on restart.
7. Challenge maps are in memory; restart invalidates in-flight passkey ceremonies.
8. No SMTP yet; dev outbox only. Production email is a blocker for real use.
9. Sessions are bearer-only until DPoP/DBSC; this is a v0.2 hardening item.
10. `ADMIN_TOKEN` in a query string is a v0.1 convenience; replace with a proper admin session before production.

## Reporting rule

Each agent must report:
- files changed,
- commands run and exact results,
- blockers,
- risks,
- what it did not do.

The director will not accept "done" without command evidence. No agent may weaken security controls to make something compile or pass.
