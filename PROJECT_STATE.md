# AuthLayer — project state

Last updated: 2026-11-23 (final integration)

## What we are building

An open-source, self-hosted passwordless authentication server: email OTP bootstrap + WebAuthn passkeys + server-side sessions + recovery codes. No passwords are stored or requested from users.

Working name: **AuthLayer**. Reference implementation language: **Rust**.

## Product decisions (locked)

- **Rust** for the server/core. No Node/Go core in v0.1.
- **Axum** HTTP server.
- **SQLite** for v0.1 (single binary, zero external DB). Postgres is a later migration.
- **WebAuthn/passkeys** via `webauthn-rs` 0.6.
- **Email OTP** 6 digits, 10 minutes, one-time, max 5 attempts; no hard account lockout (advisory failures + rate limits).
- **Sessions**: opaque 256-bit token, SHA-256 hash in DB, HttpOnly cookie, 7-day absolute, 24-hour idle.
- **Recovery**: 8 one-time codes, context-bound HMAC, 365-day default expiry, shown once.
- **No passwords. No password reset.**
- **Legacy password broker / SSH certificates** are out of scope for v0.1.
- **Neural network / risk engine** is out of scope for v0.1; auth stays deterministic.
- License: Apache-2.0 (`LICENSE`).

## Current status (short)

**The backend works and has passed live HTTP + browser E2E.**

- `cargo check` -> 0 errors, 0 warnings.
- `cargo test` -> 0 tests, exits 0.
- `cargo fmt --check` -> 0.
- `cargo build` -> 0 (MSVC).
- Live smoke `scripts/smoke.mjs` -> **26 passed, 0 failed, 0 skipped** with a 32+ char admin token; 21 passed / 5 skipped without admin.
- Browser E2E `e2e/passkey.mjs` -> **18/18 PASS** with Chrome CDP virtual authenticator: registration, recovery codes, dashboard, HttpOnly/SameSite=Strict cookies, `al_ceremony` challenge cookie, logout, passkey login, visible step-up panel, second passkey, passkey revoke, sign-out-everywhere, no unexpected console errors.
- Docker image is **fixed and verified**: real binary 13,685,440 bytes, container health `healthy`, `/healthz` 200, `/api/me` 200, real startup logs. `docker compose config` passes. The dummy-binary caching bug is closed.
- Security: round 3 complete (`SECURITY_REVIEW_ROUND3.md`). Verdict: **unrestricted public v0.1 is NO-GO**, but a **conditional GO** is defensible for a fresh single-instance deployment behind the provided Caddy with `DEV_MODE=false`, HTTPS/`__Host-`, SMTP TLS required, exact `RP_ID`, strong secrets, admin disabled/restricted, migration 0003 applied with backup, and edge CAPTCHA/rate limits. Upgrades require migration 0003 + counter backfill/re-registration. This is a **conditional self-hosted release**, not a broad public launch.
- SMTP delivery is verified against a local Mailpit sink end-to-end on the final binary (`FINAL_SMTP_E2E=PASS`: OTP email -> code -> verify); an external provider (Postmark/SES/Mailgun) is still not tested. Deployment defaults are fail-closed.
- Real-device passkey matrix (Windows Hello, Touch ID, Android, iOS, YubiKey) is not tested; E2E uses a virtual authenticator.

## Repository layout

```text
authlayer/
  Cargo.toml / Cargo.lock
  Dockerfile / .dockerignore / docker-compose.yml / .env.example
  migrations/
    0001_init.sql
    0002_security_hardening.sql
  src/
    main.rs config.rs db.rs auth.rs email.rs error.rs state.rs routes.rs
  static/
    index.html app.js style.css
  scripts/
    smoke.mjs README.md
  deploy/
    Caddyfile authlayer.service README.md
  docs/
    IMPLEMENTATION.md
  e2e/
    passkey.mjs README.md package.json package-lock.json .gitignore
  README.md
  SECURITY_REVIEW.md
  SECURITY_REVIEW_ROUND2.md   (expected)
```

Top-level:

```text
README.md
PROJECT_STATE.md
AGENT_LOG.md
SECURITY.md
LICENSE
.github/workflows/ci.yml
.gitignore
docs/ (product/architecture/market/MVP)
```

## Implemented and verified

- Config from env (26 vars): bind/app/RP/db, OTP secret, cookies, dev/proxy flags, session/recovery TTLs, SMTP, admin, trusted proxies, RP parent-domain gate.
- SQLite pool + migrations; WAL, foreign keys, busy timeout.
- Tables: users, otp_codes, passkeys, sessions, recovery_codes, outbox, audit_events.
- Email OTP: 6 digits, HMAC context-bound to user/purpose/OTP id/expiry, atomic attempts, 10-min TTL; advisory failure counter, no hard lockout.
- Sessions: 256-bit opaque token, SHA-256 hash, HttpOnly/SameSite, 7-day absolute, 24-hour idle, passkey binding, revoke one/all, cascade on passkey removal.
- WebAuthn: registration/login/add-passkey, one-time in-memory challenges with TTL, user verification required, passkey counter update.
- Step-up: `POST /api/auth/stepup/start|finish`, 5-minute window, required for add passkey, recovery regeneration, passkey revoke, revoke-all.
- Recovery: 8 codes, context-bound HMAC, 365-day TTL, atomic use, email + recovery code, revokes all old sessions/passkeys, notification.
- Admin: `/admin/login` form + `al_admin` HttpOnly/SameSite=Strict cookie backed by DB `admin_sessions` (1-hour TTL, logout revocation), rate-limited, audited; no query token.
- SMTP via `lettre`, TLS modes, startup validation, 10s timeout, redacted outbox in non-dev, outbox retention.
- Security: explicit `DEV_MODE`, loopback guard, fail-closed outbox+non-dev, trusted proxy CIDRs, `Cache-Control: no-store`, DB health, 404 revokes, audit events.
- Frontend: full flow, recovery, dashboard, add/revoke passkey, session revoke, sign-out-everywhere, visible step-up panel, responsive/accessible, no innerHTML/localStorage/eval.
- Deployment: Dockerfile (being fixed), Compose + Caddy + dedicated network, systemd unit, `.env.example`.
- QA: 26-check smoke, 17-check browser E2E.
- Docs: `authlayer/README.md`, `authlayer/docs/IMPLEMENTATION.md`, top-level product/architecture docs.
- License, SECURITY.md, CI workflow.

## Known gaps / issues

### P0 before calling it production-ready

- **Security round 3 is a conditional go, not a full public go.** Top remaining risks: open-signup OTP/email abuse without CAPTCHA/edge limits; immediate recovery on email OTP + recovery code with no delay/step-up; bearer sessions without DPoP/DBSC. Do not run open public signup or high-value accounts until these are addressed.
- **External SMTP provider delivery** is not tested (local Mailpit path passes). Test with Postmark/SES/Mailgun; configure SPF/DKIM/DMARC.
- **Upgrades from a pre-hardening DB** require migration 0003, backup, forced re-login/recovery regeneration, and counter backfill or passkey re-registration. Fresh installs are the only fully supported path for v0.1.
- **No independent external audit.** Internal reviews are not a substitute.
- **Admin token rotation does not revoke existing admin sessions** (R3-3); logout or 1h TTL. Admin is read-only and optional; restrict at the network layer.
- **Real-device passkey matrix** is not tested (Windows Hello, Touch ID, Android, iOS, YubiKey).

### P1 hardening

- Sessions remain bearer-only (no DPoP/DBSC/mTLS); step-up + idle + passkey binding + revoke-all mitigate, not eliminate, cookie theft.
- Migration 0003 invalidates legacy NULL-expiry recovery codes and legacy NULL-passkey sessions; existing passkeys default counter 0 until backfilled/re-registered (R3-2).
- In-memory challenge/rate-limit maps are single-process; no Redis/Postgres.
- SQLite single-instance; no read replicas.
- No account deletion / email change.
- Admin page is read-only; no disable-user/revoke actions.
- No multi-tenancy / localization.
- App-level security headers are delegated to Caddy in production.
- `recover/start` hides SMTP/DB errors behind a generic response.
- `cargo test` has 0 unit/integration tests; smoke + E2E cover happy paths and key denials.

## Build environment

- Windows host; production target Linux (Docker).
- Rust 1.100.0 MSVC + Visual Studio 2022 Build Tools.
- Node.js 24; Chrome 157 + Edge installed.
- Docker Desktop; `authlayer:local` built but currently broken (dummy binary).
- `playwright-core` installed in `authlayer/e2e`.

## How to run locally (verified path)

```powershell
cd authlayer
$env:APP_URL="http://localhost:8080"
$env:RP_ID="localhost"
$env:BIND_ADDR="127.0.0.1:8080"
$env:DATABASE_URL="sqlite://authlayer.db?mode=rwc"
$env:DEV_MODE="true"
$env:EMAIL_PROVIDER="outbox"
$env:OTP_SECRET="dev-only-secret-0123456789abcdef0123456789"
$env:COOKIE_SECURE="false"
cargo run
```

Open `http://localhost:8080`; read the OTP at `http://localhost:8080/dev/outbox`.

- `OTP_SECRET` must be 32+ chars and not a known placeholder when non-dev; local dev warns but still rejects placeholders.
- `DEV_MODE=true` requires loopback `BIND_ADDR`/`APP_URL` unless `ALLOW_INSECURE_DEV_MODE=true`.
- WebAuthn requires a secure context; `http://localhost` is allowed. Production must use HTTPS.
- `COOKIE_SECURE=true` only works over HTTPS.

## Agent workstreams (status)

- **Backend compile/fix** — completed; security wave completed; final fixes verified.
- **Frontend** — completed, including step-up UI.
- **DevOps** — SMTP/deploy final update completed; Docker dummy-binary fixed and container health verified.
- **Docs** — completed; final corrections applied.
- **QA** — completed; final 26/26 live smoke.
- **Browser E2E** — completed 18/18, including visible step-up and sign-out-everywhere.
- **Security review** — round 1 completed; round 2 in progress.

## Next steps

1. Final docs sync for round-3 verdict and env tables.
2. Run final smoke/E2E once more if docs/deploy edits touch runtime (they do not).
3. Commit and tag **v0.1.0** as a conditional self-hosted release.
4. Publish security notes and deployment gate (fresh single-instance behind Caddy; no open signup; no untested upgrades).
5. Plan v0.2: Postgres, DPoP/DBSC, CAPTCHA/abuse controls, recovery delay/step-up, admin token rotation revocation, counter backfill, audit retention, real-device matrix, external audit.
