# Changelog

## 0.1.0 — 2026-11-23

First conditional, self-hosted AuthLayer release.

### Added

- Rust/Axum passwordless authentication server with SQLite.
- Email OTP bootstrap (6 digits, HMAC context binding, TTL, atomic attempts).
- WebAuthn/passkey registration, login, and add-passkey.
- Server-side sessions: 7-day absolute, 24-hour idle, `__Host-` cookie, `SameSite=Strict`, revoke one/all.
- Step-up WebAuthn confirmation for sensitive actions (5-minute window).
- Recovery codes with expiry, atomic use, old-credential revocation, and email notification.
- DB-backed admin sessions with `/admin/login`, `/admin/logout`, rate limiting, and audit.
- SMTP delivery via `lettre`; dev outbox for local testing.
- Trusted-proxy client IP handling, Origin enforcement, ceremony-cookie binding.
- Frontend: email code, passkeys, recovery, dashboard, sessions/passkeys, sign-out-everywhere.
- Dockerfile, Docker Compose + Caddy, systemd unit, `.env.example`.
- Smoke tests, browser E2E with Chrome virtual authenticator, CI workflow.

### Security

- Three internal security reviews; see `authlayer/SECURITY_REVIEW_ROUND3.md`.
- Fresh single-instance deployment behind Caddy is a **conditional go** with strict configuration.
- Not approved for unrestricted public signup, untested upgrades, real-money/high-value accounts, or use without an external audit.

### Known limitations

- External SMTP provider delivery not tested (local Mailpit path passes).
- Real-device passkey matrix not tested (virtual authenticator only).
- No independent external audit.
- No DPoP/DBSC/mTLS device binding yet.
- No CAPTCHA/global abuse budget for open signup.
- Recovery has no delay/second-channel step-up.
- Existing passkeys on upgrade get counter 0 until backfilled/re-registered.
- Rotating `ADMIN_TOKEN` does not revoke existing admin sessions.
