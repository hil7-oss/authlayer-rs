# Security policy

AuthLayer is a passwordless authentication server. Security reports are taken seriously.

## Status

- v0.1 is an early implementation, not yet independently audited.
- An internal security review is in `authlayer/SECURITY_REVIEW.md`; a second focused review is in progress.
- Do not expose a v0.1 instance to the public internet until the remaining P0 items in `PROJECT_STATE.md` are closed.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability.

Use a private channel:

- GitHub Security Advisories for the repository, once published; or
- the maintainer contact listed in the repository profile.

Include:

- affected version/commit;
- deployment model (Docker, systemd, reverse proxy);
- reproduction steps or a proof of concept;
- impact and any known mitigations;
- whether you want public credit.

Do not include real user data, live OTPs, session cookies, recovery codes, SMTP passwords, or admin tokens.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | security fixes, best effort |
| < 0.1 | not supported |

## Scope

In scope:

- authentication/session/recovery logic;
- WebAuthn ceremony handling;
- admin authentication;
- OTP/email delivery;
- SQLite schema/migrations;
- Docker/Caddy/systemd configuration;
- frontend handling of credentials.

Out of scope for v0.1:

- compromised user devices/authenticators;
- compromised host/root;
- SMTP provider deliverability and DKIM/SPF/DMARC;
- third-party dependencies without a practical AuthLayer mitigation;
- social engineering.

## Disclosure

We aim to acknowledge reports within 72 hours and provide a remediation plan within 7 days. Timelines depend on severity and maintainer availability. Please give us a reasonable window before public disclosure.
