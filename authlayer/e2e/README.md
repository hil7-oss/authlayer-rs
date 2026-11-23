# AuthLayer browser E2E (real Chrome + virtual passkeys)

This harness drives the compiled AuthLayer server in real Chrome and uses the
Chrome DevTools Protocol (CDP) **virtual WebAuthn authenticator**. It covers the
whole bootstrap flow without a hardware key or a real mailbox:

1. Email form -> unique test email.
2. Read the one-time code from `/api/dev/outbox` (page context).
3. Verify the code -> create a passkey with the virtual authenticator.
4. Capture the one-time recovery codes -> dashboard.
5. Log out -> submit the same email -> passkey sign-in -> dashboard.
6. Assert the session cookie is `HttpOnly`, `SameSite=Strict`, `Path=/`, and note
   that `Secure` is `false` only because local development uses plain HTTP.
7. Add a second passkey through the **visible** `#stepup-status` step-up panel
   ("Confirm with your passkey"), then revoke it through the UI.
8. Log out and sign in again for a fresh session, then "Sign out everywhere"
   through the visible step-up panel; assert the UI returns to signed out and
   the session cookie is cleared.
9. Assert there are no uncaught page errors or unexpected console errors.

The harness also logs the HttpOnly `al_ceremony` WebAuthn challenge cookie at
each ceremony (and its absence once cleared). Those diagnostics are
non-failing; any flag problem is reported as a warning.

The script prints `PASS` / `FAIL` / `SKIP` for every step and exits non-zero on
any non-optional failure.

## Prerequisites

- Node.js 20+ (Node 24 is used here).
- Google Chrome installed. The default path is:

  ```text
  C:\Program Files\Google\Chrome\Application\chrome.exe
  ```

  Override it with `E2E_CHROME_PATH` if Chrome lives elsewhere.
- A compiled server binary at `authlayer/target/debug/authlayer.exe` (or set
  `E2E_BINARY`).
- Network access for the first `npm install` (only `playwright-core`, no
  browser download).

## Install

From `authlayer/e2e`:

```powershell
npm install
```

If PowerShell blocks `npm.ps1` with an execution-policy error, use `npm.cmd`:

```powershell
& 'C:\Program Files\nodejs\npm.cmd' install
```

## Run: spawn a disposable server (recommended)

`E2E_START_SERVER=1` starts the binary with a temporary SQLite database,
waits up to 20 seconds for `/healthz`, and removes the database, server child,
and Chrome when the run ends.

PowerShell:

```powershell
$env:E2E_START_SERVER='1'
npm test
```

bash:

```bash
E2E_START_SERVER=1 npm test
```

The spawned server uses:

```text
APP_URL=http://localhost:8080
RP_ID=localhost
BIND_ADDR=127.0.0.1:8080
DATABASE_URL=sqlite://e2e-<pid>.db?mode=rwc
DEV_MODE=true
EMAIL_PROVIDER=outbox
OTP_SECRET=<random 64 hex characters>
COOKIE_SECURE=false
```

`OTP_SECRET` is generated fresh for every run and is never written to the
repository. The temporary DB and logs are git-ignored.

## Run: use an already-running server

Start the server yourself with `DEV_MODE=true`, `EMAIL_PROVIDER=outbox`,
`RP_ID=localhost`, and `APP_URL=http://localhost:8080`. Then:

```powershell
$env:E2E_START_SERVER='0'
npm test
```

The harness checks `/healthz` before launching Chrome. It does not build or
modify the Rust server.

## Environment variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `E2E_BASE_URL` | `http://localhost:8080` | Bare origin of the server. Must match `RP_ID` (or be a subdomain of it) and use HTTPS unless loopback. |
| `E2E_START_SERVER` | `0` | `1` spawns `E2E_BINARY` and manages its lifetime. |
| `E2E_BINARY` | `../target/debug/authlayer.exe` | Server binary when spawning. Relative paths resolve from the current directory. |
| `E2E_HEADLESS` | `1` | `0` (or `false`) launches visible Chrome. |
| `E2E_HEADED_FALLBACK` | `1` | If headless Chrome/WebAuthn setup fails, retry with `headless: false` and print a warning. Set to `0` to fail instead. |
| `E2E_CHROME_PATH` | `C:\Program Files\Google\Chrome\Application\chrome.exe` | Chrome executable. |
| `E2E_RP_ID` | `localhost` | WebAuthn RP ID. Must be a suffix of the host in `E2E_BASE_URL`. |
| `E2E_COOKIE_NAME` | `al_session` | Session cookie name to assert. |
| `E2E_ADMIN_TOKEN` | unset | Optional; passed as `ADMIN_TOKEN` when spawning. Must be 32+ chars if set. |
| `E2E_KEEP_ARTIFACTS` | `0` | `1` keeps `.e2e-server-<pid>.log`; the temp DB is still deleted. |

The test email is always unique and disposable, in the form
`e2e-<timestamp>-<random>@example.test`. No secrets or real addresses are
committed.

## Headless behavior

The default is `headless: true` using the installed Chrome. The CDP
virtual-authenticator flow works in Chrome's new headless mode. If a particular
Chrome build rejects WebAuthn setup in headless mode, the harness automatically
prints a warning and retries with `headless: false` (unless
`E2E_HEADED_FALLBACK=0`). In CI without a display, prefer a current Chrome and
run headless; a headed fallback needs a desktop session.

Manual headed run:

```powershell
$env:E2E_HEADLESS='0'
npm test
```

## What the passkey simulation does

For each virtual authenticator the harness sends:

```json
{
  "options": {
    "protocol": "ctap2",
    "ctap2Version": "ctap2_1",
    "transport": "internal",
    "hasResidentKey": true,
    "hasUserVerification": true,
    "isUserVerified": true,
    "automaticPresenceSimulation": true
  }
}
```

to `WebAuthn.addVirtualAuthenticator` after enabling the `WebAuthn` CDP domain.
A second authenticator (`transport: "usb"`) is added only after step-up finishes,
immediately before the passkey creation prompt is released.

## Visible step-up flow

The harness drives step-up entirely through the UI:

- Sensitive requests (add/revoke passkey, sign out everywhere) return HTTP 403
  `stepup_required`; the UI must show `#stepup-status` with the text
  "Confirm with your passkey".
- Session cookies are asserted as `HttpOnly` and `SameSite=Strict`. The
  `al_ceremony` challenge cookie uses the same flags; the harness logs its
  presence at registration/login/step-up and its clearing after completion.
- Before clicking the action, the harness installs page-level gates around
  `navigator.credentials.get()` and `navigator.credentials.create()`. When the UI
  reaches WebAuthn, the call is held at the gate so the visible panel can be
  asserted reliably even with an instant virtual authenticator.
- The harness asserts the panel is visible, checks its text, verifies that the UI
  actually called `navigator.credentials.get()`, then releases the gate.
- For add-passkey, a second virtual authenticator is added after step-up and
  before releasing the creation gate, so the creation prompt succeeds.
- After success the panel must be hidden and the passkey count must increase.
- "Sign out everywhere" is tested from a fresh passkey-login session (step-up
  cache cleared), confirms the dialog, exercises the panel, and asserts the UI
  returns to signed out with no session cookie.
- If the "Sign out everywhere" button is missing, that step is reported as
  `SKIP` with the missing-UI reason. If step-up is genuinely not required, the
  direct action path is accepted; if the step-up API ran but the panel was never
  observed, the run fails.
- Chrome logs the intentional 403 step-up probe as a console error. The harness
  tolerates only those 403s that match a known step-up-protected endpoint and a
  recorded 403 response; other console and page errors still fail the run.

## Known limitations

- A CDP virtual authenticator is not a hardware key. It does not exercise
  platform UI, biometrics, Bluetooth, NFC, or hardware attestation.
- The account and recovery codes live in a throwaway SQLite database when
  `E2E_START_SERVER=1`; nothing is persisted between runs.
- Email is read from the dev outbox. Real SMTP delivery, deliverability, and
  template rendering are not covered.
- Passkey add/revoke and "Sign out everywhere" depend on step-up. The harness
  proves the visible panel path; if the UI/API diverge, those steps fail or skip
  with a clear reason rather than silently passing.
- Add-passkey is marked optional in the harness so backend churn does not hide
  the mandatory registration/login/logout results. It currently passes.
- The harness asserts session/ceremony cookie flags from `context.cookies()`; it
  does not inspect raw `Set-Cookie` headers beyond what Chrome exposes.
- `Secure` is expected to be `false` over local HTTP. Run against an HTTPS
  origin to validate `Secure=true`.
- UI selectors use stable labels/ARIA names and a few `data`-free CSS classes
  (`.codes-grid`, `.dash-email`, `.stat`, panel `aria-labelledby`). If static
  UI markup is refactored, update `passkey.mjs` with it.
- No build is performed. Rebuild the Rust binary separately before running the
  harness.

## Troubleshooting

- **No healthy server**: start AuthLayer, or set `E2E_START_SERVER=1`.
- **`spawn ... ENOENT`**: set `E2E_BINARY` to the built `authlayer.exe`.
- **Chrome not found**: install Chrome or set `E2E_CHROME_PATH`.
- **Passkey registration fails with `SecurityError`**: `E2E_BASE_URL` host and
  `E2E_RP_ID` do not match (`localhost` by default), or the origin is not a
  secure context.
- **Optional add/revoke SKIP**: check the printed reason and the server log path
  shown on failure. A missing "Add another passkey" or "Sign out everywhere"
  button also produces a SKIP.
- **Runtime files**: `e2e-<pid>.db*` and `.e2e-server-<pid>.log` are ignored by
  Git and removed at the end of a successful run.
