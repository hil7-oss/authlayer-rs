-- Invalidate pre-hardening recovery codes. They have no expiry and use the old
-- global HMAC format, so they must not remain usable after upgrade.
UPDATE recovery_codes
SET expires_at = '1970-01-01T00:00:00Z'
WHERE expires_at IS NULL;

-- Sessions created before passkey binding cannot be safely cascaded from a
-- passkey revocation. Force re-login for all of them.
UPDATE sessions
SET revoked_at = '1970-01-01T00:00:00Z'
WHERE passkey_id IS NULL;

-- Credential counter used for clone/regression policy.
ALTER TABLE passkeys ADD COLUMN counter INTEGER NOT NULL DEFAULT 0;

-- DB-backed admin sessions so logout can revoke server-side.
CREATE TABLE IF NOT EXISTS admin_sessions (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_expiry
    ON admin_sessions(expires_at, revoked_at);
