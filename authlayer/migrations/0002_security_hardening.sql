ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until TEXT;

ALTER TABLE sessions ADD COLUMN passkey_id TEXT;
ALTER TABLE sessions ADD COLUMN stepup_at TEXT;

ALTER TABLE recovery_codes ADD COLUMN expires_at TEXT;

CREATE INDEX IF NOT EXISTS idx_sessions_passkey
    ON sessions(user_id, passkey_id, revoked_at);

CREATE INDEX IF NOT EXISTS idx_recovery_user_expiry
    ON recovery_codes(user_id, used_at, expires_at);

CREATE INDEX IF NOT EXISTS idx_outbox_created
    ON outbox(created_at);
