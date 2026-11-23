use std::{str::FromStr, time::Duration};

use anyhow::Context;
use chrono::{Duration as ChronoDuration, Utc};
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use uuid::Uuid;

use crate::config::Config;

pub async fn init(config: &Config) -> anyhow::Result<SqlitePool> {
    let redacted_db_url = config.redacted_db_url();
    let options = SqliteConnectOptions::from_str(&config.db_url)
        .with_context(|| format!("invalid database URL {redacted_db_url}"))?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_secs(5));

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .with_context(|| format!("failed to connect to {redacted_db_url}"))?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("failed to run database migrations")?;

    Ok(pool)
}

pub fn now() -> String {
    Utc::now().to_rfc3339()
}

pub async fn cleanup_outbox(pool: &SqlitePool) -> anyhow::Result<u64> {
    let cutoff = (Utc::now() - ChronoDuration::days(1)).to_rfc3339();
    let result = sqlx::query("DELETE FROM outbox WHERE created_at < ?")
        .bind(cutoff)
        .execute(pool)
        .await
        .context("failed to clean up the outbox")?;
    Ok(result.rows_affected())
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CleanupCounts {
    pub otp: u64,
    pub sessions: u64,
    pub recovery: u64,
    pub admin_sessions: u64,
}

impl CleanupCounts {
    pub fn total(self) -> u64 {
        self.otp + self.sessions + self.recovery + self.admin_sessions
    }
}

pub async fn cleanup_expired_rows(pool: &SqlitePool) -> anyhow::Result<CleanupCounts> {
    let now = Utc::now().to_rfc3339();
    let otp = sqlx::query("DELETE FROM otp_codes WHERE expires_at <= ?")
        .bind(&now)
        .execute(pool)
        .await
        .context("failed to clean up expired OTP rows")?
        .rows_affected();
    let sessions = sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
        .bind(&now)
        .execute(pool)
        .await
        .context("failed to clean up expired session rows")?
        .rows_affected();
    let recovery =
        sqlx::query("DELETE FROM recovery_codes WHERE expires_at IS NULL OR expires_at <= ?")
            .bind(&now)
            .execute(pool)
            .await
            .context("failed to clean up expired recovery rows")?
            .rows_affected();
    let admin_sessions =
        sqlx::query("DELETE FROM admin_sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL")
            .bind(&now)
            .execute(pool)
            .await
            .context("failed to clean up expired admin sessions")?
            .rows_affected();
    Ok(CleanupCounts {
        otp,
        sessions,
        recovery,
        admin_sessions,
    })
}

pub async fn audit(
    pool: &SqlitePool,
    user_id: Option<Uuid>,
    event: &str,
    ip: Option<&str>,
    user_agent: Option<&str>,
    metadata: serde_json::Value,
) {
    if let Err(error) = sqlx::query(
        "INSERT INTO audit_events (user_id, event, ip, user_agent, metadata, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id.map(|v| v.to_string()))
    .bind(event)
    .bind(ip)
    .bind(user_agent)
    .bind(metadata.to_string())
    .bind(now())
    .execute(pool)
    .await
    {
        tracing::error!(event = event, error = %error, "failed to write audit event");
    }
}
