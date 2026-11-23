use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use hmac::{Hmac, Mac};
use rand::{Rng, RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqliteConnection, SqlitePool};
use uuid::Uuid;

use crate::{
    config::{Config, EmailProvider},
    db,
    email::EmailSender,
    error::{AppError, AppResult},
};

const MAX_OTP_ATTEMPTS: i64 = 5;

pub fn normalize_email(email: &str) -> AppResult<String> {
    let email = email.trim().to_lowercase();
    if email.len() < 3
        || email.len() > 254
        || email.chars().any(|c| c.is_whitespace())
        || !email.contains('@')
    {
        return Err(AppError::BadRequest("invalid_email".to_string()));
    }
    let (local, domain) = email.split_once('@').expect("checked contains @");
    if local.is_empty()
        || domain.is_empty()
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains('@')
    {
        return Err(AppError::BadRequest("invalid_email".to_string()));
    }
    Ok(email)
}

pub fn hmac_hex(secret: &[u8], data: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn generate_code() -> String {
    let upper = Rng::gen_range(&mut rand::thread_rng(), 0..1_000_000);
    format!("{upper:06}")
}

pub fn normalize_recovery_code(code: &str) -> String {
    code.chars()
        .filter(|c| *c != '-' && !c.is_whitespace())
        .flat_map(|c| c.to_uppercase())
        .collect()
}

pub fn generate_recovery_code() -> String {
    let mut bytes = [0u8; 9];
    OsRng.fill_bytes(&mut bytes);
    let encoded = URL_SAFE_NO_PAD.encode(bytes);
    format!("{}-{}-{}", &encoded[0..4], &encoded[4..8], &encoded[8..12])
}

fn otp_hash(
    secret: &[u8],
    user_id: Uuid,
    purpose: &str,
    otp_id: &str,
    expires_at: &str,
    code: &str,
) -> String {
    let data = format!(
        "otp:v1:{user_id}:{purpose}:{otp_id}:{expires_at}:{}",
        code.trim()
    );
    hmac_hex(secret, data.as_bytes())
}

fn recovery_hash(
    secret: &[u8],
    user_id: Uuid,
    code_id: &str,
    expires_at: &str,
    code: &str,
) -> String {
    let data = format!(
        "recovery:v1:{user_id}:{code_id}:{expires_at}:{}",
        normalize_recovery_code(code)
    );
    hmac_hex(secret, data.as_bytes())
}

// Recovery codes created before expiry support are invalidated by migration
// 0003 and are not accepted. All valid codes use the context-bound v1 hash.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub async fn find_user_by_email(pool: &SqlitePool, email: &str) -> AppResult<Option<Uuid>> {
    let row = sqlx::query("SELECT id FROM users WHERE email = ?")
        .bind(email)
        .fetch_optional(pool)
        .await?;
    row.map(|r| {
        let id: String = r.get("id");
        Uuid::parse_str(&id).map_err(|e| AppError::Internal(e.to_string()))
    })
    .transpose()
}

pub async fn is_active_user(pool: &SqlitePool, user_id: Uuid) -> AppResult<bool> {
    let row = sqlx::query("SELECT status FROM users WHERE id = ?")
        .bind(user_id.to_string())
        .fetch_optional(pool)
        .await?;
    Ok(row
        .map(|row| row.get::<String, _>("status") == "active")
        .unwrap_or(false))
}

pub async fn ensure_user(pool: &SqlitePool, email: &str) -> AppResult<(Uuid, bool)> {
    if let Some(id) = find_user_by_email(pool, email).await? {
        return Ok((id, false));
    }

    let id = Uuid::new_v4();
    let result = sqlx::query(
        "INSERT INTO users (id, email, status, created_at) VALUES (?, ?, 'active', ?)
         ON CONFLICT(email) DO NOTHING",
    )
    .bind(id.to_string())
    .bind(email)
    .bind(db::now())
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        let existing = find_user_by_email(pool, email).await?.ok_or_else(|| {
            AppError::Internal("user insert conflicted but user was not found".to_string())
        })?;
        return Ok((existing, false));
    }

    Ok((id, true))
}

// Advisory only. Failed-attempt counts are retained for alerts/forensics, but
// they never block authentication. CAPTCHA/edge rate limits are the next step
// for public signup; per-OTP attempt limits and per-email/IP rate limits remain
// the actual controls.
pub async fn record_auth_failure(pool: &SqlitePool, user_id: Uuid) -> AppResult<()> {
    let result = sqlx::query("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?")
        .bind(user_id.to_string())
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Ok(());
    }
    let failed_attempts: Option<i64> =
        sqlx::query_scalar("SELECT failed_attempts FROM users WHERE id = ?")
            .bind(user_id.to_string())
            .fetch_optional(pool)
            .await?;
    if let Some(count) = failed_attempts
        && count > 0
        && count % 10 == 0
    {
        tracing::warn!(
            failed_attempts = count,
            "repeated authentication failures; consider CAPTCHA or edge rate limiting"
        );
    }
    Ok(())
}

pub async fn reset_auth_failures(pool: &SqlitePool, user_id: Uuid) -> AppResult<()> {
    sqlx::query("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?")
        .bind(user_id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn create_otp(
    pool: &SqlitePool,
    email_sender: &EmailSender,
    config: &Config,
    user_id: Uuid,
    email: &str,
    purpose: &str,
) -> AppResult<()> {
    let code = generate_code();
    let otp_id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let expires_at = (now + ChronoDuration::minutes(config.otp_ttl_minutes)).to_rfc3339();
    let hash = otp_hash(
        &config.otp_secret,
        user_id,
        purpose,
        &otp_id,
        &expires_at,
        &code,
    );
    let subject = "Your AuthLayer sign-in code";
    let delivery_body = format!(
        "Your one-time code is: {code}\n\nIt expires in {} minutes.",
        config.otp_ttl_minutes
    );
    let stored_body = if config.dev_mode && config.email_provider == EmailProvider::Outbox {
        delivery_body.clone()
    } else {
        "One-time code generated and sent by email.".to_string()
    };

    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO otp_codes (id, user_id, purpose, code_hash, attempts, created_at, expires_at)
         VALUES (?, ?, ?, ?, 0, ?, ?)",
    )
    .bind(&otp_id)
    .bind(user_id.to_string())
    .bind(purpose)
    .bind(hash)
    .bind(now.to_rfc3339())
    .bind(&expires_at)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO outbox (id, to_email, subject, body, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(email)
    .bind(subject)
    .bind(&stored_body)
    .bind(now.to_rfc3339())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    if let Err(error) = email_sender.send(email, subject, &delivery_body).await {
        tracing::error!(
            provider = email_sender.provider_name(),
            error = %error,
            "OTP email delivery failed"
        );
        return Err(AppError::Internal("email_delivery_failed".to_string()));
    }

    Ok(())
}

pub async fn verify_otp(
    pool: &SqlitePool,
    user_id: Uuid,
    purpose: &str,
    code: &str,
    secret: &[u8],
) -> AppResult<()> {
    let row = sqlx::query(
        "SELECT id, code_hash, expires_at, used_at
         FROM otp_codes
         WHERE user_id = ? AND purpose = ?
         ORDER BY created_at DESC, rowid DESC
         LIMIT 1",
    )
    .bind(user_id.to_string())
    .bind(purpose)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::BadRequest("code_not_found".to_string()))?;

    let id: String = row.get("id");
    let code_hash: String = row.get("code_hash");
    let expires_at: String = row.get("expires_at");
    let used_at: Option<String> = row.get("used_at");

    if used_at.is_some() {
        return Err(AppError::BadRequest("code_already_used".to_string()));
    }
    let expires = DateTime::parse_from_rfc3339(&expires_at)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .with_timezone(&Utc);
    if Utc::now() > expires {
        return Err(AppError::BadRequest("code_expired".to_string()));
    }

    let reserved = sqlx::query(
        "UPDATE otp_codes SET attempts = attempts + 1
         WHERE id = ? AND used_at IS NULL AND attempts < ?",
    )
    .bind(&id)
    .bind(MAX_OTP_ATTEMPTS)
    .execute(pool)
    .await?;
    if reserved.rows_affected() == 0 {
        let used: Option<String> = sqlx::query("SELECT used_at FROM otp_codes WHERE id = ?")
            .bind(&id)
            .fetch_one(pool)
            .await?
            .get("used_at");
        if used.is_some() {
            return Err(AppError::BadRequest("code_already_used".to_string()));
        }
        return Err(AppError::BadRequest("too_many_attempts".to_string()));
    }

    let expected = otp_hash(secret, user_id, purpose, &id, &expires_at, code);
    if !constant_time_eq(expected.as_bytes(), code_hash.as_bytes()) {
        record_auth_failure(pool, user_id).await?;
        return Err(AppError::BadRequest("invalid_code".to_string()));
    }

    let result = sqlx::query("UPDATE otp_codes SET used_at = ? WHERE id = ? AND used_at IS NULL")
        .bind(db::now())
        .bind(&id)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::BadRequest("code_already_used".to_string()));
    }

    reset_auth_failures(pool, user_id).await?;
    Ok(())
}

pub async fn create_session(
    pool: &SqlitePool,
    config: &Config,
    user_id: Uuid,
    passkey_id: Option<&str>,
    ip: Option<&str>,
    user_agent: Option<&str>,
) -> AppResult<String> {
    let mut conn = pool.acquire().await?;
    create_session_in(&mut conn, config, user_id, passkey_id, ip, user_agent).await
}

pub async fn create_session_in(
    conn: &mut SqliteConnection,
    config: &Config,
    user_id: Uuid,
    passkey_id: Option<&str>,
    ip: Option<&str>,
    user_agent: Option<&str>,
) -> AppResult<String> {
    let token = generate_token();
    let token_hash = hash_token(&token);
    let now = Utc::now();
    let expires = now + ChronoDuration::days(config.session_ttl_days);

    sqlx::query(
        "INSERT INTO sessions
         (id, user_id, token_hash, created_at, last_seen_at, expires_at, ip, user_agent, passkey_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(user_id.to_string())
    .bind(token_hash)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .bind(expires.to_rfc3339())
    .bind(ip)
    .bind(user_agent)
    .bind(passkey_id)
    .execute(&mut *conn)
    .await?;

    Ok(token)
}

#[derive(Debug, Clone)]
pub struct SessionUser {
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub email: String,
    pub expires_at: String,
    pub passkey_id: Option<String>,
    pub stepup_at: Option<DateTime<Utc>>,
}

pub async fn session_from_token(
    pool: &SqlitePool,
    config: &Config,
    token: &str,
) -> AppResult<Option<SessionUser>> {
    let token_hash = hash_token(token);
    let row = sqlx::query(
        "SELECT s.id, s.user_id, s.expires_at, s.revoked_at, s.last_seen_at,
                s.passkey_id, s.stepup_at, u.email, u.status
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ?",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    let revoked_at: Option<String> = row.get("revoked_at");
    let status: String = row.get("status");
    let expires_at: String = row.get("expires_at");
    let last_seen_at: String = row.get("last_seen_at");
    if revoked_at.is_some() || status != "active" {
        return Ok(None);
    }
    let expires = DateTime::parse_from_rfc3339(&expires_at)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .with_timezone(&Utc);
    if Utc::now() > expires {
        return Ok(None);
    }
    let last_seen = DateTime::parse_from_rfc3339(&last_seen_at)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .with_timezone(&Utc);
    if Utc::now().signed_duration_since(last_seen)
        > ChronoDuration::hours(config.session_idle_hours)
    {
        return Ok(None);
    }

    let session_id: String = row.get("id");
    let user_id: String = row.get("user_id");
    let session_id = Uuid::parse_str(&session_id).map_err(|e| AppError::Internal(e.to_string()))?;
    let user_id = Uuid::parse_str(&user_id).map_err(|e| AppError::Internal(e.to_string()))?;
    let passkey_id: Option<String> = row.get("passkey_id");
    let stepup_at = row
        .get::<Option<String>, _>("stepup_at")
        .map(|value| {
            DateTime::parse_from_rfc3339(&value)
                .map(|date| date.with_timezone(&Utc))
                .map_err(|e| AppError::Internal(e.to_string()))
        })
        .transpose()?;

    sqlx::query("UPDATE sessions SET last_seen_at = ? WHERE id = ?")
        .bind(db::now())
        .bind(session_id.to_string())
        .execute(pool)
        .await?;

    Ok(Some(SessionUser {
        session_id,
        user_id,
        email: row.get("email"),
        expires_at,
        passkey_id,
        stepup_at,
    }))
}

pub async fn revoke_session(pool: &SqlitePool, session_id: Uuid, user_id: Uuid) -> AppResult<bool> {
    let result = sqlx::query("UPDATE sessions SET revoked_at = ? WHERE id = ? AND user_id = ?")
        .bind(db::now())
        .bind(session_id.to_string())
        .bind(user_id.to_string())
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn revoke_all_sessions(pool: &SqlitePool, user_id: Uuid) -> AppResult<u64> {
    let result =
        sqlx::query("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL")
            .bind(db::now())
            .bind(user_id.to_string())
            .execute(pool)
            .await?;
    Ok(result.rows_affected())
}

pub async fn revoke_all_credentials(pool: &SqlitePool, user_id: Uuid) -> AppResult<(u64, u64)> {
    let mut tx = pool.begin().await?;
    let sessions_revoked =
        sqlx::query("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL")
            .bind(db::now())
            .bind(user_id.to_string())
            .execute(&mut *tx)
            .await?
            .rows_affected();
    let passkeys_removed = sqlx::query("DELETE FROM passkeys WHERE user_id = ?")
        .bind(user_id.to_string())
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok((sessions_revoked, passkeys_removed))
}

pub async fn count_passkeys(pool: &SqlitePool, user_id: Uuid) -> AppResult<i64> {
    let mut conn = pool.acquire().await?;
    count_passkeys_in(&mut conn, user_id).await
}

pub async fn count_passkeys_in(conn: &mut SqliteConnection, user_id: Uuid) -> AppResult<i64> {
    let row = sqlx::query("SELECT COUNT(*) AS n FROM passkeys WHERE user_id = ?")
        .bind(user_id.to_string())
        .fetch_one(&mut *conn)
        .await?;
    Ok(row.get("n"))
}

pub async fn create_recovery_codes(
    pool: &SqlitePool,
    user_id: Uuid,
    secret: &[u8],
    ttl_days: i64,
) -> AppResult<Vec<String>> {
    let mut tx = pool.begin().await?;
    let codes = create_recovery_codes_in(&mut tx, user_id, secret, ttl_days).await?;
    tx.commit().await?;
    Ok(codes)
}

pub async fn create_recovery_codes_in(
    conn: &mut SqliteConnection,
    user_id: Uuid,
    secret: &[u8],
    ttl_days: i64,
) -> AppResult<Vec<String>> {
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = ? AND used_at IS NULL")
        .bind(user_id.to_string())
        .execute(&mut *conn)
        .await?;

    let now = Utc::now();
    let created_at = now.to_rfc3339();
    let expires_at = (now + ChronoDuration::days(ttl_days)).to_rfc3339();
    let mut codes = Vec::with_capacity(8);
    for _ in 0..8 {
        let code = generate_recovery_code();
        let code_id = Uuid::new_v4().to_string();
        let hash = recovery_hash(secret, user_id, &code_id, &expires_at, &code);
        sqlx::query(
            "INSERT INTO recovery_codes (id, user_id, code_hash, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&code_id)
        .bind(user_id.to_string())
        .bind(hash)
        .bind(&created_at)
        .bind(&expires_at)
        .execute(&mut *conn)
        .await?;
        codes.push(code);
    }
    Ok(codes)
}

pub async fn verify_recovery_code(
    pool: &SqlitePool,
    user_id: Uuid,
    code: &str,
    secret: &[u8],
) -> AppResult<bool> {
    let rows = sqlx::query(
        "SELECT id, code_hash, expires_at
         FROM recovery_codes
         WHERE user_id = ? AND used_at IS NULL
           AND expires_at IS NOT NULL AND expires_at > ?",
    )
    .bind(user_id.to_string())
    .bind(db::now())
    .fetch_all(pool)
    .await?;

    let mut matched_id = None;
    for row in rows {
        let id: String = row.get("id");
        let hash: String = row.get("code_hash");
        let expires_at: String = row.get("expires_at");
        let expected = recovery_hash(secret, user_id, &id, &expires_at, code);
        if constant_time_eq(expected.as_bytes(), hash.as_bytes()) {
            matched_id = Some(id);
            break;
        }
    }

    let Some(id) = matched_id else {
        record_auth_failure(pool, user_id).await?;
        return Ok(false);
    };

    let result = sqlx::query(
        "UPDATE recovery_codes SET used_at = ?
         WHERE id = ? AND used_at IS NULL
           AND expires_at IS NOT NULL AND expires_at > ?",
    )
    .bind(db::now())
    .bind(&id)
    .bind(db::now())
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        return Ok(false);
    }

    reset_auth_failures(pool, user_id).await?;
    Ok(true)
}

pub fn check_rate_limit(
    limiter: &crate::state::RateLimiter,
    key: &str,
    max: usize,
    window_secs: u64,
) -> AppResult<()> {
    if limiter.check(key, max, Duration::from_secs(window_secs)) {
        Ok(())
    } else {
        Err(AppError::TooManyRequests)
    }
}

pub fn client_ip(
    headers: &axum::http::HeaderMap,
    peer: SocketAddr,
    config: &Config,
) -> Option<String> {
    if !config.is_trusted_proxy(peer.ip()) {
        return Some(peer.ip().to_string());
    }

    if let Some(value) = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
    {
        let mut hops = Vec::new();
        let mut valid = true;
        for part in value.split(',') {
            match part.trim().parse::<IpAddr>() {
                Ok(address) => hops.push(address),
                Err(_) => {
                    valid = false;
                    break;
                }
            }
        }
        if valid && !hops.is_empty() {
            for address in hops.iter().rev() {
                if !config.is_trusted_proxy(*address) {
                    return Some(address.to_string());
                }
            }
            return Some(hops[0].to_string());
        }
    }

    if let Some(value) = headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        && let Ok(address) = value.trim().parse::<IpAddr>()
    {
        return Some(address.to_string());
    }

    Some(peer.ip().to_string())
}

pub fn client_ua(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
}
