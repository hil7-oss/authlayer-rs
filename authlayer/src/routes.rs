use std::net::SocketAddr;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration as ChronoDuration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, Passkey, PublicKeyCredential, RegisterPublicKeyCredential,
};

use crate::{
    auth, db,
    error::{AppError, AppResult},
    state::{AppState, AuthChallenge, RecoveryChallenge, RegChallenge},
};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/style.css", get(style_css))
        .route("/healthz", get(health))
        .route("/dev/outbox", get(dev_outbox))
        .route("/admin", get(admin))
        .route("/admin/login", get(admin_login_page).post(admin_login))
        .route("/admin/logout", post(admin_logout))
        .route("/api/auth/start", post(start))
        .route("/api/auth/verify-code", post(verify_code))
        .route("/api/auth/passkey/register", post(passkey_register))
        .route("/api/auth/passkey/login", post(passkey_login))
        .route("/api/auth/stepup/start", post(stepup_start))
        .route("/api/auth/stepup/finish", post(stepup_finish))
        .route("/api/auth/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/sessions", get(list_sessions))
        .route("/api/sessions/revoke-all", post(revoke_all_sessions))
        .route("/api/sessions/{id}/revoke", post(revoke_session))
        .route("/api/passkeys", get(list_passkeys))
        .route("/api/passkeys/add/start", post(passkey_add_start))
        .route("/api/passkeys/add/finish", post(passkey_add_finish))
        .route("/api/passkeys/{id}/revoke", post(revoke_passkey))
        .route("/api/recovery/regenerate", post(regenerate_recovery))
        .route("/api/auth/recover/start", post(recover_start))
        .route("/api/auth/recover/verify-email", post(recover_verify_email))
        .route("/api/auth/recover/verify-code", post(recover_verify_code))
        .route("/api/dev/outbox", get(api_dev_outbox))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct EmailReq {
    email: String,
}

#[derive(Debug, Deserialize)]
struct VerifyCodeReq {
    email: String,
    code: String,
}

#[derive(Debug, Deserialize)]
struct ChallengeReq {
    challenge_id: String,
    credential: Value,
}

#[derive(Debug, Deserialize)]
struct RecoveryVerifyEmailReq {
    email: String,
    code: String,
}

#[derive(Debug, Deserialize)]
struct RecoveryVerifyCodeReq {
    challenge_id: String,
    recovery_code: String,
}

#[derive(Debug, Deserialize)]
struct AdminLoginReq {
    token: String,
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn app_js() -> Response {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("../static/app.js"),
    )
        .into_response()
}

async fn style_css() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../static/style.css"),
    )
        .into_response()
}

async fn health(State(state): State<AppState>) -> Response {
    match sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&state.db)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "service": "authlayer",
                "version": env!("CARGO_PKG_VERSION"),
                "dev_mode": state.config.dev_mode,
            })),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(error = %error, "health check database probe failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "ok": false,
                    "service": "authlayer",
                    "version": env!("CARGO_PKG_VERSION"),
                    "dev_mode": state.config.dev_mode,
                    "error": "database_unavailable",
                })),
            )
                .into_response()
        }
    }
}

fn session_cookie(config: &crate::config::Config, token: &str) -> Cookie<'static> {
    Cookie::build((config.cookie_name.clone(), token.to_string()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(config.cookie_secure)
        .max_age(time::Duration::days(config.session_ttl_days))
        .build()
}

fn clear_cookie(config: &crate::config::Config) -> Cookie<'static> {
    Cookie::build((config.cookie_name.clone(), ""))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(config.cookie_secure)
        .max_age(time::Duration::ZERO)
        .build()
}

const CEREMONY_COOKIE_NAME: &str = "al_ceremony";
const CEREMONY_COOKIE_MINUTES: i64 = 10;

fn ceremony_cookie(config: &crate::config::Config, challenge_id: &str) -> Cookie<'static> {
    Cookie::build((CEREMONY_COOKIE_NAME, challenge_id.to_string()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(config.cookie_secure)
        .max_age(time::Duration::minutes(CEREMONY_COOKIE_MINUTES))
        .build()
}

fn clear_ceremony_cookie(config: &crate::config::Config) -> Cookie<'static> {
    Cookie::build((CEREMONY_COOKIE_NAME, ""))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(config.cookie_secure)
        .max_age(time::Duration::ZERO)
        .build()
}

fn ceremony_matches(jar: &CookieJar, challenge_id: &str) -> bool {
    jar.get(CEREMONY_COOKIE_NAME)
        .map(|cookie| auth::constant_time_eq(cookie.value().as_bytes(), challenge_id.as_bytes()))
        .unwrap_or(false)
}

fn require_ceremony(jar: &CookieJar, challenge_id: &str) -> AppResult<()> {
    if ceremony_matches(jar, challenge_id) {
        Ok(())
    } else {
        Err(AppError::BadRequest("challenge_not_found".to_string()))
    }
}

const ADMIN_COOKIE_NAME: &str = "al_admin";
const ADMIN_SESSION_SECONDS: i64 = 3600;
const STEPUP_MINUTES: i64 = 5;

fn admin_cookie(config: &crate::config::Config, value: String) -> Cookie<'static> {
    Cookie::build((ADMIN_COOKIE_NAME, value))
        .path("/admin")
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(config.cookie_secure)
        .max_age(time::Duration::hours(1))
        .build()
}

fn clear_admin_cookie(config: &crate::config::Config) -> Cookie<'static> {
    Cookie::build((ADMIN_COOKIE_NAME, ""))
        .path("/admin")
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(config.cookie_secure)
        .max_age(time::Duration::ZERO)
        .build()
}

fn admin_cookie_token(jar: &CookieJar) -> Option<&str> {
    jar.get(ADMIN_COOKIE_NAME).map(|cookie| cookie.value())
}

async fn admin_session_valid(state: &AppState, jar: &CookieJar) -> bool {
    let Some(token) = admin_cookie_token(jar) else {
        return false;
    };
    let token_hash = auth::hash_token(token);
    match sqlx::query(
        "SELECT 1 FROM admin_sessions
         WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?",
    )
    .bind(token_hash)
    .bind(db::now())
    .fetch_optional(&state.db)
    .await
    {
        Ok(row) => row.is_some(),
        Err(error) => {
            tracing::error!(error = %error, "failed to validate admin session");
            false
        }
    }
}

fn require_stepup(session: &auth::SessionUser) -> AppResult<()> {
    match session.stepup_at {
        Some(at) => {
            let elapsed = Utc::now().signed_duration_since(at);
            if elapsed >= ChronoDuration::zero()
                && elapsed <= ChronoDuration::minutes(STEPUP_MINUTES)
            {
                Ok(())
            } else {
                Err(AppError::StepUpRequired)
            }
        }
        None => Err(AppError::StepUpRequired),
    }
}

fn queue_security_notification(state: &AppState, to: String, subject: &'static str, body: String) {
    if state.email.is_outbox() {
        let pool = state.db.clone();
        let subject = subject.to_string();
        tokio::spawn(async move {
            let _ = sqlx::query(
                "INSERT INTO outbox (id, to_email, subject, body, created_at)
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(&to)
            .bind(&subject)
            .bind(&body)
            .bind(db::now())
            .execute(&pool)
            .await;
        });
        return;
    }

    let sender = state.email.clone();
    tokio::spawn(async move {
        if let Err(error) = sender.send(&to, subject, &body).await {
            tracing::warn!(
                provider = sender.provider_name(),
                error = %error,
                "security notification email failed"
            );
        }
    });
}

async fn current_session(
    state: &AppState,
    jar: &CookieJar,
) -> AppResult<Option<auth::SessionUser>> {
    let Some(cookie) = jar.get(&state.config.cookie_name) else {
        return Ok(None);
    };
    auth::session_from_token(&state.db, &state.config, cookie.value()).await
}

async fn require_session(state: &AppState, jar: &CookieJar) -> AppResult<auth::SessionUser> {
    current_session(state, jar)
        .await?
        .ok_or(AppError::Unauthorized)
}

fn check_origin(state: &AppState, headers: &HeaderMap) -> AppResult<()> {
    match headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        Some(origin) => {
            let expected = state.config.app_url.origin().ascii_serialization();
            if origin != expected {
                return Err(AppError::Forbidden);
            }
            Ok(())
        }
        None if state.config.dev_mode => {
            // Local smoke/E2E tests and simple dev clients often omit Origin.
            // Production requires Origin to avoid fail-open CSRF checks.
            tracing::debug!("allowing state-changing request without Origin in DEV_MODE");
            Ok(())
        }
        None => Err(AppError::Forbidden),
    }
}

async fn load_passkeys(pool: &SqlitePool, user_id: Uuid) -> AppResult<Vec<Passkey>> {
    let rows = sqlx::query("SELECT data FROM passkeys WHERE user_id = ? ORDER BY created_at")
        .bind(user_id.to_string())
        .fetch_all(pool)
        .await?;

    rows.into_iter()
        .map(|row| {
            let data: String = row.get("data");
            serde_json::from_str::<Passkey>(&data)
                .map_err(|e| AppError::Internal(format!("invalid stored passkey: {e}")))
        })
        .collect()
}

async fn start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<EmailReq>,
) -> AppResult<(CookieJar, Json<Value>)> {
    check_origin(&state, &headers)?;
    let email = auth::normalize_email(&req.email)?;
    let ip = auth::client_ip(&headers, peer, &state.config);
    let ua = auth::client_ua(&headers);

    auth::check_rate_limit(&state.rate_limiter, &format!("start:email:{email}"), 5, 60)?;
    if let Some(ip) = &ip {
        auth::check_rate_limit(&state.rate_limiter, &format!("start:ip:{ip}"), 30, 60)?;
    }

    if let Some(user_id) = auth::find_user_by_email(&state.db, &email).await? {
        if !auth::is_active_user(&state.db, user_id).await? {
            db::audit(
                &state.db,
                Some(user_id),
                "auth_start_inactive",
                ip.as_deref(),
                ua.as_deref(),
                json!({}),
            )
            .await;
            return Ok((
                jar,
                Json(json!({
                    "flow": "code",
                    "email": email,
                    "dev_outbox": if state.config.dev_mode { Some("/dev/outbox") } else { None },
                })),
            ));
        }
        let passkeys = load_passkeys(&state.db, user_id).await?;
        if !passkeys.is_empty() {
            let (options, auth_state) = state.webauthn.start_passkey_authentication(&passkeys)?;
            let challenge_id = Uuid::new_v4().to_string();
            {
                let mut challenges = state
                    .auth_challenges
                    .lock()
                    .map_err(|_| AppError::Internal("challenge lock poisoned".into()))?;
                challenges.insert(
                    challenge_id.clone(),
                    AuthChallenge {
                        user_id,
                        state: auth_state,
                        expires_at: Utc::now() + ChronoDuration::minutes(2),
                    },
                );
            }
            db::audit(
                &state.db,
                Some(user_id),
                "auth_start_passkey",
                ip.as_deref(),
                ua.as_deref(),
                json!({}),
            )
            .await;
            return Ok((
                jar.add(ceremony_cookie(&state.config, &challenge_id)),
                Json(json!({
                    "flow": "passkey",
                    "challenge_id": challenge_id,
                    "options": serde_json::to_value(options).map_err(|e| AppError::Internal(e.to_string()))?,
                })),
            ));
        }
    }

    let (user_id, created) = auth::ensure_user(&state.db, &email).await?;
    auth::create_otp(
        &state.db,
        &state.email,
        &state.config,
        user_id,
        &email,
        "login",
    )
    .await?;

    db::audit(
        &state.db,
        Some(user_id),
        if created { "user_created" } else { "otp_sent" },
        ip.as_deref(),
        ua.as_deref(),
        json!({"email": email}),
    )
    .await;

    Ok((
        jar,
        Json(json!({
            "flow": "code",
            "email": email,
            "dev_outbox": if state.config.dev_mode { Some("/dev/outbox") } else { None },
        })),
    ))
}

async fn verify_code(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<VerifyCodeReq>,
) -> AppResult<(CookieJar, Json<Value>)> {
    check_origin(&state, &headers)?;
    let email = auth::normalize_email(&req.email)?;
    let ip = auth::client_ip(&headers, peer, &state.config);
    let ua = auth::client_ua(&headers);

    auth::check_rate_limit(
        &state.rate_limiter,
        &format!("verify-code:email:{email}"),
        10,
        60,
    )?;
    if let Some(ip) = &ip {
        auth::check_rate_limit(&state.rate_limiter, &format!("verify-code:ip:{ip}"), 20, 60)?;
    }

    let Some(user_id) = auth::find_user_by_email(&state.db, &email).await? else {
        db::audit(
            &state.db,
            None,
            "otp_verification_failed",
            ip.as_deref(),
            ua.as_deref(),
            json!({"reason": "user_not_found"}),
        )
        .await;
        return Err(AppError::BadRequest("invalid_code".to_string()));
    };
    if !auth::is_active_user(&state.db, user_id).await? {
        db::audit(
            &state.db,
            Some(user_id),
            "otp_verification_failed",
            ip.as_deref(),
            ua.as_deref(),
            json!({"reason": "inactive_user"}),
        )
        .await;
        return Err(AppError::BadRequest("invalid_code".to_string()));
    }

    if let Err(error) = auth::verify_otp(
        &state.db,
        user_id,
        "login",
        &req.code,
        &state.config.otp_secret,
    )
    .await
    {
        db::audit(
            &state.db,
            Some(user_id),
            "otp_verification_failed",
            ip.as_deref(),
            ua.as_deref(),
            json!({"reason": error.to_string()}),
        )
        .await;
        return Err(error);
    }

    let passkeys = load_passkeys(&state.db, user_id).await?;
    if !passkeys.is_empty() {
        return Err(AppError::BadRequest("use_passkey".to_string()));
    }

    let (options, reg_state) = state
        .webauthn
        .start_passkey_registration(user_id, &email, &email, None)?;

    let challenge_id = Uuid::new_v4().to_string();
    {
        let mut challenges = state
            .reg_challenges
            .lock()
            .map_err(|_| AppError::Internal("challenge lock poisoned".into()))?;
        challenges.insert(
            challenge_id.clone(),
            RegChallenge {
                user_id,
                state: reg_state,
                expires_at: Utc::now() + ChronoDuration::minutes(2),
            },
        );
    }

    db::audit(
        &state.db,
        Some(user_id),
        "otp_verified",
        ip.as_deref(),
        ua.as_deref(),
        json!({}),
    )
    .await;

    Ok((
        jar.add(ceremony_cookie(&state.config, &challenge_id)),
        Json(json!({
            "flow": "register_passkey",
            "challenge_id": challenge_id,
            "options": serde_json::to_value(options).map_err(|e| AppError::Internal(e.to_string()))?,
        })),
    ))
}

async fn passkey_register(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<ChallengeReq>,
) -> AppResult<(CookieJar, Json<Value>)> {
    check_origin(&state, &headers)?;
    let ip = auth::client_ip(&headers, peer, &state.config);
    let ua = auth::client_ua(&headers);
    if let Some(ip) = &ip {
        auth::check_rate_limit(
            &state.rate_limiter,
            &format!("passkey-register:ip:{ip}"),
            20,
            60,
        )?;
    }

    require_ceremony(&jar, &req.challenge_id)?;
    let challenge = state
        .reg_challenges
        .lock()
        .map_err(|_| AppError::Internal("challenge lock poisoned".into()))?
        .remove(&req.challenge_id)
        .ok_or_else(|| AppError::BadRequest("challenge_not_found".to_string()))?;

    if Utc::now() > challenge.expires_at {
        return Err(AppError::BadRequest("challenge_expired".to_string()));
    }
    if !auth::is_active_user(&state.db, challenge.user_id).await? {
        return Err(AppError::BadRequest("registration_failed".to_string()));
    }

    let credential: RegisterPublicKeyCredential =
        serde_json::from_value(req.credential).map_err(|e| AppError::BadRequest(e.to_string()))?;

    let passkey = state
        .webauthn
        .finish_passkey_registration(&credential, &challenge.state)?;

    let credential_id = URL_SAFE_NO_PAD.encode(passkey.cred_id());
    let existing = sqlx::query("SELECT 1 FROM passkeys WHERE credential_id = ?")
        .bind(&credential_id)
        .fetch_optional(&state.db)
        .await?;
    if existing.is_some() {
        return Err(AppError::BadRequest(
            "credential_already_registered".to_string(),
        ));
    }

    let data = serde_json::to_string(&passkey)
        .map_err(|e| AppError::Internal(format!("failed to serialize passkey: {e}")))?;

    let mut tx = state.db.begin().await?;
    let passkey_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO passkeys (id, user_id, credential_id, data, label, created_at, counter)
         VALUES (?, ?, ?, ?, ?, ?, 0)",
    )
    .bind(&passkey_id)
    .bind(challenge.user_id.to_string())
    .bind(credential_id)
    .bind(data)
    .bind(passkey_label(&ua))
    .bind(db::now())
    .execute(&mut *tx)
    .await?;

    let token = auth::create_session_in(
        &mut tx,
        &state.config,
        challenge.user_id,
        Some(&passkey_id),
        ip.as_deref(),
        ua.as_deref(),
    )
    .await?;

    let passkey_count = auth::count_passkeys_in(&mut tx, challenge.user_id).await?;
    let recovery_codes = if passkey_count == 1 {
        auth::create_recovery_codes_in(
            &mut tx,
            challenge.user_id,
            &state.config.otp_secret,
            state.config.recovery_code_ttl_days,
        )
        .await?
    } else {
        Vec::new()
    };
    tx.commit().await?;

    db::audit(
        &state.db,
        Some(challenge.user_id),
        "passkey_registered",
        ip.as_deref(),
        ua.as_deref(),
        json!({"first_passkey": passkey_count == 1}),
    )
    .await;

    let jar = jar
        .add(session_cookie(&state.config, &token))
        .add(clear_ceremony_cookie(&state.config));
    Ok((
        jar,
        Json(json!({
            "ok": true,
            "recovery_codes": recovery_codes,
        })),
    ))
}

fn passkey_label(user_agent: &Option<String>) -> String {
    let ua = user_agent.as_deref().unwrap_or_default().to_lowercase();
    if ua.contains("iphone") {
        "iPhone passkey".to_string()
    } else if ua.contains("ipad") {
        "iPad passkey".to_string()
    } else if ua.contains("android") {
        "Android passkey".to_string()
    } else if ua.contains("macintosh") {
        "Mac passkey".to_string()
    } else if ua.contains("windows") {
        "Windows passkey".to_string()
    } else if ua.contains("linux") {
        "Linux passkey".to_string()
    } else {
        "Passkey".to_string()
    }
}

async fn apply_passkey_assertion(
    state: &AppState,
    user_id: Uuid,
    result: &AuthenticationResult,
    ip: Option<&str>,
    ua: Option<&str>,
) -> AppResult<String> {
    let rows = sqlx::query(
        "SELECT id, data, counter FROM passkeys WHERE user_id = ? AND credential_id = ?",
    )
    .bind(user_id.to_string())
    .bind(URL_SAFE_NO_PAD.encode(result.cred_id()))
    .fetch_all(&state.db)
    .await?;
    let row = rows
        .into_iter()
        .next()
        .ok_or_else(|| AppError::BadRequest("passkey_not_found".to_string()))?;

    let passkey_id: String = row.get("id");
    let data: String = row.get("data");
    let stored_counter: i64 = row.get("counter");
    let asserted_counter = i64::from(result.counter());

    // Device-bound authenticators must advance the counter. Synced passkeys
    // commonly report 0/0, which is accepted and audited as an explicit policy.
    if stored_counter > 0 && asserted_counter <= stored_counter {
        db::audit(
            &state.db,
            Some(user_id),
            "passkey_counter_regression",
            ip,
            ua,
            json!({
                "passkey_id": passkey_id,
                "stored_counter": stored_counter,
                "asserted_counter": asserted_counter,
            }),
        )
        .await;
        return Err(AppError::BadRequest(
            "passkey_counter_regression".to_string(),
        ));
    }
    if stored_counter == 0 && asserted_counter == 0 {
        db::audit(
            &state.db,
            Some(user_id),
            "passkey_synced_counter_zero",
            ip,
            ua,
            json!({"passkey_id": passkey_id, "policy": "synced_passkey"}),
        )
        .await;
    }

    let mut passkey: Passkey =
        serde_json::from_str(&data).map_err(|e| AppError::Internal(e.to_string()))?;
    if passkey.update_credential(result).unwrap_or(false) {
        let updated =
            serde_json::to_string(&passkey).map_err(|e| AppError::Internal(e.to_string()))?;
        sqlx::query("UPDATE passkeys SET data = ?, counter = ?, last_used_at = ? WHERE id = ?")
            .bind(updated)
            .bind(asserted_counter)
            .bind(db::now())
            .bind(&passkey_id)
            .execute(&state.db)
            .await?;
    } else {
        sqlx::query("UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?")
            .bind(asserted_counter)
            .bind(db::now())
            .bind(&passkey_id)
            .execute(&state.db)
            .await?;
    }

    Ok(passkey_id)
}

async fn passkey_login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<ChallengeReq>,
) -> AppResult<(CookieJar, Json<Value>)> {
    check_origin(&state, &headers)?;
    let ip = auth::client_ip(&headers, peer, &state.config);
    let ua = auth::client_ua(&headers);
    if let Some(ip) = &ip {
        auth::check_rate_limit(
            &state.rate_limiter,
            &format!("passkey-login:ip:{ip}"),
            20,
            60,
        )?;
    }

    require_ceremony(&jar, &req.challenge_id)?;
    let challenge = state
        .auth_challenges
        .lock()
        .map_err(|_| AppError::Internal("challenge lock poisoned".into()))?
        .remove(&req.challenge_id)
        .ok_or_else(|| AppError::BadRequest("challenge_not_found".to_string()))?;

    if Utc::now() > challenge.expires_at {
        return Err(AppError::BadRequest("challenge_expired".to_string()));
    }
    if !auth::is_active_user(&state.db, challenge.user_id).await? {
        return Err(AppError::Unauthorized);
    }

    let credential: PublicKeyCredential =
        serde_json::from_value(req.credential).map_err(|e| AppError::BadRequest(e.to_string()))?;

    let result = state
        .webauthn
        .finish_passkey_authentication(&credential, &challenge.state)?;

    let passkey_id = apply_passkey_assertion(
        &state,
        challenge.user_id,
        &result,
        ip.as_deref(),
        ua.as_deref(),
    )
    .await?;

    let token = auth::create_session(
        &state.db,
        &state.config,
        challenge.user_id,
        Some(&passkey_id),
        ip.as_deref(),
        ua.as_deref(),
    )
    .await?;

    db::audit(
        &state.db,
        Some(challenge.user_id),
        "passkey_login",
        ip.as_deref(),
        ua.as_deref(),
        json!({"passkey_id": passkey_id}),
    )
    .await;

    let jar = jar
        .add(session_cookie(&state.config, &token))
        .add(clear_ceremony_cookie(&state.config));
    Ok((jar, Json(json!({"ok": true}))))
}

async fn stepup_start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
) -> AppResult<(CookieJar, Json<Value>)> {
    check_origin(&state, &headers)?;
    let ip = auth::client_ip(&headers, peer, &state.config);
    let ua = auth::client_ua(&headers);
    if let Some(ip) = &ip {
        auth::check_rate_limit(
            &state.rate_limiter,
            &format!("stepup-start:ip:{ip}"),
            20,
            60,
        )?;
    }

    let session = require_session(&state, &jar).await?;
    let passkeys = load_passkeys(&state.db, session.user_id).await?;
    if passkeys.is_empty() {
        return Err(AppError::BadRequest("no_passkeys".to_string()));
    }

    let (options, auth_state) = state.webauthn.start_passkey_authentication(&passkeys)?;
    let challenge_id = Uuid::new_v4().to_string();
    {
        let mut challenges = state
            .stepup_challenges
            .lock()
            .map_err(|_| AppError::Internal("challenge lock poisoned".into()))?;
        challenges.insert(
            challenge_id.clone(),
            AuthChallenge {
                user_id: session.user_id,
                state: auth_state,
                expires_at: Utc::now() + ChronoDuration::minutes(2),
            },
        );
    }

    db::audit(
        &state.db,
        Some(session.user_id),
        "stepup_started",
        ip.as_deref(),
        ua.as_deref(),
        json!({}),
    )
    .await;

    Ok((
        jar.add(ceremony_cookie(&state.config, &challenge_id)),
        Json(json!({
            "challenge_id": challenge_id,
            "options": serde_json::to_value(options).map_err(|e| AppError::Internal(e.to_string()))?,
        })),
    ))
}

async fn stepup_finish(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<ChallengeReq>,
) -> AppResult<(CookieJar, Json<Value>)> {
    check_origin(&state, &headers)?;
    let ip = auth::client_ip(&headers, peer, &state.config);
    let ua = auth::client_ua(&headers);
    if let Some(ip) = &ip {
        auth::check_rate_limit(
            &state.rate_limiter,
            &format!("stepup-finish:ip:{ip}"),
            20,
            60,
        )?;
    }

    let session = require_session(&state, &jar).await?;
    require_ceremony(&jar, &req.challenge_id)?;
    let challenge = {
        let mut challenges = state
            .stepup_challenges
            .lock()
            .map_err(|_| AppError::Internal("challenge lock poisoned".into()))?;
        let Some(existing) = challenges.get(&req.challenge_id) else {
            return Err(AppError::BadRequest("challenge_not_found".to_string()));
        };
        if existing.user_id != session.user_id {
            return Err(AppError::BadRequest("challenge_not_found".to_string()));
        }
        challenges
            .remove(&req.challenge_id)
            .ok_or_else(|| AppError::BadRequest("challenge_not_found".to_string()))?
    };

    if Utc::now() > challenge.expires_at {
        return Err(AppError::BadRequest("challenge_expired".to_string()));
    }
    if !auth::is_active_user(&state.db, session.user_id).await? {
        return Err(AppError::Unauthorized);
    }

    let credential: PublicKeyCredential =
        serde_json::from_value(req.credential).map_err(|e| AppError::BadRequest(e.to_string()))?;
    let result = state
        .webauthn
        .finish_passkey_authentication(&credential, &challenge.state)?;

    let passkey_id = apply_passkey_assertion(
        &state,
        session.user_id,
        &result,
        ip.as_deref(),
        ua.as_deref(),
    )
    .await?;

    let stepup_at = Utc::now();
    let stepup_until = stepup_at + ChronoDuration::minutes(STEPUP_MINUTES);
    let result = sqlx::query(
        "UPDATE sessions SET stepup_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
    )
    .bind(stepup_at.to_rfc3339())
    .bind(session.session_id.to_string())
    .bind(session.user_id.to_string())
    .execute(&state.db)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::Unauthorized);
    }

    db::audit(
        &state.db,
        Some(session.user_id),
        "stepup_completed",
        ip.as_deref(),
        ua.as_deref(),
        json!({"passkey_id": passkey_id}),
    )
    .await;

    Ok((
        jar.add(clear_ceremony_cookie(&state.config)),
        Json(json!({
            "ok": true,
            "stepup_until": stepup_until.to_rfc3339(),
        })),
    ))
}

async fn revoke_all_sessions(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
) -> AppResult<(CookieJar, Json<Value>)> {
    check_origin(&state, &headers)?;
    let session = require_session(&state, &jar).await?;
    require_stepup(&session)?;
    let revoked = auth::revoke_all_sessions(&state.db, session.user_id).await?;
    db::audit(
        &state.db,
        Some(session.user_id),
        "sessions_revoked_all",
        auth::client_ip(&headers, peer, &state.config).as_deref(),
        auth::client_ua(&headers).as_deref(),
        json!({"count": revoked}),
    )
    .await;
    let jar = jar.add(clear_cookie(&state.config));
    Ok((jar, Json(json!({"ok": true}))))
}

async fn logout(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
) -> AppResult<(CookieJar, Json<Value>)> {
    check_origin(&state, &headers)?;
    if let Some(session) = current_session(&state, &jar).await? {
        auth::revoke_session(&state.db, session.session_id, session.user_id).await?;
        db::audit(
            &state.db,
            Some(session.user_id),
            "logout",
            auth::client_ip(&headers, peer, &state.config).as_deref(),
            auth::client_ua(&headers).as_deref(),
            json!({}),
        )
        .await;
    }
    let jar = jar.add(clear_cookie(&state.config));
    Ok((jar, Json(json!({"ok": true}))))
}

async fn me(State(state): State<AppState>, jar: CookieJar) -> AppResult<Json<Value>> {
    let Some(session) = current_session(&state, &jar).await? else {
        return Ok(Json(json!({"authenticated": false})));
    };

    let passkeys = auth::count_passkeys(&state.db, session.user_id).await?;
    let sessions = count_active_sessions(&state.db, session.user_id).await?;
    let recovery = count_recovery_codes(&state.db, session.user_id).await?;

    Ok(Json(json!({
        "authenticated": true,
        "user": {
            "id": session.user_id,
            "email": session.email,
        },
        "passkeys": passkeys,
        "sessions": sessions,
        "recovery_codes_remaining": recovery,
        "session_expires_at": session.expires_at,
    })))
}

async fn count_active_sessions(pool: &SqlitePool, user_id: Uuid) -> AppResult<i64> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS n FROM sessions
         WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?",
    )
    .bind(user_id.to_string())
    .bind(db::now())
    .fetch_one(pool)
    .await?;
    Ok(row.get("n"))
}

async fn count_recovery_codes(pool: &SqlitePool, user_id: Uuid) -> AppResult<i64> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS n FROM recovery_codes
         WHERE user_id = ? AND used_at IS NULL
           AND expires_at IS NOT NULL AND expires_at > ?",
    )
    .bind(user_id.to_string())
    .bind(db::now())
    .fetch_one(pool)
    .await?;
    Ok(row.get("n"))
}

async fn list_sessions(State(state): State<AppState>, jar: CookieJar) -> AppResult<Json<Value>> {
    let session = require_session(&state, &jar).await?;
    let rows = sqlx::query(
        "SELECT id, created_at, last_seen_at, expires_at, ip, user_agent
         FROM sessions
         WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
         ORDER BY last_seen_at DESC",
    )
    .bind(session.user_id.to_string())
    .bind(db::now())
    .fetch_all(&state.db)
    .await?;

    let sessions: Vec<Value> = rows
        .into_iter()
        .map(|row| {
            let id: String = row.get("id");
            json!({
                "id": id,
                "current": id == session.session_id.to_string(),
                "created_at": row.get::<String, _>("created_at"),
                "last_seen_at": row.get::<String, _>("last_seen_at"),
                "expires_at": row.get::<String, _>("expires_at"),
                "ip": row.get::<Option<String>, _>("ip"),
                "user_agent": row.get::<Option<String>, _>("user_agent"),
            })
        })
        .collect();

    Ok(Json(json!({"sessions": sessions})))
}

async fn revoke_session(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<(CookieJar, Json<Value>)> {
    check_origin(&state, &headers)?;
    let session = require_session(&state, &jar).await?;
    let target = Uuid::parse_str(&id).map_err(|_| AppError::BadRequest("invalid_id".into()))?;
    let revoked = auth::revoke_session(&state.db, target, session.user_id).await?;
    if !revoked {
        return Err(AppError::NotFound);
    }
    db::audit(
        &state.db,
        Some(session.user_id),
        "session_revoked",
        auth::client_ip(&headers, peer, &state.config).as_deref(),
        auth::client_ua(&headers).as_deref(),
        json!({"session_id": target}),
    )
    .await;

    let jar = if target == session.session_id {
        jar.add(clear_cookie(&state.config))
    } else {
        jar
    };
    Ok((jar, Json(json!({"ok": true}))))
}

async fn list_passkeys(State(state): State<AppState>, jar: CookieJar) -> AppResult<Json<Value>> {
    let session = require_session(&state, &jar).await?;
    let rows = sqlx::query(
        "SELECT id, label, credential_id, created_at, last_used_at
         FROM passkeys WHERE user_id = ? ORDER BY created_at",
    )
    .bind(session.user_id.to_string())
    .fetch_all(&state.db)
    .await?;

    let passkeys: Vec<Value> = rows
        .into_iter()
        .map(|row| {
            json!({
                "id": row.get::<String, _>("id"),
                "label": row.get::<String, _>("label"),
                "credential_id": row.get::<String, _>("credential_id"),
                "created_at": row.get::<String, _>("created_at"),
                "last_used_at": row.get::<Option<String>, _>("last_used_at"),
            })
        })
        .collect();

    Ok(Json(json!({"passkeys": passkeys})))
}

async fn passkey_add_start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
) -> AppResult<(CookieJar, Json<Value>)> {
    check_origin(&state, &headers)?;
    let ip = auth::client_ip(&headers, peer, &state.config);
    let ua = auth::client_ua(&headers);
    if let Some(ip) = &ip {
        auth::check_rate_limit(
            &state.rate_limiter,
            &format!("passkey-add-start:ip:{ip}"),
            20,
            60,
        )?;
    }

    let session = require_session(&state, &jar).await?;
    require_stepup(&session)?;
    let passkeys = load_passkeys(&state.db, session.user_id).await?;
    let exclude = passkeys
        .iter()
        .map(|passkey| passkey.cred_id().clone())
        .collect::<Vec<_>>();

    let (options, reg_state) = state.webauthn.start_passkey_registration(
        session.user_id,
        &session.email,
        &session.email,
        Some(exclude),
    )?;

    let challenge_id = Uuid::new_v4().to_string();
    {
        let mut challenges = state
            .reg_challenges
            .lock()
            .map_err(|_| AppError::Internal("challenge lock poisoned".into()))?;
        challenges.insert(
            challenge_id.clone(),
            RegChallenge {
                user_id: session.user_id,
                state: reg_state,
                expires_at: Utc::now() + ChronoDuration::minutes(2),
            },
        );
    }

    db::audit(
        &state.db,
        Some(session.user_id),
        "passkey_add_started",
        ip.as_deref(),
        ua.as_deref(),
        json!({}),
    )
    .await;

    Ok((
        jar.add(ceremony_cookie(&state.config, &challenge_id)),
        Json(json!({
            "challenge_id": challenge_id,
            "options": serde_json::to_value(options).map_err(|e| AppError::Internal(e.to_string()))?,
        })),
    ))
}

async fn passkey_add_finish(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<ChallengeReq>,
) -> AppResult<(CookieJar, Json<Value>)> {
    check_origin(&state, &headers)?;
    let ip = auth::client_ip(&headers, peer, &state.config);
    let ua = auth::client_ua(&headers);
    if let Some(ip) = &ip {
        auth::check_rate_limit(
            &state.rate_limiter,
            &format!("passkey-add-finish:ip:{ip}"),
            20,
            60,
        )?;
    }

    let session = require_session(&state, &jar).await?;
    require_stepup(&session)?;
    require_ceremony(&jar, &req.challenge_id)?;
    let challenge = {
        let mut challenges = state
            .reg_challenges
            .lock()
            .map_err(|_| AppError::Internal("challenge lock poisoned".into()))?;
        let Some(existing) = challenges.get(&req.challenge_id) else {
            return Err(AppError::BadRequest("challenge_not_found".to_string()));
        };
        if existing.user_id != session.user_id {
            return Err(AppError::BadRequest("challenge_not_found".to_string()));
        }
        challenges
            .remove(&req.challenge_id)
            .ok_or_else(|| AppError::BadRequest("challenge_not_found".to_string()))?
    };

    if Utc::now() > challenge.expires_at {
        return Err(AppError::BadRequest("challenge_expired".to_string()));
    }

    let credential: RegisterPublicKeyCredential =
        serde_json::from_value(req.credential).map_err(|e| AppError::BadRequest(e.to_string()))?;

    let passkey = state
        .webauthn
        .finish_passkey_registration(&credential, &challenge.state)?;

    let credential_id = URL_SAFE_NO_PAD.encode(passkey.cred_id());
    let existing = sqlx::query("SELECT 1 FROM passkeys WHERE credential_id = ?")
        .bind(&credential_id)
        .fetch_optional(&state.db)
        .await?;
    if existing.is_some() {
        return Err(AppError::BadRequest(
            "credential_already_registered".to_string(),
        ));
    }

    let data = serde_json::to_string(&passkey)
        .map_err(|e| AppError::Internal(format!("failed to serialize passkey: {e}")))?;
    let passkey_id = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO passkeys (id, user_id, credential_id, data, label, created_at, counter)
         VALUES (?, ?, ?, ?, ?, ?, 0)",
    )
    .bind(&passkey_id)
    .bind(session.user_id.to_string())
    .bind(credential_id)
    .bind(data)
    .bind(passkey_label(&ua))
    .bind(db::now())
    .execute(&state.db)
    .await?;

    db::audit(
        &state.db,
        Some(session.user_id),
        "passkey_added",
        ip.as_deref(),
        ua.as_deref(),
        json!({"passkey_id": passkey_id}),
    )
    .await;

    queue_security_notification(
        &state,
        session.email.clone(),
        "AuthLayer passkey added",
        "A new passkey was added to your AuthLayer account. If this was not you, revoke it and contact your administrator immediately."
            .to_string(),
    );

    Ok((
        jar.add(clear_ceremony_cookie(&state.config)),
        Json(json!({"ok": true})),
    ))
}

async fn revoke_passkey(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<(CookieJar, Json<Value>)> {
    check_origin(&state, &headers)?;
    let session = require_session(&state, &jar).await?;
    require_stepup(&session)?;
    let target = Uuid::parse_str(&id).map_err(|_| AppError::BadRequest("invalid_id".into()))?;
    let target_string = target.to_string();
    let current_bound_to_target = session.passkey_id.as_deref() == Some(target_string.as_str());

    let mut tx = state.db.begin().await?;
    let exists = sqlx::query("SELECT 1 FROM passkeys WHERE id = ? AND user_id = ?")
        .bind(&target_string)
        .bind(session.user_id.to_string())
        .fetch_optional(&mut *tx)
        .await?;
    if exists.is_none() {
        return Err(AppError::NotFound);
    }

    let result = sqlx::query("DELETE FROM passkeys WHERE id = ? AND user_id = ?")
        .bind(&target_string)
        .bind(session.user_id.to_string())
        .execute(&mut *tx)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    let passkeys_remaining = auth::count_passkeys_in(&mut tx, session.user_id).await?;
    let recovery: i64 = sqlx::query(
        "SELECT COUNT(*) AS n FROM recovery_codes
         WHERE user_id = ? AND used_at IS NULL
           AND expires_at IS NOT NULL AND expires_at > ?",
    )
    .bind(session.user_id.to_string())
    .bind(db::now())
    .fetch_one(&mut *tx)
    .await?
    .get("n");
    if passkeys_remaining == 0 && recovery == 0 {
        tx.rollback().await?;
        return Err(AppError::BadRequest(
            "cannot_remove_last_credential".to_string(),
        ));
    }

    let sessions_revoked = sqlx::query(
        "UPDATE sessions SET revoked_at = ?
         WHERE user_id = ? AND passkey_id = ? AND revoked_at IS NULL",
    )
    .bind(db::now())
    .bind(session.user_id.to_string())
    .bind(&target_string)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;

    db::audit(
        &state.db,
        Some(session.user_id),
        "passkey_revoked",
        auth::client_ip(&headers, peer, &state.config).as_deref(),
        auth::client_ua(&headers).as_deref(),
        json!({
            "passkey_id": target,
            "sessions_revoked": sessions_revoked,
        }),
    )
    .await;

    let jar = if current_bound_to_target {
        jar.add(clear_cookie(&state.config))
    } else {
        jar
    };
    queue_security_notification(
        &state,
        session.email.clone(),
        "AuthLayer passkey removed",
        "A passkey was removed from your AuthLayer account. If this was not you, contact your administrator immediately."
            .to_string(),
    );
    Ok((jar, Json(json!({"ok": true}))))
}

async fn regenerate_recovery(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
) -> AppResult<Json<Value>> {
    check_origin(&state, &headers)?;
    let session = require_session(&state, &jar).await?;
    require_stepup(&session)?;
    let codes = auth::create_recovery_codes(
        &state.db,
        session.user_id,
        &state.config.otp_secret,
        state.config.recovery_code_ttl_days,
    )
    .await?;

    db::audit(
        &state.db,
        Some(session.user_id),
        "recovery_codes_regenerated",
        auth::client_ip(&headers, peer, &state.config).as_deref(),
        auth::client_ua(&headers).as_deref(),
        json!({"count": codes.len()}),
    )
    .await;

    queue_security_notification(
        &state,
        session.email.clone(),
        "AuthLayer recovery codes regenerated",
        "New recovery codes were generated for your AuthLayer account. If you did not do this, review your active sessions and passkeys immediately."
            .to_string(),
    );

    Ok(Json(json!({"recovery_codes": codes})))
}

async fn recover_start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<EmailReq>,
) -> AppResult<Json<Value>> {
    check_origin(&state, &headers)?;
    let email = auth::normalize_email(&req.email)?;
    let ip = auth::client_ip(&headers, peer, &state.config);
    let ua = auth::client_ua(&headers);

    auth::check_rate_limit(
        &state.rate_limiter,
        &format!("recover:email:{email}"),
        3,
        300,
    )?;
    if let Some(ip) = &ip {
        auth::check_rate_limit(
            &state.rate_limiter,
            &format!("recover-start:ip:{ip}"),
            20,
            300,
        )?;
    }

    if let Some(user_id) = auth::find_user_by_email(&state.db, &email).await? {
        if auth::is_active_user(&state.db, user_id).await? {
            match auth::create_otp(
                &state.db,
                &state.email,
                &state.config,
                user_id,
                &email,
                "recovery",
            )
            .await
            {
                Ok(()) => {
                    db::audit(
                        &state.db,
                        Some(user_id),
                        "recovery_started",
                        ip.as_deref(),
                        ua.as_deref(),
                        json!({}),
                    )
                    .await;
                    queue_security_notification(
                        &state,
                        email.clone(),
                        "AuthLayer recovery attempt started",
                        "A recovery attempt was started for your AuthLayer account. If this was not you, secure your email account and contact your administrator."
                            .to_string(),
                    );
                }
                Err(error) => {
                    db::audit(
                        &state.db,
                        Some(user_id),
                        "recovery_start_delivery_failed",
                        ip.as_deref(),
                        ua.as_deref(),
                        json!({"reason": error.to_string()}),
                    )
                    .await;
                }
            }
        } else {
            db::audit(
                &state.db,
                Some(user_id),
                "recovery_start_inactive",
                ip.as_deref(),
                ua.as_deref(),
                json!({}),
            )
            .await;
        }
    } else {
        db::audit(
            &state.db,
            None,
            "recovery_start_unknown",
            ip.as_deref(),
            ua.as_deref(),
            json!({}),
        )
        .await;
    }

    Ok(Json(json!({
        "flow": "code",
        "email": email,
        "dev_outbox": if state.config.dev_mode { Some("/dev/outbox") } else { None },
    })))
}

async fn recover_verify_email(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<RecoveryVerifyEmailReq>,
) -> AppResult<(CookieJar, Json<Value>)> {
    check_origin(&state, &headers)?;
    let email = auth::normalize_email(&req.email)?;
    let ip = auth::client_ip(&headers, peer, &state.config);
    let ua = auth::client_ua(&headers);

    auth::check_rate_limit(
        &state.rate_limiter,
        &format!("recover-verify-email:email:{email}"),
        5,
        60,
    )?;
    if let Some(ip) = &ip {
        auth::check_rate_limit(
            &state.rate_limiter,
            &format!("recover-verify-email:ip:{ip}"),
            10,
            60,
        )?;
    }

    let Some(user_id) = auth::find_user_by_email(&state.db, &email).await? else {
        db::audit(
            &state.db,
            None,
            "recovery_otp_verification_failed",
            ip.as_deref(),
            ua.as_deref(),
            json!({"reason": "invalid_code"}),
        )
        .await;
        return Err(AppError::BadRequest("invalid_code".to_string()));
    };
    if !auth::is_active_user(&state.db, user_id).await? {
        db::audit(
            &state.db,
            Some(user_id),
            "recovery_otp_verification_failed",
            ip.as_deref(),
            ua.as_deref(),
            json!({"reason": "inactive_user"}),
        )
        .await;
        return Err(AppError::BadRequest("invalid_code".to_string()));
    }

    if let Err(error) = auth::verify_otp(
        &state.db,
        user_id,
        "recovery",
        &req.code,
        &state.config.otp_secret,
    )
    .await
    {
        db::audit(
            &state.db,
            Some(user_id),
            "recovery_otp_verification_failed",
            ip.as_deref(),
            ua.as_deref(),
            json!({"reason": error.to_string()}),
        )
        .await;
        return Err(error);
    }

    let challenge_id = Uuid::new_v4().to_string();
    {
        let mut challenges = state
            .recovery_challenges
            .lock()
            .map_err(|_| AppError::Internal("challenge lock poisoned".into()))?;
        challenges.insert(
            challenge_id.clone(),
            RecoveryChallenge {
                user_id,
                email: email.clone(),
                expires_at: Utc::now() + ChronoDuration::minutes(10),
            },
        );
    }

    db::audit(
        &state.db,
        Some(user_id),
        "recovery_email_verified",
        ip.as_deref(),
        ua.as_deref(),
        json!({}),
    )
    .await;

    Ok((
        jar.add(ceremony_cookie(&state.config, &challenge_id)),
        Json(json!({
            "flow": "recovery_code",
            "challenge_id": challenge_id,
        })),
    ))
}

async fn recover_verify_code(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<RecoveryVerifyCodeReq>,
) -> AppResult<(CookieJar, Json<Value>)> {
    check_origin(&state, &headers)?;
    let ip = auth::client_ip(&headers, peer, &state.config);
    let ua = auth::client_ua(&headers);
    if let Some(ip) = &ip {
        auth::check_rate_limit(
            &state.rate_limiter,
            &format!("recover-verify-code:ip:{ip}"),
            10,
            60,
        )?;
    }

    let challenge_email = {
        let challenges = state
            .recovery_challenges
            .lock()
            .map_err(|_| AppError::Internal("challenge lock poisoned".into()))?;
        challenges
            .get(&req.challenge_id)
            .map(|challenge| challenge.email.clone())
    };
    if let Some(email) = &challenge_email {
        auth::check_rate_limit(
            &state.rate_limiter,
            &format!("recover-verify-code:email:{email}"),
            5,
            60,
        )?;
    }

    require_ceremony(&jar, &req.challenge_id)?;
    let challenge = state
        .recovery_challenges
        .lock()
        .map_err(|_| AppError::Internal("challenge lock poisoned".into()))?
        .remove(&req.challenge_id)
        .ok_or_else(|| AppError::BadRequest("challenge_not_found".to_string()))?;

    if Utc::now() > challenge.expires_at {
        return Err(AppError::BadRequest("challenge_expired".to_string()));
    }
    if !auth::is_active_user(&state.db, challenge.user_id).await? {
        db::audit(
            &state.db,
            Some(challenge.user_id),
            "recovery_code_failed",
            ip.as_deref(),
            ua.as_deref(),
            json!({"reason": "inactive_user"}),
        )
        .await;
        return Err(AppError::BadRequest("invalid_recovery_code".to_string()));
    }

    match auth::verify_recovery_code(
        &state.db,
        challenge.user_id,
        &req.recovery_code,
        &state.config.otp_secret,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            db::audit(
                &state.db,
                Some(challenge.user_id),
                "recovery_code_failed",
                ip.as_deref(),
                ua.as_deref(),
                json!({"reason": "invalid_recovery_code"}),
            )
            .await;
            return Err(AppError::BadRequest("invalid_recovery_code".to_string()));
        }
        Err(error) => {
            db::audit(
                &state.db,
                Some(challenge.user_id),
                "recovery_code_failed",
                ip.as_deref(),
                ua.as_deref(),
                json!({"reason": error.to_string()}),
            )
            .await;
            return Err(error);
        }
    }

    // Create the replacement registration challenge before destroying existing
    // credentials. If this fails, the account keeps its current passkeys and
    // sessions; a second recovery code can be used to retry.
    let email = challenge.email.clone();
    let (options, reg_state) =
        state
            .webauthn
            .start_passkey_registration(challenge.user_id, &email, &email, None)?;
    let registration_id = Uuid::new_v4().to_string();
    {
        let mut challenges = state
            .reg_challenges
            .lock()
            .map_err(|_| AppError::Internal("challenge lock poisoned".into()))?;
        challenges.insert(
            registration_id.clone(),
            RegChallenge {
                user_id: challenge.user_id,
                state: reg_state,
                expires_at: Utc::now() + ChronoDuration::minutes(5),
            },
        );
    }

    let (sessions_revoked, passkeys_removed) =
        match auth::revoke_all_credentials(&state.db, challenge.user_id).await {
            Ok(counts) => counts,
            Err(error) => {
                if let Ok(mut challenges) = state.reg_challenges.lock() {
                    challenges.remove(&registration_id);
                }
                return Err(error);
            }
        };

    db::audit(
        &state.db,
        Some(challenge.user_id),
        "recovery_credentials_revoked",
        ip.as_deref(),
        ua.as_deref(),
        json!({
            "sessions_revoked": sessions_revoked,
            "passkeys_removed": passkeys_removed,
        }),
    )
    .await;

    queue_security_notification(
        &state,
        challenge.email.clone(),
        "AuthLayer account recovery completed",
        "Account recovery completed for your AuthLayer account. All existing sessions and passkeys were revoked. If this was not you, contact your administrator immediately."
            .to_string(),
    );

    db::audit(
        &state.db,
        Some(challenge.user_id),
        "recovery_code_verified",
        ip.as_deref(),
        ua.as_deref(),
        json!({}),
    )
    .await;

    Ok((
        jar.add(ceremony_cookie(&state.config, &registration_id)),
        Json(json!({
            "flow": "register_passkey",
            "challenge_id": registration_id,
            "options": serde_json::to_value(options).map_err(|e| AppError::Internal(e.to_string()))?,
        })),
    ))
}

async fn dev_outbox(State(state): State<AppState>) -> AppResult<Html<String>> {
    if !state.config.dev_mode {
        return Err(AppError::NotFound);
    }

    let rows = sqlx::query(
        "SELECT to_email, subject, body, created_at FROM outbox ORDER BY created_at DESC LIMIT 50",
    )
    .fetch_all(&state.db)
    .await?;

    let mut items = String::new();
    for row in rows {
        let to: String = row.get("to_email");
        let subject: String = row.get("subject");
        let body: String = row.get("body");
        let created: String = row.get("created_at");
        items.push_str(&format!(
            "<article class=\"mail\"><header><b>{}</b><span>{}</span></header><h3>{}</h3><pre>{}</pre></article>",
            html_escape::encode_text(&to),
            html_escape::encode_text(&created),
            html_escape::encode_text(&subject),
            html_escape::encode_text(&body),
        ));
    }

    Ok(Html(format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="5">
<title>AuthLayer dev outbox</title>
<style>
body{{font-family:ui-sans-serif,system-ui,sans-serif;max-width:900px;margin:40px auto;padding:0 20px;background:#0b1020;color:#e8ecf8}}
a{{color:#7dd3fc}} .mail{{background:#151c33;border:1px solid #26304f;border-radius:14px;padding:16px;margin:14px 0}}
header{{display:flex;justify-content:space-between;color:#93a4c8;font-size:13px}} h3{{margin:10px 0}}
pre{{white-space:pre-wrap;background:#0d1428;padding:12px;border-radius:10px;color:#c7d2fe}}
</style></head><body>
<h1>Dev outbox</h1>
<p>This page shows the last 50 messages recorded by the server. <a href="/">Back to app</a></p>
{items}
</body></html>"#
    )))
}

async fn api_dev_outbox(State(state): State<AppState>) -> AppResult<Json<Value>> {
    if !state.config.dev_mode {
        return Err(AppError::NotFound);
    }

    let rows = sqlx::query(
        "SELECT to_email, subject, body, created_at FROM outbox ORDER BY created_at DESC LIMIT 50",
    )
    .fetch_all(&state.db)
    .await?;

    let items: Vec<Value> = rows
        .into_iter()
        .map(|row| {
            json!({
                "to": row.get::<String, _>("to_email"),
                "subject": row.get::<String, _>("subject"),
                "body": row.get::<String, _>("body"),
                "created_at": row.get::<String, _>("created_at"),
            })
        })
        .collect();

    Ok(Json(json!({"messages": items})))
}

async fn admin_login_page(State(state): State<AppState>, jar: CookieJar) -> AppResult<Response> {
    if state.config.admin_token.is_none() {
        return Err(AppError::NotFound);
    }
    if admin_session_valid(&state, &jar).await {
        return Ok(Redirect::to("/admin").into_response());
    }
    Ok(Html(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AuthLayer admin login</title>
<style>
body{font-family:ui-sans-serif,system-ui,sans-serif;max-width:420px;margin:80px auto;padding:0 20px;background:#0b1020;color:#e8ecf8}
form{background:#151c33;border:1px solid #26304f;border-radius:14px;padding:24px}
label{display:block;margin-bottom:8px;color:#93a4c8} input{width:100%;box-sizing:border-box;padding:10px;border-radius:8px;border:1px solid #26304f;background:#0d1428;color:#e8ecf8}
button{margin-top:16px;padding:10px 16px;border-radius:8px;border:0;background:#7dd3fc;color:#0b1020;font-weight:600;cursor:pointer}
p{color:#93a4c8;font-size:14px}
</style></head><body>
<h1>AuthLayer admin</h1>
<form method="post" action="/admin/login">
<label for="token">Admin token</label>
<input id="token" name="token" type="password" autocomplete="off" required autofocus>
<button type="submit">Sign in</button>
</form>
<p>This page is read-only. The admin token is never accepted in the URL.</p>
</body></html>"#,
    )
    .into_response())
}

async fn admin_login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    body: Bytes,
) -> AppResult<Response> {
    check_origin(&state, &headers)?;
    let ip = auth::client_ip(&headers, peer, &state.config);
    let ua = auth::client_ua(&headers);

    if let Err(error) = auth::check_rate_limit(
        &state.rate_limiter,
        &format!("admin-login:ip:{}", ip.as_deref().unwrap_or("unknown")),
        5,
        60,
    ) {
        db::audit(
            &state.db,
            None,
            "admin_login_rate_limited",
            ip.as_deref(),
            ua.as_deref(),
            json!({}),
        )
        .await;
        return Err(error);
    }

    let Some(expected) = &state.config.admin_token else {
        return Err(AppError::NotFound);
    };
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let is_json = content_type.starts_with("application/json");
    let token = if is_json {
        serde_json::from_slice::<AdminLoginReq>(&body)
            .map(|request| request.token)
            .map_err(|_| AppError::BadRequest("invalid_request".to_string()))?
    } else {
        url::form_urlencoded::parse(&body)
            .find(|(key, _)| key == "token")
            .map(|(_, value)| value.into_owned())
            .ok_or_else(|| AppError::BadRequest("invalid_request".to_string()))?
    };

    if !auth::constant_time_eq(token.as_bytes(), expected.as_bytes()) {
        db::audit(
            &state.db,
            None,
            "admin_login_failed",
            ip.as_deref(),
            ua.as_deref(),
            json!({}),
        )
        .await;
        return Err(AppError::Forbidden);
    }

    let token = auth::generate_token();
    let token_hash = auth::hash_token(&token);
    let now = Utc::now();
    let expires_at = now + ChronoDuration::seconds(ADMIN_SESSION_SECONDS);
    sqlx::query(
        "INSERT INTO admin_sessions
         (id, token_hash, created_at, expires_at, ip, user_agent)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(token_hash)
    .bind(now.to_rfc3339())
    .bind(expires_at.to_rfc3339())
    .bind(ip.as_deref())
    .bind(ua.as_deref())
    .execute(&state.db)
    .await?;

    let jar = jar.add(admin_cookie(&state.config, token));
    db::audit(
        &state.db,
        None,
        "admin_login_success",
        ip.as_deref(),
        ua.as_deref(),
        json!({}),
    )
    .await;

    if is_json {
        Ok((jar, Json(json!({"ok": true}))).into_response())
    } else {
        Ok((jar, Redirect::to("/admin")).into_response())
    }
}

async fn admin_logout(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
) -> AppResult<Response> {
    if state.config.admin_token.is_none() {
        return Err(AppError::NotFound);
    }
    check_origin(&state, &headers)?;
    let was_valid = admin_session_valid(&state, &jar).await;
    if let Some(token) = admin_cookie_token(&jar) {
        let token_hash = auth::hash_token(token);
        if let Err(error) = sqlx::query(
            "UPDATE admin_sessions SET revoked_at = ?
             WHERE token_hash = ? AND revoked_at IS NULL",
        )
        .bind(db::now())
        .bind(token_hash)
        .execute(&state.db)
        .await
        {
            tracing::error!(error = %error, "failed to revoke admin session");
        }
    }
    db::audit(
        &state.db,
        None,
        "admin_logout",
        auth::client_ip(&headers, peer, &state.config).as_deref(),
        auth::client_ua(&headers).as_deref(),
        json!({"authenticated": was_valid}),
    )
    .await;
    let jar = jar.add(clear_admin_cookie(&state.config));
    Ok((jar, Redirect::to("/admin/login")).into_response())
}

async fn admin(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
) -> AppResult<Response> {
    if state.config.admin_token.is_none() {
        return Err(AppError::NotFound);
    }
    if !admin_session_valid(&state, &jar).await {
        db::audit(
            &state.db,
            None,
            "admin_view_denied",
            auth::client_ip(&headers, peer, &state.config).as_deref(),
            auth::client_ua(&headers).as_deref(),
            json!({}),
        )
        .await;
        return Ok(Redirect::to("/admin/login").into_response());
    }

    db::audit(
        &state.db,
        None,
        "admin_view",
        auth::client_ip(&headers, peer, &state.config).as_deref(),
        auth::client_ua(&headers).as_deref(),
        json!({}),
    )
    .await;

    let users = sqlx::query(
        "SELECT id, email, status, created_at FROM users ORDER BY created_at DESC LIMIT 200",
    )
    .fetch_all(&state.db)
    .await?;
    let user_count = users.len();

    let sessions = sqlx::query(
        "SELECT s.id, s.user_id, s.created_at, s.last_seen_at, s.expires_at, s.revoked_at, s.ip, u.email
         FROM sessions s JOIN users u ON u.id = s.user_id
         ORDER BY s.last_seen_at DESC LIMIT 200",
    )
    .fetch_all(&state.db)
    .await?;

    let audit = sqlx::query(
        "SELECT event, user_id, ip, created_at FROM audit_events ORDER BY id DESC LIMIT 100",
    )
    .fetch_all(&state.db)
    .await?;

    let mut users_html = String::new();
    for row in users {
        users_html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape::encode_text(&row.get::<String, _>("email")),
            html_escape::encode_text(&row.get::<String, _>("status")),
            html_escape::encode_text(&row.get::<String, _>("created_at")),
            html_escape::encode_text(&row.get::<String, _>("id")),
        ));
    }

    let mut sessions_html = String::new();
    for row in sessions {
        let revoked: Option<String> = row.get("revoked_at");
        sessions_html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape::encode_text(&row.get::<String, _>("email")),
            html_escape::encode_text(&row.get::<String, _>("last_seen_at")),
            html_escape::encode_text(&row.get::<String, _>("expires_at")),
            if revoked.is_some() {
                "revoked"
            } else {
                "active"
            },
            html_escape::encode_text(row.get::<Option<String>, _>("ip").as_deref().unwrap_or("-")),
        ));
    }

    let mut audit_html = String::new();
    for row in audit {
        audit_html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape::encode_text(&row.get::<String, _>("created_at")),
            html_escape::encode_text(&row.get::<String, _>("event")),
            html_escape::encode_text(
                row.get::<Option<String>, _>("user_id")
                    .as_deref()
                    .unwrap_or("-")
            ),
            html_escape::encode_text(row.get::<Option<String>, _>("ip").as_deref().unwrap_or("-")),
        ));
    }

    Ok(Html(format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AuthLayer admin</title>
<style>
body{{font-family:ui-sans-serif,system-ui,sans-serif;max-width:1200px;margin:40px auto;padding:0 20px;background:#0b1020;color:#e8ecf8}}
h1{{margin-bottom:4px}} h2{{margin-top:32px}} table{{width:100%;border-collapse:collapse;font-size:13px}}
th,td{{text-align:left;padding:8px;border-bottom:1px solid #26304f}} th{{color:#93a4c8}}
code{{color:#7dd3fc}} form{{margin:12px 0}} button{{padding:8px 12px;border-radius:8px;border:0;background:#7dd3fc;color:#0b1020;font-weight:600;cursor:pointer}}
</style></head><body>
<h1>AuthLayer admin</h1>
<form method="post" action="/admin/logout"><button type="submit">Sign out</button></form>
<p>Read-only overview. API revocation is available from the user dashboard.</p>
<h2>Users ({})</h2>
<table><thead><tr><th>Email</th><th>Status</th><th>Created</th><th>ID</th></tr></thead><tbody>{}</tbody></table>
<h2>Sessions</h2>
<table><thead><tr><th>User</th><th>Last seen</th><th>Expires</th><th>State</th><th>IP</th></tr></thead><tbody>{}</tbody></table>
<h2>Audit (last 100)</h2>
<table><thead><tr><th>Time</th><th>Event</th><th>User</th><th>IP</th></tr></thead><tbody>{}</tbody></table>
</body></html>"#,
        user_count, users_html, sessions_html, audit_html,
    ))
    .into_response())
}
