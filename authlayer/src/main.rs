mod auth;
mod config;
mod db;
mod email;
mod error;
mod routes;
mod state;

use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result};
use axum::{
    extract::Request,
    http::{HeaderValue, header},
    middleware::{self, Next},
    response::Response,
};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;
use webauthn_rs::prelude::WebauthnBuilder;

use crate::{config::Config, email::EmailSender, state::AppState};

async fn cache_control_no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "authlayer=info,tower_http=info".into()),
        )
        .init();

    let config = Config::from_env()?;

    tracing::info!(
        app_url = %config.app_url,
        rp_id = %config.rp_id,
        db = %config.redacted_db_url(),
        dev_mode = config.dev_mode,
        trust_proxy = config.trust_proxy,
        "starting AuthLayer"
    );
    if config.dev_mode {
        tracing::warn!(
            "DEV_MODE=true is enabled; the dev outbox and OTP diagnostic endpoints are available on this listener"
        );
    }
    if config.admin_token.is_some() {
        tracing::warn!(
            "ADMIN_TOKEN is set; restrict /admin at the proxy/network layer and rotate the token after suspected exposure"
        );
    }

    let email_sender =
        EmailSender::from_config(&config).context("failed to configure the email provider")?;
    tracing::info!(
        email_provider = email_sender.provider_name(),
        "email provider configured"
    );

    let pool = db::init(&config).await?;
    if let Err(error) = db::cleanup_outbox(&pool).await {
        tracing::warn!(error = %error, "outbox startup cleanup failed");
    }
    match db::cleanup_expired_rows(&pool).await {
        Ok(counts) if counts.total() > 0 => {
            tracing::info!(
                otp = counts.otp,
                sessions = counts.sessions,
                recovery = counts.recovery,
                admin_sessions = counts.admin_sessions,
                "cleaned expired rows at startup"
            );
        }
        Ok(_) => {}
        Err(error) => tracing::warn!(error = %error, "expired-row startup cleanup failed"),
    }

    let webauthn = WebauthnBuilder::new(&config.rp_id, &config.app_url)
        .context("invalid WebAuthn relying party configuration")?
        .rp_name(&config.rp_name)
        .build()
        .context("failed to build WebAuthn")?;

    let state = AppState::new(pool, config.clone(), webauthn, email_sender);
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            cleanup_state.cleanup_expired();
            if let Err(error) = db::cleanup_outbox(&cleanup_state.db).await {
                tracing::warn!(error = %error, "periodic outbox cleanup failed");
            }
            if let Err(error) = db::cleanup_expired_rows(&cleanup_state.db).await {
                tracing::warn!(error = %error, "periodic expired-row cleanup failed");
            }
        }
    });
    let app = routes::router(state)
        .layer(middleware::from_fn(cache_control_no_store))
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("failed to bind {}", config.bind_addr))?;

    tracing::info!("listening on http://{}", config.bind_addr);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("server failed")
}
