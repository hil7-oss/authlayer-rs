use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use uuid::Uuid;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration, Webauthn};

use crate::{config::Config, email::EmailSender};

const MAX_CHALLENGES: usize = 10_000;
const RATE_LIMIT_MAX_ENTRIES: usize = 10_000;
const RATE_LIMIT_MAX_AGE: Duration = Duration::from_secs(3600);

pub struct RegChallenge {
    pub user_id: Uuid,
    pub state: PasskeyRegistration,
    pub expires_at: DateTime<Utc>,
}

pub struct AuthChallenge {
    pub user_id: Uuid,
    pub state: PasskeyAuthentication,
    pub expires_at: DateTime<Utc>,
}

pub struct RecoveryChallenge {
    pub user_id: Uuid,
    pub email: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub config: Arc<Config>,
    pub webauthn: Arc<Webauthn>,
    pub email: Arc<EmailSender>,
    pub reg_challenges: Arc<Mutex<HashMap<String, RegChallenge>>>,
    pub auth_challenges: Arc<Mutex<HashMap<String, AuthChallenge>>>,
    pub stepup_challenges: Arc<Mutex<HashMap<String, AuthChallenge>>>,
    pub recovery_challenges: Arc<Mutex<HashMap<String, RecoveryChallenge>>>,
    pub rate_limiter: Arc<RateLimiter>,
}

impl AppState {
    pub fn new(db: SqlitePool, config: Config, webauthn: Webauthn, email: EmailSender) -> Self {
        Self {
            db,
            config: Arc::new(config),
            webauthn: Arc::new(webauthn),
            email: Arc::new(email),
            reg_challenges: Arc::new(Mutex::new(HashMap::new())),
            auth_challenges: Arc::new(Mutex::new(HashMap::new())),
            stepup_challenges: Arc::new(Mutex::new(HashMap::new())),
            recovery_challenges: Arc::new(Mutex::new(HashMap::new())),
            rate_limiter: Arc::new(RateLimiter::default()),
        }
    }

    pub fn cleanup_expired(&self) {
        let now = Utc::now();
        if let Ok(mut challenges) = self.reg_challenges.lock() {
            prune_challenges(&mut challenges, now, |challenge| challenge.expires_at);
        }
        if let Ok(mut challenges) = self.auth_challenges.lock() {
            prune_challenges(&mut challenges, now, |challenge| challenge.expires_at);
        }
        if let Ok(mut challenges) = self.stepup_challenges.lock() {
            prune_challenges(&mut challenges, now, |challenge| challenge.expires_at);
        }
        if let Ok(mut challenges) = self.recovery_challenges.lock() {
            prune_challenges(&mut challenges, now, |challenge| challenge.expires_at);
        }
        self.rate_limiter
            .prune(RATE_LIMIT_MAX_AGE, RATE_LIMIT_MAX_ENTRIES);
    }
}

fn prune_challenges<T>(
    challenges: &mut HashMap<String, T>,
    now: DateTime<Utc>,
    expires_at: impl Fn(&T) -> DateTime<Utc>,
) {
    challenges.retain(|_, challenge| expires_at(challenge) > now);
    if challenges.len() > MAX_CHALLENGES {
        let excess = challenges.len() - MAX_CHALLENGES;
        let keys: Vec<String> = challenges.keys().take(excess).cloned().collect();
        for key in keys {
            challenges.remove(&key);
        }
    }
}

#[derive(Default)]
pub struct RateLimiter {
    hits: Mutex<HashMap<String, Vec<Instant>>>,
}

impl RateLimiter {
    pub fn check(&self, key: &str, max: usize, window: Duration) -> bool {
        let now = Instant::now();
        let mut hits = self.hits.lock().expect("rate limiter lock");
        let entry = hits.entry(key.to_string()).or_default();
        entry.retain(|t| now.duration_since(*t) < window);
        if entry.len() >= max {
            return false;
        }
        entry.push(now);
        true
    }

    pub fn prune(&self, max_age: Duration, max_entries: usize) {
        let now = Instant::now();
        let mut hits = self.hits.lock().expect("rate limiter lock");
        hits.retain(|_, timestamps| {
            timestamps.retain(|timestamp| now.duration_since(*timestamp) < max_age);
            !timestamps.is_empty()
        });
        if hits.len() > max_entries {
            let excess = hits.len() - max_entries;
            let keys: Vec<String> = hits.keys().take(excess).cloned().collect();
            for key in keys {
                hits.remove(&key);
            }
        }
    }
}
