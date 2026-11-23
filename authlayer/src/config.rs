use std::{
    env, fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use anyhow::{Context, Result, bail};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailProvider {
    Outbox,
    Smtp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpTlsMode {
    Required,
    Opportunistic,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(value: &str) -> Result<Self> {
        let (address, prefix) = value
            .split_once('/')
            .with_context(|| format!("trusted proxy CIDR must include a prefix: {value:?}"))?;
        let address: IpAddr = address
            .parse()
            .with_context(|| format!("invalid IP address in CIDR: {value:?}"))?;
        let prefix: u8 = prefix
            .parse()
            .with_context(|| format!("invalid prefix length in CIDR: {value:?}"))?;
        let max_prefix = if address.is_ipv4() { 32 } else { 128 };
        if prefix > max_prefix {
            bail!("CIDR prefix must be between 0 and {max_prefix}: {value:?}");
        }
        Ok(Self {
            network: mask_ip(address, prefix),
            prefix,
        })
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = ipv4_mask(self.prefix);
                (u32::from(network) & mask) == (u32::from(address) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = ipv6_mask(self.prefix);
                (u128::from(network) & mask) == (u128::from(address) & mask)
            }
            _ => false,
        }
    }
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    }
}

fn mask_ip(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => IpAddr::V4(Ipv4Addr::from(u32::from(address) & ipv4_mask(prefix))),
        IpAddr::V6(address) => IpAddr::V6(Ipv6Addr::from(u128::from(address) & ipv6_mask(prefix))),
    }
}

#[derive(Clone)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([redacted])")
    }
}

#[derive(Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub app_url: Url,
    pub rp_id: String,
    pub rp_name: String,
    pub db_url: String,
    pub otp_secret: [u8; 32],
    pub cookie_name: String,
    pub cookie_secure: bool,
    pub dev_mode: bool,
    pub admin_token: Option<String>,
    pub session_ttl_days: i64,
    pub session_idle_hours: i64,
    pub otp_ttl_minutes: i64,
    pub recovery_code_ttl_days: i64,
    pub email_provider: EmailProvider,
    pub smtp_host: Option<String>,
    pub smtp_port: u16,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<SecretString>,
    pub smtp_from: Option<String>,
    pub smtp_tls: SmtpTlsMode,
    pub trust_proxy: bool,
    pub trusted_proxy_cidrs: Vec<Cidr>,
}

fn env_trimmed(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_bool(name: &str, default: bool) -> Result<bool> {
    match env_trimmed(name) {
        Some(value) => value
            .parse::<bool>()
            .with_context(|| format!("{name} must be true or false")),
        None => Ok(default),
    }
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|address| address.is_loopback())
            .unwrap_or(false)
}

fn is_placeholder_secret(secret: &str) -> bool {
    let normalized = secret.trim().to_ascii_lowercase();
    normalized == "secret"
        || normalized == "password"
        || normalized == "changeme"
        || normalized == "change-me"
        || normalized.contains("change_me")
        || normalized.contains("dev-secret-change-me")
        || normalized == "change_me_generate_with_openssl_rand_hex_32"
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let bind_addr: SocketAddr = env::var("BIND_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
            .parse()
            .context("BIND_ADDR must be a valid socket address")?;

        let app_url = Url::parse(
            &env::var("APP_URL").unwrap_or_else(|_| "http://localhost:8080".to_string()),
        )
        .context("APP_URL must be a valid URL")?;

        let dev_mode = env_bool("DEV_MODE", false)?;
        let allow_insecure_dev_mode = env_bool("ALLOW_INSECURE_DEV_MODE", false)?;
        let allow_outbox_without_dev = env_bool("ALLOW_OUTBOX_WITHOUT_DEV", false)?;
        let allow_rp_id_parent = env_bool("ALLOW_RP_ID_PARENT", false)?;

        if dev_mode {
            let bind_loopback = bind_addr.ip().is_loopback();
            let url_loopback = app_url.host_str().map(is_loopback_host).unwrap_or(false);
            if !bind_loopback || !url_loopback {
                if !allow_insecure_dev_mode {
                    bail!(
                        "DEV_MODE=true requires loopback BIND_ADDR and APP_URL; got BIND_ADDR={bind_addr} and APP_URL={app_url}. Set ALLOW_INSECURE_DEV_MODE=true only for isolated development."
                    );
                }
                tracing::warn!(
                    bind_addr = %bind_addr,
                    app_url = %app_url,
                    "ALLOW_INSECURE_DEV_MODE=true is enabled with a non-loopback dev configuration; this is unsafe outside isolated development"
                );
            }
        }

        let otp_secret = match env_trimmed("OTP_SECRET") {
            Some(secret) => {
                if is_placeholder_secret(&secret) {
                    bail!("OTP_SECRET must not be a known placeholder value");
                }
                if secret.len() < 32 {
                    if dev_mode {
                        tracing::warn!(
                            "OTP_SECRET is shorter than 32 characters; this is only acceptable for local development"
                        );
                    } else {
                        bail!("OTP_SECRET must be at least 32 characters when DEV_MODE=false");
                    }
                }
                secret_key(&secret)
            }
            None => {
                if dev_mode {
                    tracing::warn!(
                        "OTP_SECRET is missing; using an ephemeral random secret. Pending OTPs and all unused recovery codes will be invalidated after restart."
                    );
                    random_key()
                } else {
                    bail!("OTP_SECRET is required when DEV_MODE=false");
                }
            }
        };

        let rp_id = env_trimmed("RP_ID")
            .unwrap_or_else(|| app_url.host_str().unwrap_or("localhost").to_string());
        if !dev_mode {
            let app_host = app_url.host_str().unwrap_or_default();
            if !rp_id.eq_ignore_ascii_case(app_host) {
                if !allow_rp_id_parent {
                    bail!(
                        "RP_ID must match the APP_URL host ({app_host}) when DEV_MODE=false; set ALLOW_RP_ID_PARENT=true to explicitly allow a parent/other RP ID"
                    );
                }
                tracing::warn!(
                    rp_id = %rp_id,
                    app_host = %app_host,
                    "ALLOW_RP_ID_PARENT=true permits a broader WebAuthn RP ID scope"
                );
            }
        }

        let rp_name = env::var("RP_NAME").unwrap_or_else(|_| "AuthLayer".to_string());

        let db_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "sqlite://authlayer.db?mode=rwc".to_string());

        let cookie_secure = env_bool("COOKIE_SECURE", app_url.scheme() == "https")?;
        let default_cookie_name = if cookie_secure {
            "__Host-al_session"
        } else {
            "al_session"
        };
        let cookie_name =
            env_trimmed("COOKIE_NAME").unwrap_or_else(|| default_cookie_name.to_string());
        if !dev_mode {
            if !cookie_secure {
                bail!("COOKIE_SECURE must be true when DEV_MODE=false");
            }
            if app_url.scheme() != "https" {
                bail!("APP_URL must use https when DEV_MODE=false");
            }
            if !cookie_name.starts_with("__Host-") {
                bail!(
                    "COOKIE_NAME must start with '__Host-' when DEV_MODE=false (for example '__Host-al_session')"
                );
            }
        } else if cookie_secure && app_url.scheme() != "https" {
            tracing::warn!(
                "COOKIE_SECURE=true with a non-HTTPS APP_URL in DEV_MODE; browsers may reject the session cookie"
            );
        }

        let admin_token = env::var("ADMIN_TOKEN")
            .ok()
            .filter(|v| !v.trim().is_empty());
        if let Some(token) = &admin_token {
            if token.len() < 32 {
                bail!("ADMIN_TOKEN must be at least 32 characters when set");
            }
            if is_placeholder_secret(token) {
                bail!("ADMIN_TOKEN must not be a known placeholder value");
            }
        }

        let session_ttl_days = positive_env("SESSION_TTL_DAYS", 7)?;
        let session_idle_hours = positive_env("SESSION_IDLE_HOURS", 24)?;
        let otp_ttl_minutes = positive_env("OTP_TTL_MINUTES", 10)?;
        let recovery_code_ttl_days = positive_env("RECOVERY_CODE_TTL_DAYS", 365)?;

        let email_provider = match env_trimmed("EMAIL_PROVIDER")
            .unwrap_or_else(|| "outbox".to_string())
            .to_ascii_lowercase()
            .as_str()
        {
            "outbox" => EmailProvider::Outbox,
            "smtp" => EmailProvider::Smtp,
            other => bail!("EMAIL_PROVIDER must be 'outbox' or 'smtp' (got {other:?})"),
        };

        if email_provider == EmailProvider::Outbox && !dev_mode && !allow_outbox_without_dev {
            bail!(
                "EMAIL_PROVIDER=outbox requires DEV_MODE=true because users cannot receive OTPs; set EMAIL_PROVIDER=smtp or ALLOW_OUTBOX_WITHOUT_DEV=true"
            );
        }
        if email_provider == EmailProvider::Outbox && !dev_mode {
            tracing::warn!(
                "ALLOW_OUTBOX_WITHOUT_DEV=true is enabled; OTPs will not be delivered to users"
            );
        }

        let (smtp_host, smtp_port, smtp_username, smtp_password, smtp_from, smtp_tls) =
            if email_provider == EmailProvider::Smtp {
                let smtp_host = env_trimmed("SMTP_HOST")
                    .context("SMTP_HOST is required when EMAIL_PROVIDER=smtp")?;
                let smtp_from = env_trimmed("SMTP_FROM")
                    .context("SMTP_FROM is required when EMAIL_PROVIDER=smtp")?;
                let smtp_port = match env_trimmed("SMTP_PORT") {
                    Some(value) => value
                        .parse::<u16>()
                        .context("SMTP_PORT must be a valid TCP port (1-65535)")?,
                    None => 587,
                };
                if smtp_port == 0 {
                    bail!("SMTP_PORT must be between 1 and 65535");
                }
                let smtp_tls = match env_trimmed("SMTP_TLS")
                    .unwrap_or_else(|| "required".to_string())
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "required" => SmtpTlsMode::Required,
                    "opportunistic" => SmtpTlsMode::Opportunistic,
                    "none" => SmtpTlsMode::None,
                    other => bail!(
                        "SMTP_TLS must be 'required', 'opportunistic', or 'none' (got {other:?})"
                    ),
                };
                if !dev_mode && smtp_tls == SmtpTlsMode::None {
                    bail!("SMTP_TLS=none is not allowed when DEV_MODE=false");
                }
                let smtp_username = env_trimmed("SMTP_USERNAME");
                let smtp_password = env::var("SMTP_PASSWORD")
                    .ok()
                    .filter(|value| !value.is_empty())
                    .map(SecretString::new);
                match (&smtp_username, &smtp_password) {
                    (Some(_), Some(_)) | (None, None) => {}
                    _ => bail!("SMTP_USERNAME and SMTP_PASSWORD must be set together"),
                }
                if smtp_tls == SmtpTlsMode::Opportunistic {
                    if !dev_mode || smtp_username.is_some() || smtp_password.is_some() {
                        bail!(
                            "SMTP_TLS=opportunistic is only allowed in DEV_MODE without SMTP credentials; use SMTP_TLS=required"
                        );
                    }
                    tracing::warn!(
                        "SMTP_TLS=opportunistic is enabled in DEV_MODE; this is not safe for production"
                    );
                }
                (
                    Some(smtp_host),
                    smtp_port,
                    smtp_username,
                    smtp_password,
                    Some(smtp_from),
                    smtp_tls,
                )
            } else {
                (None, 587, None, None, None, SmtpTlsMode::Required)
            };

        let trust_proxy = env_bool("TRUST_PROXY", false)?;
        let trusted_proxy_cidrs = if trust_proxy {
            let raw = env_trimmed("TRUSTED_PROXY_CIDRS").context(
                "TRUSTED_PROXY_CIDRS is required when TRUST_PROXY=true (comma-separated CIDRs)",
            )?;
            let mut cidrs = Vec::new();
            for item in raw.split(',') {
                let item = item.trim();
                if item.is_empty() {
                    continue;
                }
                cidrs.push(
                    Cidr::parse(item)
                        .with_context(|| format!("invalid TRUSTED_PROXY_CIDRS entry: {item:?}"))?,
                );
            }
            if cidrs.is_empty() {
                bail!("TRUSTED_PROXY_CIDRS must contain at least one CIDR when TRUST_PROXY=true");
            }
            cidrs
        } else {
            Vec::new()
        };

        Ok(Self {
            bind_addr,
            app_url,
            rp_id,
            rp_name,
            db_url,
            otp_secret,
            cookie_name,
            cookie_secure,
            dev_mode,
            admin_token,
            session_ttl_days,
            session_idle_hours,
            otp_ttl_minutes,
            recovery_code_ttl_days,
            email_provider,
            smtp_host,
            smtp_port,
            smtp_username,
            smtp_password,
            smtp_from,
            smtp_tls,
            trust_proxy,
            trusted_proxy_cidrs,
        })
    }

    pub fn is_trusted_proxy(&self, address: IpAddr) -> bool {
        self.trust_proxy
            && self
                .trusted_proxy_cidrs
                .iter()
                .any(|cidr| cidr.contains(address))
    }

    pub fn redacted_db_url(&self) -> String {
        redact_db_url(&self.db_url)
    }
}

fn redact_db_url(raw: &str) -> String {
    let without_query = raw.split('?').next().unwrap_or(raw);
    if let Some((scheme, rest)) = without_query.split_once("://") {
        let without_userinfo = match rest.rfind('@') {
            Some(index) => &rest[index + 1..],
            None => rest,
        };
        format!("{scheme}://{without_userinfo}")
    } else {
        without_query.to_string()
    }
}

fn positive_env(name: &str, default: i64) -> Result<i64> {
    let value = match env_trimmed(name) {
        Some(value) => value
            .parse::<i64>()
            .with_context(|| format!("{name} must be a positive integer"))?,
        None => default,
    };
    if value <= 0 {
        bail!("{name} must be a positive integer");
    }
    Ok(value)
}

fn secret_key(secret: &str) -> [u8; 32] {
    let digest = Sha256::digest(secret.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn random_key() -> [u8; 32] {
    let mut out = [0u8; 32];
    OsRng.fill_bytes(&mut out);
    out
}
