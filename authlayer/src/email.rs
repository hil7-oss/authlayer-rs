use std::time::Duration;

use anyhow::{Context, Result};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
    },
};

use crate::config::{Config, EmailProvider, SmtpTlsMode};

pub const EMAIL_SEND_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct SmtpSender {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

#[derive(Clone)]
pub enum EmailSender {
    Outbox,
    Smtp(Box<SmtpSender>),
}

impl EmailSender {
    pub fn from_config(config: &Config) -> Result<Self> {
        if config.email_provider == EmailProvider::Outbox {
            return Ok(Self::Outbox);
        }

        let host = config
            .smtp_host
            .clone()
            .context("SMTP_HOST is required when EMAIL_PROVIDER=smtp")?;
        let from_raw = config
            .smtp_from
            .clone()
            .context("SMTP_FROM is required when EMAIL_PROVIDER=smtp")?;
        let from: Mailbox = from_raw
            .parse()
            .with_context(|| format!("SMTP_FROM is not a valid mailbox: {from_raw:?}"))?;

        let tls = match config.smtp_tls {
            SmtpTlsMode::None => Tls::None,
            SmtpTlsMode::Opportunistic => Tls::Opportunistic(
                TlsParameters::new(host.clone())
                    .context("failed to initialize opportunistic SMTP TLS parameters")?,
            ),
            SmtpTlsMode::Required => {
                let parameters = TlsParameters::new(host.clone())
                    .context("failed to initialize required SMTP TLS parameters")?;
                if config.smtp_port == 465 {
                    Tls::Wrapper(parameters)
                } else {
                    Tls::Required(parameters)
                }
            }
        };

        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
            .port(config.smtp_port)
            .timeout(Some(EMAIL_SEND_TIMEOUT))
            .tls(tls);

        if let (Some(username), Some(password)) = (&config.smtp_username, &config.smtp_password) {
            if config.smtp_tls == SmtpTlsMode::None {
                tracing::warn!(
                    "SMTP_TLS=none is configured with SMTP credentials; credentials will be sent without TLS"
                );
            }
            builder = builder.credentials(Credentials::new(
                username.clone(),
                password.expose().to_string(),
            ));
        }

        Ok(Self::Smtp(Box::new(SmtpSender {
            transport: builder.build(),
            from,
        })))
    }

    pub fn provider_name(&self) -> &'static str {
        match self {
            Self::Outbox => "outbox",
            Self::Smtp(_) => "smtp",
        }
    }

    pub fn is_outbox(&self) -> bool {
        matches!(self, Self::Outbox)
    }

    pub async fn send(&self, to: &str, subject: &str, body: &str) -> Result<()> {
        match self {
            Self::Outbox => Ok(()),
            Self::Smtp(smtp) => {
                let recipient: Mailbox = to.parse().context("invalid recipient email address")?;
                let message = Message::builder()
                    .from(smtp.from.clone())
                    .to(recipient)
                    .subject(subject.to_string())
                    .header(ContentType::TEXT_PLAIN)
                    .body(body.to_string())
                    .context("failed to build email message")?;

                match tokio::time::timeout(EMAIL_SEND_TIMEOUT, smtp.transport.send(message)).await {
                    Ok(Ok(_)) => Ok(()),
                    Ok(Err(error)) => Err(anyhow::anyhow!("SMTP send failed: {error}")),
                    Err(_) => Err(anyhow::anyhow!(
                        "SMTP send timed out after {} seconds",
                        EMAIL_SEND_TIMEOUT.as_secs()
                    )),
                }
            }
        }
    }
}
