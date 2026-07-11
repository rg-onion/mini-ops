mod outbox;

pub(crate) use outbox::{EnqueueOutcome, NotificationEvent, NotificationOutbox};

use reqwest::{Client, StatusCode, redirect::Policy};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::Mutex as AsyncMutex;

const TELEGRAM_ORIGIN: &str = "https://api.telegram.org";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const PROVIDER_CALL_INTERVAL: Duration = Duration::from_secs(3);
const MAX_RESPONSE_BYTES: usize = 4 * 1024;
const MAX_REQUEST_BYTES: usize = 4 * 1024;
const MAX_IN_MEMORY_DEDUP_KEYS: usize = 1024;
const MAX_IN_MEMORY_COOLDOWN: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryErrorCode {
    // reqwest does not expose a portable DNS error discriminator. The closed
    // code remains reserved for resolvers that can prove this classification.
    #[allow(dead_code)]
    Dns,
    ConnectTimeout,
    RequestTimeout,
    Transport,
    #[serde(rename = "http_4xx")]
    Http4xx,
    #[serde(rename = "http_5xx")]
    Http5xx,
    ResponseTooLarge,
    InvalidResponse,
    ProviderRejected,
    LeaseExpired,
    RetentionExpired,
}

impl DeliveryErrorCode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::ConnectTimeout => "connect_timeout",
            Self::RequestTimeout => "request_timeout",
            Self::Transport => "transport",
            Self::Http4xx => "http_4xx",
            Self::Http5xx => "http_5xx",
            Self::ResponseTooLarge => "response_too_large",
            Self::InvalidResponse => "invalid_response",
            Self::ProviderRejected => "provider_rejected",
            Self::LeaseExpired => "lease_expired",
            Self::RetentionExpired => "retention_expired",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum NotificationOutcome {
    Sent,
    Disabled,
    Suppressed,
    Failed {
        code: DeliveryErrorCode,
        retry_scheduled: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DeliveryFailure {
    pub(crate) code: DeliveryErrorCode,
    pub(crate) retryable: bool,
    pub(crate) http_status: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderAttempt {
    Sent,
    Disabled,
    Failed(DeliveryFailure),
}

#[derive(Serialize)]
struct TelegramMessage<'a> {
    chat_id: &'a str,
    text: &'a str,
}

#[derive(Deserialize)]
struct TelegramResponse {
    ok: bool,
}

struct NotificationConfig {
    token: Option<String>,
    chat_id: Option<String>,
    server_name: String,
}

enum ClientState {
    Ready(Client),
    Unavailable,
}

pub struct NotificationService {
    client: ClientState,
    token: Option<String>,
    chat_id: Option<String>,
    server_name: String,
    endpoint_origin: String,
    provider_call_interval: Duration,
    last_provider_call: AsyncMutex<Option<Instant>>,
    semantic_guard: AsyncMutex<()>,
    alert_history: Mutex<HashMap<String, Instant>>,
}

impl NotificationService {
    pub fn new() -> Self {
        let config = NotificationConfig::from_env();
        Self::from_config(
            config,
            TELEGRAM_ORIGIN.to_string(),
            PROVIDER_CALL_INTERVAL,
            CONNECT_TIMEOUT,
            REQUEST_TIMEOUT,
        )
    }

    #[cfg(test)]
    pub fn disabled_for_tests() -> Self {
        Self::from_config(
            NotificationConfig {
                token: None,
                chat_id: None,
                server_name: "test".to_string(),
            },
            "http://127.0.0.1".to_string(),
            Duration::ZERO,
            CONNECT_TIMEOUT,
            REQUEST_TIMEOUT,
        )
    }

    #[cfg(test)]
    pub(crate) fn with_test_endpoint(token: &str, endpoint_origin: String) -> Self {
        Self::from_config(
            NotificationConfig {
                token: non_blank(token),
                chat_id: Some("123456".to_string()),
                server_name: "test-host".to_string(),
            },
            endpoint_origin,
            Duration::ZERO,
            CONNECT_TIMEOUT,
            REQUEST_TIMEOUT,
        )
    }

    #[cfg(test)]
    fn with_test_request_timeout(
        token: &str,
        endpoint_origin: String,
        request_timeout: Duration,
    ) -> Self {
        Self::from_config(
            NotificationConfig {
                token: non_blank(token),
                chat_id: Some("123456".to_string()),
                server_name: "test-host".to_string(),
            },
            endpoint_origin,
            Duration::ZERO,
            CONNECT_TIMEOUT,
            request_timeout,
        )
    }

    fn from_config(
        config: NotificationConfig,
        endpoint_origin: String,
        provider_call_interval: Duration,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Self {
        let client = match Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(request_timeout)
            .redirect(Policy::none())
            .build()
        {
            Ok(client) => ClientState::Ready(client),
            Err(_) => ClientState::Unavailable,
        };

        Self {
            client,
            token: config.token,
            chat_id: config.chat_id,
            server_name: config.server_name,
            endpoint_origin: endpoint_origin.trim_end_matches('/').to_string(),
            provider_call_interval,
            last_provider_call: AsyncMutex::new(None),
            semantic_guard: AsyncMutex::new(()),
            alert_history: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.token.is_some() && self.chat_id.is_some()
    }

    pub(crate) fn payload_contains_credentials(&self, text: &str) -> bool {
        self.token
            .as_ref()
            .is_some_and(|token| text.contains(token))
            || self
                .chat_id
                .as_ref()
                .is_some_and(|chat_id| text.contains(chat_id))
    }

    pub fn render_alert_text(&self, message: &str) -> String {
        format!("🚨 Mini-Ops Alert [{}] 🚨\n\n{}", self.server_name, message)
    }

    pub async fn send_alert(&self, message: &str) -> NotificationOutcome {
        let dedup_key = format!("immediate:{}", uuid::Uuid::new_v4().simple());
        self.send_semantic_alert(&dedup_key, message, Duration::ZERO)
            .await
    }

    pub async fn send_semantic_alert(
        &self,
        dedup_key: &str,
        message: &str,
        cooldown: Duration,
    ) -> NotificationOutcome {
        if !valid_key(dedup_key) {
            return NotificationOutcome::Failed {
                code: DeliveryErrorCode::InvalidResponse,
                retry_scheduled: false,
            };
        }
        if !self.is_enabled() {
            return NotificationOutcome::Disabled;
        }

        let Ok(_semantic_guard) = self.semantic_guard.try_lock() else {
            return NotificationOutcome::Suppressed;
        };
        let now = Instant::now();
        if self.is_suppressed(dedup_key, now) {
            return NotificationOutcome::Suppressed;
        }

        let text = self.render_alert_text(message);
        let attempt = self.deliver_rendered_text(&text).await;
        if attempt == ProviderAttempt::Sent {
            let delivered_at = Instant::now();
            self.record_suppression(
                dedup_key,
                delivered_at
                    .checked_add(cooldown.min(MAX_IN_MEMORY_COOLDOWN))
                    .unwrap_or(delivered_at),
            );
        }
        self.attempt_to_outcome(attempt, false)
    }

    pub(crate) async fn deliver_rendered_text(&self, text: &str) -> ProviderAttempt {
        let (token, chat_id) = match (&self.token, &self.chat_id) {
            (Some(token), Some(chat_id)) => (token, chat_id),
            _ => return ProviderAttempt::Disabled,
        };
        let client = match &self.client {
            ClientState::Ready(client) => client,
            ClientState::Unavailable => {
                return ProviderAttempt::Failed(DeliveryFailure {
                    code: DeliveryErrorCode::Transport,
                    retryable: true,
                    http_status: None,
                });
            }
        };

        if !valid_token(token) || chat_id.len() > 256 || chat_id.chars().any(char::is_control) {
            return ProviderAttempt::Failed(DeliveryFailure {
                code: DeliveryErrorCode::ProviderRejected,
                retryable: false,
                http_status: None,
            });
        }

        let payload = TelegramMessage { chat_id, text };
        let request_body = match serde_json::to_vec(&payload) {
            Ok(body) if body.len() <= MAX_REQUEST_BYTES => body,
            _ => {
                return ProviderAttempt::Failed(DeliveryFailure {
                    code: DeliveryErrorCode::InvalidResponse,
                    retryable: false,
                    http_status: None,
                });
            }
        };

        let mut last_provider_call = self.last_provider_call.lock().await;
        if let Some(last_call) = *last_provider_call {
            let wait = self
                .provider_call_interval
                .saturating_sub(last_call.elapsed());
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
        }
        *last_provider_call = Some(Instant::now());

        let url = format!("{}/bot{}/sendMessage", self.endpoint_origin, token);
        let response = match client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(request_body)
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                let failure = classify_transport_error(&error);
                log_delivery_failure(failure);
                return ProviderAttempt::Failed(failure);
            }
        };

        let status = response.status();
        let body = match read_bounded_body(response).await {
            Ok(body) => body,
            Err(mut failure) => {
                failure.http_status = Some(status.as_u16());
                failure.retryable = if status.is_success() {
                    failure.retryable
                } else {
                    retryable_status(status)
                };
                log_delivery_failure(failure);
                return ProviderAttempt::Failed(failure);
            }
        };

        let attempt = classify_provider_response(status, &body);
        if let ProviderAttempt::Failed(failure) = attempt {
            log_delivery_failure(failure);
        }
        attempt
    }

    fn attempt_to_outcome(
        &self,
        attempt: ProviderAttempt,
        retry_scheduled: bool,
    ) -> NotificationOutcome {
        match attempt {
            ProviderAttempt::Sent => NotificationOutcome::Sent,
            ProviderAttempt::Disabled => NotificationOutcome::Disabled,
            ProviderAttempt::Failed(failure) => NotificationOutcome::Failed {
                code: failure.code,
                retry_scheduled,
            },
        }
    }

    fn is_suppressed(&self, key: &str, now: Instant) -> bool {
        let mut history = self
            .alert_history
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        history.retain(|_, until| *until > now);
        history.get(key).is_some_and(|until| *until > now)
    }

    fn record_suppression(&self, key: &str, until: Instant) {
        let mut history = self
            .alert_history
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        history.retain(|_, existing_until| *existing_until > now);
        if history.len() >= MAX_IN_MEMORY_DEDUP_KEYS
            && !history.contains_key(key)
            && let Some(oldest_key) = history
                .iter()
                .min_by_key(|(_, existing_until)| **existing_until)
                .map(|(key, _)| key.clone())
        {
            history.remove(&oldest_key);
        }
        history.insert(key.to_string(), until);
    }
}

impl Default for NotificationService {
    fn default() -> Self {
        Self::new()
    }
}

impl NotificationConfig {
    fn from_env() -> Self {
        let token = std::env::var("TELEGRAM_BOT_TOKEN")
            .ok()
            .and_then(|value| non_blank(&value));
        let chat_id = std::env::var("TELEGRAM_CHAT_ID")
            .ok()
            .and_then(|value| non_blank(&value));
        let configured_server_name = std::env::var("SERVER_NAME").ok();

        Self {
            token,
            chat_id,
            server_name: resolve_server_name(configured_server_name.as_deref()),
        }
    }
}

fn non_blank(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn resolve_server_name(configured: Option<&str>) -> String {
    configured
        .and_then(non_blank)
        .or_else(|| {
            hostname::get()
                .ok()
                .and_then(|hostname| non_blank(&hostname.to_string_lossy()))
        })
        .unwrap_or_else(|| "Unknown Server".to_string())
}

fn valid_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 255 && !key.chars().any(char::is_control)
}

fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 256
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':' | b'-'))
}

fn classify_transport_error(error: &reqwest::Error) -> DeliveryFailure {
    let code = if error.is_timeout() && error.is_connect() {
        DeliveryErrorCode::ConnectTimeout
    } else if error.is_timeout() {
        DeliveryErrorCode::RequestTimeout
    } else {
        DeliveryErrorCode::Transport
    };
    DeliveryFailure {
        code,
        retryable: true,
        http_status: None,
    }
}

async fn read_bounded_body(mut response: reqwest::Response) -> Result<Vec<u8>, DeliveryFailure> {
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if body.len().saturating_add(chunk.len()) <= MAX_RESPONSE_BYTES => {
                body.extend_from_slice(&chunk);
            }
            Ok(Some(_)) => {
                return Err(DeliveryFailure {
                    code: DeliveryErrorCode::ResponseTooLarge,
                    retryable: false,
                    http_status: None,
                });
            }
            Ok(None) => return Ok(body),
            Err(error) => return Err(classify_transport_error(&error)),
        }
    }
}

fn classify_provider_response(status: StatusCode, body: &[u8]) -> ProviderAttempt {
    if !status.is_success() {
        let retryable = retryable_status(status);
        let code = if status.is_server_error() {
            DeliveryErrorCode::Http5xx
        } else if status.is_client_error() {
            DeliveryErrorCode::Http4xx
        } else {
            DeliveryErrorCode::InvalidResponse
        };
        return ProviderAttempt::Failed(DeliveryFailure {
            code,
            retryable,
            http_status: Some(status.as_u16()),
        });
    }

    match serde_json::from_slice::<TelegramResponse>(body) {
        Ok(response) if response.ok => ProviderAttempt::Sent,
        Ok(_) => ProviderAttempt::Failed(DeliveryFailure {
            code: DeliveryErrorCode::ProviderRejected,
            retryable: false,
            http_status: Some(status.as_u16()),
        }),
        Err(_) => ProviderAttempt::Failed(DeliveryFailure {
            code: DeliveryErrorCode::InvalidResponse,
            retryable: false,
            http_status: Some(status.as_u16()),
        }),
    }
}

fn retryable_status(status: StatusCode) -> bool {
    matches!(status.as_u16(), 408 | 425 | 429) || status.is_server_error()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeliveryLogFields {
    delivery_error: &'static str,
    retryable: bool,
    http_status: Option<u16>,
}

fn delivery_log_fields(failure: DeliveryFailure) -> DeliveryLogFields {
    DeliveryLogFields {
        delivery_error: failure.code.as_str(),
        retryable: failure.retryable,
        http_status: failure.http_status,
    }
}

fn log_delivery_failure(failure: DeliveryFailure) {
    let fields = delivery_log_fields(failure);
    tracing::warn!(
        delivery_error = fields.delivery_error,
        retryable = fields.retryable,
        http_status = fields.http_status,
        "Telegram notification delivery failed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct MockReply {
        status: u16,
        body: Vec<u8>,
        delay: Duration,
    }

    async fn spawn_mock_server(
        replies: Vec<MockReply>,
    ) -> (
        String,
        Arc<Mutex<Vec<Vec<u8>>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock listener should bind");
        let origin = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("mock listener should have address")
        );
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured_requests = Arc::clone(&requests);
        let handle = tokio::spawn(async move {
            for reply in replies {
                let (mut stream, _) = listener.accept().await.expect("mock should accept request");
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                let header_end = loop {
                    let read = stream
                        .read(&mut buffer)
                        .await
                        .expect("mock should read request");
                    if read == 0 {
                        break request.len();
                    }
                    request.extend_from_slice(&buffer[..read]);
                    if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n")
                    {
                        break index + 4;
                    }
                    assert!(
                        request.len() <= 16 * 1024,
                        "request headers must be bounded"
                    );
                };
                let header = String::from_utf8_lossy(&request[..header_end]);
                let content_length = header
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                    })
                    .unwrap_or(0);
                while request.len().saturating_sub(header_end) < content_length {
                    let read = stream
                        .read(&mut buffer)
                        .await
                        .expect("mock should read request body");
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    assert!(request.len() <= 20 * 1024, "request must be bounded");
                }
                captured_requests
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(request);
                if !reply.delay.is_zero() {
                    tokio::time::sleep(reply.delay).await;
                }
                let reason = if reply.status == 200 {
                    "OK"
                } else {
                    "Mock Failure"
                };
                let response = format!(
                    "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.status,
                    reason,
                    reply.body.len()
                );
                if stream.write_all(response.as_bytes()).await.is_ok() {
                    let _ = stream.write_all(&reply.body).await;
                }
            }
        });
        (origin, requests, handle)
    }

    async fn spawn_truncated_body_server(status: u16) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock listener should bind");
        let origin = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("mock listener should have address")
        );
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("mock should accept request");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).await.expect("mock should read");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
                assert!(request.len() <= 16 * 1024);
            }
            let response = format!(
                "HTTP/1.1 {status} Mock\r\nContent-Type: application/json\r\nContent-Length: 64\r\nConnection: close\r\n\r\n{{"
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("mock should write truncated response");
        });
        (origin, handle)
    }

    #[test]
    fn blank_credentials_are_disabled_and_blank_server_uses_fallback() {
        assert_eq!(non_blank(" \t\n"), None);
        assert!(!resolve_server_name(Some("   ")).trim().is_empty());

        let service = NotificationService::disabled_for_tests();
        assert!(!service.is_enabled());
        assert!(service.render_alert_text("test").contains("[test]"));
    }

    #[test]
    fn provider_response_requires_success_status_and_ok_true() {
        assert_eq!(
            classify_provider_response(StatusCode::OK, br#"{"ok":true}"#),
            ProviderAttempt::Sent
        );
        assert!(matches!(
            classify_provider_response(StatusCode::OK, br#"{"ok":false}"#),
            ProviderAttempt::Failed(DeliveryFailure {
                code: DeliveryErrorCode::ProviderRejected,
                retryable: false,
                ..
            })
        ));
        assert!(matches!(
            classify_provider_response(StatusCode::INTERNAL_SERVER_ERROR, b"sentinel-body"),
            ProviderAttempt::Failed(DeliveryFailure {
                code: DeliveryErrorCode::Http5xx,
                retryable: true,
                ..
            })
        ));
    }

    #[test]
    fn notification_outcome_serialization_exposes_only_closed_typed_fields() {
        assert_eq!(
            serde_json::to_value(NotificationOutcome::Sent).unwrap(),
            serde_json::json!({"status": "sent"})
        );
        assert_eq!(
            serde_json::to_value(NotificationOutcome::Failed {
                code: DeliveryErrorCode::Http4xx,
                retry_scheduled: false,
            })
            .unwrap(),
            serde_json::json!({
                "status": "failed",
                "code": "http_4xx",
                "retry_scheduled": false,
            })
        );
    }

    #[tokio::test]
    async fn disabled_attempt_is_typed_and_does_not_record_suppression() {
        let service = NotificationService::disabled_for_tests();
        assert_eq!(
            service
                .send_semantic_alert(
                    "metric:cpu:critical",
                    "secret-message",
                    Duration::from_secs(30)
                )
                .await,
            NotificationOutcome::Disabled
        );
        assert!(service.alert_history.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn mock_endpoint_truth_is_typed_and_failure_log_fields_are_closed() {
        let token = "123456:SENTINEL_TOKEN";
        let response_sentinel = "SENTINEL_PROVIDER_DESCRIPTION";
        let message_sentinel = "SENTINEL_ALERT_TEXT";
        let (origin, requests, server) = spawn_mock_server(vec![
            MockReply {
                status: 500,
                body: format!(r#"{{"ok":false,"description":"{response_sentinel}"}}"#).into_bytes(),
                delay: Duration::ZERO,
            },
            MockReply {
                status: 200,
                body: br#"{"ok":true}"#.to_vec(),
                delay: Duration::ZERO,
            },
        ])
        .await;
        let service = NotificationService::with_test_endpoint(token, origin);

        let failed = service.send_alert(message_sentinel).await;
        assert_eq!(
            failed,
            NotificationOutcome::Failed {
                code: DeliveryErrorCode::Http5xx,
                retry_scheduled: false,
            }
        );
        assert_eq!(
            service.send_alert("second attempt").await,
            NotificationOutcome::Sent
        );
        server.await.unwrap();

        let fields = delivery_log_fields(DeliveryFailure {
            code: DeliveryErrorCode::Http5xx,
            retryable: true,
            http_status: Some(500),
        });
        assert_eq!(fields.delivery_error, "http_5xx");
        assert!(fields.retryable);
        assert_eq!(fields.http_status, Some(500));
        let log_fields = format!("{fields:?}");
        assert!(!log_fields.contains(token));
        assert!(!log_fields.contains(response_sentinel));
        assert!(!log_fields.contains(message_sentinel));

        let requests = requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(requests.len(), 2);
        let first_request = String::from_utf8_lossy(&requests[0]);
        assert!(first_request.contains("/bot123456:SENTINEL_TOKEN/sendMessage"));
        assert!(!first_request.contains("parse_mode"));
    }

    #[tokio::test]
    async fn semantic_dedup_is_recorded_only_after_provider_success() {
        let (origin, requests, server) = spawn_mock_server(vec![
            MockReply {
                status: 500,
                body: br#"{"ok":false}"#.to_vec(),
                delay: Duration::ZERO,
            },
            MockReply {
                status: 200,
                body: br#"{"ok":true}"#.to_vec(),
                delay: Duration::ZERO,
            },
        ])
        .await;
        let service = NotificationService::with_test_endpoint("123456:test", origin);
        let key = "metric:cpu:critical";
        assert!(matches!(
            service
                .send_semantic_alert(key, "cpu=99.1", Duration::from_secs(1800))
                .await,
            NotificationOutcome::Failed { .. }
        ));
        assert_eq!(
            service
                .send_semantic_alert(key, "cpu=99.2", Duration::from_secs(1800))
                .await,
            NotificationOutcome::Sent
        );
        assert_eq!(
            service
                .send_semantic_alert(key, "cpu=99.3", Duration::from_secs(1800))
                .await,
            NotificationOutcome::Suppressed
        );
        server.await.unwrap();
        assert_eq!(
            requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn concurrent_semantic_alerts_make_one_provider_call() {
        let (origin, requests, server) = spawn_mock_server(vec![MockReply {
            status: 200,
            body: br#"{"ok":true}"#.to_vec(),
            delay: Duration::from_millis(25),
        }])
        .await;
        let service = Arc::new(NotificationService::with_test_endpoint(
            "123456:test",
            origin,
        ));
        let first_service = Arc::clone(&service);
        let second_service = Arc::clone(&service);
        let (first, second) = tokio::join!(
            async move {
                first_service
                    .send_semantic_alert(
                        "metric:cpu:critical",
                        "cpu=99.1",
                        Duration::from_secs(1800),
                    )
                    .await
            },
            async move {
                second_service
                    .send_semantic_alert(
                        "metric:cpu:critical",
                        "cpu=99.2",
                        Duration::from_secs(1800),
                    )
                    .await
            }
        );
        assert!(matches!(
            (first, second),
            (NotificationOutcome::Sent, NotificationOutcome::Suppressed)
                | (NotificationOutcome::Suppressed, NotificationOutcome::Sent)
        ));
        server.await.unwrap();
        assert_eq!(
            requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn concurrent_unique_immediate_alerts_do_not_queue_provider_attempts() {
        let (origin, requests, server) = spawn_mock_server(vec![MockReply {
            status: 200,
            body: br#"{"ok":true}"#.to_vec(),
            delay: Duration::from_millis(25),
        }])
        .await;
        let service = Arc::new(NotificationService::with_test_endpoint(
            "123456:test",
            origin,
        ));
        let first_service = Arc::clone(&service);
        let second_service = Arc::clone(&service);
        let (first, second) = tokio::join!(
            async move { first_service.send_alert("first unique attempt").await },
            async move { second_service.send_alert("second unique attempt").await }
        );
        assert!(matches!(
            (first, second),
            (NotificationOutcome::Sent, NotificationOutcome::Suppressed)
                | (NotificationOutcome::Suppressed, NotificationOutcome::Sent)
        ));
        server.await.unwrap();
        assert_eq!(
            requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn total_request_timeout_is_typed_without_raw_error() {
        let (origin, _, server) = spawn_mock_server(vec![MockReply {
            status: 200,
            body: br#"{"ok":true}"#.to_vec(),
            delay: Duration::from_millis(200),
        }])
        .await;
        let service = NotificationService::with_test_request_timeout(
            "123456:test",
            origin,
            Duration::from_millis(50),
        );
        assert_eq!(
            service.send_alert("timeout test").await,
            NotificationOutcome::Failed {
                code: DeliveryErrorCode::RequestTimeout,
                retry_scheduled: false,
            }
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_provider_response_is_not_success() {
        let (origin, _, server) = spawn_mock_server(vec![MockReply {
            status: 200,
            body: vec![b'x'; MAX_RESPONSE_BYTES + 1],
            delay: Duration::ZERO,
        }])
        .await;
        let service = NotificationService::with_test_endpoint("123456:test", origin);
        let rendered = service.render_alert_text("oversized response");
        assert_eq!(
            service.deliver_rendered_text(&rendered).await,
            ProviderAttempt::Failed(DeliveryFailure {
                code: DeliveryErrorCode::ResponseTooLarge,
                retryable: false,
                http_status: Some(200),
            })
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn permanent_http_status_stays_non_retryable_when_response_body_is_truncated() {
        let (origin, server) = spawn_truncated_body_server(400).await;
        let service = NotificationService::with_test_endpoint("123456:test", origin);
        let rendered = service.render_alert_text("truncated response");
        assert_eq!(
            service.deliver_rendered_text(&rendered).await,
            ProviderAttempt::Failed(DeliveryFailure {
                code: DeliveryErrorCode::Transport,
                retryable: false,
                http_status: Some(400),
            })
        );
        server.await.unwrap();
    }
}
