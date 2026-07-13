use crate::notifications::{EnqueueOutcome, NotificationOutbox, NotificationService};
use crate::security_events::SecurityEventService;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// Validates that the given string is a syntactically correct IPv4 or IPv6 address.
/// Rejects hostnames, CIDR ranges, and other arbitrary input.
pub fn validate_ip(ip: &str) -> Result<(), String> {
    if ip.is_empty() {
        return Err("IP address cannot be empty".to_string());
    }
    ip.parse::<IpAddr>()
        .map(|_| ())
        .map_err(|_| format!("Invalid IP address: '{}'", ip))
}

#[derive(Debug, Deserialize)]
pub struct SshLoginEvent {
    pub user: String,
    pub ip: String,
    pub timestamp: i64,
    pub method: String,
}

#[derive(Debug, Serialize)]
pub struct TrustedIp {
    pub id: i64,
    pub ip: String,
    pub description: Option<String>,
    pub added_at: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct SshLoginLog {
    pub id: i64,
    pub user: String,
    pub ip: String,
    pub timestamp: i64,
    pub method: String,
    pub notified: bool,
}

/// Сервис управления SSH-уведомлениями.
/// Обеспечивает обработку событий PAM, фильтрацию по белому списку и отправку оповещений.
pub struct SshAlertsService {
    db: SqlitePool,
    notifier: Arc<NotificationService>,
    security_events: Arc<SecurityEventService>,
    notification_outbox: Arc<NotificationOutbox>,
    retention_days: i64,
    internal_token: Mutex<String>,
}

impl SshAlertsService {
    pub fn new(
        db: SqlitePool,
        notifier: Arc<NotificationService>,
        security_events: Arc<SecurityEventService>,
        notification_outbox: Arc<NotificationOutbox>,
        retention_days: i64,
    ) -> Self {
        Self {
            db,
            notifier,
            security_events,
            notification_outbox,
            retention_days,
            internal_token: Mutex::new(String::new()),
        }
    }

    pub fn set_token(&self, token: String) {
        let mut t = self.internal_token.lock().unwrap();
        *t = token;
    }

    /// Обрабатывает событие успешного входа по SSH.
    /// Проверяет токен и baseline доверенных IP; durable outbox применяет cooldown.
    pub async fn handle_login(&self, mut event: SshLoginEvent, token: &str) -> Result<(), String> {
        {
            let t = self.internal_token.lock().unwrap();
            if t.is_empty() {
                return Err("Internal token not configured".to_string());
            }
            if !crate::auth::constant_time_eq(token, &t) {
                return Err("Invalid internal token".to_string());
            }
        }

        validate_login_event(&event)?;
        event.ip = normalize_ip(&event.ip)?;

        let is_trusted = match self.is_trusted_ip(&event.ip).await {
            Ok(is_trusted) => is_trusted,
            Err(_) => {
                tracing::warn!(
                    event_error = "database",
                    "Failed to check trusted SSH source IP baseline"
                );
                false
            }
        };

        if is_trusted {
            tracing::info!("Skipping notification for trusted IP: {}", event.ip);
            if self
                .security_events
                .resolve_ssh_source_ip_event(&event.ip)
                .await
                .is_err()
            {
                tracing::warn!(
                    event_error = "database",
                    "Failed to resolve SSH source IP security event"
                );
            }
            self.log_to_db(&event, false).await;
            return Ok(());
        }

        let date_str = DateTime::from_timestamp(event.timestamp, 0)
            .unwrap_or_default()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        let message = format!(
            "SSH Login Detected\n\nUser: {}\nIP: {}\nMethod: {}\nTime: {}",
            event.user, event.ip, event.method, date_str
        );
        let rendered = self.notifier.render_alert_text(&message);
        let notified = match self
            .security_events
            .raise_ssh_source_ip_event_with_notification(
                &event.user,
                &event.ip,
                &event.method,
                event.timestamp,
                &self.notification_outbox,
                &rendered,
            )
            .await
        {
            Ok(Some(EnqueueOutcome::Pending { .. })) => true,
            Ok(_) => false,
            Err(_) => {
                tracing::warn!(
                    event_error = "database",
                    "Failed to persist SSH source event and notification"
                );
                false
            }
        };
        self.log_to_db(&event, notified).await;

        Ok(())
    }

    async fn is_trusted_ip(&self, ip: &str) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM trusted_ips WHERE ip = ?")
            .bind(ip)
            .fetch_one(&self.db)
            .await?;

        Ok(count > 0)
    }

    async fn log_to_db(&self, event: &SshLoginEvent, notified: bool) {
        let _ = sqlx::query(
            "INSERT INTO ssh_logins (user, ip, timestamp, method, notified) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&event.user)
        .bind(&event.ip)
        .bind(event.timestamp)
        .bind(&event.method)
        .bind(notified)
        .execute(&self.db)
        .await
        .map_err(|_| tracing::error!(event_error = "database", "Failed to save SSH log"));

        match crate::retention::prune_ssh_logins(
            &self.db,
            Utc::now().timestamp(),
            self.retention_days,
        )
        .await
        {
            Ok(rows) if rows > 0 => tracing::info!("Pruned {} old SSH login rows", rows),
            Ok(_) => {}
            Err(_) => tracing::warn!(
                event_error = "database",
                "Failed to prune old SSH login rows"
            ),
        }
    }

    pub async fn get_logs(&self) -> Result<Vec<SshLoginLog>, sqlx::Error> {
        sqlx::query_as::<_, SshLoginLog>(
            "SELECT * FROM ssh_logins ORDER BY timestamp DESC LIMIT 100",
        )
        .fetch_all(&self.db)
        .await
    }

    pub async fn get_trusted_ips(&self) -> Result<Vec<TrustedIp>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, ip, description, added_at FROM trusted_ips ORDER BY added_at DESC",
        )
        .fetch_all(&self.db)
        .await?;

        let ips = rows
            .into_iter()
            .map(|row| {
                use sqlx::Row;
                TrustedIp {
                    id: row.get("id"),
                    ip: row.get("ip"),
                    description: row.get("description"),
                    added_at: row.get("added_at"),
                }
            })
            .collect();

        Ok(ips)
    }

    pub async fn add_trusted_ip(
        &self,
        ip: String,
        description: Option<String>,
    ) -> Result<(), sqlx::Error> {
        let ip = normalize_ip(&ip).map_err(sqlx::Error::Protocol)?;

        sqlx::query("INSERT INTO trusted_ips (ip, description, added_at) VALUES (?, ?, ?)")
            .bind(&ip)
            .bind(description)
            .bind(Utc::now().timestamp())
            .execute(&self.db)
            .await?;
        self.security_events
            .resolve_ssh_source_ip_event(&ip)
            .await?;
        Ok(())
    }

    pub async fn delete_trusted_ip(&self, id: i64) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM trusted_ips WHERE id = ?")
            .bind(id)
            .execute(&self.db)
            .await?;
        Ok(())
    }
}

fn validate_login_event(event: &SshLoginEvent) -> Result<(), String> {
    validate_ip(&event.ip)?;
    validate_bounded_field("user", &event.user, 64)?;
    validate_bounded_field("method", &event.method, 32)?;

    match event.method.as_str() {
        "ssh" | "password" | "publickey" | "keyboard-interactive" | "unknown" => {}
        _ => return Err(format!("Invalid SSH auth method: '{}'", event.method)),
    }

    let now = Utc::now().timestamp();
    if event.timestamp < 0 || event.timestamp > now + 300 {
        return Err("Invalid SSH login timestamp".to_string());
    }

    Ok(())
}

fn validate_bounded_field(name: &str, value: &str, max_len: usize) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{} cannot be empty", name));
    }
    if value.len() > max_len {
        return Err(format!("{} is too long", name));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(format!("{} contains control characters", name));
    }
    Ok(())
}

fn normalize_ip(ip: &str) -> Result<String, String> {
    ip.parse::<IpAddr>()
        .map(|ip| ip.to_string())
        .map_err(|_| format!("Invalid IP address: '{}'", ip))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn test_service_with_notifier(
        notifier: NotificationService,
    ) -> (SshAlertsService, Arc<SecurityEventService>) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory sqlite should connect");

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS ssh_logins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT NOT NULL,
                ip TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                method TEXT NOT NULL,
                notified BOOLEAN DEFAULT 0
            )",
        )
        .execute(&pool)
        .await
        .expect("ssh_logins schema should initialize");

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS trusted_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                description TEXT,
                added_at INTEGER NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .expect("trusted_ips schema should initialize");

        SecurityEventService::init_schema(&pool)
            .await
            .expect("security event schema should initialize");

        let events = Arc::new(SecurityEventService::new(pool.clone()));
        let notifier = Arc::new(notifier);
        let outbox = Arc::new(NotificationOutbox::new(pool.clone(), notifier.clone()));
        let service = SshAlertsService::new(pool, notifier, events.clone(), outbox, 90);
        service.set_token("test-token".to_string());

        (service, events)
    }

    async fn test_service() -> (SshAlertsService, Arc<SecurityEventService>) {
        test_service_with_notifier(NotificationService::with_test_endpoint(
            "123456:test",
            "http://127.0.0.1:9".to_string(),
        ))
        .await
    }

    #[test]
    fn test_validate_ip_valid_ipv4() {
        assert!(validate_ip("192.168.1.1").is_ok());
        assert!(validate_ip("10.0.0.1").is_ok());
        assert!(validate_ip("0.0.0.0").is_ok());
        assert!(validate_ip("255.255.255.255").is_ok());
    }

    #[test]
    fn test_validate_ip_valid_ipv6() {
        assert!(validate_ip("::1").is_ok());
        assert!(validate_ip("2001:db8::1").is_ok());
        assert!(validate_ip("fe80::1").is_ok());
    }

    #[test]
    fn test_validate_ip_rejects_hostname() {
        assert!(validate_ip("example.com").is_err());
        assert!(validate_ip("localhost").is_err());
    }

    #[test]
    fn test_validate_ip_rejects_cidr() {
        assert!(validate_ip("192.168.1.0/24").is_err());
        assert!(validate_ip("10.0.0.0/8").is_err());
    }

    #[test]
    fn test_validate_ip_rejects_empty() {
        assert!(validate_ip("").is_err());
    }

    #[test]
    fn test_validate_ip_rejects_malformed() {
        assert!(validate_ip("999.999.999.999").is_err());
        assert!(validate_ip("1.2.3").is_err());
        assert!(validate_ip("not_an_ip").is_err());
        assert!(validate_ip("192.168.1.1; rm -rf /").is_err());
    }

    #[test]
    fn test_validate_login_event_rejects_bad_method_and_future_time() {
        let event = SshLoginEvent {
            user: "root".to_string(),
            ip: "192.168.1.1".to_string(),
            timestamp: Utc::now().timestamp() + 600,
            method: "ssh".to_string(),
        };
        assert!(validate_login_event(&event).is_err());

        let event = SshLoginEvent {
            timestamp: Utc::now().timestamp(),
            method: "bad method".to_string(),
            ..event
        };
        assert!(validate_login_event(&event).is_err());
    }

    #[test]
    fn test_normalize_ip_normalizes_ipv6() {
        assert_eq!(normalize_ip("0:0:0:0:0:0:0:1").unwrap(), "::1");
    }

    #[tokio::test]
    async fn untrusted_login_creates_security_event() {
        let (service, events) = test_service().await;
        let event = SshLoginEvent {
            user: "root".to_string(),
            ip: "203.0.113.20".to_string(),
            timestamp: Utc::now().timestamp(),
            method: "publickey".to_string(),
        };

        service.handle_login(event, "test-token").await.unwrap();

        let logs = service.get_logs().await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].ip, "203.0.113.20");
        assert!(logs[0].notified);

        let active = events.list(Some("active"), 10).await.unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].event_key, "ssh:source_ip:203.0.113.20");
        assert_eq!(active[0].event_type, "ssh.untrusted_source_ip");
    }

    #[tokio::test]
    async fn disabled_delivery_is_recorded_as_not_notified() {
        let (service, events) =
            test_service_with_notifier(NotificationService::disabled_for_tests()).await;
        let event = SshLoginEvent {
            user: "root".to_string(),
            ip: "203.0.113.25".to_string(),
            timestamp: Utc::now().timestamp(),
            method: "publickey".to_string(),
        };

        service.handle_login(event, "test-token").await.unwrap();

        let logs = service.get_logs().await.unwrap();
        assert_eq!(logs.len(), 1);
        assert!(!logs[0].notified);
        assert_eq!(events.list(Some("active"), 10).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn trusted_login_does_not_create_active_security_event() {
        let (service, events) = test_service().await;
        service
            .add_trusted_ip("203.0.113.21".to_string(), Some("office".to_string()))
            .await
            .unwrap();
        let event = SshLoginEvent {
            user: "root".to_string(),
            ip: "203.0.113.21".to_string(),
            timestamp: Utc::now().timestamp(),
            method: "publickey".to_string(),
        };

        service.handle_login(event, "test-token").await.unwrap();

        let logs = service.get_logs().await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].ip, "203.0.113.21");
        assert!(!logs[0].notified);
        assert!(events.list(Some("active"), 10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn duplicate_untrusted_login_is_durably_suppressed_and_records_history() {
        let (service, events) = test_service().await;
        let first = SshLoginEvent {
            user: "root".to_string(),
            ip: "203.0.113.23".to_string(),
            timestamp: Utc::now().timestamp(),
            method: "publickey".to_string(),
        };
        let second = SshLoginEvent {
            user: "root".to_string(),
            ip: "203.0.113.23".to_string(),
            timestamp: Utc::now().timestamp(),
            method: "publickey".to_string(),
        };

        service.handle_login(first, "test-token").await.unwrap();
        service.handle_login(second, "test-token").await.unwrap();

        let logs = service.get_logs().await.unwrap();
        assert_eq!(logs.len(), 2);
        assert!(logs.iter().all(|log| log.ip == "203.0.113.23"));
        assert_eq!(logs.iter().filter(|log| log.notified).count(), 1);
        assert_eq!(logs.iter().filter(|log| !log.notified).count(), 1);

        let active = events.list(Some("active"), 10).await.unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].event_key, "ssh:source_ip:203.0.113.23");
    }

    #[tokio::test]
    async fn repeated_trusted_login_still_records_history_without_notification() {
        let (service, _events) = test_service().await;
        service
            .add_trusted_ip("203.0.113.24".to_string(), Some("office".to_string()))
            .await
            .unwrap();
        let first = SshLoginEvent {
            user: "root".to_string(),
            ip: "203.0.113.24".to_string(),
            timestamp: Utc::now().timestamp(),
            method: "publickey".to_string(),
        };
        let second = SshLoginEvent {
            user: "root".to_string(),
            ip: "203.0.113.24".to_string(),
            timestamp: Utc::now().timestamp(),
            method: "publickey".to_string(),
        };

        service.handle_login(first, "test-token").await.unwrap();
        service.handle_login(second, "test-token").await.unwrap();

        let logs = service.get_logs().await.unwrap();
        assert_eq!(logs.len(), 2);
        assert!(logs.iter().all(|log| log.ip == "203.0.113.24"));
        assert!(logs.iter().all(|log| !log.notified));
    }

    #[tokio::test]
    async fn adding_trusted_ip_resolves_existing_source_event() {
        let (service, events) = test_service().await;
        events
            .raise_ssh_source_ip_event("root", "203.0.113.22", "publickey", Utc::now().timestamp())
            .await
            .unwrap();

        service
            .add_trusted_ip("203.0.113.22".to_string(), Some("office".to_string()))
            .await
            .unwrap();

        assert!(events.list(Some("active"), 10).await.unwrap().is_empty());
        let resolved = events.list(Some("resolved"), 10).await.unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].event_key, "ssh:source_ip:203.0.113.22");
    }
}
