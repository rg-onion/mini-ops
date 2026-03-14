use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{Instant, Duration};
use std::net::IpAddr;
use crate::notifications::NotificationService;
use chrono::{DateTime, Utc};

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
    internal_token: Mutex<String>,
    // IP -> last_alert_time
    rate_limiter: Mutex<HashMap<String, Instant>>, 
}

impl SshAlertsService {
    pub fn new(db: SqlitePool, notifier: Arc<NotificationService>) -> Self {
        Self {
            db,
            notifier,
            internal_token: Mutex::new(String::new()),
            rate_limiter: Mutex::new(HashMap::new()),
        }
    }

    pub fn set_token(&self, token: String) {
        let mut t = self.internal_token.lock().unwrap();
        *t = token;
    }

    /// Обрабатывает событие успешного входа по SSH.
    /// Проверяет токен, применяет rate limiting и проверяет белый список перед отправкой уведомления.
    pub async fn handle_login(&self, event: SshLoginEvent, token: &str) -> Result<(), String> {
        {
            let t = self.internal_token.lock().unwrap();
            if t.is_empty() {
                return Err("Internal token not configured".to_string());
            }
            if token != *t {
                return Err("Invalid internal token".to_string());
            }
        }

        // Validate IP address format to prevent storage of arbitrary values
        validate_ip(&event.ip)?;

        // Rate limiting (10s per IP)
        {
            let mut limiter = self.rate_limiter.lock().unwrap();
            if let Some(last) = limiter.get(&event.ip) {
                if last.elapsed() < Duration::from_secs(10) {
                     tracing::info!("Rate limiting SSH alert for IP: {}", event.ip);
                     return Ok(()); // Silently skip
                }
            }
            limiter.insert(event.ip.clone(), Instant::now());
        }
    
        // Check whitelist
        // We use a simplified query here.
        // Note: 'trusted_ips' table MUST expect IP string.
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM trusted_ips WHERE ip = ?")
            .bind(&event.ip)
            .fetch_one(&self.db)
            .await
            .unwrap_or(0);

        if count > 0 {
             tracing::info!("Skipping notification for trusted IP: {}", event.ip);
             self.log_to_db(&event, false).await;
             return Ok(());
        }

        // Save to DB
        self.log_to_db(&event, true).await;

        // Send Notification
        let date_str = DateTime::from_timestamp(event.timestamp, 0)
            .unwrap_or_default()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();

         let msg_tg = format!(
            "🔐 *SSH Login Detected*\n\n*User:* `{}`\n*IP:* `{}`\n*Method:* `{}`\n*Time:* `{}`",
            event.user, event.ip, event.method, date_str
        );

        self.notifier.send_alert(&msg_tg).await;
        
        Ok(())
    }

    async fn log_to_db(&self, event: &SshLoginEvent, notified: bool) {
        let _ = sqlx::query(
            "INSERT INTO ssh_logins (user, ip, timestamp, method, notified) VALUES (?, ?, ?, ?, ?)"
        )
        .bind(&event.user)
        .bind(&event.ip)
        .bind(event.timestamp)
        .bind(&event.method)
        .bind(notified)
        .execute(&self.db)
        .await
        .map_err(|e| tracing::error!("Failed to save SSH log: {}", e));
    }

    pub async fn get_logs(&self) -> Result<Vec<SshLoginLog>, sqlx::Error> {
        sqlx::query_as::<_, SshLoginLog>("SELECT * FROM ssh_logins ORDER BY timestamp DESC LIMIT 100")
            .fetch_all(&self.db)
            .await
    }

    pub async fn get_trusted_ips(&self) -> Result<Vec<TrustedIp>, sqlx::Error> {
        let rows = sqlx::query("SELECT id, ip, description, added_at FROM trusted_ips ORDER BY added_at DESC")
            .fetch_all(&self.db)
            .await?;
        
        let ips = rows.into_iter().map(|row| {
            use sqlx::Row;
            TrustedIp {
                id: row.get("id"),
                ip: row.get("ip"),
                description: row.get("description"),
                added_at: row.get("added_at"),
            }
        }).collect();
        
        Ok(ips)
    }

    pub async fn add_trusted_ip(&self, ip: String, description: Option<String>) -> Result<(), sqlx::Error> {
        // Validate IP before storing
        validate_ip(&ip).map_err(|e| sqlx::Error::Protocol(e))?;

        sqlx::query("INSERT INTO trusted_ips (ip, description, added_at) VALUES (?, ?, ?)")
            .bind(ip)
            .bind(description)
            .bind(Utc::now().timestamp())
            .execute(&self.db)
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
