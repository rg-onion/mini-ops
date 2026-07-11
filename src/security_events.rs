use chrono::Utc;
use serde::Serialize;
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::notifications::{EnqueueOutcome, NotificationEvent, NotificationOutbox};
use crate::security::SecurityCheck;

const DEFAULT_SECURITY_EVENTS_RETENTION_HOURS: i64 = 168;
const MAX_SECURITY_EVENTS_RETENTION_HOURS: i64 = 24 * 365 * 5;

#[derive(Debug, Clone, Serialize)]
pub struct SecurityEvent {
    pub id: i64,
    pub event_key: String,
    pub event_type: String,
    pub severity: String,
    pub title: String,
    pub message: String,
    pub evidence_json: String,
    pub status: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub acknowledged_at: Option<i64>,
    pub resolved_at: Option<i64>,
    pub notification_delivery_status: Option<String>,
    pub notification_delivery_attempts: Option<i64>,
    pub notification_delivery_updated_at: Option<i64>,
    pub notification_delivery_error_code: Option<String>,
}

#[derive(Clone)]
pub struct SecurityEventService {
    db: SqlitePool,
    retention_hours: i64,
    last_cleanup: std::sync::Arc<Mutex<Option<Instant>>>,
}

impl SecurityEventService {
    pub fn new(db: SqlitePool) -> Self {
        let retention_hours = parse_security_events_retention_hours(
            std::env::var("SECURITY_EVENTS_RETENTION_HOURS")
                .ok()
                .as_deref(),
        );

        Self {
            db,
            retention_hours,
            last_cleanup: std::sync::Arc::new(Mutex::new(None)),
        }
    }

    pub async fn init_schema(db: &SqlitePool) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_key TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                status TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                acknowledged_at INTEGER,
                resolved_at INTEGER
            )",
        )
        .execute(db)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_security_events_status_last_seen
                ON security_events(status, last_seen)",
        )
        .execute(db)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_security_events_type_last_seen
                ON security_events(event_type, last_seen)",
        )
        .execute(db)
        .await?;

        ensure_notification_columns(db).await?;
        NotificationOutbox::init_schema(db).await?;

        Ok(())
    }

    pub async fn raise_audit_event(&self, check: &SecurityCheck) -> Result<bool, sqlx::Error> {
        let (should_alert, _) = self.raise_audit_event_inner(check, None).await?;
        Ok(should_alert)
    }

    pub(crate) async fn raise_audit_event_with_notification(
        &self,
        check: &SecurityCheck,
        outbox: &NotificationOutbox,
        notification_text: &str,
    ) -> Result<Option<EnqueueOutcome>, sqlx::Error> {
        let (_, notification) = self
            .raise_audit_event_inner(check, Some((outbox, notification_text)))
            .await?;
        Ok(notification)
    }

    async fn raise_audit_event_inner(
        &self,
        check: &SecurityCheck,
        notification: Option<(&NotificationOutbox, &str)>,
    ) -> Result<(bool, Option<EnqueueOutcome>), sqlx::Error> {
        let event_key = Self::audit_event_key(&check.id);
        let now = Utc::now().timestamp();
        let event_type = if check.status == "WARN" {
            "audit.check_warning"
        } else {
            "audit.check_failed"
        };
        let mut transaction = self.db.begin_with("BEGIN IMMEDIATE").await?;
        let previous_state = get_notification_state_by_key(&mut transaction, &event_key).await?;
        let is_warning_to_failed = matches!(
            previous_state.as_ref(),
            Some((status, previous_event_type, _))
                if matches!(status.as_str(), "open" | "acknowledged")
                    && previous_event_type == "audit.check_warning"
                    && event_type == "audit.check_failed"
        );
        let should_alert = match previous_state.as_ref() {
            None => event_type == "audit.check_failed",
            Some((status, _, _)) if status == "resolved" => event_type == "audit.check_failed",
            _ if is_warning_to_failed => true,
            _ => false,
        };
        let evidence_json = Self::audit_evidence_json(check);

        sqlx::query(
            "INSERT INTO security_events (
                event_key, event_type, severity, title, message, evidence_json,
                status, first_seen, last_seen, acknowledged_at, resolved_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, NULL, NULL)
            ON CONFLICT(event_key) DO UPDATE SET
                event_type = CASE
                    WHEN security_events.status IN ('open', 'acknowledged')
                        AND security_events.event_type = 'audit.check_failed'
                        AND excluded.event_type = 'audit.check_warning'
                    THEN security_events.event_type
                    ELSE excluded.event_type
                END,
                severity = excluded.severity,
                title = excluded.title,
                message = excluded.message,
                evidence_json = excluded.evidence_json,
                status = CASE
                    WHEN security_events.status = 'resolved' THEN 'open'
                    WHEN security_events.status IN ('open', 'acknowledged')
                        AND security_events.event_type = 'audit.check_warning'
                        AND excluded.event_type = 'audit.check_failed'
                    THEN 'open'
                    ELSE security_events.status
                END,
                first_seen = CASE
                    WHEN security_events.status = 'resolved' THEN excluded.first_seen
                    ELSE security_events.first_seen
                END,
                last_seen = excluded.last_seen,
                acknowledged_at = CASE
                    WHEN security_events.status = 'resolved' THEN NULL
                    WHEN security_events.status IN ('open', 'acknowledged')
                        AND security_events.event_type = 'audit.check_warning'
                        AND excluded.event_type = 'audit.check_failed'
                    THEN NULL
                    ELSE security_events.acknowledged_at
                END,
                resolved_at = CASE
                    WHEN security_events.status = 'resolved' THEN NULL
                    WHEN security_events.status IN ('open', 'acknowledged')
                        AND security_events.event_type = 'audit.check_warning'
                        AND excluded.event_type = 'audit.check_failed'
                    THEN NULL
                    ELSE security_events.resolved_at
                END",
        )
        .bind(&event_key)
        .bind(event_type)
        .bind(&check.severity)
        .bind(&check.name)
        .bind(&check.message)
        .bind(evidence_json)
        .bind(now)
        .bind(now)
        .execute(&mut *transaction)
        .await?;

        let notification_outcome = if should_alert {
            if let Some((outbox, notification_text)) = notification {
                let sequence = next_notification_sequence(&mut transaction, &event_key).await?;
                let event = NotificationEvent::security_transition(
                    &event_key,
                    sequence,
                    event_type,
                    notification_text,
                    now,
                );
                let outcome = outbox
                    .enqueue_in_transaction(&mut transaction, &event, now)
                    .await?;
                update_enqueue_summary(&mut transaction, &event_key, sequence, &outcome, now)
                    .await?;
                Some(outcome)
            } else {
                None
            }
        } else {
            None
        };

        transaction.commit().await?;
        Ok((should_alert, notification_outcome))
    }

    #[cfg(test)]
    pub async fn resolve_audit_event(&self, check: &SecurityCheck) -> Result<bool, sqlx::Error> {
        let (should_alert, _) = self.resolve_audit_event_inner(check, None).await?;
        Ok(should_alert)
    }

    pub(crate) async fn resolve_audit_event_with_notification(
        &self,
        check: &SecurityCheck,
        outbox: &NotificationOutbox,
        notification_text: &str,
    ) -> Result<Option<EnqueueOutcome>, sqlx::Error> {
        let (_, notification) = self
            .resolve_audit_event_inner(check, Some((outbox, notification_text)))
            .await?;
        Ok(notification)
    }

    async fn resolve_audit_event_inner(
        &self,
        check: &SecurityCheck,
        notification: Option<(&NotificationOutbox, &str)>,
    ) -> Result<(bool, Option<EnqueueOutcome>), sqlx::Error> {
        let event_key = Self::audit_event_key(&check.id);
        let mut transaction = self.db.begin_with("BEGIN IMMEDIATE").await?;
        let previous_state = get_notification_state_by_key(&mut transaction, &event_key).await?;
        let should_resolve = matches!(
            previous_state
                .as_ref()
                .map(|(status, _, _)| status.as_str()),
            Some("open") | Some("acknowledged")
        );
        let should_alert = matches!(
            previous_state.as_ref(),
            Some((status, event_type, _))
                if matches!(status.as_str(), "open" | "acknowledged")
                    && event_type == "audit.check_failed"
        );

        let now = Utc::now().timestamp();
        if should_resolve {
            sqlx::query(
                "UPDATE security_events
                SET status = 'resolved', last_seen = ?, resolved_at = ?
                WHERE event_key = ? AND status IN ('open', 'acknowledged')",
            )
            .bind(now)
            .bind(now)
            .bind(&event_key)
            .execute(&mut *transaction)
            .await?;
        }

        let notification_outcome = if should_alert {
            if let Some((outbox, notification_text)) = notification {
                let sequence = next_notification_sequence(&mut transaction, &event_key).await?;
                let event = NotificationEvent::security_transition(
                    &event_key,
                    sequence,
                    "audit.check_resolved",
                    notification_text,
                    now,
                );
                let outcome = outbox
                    .enqueue_in_transaction(&mut transaction, &event, now)
                    .await?;
                update_enqueue_summary(&mut transaction, &event_key, sequence, &outcome, now)
                    .await?;
                Some(outcome)
            } else {
                None
            }
        } else {
            None
        };

        transaction.commit().await?;
        Ok((should_alert, notification_outcome))
    }

    #[cfg(test)]
    pub async fn raise_ssh_source_ip_event(
        &self,
        user: &str,
        ip: &str,
        method: &str,
        timestamp: i64,
    ) -> Result<bool, sqlx::Error> {
        let (should_alert, _) = self
            .raise_ssh_source_ip_event_inner(user, ip, method, timestamp, None)
            .await?;
        Ok(should_alert)
    }

    pub(crate) async fn raise_ssh_source_ip_event_with_notification(
        &self,
        user: &str,
        ip: &str,
        method: &str,
        timestamp: i64,
        outbox: &NotificationOutbox,
        notification_text: &str,
    ) -> Result<Option<EnqueueOutcome>, sqlx::Error> {
        let (_, notification) = self
            .raise_ssh_source_ip_event_inner(
                user,
                ip,
                method,
                timestamp,
                Some((outbox, notification_text)),
            )
            .await?;
        Ok(notification)
    }

    async fn raise_ssh_source_ip_event_inner(
        &self,
        user: &str,
        ip: &str,
        method: &str,
        timestamp: i64,
        notification: Option<(&NotificationOutbox, &str)>,
    ) -> Result<(bool, Option<EnqueueOutcome>), sqlx::Error> {
        let event_key = Self::ssh_source_ip_event_key(ip);
        let mut transaction = self.db.begin_with("BEGIN IMMEDIATE").await?;
        let previous_state = get_notification_state_by_key(&mut transaction, &event_key).await?;
        let should_alert = matches!(
            previous_state
                .as_ref()
                .map(|(status, _, _)| status.as_str()),
            None | Some("resolved")
        );
        let now = Utc::now().timestamp();
        let lang = crate::i18n::Lang::from_headers(&crate::i18n::HeaderMap::new());
        let title = crate::i18n::t("security.ssh_source_ip.title", &lang);
        let message = format!(
            "{}: user={}, ip={}, method={}",
            crate::i18n::t("security.ssh_source_ip.message", &lang),
            user,
            ip,
            method
        );
        let evidence_json = serde_json::to_string(&serde_json::json!({
            "user": user,
            "ip": ip,
            "method": method,
            "timestamp": timestamp,
            "baseline": "trusted_ips",
        }))
        .unwrap_or_else(|_| "{}".to_string());

        sqlx::query(
            "INSERT INTO security_events (
                event_key, event_type, severity, title, message, evidence_json,
                status, first_seen, last_seen, acknowledged_at, resolved_at
            )
            VALUES (?, 'ssh.untrusted_source_ip', 'high', ?, ?, ?, 'open', ?, ?, NULL, NULL)
            ON CONFLICT(event_key) DO UPDATE SET
                event_type = excluded.event_type,
                severity = excluded.severity,
                title = excluded.title,
                message = excluded.message,
                evidence_json = excluded.evidence_json,
                status = CASE
                    WHEN security_events.status = 'resolved' THEN 'open'
                    ELSE security_events.status
                END,
                first_seen = CASE
                    WHEN security_events.status = 'resolved' THEN excluded.first_seen
                    ELSE security_events.first_seen
                END,
                last_seen = excluded.last_seen,
                acknowledged_at = CASE
                    WHEN security_events.status = 'resolved' THEN NULL
                    ELSE security_events.acknowledged_at
                END,
                resolved_at = CASE
                    WHEN security_events.status = 'resolved' THEN NULL
                    ELSE security_events.resolved_at
                END",
        )
        .bind(&event_key)
        .bind(title)
        .bind(message)
        .bind(evidence_json)
        .bind(now)
        .bind(now)
        .execute(&mut *transaction)
        .await?;

        let notification_outcome = if let Some((outbox, notification_text)) = notification {
            let sequence = next_notification_sequence(&mut transaction, &event_key).await?;
            let event = NotificationEvent::ssh_login_transition(
                &event_key,
                ip,
                sequence,
                notification_text,
                now,
            );
            let outcome = outbox
                .enqueue_in_transaction(&mut transaction, &event, now)
                .await?;
            update_enqueue_summary(&mut transaction, &event_key, sequence, &outcome, now).await?;
            Some(outcome)
        } else {
            None
        };

        transaction.commit().await?;
        Ok((should_alert, notification_outcome))
    }

    pub async fn resolve_ssh_source_ip_event(&self, ip: &str) -> Result<bool, sqlx::Error> {
        let event_key = Self::ssh_source_ip_event_key(ip);
        let previous_state = self.get_state_by_key(&event_key).await?;
        let should_resolve = matches!(
            previous_state.as_ref().map(|(status, _)| status.as_str()),
            Some("open") | Some("acknowledged")
        );

        if should_resolve {
            let now = Utc::now().timestamp();
            sqlx::query(
                "UPDATE security_events
                SET status = 'resolved', last_seen = ?, resolved_at = ?
                WHERE event_key = ? AND status IN ('open', 'acknowledged')",
            )
            .bind(now)
            .bind(now)
            .bind(event_key)
            .execute(&self.db)
            .await?;
        }

        Ok(should_resolve)
    }

    pub async fn acknowledge(&self, id: i64) -> Result<bool, sqlx::Error> {
        let now = Utc::now().timestamp();
        let result = sqlx::query(
            "UPDATE security_events
            SET status = 'acknowledged', acknowledged_at = ?
            WHERE id = ? AND status = 'open'",
        )
        .bind(now)
        .bind(id)
        .execute(&self.db)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn list(
        &self,
        status: Option<&str>,
        limit: i64,
    ) -> Result<Vec<SecurityEvent>, sqlx::Error> {
        let limit = limit.clamp(1, 500);
        let rows = match status {
            Some("active") => {
                sqlx::query(
                    "SELECT * FROM security_events
                    WHERE status IN ('open', 'acknowledged')
                    ORDER BY last_seen DESC
                    LIMIT ?",
                )
                .bind(limit)
                .fetch_all(&self.db)
                .await?
            }
            Some("open") | Some("acknowledged") | Some("resolved") => {
                sqlx::query(
                    "SELECT * FROM security_events
                    WHERE status = ?
                    ORDER BY last_seen DESC
                    LIMIT ?",
                )
                .bind(status.unwrap_or_default())
                .bind(limit)
                .fetch_all(&self.db)
                .await?
            }
            _ => {
                sqlx::query("SELECT * FROM security_events ORDER BY last_seen DESC LIMIT ?")
                    .bind(limit)
                    .fetch_all(&self.db)
                    .await?
            }
        };

        Ok(rows.into_iter().map(Self::event_from_row).collect())
    }

    pub async fn cleanup_if_due(&self) -> Result<(), sqlx::Error> {
        {
            let mut last_cleanup = self.last_cleanup.lock().await;
            if let Some(last) = *last_cleanup
                && last.elapsed() < Duration::from_secs(3600)
            {
                return Ok(());
            }
            *last_cleanup = Some(Instant::now());
        }

        let cutoff = retention_cutoff(Utc::now().timestamp(), self.retention_hours);
        sqlx::query(
            "DELETE FROM security_events
            WHERE status = 'resolved' AND last_seen < ?",
        )
        .bind(cutoff)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    async fn get_state_by_key(
        &self,
        event_key: &str,
    ) -> Result<Option<(String, String)>, sqlx::Error> {
        let row = sqlx::query("SELECT status, event_type FROM security_events WHERE event_key = ?")
            .bind(event_key)
            .fetch_optional(&self.db)
            .await?;

        Ok(row.map(|row| (row.get("status"), row.get("event_type"))))
    }

    fn audit_event_key(check_id: &str) -> String {
        format!("audit:{}", check_id)
    }

    fn ssh_source_ip_event_key(ip: &str) -> String {
        format!("ssh:source_ip:{}", ip)
    }

    fn audit_evidence_json(check: &SecurityCheck) -> String {
        serde_json::to_string(&serde_json::json!({
            "check_id": check.id,
            "category": check.category,
            "status": check.status,
            "evidence": check.evidence,
            "remediation": check.remediation,
            "metadata": check.metadata,
        }))
        .unwrap_or_else(|_| "{}".to_string())
    }

    fn event_from_row(row: sqlx::sqlite::SqliteRow) -> SecurityEvent {
        SecurityEvent {
            id: row.get("id"),
            event_key: row.get("event_key"),
            event_type: row.get("event_type"),
            severity: row.get("severity"),
            title: row.get("title"),
            message: row.get("message"),
            evidence_json: row.get("evidence_json"),
            status: row.get("status"),
            first_seen: row.get("first_seen"),
            last_seen: row.get("last_seen"),
            acknowledged_at: row.get("acknowledged_at"),
            resolved_at: row.get("resolved_at"),
            notification_delivery_status: row.get("notification_delivery_status"),
            notification_delivery_attempts: row.get("notification_delivery_attempts"),
            notification_delivery_updated_at: row.get("notification_delivery_updated_at"),
            notification_delivery_error_code: row.get("notification_delivery_error_code"),
        }
    }
}

async fn ensure_notification_columns(db: &SqlitePool) -> Result<(), sqlx::Error> {
    let rows = sqlx::query("PRAGMA table_info(security_events)")
        .fetch_all(db)
        .await?;
    let existing: std::collections::HashSet<String> = rows
        .into_iter()
        .map(|row| row.get::<String, _>("name"))
        .collect();

    let additions = [
        (
            "notification_seq",
            "ALTER TABLE security_events ADD COLUMN notification_seq INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "notification_delivery_status",
            "ALTER TABLE security_events ADD COLUMN notification_delivery_status TEXT",
        ),
        (
            "notification_delivery_attempts",
            "ALTER TABLE security_events ADD COLUMN notification_delivery_attempts INTEGER",
        ),
        (
            "notification_delivery_updated_at",
            "ALTER TABLE security_events ADD COLUMN notification_delivery_updated_at INTEGER",
        ),
        (
            "notification_delivery_error_code",
            "ALTER TABLE security_events ADD COLUMN notification_delivery_error_code TEXT",
        ),
    ];
    for (name, statement) in additions {
        if !existing.contains(name) {
            sqlx::query(statement).execute(db).await?;
        }
    }
    Ok(())
}

async fn get_notification_state_by_key(
    transaction: &mut Transaction<'_, Sqlite>,
    event_key: &str,
) -> Result<Option<(String, String, i64)>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT status, event_type, notification_seq
         FROM security_events WHERE event_key = ?",
    )
    .bind(event_key)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(row.map(|row| {
        (
            row.get("status"),
            row.get("event_type"),
            row.get("notification_seq"),
        )
    }))
}

async fn next_notification_sequence(
    transaction: &mut Transaction<'_, Sqlite>,
    event_key: &str,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE security_events
         SET notification_seq = MAX(
                notification_seq,
                COALESCE((
                    SELECT MAX(source_event_seq) FROM notification_outbox
                    WHERE channel = 'telegram' AND source_event_key = ?
                ), 0)
             ) + 1
         WHERE event_key = ?
         RETURNING notification_seq",
    )
    .bind(event_key)
    .bind(event_key)
    .fetch_one(&mut **transaction)
    .await
}

async fn update_enqueue_summary(
    transaction: &mut Transaction<'_, Sqlite>,
    event_key: &str,
    sequence: i64,
    outcome: &EnqueueOutcome,
    now: i64,
) -> Result<(), sqlx::Error> {
    let (status, error_code) = match outcome {
        EnqueueOutcome::Pending { .. } => ("pending", None),
        EnqueueOutcome::Disabled => ("disabled", None),
        EnqueueOutcome::Suppressed => ("suppressed", None),
        EnqueueOutcome::Backpressure => ("failed", None),
        EnqueueOutcome::Failed { code } => ("failed", Some(code.as_str())),
    };
    sqlx::query(
        "UPDATE security_events
         SET notification_delivery_status = ?,
             notification_delivery_attempts = 0,
             notification_delivery_updated_at = ?,
             notification_delivery_error_code = ?
         WHERE event_key = ? AND notification_seq = ?",
    )
    .bind(status)
    .bind(now)
    .bind(error_code)
    .bind(event_key)
    .bind(sequence)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn parse_security_events_retention_hours(value: Option<&str>) -> i64 {
    parse_bounded_i64(
        value,
        DEFAULT_SECURITY_EVENTS_RETENTION_HOURS,
        1,
        MAX_SECURITY_EVENTS_RETENTION_HOURS,
    )
}

fn parse_bounded_i64(value: Option<&str>, default: i64, min: i64, max: i64) -> i64 {
    value
        .and_then(|value| value.trim().parse::<i64>().ok())
        .map(|value| value.clamp(min, max))
        .unwrap_or(default)
}

fn retention_cutoff(now: i64, retention_hours: i64) -> i64 {
    now.saturating_sub(retention_hours.saturating_mul(3600))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notifications::{EnqueueOutcome, NotificationOutbox, NotificationService};
    use crate::security::SecurityCheck;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::Arc;

    async fn test_service() -> SecurityEventService {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory sqlite should connect");
        SecurityEventService::init_schema(&pool)
            .await
            .expect("schema should initialize");
        SecurityEventService::new(pool)
    }

    fn failed_check() -> SecurityCheck {
        SecurityCheck {
            id: "test.failure".to_string(),
            name: "Test failure".to_string(),
            category: "test".to_string(),
            severity: "high".to_string(),
            status: "FAIL".to_string(),
            message: "Something failed".to_string(),
            evidence: vec!["evidence=true".to_string()],
            remediation: "Fix it".to_string(),
            references: Vec::new(),
            metadata: std::collections::HashMap::new(),
        }
    }

    fn passed_check() -> SecurityCheck {
        SecurityCheck {
            status: "PASS".to_string(),
            ..failed_check()
        }
    }

    fn warning_check() -> SecurityCheck {
        SecurityCheck {
            severity: "medium".to_string(),
            status: "WARN".to_string(),
            ..failed_check()
        }
    }

    fn enabled_outbox(service: &SecurityEventService) -> NotificationOutbox {
        NotificationOutbox::new(
            service.db.clone(),
            Arc::new(NotificationService::with_test_endpoint(
                "123456:test",
                "http://127.0.0.1:9".to_string(),
            )),
        )
    }

    #[test]
    fn security_events_retention_hours_uses_default_and_bounds() {
        assert_eq!(parse_security_events_retention_hours(None), 168);
        assert_eq!(
            parse_security_events_retention_hours(Some("not-a-number")),
            168
        );
        assert_eq!(parse_security_events_retention_hours(Some("0")), 1);
        assert_eq!(parse_security_events_retention_hours(Some("-42")), 1);
        assert_eq!(parse_security_events_retention_hours(Some(" 24 ")), 24);
        assert_eq!(
            parse_security_events_retention_hours(Some("43801")),
            MAX_SECURITY_EVENTS_RETENTION_HOURS
        );
    }

    #[test]
    fn security_events_retention_cutoff_uses_saturating_math() {
        assert_eq!(
            retention_cutoff(1_000, i64::MAX),
            1_000_i64.saturating_sub(i64::MAX)
        );
    }

    #[tokio::test]
    async fn schema_upgrade_adds_notification_state_without_backfill_delivery() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_key TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                status TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                acknowledged_at INTEGER,
                resolved_at INTEGER
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO security_events (
                event_key, event_type, severity, title, message, evidence_json,
                status, first_seen, last_seen
             ) VALUES ('legacy', 'audit.check_failed', 'high', 'title',
                       'message', '{}', 'open', 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();

        SecurityEventService::init_schema(&pool).await.unwrap();
        let row = sqlx::query(
            "SELECT notification_seq, notification_delivery_status,
                    notification_delivery_attempts,
                    notification_delivery_updated_at,
                    notification_delivery_error_code
             FROM security_events WHERE event_key = 'legacy'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.get::<i64, _>("notification_seq"), 0);
        assert!(
            row.get::<Option<String>, _>("notification_delivery_status")
                .is_none()
        );
        assert!(
            row.get::<Option<i64>, _>("notification_delivery_attempts")
                .is_none()
        );
        assert!(
            row.get::<Option<i64>, _>("notification_delivery_updated_at")
                .is_none()
        );
        assert!(
            row.get::<Option<String>, _>("notification_delivery_error_code")
                .is_none()
        );
        let queued: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notification_outbox")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(queued, 0);
    }

    #[tokio::test]
    async fn audit_event_alerts_once_until_resolved() {
        let service = test_service().await;

        assert!(service.raise_audit_event(&failed_check()).await.unwrap());
        assert!(!service.raise_audit_event(&failed_check()).await.unwrap());

        let active = service.list(Some("active"), 10).await.unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].status, "open");

        assert!(service.resolve_audit_event(&passed_check()).await.unwrap());
        assert!(!service.resolve_audit_event(&passed_check()).await.unwrap());

        let resolved = service.list(Some("resolved"), 10).await.unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].status, "resolved");

        assert!(service.raise_audit_event(&failed_check()).await.unwrap());
    }

    #[tokio::test]
    async fn resolved_audit_event_resets_first_seen_when_reopened() {
        let service = test_service().await;
        let check = failed_check();
        let event_key = SecurityEventService::audit_event_key(&check.id);

        assert!(service.raise_audit_event(&check).await.unwrap());
        assert!(service.resolve_audit_event(&passed_check()).await.unwrap());

        sqlx::query(
            "UPDATE security_events
            SET first_seen = 1, last_seen = 2, resolved_at = 2
            WHERE event_key = ?",
        )
        .bind(&event_key)
        .execute(&service.db)
        .await
        .unwrap();

        assert!(service.raise_audit_event(&check).await.unwrap());

        let active = service.list(Some("active"), 10).await.unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].status, "open");
        assert_eq!(active[0].first_seen, active[0].last_seen);
        assert!(active[0].first_seen > 1);
        assert!(active[0].resolved_at.is_none());
    }

    #[tokio::test]
    async fn acknowledge_marks_open_event_without_resolving_it() {
        let service = test_service().await;

        assert!(service.raise_audit_event(&failed_check()).await.unwrap());
        let event = service
            .list(Some("active"), 10)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();

        assert!(service.acknowledge(event.id).await.unwrap());
        assert!(!service.acknowledge(event.id).await.unwrap());

        let events = service.list(Some("active"), 10).await.unwrap();
        assert_eq!(events[0].status, "acknowledged");
        assert!(events[0].acknowledged_at.is_some());
    }

    #[tokio::test]
    async fn warning_events_do_not_alert_on_open_or_resolve() {
        let service = test_service().await;

        assert!(!service.raise_audit_event(&warning_check()).await.unwrap());
        assert!(!service.resolve_audit_event(&passed_check()).await.unwrap());

        let resolved = service.list(Some("resolved"), 10).await.unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].event_type, "audit.check_warning");
    }

    #[tokio::test]
    async fn warning_to_failed_escalation_alerts_once() {
        let service = test_service().await;

        assert!(!service.raise_audit_event(&warning_check()).await.unwrap());
        assert!(service.raise_audit_event(&failed_check()).await.unwrap());
        assert!(!service.raise_audit_event(&failed_check()).await.unwrap());
    }

    #[tokio::test]
    async fn failed_to_warning_to_pass_still_alerts_on_resolve() {
        let service = test_service().await;

        assert!(service.raise_audit_event(&failed_check()).await.unwrap());
        assert!(!service.raise_audit_event(&warning_check()).await.unwrap());

        let active = service.list(Some("active"), 10).await.unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].event_type, "audit.check_failed");
        assert_eq!(active[0].severity, "medium");

        assert!(service.resolve_audit_event(&passed_check()).await.unwrap());

        let resolved = service.list(Some("resolved"), 10).await.unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].event_type, "audit.check_failed");
    }

    #[tokio::test]
    async fn acknowledged_warning_to_failed_reopens_event() {
        let service = test_service().await;

        assert!(!service.raise_audit_event(&warning_check()).await.unwrap());
        let event = service
            .list(Some("active"), 10)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        assert!(service.acknowledge(event.id).await.unwrap());

        assert!(service.raise_audit_event(&failed_check()).await.unwrap());

        let active = service.list(Some("active"), 10).await.unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].status, "open");
        assert_eq!(active[0].event_type, "audit.check_failed");
        assert!(active[0].acknowledged_at.is_none());
    }

    #[tokio::test]
    async fn warning_failed_pass_transition_enqueues_once_without_alert_spam() {
        let service = test_service().await;
        let outbox = enabled_outbox(&service);

        assert_eq!(
            service
                .raise_audit_event_with_notification(
                    &warning_check(),
                    &outbox,
                    "warning should not deliver",
                )
                .await
                .unwrap(),
            None
        );
        assert!(matches!(
            service
                .raise_audit_event_with_notification(&failed_check(), &outbox, "audit failure",)
                .await
                .unwrap(),
            Some(EnqueueOutcome::Pending { .. })
        ));
        assert_eq!(
            service
                .raise_audit_event_with_notification(
                    &failed_check(),
                    &outbox,
                    "same failure with changed metric=99",
                )
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            service
                .resolve_audit_event_with_notification(&passed_check(), &outbox, "audit resolved",)
                .await
                .unwrap(),
            Some(EnqueueOutcome::Suppressed)
        );

        let row = sqlx::query(
            "SELECT notification_seq, notification_delivery_status
             FROM security_events WHERE event_key = 'audit:test.failure'",
        )
        .fetch_one(&service.db)
        .await
        .unwrap();
        assert_eq!(row.get::<i64, _>("notification_seq"), 2);
        assert_eq!(
            row.get::<String, _>("notification_delivery_status"),
            "suppressed"
        );
        let queued: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_outbox
             WHERE source_event_key = 'audit:test.failure'",
        )
        .fetch_one(&service.db)
        .await
        .unwrap();
        assert_eq!(queued, 1);
    }

    #[tokio::test]
    async fn event_and_outbox_enqueue_roll_back_together() {
        let service = test_service().await;
        let outbox = enabled_outbox(&service);
        sqlx::query("DROP TABLE notification_outbox")
            .execute(&service.db)
            .await
            .unwrap();

        assert!(
            service
                .raise_audit_event_with_notification(&failed_check(), &outbox, "must roll back",)
                .await
                .is_err()
        );
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_events")
            .fetch_one(&service.db)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn recreated_event_continues_sequence_from_retained_terminal_outbox_row() {
        let service = test_service().await;
        let outbox = enabled_outbox(&service);
        let now = Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO notification_outbox (
                channel, dedup_key, kind, source_event_key, source_event_seq,
                payload_json, suppress_until, state, attempts, next_attempt_at,
                lease_until, last_error_code, last_http_status, created_at,
                updated_at, sent_at, abandoned_at
             ) VALUES (
                'telegram', 'security:audit:test.failure', 'audit.check_failed',
                'audit:test.failure', 1,
                '{\"version\":1,\"text\":\"old\",\"occurred_at\":1}',
                ?, 'sent', 1, NULL, NULL, NULL, NULL, ?, ?, ?, NULL
             )",
        )
        .bind(now.saturating_sub(1))
        .bind(now.saturating_sub(2))
        .bind(now.saturating_sub(2))
        .bind(now.saturating_sub(2))
        .execute(&service.db)
        .await
        .unwrap();

        assert!(matches!(
            service
                .raise_audit_event_with_notification(&failed_check(), &outbox, "new failure")
                .await
                .unwrap(),
            Some(EnqueueOutcome::Pending { .. })
        ));
        let sequence: i64 = sqlx::query_scalar(
            "SELECT notification_seq FROM security_events
             WHERE event_key = 'audit:test.failure'",
        )
        .fetch_one(&service.db)
        .await
        .unwrap();
        let sequences: Vec<i64> = sqlx::query_scalar(
            "SELECT source_event_seq FROM notification_outbox
             WHERE source_event_key = 'audit:test.failure'
             ORDER BY source_event_seq",
        )
        .fetch_all(&service.db)
        .await
        .unwrap();
        assert_eq!(sequence, 2);
        assert_eq!(sequences, vec![1, 2]);
    }

    #[tokio::test]
    async fn repeated_ssh_login_after_cooldown_enqueues_while_event_stays_open() {
        let service = test_service().await;
        let outbox = enabled_outbox(&service);
        let ip = "203.0.113.42";
        assert!(matches!(
            service
                .raise_ssh_source_ip_event_with_notification(
                    "root",
                    ip,
                    "publickey",
                    1_700_000_000,
                    &outbox,
                    "first login",
                )
                .await
                .unwrap(),
            Some(EnqueueOutcome::Pending { .. })
        ));
        assert_eq!(
            service
                .raise_ssh_source_ip_event_with_notification(
                    "root",
                    ip,
                    "publickey",
                    1_700_000_001,
                    &outbox,
                    "duplicate login",
                )
                .await
                .unwrap(),
            Some(EnqueueOutcome::Suppressed)
        );

        let now = Utc::now().timestamp();
        sqlx::query(
            "UPDATE notification_outbox
             SET state = 'sent', next_attempt_at = NULL, sent_at = ?,
                 suppress_until = ?, updated_at = ?
             WHERE dedup_key = ?",
        )
        .bind(now)
        .bind(now.saturating_sub(1))
        .bind(now)
        .bind(format!("ssh:login:{ip}"))
        .execute(&service.db)
        .await
        .unwrap();

        assert!(matches!(
            service
                .raise_ssh_source_ip_event_with_notification(
                    "root",
                    ip,
                    "publickey",
                    1_700_000_020,
                    &outbox,
                    "later login",
                )
                .await
                .unwrap(),
            Some(EnqueueOutcome::Pending { .. })
        ));
        let active = service.list(Some("active"), 10).await.unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].status, "open");
        let queued: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM notification_outbox WHERE dedup_key = ?")
                .bind(format!("ssh:login:{ip}"))
                .fetch_one(&service.db)
                .await
                .unwrap();
        assert_eq!(queued, 2);
    }

    #[tokio::test]
    async fn ssh_source_ip_event_alerts_once_until_resolved() {
        let service = test_service().await;

        assert!(
            service
                .raise_ssh_source_ip_event("root", "203.0.113.10", "publickey", 1_700_000_000)
                .await
                .unwrap()
        );
        assert!(
            !service
                .raise_ssh_source_ip_event("root", "203.0.113.10", "publickey", 1_700_000_010)
                .await
                .unwrap()
        );

        let active = service.list(Some("active"), 10).await.unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].event_key, "ssh:source_ip:203.0.113.10");
        assert_eq!(active[0].event_type, "ssh.untrusted_source_ip");
        assert_eq!(active[0].severity, "high");

        assert!(
            service
                .resolve_ssh_source_ip_event("203.0.113.10")
                .await
                .unwrap()
        );
        assert!(
            !service
                .resolve_ssh_source_ip_event("203.0.113.10")
                .await
                .unwrap()
        );

        let resolved = service.list(Some("resolved"), 10).await.unwrap();
        assert_eq!(resolved.len(), 1);
    }

    #[tokio::test]
    async fn resolved_ssh_source_ip_event_reopens_with_new_first_seen() {
        let service = test_service().await;

        assert!(
            service
                .raise_ssh_source_ip_event("root", "203.0.113.11", "publickey", 1_700_000_000)
                .await
                .unwrap()
        );
        assert!(
            service
                .resolve_ssh_source_ip_event("203.0.113.11")
                .await
                .unwrap()
        );

        sqlx::query(
            "UPDATE security_events
            SET first_seen = 1, last_seen = 2, resolved_at = 2
            WHERE event_key = ?",
        )
        .bind(SecurityEventService::ssh_source_ip_event_key(
            "203.0.113.11",
        ))
        .execute(&service.db)
        .await
        .unwrap();

        assert!(
            service
                .raise_ssh_source_ip_event("root", "203.0.113.11", "publickey", 1_700_000_100)
                .await
                .unwrap()
        );

        let active = service.list(Some("active"), 10).await.unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].status, "open");
        assert_eq!(active[0].first_seen, active[0].last_seen);
        assert!(active[0].first_seen > 1);
        assert!(active[0].resolved_at.is_none());
    }
}
