use chrono::Utc;
use serde::Serialize;
use sqlx::{Row, SqlitePool};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::security::SecurityCheck;

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
}

#[derive(Clone)]
pub struct SecurityEventService {
    db: SqlitePool,
    retention_hours: i64,
    last_cleanup: std::sync::Arc<Mutex<Option<Instant>>>,
}

impl SecurityEventService {
    pub fn new(db: SqlitePool) -> Self {
        let retention_hours = std::env::var("SECURITY_EVENTS_RETENTION_HOURS")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(168);

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

        Ok(())
    }

    pub async fn raise_audit_event(&self, check: &SecurityCheck) -> Result<bool, sqlx::Error> {
        let event_key = Self::audit_event_key(&check.id);
        let now = Utc::now().timestamp();
        let event_type = if check.status == "WARN" {
            "audit.check_warning"
        } else {
            "audit.check_failed"
        };
        let previous_state = self.get_state_by_key(&event_key).await?;
        let is_warning_to_failed = matches!(
            previous_state.as_ref(),
            Some((status, previous_event_type))
                if matches!(status.as_str(), "open" | "acknowledged")
                    && previous_event_type == "audit.check_warning"
                    && event_type == "audit.check_failed"
        );
        let should_alert = match previous_state.as_ref() {
            None => event_type == "audit.check_failed",
            Some((status, _)) if status == "resolved" => event_type == "audit.check_failed",
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
        .execute(&self.db)
        .await?;

        Ok(should_alert)
    }

    pub async fn resolve_audit_event(&self, check: &SecurityCheck) -> Result<bool, sqlx::Error> {
        let event_key = Self::audit_event_key(&check.id);
        let previous_state = self.get_state_by_key(&event_key).await?;
        let should_resolve = matches!(
            previous_state.as_ref().map(|(status, _)| status.as_str()),
            Some("open") | Some("acknowledged")
        );
        let should_alert = matches!(
            previous_state.as_ref(),
            Some((status, event_type))
                if matches!(status.as_str(), "open" | "acknowledged")
                    && event_type == "audit.check_failed"
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

        Ok(should_alert)
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

        let cutoff = Utc::now().timestamp() - (self.retention_hours * 3600);
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecurityCheck;
    use sqlx::sqlite::SqlitePoolOptions;

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
}
