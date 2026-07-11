use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::notifications::{EnqueueOutcome, NotificationEvent, NotificationOutbox};
use crate::security::SecurityCheck;

const DEFAULT_SECURITY_EVENTS_RETENTION_HOURS: i64 = 168;
const MAX_SECURITY_EVENTS_RETENTION_HOURS: i64 = 24 * 365 * 5;
const CURRENT_EVIDENCE_SCHEMA_VERSION: i64 = 1;
const MAX_STORED_EVIDENCE_BYTES: usize = 64 * 1024;
const MAX_AUDIT_IDENTIFIER_BYTES: usize = 128;
const MAX_AUDIT_CATEGORY_BYTES: usize = 64;
const MAX_AUDIT_REMEDIATION_BYTES: usize = 4 * 1024;
const MAX_AUDIT_EVIDENCE_ITEMS: usize = 128;
const MAX_AUDIT_EVIDENCE_BYTES: usize = 4 * 1024;
const MAX_AUDIT_METADATA_KEYS: usize = 16;
const MAX_AUDIT_METADATA_ITEMS: usize = 128;
const MAX_AUDIT_METADATA_VALUE_BYTES: usize = 4 * 1024;
const MAX_AUDIT_METADATA_TOTAL_BYTES: usize = 48 * 1024;
const JS_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_FILE_TIMESTAMP: i64 = 253_402_300_799;
const SECURITY_EVENT_LIST_COLUMNS: &str =
    "SELECT id, event_key, event_type, severity, title, message,
            CASE
                WHEN typeof(evidence_json) = 'text'
                    AND length(CAST(evidence_json AS BLOB)) <= ?
                THEN CAST(evidence_json AS BLOB)
                ELSE NULL
            END AS bounded_evidence_bytes,
            CASE
                WHEN typeof(evidence_json) != 'text'
                    OR length(CAST(evidence_json AS BLOB)) > ? THEN 1
                ELSE 0
            END AS evidence_payload_invalid,
            evidence_schema_version, status, first_seen, last_seen,
            acknowledged_at, resolved_at,
            notification_delivery_status, notification_delivery_attempts,
            notification_delivery_updated_at, notification_delivery_error_code
     FROM security_events";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventEvidenceErrorCode {
    UnsupportedSchemaVersion,
    InvalidStoredPayload,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SecurityEventEvidence(SecurityEventEvidenceProjection);

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
enum SecurityEventEvidenceProjection {
    Known(KnownSecurityEventEvidence),
    Unavailable(UnavailableSecurityEventEvidence),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct KnownSecurityEventEvidence {
    schema_version: i64,
    #[serde(flatten)]
    kind: KnownSecurityEventEvidenceV1,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind")]
enum KnownSecurityEventEvidenceV1 {
    #[serde(rename = "audit.check_failed")]
    AuditCheckFailed {
        data: AuditEventEvidenceV1,
        error_code: (),
    },
    #[serde(rename = "audit.check_warning")]
    AuditCheckWarning {
        data: AuditEventEvidenceV1,
        error_code: (),
    },
    #[serde(rename = "ssh.untrusted_source_ip")]
    SshUntrustedSourceIp {
        data: SshEventEvidenceV1,
        error_code: (),
    },
    #[serde(rename = "notification.delivery_degraded")]
    NotificationDeliveryDegraded {
        data: NotificationDeliveryDegradedEvidenceV1,
        error_code: (),
    },
    #[serde(rename = "file.sensitive_changed")]
    FileSensitiveChanged {
        data: FileSensitiveChangedEvidenceV1,
        error_code: (),
    },
}

impl KnownSecurityEventEvidenceV1 {
    fn data_json(&self) -> Result<String, serde_json::Error> {
        match self {
            Self::AuditCheckFailed { data, .. } | Self::AuditCheckWarning { data, .. } => {
                serde_json::to_string(data)
            }
            Self::SshUntrustedSourceIp { data, .. } => serde_json::to_string(data),
            Self::NotificationDeliveryDegraded { data, .. } => serde_json::to_string(data),
            Self::FileSensitiveChanged { data, .. } => serde_json::to_string(data),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct UnavailableSecurityEventEvidence {
    schema_version: i64,
    kind: String,
    data: (),
    error_code: SecurityEventEvidenceErrorCode,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEventEvidenceV1 {
    pub category: String,
    pub check_id: String,
    pub evidence: Vec<String>,
    pub metadata: BTreeMap<String, Vec<String>>,
    pub remediation: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshEventEvidenceV1 {
    pub baseline: String,
    pub ip: String,
    pub method: String,
    pub timestamp: i64,
    pub user: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationDeliveryDegradedEvidenceV1 {
    pub reason: String,
    pub live_limit: u64,
    pub terminal_limit: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSensitiveChangedEvidenceV1 {
    pub path_id: String,
    pub logical_path: String,
    pub change_kinds: Vec<FileChangeKindV1>,
    pub baseline_generation: u64,
    pub observed_generation: u64,
    pub baseline_metadata: FileEvidenceMetadataV1,
    pub observed_metadata: FileEvidenceMetadataV1,
    pub observed_at: i64,
    pub observation_error: Option<FileObservationErrorV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileChangeKindV1 {
    Added,
    ContentChanged,
    OwnerChanged,
    PermissionsChanged,
    Removed,
    TypeChanged,
    Unreadable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEvidenceMetadataV1 {
    pub state: FileEvidenceStateV1,
    pub size_bytes: Option<u64>,
    pub mtime_unix_seconds: Option<i64>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileEvidenceStateV1 {
    Regular,
    Absent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileObservationErrorV1 {
    PermissionDenied,
    Symlink,
    NotRegular,
    FileTooLarge,
    TrackedFileLimit,
    ScanByteLimit,
    DeadlineExceeded,
    ChangedDuringRead,
    VanishedDuringScan,
    DirectoryUnreadable,
    PathNotUtf8,
    PathTooLong,
    IoError,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityEvent {
    pub id: i64,
    pub event_key: String,
    pub event_type: String,
    pub severity: String,
    pub title: String,
    pub message: String,
    pub evidence_json: String,
    pub evidence: SecurityEventEvidence,
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
                evidence_schema_version INTEGER NOT NULL DEFAULT 1
                    CHECK (evidence_schema_version BETWEEN 1 AND 65535)
                    CHECK (typeof(evidence_schema_version) = 'integer'),
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

        ensure_evidence_schema_version_column(db).await?;
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
                evidence_schema_version,
                status, first_seen, last_seen, acknowledged_at, resolved_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 1, 'open', ?, ?, NULL, NULL)
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
                evidence_schema_version = excluded.evidence_schema_version,
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
                evidence_schema_version,
                status, first_seen, last_seen, acknowledged_at, resolved_at
            )
            VALUES (?, 'ssh.untrusted_source_ip', 'high', ?, ?, ?, 1, 'open', ?, ?, NULL, NULL)
            ON CONFLICT(event_key) DO UPDATE SET
                event_type = excluded.event_type,
                severity = excluded.severity,
                title = excluded.title,
                message = excluded.message,
                evidence_json = excluded.evidence_json,
                evidence_schema_version = excluded.evidence_schema_version,
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
                let query = format!(
                    "{SECURITY_EVENT_LIST_COLUMNS}
                     WHERE status IN ('open', 'acknowledged')
                     ORDER BY last_seen DESC
                     LIMIT ?"
                );
                sqlx::query(&query)
                    .bind(MAX_STORED_EVIDENCE_BYTES as i64)
                    .bind(MAX_STORED_EVIDENCE_BYTES as i64)
                    .bind(limit)
                    .fetch_all(&self.db)
                    .await?
            }
            Some("open") | Some("acknowledged") | Some("resolved") => {
                let query = format!(
                    "{SECURITY_EVENT_LIST_COLUMNS}
                     WHERE status = ?
                     ORDER BY last_seen DESC
                     LIMIT ?"
                );
                sqlx::query(&query)
                    .bind(MAX_STORED_EVIDENCE_BYTES as i64)
                    .bind(MAX_STORED_EVIDENCE_BYTES as i64)
                    .bind(status.unwrap_or_default())
                    .bind(limit)
                    .fetch_all(&self.db)
                    .await?
            }
            _ => {
                let query = format!(
                    "{SECURITY_EVENT_LIST_COLUMNS}
                     ORDER BY last_seen DESC
                     LIMIT ?"
                );
                sqlx::query(&query)
                    .bind(MAX_STORED_EVIDENCE_BYTES as i64)
                    .bind(MAX_STORED_EVIDENCE_BYTES as i64)
                    .bind(limit)
                    .fetch_all(&self.db)
                    .await?
            }
        };

        rows.into_iter().map(Self::event_from_row).collect()
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

    fn event_from_row(row: sqlx::sqlite::SqliteRow) -> Result<SecurityEvent, sqlx::Error> {
        let event_type: String = row.try_get("event_type")?;
        let stored_evidence: Option<Vec<u8>> = row.try_get("bounded_evidence_bytes")?;
        let evidence_payload_invalid: i64 = row.try_get("evidence_payload_invalid")?;
        let evidence_schema_version: i64 = row.try_get("evidence_schema_version")?;
        let (evidence_json, evidence) = if evidence_schema_version
            != CURRENT_EVIDENCE_SCHEMA_VERSION
        {
            invalid_evidence_projection(
                evidence_schema_version,
                &event_type,
                SecurityEventEvidenceErrorCode::UnsupportedSchemaVersion,
            )
        } else if evidence_payload_invalid == 0 {
            match stored_evidence.and_then(|stored| String::from_utf8(stored).ok()) {
                Some(stored_evidence) => {
                    project_stored_evidence(evidence_schema_version, &event_type, &stored_evidence)
                }
                None => invalid_evidence_projection(
                    evidence_schema_version,
                    &event_type,
                    SecurityEventEvidenceErrorCode::InvalidStoredPayload,
                ),
            }
        } else {
            invalid_evidence_projection(
                evidence_schema_version,
                &event_type,
                SecurityEventEvidenceErrorCode::InvalidStoredPayload,
            )
        };

        Ok(SecurityEvent {
            id: row.try_get("id")?,
            event_key: row.try_get("event_key")?,
            event_type,
            severity: row.try_get("severity")?,
            title: row.try_get("title")?,
            message: row.try_get("message")?,
            evidence_json,
            evidence,
            status: row.try_get("status")?,
            first_seen: row.try_get("first_seen")?,
            last_seen: row.try_get("last_seen")?,
            acknowledged_at: row.try_get("acknowledged_at")?,
            resolved_at: row.try_get("resolved_at")?,
            notification_delivery_status: row.try_get("notification_delivery_status")?,
            notification_delivery_attempts: row.try_get("notification_delivery_attempts")?,
            notification_delivery_updated_at: row.try_get("notification_delivery_updated_at")?,
            notification_delivery_error_code: row.try_get("notification_delivery_error_code")?,
        })
    }
}

fn project_stored_evidence(
    schema_version: i64,
    event_type: &str,
    stored_evidence: &str,
) -> (String, SecurityEventEvidence) {
    if schema_version != CURRENT_EVIDENCE_SCHEMA_VERSION {
        return invalid_evidence_projection(
            schema_version,
            event_type,
            SecurityEventEvidenceErrorCode::UnsupportedSchemaVersion,
        );
    }

    if stored_evidence.len() > MAX_STORED_EVIDENCE_BYTES {
        return invalid_evidence_projection(
            schema_version,
            event_type,
            SecurityEventEvidenceErrorCode::InvalidStoredPayload,
        );
    }

    let known = match event_type {
        "audit.check_failed" => parse_audit_evidence(event_type, stored_evidence).map(|data| {
            KnownSecurityEventEvidenceV1::AuditCheckFailed {
                data,
                error_code: (),
            }
        }),
        "audit.check_warning" => parse_audit_evidence(event_type, stored_evidence).map(|data| {
            KnownSecurityEventEvidenceV1::AuditCheckWarning {
                data,
                error_code: (),
            }
        }),
        "ssh.untrusted_source_ip" => parse_ssh_evidence(stored_evidence).map(|data| {
            KnownSecurityEventEvidenceV1::SshUntrustedSourceIp {
                data,
                error_code: (),
            }
        }),
        "notification.delivery_degraded" => {
            parse_notification_delivery_degraded_evidence(stored_evidence).map(|data| {
                KnownSecurityEventEvidenceV1::NotificationDeliveryDegraded {
                    data,
                    error_code: (),
                }
            })
        }
        "file.sensitive_changed" => {
            parse_file_sensitive_changed_evidence(stored_evidence).map(|data| {
                KnownSecurityEventEvidenceV1::FileSensitiveChanged {
                    data,
                    error_code: (),
                }
            })
        }
        _ => None,
    };

    let Some(known) = known else {
        return invalid_evidence_projection(
            schema_version,
            event_type,
            SecurityEventEvidenceErrorCode::InvalidStoredPayload,
        );
    };
    let evidence_json = known.data_json();
    let Ok(evidence_json) = evidence_json else {
        return invalid_evidence_projection(
            schema_version,
            event_type,
            SecurityEventEvidenceErrorCode::InvalidStoredPayload,
        );
    };

    (
        evidence_json,
        SecurityEventEvidence(SecurityEventEvidenceProjection::Known(
            KnownSecurityEventEvidence {
                schema_version,
                kind: known,
            },
        )),
    )
}

fn invalid_evidence_projection(
    schema_version: i64,
    event_type: &str,
    error_code: SecurityEventEvidenceErrorCode,
) -> (String, SecurityEventEvidence) {
    (
        "{}".to_string(),
        SecurityEventEvidence(SecurityEventEvidenceProjection::Unavailable(
            UnavailableSecurityEventEvidence {
                schema_version,
                kind: event_type.to_string(),
                data: (),
                error_code,
            },
        )),
    )
}

fn parse_audit_evidence(event_type: &str, stored: &str) -> Option<AuditEventEvidenceV1> {
    let evidence: AuditEventEvidenceV1 = serde_json::from_str(stored).ok()?;
    if !valid_machine_identifier(&evidence.check_id, MAX_AUDIT_IDENTIFIER_BYTES)
        || !valid_machine_identifier(&evidence.category, MAX_AUDIT_CATEGORY_BYTES)
        || !valid_bounded_text(&evidence.remediation, MAX_AUDIT_REMEDIATION_BYTES, true)
        || contains_private_legacy_marker(&evidence.remediation)
        || !valid_bounded_string_list(
            &evidence.evidence,
            MAX_AUDIT_EVIDENCE_ITEMS,
            MAX_AUDIT_EVIDENCE_BYTES,
        )
        || !valid_audit_metadata(&evidence.metadata)
    {
        return None;
    }

    let status_is_valid = match event_type {
        // An active failed event deliberately retains its machine identity when
        // the latest observation is WARN, until the check resolves to PASS.
        "audit.check_failed" => matches!(evidence.status.as_str(), "FAIL" | "WARN"),
        "audit.check_warning" => evidence.status == "WARN",
        _ => false,
    };
    status_is_valid.then_some(evidence)
}

fn parse_ssh_evidence(stored: &str) -> Option<SshEventEvidenceV1> {
    let evidence: SshEventEvidenceV1 = serde_json::from_str(stored).ok()?;
    let ip = evidence.ip.parse::<IpAddr>().ok()?;
    if evidence.ip != ip.to_string()
        || evidence.baseline != "trusted_ips"
        || !matches!(
            evidence.method.as_str(),
            "ssh" | "password" | "publickey" | "keyboard-interactive" | "unknown"
        )
        || !valid_bounded_text(&evidence.user, 64, false)
        || contains_private_legacy_marker(&evidence.user)
        || evidence.timestamp < 0
        || evidence.timestamp > 253_402_300_799
    {
        return None;
    }
    Some(evidence)
}

fn parse_notification_delivery_degraded_evidence(
    stored: &str,
) -> Option<NotificationDeliveryDegradedEvidenceV1> {
    let evidence: NotificationDeliveryDegradedEvidenceV1 = serde_json::from_str(stored).ok()?;
    if evidence.reason != "backpressure"
        || evidence.live_limit != 1_000
        || evidence.terminal_limit != 200
    {
        return None;
    }
    Some(evidence)
}

fn parse_file_sensitive_changed_evidence(stored: &str) -> Option<FileSensitiveChangedEvidenceV1> {
    let evidence: FileSensitiveChangedEvidenceV1 = serde_json::from_str(stored).ok()?;
    let observation_failed = evidence.observation_error.is_some();
    if !valid_file_path_id(&evidence.path_id)
        || !valid_logical_file_path(&evidence.logical_path)
        || evidence.change_kinds.is_empty()
        || evidence.change_kinds.len() > 7
        || !evidence
            .change_kinds
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || evidence.baseline_generation > JS_MAX_SAFE_INTEGER
        || evidence.observed_generation > JS_MAX_SAFE_INTEGER
        || !(0..=MAX_FILE_TIMESTAMP).contains(&evidence.observed_at)
        || !valid_file_evidence_metadata(&evidence.baseline_metadata, false)
        || !valid_file_evidence_metadata(&evidence.observed_metadata, observation_failed)
    {
        return None;
    }
    Some(evidence)
}

fn valid_file_path_id(path_id: &str) -> bool {
    let Some(digest) = path_id.strip_prefix("path-v1:") else {
        return false;
    };
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_logical_file_path(path: &str) -> bool {
    const FIXED_PATHS: &[&str] = &[
        "/etc/passwd",
        "/etc/group",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/crontab",
    ];
    const DIRECT_CHILD_ROOTS: &[&str] = &[
        "/etc/sudoers.d/",
        "/etc/ssh/sshd_config.d/",
        "/etc/cron.d/",
        "/etc/cron.daily/",
        "/etc/cron.hourly/",
        "/etc/cron.weekly/",
    ];

    if path.len() < 2
        || path.len() > 1024
        || !path.starts_with('/')
        || path.ends_with('/')
        || path.chars().any(char::is_control)
        || !path
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
    {
        return false;
    }
    FIXED_PATHS.contains(&path)
        || DIRECT_CHILD_ROOTS.iter().any(|root| {
            path.strip_prefix(root)
                .map(|basename| {
                    !basename.is_empty()
                        && basename.len() <= 255
                        && !basename.contains('/')
                        && !matches!(basename, "." | "..")
                        && !basename.chars().any(char::is_control)
                })
                .unwrap_or(false)
        })
}

fn valid_file_evidence_metadata(
    metadata: &FileEvidenceMetadataV1,
    allow_partial_regular: bool,
) -> bool {
    let fields_are_bounded = metadata
        .size_bytes
        .map(|size| size <= JS_MAX_SAFE_INTEGER)
        .unwrap_or(true)
        && metadata
            .mtime_unix_seconds
            .map(|mtime| (0..=MAX_FILE_TIMESTAMP).contains(&mtime))
            .unwrap_or(true)
        && metadata.mode.map(|mode| mode <= 0o7777).unwrap_or(true);
    if !fields_are_bounded {
        return false;
    }

    let all_metadata_absent = metadata.size_bytes.is_none()
        && metadata.mtime_unix_seconds.is_none()
        && metadata.mode.is_none()
        && metadata.uid.is_none()
        && metadata.gid.is_none();
    match metadata.state {
        FileEvidenceStateV1::Absent => all_metadata_absent,
        FileEvidenceStateV1::Regular => {
            allow_partial_regular
                || (metadata.size_bytes.is_some()
                    && metadata.mtime_unix_seconds.is_some()
                    && metadata.mode.is_some()
                    && metadata.uid.is_some()
                    && metadata.gid.is_some())
        }
    }
}

fn valid_machine_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_bounded_text(value: &str, max_bytes: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.trim().is_empty())
        && value.len() <= max_bytes
        && !value.chars().any(char::is_control)
}

fn valid_bounded_string_list(values: &[String], max_items: usize, max_bytes: usize) -> bool {
    if values.len() > max_items {
        return false;
    }
    let mut total_bytes = 0usize;
    for value in values {
        if !valid_bounded_text(value, max_bytes, false) || contains_private_legacy_marker(value) {
            return false;
        }
        total_bytes = match total_bytes.checked_add(value.len()) {
            Some(total) if total <= max_bytes => total,
            _ => return false,
        };
    }
    true
}

fn valid_audit_metadata(metadata: &BTreeMap<String, Vec<String>>) -> bool {
    if metadata.len() > MAX_AUDIT_METADATA_KEYS {
        return false;
    }
    let mut total_bytes = 0usize;
    for (key, values) in metadata {
        if !is_allowed_audit_metadata_key(key)
            || values.len() > MAX_AUDIT_METADATA_ITEMS
            || values
                .iter()
                .any(|value| !valid_bounded_text(value, 1024, false))
        {
            return false;
        }
        let values_bytes = values
            .iter()
            .try_fold(0usize, |total, value| total.checked_add(value.len()));
        let Some(values_bytes) = values_bytes else {
            return false;
        };
        if values_bytes > MAX_AUDIT_METADATA_VALUE_BYTES {
            return false;
        }
        total_bytes = match total_bytes
            .checked_add(key.len())
            .and_then(|total| total.checked_add(values_bytes))
        {
            Some(total) if total <= MAX_AUDIT_METADATA_TOTAL_BYTES => total,
            _ => return false,
        };

        if !valid_audit_metadata_values(key, values) {
            return false;
        }
    }
    true
}

fn is_allowed_audit_metadata_key(key: &str) -> bool {
    matches!(
        key,
        "suspicious_ports"
            | "unexpected_listeners"
            | "open_ports"
            | "listeners"
            | "loopback_listeners"
            | "non_loopback_listeners"
            | "wildcard_listeners"
            | "allowed_public_ports"
            | "allowed_loopback_ports"
            | "invalid_allowed_port_count"
            | "public_listeners"
            | "risk_count"
            | "critical_risks"
            | "high_risks"
            | "medium_risks"
            | "low_risks"
            | "info_risks"
    )
}

fn valid_audit_metadata_values(key: &str, values: &[String]) -> bool {
    if values
        .iter()
        .any(|value| contains_private_legacy_marker(value))
    {
        return false;
    }

    match key {
        "suspicious_ports" | "open_ports" | "allowed_public_ports" | "allowed_loopback_ports" => {
            values.iter().all(|value| {
                value
                    .parse::<u16>()
                    .map(|port| port != 0 && value == &port.to_string())
                    .unwrap_or(false)
            })
        }
        "invalid_allowed_port_count" | "risk_count" => {
            matches!(values, [value] if value.parse::<u64>()
                .map(|count| count <= 1_000_000 && value == &count.to_string())
                .unwrap_or(false))
        }
        _ => true,
    }
}

fn contains_private_legacy_marker(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    [
        "command_output=",
        "raw_command=",
        "raw_error=",
        "sql_error=",
        "stdout=",
        "stderr=",
        "contents=",
        "content_digest=",
        "excerpt=",
        "symlink_target=",
    ]
    .iter()
    .any(|marker| value.contains(marker))
}

async fn ensure_evidence_schema_version_column(db: &SqlitePool) -> Result<(), sqlx::Error> {
    let mut transaction = db.begin_with("BEGIN IMMEDIATE").await?;
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('security_events')
         WHERE name = 'evidence_schema_version'",
    )
    .fetch_one(&mut *transaction)
    .await?;
    if exists == 0 {
        sqlx::query(
            "ALTER TABLE security_events
             ADD COLUMN evidence_schema_version INTEGER NOT NULL DEFAULT 1
             CHECK (evidence_schema_version BETWEEN 1 AND 65535)
             CHECK (typeof(evidence_schema_version) = 'integer')",
        )
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await
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

    fn valid_file_evidence_payload() -> serde_json::Value {
        serde_json::json!({
            "path_id": format!("path-v1:{}", "a".repeat(64)),
            "logical_path": "/etc/passwd",
            "change_kinds": ["content_changed", "permissions_changed"],
            "baseline_generation": 1,
            "observed_generation": 2,
            "baseline_metadata": {
                "state": "regular",
                "size_bytes": 2048,
                "mtime_unix_seconds": 1_700_000_000_i64,
                "mode": 420,
                "uid": 0,
                "gid": 0,
            },
            "observed_metadata": {
                "state": "regular",
                "size_bytes": 2049,
                "mtime_unix_seconds": 1_700_000_001_i64,
                "mode": 384,
                "uid": 0,
                "gid": 0,
            },
            "observed_at": 1_700_000_002_i64,
            "observation_error": null,
        })
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

    async fn insert_stored_event(
        service: &SecurityEventService,
        event_key: &str,
        event_type: &str,
        evidence_json: &str,
        evidence_schema_version: i64,
    ) {
        sqlx::query(
            "INSERT INTO security_events (
                event_key, event_type, severity, title, message, evidence_json,
                evidence_schema_version, status, first_seen, last_seen
             ) VALUES (?, ?, 'high', 'fixture', 'fixture', ?, ?, 'open', 1, 1)",
        )
        .bind(event_key)
        .bind(event_type)
        .bind(evidence_json)
        .bind(evidence_schema_version)
        .execute(&service.db)
        .await
        .expect("stored event fixture should insert");
    }

    fn assert_valid_evidence(event: &SecurityEvent) -> serde_json::Value {
        let envelope = serde_json::to_value(&event.evidence)
            .expect("typed evidence envelope should serialize");
        assert_eq!(envelope["schema_version"], 1);
        assert_eq!(envelope["kind"], event.event_type);
        assert!(envelope["error_code"].is_null());
        assert!(envelope["data"].is_object());
        let data = envelope["data"].clone();
        let legacy: serde_json::Value =
            serde_json::from_str(&event.evidence_json).expect("legacy evidence should be JSON");
        assert_eq!(legacy, data);
        let SecurityEventEvidenceProjection::Known(known) = &event.evidence.0 else {
            panic!("known v1 event should use the kind-coupled Rust variant");
        };
        assert_eq!(
            event.evidence_json,
            known
                .kind
                .data_json()
                .expect("typed evidence should serialize exactly")
        );
        let public = serde_json::to_value(event).expect("event should serialize");
        assert_eq!(public["evidence"]["data"], data);
        assert!(public["evidence"]["error_code"].is_null());
        data
    }

    fn assert_unavailable_evidence(
        event: &SecurityEvent,
        schema_version: i64,
        kind: &str,
        error_code: SecurityEventEvidenceErrorCode,
    ) {
        let envelope = serde_json::to_value(&event.evidence)
            .expect("unavailable evidence envelope should serialize");
        assert_eq!(envelope["schema_version"], schema_version);
        assert_eq!(envelope["kind"], kind);
        assert!(envelope["data"].is_null());
        assert_eq!(
            envelope["error_code"],
            serde_json::to_value(error_code).unwrap()
        );
        assert_eq!(event.evidence_json, "{}");
        assert!(matches!(
            event.evidence.0,
            SecurityEventEvidenceProjection::Unavailable(_)
        ));
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
    async fn schema_upgrade_is_additive_idempotent_and_does_not_backfill_delivery() {
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
        SecurityEventService::init_schema(&pool).await.unwrap();
        let row = sqlx::query(
            "SELECT id, evidence_json, evidence_schema_version,
                    notification_seq, notification_delivery_status,
                    notification_delivery_attempts,
                    notification_delivery_updated_at,
                    notification_delivery_error_code
             FROM security_events WHERE event_key = 'legacy'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.get::<i64, _>("id"), 1);
        assert_eq!(row.get::<String, _>("evidence_json"), "{}");
        assert_eq!(row.get::<i64, _>("evidence_schema_version"), 1);
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

        let table_sql: String = sqlx::query_scalar(
            "SELECT sql FROM sqlite_master
             WHERE type = 'table' AND name = 'security_events'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(table_sql.contains("evidence_schema_version INTEGER NOT NULL DEFAULT 1"));
        assert!(table_sql.contains("evidence_schema_version BETWEEN 1 AND 65535"));
        assert!(table_sql.contains("typeof(evidence_schema_version) = 'integer'"));
        for invalid_version in [0_i64, 65_536] {
            assert!(
                sqlx::query("UPDATE security_events SET evidence_schema_version = ? WHERE id = 1",)
                    .bind(invalid_version)
                    .execute(&pool)
                    .await
                    .is_err()
            );
        }
        assert!(
            sqlx::query("UPDATE security_events SET evidence_schema_version = 1.5 WHERE id = 1")
                .execute(&pool)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn all_frozen_v1_evidence_kinds_project_as_typed_data() {
        let service = test_service().await;
        let failed = failed_check();
        assert!(service.raise_audit_event(&failed).await.unwrap());
        assert!(
            service
                .raise_ssh_source_ip_event("root", "2001:db8::10", "publickey", 1_700_000_000,)
                .await
                .unwrap()
        );
        insert_stored_event(
            &service,
            "notification:delivery_degraded",
            "notification.delivery_degraded",
            r#"{"reason":"backpressure","live_limit":1000,"terminal_limit":200}"#,
            1,
        )
        .await;
        let file_payload = valid_file_evidence_payload().to_string();
        insert_stored_event(
            &service,
            "file:sensitive_changed:path-v1:fixture",
            "file.sensitive_changed",
            &file_payload,
            1,
        )
        .await;

        let events = service.list(None, 10).await.unwrap();
        assert_eq!(events.len(), 4);

        let audit = events
            .iter()
            .find(|event| event.event_type == "audit.check_failed")
            .expect("audit event should exist");
        let audit_data = assert_valid_evidence(audit);
        assert_eq!(audit_data["check_id"], failed.id);
        assert_eq!(audit_data["status"], "FAIL");
        assert_eq!(audit_data["evidence"], serde_json::json!(["evidence=true"]));

        let ssh = events
            .iter()
            .find(|event| event.event_type == "ssh.untrusted_source_ip")
            .expect("SSH event should exist");
        let ssh_data = assert_valid_evidence(ssh);
        assert_eq!(ssh_data["ip"], "2001:db8::10");
        assert_eq!(ssh_data["method"], "publickey");
        assert_eq!(ssh_data["baseline"], "trusted_ips");

        let delivery = events
            .iter()
            .find(|event| event.event_type == "notification.delivery_degraded")
            .expect("delivery event should exist");
        let delivery_data = assert_valid_evidence(delivery);
        assert_eq!(delivery_data["reason"], "backpressure");
        assert_eq!(delivery_data["live_limit"], 1_000);
        assert_eq!(delivery_data["terminal_limit"], 200);

        let file = events
            .iter()
            .find(|event| event.event_type == "file.sensitive_changed")
            .expect("file evidence groundwork fixture should exist");
        let file_data = assert_valid_evidence(file);
        assert_eq!(file_data["logical_path"], "/etc/passwd");
        assert_eq!(
            file_data["change_kinds"],
            serde_json::json!(["content_changed", "permissions_changed"])
        );
        assert_eq!(file_data["baseline_metadata"]["mode"], 420);
        assert_eq!(file_data["observed_metadata"]["mode"], 384);
    }

    #[test]
    fn per_kind_v1_validation_rejects_unknown_fields_types_ranges_and_controls() {
        let valid_audit = serde_json::json!({
            "check_id": "test.failure",
            "category": "test",
            "status": "FAIL",
            "evidence": ["probe_error=timeout"],
            "remediation": "Fix it",
            "metadata": {"open_ports": ["22"]},
        });
        let invalid_audit_payloads = [
            serde_json::json!({
                "check_id": "test.failure",
                "category": "test",
                "status": "FAIL",
                "evidence": [],
                "remediation": "raw_error=REMEDIATION_SECRET_SENTINEL",
                "metadata": {},
            }),
            serde_json::json!({
                "check_id": "test.failure",
                "category": "test",
                "status": "FAIL",
                "evidence": [],
                "remediation": "Fix it",
                "metadata": {},
                "stderr": "RAW_SENTINEL",
            }),
            serde_json::json!({
                "check_id": "test.failure",
                "category": "test",
                "status": "PASS",
                "evidence": [],
                "remediation": "Fix it",
                "metadata": {},
            }),
            serde_json::json!({
                "check_id": "test.failure",
                "category": "test",
                "status": "FAIL",
                "evidence": ["line\nbreak"],
                "remediation": "Fix it",
                "metadata": {},
            }),
            serde_json::json!({
                "check_id": "test.failure",
                "category": "test",
                "status": "FAIL",
                "evidence": [],
                "remediation": "Fix it",
                "metadata": {"items": ["test-only key"]},
            }),
            serde_json::json!({
                "check_id": "test.failure",
                "category": "test",
                "status": "FAIL",
                "evidence": [],
                "remediation": "Fix it",
                "metadata": {"open_ports": ["0"]},
            }),
        ];
        assert!(parse_audit_evidence("audit.check_failed", &valid_audit.to_string()).is_some());
        for payload in invalid_audit_payloads {
            assert!(
                parse_audit_evidence("audit.check_failed", &payload.to_string()).is_none(),
                "unexpected valid audit payload: {payload}"
            );
        }
        let private_remediation = serde_json::json!({
            "check_id": "test.failure",
            "category": "test",
            "status": "FAIL",
            "evidence": [],
            "remediation": "raw_error=REMEDIATION_SECRET_SENTINEL",
            "metadata": {},
        });
        let (legacy, envelope) =
            project_stored_evidence(1, "audit.check_failed", &private_remediation.to_string());
        assert_eq!(legacy, "{}");
        let public = serde_json::to_string(&envelope).unwrap();
        assert!(public.contains("invalid_stored_payload"));
        assert!(!public.contains("REMEDIATION_SECRET_SENTINEL"));

        let valid_ssh = serde_json::json!({
            "user": "root",
            "ip": "203.0.113.10",
            "method": "publickey",
            "timestamp": 1_700_000_000_i64,
            "baseline": "trusted_ips",
        });
        assert!(parse_ssh_evidence(&valid_ssh.to_string()).is_some());
        for payload in [
            serde_json::json!({
                "user": "raw_error=SSH_SECRET_SENTINEL",
                "ip": "203.0.113.10",
                "method": "publickey",
                "timestamp": 1_700_000_000_i64,
                "baseline": "trusted_ips",
            }),
            serde_json::json!({
                "user": "root",
                "ip": "2001:0db8:0:0:0:0:0:10",
                "method": "publickey",
                "timestamp": 1_700_000_000_i64,
                "baseline": "trusted_ips",
            }),
            serde_json::json!({
                "user": "root",
                "ip": "203.0.113.10",
                "method": "raw-command",
                "timestamp": 1_700_000_000_i64,
                "baseline": "trusted_ips",
            }),
            serde_json::json!({
                "user": "root",
                "ip": "203.0.113.10",
                "method": "publickey",
                "timestamp": -1,
                "baseline": "trusted_ips",
            }),
        ] {
            assert!(parse_ssh_evidence(&payload.to_string()).is_none());
        }

        assert!(
            parse_notification_delivery_degraded_evidence(
                r#"{"reason":"backpressure","live_limit":1000,"terminal_limit":200}"#,
            )
            .is_some()
        );
        for payload in [
            r#"{"reason":"backpressure","live_limit":999,"terminal_limit":200}"#,
            r#"{"reason":"database","live_limit":1000,"terminal_limit":200}"#,
            r#"{"reason":"backpressure","live_limit":1000,"terminal_limit":200,"error":"RAW_SENTINEL"}"#,
        ] {
            assert!(parse_notification_delivery_degraded_evidence(payload).is_none());
        }
    }

    #[test]
    fn file_evidence_v1_accepts_only_frozen_paths_changes_and_error_codes() {
        for path in [
            "/etc/passwd",
            "/etc/group",
            "/etc/sudoers",
            "/etc/ssh/sshd_config",
            "/etc/crontab",
            "/etc/sudoers.d/90-cloud-init-users",
            "/etc/ssh/sshd_config.d/20-mini-ops.conf",
            "/etc/cron.d/mini-ops",
            "/etc/cron.daily/cleanup",
            "/etc/cron.hourly/metrics",
            "/etc/cron.weekly/report",
        ] {
            let mut payload = valid_file_evidence_payload();
            payload["logical_path"] = serde_json::json!(path);
            assert!(
                parse_file_sensitive_changed_evidence(&payload.to_string()).is_some(),
                "frozen path should be accepted: {path}"
            );
        }

        let long_basename = format!("/etc/cron.d/{}", "x".repeat(256));
        for path in [
            "/",
            "etc/passwd",
            "/etc",
            "/etc/passwd/child",
            "/etc/sudoers.d",
            "/etc/sudoers.d/",
            "/etc/sudoers.d/nested/child",
            "/etc/sudoers.d/../passwd",
            "/etc//passwd",
            "/root/.ssh/authorized_keys",
            "/home/operator/.ssh/authorized_keys",
            "/etc/cron.d/bad\nname",
            long_basename.as_str(),
        ] {
            let mut payload = valid_file_evidence_payload();
            payload["logical_path"] = serde_json::json!(path);
            assert!(
                parse_file_sensitive_changed_evidence(&payload.to_string()).is_none(),
                "path outside frozen direct-file coverage must be rejected: {path:?}"
            );
        }

        let mut all_changes = valid_file_evidence_payload();
        all_changes["change_kinds"] = serde_json::json!([
            "added",
            "content_changed",
            "owner_changed",
            "permissions_changed",
            "removed",
            "type_changed",
            "unreadable",
        ]);
        assert!(parse_file_sensitive_changed_evidence(&all_changes.to_string()).is_some());
        for changes in [
            serde_json::json!([]),
            serde_json::json!(["permissions_changed", "content_changed"]),
            serde_json::json!(["content_changed", "content_changed"]),
            serde_json::json!(["content_changed", "digest_changed"]),
        ] {
            let mut payload = valid_file_evidence_payload();
            payload["change_kinds"] = changes;
            assert!(parse_file_sensitive_changed_evidence(&payload.to_string()).is_none());
        }

        for error in [
            "permission_denied",
            "symlink",
            "not_regular",
            "file_too_large",
            "tracked_file_limit",
            "scan_byte_limit",
            "deadline_exceeded",
            "changed_during_read",
            "vanished_during_scan",
            "directory_unreadable",
            "path_not_utf8",
            "path_too_long",
            "io_error",
        ] {
            let mut payload = valid_file_evidence_payload();
            payload["observation_error"] = serde_json::json!(error);
            for field in ["size_bytes", "mtime_unix_seconds", "mode", "uid", "gid"] {
                payload["observed_metadata"][field] = serde_json::Value::Null;
            }
            assert!(
                parse_file_sensitive_changed_evidence(&payload.to_string()).is_some(),
                "closed observation error should be accepted: {error}"
            );
        }
        let mut unknown_error = valid_file_evidence_payload();
        unknown_error["observation_error"] = serde_json::json!("raw_io_error");
        assert!(parse_file_sensitive_changed_evidence(&unknown_error.to_string()).is_none());
    }

    #[test]
    fn file_evidence_v1_enforces_numeric_metadata_and_privacy_bounds() {
        let mut absent = valid_file_evidence_payload();
        absent["baseline_metadata"]["state"] = serde_json::json!("absent");
        for field in ["size_bytes", "mtime_unix_seconds", "mode", "uid", "gid"] {
            absent["baseline_metadata"][field] = serde_json::Value::Null;
        }
        assert!(parse_file_sensitive_changed_evidence(&absent.to_string()).is_some());

        let mut partial_observed = valid_file_evidence_payload();
        partial_observed["observation_error"] = serde_json::json!("permission_denied");
        for field in ["size_bytes", "mtime_unix_seconds", "mode", "uid", "gid"] {
            partial_observed["observed_metadata"][field] = serde_json::Value::Null;
        }
        assert!(parse_file_sensitive_changed_evidence(&partial_observed.to_string()).is_some());

        let mut invalid_payloads = Vec::new();
        let mut bad_path_id = valid_file_evidence_payload();
        bad_path_id["path_id"] = serde_json::json!(format!("path-v1:{}", "A".repeat(64)));
        invalid_payloads.push(bad_path_id);

        let mut large_baseline_generation = valid_file_evidence_payload();
        large_baseline_generation["baseline_generation"] =
            serde_json::json!(JS_MAX_SAFE_INTEGER + 1);
        invalid_payloads.push(large_baseline_generation);

        let mut large_observed_generation = valid_file_evidence_payload();
        large_observed_generation["observed_generation"] =
            serde_json::json!(JS_MAX_SAFE_INTEGER + 1);
        invalid_payloads.push(large_observed_generation);

        let mut bad_observed_at = valid_file_evidence_payload();
        bad_observed_at["observed_at"] = serde_json::json!(-1);
        invalid_payloads.push(bad_observed_at);

        let mut large_size = valid_file_evidence_payload();
        large_size["observed_metadata"]["size_bytes"] = serde_json::json!(JS_MAX_SAFE_INTEGER + 1);
        invalid_payloads.push(large_size);

        let mut negative_mtime = valid_file_evidence_payload();
        negative_mtime["observed_metadata"]["mtime_unix_seconds"] = serde_json::json!(-1);
        invalid_payloads.push(negative_mtime);

        let mut future_mtime = valid_file_evidence_payload();
        future_mtime["observed_metadata"]["mtime_unix_seconds"] =
            serde_json::json!(MAX_FILE_TIMESTAMP + 1);
        invalid_payloads.push(future_mtime);

        let mut large_mode = valid_file_evidence_payload();
        large_mode["observed_metadata"]["mode"] = serde_json::json!(0o10000);
        invalid_payloads.push(large_mode);

        let mut large_uid = valid_file_evidence_payload();
        large_uid["observed_metadata"]["uid"] = serde_json::json!(u64::from(u32::MAX) + 1);
        invalid_payloads.push(large_uid);

        let mut absent_with_metadata = absent.clone();
        absent_with_metadata["baseline_metadata"]["size_bytes"] = serde_json::json!(0);
        invalid_payloads.push(absent_with_metadata);

        let mut partial_baseline = valid_file_evidence_payload();
        partial_baseline["observation_error"] = serde_json::json!("permission_denied");
        partial_baseline["baseline_metadata"]["size_bytes"] = serde_json::Value::Null;
        invalid_payloads.push(partial_baseline);

        let mut partial_without_error = valid_file_evidence_payload();
        partial_without_error["observed_metadata"]["size_bytes"] = serde_json::Value::Null;
        invalid_payloads.push(partial_without_error);

        let sentinel = "RAW_FILE_CONTENT_SENTINEL";
        let mut raw_content = valid_file_evidence_payload();
        raw_content["content_digest"] = serde_json::json!(sentinel);
        invalid_payloads.push(raw_content.clone());

        let mut nested_digest = valid_file_evidence_payload();
        nested_digest["observed_metadata"]["digest"] = serde_json::json!(sentinel);
        invalid_payloads.push(nested_digest);

        for payload in invalid_payloads {
            assert!(
                parse_file_sensitive_changed_evidence(&payload.to_string()).is_none(),
                "invalid file evidence unexpectedly passed: {payload}"
            );
        }

        let (legacy, envelope) =
            project_stored_evidence(1, "file.sensitive_changed", &raw_content.to_string());
        assert_eq!(legacy, "{}");
        let public = serde_json::to_string(&envelope).unwrap();
        assert!(!public.contains(sentinel));
        assert!(public.contains("invalid_stored_payload"));
    }

    #[tokio::test]
    async fn invalid_and_unsupported_evidence_is_sanitized_per_row_without_db_rewrite() {
        let service = test_service().await;
        let sentinel = "RAW_EVIDENCE_SENTINEL";
        let invalid_payload = serde_json::json!({
            "check_id": "test.invalid",
            "category": "test",
            "status": "FAIL",
            "evidence": [],
            "remediation": "Fix it",
            "metadata": {},
            "stdout": sentinel,
        })
        .to_string();
        insert_stored_event(
            &service,
            "fixture:invalid",
            "audit.check_failed",
            &invalid_payload,
            1,
        )
        .await;
        insert_stored_event(&service, "fixture:unsupported", "future.event", sentinel, 2).await;
        let valid_payload = SecurityEventService::audit_evidence_json(&failed_check());
        insert_stored_event(
            &service,
            "fixture:valid",
            "audit.check_failed",
            &valid_payload,
            1,
        )
        .await;

        let events = service.list(None, 10).await.unwrap();
        assert_eq!(events.len(), 3, "one bad row must not fail the list");
        assert_valid_evidence(
            events
                .iter()
                .find(|event| event.event_key == "fixture:valid")
                .expect("valid fixture should remain visible"),
        );

        let invalid = events
            .iter()
            .find(|event| event.event_key == "fixture:invalid")
            .expect("invalid fixture should remain visible");
        assert_unavailable_evidence(
            invalid,
            1,
            "audit.check_failed",
            SecurityEventEvidenceErrorCode::InvalidStoredPayload,
        );

        let unsupported = events
            .iter()
            .find(|event| event.event_key == "fixture:unsupported")
            .expect("unsupported fixture should remain visible");
        assert_unavailable_evidence(
            unsupported,
            2,
            "future.event",
            SecurityEventEvidenceErrorCode::UnsupportedSchemaVersion,
        );

        let public_json = serde_json::to_string(&events).unwrap();
        assert!(!public_json.contains(sentinel));
        let stored: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT event_key, evidence_json, evidence_schema_version
             FROM security_events WHERE event_key IN ('fixture:invalid', 'fixture:unsupported')
             ORDER BY event_key",
        )
        .fetch_all(&service.db)
        .await
        .unwrap();
        assert_eq!(
            stored,
            vec![
                ("fixture:invalid".to_string(), invalid_payload, 1),
                ("fixture:unsupported".to_string(), sentinel.to_string(), 2,),
            ]
        );
    }

    #[test]
    fn oversized_stored_evidence_is_never_projected() {
        let oversized = "x".repeat(MAX_STORED_EVIDENCE_BYTES + 1);
        let (legacy, evidence) = project_stored_evidence(1, "audit.check_failed", &oversized);
        assert_eq!(legacy, "{}");
        let envelope = serde_json::to_value(evidence).unwrap();
        assert!(envelope["data"].is_null());
        assert_eq!(envelope["error_code"], "invalid_stored_payload");
    }

    #[tokio::test]
    async fn list_bounds_multi_mib_evidence_inside_sql_before_projection() {
        assert!(!SECURITY_EVENT_LIST_COLUMNS.contains("SELECT *"));
        assert!(SECURITY_EVENT_LIST_COLUMNS.contains("bounded_evidence_bytes"));
        assert_eq!(MAX_STORED_EVIDENCE_BYTES, 65_536);

        let service = test_service().await;
        let oversized = "RAW_MULTI_MIB_SENTINEL".repeat(128 * 1024);
        let stored_len = oversized.len() as i64;
        assert!(stored_len > 2 * 1024 * 1024);
        insert_stored_event(
            &service,
            "fixture:multi-mib",
            "audit.check_failed",
            &oversized,
            1,
        )
        .await;
        drop(oversized);

        let events = service.list(None, 10).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_unavailable_evidence(
            &events[0],
            1,
            "audit.check_failed",
            SecurityEventEvidenceErrorCode::InvalidStoredPayload,
        );
        let public = serde_json::to_string(&events).unwrap();
        assert!(!public.contains("RAW_MULTI_MIB_SENTINEL"));
        assert!(public.len() < 4 * 1024);

        let persisted_len: i64 = sqlx::query_scalar(
            "SELECT length(CAST(evidence_json AS BLOB))
             FROM security_events WHERE event_key = 'fixture:multi-mib'",
        )
        .fetch_one(&service.db)
        .await
        .unwrap();
        assert_eq!(
            persisted_len, stored_len,
            "projection must not rewrite the DB row"
        );
    }

    #[tokio::test]
    async fn blob_and_invalid_utf8_text_are_sanitized_without_rewriting_bytes() {
        let service = test_service().await;
        let blob = [vec![0xff, 0xfe, 0x00], b"RAW_BLOB_SENTINEL".to_vec()].concat();
        let blob_hex = blob
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>();
        sqlx::query(
            "INSERT INTO security_events (
                event_key, event_type, severity, title, message, evidence_json,
                evidence_schema_version, status, first_seen, last_seen
             ) VALUES (
                'fixture:blob', 'audit.check_failed', 'high', 'fixture',
                'fixture', ?, 1, 'open', 1, 1
             )",
        )
        .bind(blob)
        .execute(&service.db)
        .await
        .unwrap();
        let invalid_text = [vec![0x80, 0x81], b"RAW_TEXT_SENTINEL".to_vec()].concat();
        let invalid_text_hex = invalid_text
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>();
        sqlx::query(
            "INSERT INTO security_events (
                event_key, event_type, severity, title, message, evidence_json,
                evidence_schema_version, status, first_seen, last_seen
             ) VALUES (
                'fixture:invalid-text', 'audit.check_failed', 'high', 'fixture',
                'fixture', CAST(? AS TEXT), 1, 'open', 1, 1
             )",
        )
        .bind(invalid_text)
        .execute(&service.db)
        .await
        .unwrap();
        let invalid_text_v2 = [vec![0x82, 0x83], b"RAW_TEXT_V2_SENTINEL".to_vec()].concat();
        let invalid_text_v2_hex = invalid_text_v2
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>();
        sqlx::query(
            "INSERT INTO security_events (
                event_key, event_type, severity, title, message, evidence_json,
                evidence_schema_version, status, first_seen, last_seen
             ) VALUES (
                'fixture:invalid-text-v2', 'audit.check_failed', 'high', 'fixture',
                'fixture', CAST(? AS TEXT), 2, 'open', 1, 1
             )",
        )
        .bind(invalid_text_v2)
        .execute(&service.db)
        .await
        .unwrap();

        let events = service.list(None, 10).await.unwrap();
        assert_eq!(events.len(), 3);
        for event in &events {
            if event.event_key == "fixture:invalid-text-v2" {
                assert_unavailable_evidence(
                    event,
                    2,
                    "audit.check_failed",
                    SecurityEventEvidenceErrorCode::UnsupportedSchemaVersion,
                );
            } else {
                assert_unavailable_evidence(
                    event,
                    1,
                    "audit.check_failed",
                    SecurityEventEvidenceErrorCode::InvalidStoredPayload,
                );
            }
        }
        let public = serde_json::to_string(&events).unwrap();
        assert!(!public.contains("RAW_BLOB_SENTINEL"));
        assert!(!public.contains("RAW_TEXT_SENTINEL"));
        assert!(!public.contains("RAW_TEXT_V2_SENTINEL"));

        let stored: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT event_key, typeof(evidence_json), hex(evidence_json)
             FROM security_events
             WHERE event_key IN (
                'fixture:blob', 'fixture:invalid-text', 'fixture:invalid-text-v2'
             )
             ORDER BY event_key",
        )
        .fetch_all(&service.db)
        .await
        .unwrap();
        assert_eq!(
            stored,
            vec![
                ("fixture:blob".to_string(), "blob".to_string(), blob_hex),
                (
                    "fixture:invalid-text".to_string(),
                    "text".to_string(),
                    invalid_text_hex,
                ),
                (
                    "fixture:invalid-text-v2".to_string(),
                    "text".to_string(),
                    invalid_text_v2_hex,
                ),
            ]
        );
    }

    #[tokio::test]
    async fn current_audit_and_ssh_writers_reset_evidence_version_to_v1() {
        let service = test_service().await;
        let failed = failed_check();
        assert!(service.raise_audit_event(&failed).await.unwrap());
        sqlx::query(
            "UPDATE security_events
             SET evidence_schema_version = 2, evidence_json = '{\"future\":true}'
             WHERE event_key = ?",
        )
        .bind(SecurityEventService::audit_event_key(&failed.id))
        .execute(&service.db)
        .await
        .unwrap();
        assert!(!service.raise_audit_event(&failed).await.unwrap());

        assert!(
            service
                .raise_ssh_source_ip_event("root", "203.0.113.10", "publickey", 1_700_000_000)
                .await
                .unwrap()
        );
        sqlx::query(
            "UPDATE security_events
             SET evidence_schema_version = 2, evidence_json = '{\"future\":true}'
             WHERE event_key = ?",
        )
        .bind(SecurityEventService::ssh_source_ip_event_key(
            "203.0.113.10",
        ))
        .execute(&service.db)
        .await
        .unwrap();
        assert!(
            !service
                .raise_ssh_source_ip_event("root", "203.0.113.10", "publickey", 1_700_000_001)
                .await
                .unwrap()
        );

        let rows: Vec<(i64, String)> = sqlx::query_as(
            "SELECT evidence_schema_version, evidence_json
             FROM security_events ORDER BY event_key",
        )
        .fetch_all(&service.db)
        .await
        .unwrap();
        assert_eq!(rows.len(), 2);
        for (version, payload) in rows {
            assert_eq!(version, 1);
            assert!(!payload.contains("future"));
        }
        for event in service.list(None, 10).await.unwrap() {
            assert_valid_evidence(&event);
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
        let data = assert_valid_evidence(&active[0]);
        assert_eq!(data["status"], "WARN");

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
