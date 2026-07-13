use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
const FILE_INTEGRITY_EVENT_TOUCH_SECONDS: i64 = 60 * 60;
const FILE_INTEGRITY_PATH_DOMAIN: &[u8] = b"mini-ops:file-integrity:path:v1\0";
const FILE_INTEGRITY_COVERAGE_EVENT_KEY: &str = "file:integrity_coverage_degraded";
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
            notification_seq,
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
    #[serde(rename = "file.integrity_coverage_degraded")]
    FileIntegrityCoverageDegraded {
        data: FileIntegrityCoverageDegradedEvidenceV1,
        error_code: (),
    },
    #[serde(rename = "file.integrity_baseline_reenrolled")]
    FileIntegrityBaselineReenrolled {
        data: FileIntegrityBaselineReenrolledEvidenceV1,
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
            Self::FileIntegrityCoverageDegraded { data, .. } => serde_json::to_string(data),
            Self::FileIntegrityBaselineReenrolled { data, .. } => serde_json::to_string(data),
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
    Directory,
    Absent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileObservationErrorV1 {
    PermissionDenied,
    Symlink,
    NotRegular,
    FileTooLarge,
    ChangedDuringRead,
    VanishedDuringScan,
    IoError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FileIntegrityDegradedReasonV1 {
    CoverageUnavailable,
    LimitExceeded,
    DeadlineExceeded,
    BaselineCorrupt,
    UnsupportedAlgorithm,
    DatabaseRestoreRequired,
    InternalError,
}

impl FileIntegrityDegradedReasonV1 {
    const fn severity(self) -> &'static str {
        match self {
            Self::BaselineCorrupt
            | Self::UnsupportedAlgorithm
            | Self::DatabaseRestoreRequired
            | Self::InternalError => "high",
            Self::CoverageUnavailable | Self::LimitExceeded | Self::DeadlineExceeded => "medium",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FileIntegrityCoverageErrorCodeV1 {
    ChangedDuringRead,
    DeadlineExceeded,
    DirectoryUnreadable,
    FileTooLarge,
    FilesystemUnclassified,
    IoError,
    NetworkFilesystem,
    NoObservableTargets,
    NotRegular,
    PathNotUtf8,
    PathTooLong,
    PermissionDenied,
    ScanByteLimit,
    Symlink,
    TrackedFileLimit,
    UntrustedNewCoverage,
    VanishedDuringScan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileIntegrityCoverageErrorCountV1 {
    pub(crate) code: FileIntegrityCoverageErrorCodeV1,
    pub(crate) count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileIntegrityCoverageDegradedEvidenceV1 {
    pub(crate) degraded_reason: FileIntegrityDegradedReasonV1,
    pub(crate) state_revision: u64,
    pub(crate) baseline_generation: u64,
    pub(crate) observed_generation: u64,
    pub(crate) observation_complete: bool,
    pub(crate) observed_at: i64,
    pub(crate) tracked_file_count: u64,
    pub(crate) drift_file_count: u64,
    pub(crate) unavailable_target_count: u64,
    pub(crate) error_counts: Vec<FileIntegrityCoverageErrorCountV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FileIntegrityReenrollReasonV1 {
    BaselineCorrupt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileIntegrityBaselineReenrolledEvidenceV1 {
    pub(crate) reason: FileIntegrityReenrollReasonV1,
    pub(crate) old_baseline_generation: u64,
    pub(crate) new_baseline_generation: u64,
    pub(crate) state_revision: u64,
    pub(crate) observed_generation: u64,
    pub(crate) reenrolled_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileIntegrityDriftEventText<'a> {
    pub(crate) title: &'a str,
    pub(crate) message: &'a str,
    pub(crate) notification: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileIntegrityEventMutation {
    Noop,
    Opened,
    Reopened,
    Updated,
    HourlyTouched,
    Resolved,
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

struct StoredSecurityEventContext<'a> {
    event_key: &'a str,
    event_type: &'a str,
    severity: &'a str,
    status: &'a str,
    first_seen: i64,
    last_seen: i64,
    acknowledged_at: Option<i64>,
    resolved_at: Option<i64>,
    notification_seq: i64,
    notification_delivery_status: Option<&'a str>,
    notification_delivery_attempts: Option<i64>,
    notification_delivery_updated_at: Option<i64>,
    notification_delivery_error_code: Option<&'a str>,
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

    pub(crate) async fn upsert_file_integrity_drift_in_transaction(
        transaction: &mut Transaction<'_, Sqlite>,
        outbox: &NotificationOutbox,
        evidence: &FileSensitiveChangedEvidenceV1,
        text: FileIntegrityDriftEventText<'_>,
        material_changed: bool,
        now: i64,
    ) -> Result<FileIntegrityEventMutation, sqlx::Error> {
        validate_file_integrity_drift_input(
            evidence,
            text.title,
            text.message,
            text.notification,
            now,
        )?;
        let event_key = format!("file:sensitive_changed:{}", evidence.path_id);
        let evidence_json = serialize_integrity_evidence(evidence)?;
        let existing = sqlx::query(
            "SELECT event_type, status, last_seen
             FROM security_events WHERE event_key = ?",
        )
        .bind(&event_key)
        .fetch_optional(&mut **transaction)
        .await?;

        let (mutation, should_notify) = match existing {
            None => {
                sqlx::query(
                    "INSERT INTO security_events (
                        event_key, event_type, severity, title, message, evidence_json,
                        evidence_schema_version, status, first_seen, last_seen,
                        acknowledged_at, resolved_at
                     ) VALUES (?, 'file.sensitive_changed', 'high', ?, ?, ?, 1,
                               'open', ?, ?, NULL, NULL)",
                )
                .bind(&event_key)
                .bind(text.title)
                .bind(text.message)
                .bind(&evidence_json)
                .bind(now)
                .bind(now)
                .execute(&mut **transaction)
                .await?;
                (FileIntegrityEventMutation::Opened, true)
            }
            Some(row) => {
                let event_type: String = row.try_get("event_type")?;
                let status: String = row.try_get("status")?;
                let last_seen: i64 = row.try_get("last_seen")?;
                if event_type != "file.sensitive_changed" {
                    return Err(invalid_integrity_event_input());
                }
                match status.as_str() {
                    "resolved" => {
                        sqlx::query(
                            "UPDATE security_events
                             SET event_type = 'file.sensitive_changed', severity = 'high',
                                 title = ?, message = ?, evidence_json = ?,
                                 evidence_schema_version = 1, status = 'open',
                                 first_seen = ?, last_seen = ?, acknowledged_at = NULL,
                                 resolved_at = NULL
                             WHERE event_key = ? AND status = 'resolved'",
                        )
                        .bind(text.title)
                        .bind(text.message)
                        .bind(&evidence_json)
                        .bind(now)
                        .bind(now)
                        .bind(&event_key)
                        .execute(&mut **transaction)
                        .await?;
                        (FileIntegrityEventMutation::Reopened, true)
                    }
                    "acknowledged" if material_changed => {
                        sqlx::query(
                            "UPDATE security_events
                             SET severity = 'high', title = ?, message = ?,
                                 evidence_json = ?, evidence_schema_version = 1,
                                 status = 'open', last_seen = ?, acknowledged_at = NULL,
                                 resolved_at = NULL
                             WHERE event_key = ? AND status = 'acknowledged'",
                        )
                        .bind(text.title)
                        .bind(text.message)
                        .bind(&evidence_json)
                        .bind(now)
                        .bind(&event_key)
                        .execute(&mut **transaction)
                        .await?;
                        (FileIntegrityEventMutation::Reopened, true)
                    }
                    "open" if material_changed => {
                        sqlx::query(
                            "UPDATE security_events
                             SET severity = 'high', title = ?, message = ?,
                                 evidence_json = ?, evidence_schema_version = 1,
                                 last_seen = ?, resolved_at = NULL
                             WHERE event_key = ? AND status = 'open'",
                        )
                        .bind(text.title)
                        .bind(text.message)
                        .bind(&evidence_json)
                        .bind(now)
                        .bind(&event_key)
                        .execute(&mut **transaction)
                        .await?;
                        (FileIntegrityEventMutation::Updated, false)
                    }
                    "open" | "acknowledged"
                        if now.saturating_sub(last_seen) >= FILE_INTEGRITY_EVENT_TOUCH_SECONDS =>
                    {
                        sqlx::query(
                            "UPDATE security_events SET last_seen = ?
                             WHERE event_key = ? AND status IN ('open', 'acknowledged')",
                        )
                        .bind(now)
                        .bind(&event_key)
                        .execute(&mut **transaction)
                        .await?;
                        (FileIntegrityEventMutation::HourlyTouched, false)
                    }
                    "open" | "acknowledged" => (FileIntegrityEventMutation::Noop, false),
                    _ => return Err(invalid_integrity_event_input()),
                }
            }
        };

        if should_notify {
            enqueue_file_integrity_notification_in_transaction(
                transaction,
                outbox,
                &event_key,
                "file.sensitive_changed",
                text.notification,
                now,
            )
            .await?;
        }
        Ok(mutation)
    }

    pub(crate) async fn resolve_file_integrity_drift_in_transaction(
        transaction: &mut Transaction<'_, Sqlite>,
        outbox: &NotificationOutbox,
        path_id: &str,
        logical_path: &str,
        notification_text: &str,
        now: i64,
    ) -> Result<FileIntegrityEventMutation, sqlx::Error> {
        if file_integrity_path_id(logical_path).as_deref() != Some(path_id)
            || !valid_file_integrity_notification_text(notification_text, logical_path, path_id)
            || !valid_integrity_timestamp(now)
        {
            return Err(invalid_integrity_event_input());
        }
        let event_key = format!("file:sensitive_changed:{path_id}");
        let existing =
            sqlx::query("SELECT event_type, status FROM security_events WHERE event_key = ?")
                .bind(&event_key)
                .fetch_optional(&mut **transaction)
                .await?;
        let Some(row) = existing else {
            return Ok(FileIntegrityEventMutation::Noop);
        };
        let event_type: String = row.try_get("event_type")?;
        let status: String = row.try_get("status")?;
        if event_type != "file.sensitive_changed" {
            return Err(invalid_integrity_event_input());
        }
        if status == "resolved" {
            return Ok(FileIntegrityEventMutation::Noop);
        }
        if !matches!(status.as_str(), "open" | "acknowledged") {
            return Err(invalid_integrity_event_input());
        }
        let updated = sqlx::query(
            "UPDATE security_events
             SET status = 'resolved', last_seen = ?, resolved_at = ?
             WHERE event_key = ? AND status IN ('open', 'acknowledged')",
        )
        .bind(now)
        .bind(now)
        .bind(&event_key)
        .execute(&mut **transaction)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(invalid_integrity_event_input());
        }
        enqueue_file_integrity_notification_in_transaction(
            transaction,
            outbox,
            &event_key,
            "file.sensitive_changed.resolved",
            notification_text,
            now,
        )
        .await?;
        Ok(FileIntegrityEventMutation::Resolved)
    }

    pub(crate) async fn upsert_file_integrity_coverage_degraded_in_transaction(
        transaction: &mut Transaction<'_, Sqlite>,
        evidence: &FileIntegrityCoverageDegradedEvidenceV1,
        title: &str,
        message: &str,
        now: i64,
    ) -> Result<FileIntegrityEventMutation, sqlx::Error> {
        let evidence_json = serialize_integrity_evidence(evidence)?;
        if parse_file_integrity_coverage_degraded_evidence(&evidence_json).as_ref()
            != Some(evidence)
            || !valid_integrity_event_text(title, 256)
            || !valid_integrity_event_text(message, 2 * 1024)
            || !valid_integrity_timestamp(now)
        {
            return Err(invalid_integrity_event_input());
        }
        let severity = evidence.degraded_reason.severity();
        let existing = sqlx::query(
            "SELECT event_type, severity, evidence_json, evidence_schema_version,
                    status, last_seen, notification_seq,
                    notification_delivery_status, notification_delivery_attempts,
                    notification_delivery_updated_at, notification_delivery_error_code
             FROM security_events WHERE event_key = ?",
        )
        .bind(FILE_INTEGRITY_COVERAGE_EVENT_KEY)
        .fetch_optional(&mut **transaction)
        .await?;

        let Some(row) = existing else {
            sqlx::query(
                "INSERT INTO security_events (
                    event_key, event_type, severity, title, message, evidence_json,
                    evidence_schema_version, status, first_seen, last_seen,
                    acknowledged_at, resolved_at, notification_seq
                 ) VALUES (?, 'file.integrity_coverage_degraded', ?, ?, ?, ?, 1,
                           'open', ?, ?, NULL, NULL, 0)",
            )
            .bind(FILE_INTEGRITY_COVERAGE_EVENT_KEY)
            .bind(severity)
            .bind(title)
            .bind(message)
            .bind(&evidence_json)
            .bind(now)
            .bind(now)
            .execute(&mut **transaction)
            .await?;
            return Ok(FileIntegrityEventMutation::Opened);
        };

        let event_type: String = row.try_get("event_type")?;
        let old_severity: String = row.try_get("severity")?;
        let status: String = row.try_get("status")?;
        let last_seen: i64 = row.try_get("last_seen")?;
        if event_type != "file.integrity_coverage_degraded" {
            return Err(invalid_integrity_event_input());
        }
        if status == "resolved" {
            sqlx::query(
                "UPDATE security_events
                 SET severity = ?, title = ?, message = ?, evidence_json = ?,
                     evidence_schema_version = 1, status = 'open', first_seen = ?,
                     last_seen = ?, acknowledged_at = NULL, resolved_at = NULL,
                     notification_seq = 0, notification_delivery_status = NULL,
                     notification_delivery_attempts = NULL,
                     notification_delivery_updated_at = NULL,
                     notification_delivery_error_code = NULL
                 WHERE event_key = ? AND status = 'resolved'",
            )
            .bind(severity)
            .bind(title)
            .bind(message)
            .bind(&evidence_json)
            .bind(now)
            .bind(now)
            .bind(FILE_INTEGRITY_COVERAGE_EVENT_KEY)
            .execute(&mut **transaction)
            .await?;
            return Ok(FileIntegrityEventMutation::Reopened);
        }
        if !matches!(status.as_str(), "open" | "acknowledged") {
            return Err(invalid_integrity_event_input());
        }

        let old_evidence = if row.try_get::<i64, _>("evidence_schema_version")? == 1 {
            row.try_get::<String, _>("evidence_json")
                .ok()
                .and_then(|stored| parse_file_integrity_coverage_degraded_evidence(&stored))
        } else {
            None
        };
        let notification_state_is_clean = row.try_get::<i64, _>("notification_seq")? == 0
            && row
                .try_get::<Option<String>, _>("notification_delivery_status")?
                .is_none()
            && row
                .try_get::<Option<i64>, _>("notification_delivery_attempts")?
                .is_none()
            && row
                .try_get::<Option<i64>, _>("notification_delivery_updated_at")?
                .is_none()
            && row
                .try_get::<Option<String>, _>("notification_delivery_error_code")?
                .is_none();
        let material_changed = old_evidence
            .as_ref()
            .map(|old| coverage_materially_differs(old, evidence))
            .unwrap_or(true)
            || !notification_state_is_clean;
        if material_changed {
            let escalated = old_severity != "high" && severity == "high";
            sqlx::query(
                "UPDATE security_events
                 SET severity = ?, title = ?, message = ?, evidence_json = ?,
                     evidence_schema_version = 1,
                     status = CASE WHEN ? THEN 'open' ELSE status END,
                     last_seen = ?,
                     acknowledged_at = CASE WHEN ? THEN NULL ELSE acknowledged_at END,
                     resolved_at = NULL, notification_seq = 0,
                     notification_delivery_status = NULL,
                     notification_delivery_attempts = NULL,
                     notification_delivery_updated_at = NULL,
                     notification_delivery_error_code = NULL
                 WHERE event_key = ? AND status IN ('open', 'acknowledged')",
            )
            .bind(severity)
            .bind(title)
            .bind(message)
            .bind(&evidence_json)
            .bind(escalated)
            .bind(now)
            .bind(escalated)
            .bind(FILE_INTEGRITY_COVERAGE_EVENT_KEY)
            .execute(&mut **transaction)
            .await?;
            return Ok(if escalated {
                FileIntegrityEventMutation::Reopened
            } else {
                FileIntegrityEventMutation::Updated
            });
        }
        if now.saturating_sub(last_seen) >= FILE_INTEGRITY_EVENT_TOUCH_SECONDS {
            sqlx::query(
                "UPDATE security_events SET last_seen = ?
                 WHERE event_key = ? AND status IN ('open', 'acknowledged')",
            )
            .bind(now)
            .bind(FILE_INTEGRITY_COVERAGE_EVENT_KEY)
            .execute(&mut **transaction)
            .await?;
            return Ok(FileIntegrityEventMutation::HourlyTouched);
        }
        Ok(FileIntegrityEventMutation::Noop)
    }

    pub(crate) async fn resolve_file_integrity_coverage_degraded_in_transaction(
        transaction: &mut Transaction<'_, Sqlite>,
        now: i64,
    ) -> Result<FileIntegrityEventMutation, sqlx::Error> {
        if !valid_integrity_timestamp(now) {
            return Err(invalid_integrity_event_input());
        }
        let existing =
            sqlx::query("SELECT event_type, status FROM security_events WHERE event_key = ?")
                .bind(FILE_INTEGRITY_COVERAGE_EVENT_KEY)
                .fetch_optional(&mut **transaction)
                .await?;
        let Some(row) = existing else {
            return Ok(FileIntegrityEventMutation::Noop);
        };
        if row.try_get::<String, _>("event_type")? != "file.integrity_coverage_degraded" {
            return Err(invalid_integrity_event_input());
        }
        let status: String = row.try_get("status")?;
        if status == "resolved" {
            return Ok(FileIntegrityEventMutation::Noop);
        }
        if !matches!(status.as_str(), "open" | "acknowledged") {
            return Err(invalid_integrity_event_input());
        }
        let updated = sqlx::query(
            "UPDATE security_events
             SET status = 'resolved', last_seen = ?, resolved_at = ?,
                 notification_seq = 0, notification_delivery_status = NULL,
                 notification_delivery_attempts = NULL,
                 notification_delivery_updated_at = NULL,
                 notification_delivery_error_code = NULL
             WHERE event_key = ? AND status IN ('open', 'acknowledged')",
        )
        .bind(now)
        .bind(now)
        .bind(FILE_INTEGRITY_COVERAGE_EVENT_KEY)
        .execute(&mut **transaction)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(invalid_integrity_event_input());
        }
        Ok(FileIntegrityEventMutation::Resolved)
    }

    pub(crate) async fn insert_file_integrity_baseline_reenrolled_in_transaction(
        transaction: &mut Transaction<'_, Sqlite>,
        evidence: &FileIntegrityBaselineReenrolledEvidenceV1,
        title: &str,
        message: &str,
    ) -> Result<(), sqlx::Error> {
        let evidence_json = serialize_integrity_evidence(evidence)?;
        if parse_file_integrity_baseline_reenrolled_evidence(&evidence_json).as_ref()
            != Some(evidence)
            || !valid_integrity_event_text(title, 256)
            || !valid_integrity_event_text(message, 2 * 1024)
        {
            return Err(invalid_integrity_event_input());
        }
        let event_key = format!(
            "file:integrity_baseline_reenrolled:{}",
            evidence.state_revision
        );
        sqlx::query(
            "INSERT INTO security_events (
                event_key, event_type, severity, title, message, evidence_json,
                evidence_schema_version, status, first_seen, last_seen,
                acknowledged_at, resolved_at, notification_seq,
                notification_delivery_status, notification_delivery_attempts,
                notification_delivery_updated_at, notification_delivery_error_code
             ) VALUES (?, 'file.integrity_baseline_reenrolled', 'info', ?, ?, ?, 1,
                       'resolved', ?, ?, NULL, ?, 0, NULL, NULL, NULL, NULL)",
        )
        .bind(event_key)
        .bind(title)
        .bind(message)
        .bind(evidence_json)
        .bind(evidence.reenrolled_at)
        .bind(evidence.reenrolled_at)
        .bind(evidence.reenrolled_at)
        .execute(&mut **transaction)
        .await?;
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
        let event_key: String = row.try_get("event_key")?;
        let event_type: String = row.try_get("event_type")?;
        let severity: String = row.try_get("severity")?;
        let status: String = row.try_get("status")?;
        let first_seen: i64 = row.try_get("first_seen")?;
        let last_seen: i64 = row.try_get("last_seen")?;
        let acknowledged_at: Option<i64> = row.try_get("acknowledged_at")?;
        let resolved_at: Option<i64> = row.try_get("resolved_at")?;
        let notification_seq: i64 = row.try_get("notification_seq")?;
        let notification_delivery_status: Option<String> =
            row.try_get("notification_delivery_status")?;
        let notification_delivery_attempts: Option<i64> =
            row.try_get("notification_delivery_attempts")?;
        let notification_delivery_updated_at: Option<i64> =
            row.try_get("notification_delivery_updated_at")?;
        let notification_delivery_error_code: Option<String> =
            row.try_get("notification_delivery_error_code")?;
        let stored_evidence: Option<Vec<u8>> = row.try_get("bounded_evidence_bytes")?;
        let evidence_payload_invalid: i64 = row.try_get("evidence_payload_invalid")?;
        let evidence_schema_version: i64 = row.try_get("evidence_schema_version")?;
        let (mut evidence_json, mut evidence) = if evidence_schema_version
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

        let context = StoredSecurityEventContext {
            event_key: &event_key,
            event_type: &event_type,
            severity: &severity,
            status: &status,
            first_seen,
            last_seen,
            acknowledged_at,
            resolved_at,
            notification_seq,
            notification_delivery_status: notification_delivery_status.as_deref(),
            notification_delivery_attempts,
            notification_delivery_updated_at,
            notification_delivery_error_code: notification_delivery_error_code.as_deref(),
        };
        if !valid_stored_security_event_context(&context, &evidence) {
            (evidence_json, evidence) = invalid_evidence_projection(
                evidence_schema_version,
                &event_type,
                SecurityEventEvidenceErrorCode::InvalidStoredPayload,
            );
        }

        Ok(SecurityEvent {
            id: row.try_get("id")?,
            event_key,
            event_type,
            severity,
            title: row.try_get("title")?,
            message: row.try_get("message")?,
            evidence_json,
            evidence,
            status,
            first_seen,
            last_seen,
            acknowledged_at,
            resolved_at,
            notification_delivery_status,
            notification_delivery_attempts,
            notification_delivery_updated_at,
            notification_delivery_error_code,
        })
    }
}

fn validate_file_integrity_drift_input(
    evidence: &FileSensitiveChangedEvidenceV1,
    title: &str,
    message: &str,
    notification_text: &str,
    now: i64,
) -> Result<(), sqlx::Error> {
    let evidence_json = serialize_integrity_evidence(evidence)?;
    if parse_file_sensitive_changed_evidence(&evidence_json).as_ref() != Some(evidence)
        || !valid_file_sensitive_event_identity(
            &format!("file:sensitive_changed:{}", evidence.path_id),
            evidence,
        )
        || !valid_integrity_event_text(title, 256)
        || !valid_integrity_event_text(message, 2 * 1024)
        || !valid_file_integrity_notification_text(
            notification_text,
            &evidence.logical_path,
            &evidence.path_id,
        )
        || !valid_integrity_timestamp(now)
    {
        return Err(invalid_integrity_event_input());
    }
    Ok(())
}

fn serialize_integrity_evidence<T: Serialize>(evidence: &T) -> Result<String, sqlx::Error> {
    serde_json::to_string(evidence).map_err(|_| invalid_integrity_event_input())
}

fn valid_integrity_event_text(value: &str, max_bytes: usize) -> bool {
    valid_bounded_text(value, max_bytes, false) && !contains_private_legacy_marker(value)
}

fn valid_file_integrity_notification_text(value: &str, logical_path: &str, path_id: &str) -> bool {
    if value.trim().is_empty()
        || value.len() > 1536
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
        || value.contains(logical_path)
        || value.contains(path_id)
    {
        return false;
    }
    let lowered = value.to_ascii_lowercase();
    !lowered.contains("/etc")
        && !lowered.contains("path-v1:")
        && !lowered.contains("content_digest")
        && !lowered.contains("sha256")
        && !lowered.contains("sha-256")
        && !contains_private_legacy_marker(value)
}

fn valid_integrity_timestamp(value: i64) -> bool {
    (0..=MAX_FILE_TIMESTAMP).contains(&value)
}

fn coverage_materially_differs(
    old: &FileIntegrityCoverageDegradedEvidenceV1,
    new: &FileIntegrityCoverageDegradedEvidenceV1,
) -> bool {
    old.degraded_reason != new.degraded_reason
        || old.observation_complete != new.observation_complete
        || old.tracked_file_count != new.tracked_file_count
        || old.drift_file_count != new.drift_file_count
        || old.unavailable_target_count != new.unavailable_target_count
        || old.error_counts != new.error_counts
}

async fn enqueue_file_integrity_notification_in_transaction(
    transaction: &mut Transaction<'_, Sqlite>,
    outbox: &NotificationOutbox,
    event_key: &str,
    kind: &str,
    notification_text: &str,
    now: i64,
) -> Result<(), sqlx::Error> {
    let sequence = next_notification_sequence(transaction, event_key).await?;
    let event = NotificationEvent::file_integrity_transition(
        event_key,
        sequence,
        kind,
        notification_text,
        now,
    );
    let outcome = outbox
        .enqueue_in_transaction(transaction, &event, now)
        .await?;
    update_enqueue_summary(transaction, event_key, sequence, &outcome, now).await
}

fn invalid_integrity_event_input() -> sqlx::Error {
    sqlx::Error::Protocol("invalid file integrity event input".to_string())
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
        "file.integrity_coverage_degraded" => {
            parse_file_integrity_coverage_degraded_evidence(stored_evidence).map(|data| {
                KnownSecurityEventEvidenceV1::FileIntegrityCoverageDegraded {
                    data,
                    error_code: (),
                }
            })
        }
        "file.integrity_baseline_reenrolled" => {
            parse_file_integrity_baseline_reenrolled_evidence(stored_evidence).map(|data| {
                KnownSecurityEventEvidenceV1::FileIntegrityBaselineReenrolled {
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

fn valid_stored_security_event_context(
    context: &StoredSecurityEventContext<'_>,
    evidence: &SecurityEventEvidence,
) -> bool {
    let SecurityEventEvidenceProjection::Known(known) = &evidence.0 else {
        return true;
    };
    match &known.kind {
        KnownSecurityEventEvidenceV1::FileSensitiveChanged { data, .. } => {
            valid_integrity_status_context(context)
                && context.severity == "high"
                && valid_file_sensitive_event_identity(context.event_key, data)
        }
        KnownSecurityEventEvidenceV1::FileIntegrityCoverageDegraded { data, .. } => {
            valid_integrity_status_context(context)
                && context.event_key == FILE_INTEGRITY_COVERAGE_EVENT_KEY
                && context.severity == data.degraded_reason.severity()
                && integrity_event_has_no_notification_state(context)
        }
        KnownSecurityEventEvidenceV1::FileIntegrityBaselineReenrolled { data, .. } => {
            let expected_key =
                format!("file:integrity_baseline_reenrolled:{}", data.state_revision);
            context.event_key == expected_key
                && context.event_type == "file.integrity_baseline_reenrolled"
                && context.severity == "info"
                && context.status == "resolved"
                && context.first_seen == data.reenrolled_at
                && context.last_seen == data.reenrolled_at
                && context.resolved_at == Some(data.reenrolled_at)
                && context.acknowledged_at.is_none()
                && integrity_event_has_no_notification_state(context)
        }
        _ => true,
    }
}

fn valid_integrity_status_context(context: &StoredSecurityEventContext<'_>) -> bool {
    if !(0..=MAX_FILE_TIMESTAMP).contains(&context.first_seen)
        || !(0..=MAX_FILE_TIMESTAMP).contains(&context.last_seen)
        || context.first_seen > context.last_seen
        || context
            .acknowledged_at
            .is_some_and(|value| !(0..=MAX_FILE_TIMESTAMP).contains(&value))
        || context
            .resolved_at
            .is_some_and(|value| !(0..=MAX_FILE_TIMESTAMP).contains(&value))
    {
        return false;
    }
    match context.status {
        "open" => context.acknowledged_at.is_none() && context.resolved_at.is_none(),
        "acknowledged" => context.acknowledged_at.is_some() && context.resolved_at.is_none(),
        "resolved" => context.resolved_at.is_some(),
        _ => false,
    }
}

fn integrity_event_has_no_notification_state(context: &StoredSecurityEventContext<'_>) -> bool {
    context.notification_seq == 0
        && context.notification_delivery_status.is_none()
        && context.notification_delivery_attempts.is_none()
        && context.notification_delivery_updated_at.is_none()
        && context.notification_delivery_error_code.is_none()
}

fn valid_file_sensitive_event_identity(
    event_key: &str,
    evidence: &FileSensitiveChangedEvidenceV1,
) -> bool {
    let Some(expected_path_id) = file_integrity_path_id(&evidence.logical_path) else {
        return false;
    };
    evidence.path_id == expected_path_id
        && event_key == format!("file:sensitive_changed:{}", evidence.path_id)
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
        || !file_metadata_matches_logical_path(
            &evidence.logical_path,
            &evidence.baseline_metadata,
            &evidence.observed_metadata,
            &evidence.change_kinds,
            observation_failed,
        )
        || (evidence
            .change_kinds
            .contains(&FileChangeKindV1::ContentChanged)
            && (evidence.baseline_metadata.state == FileEvidenceStateV1::Directory
                || evidence.observed_metadata.state == FileEvidenceStateV1::Directory))
    {
        return None;
    }
    Some(evidence)
}

fn parse_file_integrity_coverage_degraded_evidence(
    stored: &str,
) -> Option<FileIntegrityCoverageDegradedEvidenceV1> {
    let evidence: FileIntegrityCoverageDegradedEvidenceV1 = serde_json::from_str(stored).ok()?;
    let counts_are_bounded = evidence.tracked_file_count <= 256
        && evidence.drift_file_count <= evidence.tracked_file_count
        && evidence.unavailable_target_count <= 256;
    let revisions_are_bounded = evidence.state_revision <= JS_MAX_SAFE_INTEGER
        && evidence.baseline_generation <= JS_MAX_SAFE_INTEGER
        && evidence.observed_generation <= JS_MAX_SAFE_INTEGER;
    let error_counts_are_valid = evidence.error_counts.len() <= 24
        && evidence
            .error_counts
            .windows(2)
            .all(|pair| pair[0].code < pair[1].code)
        && evidence
            .error_counts
            .iter()
            .all(|entry| (1..=256).contains(&entry.count))
        && evidence
            .error_counts
            .iter()
            .try_fold(0_u64, |total, entry| total.checked_add(entry.count))
            .is_some_and(|total| total <= 256);
    if !counts_are_bounded
        || !revisions_are_bounded
        || !(0..=MAX_FILE_TIMESTAMP).contains(&evidence.observed_at)
        || !error_counts_are_valid
    {
        return None;
    }
    Some(evidence)
}

fn parse_file_integrity_baseline_reenrolled_evidence(
    stored: &str,
) -> Option<FileIntegrityBaselineReenrolledEvidenceV1> {
    let evidence: FileIntegrityBaselineReenrolledEvidenceV1 = serde_json::from_str(stored).ok()?;
    if evidence.old_baseline_generation == 0
        || evidence.old_baseline_generation > JS_MAX_SAFE_INTEGER
        || evidence.new_baseline_generation == 0
        || evidence.new_baseline_generation > JS_MAX_SAFE_INTEGER
        || evidence.state_revision > JS_MAX_SAFE_INTEGER
        || evidence.observed_generation == 0
        || evidence.observed_generation > JS_MAX_SAFE_INTEGER
        || !(0..=MAX_FILE_TIMESTAMP).contains(&evidence.reenrolled_at)
    {
        return None;
    }
    Some(evidence)
}

fn is_directory_root_path(path: &str) -> bool {
    matches!(
        path,
        "/etc/sudoers.d"
            | "/etc/ssh/sshd_config.d"
            | "/etc/cron.d"
            | "/etc/cron.daily"
            | "/etc/cron.hourly"
            | "/etc/cron.weekly"
    )
}

fn file_metadata_matches_logical_path(
    path: &str,
    baseline: &FileEvidenceMetadataV1,
    observed: &FileEvidenceMetadataV1,
    change_kinds: &[FileChangeKindV1],
    observation_failed: bool,
) -> bool {
    let directory_root = is_directory_root_path(path);
    let baseline_matches_target = if directory_root {
        matches!(
            baseline.state,
            FileEvidenceStateV1::Directory | FileEvidenceStateV1::Absent
        )
    } else if matches!(path, "/etc/passwd" | "/etc/group") {
        baseline.state == FileEvidenceStateV1::Regular
    } else {
        baseline.state != FileEvidenceStateV1::Directory
    };
    if !baseline_matches_target {
        return false;
    }

    let has = |kind| change_kinds.contains(&kind);
    let owner_change_is_proven = || {
        baseline.state != FileEvidenceStateV1::Absent
            && observed.state != FileEvidenceStateV1::Absent
            && ((baseline.uid.is_some() && observed.uid.is_some() && baseline.uid != observed.uid)
                || (baseline.gid.is_some()
                    && observed.gid.is_some()
                    && baseline.gid != observed.gid))
    };
    let permission_change_is_proven = || {
        baseline.state != FileEvidenceStateV1::Absent
            && observed.state != FileEvidenceStateV1::Absent
            && baseline.mode.is_some()
            && observed.mode.is_some()
            && baseline.mode != observed.mode
    };
    if observation_failed {
        return !directory_root
            && observed.state != FileEvidenceStateV1::Directory
            && has(FileChangeKindV1::Unreadable)
            && !has(FileChangeKindV1::Added)
            && !has(FileChangeKindV1::Removed)
            && !has(FileChangeKindV1::TypeChanged)
            && !has(FileChangeKindV1::ContentChanged)
            && has(FileChangeKindV1::OwnerChanged) == owner_change_is_proven()
            && has(FileChangeKindV1::PermissionsChanged) == permission_change_is_proven();
    }

    if has(FileChangeKindV1::Unreadable) {
        return false;
    }
    let baseline_present = baseline.state != FileEvidenceStateV1::Absent;
    let observed_present = observed.state != FileEvidenceStateV1::Absent;
    let observed_has_wrong_target_type = if directory_root {
        observed.state == FileEvidenceStateV1::Regular
    } else {
        observed.state == FileEvidenceStateV1::Directory
    };
    let content_change_is_valid = !has(FileChangeKindV1::ContentChanged)
        || (baseline.state == FileEvidenceStateV1::Regular
            && observed.state == FileEvidenceStateV1::Regular);
    let regular_size_changed = baseline.state == FileEvidenceStateV1::Regular
        && observed.state == FileEvidenceStateV1::Regular
        && baseline.size_bytes != observed.size_bytes;

    has(FileChangeKindV1::Added) == (!baseline_present && observed_present)
        && has(FileChangeKindV1::Removed) == (baseline_present && !observed_present)
        && has(FileChangeKindV1::TypeChanged) == observed_has_wrong_target_type
        && has(FileChangeKindV1::OwnerChanged) == owner_change_is_proven()
        && has(FileChangeKindV1::PermissionsChanged) == permission_change_is_proven()
        && content_change_is_valid
        && (!regular_size_changed || has(FileChangeKindV1::ContentChanged))
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

pub(crate) fn file_integrity_path_id(logical_path: &str) -> Option<String> {
    if !valid_logical_file_path(logical_path) {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(FILE_INTEGRITY_PATH_DOMAIN);
    hasher.update(logical_path.as_bytes());
    let digest = hasher.finalize();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut path_id = String::with_capacity("path-v1:".len() + digest.len() * 2);
    path_id.push_str("path-v1:");
    for byte in digest {
        path_id.push(char::from(HEX[usize::from(byte >> 4)]));
        path_id.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Some(path_id)
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
        || is_directory_root_path(path)
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
        FileEvidenceStateV1::Directory => {
            metadata.size_bytes.is_none()
                && metadata.mtime_unix_seconds.is_none()
                && metadata.mode.is_some()
                && metadata.uid.is_some()
                && metadata.gid.is_some()
        }
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
            "path_id": file_integrity_path_id("/etc/passwd").expect("frozen path should hash"),
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
            &format!(
                "file:sensitive_changed:{}",
                file_integrity_path_id("/etc/passwd").unwrap()
            ),
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

        for root in [
            "/etc/sudoers.d",
            "/etc/ssh/sshd_config.d",
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.hourly",
            "/etc/cron.weekly",
        ] {
            let mut payload = valid_file_evidence_payload();
            payload["logical_path"] = serde_json::json!(root);
            payload["change_kinds"] = serde_json::json!(["owner_changed", "permissions_changed"]);
            for side in ["baseline_metadata", "observed_metadata"] {
                payload[side]["state"] = serde_json::json!("directory");
                payload[side]["size_bytes"] = serde_json::Value::Null;
                payload[side]["mtime_unix_seconds"] = serde_json::Value::Null;
            }
            payload["observed_metadata"]["uid"] = serde_json::json!(1);
            assert!(
                parse_file_sensitive_changed_evidence(&payload.to_string()).is_some(),
                "configured directory root should be accepted: {root}"
            );
        }

        let long_basename = format!("/etc/cron.d/{}", "x".repeat(256));
        for path in [
            "/",
            "etc/passwd",
            "/etc",
            "/etc/passwd/child",
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
            "changed_during_read",
            "vanished_during_scan",
            "io_error",
        ] {
            let mut payload = valid_file_evidence_payload();
            payload["observation_error"] = serde_json::json!(error);
            payload["change_kinds"] = serde_json::json!(["unreadable"]);
            for field in ["size_bytes", "mtime_unix_seconds", "mode", "uid", "gid"] {
                payload["observed_metadata"][field] = serde_json::Value::Null;
            }
            assert!(
                parse_file_sensitive_changed_evidence(&payload.to_string()).is_some(),
                "closed observation error should be accepted: {error}"
            );
        }
        for aggregate_error in [
            "tracked_file_limit",
            "scan_byte_limit",
            "deadline_exceeded",
            "directory_unreadable",
            "path_not_utf8",
            "path_too_long",
        ] {
            let mut payload = valid_file_evidence_payload();
            payload["observation_error"] = serde_json::json!(aggregate_error);
            payload["change_kinds"] = serde_json::json!(["unreadable"]);
            assert!(
                parse_file_sensitive_changed_evidence(&payload.to_string()).is_none(),
                "aggregate-only error must not project as a file event: {aggregate_error}"
            );
        }
        let mut unknown_error = valid_file_evidence_payload();
        unknown_error["observation_error"] = serde_json::json!("raw_io_error");
        assert!(parse_file_sensitive_changed_evidence(&unknown_error.to_string()).is_none());
    }

    #[test]
    fn file_evidence_v1_enforces_numeric_metadata_and_privacy_bounds() {
        let mut absent = valid_file_evidence_payload();
        absent["logical_path"] = serde_json::json!("/etc/sudoers");
        absent["change_kinds"] = serde_json::json!(["added"]);
        absent["baseline_metadata"]["state"] = serde_json::json!("absent");
        for field in ["size_bytes", "mtime_unix_seconds", "mode", "uid", "gid"] {
            absent["baseline_metadata"][field] = serde_json::Value::Null;
        }
        assert!(parse_file_sensitive_changed_evidence(&absent.to_string()).is_some());

        let mut directory = valid_file_evidence_payload();
        directory["logical_path"] = serde_json::json!("/etc/sudoers.d");
        directory["change_kinds"] = serde_json::json!(["owner_changed", "permissions_changed"]);
        for side in ["baseline_metadata", "observed_metadata"] {
            directory[side]["state"] = serde_json::json!("directory");
            directory[side]["size_bytes"] = serde_json::Value::Null;
            directory[side]["mtime_unix_seconds"] = serde_json::Value::Null;
        }
        directory["observed_metadata"]["uid"] = serde_json::json!(1);
        assert!(parse_file_sensitive_changed_evidence(&directory.to_string()).is_some());

        let mut absent_to_directory = directory.clone();
        absent_to_directory["change_kinds"] = serde_json::json!(["added"]);
        absent_to_directory["baseline_metadata"]["state"] = serde_json::json!("absent");
        for field in ["size_bytes", "mtime_unix_seconds", "mode", "uid", "gid"] {
            absent_to_directory["baseline_metadata"][field] = serde_json::Value::Null;
        }
        assert!(parse_file_sensitive_changed_evidence(&absent_to_directory.to_string()).is_some());

        let mut directory_to_absent = directory.clone();
        directory_to_absent["change_kinds"] = serde_json::json!(["removed"]);
        directory_to_absent["observed_metadata"]["state"] = serde_json::json!("absent");
        for field in ["size_bytes", "mtime_unix_seconds", "mode", "uid", "gid"] {
            directory_to_absent["observed_metadata"][field] = serde_json::Value::Null;
        }
        assert!(parse_file_sensitive_changed_evidence(&directory_to_absent.to_string()).is_some());

        let mut directory_metadata_change = directory.clone();
        directory_metadata_change["change_kinds"] =
            serde_json::json!(["owner_changed", "permissions_changed"]);
        assert!(
            parse_file_sensitive_changed_evidence(&directory_metadata_change.to_string()).is_some()
        );

        let mut fixed_to_directory = valid_file_evidence_payload();
        fixed_to_directory["change_kinds"] =
            serde_json::json!(["permissions_changed", "type_changed"]);
        fixed_to_directory["observed_metadata"]["state"] = serde_json::json!("directory");
        fixed_to_directory["observed_metadata"]["size_bytes"] = serde_json::Value::Null;
        fixed_to_directory["observed_metadata"]["mtime_unix_seconds"] = serde_json::Value::Null;
        assert!(parse_file_sensitive_changed_evidence(&fixed_to_directory.to_string()).is_some());

        let mut directory_to_regular = directory.clone();
        directory_to_regular["change_kinds"] =
            serde_json::json!(["permissions_changed", "type_changed"]);
        directory_to_regular["observed_metadata"] =
            valid_file_evidence_payload()["observed_metadata"].clone();
        assert!(parse_file_sensitive_changed_evidence(&directory_to_regular.to_string()).is_some());

        let mut fixed_to_directory_without_type_change = fixed_to_directory.clone();
        fixed_to_directory_without_type_change["change_kinds"] =
            serde_json::json!(["permissions_changed"]);
        assert!(
            parse_file_sensitive_changed_evidence(
                &fixed_to_directory_without_type_change.to_string()
            )
            .is_none()
        );

        let mut directory_to_regular_without_type_change = directory_to_regular.clone();
        directory_to_regular_without_type_change["change_kinds"] =
            serde_json::json!(["permissions_changed"]);
        assert!(
            parse_file_sensitive_changed_evidence(
                &directory_to_regular_without_type_change.to_string()
            )
            .is_none()
        );

        let mut partial_observed = valid_file_evidence_payload();
        partial_observed["observation_error"] = serde_json::json!("permission_denied");
        partial_observed["change_kinds"] = serde_json::json!(["unreadable"]);
        for field in ["size_bytes", "mtime_unix_seconds", "mode", "uid", "gid"] {
            partial_observed["observed_metadata"][field] = serde_json::Value::Null;
        }
        assert!(parse_file_sensitive_changed_evidence(&partial_observed.to_string()).is_some());

        let mut required_absent = absent.clone();
        required_absent["logical_path"] = serde_json::json!("/etc/passwd");
        assert!(parse_file_sensitive_changed_evidence(&required_absent.to_string()).is_none());

        let mut child_added = absent.clone();
        child_added["logical_path"] = serde_json::json!("/etc/cron.d/new-job");
        assert!(parse_file_sensitive_changed_evidence(&child_added.to_string()).is_some());

        let mut absent_to_wrong_type = child_added.clone();
        absent_to_wrong_type["change_kinds"] = serde_json::json!(["added", "type_changed"]);
        absent_to_wrong_type["observed_metadata"]["state"] = serde_json::json!("directory");
        absent_to_wrong_type["observed_metadata"]["size_bytes"] = serde_json::Value::Null;
        absent_to_wrong_type["observed_metadata"]["mtime_unix_seconds"] = serde_json::Value::Null;
        assert!(parse_file_sensitive_changed_evidence(&absent_to_wrong_type.to_string()).is_some());

        let mut expected_add_with_type_change = absent.clone();
        expected_add_with_type_change["change_kinds"] =
            serde_json::json!(["added", "type_changed"]);
        assert!(
            parse_file_sensitive_changed_evidence(&expected_add_with_type_change.to_string())
                .is_none()
        );

        let mut root_error = directory.clone();
        root_error["change_kinds"] = serde_json::json!(["unreadable"]);
        root_error["observation_error"] = serde_json::json!("permission_denied");
        root_error["observed_metadata"]["state"] = serde_json::json!("absent");
        for field in ["size_bytes", "mtime_unix_seconds", "mode", "uid", "gid"] {
            root_error["observed_metadata"][field] = serde_json::Value::Null;
        }
        assert!(parse_file_sensitive_changed_evidence(&root_error.to_string()).is_none());

        let mut error_without_unreadable = partial_observed.clone();
        error_without_unreadable["change_kinds"] = serde_json::json!(["permissions_changed"]);
        assert!(
            parse_file_sensitive_changed_evidence(&error_without_unreadable.to_string()).is_none()
        );

        let mut error_with_transition = partial_observed.clone();
        error_with_transition["change_kinds"] = serde_json::json!(["added", "unreadable"]);
        assert!(
            parse_file_sensitive_changed_evidence(&error_with_transition.to_string()).is_none()
        );

        let mut missing_content_change = valid_file_evidence_payload();
        missing_content_change["change_kinds"] = serde_json::json!(["permissions_changed"]);
        assert!(
            parse_file_sensitive_changed_evidence(&missing_content_change.to_string()).is_none()
        );

        let mut partial_owner_change = partial_observed.clone();
        partial_owner_change["change_kinds"] = serde_json::json!(["owner_changed", "unreadable"]);
        partial_owner_change["observed_metadata"]["uid"] = serde_json::json!(1);
        assert!(parse_file_sensitive_changed_evidence(&partial_owner_change.to_string()).is_some());

        let mut unreported_partial_owner_change = partial_owner_change.clone();
        unreported_partial_owner_change["change_kinds"] = serde_json::json!(["unreadable"]);
        assert!(
            parse_file_sensitive_changed_evidence(&unreported_partial_owner_change.to_string())
                .is_none()
        );

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

        let mut directory_with_size = directory.clone();
        directory_with_size["observed_metadata"]["size_bytes"] = serde_json::json!(4096);
        invalid_payloads.push(directory_with_size);

        let mut directory_without_owner = directory.clone();
        directory_without_owner["observed_metadata"]["uid"] = serde_json::Value::Null;
        invalid_payloads.push(directory_without_owner);

        let mut directory_on_fixed_file = directory.clone();
        directory_on_fixed_file["logical_path"] = serde_json::json!("/etc/passwd");
        invalid_payloads.push(directory_on_fixed_file);

        let mut regular_on_directory_root = valid_file_evidence_payload();
        regular_on_directory_root["logical_path"] = serde_json::json!("/etc/sudoers.d");
        invalid_payloads.push(regular_on_directory_root);

        let mut directory_content_change = directory.clone();
        directory_content_change["change_kinds"] = serde_json::json!(["content_changed"]);
        invalid_payloads.push(directory_content_change);

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

    fn valid_file_integrity_drift_evidence() -> FileSensitiveChangedEvidenceV1 {
        serde_json::from_value(valid_file_evidence_payload()).unwrap()
    }

    fn file_integrity_drift_text(notification: &str) -> FileIntegrityDriftEventText<'_> {
        FileIntegrityDriftEventText {
            title: "Sensitive file changed",
            message: "Open the local Security page.",
            notification,
        }
    }

    fn valid_coverage_evidence(
        reason: FileIntegrityDegradedReasonV1,
    ) -> FileIntegrityCoverageDegradedEvidenceV1 {
        FileIntegrityCoverageDegradedEvidenceV1 {
            degraded_reason: reason,
            state_revision: 2,
            baseline_generation: 1,
            observed_generation: 2,
            observation_complete: false,
            observed_at: 1_700_000_100,
            tracked_file_count: 2,
            drift_file_count: 1,
            unavailable_target_count: 1,
            error_counts: vec![FileIntegrityCoverageErrorCountV1 {
                code: FileIntegrityCoverageErrorCodeV1::PermissionDenied,
                count: 1,
            }],
        }
    }

    #[tokio::test]
    async fn integrity_drift_transitions_are_atomic_and_each_enqueue_is_durable() {
        let service = test_service().await;
        let outbox = enabled_outbox(&service);
        let evidence = valid_file_integrity_drift_evidence();
        let notification = "Sensitive-file integrity changed: severity high, count 1";
        let mut transaction = service.db.begin_with("BEGIN IMMEDIATE").await.unwrap();
        assert_eq!(
            SecurityEventService::upsert_file_integrity_drift_in_transaction(
                &mut transaction,
                &outbox,
                &evidence,
                file_integrity_drift_text(notification),
                true,
                1_700_000_101,
            )
            .await
            .unwrap(),
            FileIntegrityEventMutation::Opened
        );
        transaction.commit().await.unwrap();

        let event = service.list(Some("active"), 10).await.unwrap().remove(0);
        assert_valid_evidence(&event);
        assert!(service.acknowledge(event.id).await.unwrap());

        let mut transaction = service.db.begin_with("BEGIN IMMEDIATE").await.unwrap();
        assert_eq!(
            SecurityEventService::upsert_file_integrity_drift_in_transaction(
                &mut transaction,
                &outbox,
                &evidence,
                file_integrity_drift_text(notification),
                true,
                1_700_000_102,
            )
            .await
            .unwrap(),
            FileIntegrityEventMutation::Reopened
        );
        assert_eq!(
            SecurityEventService::resolve_file_integrity_drift_in_transaction(
                &mut transaction,
                &outbox,
                &evidence.path_id,
                &evidence.logical_path,
                "Sensitive-file integrity recovered: severity high, count 1",
                1_700_000_103,
            )
            .await
            .unwrap(),
            FileIntegrityEventMutation::Resolved
        );
        transaction.commit().await.unwrap();

        let sequences: Vec<i64> = sqlx::query_scalar(
            "SELECT source_event_seq FROM notification_outbox
             WHERE source_event_key = ? ORDER BY source_event_seq",
        )
        .bind(format!("file:sensitive_changed:{}", evidence.path_id))
        .fetch_all(&service.db)
        .await
        .unwrap();
        assert_eq!(sequences, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn caller_rollback_removes_integrity_event_and_outbox_together() {
        let service = test_service().await;
        let outbox = enabled_outbox(&service);
        let evidence = valid_file_integrity_drift_evidence();
        let mut transaction = service.db.begin_with("BEGIN IMMEDIATE").await.unwrap();
        SecurityEventService::upsert_file_integrity_drift_in_transaction(
            &mut transaction,
            &outbox,
            &evidence,
            file_integrity_drift_text("Sensitive-file integrity changed: severity high, count 1"),
            true,
            1_700_000_101,
        )
        .await
        .unwrap();
        transaction.rollback().await.unwrap();

        let event_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_events")
            .fetch_one(&service.db)
            .await
            .unwrap();
        let outbox_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notification_outbox")
            .fetch_one(&service.db)
            .await
            .unwrap();
        assert_eq!((event_count, outbox_count), (0, 0));
    }

    #[tokio::test]
    async fn integrity_state_events_project_strictly_without_notifications() {
        let service = test_service().await;
        let coverage = valid_coverage_evidence(FileIntegrityDegradedReasonV1::CoverageUnavailable);
        let reenrolled = FileIntegrityBaselineReenrolledEvidenceV1 {
            reason: FileIntegrityReenrollReasonV1::BaselineCorrupt,
            old_baseline_generation: 1,
            new_baseline_generation: 2,
            state_revision: 3,
            observed_generation: 2,
            reenrolled_at: 1_700_000_110,
        };
        let mut transaction = service.db.begin_with("BEGIN IMMEDIATE").await.unwrap();
        SecurityEventService::upsert_file_integrity_coverage_degraded_in_transaction(
            &mut transaction,
            &coverage,
            "Integrity coverage degraded",
            "Open the local Security page.",
            1_700_000_100,
        )
        .await
        .unwrap();
        SecurityEventService::insert_file_integrity_baseline_reenrolled_in_transaction(
            &mut transaction,
            &reenrolled,
            "Integrity baseline re-enrolled",
            "A new local trust baseline was explicitly enrolled.",
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();

        let events = service.list(None, 10).await.unwrap();
        assert_eq!(events.len(), 2);
        for event in &events {
            assert_valid_evidence(event);
            assert!(event.notification_delivery_status.is_none());
        }
        let outbox_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notification_outbox")
            .fetch_one(&service.db)
            .await
            .unwrap();
        assert_eq!(outbox_count, 0);
    }

    #[tokio::test]
    async fn integrity_outer_identity_mismatch_is_sanitized() {
        let service = test_service().await;
        let payload = valid_file_evidence_payload().to_string();
        insert_stored_event(
            &service,
            "file:sensitive_changed:path-v1:wrong",
            "file.sensitive_changed",
            &payload,
            1,
        )
        .await;
        let event = service.list(None, 1).await.unwrap().remove(0);
        assert_unavailable_evidence(
            &event,
            1,
            "file.sensitive_changed",
            SecurityEventEvidenceErrorCode::InvalidStoredPayload,
        );
        let public = serde_json::to_string(&event).unwrap();
        assert!(!public.contains("content_digest"));
    }

    #[tokio::test]
    async fn integrity_drift_identical_hourly_and_acknowledged_materiality_are_bounded() {
        let service = test_service().await;
        let outbox = enabled_outbox(&service);
        let evidence = valid_file_integrity_drift_evidence();
        let event_key = format!("file:sensitive_changed:{}", evidence.path_id);
        let notification = "Sensitive-file integrity changed: severity high, count 1";
        let now = Utc::now().timestamp();

        let mut transaction = service.db.begin_with("BEGIN IMMEDIATE").await.unwrap();
        assert_eq!(
            SecurityEventService::upsert_file_integrity_drift_in_transaction(
                &mut transaction,
                &outbox,
                &evidence,
                file_integrity_drift_text(notification),
                true,
                now,
            )
            .await
            .unwrap(),
            FileIntegrityEventMutation::Opened
        );
        transaction.commit().await.unwrap();

        let mut transaction = service.db.begin_with("BEGIN IMMEDIATE").await.unwrap();
        assert_eq!(
            SecurityEventService::upsert_file_integrity_drift_in_transaction(
                &mut transaction,
                &outbox,
                &evidence,
                file_integrity_drift_text(notification),
                false,
                now + 1,
            )
            .await
            .unwrap(),
            FileIntegrityEventMutation::Noop
        );
        transaction.commit().await.unwrap();

        let unchanged: (i64, i64, String) = sqlx::query_as(
            "SELECT last_seen, notification_seq, evidence_json
             FROM security_events WHERE event_key = ?",
        )
        .bind(&event_key)
        .fetch_one(&service.db)
        .await
        .unwrap();
        assert_eq!(unchanged.0, now);
        assert_eq!(unchanged.1, 1);
        assert_eq!(unchanged.2, serde_json::to_string(&evidence).unwrap());

        let mut transaction = service.db.begin_with("BEGIN IMMEDIATE").await.unwrap();
        assert_eq!(
            SecurityEventService::upsert_file_integrity_drift_in_transaction(
                &mut transaction,
                &outbox,
                &evidence,
                file_integrity_drift_text(notification),
                false,
                now + FILE_INTEGRITY_EVENT_TOUCH_SECONDS,
            )
            .await
            .unwrap(),
            FileIntegrityEventMutation::HourlyTouched
        );
        transaction.commit().await.unwrap();

        sqlx::query(
            "UPDATE security_events
             SET status = 'acknowledged', acknowledged_at = ?
             WHERE event_key = ?",
        )
        .bind(now + FILE_INTEGRITY_EVENT_TOUCH_SECONDS)
        .bind(&event_key)
        .execute(&service.db)
        .await
        .unwrap();

        let mut transaction = service.db.begin_with("BEGIN IMMEDIATE").await.unwrap();
        assert_eq!(
            SecurityEventService::upsert_file_integrity_drift_in_transaction(
                &mut transaction,
                &outbox,
                &evidence,
                file_integrity_drift_text(notification),
                false,
                now + FILE_INTEGRITY_EVENT_TOUCH_SECONDS + 1,
            )
            .await
            .unwrap(),
            FileIntegrityEventMutation::Noop
        );
        transaction.commit().await.unwrap();

        let acknowledged: (String, Option<i64>, i64) = sqlx::query_as(
            "SELECT status, acknowledged_at, notification_seq
             FROM security_events WHERE event_key = ?",
        )
        .bind(&event_key)
        .fetch_one(&service.db)
        .await
        .unwrap();
        assert_eq!(acknowledged.0, "acknowledged");
        assert!(acknowledged.1.is_some());
        assert_eq!(acknowledged.2, 1);

        let mut changed = evidence.clone();
        changed.observed_metadata.size_bytes = Some(2_050);
        let mut transaction = service.db.begin_with("BEGIN IMMEDIATE").await.unwrap();
        assert_eq!(
            SecurityEventService::upsert_file_integrity_drift_in_transaction(
                &mut transaction,
                &outbox,
                &changed,
                file_integrity_drift_text(notification),
                true,
                now + FILE_INTEGRITY_EVENT_TOUCH_SECONDS + 2,
            )
            .await
            .unwrap(),
            FileIntegrityEventMutation::Reopened
        );
        transaction.commit().await.unwrap();

        let reopened: (String, Option<i64>, i64, String) = sqlx::query_as(
            "SELECT status, acknowledged_at, notification_seq, evidence_json
             FROM security_events WHERE event_key = ?",
        )
        .bind(&event_key)
        .fetch_one(&service.db)
        .await
        .unwrap();
        assert_eq!(reopened.0, "open");
        assert!(reopened.1.is_none());
        assert_eq!(reopened.2, 2);
        assert_eq!(reopened.3, serde_json::to_string(&changed).unwrap());

        let outbox_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_outbox WHERE source_event_key = ?",
        )
        .bind(event_key)
        .fetch_one(&service.db)
        .await
        .unwrap();
        assert_eq!(outbox_count, 2);
    }

    #[tokio::test]
    async fn integrity_coverage_escalation_preserves_ack_and_never_enqueues() {
        let service = test_service().await;
        let now = Utc::now().timestamp();
        let mut coverage =
            valid_coverage_evidence(FileIntegrityDegradedReasonV1::CoverageUnavailable);
        let mut transaction = service.db.begin_with("BEGIN IMMEDIATE").await.unwrap();
        assert_eq!(
            SecurityEventService::upsert_file_integrity_coverage_degraded_in_transaction(
                &mut transaction,
                &coverage,
                "Integrity coverage degraded",
                "Open the local Security page.",
                now,
            )
            .await
            .unwrap(),
            FileIntegrityEventMutation::Opened
        );
        transaction.commit().await.unwrap();

        sqlx::query(
            "UPDATE security_events
             SET status = 'acknowledged', acknowledged_at = ?
             WHERE event_key = ?",
        )
        .bind(now)
        .bind(FILE_INTEGRITY_COVERAGE_EVENT_KEY)
        .execute(&service.db)
        .await
        .unwrap();

        coverage.state_revision += 1;
        coverage.observed_generation += 1;
        coverage.observed_at += 1;
        let mut transaction = service.db.begin_with("BEGIN IMMEDIATE").await.unwrap();
        assert_eq!(
            SecurityEventService::upsert_file_integrity_coverage_degraded_in_transaction(
                &mut transaction,
                &coverage,
                "Integrity coverage degraded",
                "Open the local Security page.",
                now + 1,
            )
            .await
            .unwrap(),
            FileIntegrityEventMutation::Noop
        );
        transaction.commit().await.unwrap();

        coverage.degraded_reason = FileIntegrityDegradedReasonV1::BaselineCorrupt;
        let mut transaction = service.db.begin_with("BEGIN IMMEDIATE").await.unwrap();
        assert_eq!(
            SecurityEventService::upsert_file_integrity_coverage_degraded_in_transaction(
                &mut transaction,
                &coverage,
                "Integrity coverage degraded",
                "Open the local Security page.",
                now + 2,
            )
            .await
            .unwrap(),
            FileIntegrityEventMutation::Reopened
        );
        transaction.commit().await.unwrap();

        let escalated: (String, String, Option<i64>) = sqlx::query_as(
            "SELECT severity, status, acknowledged_at
             FROM security_events WHERE event_key = ?",
        )
        .bind(FILE_INTEGRITY_COVERAGE_EVENT_KEY)
        .fetch_one(&service.db)
        .await
        .unwrap();
        assert_eq!(escalated.0, "high");
        assert_eq!(escalated.1, "open");
        assert!(escalated.2.is_none());

        sqlx::query(
            "UPDATE security_events
             SET status = 'acknowledged', acknowledged_at = ?
             WHERE event_key = ?",
        )
        .bind(now + 2)
        .bind(FILE_INTEGRITY_COVERAGE_EVENT_KEY)
        .execute(&service.db)
        .await
        .unwrap();

        coverage.degraded_reason = FileIntegrityDegradedReasonV1::CoverageUnavailable;
        let mut transaction = service.db.begin_with("BEGIN IMMEDIATE").await.unwrap();
        assert_eq!(
            SecurityEventService::upsert_file_integrity_coverage_degraded_in_transaction(
                &mut transaction,
                &coverage,
                "Integrity coverage degraded",
                "Open the local Security page.",
                now + 3,
            )
            .await
            .unwrap(),
            FileIntegrityEventMutation::Updated
        );
        transaction.commit().await.unwrap();

        let deescalated: (String, String, Option<i64>) = sqlx::query_as(
            "SELECT severity, status, acknowledged_at
             FROM security_events WHERE event_key = ?",
        )
        .bind(FILE_INTEGRITY_COVERAGE_EVENT_KEY)
        .fetch_one(&service.db)
        .await
        .unwrap();
        assert_eq!(deescalated.0, "medium");
        assert_eq!(deescalated.1, "acknowledged");
        assert_eq!(deescalated.2, Some(now + 2));

        let mut transaction = service.db.begin_with("BEGIN IMMEDIATE").await.unwrap();
        assert_eq!(
            SecurityEventService::resolve_file_integrity_coverage_degraded_in_transaction(
                &mut transaction,
                now + 4,
            )
            .await
            .unwrap(),
            FileIntegrityEventMutation::Resolved
        );
        transaction.commit().await.unwrap();

        let resolved: (String, Option<i64>, Option<String>, i64) = sqlx::query_as(
            "SELECT status, resolved_at, notification_delivery_status, notification_seq
             FROM security_events WHERE event_key = ?",
        )
        .bind(FILE_INTEGRITY_COVERAGE_EVENT_KEY)
        .fetch_one(&service.db)
        .await
        .unwrap();
        assert_eq!(resolved.0, "resolved");
        assert_eq!(resolved.1, Some(now + 4));
        assert!(resolved.2.is_none());
        assert_eq!(resolved.3, 0);
        let outbox_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notification_outbox")
            .fetch_one(&service.db)
            .await
            .unwrap();
        assert_eq!(outbox_count, 0);
    }

    #[tokio::test]
    async fn disabled_integrity_notification_is_recorded_without_an_outbox_row() {
        let service = test_service().await;
        let outbox = NotificationOutbox::new(
            service.db.clone(),
            Arc::new(NotificationService::disabled_for_tests()),
        );
        let evidence = valid_file_integrity_drift_evidence();
        let event_key = format!("file:sensitive_changed:{}", evidence.path_id);
        let now = Utc::now().timestamp();
        let mut transaction = service.db.begin_with("BEGIN IMMEDIATE").await.unwrap();
        assert_eq!(
            SecurityEventService::upsert_file_integrity_drift_in_transaction(
                &mut transaction,
                &outbox,
                &evidence,
                file_integrity_drift_text(
                    "Sensitive-file integrity changed: severity high, count 1",
                ),
                true,
                now,
            )
            .await
            .unwrap(),
            FileIntegrityEventMutation::Opened
        );
        transaction.commit().await.unwrap();

        let delivery: (i64, Option<String>, Option<i64>, Option<String>) = sqlx::query_as(
            "SELECT notification_seq, notification_delivery_status,
                    notification_delivery_attempts, notification_delivery_error_code
             FROM security_events WHERE event_key = ?",
        )
        .bind(event_key)
        .fetch_one(&service.db)
        .await
        .unwrap();
        assert_eq!(delivery.0, 1);
        assert_eq!(delivery.1.as_deref(), Some("disabled"));
        assert_eq!(delivery.2, Some(0));
        assert!(delivery.3.is_none());
        let outbox_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notification_outbox")
            .fetch_one(&service.db)
            .await
            .unwrap();
        assert_eq!(outbox_count, 0);
    }
}
