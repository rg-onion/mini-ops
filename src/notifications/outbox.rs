use super::{DeliveryErrorCode, DeliveryFailure, NotificationService, ProviderAttempt};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;

const MAX_LIVE_ROWS: i64 = 1000;
const MAX_TERMINAL_ROWS: i64 = 200;
const MAX_ATTEMPTS: i64 = 5;
const MAX_PAYLOAD_BYTES: usize = 4095;
const MAX_SUPPRESSION_SECONDS: i64 = 30 * 60;
const MAX_RETENTION_SECONDS: i64 = 168 * 60 * 60;
const LEASE_SECONDS: i64 = 30;
const WORKER_WAKE_INTERVAL: Duration = Duration::from_secs(5);

const OUTBOX_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS notification_outbox (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    channel          TEXT NOT NULL CHECK (channel = 'telegram'),
    dedup_key        TEXT NOT NULL
                           CHECK (length(dedup_key) BETWEEN 1 AND 255),
    kind             TEXT NOT NULL
                           CHECK (length(kind) BETWEEN 1 AND 64),
    source_event_key TEXT CHECK (source_event_key IS NULL OR
                                 length(source_event_key) BETWEEN 1 AND 255),
    source_event_seq INTEGER,
    payload_json     TEXT NOT NULL
                           CHECK (length(CAST(payload_json AS BLOB))
                                  BETWEEN 1 AND 4095),
    suppress_until   INTEGER NOT NULL,
    state            TEXT NOT NULL
                           CHECK (state IN
                                  ('pending','sending','sent','abandoned')),
    attempts         INTEGER NOT NULL DEFAULT 0
                           CHECK (attempts BETWEEN 0 AND 5),
    next_attempt_at  INTEGER,
    lease_until      INTEGER,
    last_error_code  TEXT CHECK (last_error_code IS NULL OR
                                 length(last_error_code) BETWEEN 1 AND 64),
    last_http_status INTEGER CHECK (last_http_status IS NULL OR
                                    last_http_status BETWEEN 100 AND 599),
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    sent_at          INTEGER,
    abandoned_at     INTEGER,
    CHECK ((source_event_key IS NULL AND source_event_seq IS NULL) OR
           (source_event_key IS NOT NULL AND source_event_seq IS NOT NULL AND
            source_event_seq >= 1)),
    CHECK ((state = 'pending' AND next_attempt_at IS NOT NULL AND
            lease_until IS NULL AND sent_at IS NULL AND abandoned_at IS NULL) OR
           (state = 'sending' AND next_attempt_at IS NULL AND
            lease_until IS NOT NULL AND
            sent_at IS NULL AND abandoned_at IS NULL) OR
           (state = 'sent' AND next_attempt_at IS NULL AND
            lease_until IS NULL AND sent_at IS NOT NULL AND
            abandoned_at IS NULL) OR
           (state = 'abandoned' AND next_attempt_at IS NULL AND
            lease_until IS NULL AND abandoned_at IS NOT NULL AND
            sent_at IS NULL))
)
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EnqueueOutcome {
    Pending { id: i64 },
    Disabled,
    Suppressed,
    Backpressure,
    Failed { code: DeliveryErrorCode },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OutboxRunOutcome {
    Idle,
    Backpressure,
    Sent {
        id: i64,
    },
    RetryScheduled {
        id: i64,
        attempts: i64,
        next_attempt_at: i64,
        code: DeliveryErrorCode,
    },
    Abandoned {
        id: i64,
        attempts: i64,
        code: Option<DeliveryErrorCode>,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct NotificationEvent {
    dedup_key: String,
    kind: String,
    source_event_key: Option<String>,
    source_event_seq: Option<i64>,
    text: String,
    occurred_at: i64,
    suppress_for_seconds: i64,
}

impl NotificationEvent {
    pub(crate) fn generic(
        dedup_key: impl Into<String>,
        kind: impl Into<String>,
        text: impl Into<String>,
        occurred_at: i64,
        suppress_for_seconds: i64,
    ) -> Self {
        Self {
            dedup_key: dedup_key.into(),
            kind: kind.into(),
            source_event_key: None,
            source_event_seq: None,
            text: text.into(),
            occurred_at,
            suppress_for_seconds: suppress_for_seconds.clamp(0, MAX_SUPPRESSION_SECONDS),
        }
    }

    pub(crate) fn security_transition(
        event_key: impl Into<String>,
        sequence: i64,
        kind: impl Into<String>,
        text: impl Into<String>,
        occurred_at: i64,
    ) -> Self {
        let event_key = event_key.into();
        Self {
            dedup_key: format!("security:{event_key}"),
            kind: kind.into(),
            source_event_key: Some(event_key),
            source_event_seq: Some(sequence),
            text: text.into(),
            occurred_at,
            suppress_for_seconds: 0,
        }
    }

    pub(crate) fn file_integrity_transition(
        event_key: impl Into<String>,
        sequence: i64,
        kind: impl Into<String>,
        text: impl Into<String>,
        occurred_at: i64,
    ) -> Self {
        let event_key = event_key.into();
        Self {
            // Integrity alert and recovery transitions for one path are distinct
            // durable occurrences, even while an older delivery is still live.
            dedup_key: format!("security:{event_key}:{sequence}"),
            kind: kind.into(),
            source_event_key: Some(event_key),
            source_event_seq: Some(sequence),
            text: text.into(),
            occurred_at,
            suppress_for_seconds: 0,
        }
    }

    pub(crate) fn ssh_login_transition(
        event_key: impl Into<String>,
        normalized_ip: &str,
        sequence: i64,
        text: impl Into<String>,
        occurred_at: i64,
    ) -> Self {
        let event_key = event_key.into();
        Self {
            dedup_key: format!("ssh:login:{normalized_ip}"),
            kind: "ssh.login".to_string(),
            source_event_key: Some(event_key),
            source_event_seq: Some(sequence),
            text: text.into(),
            occurred_at,
            suppress_for_seconds: 10,
        }
    }
}

#[derive(Clone)]
pub(crate) struct NotificationOutbox {
    db: SqlitePool,
    notifier: Arc<NotificationService>,
    run_guard: Arc<AsyncMutex<()>>,
}

#[derive(Serialize, Deserialize)]
struct StoredPayload {
    version: u8,
    text: String,
    occurred_at: i64,
}

struct ClaimedDelivery {
    id: i64,
    payload_json: String,
    attempts: i64,
    created_at: i64,
    source_event_key: Option<String>,
    source_event_seq: Option<i64>,
}

impl NotificationOutbox {
    pub(crate) fn new(db: SqlitePool, notifier: Arc<NotificationService>) -> Self {
        Self {
            db,
            notifier,
            run_guard: Arc::new(AsyncMutex::new(())),
        }
    }

    pub(crate) async fn init_schema(db: &SqlitePool) -> Result<(), sqlx::Error> {
        sqlx::query(OUTBOX_DDL).execute(db).await?;
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_notification_outbox_event_transition
                ON notification_outbox(channel, source_event_key, source_event_seq)
                WHERE source_event_key IS NOT NULL",
        )
        .execute(db)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_notification_outbox_due
                ON notification_outbox(state, next_attempt_at, id)",
        )
        .execute(db)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_notification_outbox_dedup
                ON notification_outbox(channel, dedup_key, suppress_until)",
        )
        .execute(db)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_notification_outbox_terminal
                ON notification_outbox(state, updated_at)",
        )
        .execute(db)
        .await?;
        Ok(())
    }

    pub(crate) fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(WORKER_WAKE_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                if self.run_once().await.is_err() {
                    tracing::warn!(
                        delivery_error = "database",
                        "Notification outbox worker iteration failed"
                    );
                }
            }
        })
    }

    pub(crate) async fn enqueue(
        &self,
        event: &NotificationEvent,
    ) -> Result<EnqueueOutcome, sqlx::Error> {
        let mut transaction = self.db.begin_with("BEGIN IMMEDIATE").await?;
        let outcome = self
            .enqueue_in_transaction(&mut transaction, event, Utc::now().timestamp())
            .await?;
        transaction.commit().await?;
        Ok(outcome)
    }

    pub(crate) async fn enqueue_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Sqlite>,
        event: &NotificationEvent,
        now: i64,
    ) -> Result<EnqueueOutcome, sqlx::Error> {
        if !self.notifier.is_enabled() {
            return Ok(EnqueueOutcome::Disabled);
        }
        if !valid_event(event) || self.notifier.payload_contains_credentials(&event.text) {
            return Ok(EnqueueOutcome::Failed {
                code: DeliveryErrorCode::InvalidResponse,
            });
        }

        let payload_json = match serde_json::to_string(&StoredPayload {
            version: 1,
            text: event.text.clone(),
            occurred_at: event.occurred_at,
        }) {
            Ok(payload) if !payload.is_empty() && payload.len() <= MAX_PAYLOAD_BYTES => payload,
            _ => {
                return Ok(EnqueueOutcome::Failed {
                    code: DeliveryErrorCode::InvalidResponse,
                });
            }
        };
        let suppress_until = now.saturating_add(event.suppress_for_seconds.max(0));

        let result = sqlx::query(
            "INSERT INTO notification_outbox (
                channel, dedup_key, kind, source_event_key, source_event_seq,
                payload_json, suppress_until, state, attempts, next_attempt_at,
                lease_until, last_error_code, last_http_status, created_at,
                updated_at, sent_at, abandoned_at
            )
            SELECT 'telegram', ?, ?, ?, ?, ?, ?, 'pending', 0, ?,
                   NULL, NULL, NULL, ?, ?, NULL, NULL
            WHERE (
                SELECT COUNT(*) FROM notification_outbox
                WHERE state IN ('pending', 'sending')
            ) < ?
            AND NOT EXISTS (
                SELECT 1 FROM notification_outbox
                WHERE channel = 'telegram' AND dedup_key = ?
                  AND (
                    state IN ('pending', 'sending') OR
                    (state IN ('sent', 'abandoned') AND suppress_until > ?)
                  )
            )
            ON CONFLICT(channel, source_event_key, source_event_seq)
                WHERE source_event_key IS NOT NULL DO NOTHING",
        )
        .bind(&event.dedup_key)
        .bind(&event.kind)
        .bind(event.source_event_key.as_deref())
        .bind(event.source_event_seq)
        .bind(payload_json)
        .bind(suppress_until)
        .bind(now)
        .bind(now)
        .bind(now)
        .bind(MAX_LIVE_ROWS)
        .bind(&event.dedup_key)
        .bind(now)
        .execute(&mut **transaction)
        .await?;

        if result.rows_affected() == 1 {
            return Ok(EnqueueOutcome::Pending {
                id: result.last_insert_rowid(),
            });
        }

        let is_suppressed: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM notification_outbox
                WHERE channel = 'telegram'
                  AND (
                    (dedup_key = ? AND (
                        state IN ('pending', 'sending') OR
                        (state IN ('sent', 'abandoned') AND suppress_until > ?)
                    )) OR (
                        source_event_key IS NOT NULL
                        AND source_event_key = ?
                        AND source_event_seq = ?
                    )
                  )
             )",
        )
        .bind(&event.dedup_key)
        .bind(now)
        .bind(event.source_event_key.as_deref())
        .bind(event.source_event_seq)
        .fetch_one(&mut **transaction)
        .await?;
        if is_suppressed {
            return Ok(EnqueueOutcome::Suppressed);
        }

        let live_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_outbox
             WHERE state IN ('pending', 'sending')",
        )
        .fetch_one(&mut **transaction)
        .await?;
        if live_count >= MAX_LIVE_ROWS {
            set_delivery_degraded(transaction, now).await?;
            Ok(EnqueueOutcome::Backpressure)
        } else {
            Ok(EnqueueOutcome::Suppressed)
        }
    }

    pub(crate) async fn run_once(&self) -> Result<OutboxRunOutcome, sqlx::Error> {
        self.run_once_at(Utc::now().timestamp()).await
    }

    async fn run_once_at(&self, now: i64) -> Result<OutboxRunOutcome, sqlx::Error> {
        let _run_guard = self.run_guard.lock().await;
        self.maintain(now).await?;
        let Some(claimed) = self.claim_due(now).await? else {
            let terminal_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM notification_outbox
                 WHERE state IN ('sent', 'abandoned')",
            )
            .fetch_one(&self.db)
            .await?;
            let due_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM notification_outbox
                 WHERE (state = 'pending' AND next_attempt_at <= ?)
                    OR (state = 'sending' AND lease_until <= ?)",
            )
            .bind(now)
            .bind(now)
            .fetch_one(&self.db)
            .await?;
            return if terminal_count >= MAX_TERMINAL_ROWS && due_count > 0 {
                self.set_delivery_degraded(now).await?;
                Ok(OutboxRunOutcome::Backpressure)
            } else {
                Ok(OutboxRunOutcome::Idle)
            };
        };

        let payload = match serde_json::from_str::<StoredPayload>(&claimed.payload_json) {
            Ok(payload) if payload.version == 1 => payload,
            _ => {
                return self
                    .finish_failure(
                        &claimed,
                        now,
                        DeliveryFailure {
                            code: DeliveryErrorCode::InvalidResponse,
                            retryable: false,
                            http_status: None,
                        },
                    )
                    .await;
            }
        };

        match self.notifier.deliver_rendered_text(&payload.text).await {
            ProviderAttempt::Sent => self.finish_sent(&claimed, now).await,
            ProviderAttempt::Disabled => self.finish_disabled(&claimed, now).await,
            ProviderAttempt::Failed(failure) => self.finish_failure(&claimed, now, failure).await,
        }
    }

    async fn maintain(&self, now: i64) -> Result<(), sqlx::Error> {
        let mut transaction = self.db.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(
            "DELETE FROM notification_outbox
             WHERE id IN (
                SELECT id FROM notification_outbox
                WHERE state IN ('sent', 'abandoned')
                  AND updated_at < ? AND suppress_until <= ?
                ORDER BY updated_at, id
             )",
        )
        .bind(now.saturating_sub(MAX_RETENTION_SECONDS))
        .bind(now)
        .execute(&mut *transaction)
        .await?;

        let terminal_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_outbox
             WHERE state IN ('sent', 'abandoned')",
        )
        .fetch_one(&mut *transaction)
        .await?;
        let has_due_work: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM notification_outbox
                WHERE (state = 'pending' AND next_attempt_at <= ?)
                   OR (state = 'sending' AND lease_until <= ?)
             )",
        )
        .bind(now)
        .bind(now)
        .fetch_one(&mut *transaction)
        .await?;
        let terminal_target = if has_due_work {
            MAX_TERMINAL_ROWS.saturating_sub(1)
        } else {
            MAX_TERMINAL_ROWS
        };
        let removable = terminal_count.saturating_sub(terminal_target);
        if removable > 0 {
            sqlx::query(
                "DELETE FROM notification_outbox
                 WHERE id IN (
                    SELECT id FROM notification_outbox
                    WHERE state IN ('sent', 'abandoned') AND suppress_until <= ?
                    ORDER BY updated_at, id LIMIT ?
                 )",
            )
            .bind(now)
            .bind(removable)
            .execute(&mut *transaction)
            .await?;
        }

        sqlx::query(
            "UPDATE notification_outbox
             SET state = 'pending', next_attempt_at = ?, lease_until = NULL,
                 last_error_code = ?, last_http_status = NULL,
                 updated_at = ?
             WHERE state = 'sending' AND lease_until <= ? AND attempts < ?",
        )
        .bind(now)
        .bind(DeliveryErrorCode::LeaseExpired.as_str())
        .bind(now)
        .bind(now)
        .bind(MAX_ATTEMPTS)
        .execute(&mut *transaction)
        .await?;

        let mut terminal_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_outbox
             WHERE state IN ('sent', 'abandoned')",
        )
        .fetch_one(&mut *transaction)
        .await?;
        let terminal_slots = MAX_TERMINAL_ROWS.saturating_sub(terminal_count);
        if terminal_slots > 0 {
            sqlx::query(
                "UPDATE notification_outbox
                 SET state = 'abandoned', next_attempt_at = NULL,
                     lease_until = NULL, last_error_code = ?,
                     last_http_status = NULL, updated_at = ?, abandoned_at = ?
                 WHERE id IN (
                    SELECT id FROM notification_outbox
                    WHERE ((state = 'sending' AND lease_until <= ?) OR state = 'pending')
                      AND attempts >= ?
                    ORDER BY created_at, id LIMIT ?
                 )",
            )
            .bind(DeliveryErrorCode::LeaseExpired.as_str())
            .bind(now)
            .bind(now)
            .bind(now)
            .bind(MAX_ATTEMPTS)
            .bind(terminal_slots)
            .execute(&mut *transaction)
            .await?;
        }

        terminal_count = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_outbox
             WHERE state IN ('sent', 'abandoned')",
        )
        .fetch_one(&mut *transaction)
        .await?;
        let terminal_slots = MAX_TERMINAL_ROWS.saturating_sub(terminal_count);
        if terminal_slots > 0 {
            sqlx::query(
                "UPDATE notification_outbox
                 SET state = 'abandoned', next_attempt_at = NULL,
                     lease_until = NULL, last_error_code = ?,
                     last_http_status = NULL, updated_at = ?, abandoned_at = ?
                 WHERE id IN (
                    SELECT id FROM notification_outbox
                    WHERE state = 'pending' AND created_at < ?
                    ORDER BY created_at, id LIMIT ?
                 )",
            )
            .bind(DeliveryErrorCode::RetentionExpired.as_str())
            .bind(now)
            .bind(now)
            .bind(now.saturating_sub(MAX_RETENTION_SECONDS))
            .bind(terminal_slots)
            .execute(&mut *transaction)
            .await?;
        }

        sqlx::query(
            "UPDATE security_events
             SET notification_delivery_status = 'failed',
                 notification_delivery_attempts = (
                    SELECT attempts FROM notification_outbox
                    WHERE source_event_key = security_events.event_key
                      AND source_event_seq = security_events.notification_seq
                      AND state = 'abandoned' AND updated_at = ? LIMIT 1
                 ),
                 notification_delivery_updated_at = ?,
                 notification_delivery_error_code = (
                    SELECT last_error_code FROM notification_outbox
                    WHERE source_event_key = security_events.event_key
                      AND source_event_seq = security_events.notification_seq
                      AND state = 'abandoned' AND updated_at = ? LIMIT 1
                 )
             WHERE EXISTS (
                SELECT 1 FROM notification_outbox
                WHERE source_event_key = security_events.event_key
                  AND source_event_seq = security_events.notification_seq
                  AND state = 'abandoned' AND updated_at = ?
             )",
        )
        .bind(now)
        .bind(now)
        .bind(now)
        .bind(now)
        .execute(&mut *transaction)
        .await?;

        let live_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_outbox
             WHERE state IN ('pending', 'sending')",
        )
        .fetch_one(&mut *transaction)
        .await?;
        let terminal_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_outbox
             WHERE state IN ('sent', 'abandoned')",
        )
        .fetch_one(&mut *transaction)
        .await?;
        let due_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_outbox
             WHERE (state = 'pending' AND next_attempt_at <= ?)
                OR (state = 'sending' AND lease_until <= ?)",
        )
        .bind(now)
        .bind(now)
        .fetch_one(&mut *transaction)
        .await?;
        if live_count < MAX_LIVE_ROWS && (terminal_count < MAX_TERMINAL_ROWS || due_count == 0) {
            resolve_delivery_degraded(&mut transaction, now).await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn set_delivery_degraded(&self, now: i64) -> Result<(), sqlx::Error> {
        let mut transaction = self.db.begin_with("BEGIN IMMEDIATE").await?;
        set_delivery_degraded(&mut transaction, now).await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn claim_due(&self, now: i64) -> Result<Option<ClaimedDelivery>, sqlx::Error> {
        let mut transaction = self.db.begin_with("BEGIN IMMEDIATE").await?;
        let row = sqlx::query(
            "UPDATE notification_outbox
             SET state = 'sending', attempts = attempts + 1,
                 next_attempt_at = NULL, lease_until = ?, updated_at = ?
             WHERE id = (
                SELECT id FROM notification_outbox
                WHERE state = 'pending' AND next_attempt_at <= ? AND attempts < ?
                ORDER BY next_attempt_at, id LIMIT 1
             )
             AND (
                SELECT COUNT(*) FROM notification_outbox
                WHERE state IN ('sent', 'abandoned')
             ) < ?
             RETURNING id, payload_json, attempts, created_at,
                       source_event_key, source_event_seq",
        )
        .bind(now.saturating_add(LEASE_SECONDS))
        .bind(now)
        .bind(now)
        .bind(MAX_ATTEMPTS)
        .bind(MAX_TERMINAL_ROWS)
        .fetch_optional(&mut *transaction)
        .await?;
        let claimed = row.map(|row| ClaimedDelivery {
            id: row.get("id"),
            payload_json: row.get("payload_json"),
            attempts: row.get("attempts"),
            created_at: row.get("created_at"),
            source_event_key: row.get("source_event_key"),
            source_event_seq: row.get("source_event_seq"),
        });
        if let Some(claimed) = &claimed {
            update_security_summary(
                &mut transaction,
                claimed,
                "sending",
                claimed.attempts,
                now,
                None,
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(claimed)
    }

    async fn finish_sent(
        &self,
        claimed: &ClaimedDelivery,
        now: i64,
    ) -> Result<OutboxRunOutcome, sqlx::Error> {
        let attempts = claimed.attempts;
        let mut transaction = self.db.begin().await?;
        sqlx::query(
            "UPDATE notification_outbox
             SET state = 'sent', attempts = ?, next_attempt_at = NULL,
                 lease_until = NULL, last_error_code = NULL,
                 last_http_status = NULL, updated_at = ?, sent_at = ?
             WHERE id = ? AND state = 'sending'",
        )
        .bind(attempts)
        .bind(now)
        .bind(now)
        .bind(claimed.id)
        .execute(&mut *transaction)
        .await?;
        update_security_summary(&mut transaction, claimed, "sent", attempts, now, None).await?;
        transaction.commit().await?;
        Ok(OutboxRunOutcome::Sent { id: claimed.id })
    }

    async fn finish_disabled(
        &self,
        claimed: &ClaimedDelivery,
        now: i64,
    ) -> Result<OutboxRunOutcome, sqlx::Error> {
        let mut transaction = self.db.begin().await?;
        sqlx::query(
            "UPDATE notification_outbox
             SET state = 'abandoned', next_attempt_at = NULL,
                 lease_until = NULL, last_error_code = NULL,
                 last_http_status = NULL, updated_at = ?, abandoned_at = ?
             WHERE id = ? AND state = 'sending'",
        )
        .bind(now)
        .bind(now)
        .bind(claimed.id)
        .execute(&mut *transaction)
        .await?;
        update_security_summary(
            &mut transaction,
            claimed,
            "disabled",
            claimed.attempts,
            now,
            None,
        )
        .await?;
        transaction.commit().await?;
        Ok(OutboxRunOutcome::Abandoned {
            id: claimed.id,
            attempts: claimed.attempts,
            code: None,
        })
    }

    async fn finish_failure(
        &self,
        claimed: &ClaimedDelivery,
        now: i64,
        failure: DeliveryFailure,
    ) -> Result<OutboxRunOutcome, sqlx::Error> {
        let attempts = claimed.attempts;
        let retention_expired = claimed.created_at < now.saturating_sub(MAX_RETENTION_SECONDS);
        let retry = failure.retryable && attempts < MAX_ATTEMPTS && !retention_expired;
        let mut transaction = self.db.begin().await?;
        if retry {
            let next_attempt_at = now.saturating_add(retry_delay_seconds(attempts));
            sqlx::query(
                "UPDATE notification_outbox
                 SET state = 'pending', attempts = ?, next_attempt_at = ?,
                     lease_until = NULL, last_error_code = ?,
                     last_http_status = ?, updated_at = ?
                 WHERE id = ? AND state = 'sending'",
            )
            .bind(attempts)
            .bind(next_attempt_at)
            .bind(failure.code.as_str())
            .bind(failure.http_status)
            .bind(now)
            .bind(claimed.id)
            .execute(&mut *transaction)
            .await?;
            update_security_summary(
                &mut transaction,
                claimed,
                "pending",
                attempts,
                now,
                Some(failure.code),
            )
            .await?;
            transaction.commit().await?;
            Ok(OutboxRunOutcome::RetryScheduled {
                id: claimed.id,
                attempts,
                next_attempt_at,
                code: failure.code,
            })
        } else {
            let code = if retention_expired {
                DeliveryErrorCode::RetentionExpired
            } else {
                failure.code
            };
            sqlx::query(
                "UPDATE notification_outbox
                 SET state = 'abandoned', attempts = ?, next_attempt_at = NULL,
                     lease_until = NULL, last_error_code = ?,
                     last_http_status = ?, updated_at = ?, abandoned_at = ?
                 WHERE id = ? AND state = 'sending'",
            )
            .bind(attempts)
            .bind(code.as_str())
            .bind(failure.http_status)
            .bind(now)
            .bind(now)
            .bind(claimed.id)
            .execute(&mut *transaction)
            .await?;
            update_security_summary(
                &mut transaction,
                claimed,
                "failed",
                attempts,
                now,
                Some(code),
            )
            .await?;
            transaction.commit().await?;
            Ok(OutboxRunOutcome::Abandoned {
                id: claimed.id,
                attempts,
                code: Some(code),
            })
        }
    }
}

async fn update_security_summary(
    transaction: &mut Transaction<'_, Sqlite>,
    claimed: &ClaimedDelivery,
    status: &str,
    attempts: i64,
    now: i64,
    error: Option<DeliveryErrorCode>,
) -> Result<(), sqlx::Error> {
    let (Some(event_key), Some(sequence)) = (&claimed.source_event_key, claimed.source_event_seq)
    else {
        return Ok(());
    };
    sqlx::query(
        "UPDATE security_events
         SET notification_delivery_status = ?,
             notification_delivery_attempts = ?,
             notification_delivery_updated_at = ?,
             notification_delivery_error_code = ?
         WHERE event_key = ? AND notification_seq = ?",
    )
    .bind(status)
    .bind(attempts)
    .bind(now)
    .bind(error.map(DeliveryErrorCode::as_str))
    .bind(event_key)
    .bind(sequence)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn set_delivery_degraded(
    transaction: &mut Transaction<'_, Sqlite>,
    now: i64,
) -> Result<(), sqlx::Error> {
    let lang = crate::i18n::Lang::from_headers(&crate::i18n::HeaderMap::new());
    let title = crate::i18n::t("notification.delivery_degraded.title", &lang);
    let message = crate::i18n::t("notification.delivery_degraded.message", &lang);
    sqlx::query(
        "INSERT INTO security_events (
            event_key, event_type, severity, title, message, evidence_json,
            evidence_schema_version,
            status, first_seen, last_seen, acknowledged_at, resolved_at
         ) VALUES (
            'notification:delivery_degraded',
            'notification.delivery_degraded',
            'high',
            ?,
            ?,
            '{\"reason\":\"backpressure\",\"live_limit\":1000,\"terminal_limit\":200}',
            1,
            'open', ?, ?, NULL, NULL
         )
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
            resolved_at = NULL,
            notification_delivery_status = NULL,
            notification_delivery_attempts = NULL,
            notification_delivery_updated_at = NULL,
            notification_delivery_error_code = NULL",
    )
    .bind(title)
    .bind(message)
    .bind(now)
    .bind(now)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn resolve_delivery_degraded(
    transaction: &mut Transaction<'_, Sqlite>,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE security_events
         SET status = 'resolved', last_seen = ?, resolved_at = ?
         WHERE event_key = 'notification:delivery_degraded'
           AND status IN ('open', 'acknowledged')",
    )
    .bind(now)
    .bind(now)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn valid_event(event: &NotificationEvent) -> bool {
    !event.dedup_key.is_empty()
        && event.dedup_key.len() <= 255
        && !event.dedup_key.chars().any(char::is_control)
        && !event.kind.is_empty()
        && event.kind.len() <= 64
        && !event.kind.chars().any(char::is_control)
        && match (&event.source_event_key, event.source_event_seq) {
            (None, None) => true,
            (Some(key), Some(sequence)) => {
                !key.is_empty()
                    && key.len() <= 255
                    && !key.chars().any(char::is_control)
                    && sequence >= 1
            }
            _ => false,
        }
}

fn retry_delay_seconds(attempts: i64) -> i64 {
    match attempts {
        i64::MIN..=1 => 30,
        2 => 120,
        3 => 480,
        _ => 1800,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notifications::NotificationService;
    use crate::security::SecurityCheck;
    use crate::security_events::SecurityEventService;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::path::{Path, PathBuf};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn test_outbox(notifier: NotificationService) -> NotificationOutbox {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory sqlite should connect");
        NotificationOutbox::init_schema(&pool)
            .await
            .expect("outbox schema should initialize");
        NotificationOutbox::new(pool, Arc::new(notifier))
    }

    async fn full_test_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory sqlite should connect");
        SecurityEventService::init_schema(&pool)
            .await
            .expect("application schema should initialize");
        pool
    }

    async fn file_pool(path: &Path) -> SqlitePool {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .expect("file sqlite should connect");
        SecurityEventService::init_schema(&pool)
            .await
            .expect("application schema should initialize");
        pool
    }

    async fn spawn_sequence_server(
        replies: Vec<(u16, &'static [u8])>,
    ) -> (String, tokio::task::JoinHandle<()>) {
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
            for (status, body) in replies {
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
                    "HTTP/1.1 {status} Mock\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.write_all(body).await.unwrap();
            }
        });
        (origin, handle)
    }

    fn temp_db_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "mini-ops-{label}-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4()
        ))
    }

    fn remove_sqlite_files(path: &Path) {
        for suffix in ["", "-wal", "-shm"] {
            let candidate = PathBuf::from(format!("{}{suffix}", path.display()));
            if let Err(error) = std::fs::remove_file(&candidate)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                panic!("failed to remove test database: {error}");
            }
        }
    }

    #[test]
    fn retry_schedule_is_bounded() {
        assert_eq!(retry_delay_seconds(1), 30);
        assert_eq!(retry_delay_seconds(2), 120);
        assert_eq!(retry_delay_seconds(3), 480);
        assert_eq!(retry_delay_seconds(4), 1800);
        assert_eq!(retry_delay_seconds(5), 1800);
    }

    #[tokio::test]
    async fn disabled_configuration_does_not_enqueue_payload() {
        let outbox = test_outbox(NotificationService::disabled_for_tests()).await;
        let event = NotificationEvent::generic(
            "metric:cpu:critical",
            "metric.critical",
            "sentinel-payload",
            1_700_000_000,
            1800,
        );
        assert_eq!(
            outbox.enqueue(&event).await.unwrap(),
            EnqueueOutcome::Disabled
        );
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notification_outbox")
            .fetch_one(&outbox.db)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn payload_and_semantic_dedup_are_bounded() {
        let notifier = NotificationService::with_test_endpoint(
            "sentinel-token",
            "http://127.0.0.1:9".to_string(),
        );
        let outbox = test_outbox(notifier).await;
        let event = NotificationEvent::generic(
            "metric:cpu:critical",
            "metric.critical",
            "cpu=99.1",
            1_700_000_000,
            1800,
        );
        assert!(matches!(
            outbox.enqueue(&event).await.unwrap(),
            EnqueueOutcome::Pending { .. }
        ));
        assert_eq!(
            outbox.enqueue(&event).await.unwrap(),
            EnqueueOutcome::Suppressed
        );

        let stored: String =
            sqlx::query_scalar("SELECT payload_json FROM notification_outbox LIMIT 1")
                .fetch_one(&outbox.db)
                .await
                .unwrap();
        assert!(stored.len() < 4096);
        assert!(!stored.contains("sentinel-token"));
        assert!(!stored.contains("123456"));
    }

    #[tokio::test]
    async fn concurrent_same_key_producers_create_one_occurrence() {
        const PRODUCERS: usize = 16;

        let path = temp_db_path("outbox-concurrent-dedup");
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(PRODUCERS as u32)
            .connect_with(options)
            .await
            .unwrap();
        SecurityEventService::init_schema(&pool).await.unwrap();
        let outbox = Arc::new(NotificationOutbox::new(
            pool.clone(),
            Arc::new(NotificationService::with_test_endpoint(
                "123456:test",
                "http://127.0.0.1:9".to_string(),
            )),
        ));
        let event = NotificationEvent::generic(
            "metric:cpu:critical",
            "metric.critical",
            "cpu high",
            Utc::now().timestamp(),
            1800,
        );
        let barrier = Arc::new(tokio::sync::Barrier::new(PRODUCERS));
        let mut tasks = Vec::with_capacity(PRODUCERS);
        for _ in 0..PRODUCERS {
            let outbox = Arc::clone(&outbox);
            let event = event.clone();
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                outbox.enqueue(&event).await
            }));
        }

        let mut pending = 0;
        let mut suppressed = 0;
        for task in tasks {
            match task.await.unwrap().unwrap() {
                EnqueueOutcome::Pending { .. } => pending += 1,
                EnqueueOutcome::Suppressed => suppressed += 1,
                other => panic!("unexpected concurrent enqueue outcome: {other:?}"),
            }
        }
        assert_eq!(pending, 1);
        assert_eq!(suppressed, PRODUCERS - 1);
        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_outbox
             WHERE dedup_key = 'metric:cpu:critical'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(rows, 1);

        drop(outbox);
        pool.close().await;
        remove_sqlite_files(&path);
    }

    #[tokio::test]
    async fn credential_sentinel_is_rejected_before_database_write() {
        let notifier = NotificationService::with_test_endpoint(
            "123456:SENTINEL_TOKEN",
            "http://127.0.0.1:9".to_string(),
        );
        let outbox = test_outbox(notifier).await;
        let event = NotificationEvent::generic(
            "metric:disk:low",
            "metric.critical",
            "accidental 123456:SENTINEL_TOKEN disclosure",
            1_700_000_000,
            1800,
        );
        assert_eq!(
            outbox.enqueue(&event).await.unwrap(),
            EnqueueOutcome::Failed {
                code: DeliveryErrorCode::InvalidResponse,
            }
        );
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notification_outbox")
            .fetch_one(&outbox.db)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn claimed_attempts_survive_lease_expiry_and_stop_at_five() {
        let pool = full_test_pool().await;
        let notifier = Arc::new(NotificationService::with_test_endpoint(
            "123456:test",
            "http://127.0.0.1:9".to_string(),
        ));
        let outbox = NotificationOutbox::new(pool, notifier);
        let event = NotificationEvent::generic(
            "metric:cpu:critical",
            "metric.critical",
            "cpu high",
            1_700_000_000,
            1800,
        );
        assert!(matches!(
            outbox.enqueue(&event).await.unwrap(),
            EnqueueOutcome::Pending { .. }
        ));

        let mut now = Utc::now().timestamp().saturating_add(1);
        for expected_attempt in 1..=MAX_ATTEMPTS {
            let claimed = outbox
                .claim_due(now)
                .await
                .unwrap()
                .expect("delivery should be claimed");
            assert_eq!(claimed.attempts, expected_attempt);
            now = now.saturating_add(LEASE_SECONDS + 1);
            outbox.maintain(now).await.unwrap();
        }

        assert!(outbox.claim_due(now).await.unwrap().is_none());
        let row = sqlx::query("SELECT state, attempts, last_error_code FROM notification_outbox")
            .fetch_one(&outbox.db)
            .await
            .unwrap();
        assert_eq!(row.get::<String, _>("state"), "abandoned");
        assert_eq!(row.get::<i64, _>("attempts"), MAX_ATTEMPTS);
        assert_eq!(row.get::<String, _>("last_error_code"), "lease_expired");
    }

    #[tokio::test]
    async fn failed_delivery_retries_after_restart_and_then_records_success() {
        let path = temp_db_path("outbox-restart");
        let (origin, server) = spawn_sequence_server(vec![
            (500, br#"{"ok":false,"description":"SENTINEL_RESPONSE"}"#),
            (200, br#"{"ok":true}"#),
        ])
        .await;
        let token = "123456:SENTINEL_TOKEN";
        let pool = file_pool(&path).await;
        let first = NotificationOutbox::new(
            pool.clone(),
            Arc::new(NotificationService::with_test_endpoint(
                token,
                origin.clone(),
            )),
        );
        let event = NotificationEvent::generic(
            "metric:disk:low",
            "metric.critical",
            "disk low",
            Utc::now().timestamp(),
            1800,
        );
        assert!(matches!(
            first.enqueue(&event).await.unwrap(),
            EnqueueOutcome::Pending { .. }
        ));
        let now = Utc::now().timestamp().saturating_add(1);
        let next_attempt_at = match first.run_once_at(now).await.unwrap() {
            OutboxRunOutcome::RetryScheduled {
                attempts,
                next_attempt_at,
                code,
                ..
            } => {
                assert_eq!(attempts, 1);
                assert_eq!(code, DeliveryErrorCode::Http5xx);
                assert_eq!(next_attempt_at, now + 30);
                next_attempt_at
            }
            other => panic!("expected retry, got {other:?}"),
        };
        let failed_row = sqlx::query(
            "SELECT state, attempts, last_error_code, last_http_status,
                    payload_json
             FROM notification_outbox",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(failed_row.get::<String, _>("state"), "pending");
        assert_eq!(failed_row.get::<i64, _>("attempts"), 1);
        assert_eq!(failed_row.get::<String, _>("last_error_code"), "http_5xx");
        assert_eq!(failed_row.get::<i64, _>("last_http_status"), 500);
        let failed_payload = failed_row.get::<String, _>("payload_json");
        assert!(!failed_payload.contains(token));
        assert!(!failed_payload.contains("SENTINEL_RESPONSE"));
        drop(first);
        pool.close().await;

        let restarted_pool = file_pool(&path).await;
        let restarted = NotificationOutbox::new(
            restarted_pool.clone(),
            Arc::new(NotificationService::with_test_endpoint(token, origin)),
        );
        assert!(matches!(
            restarted.run_once_at(next_attempt_at).await.unwrap(),
            OutboxRunOutcome::Sent { .. }
        ));
        server.await.unwrap();

        let row = sqlx::query(
            "SELECT state, attempts, payload_json, last_error_code
             FROM notification_outbox",
        )
        .fetch_one(&restarted_pool)
        .await
        .unwrap();
        assert_eq!(row.get::<String, _>("state"), "sent");
        assert_eq!(row.get::<i64, _>("attempts"), 2);
        let payload = row.get::<String, _>("payload_json");
        assert!(!payload.contains(token));
        assert!(!payload.contains("SENTINEL_RESPONSE"));
        assert!(row.get::<Option<String>, _>("last_error_code").is_none());

        drop(restarted);
        restarted_pool.close().await;
        remove_sqlite_files(&path);
    }

    #[tokio::test]
    async fn late_retry_does_not_overwrite_newer_security_transition_summary() {
        let (origin, server) =
            spawn_sequence_server(vec![(500, br#"{"ok":false}"#), (200, br#"{"ok":true}"#)]).await;
        let pool = full_test_pool().await;
        let events = SecurityEventService::new(pool.clone());
        let outbox = NotificationOutbox::new(
            pool.clone(),
            Arc::new(NotificationService::with_test_endpoint(
                "123456:test",
                origin,
            )),
        );
        let failed = SecurityCheck {
            id: "test.outbox_late_retry".to_string(),
            name: "Late retry".to_string(),
            category: "test".to_string(),
            severity: "high".to_string(),
            status: "FAIL".to_string(),
            message: "failed".to_string(),
            evidence: Vec::new(),
            remediation: "fix".to_string(),
            references: Vec::new(),
            metadata: std::collections::HashMap::new(),
        };
        assert!(matches!(
            events
                .raise_audit_event_with_notification(&failed, &outbox, "failure")
                .await
                .unwrap(),
            Some(EnqueueOutcome::Pending { .. })
        ));
        let now = Utc::now().timestamp().saturating_add(1);
        let next_attempt_at = match outbox.run_once_at(now).await.unwrap() {
            OutboxRunOutcome::RetryScheduled {
                next_attempt_at, ..
            } => next_attempt_at,
            other => panic!("expected retry, got {other:?}"),
        };

        let passed = SecurityCheck {
            status: "PASS".to_string(),
            ..failed
        };
        assert_eq!(
            events
                .resolve_audit_event_with_notification(&passed, &outbox, "resolved")
                .await
                .unwrap(),
            Some(EnqueueOutcome::Suppressed)
        );
        assert!(matches!(
            outbox.run_once_at(next_attempt_at).await.unwrap(),
            OutboxRunOutcome::Sent { .. }
        ));
        server.await.unwrap();

        let row = sqlx::query(
            "SELECT notification_seq, notification_delivery_status,
                    notification_delivery_attempts,
                    notification_delivery_error_code
             FROM security_events
             WHERE event_key = 'audit:test.outbox_late_retry'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.get::<i64, _>("notification_seq"), 2);
        assert_eq!(
            row.get::<String, _>("notification_delivery_status"),
            "suppressed"
        );
        assert_eq!(row.get::<i64, _>("notification_delivery_attempts"), 0);
        assert!(
            row.get::<Option<String>, _>("notification_delivery_error_code")
                .is_none()
        );
    }

    #[tokio::test]
    async fn terminal_failure_is_visible_through_redacted_security_event_contract() {
        let (origin, server) = spawn_sequence_server(vec![(
            400,
            br#"{"ok":false,"description":"SENTINEL_RESPONSE"}"#,
        )])
        .await;
        let pool = full_test_pool().await;
        let events = SecurityEventService::new(pool.clone());
        let outbox = NotificationOutbox::new(
            pool,
            Arc::new(NotificationService::with_test_endpoint(
                "123456:SENTINEL_TOKEN",
                origin,
            )),
        );
        let failed = SecurityCheck {
            id: "test.outbox_terminal_failure".to_string(),
            name: "Terminal failure".to_string(),
            category: "test".to_string(),
            severity: "high".to_string(),
            status: "FAIL".to_string(),
            message: "failed".to_string(),
            evidence: Vec::new(),
            remediation: "fix".to_string(),
            references: Vec::new(),
            metadata: std::collections::HashMap::new(),
        };
        assert!(matches!(
            events
                .raise_audit_event_with_notification(&failed, &outbox, "failure")
                .await
                .unwrap(),
            Some(EnqueueOutcome::Pending { .. })
        ));

        assert!(matches!(
            outbox
                .run_once_at(Utc::now().timestamp().saturating_add(1))
                .await
                .unwrap(),
            OutboxRunOutcome::Abandoned {
                attempts: 1,
                code: Some(DeliveryErrorCode::Http4xx),
                ..
            }
        ));
        server.await.unwrap();

        let listed = events.list(None, 10).await.unwrap();
        let event = listed
            .iter()
            .find(|event| event.event_key == "audit:test.outbox_terminal_failure")
            .expect("failed event remains visible");
        assert_eq!(
            event.notification_delivery_status.as_deref(),
            Some("failed")
        );
        assert_eq!(event.notification_delivery_attempts, Some(1));
        assert!(event.notification_delivery_updated_at.is_some());
        assert_eq!(
            event.notification_delivery_error_code.as_deref(),
            Some("http_4xx")
        );

        let public_json = serde_json::to_string(event).unwrap();
        assert!(!public_json.contains("notification_seq"));
        assert!(!public_json.contains("SENTINEL_TOKEN"));
        assert!(!public_json.contains("SENTINEL_RESPONSE"));
    }

    #[tokio::test]
    async fn expired_terminal_tombstone_makes_room_for_due_delivery_at_capacity() {
        let pool = full_test_pool().await;
        let outbox = NotificationOutbox::new(
            pool.clone(),
            Arc::new(NotificationService::disabled_for_tests()),
        );
        let now = Utc::now().timestamp();
        let mut transaction = pool.begin().await.unwrap();
        for index in 0..MAX_TERMINAL_ROWS {
            sqlx::query(
                "INSERT INTO notification_outbox (
                    channel, dedup_key, kind, payload_json, suppress_until,
                    state, attempts, next_attempt_at, lease_until,
                    created_at, updated_at, sent_at, abandoned_at
                 ) VALUES (
                    'telegram', ?, 'test.terminal',
                    '{\"version\":1,\"text\":\"sent\",\"occurred_at\":1}',
                    ?, 'sent', 1, NULL, NULL, ?, ?, ?, NULL
                 )",
            )
            .bind(format!("terminal:{index}"))
            .bind(now.saturating_sub(1))
            .bind(now.saturating_sub(2))
            .bind(now.saturating_sub(2))
            .bind(now.saturating_sub(2))
            .execute(&mut *transaction)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO notification_outbox (
                channel, dedup_key, kind, payload_json, suppress_until,
                state, attempts, next_attempt_at, lease_until,
                created_at, updated_at, sent_at, abandoned_at
             ) VALUES (
                'telegram', 'due:one', 'test.due',
                '{\"version\":1,\"text\":\"due\",\"occurred_at\":1}',
                ?, 'pending', 0, ?, NULL, ?, ?, NULL, NULL
             )",
        )
        .bind(now)
        .bind(now)
        .bind(now)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .unwrap();
        transaction.commit().await.unwrap();

        assert!(matches!(
            outbox.run_once_at(now).await.unwrap(),
            OutboxRunOutcome::Abandoned {
                attempts: 1,
                code: None,
                ..
            }
        ));
        let terminal_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_outbox
             WHERE state IN ('sent', 'abandoned')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let live_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_outbox
             WHERE state IN ('pending', 'sending')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(terminal_count, MAX_TERMINAL_ROWS);
        assert_eq!(live_count, 0);
    }

    #[tokio::test]
    async fn duplicate_is_suppressed_before_unique_event_is_backpressured_at_live_cap() {
        let pool = full_test_pool().await;
        let outbox = NotificationOutbox::new(
            pool.clone(),
            Arc::new(NotificationService::with_test_endpoint(
                "123456:test",
                "http://127.0.0.1:9".to_string(),
            )),
        );
        let now = Utc::now().timestamp();
        let mut transaction = pool.begin().await.unwrap();
        for index in 0..MAX_LIVE_ROWS {
            sqlx::query(
                "INSERT INTO notification_outbox (
                    channel, dedup_key, kind, payload_json, suppress_until,
                    state, attempts, next_attempt_at, lease_until,
                    created_at, updated_at, sent_at, abandoned_at
                 ) VALUES (
                    'telegram', ?, 'test.live',
                    '{\"version\":1,\"text\":\"pending\",\"occurred_at\":1}',
                    ?, 'pending', 0, ?, NULL, ?, ?, NULL, NULL
                 )",
            )
            .bind(format!("live:{index}"))
            .bind(now.saturating_add(60))
            .bind(now.saturating_add(60))
            .bind(now)
            .bind(now)
            .execute(&mut *transaction)
            .await
            .unwrap();
        }
        transaction.commit().await.unwrap();

        let duplicate = NotificationEvent::generic("live:0", "test.live", "duplicate", now, 60);
        assert_eq!(
            outbox.enqueue(&duplicate).await.unwrap(),
            EnqueueOutcome::Suppressed
        );
        let degraded_before_unique: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security_events
             WHERE event_key = 'notification:delivery_degraded'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(degraded_before_unique, 0);

        let unique = NotificationEvent::generic("live:new", "test.live", "unique", now, 60);
        assert_eq!(
            outbox.enqueue(&unique).await.unwrap(),
            EnqueueOutcome::Backpressure
        );
        let degraded_after_unique: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security_events
             WHERE event_key = 'notification:delivery_degraded'
               AND status = 'open'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(degraded_after_unique, 1);
    }

    #[tokio::test]
    async fn delivery_degraded_writer_resets_evidence_version_to_v1() {
        let pool = full_test_pool().await;
        let outbox = NotificationOutbox::new(
            pool.clone(),
            Arc::new(NotificationService::disabled_for_tests()),
        );
        let now = Utc::now().timestamp();
        outbox.set_delivery_degraded(now).await.unwrap();
        sqlx::query(
            "UPDATE security_events
             SET evidence_schema_version = 2, evidence_json = '{\"future\":true}'
             WHERE event_key = 'notification:delivery_degraded'",
        )
        .execute(&pool)
        .await
        .unwrap();

        outbox
            .set_delivery_degraded(now.saturating_add(1))
            .await
            .unwrap();
        let row = sqlx::query(
            "SELECT evidence_schema_version, evidence_json
             FROM security_events
             WHERE event_key = 'notification:delivery_degraded'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.get::<i64, _>("evidence_schema_version"), 1);
        assert_eq!(
            row.get::<String, _>("evidence_json"),
            r#"{"reason":"backpressure","live_limit":1000,"terminal_limit":200}"#
        );
    }

    #[tokio::test]
    async fn expired_sending_at_attempt_cap_reports_backpressure_until_terminal_slot_opens() {
        let pool = full_test_pool().await;
        let outbox = NotificationOutbox::new(
            pool.clone(),
            Arc::new(NotificationService::disabled_for_tests()),
        );
        let now = Utc::now().timestamp();
        let mut transaction = pool.begin().await.unwrap();
        for index in 0..MAX_TERMINAL_ROWS {
            sqlx::query(
                "INSERT INTO notification_outbox (
                    channel, dedup_key, kind, payload_json, suppress_until,
                    state, attempts, next_attempt_at, lease_until,
                    created_at, updated_at, sent_at, abandoned_at
                 ) VALUES (
                    'telegram', ?, 'test.terminal',
                    '{\"version\":1,\"text\":\"sent\",\"occurred_at\":1}',
                    ?, 'sent', 1, NULL, NULL, ?, ?, ?, NULL
                 )",
            )
            .bind(format!("active-terminal:{index}"))
            .bind(now.saturating_add(60))
            .bind(now.saturating_sub(1))
            .bind(now.saturating_sub(1))
            .bind(now.saturating_sub(1))
            .execute(&mut *transaction)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO notification_outbox (
                channel, dedup_key, kind, payload_json, suppress_until,
                state, attempts, next_attempt_at, lease_until,
                created_at, updated_at, sent_at, abandoned_at
             ) VALUES (
                'telegram', 'sending:expired', 'test.sending',
                '{\"version\":1,\"text\":\"sending\",\"occurred_at\":1}',
                ?, 'sending', 5, NULL, ?, ?, ?, NULL, NULL
             )",
        )
        .bind(now)
        .bind(now)
        .bind(now.saturating_sub(LEASE_SECONDS + 1))
        .bind(now.saturating_sub(LEASE_SECONDS + 1))
        .execute(&mut *transaction)
        .await
        .unwrap();
        transaction.commit().await.unwrap();

        assert_eq!(
            outbox.run_once_at(now).await.unwrap(),
            OutboxRunOutcome::Backpressure
        );
        let degraded_status: String = sqlx::query_scalar(
            "SELECT status FROM security_events
             WHERE event_key = 'notification:delivery_degraded'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(degraded_status, "open");

        assert_eq!(
            outbox.run_once_at(now.saturating_add(61)).await.unwrap(),
            OutboxRunOutcome::Idle
        );
        let blocked_state: String = sqlx::query_scalar(
            "SELECT state FROM notification_outbox
             WHERE dedup_key = 'sending:expired'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let resolved_status: String = sqlx::query_scalar(
            "SELECT status FROM security_events
             WHERE event_key = 'notification:delivery_degraded'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(blocked_state, "abandoned");
        assert_eq!(resolved_status, "resolved");
    }

    #[tokio::test]
    async fn hard_capacity_fixture_stays_below_eight_mib_and_backpressures() {
        let path = temp_db_path("outbox-capacity");
        let pool = file_pool(&path).await;
        let page_size: i64 = sqlx::query_scalar("PRAGMA page_size")
            .fetch_one(&pool)
            .await
            .unwrap();
        let before_pages: i64 = sqlx::query_scalar("PRAGMA page_count")
            .fetch_one(&pool)
            .await
            .unwrap();
        let now = Utc::now().timestamp();
        let payload = "x".repeat(MAX_PAYLOAD_BYTES);
        let mut transaction = pool.begin().await.unwrap();
        for index in 0..MAX_LIVE_ROWS {
            sqlx::query(
                "INSERT INTO notification_outbox (
                    channel, dedup_key, kind, payload_json, suppress_until,
                    state, attempts, next_attempt_at, lease_until,
                    created_at, updated_at, sent_at, abandoned_at
                 ) VALUES ('telegram', ?, 'fixture', ?, ?, 'pending', 0, ?,
                           NULL, ?, ?, NULL, NULL)",
            )
            .bind(format!("live:{index}"))
            .bind(&payload)
            .bind(now + 1800)
            .bind(now)
            .bind(now)
            .bind(now)
            .execute(&mut *transaction)
            .await
            .unwrap();
        }
        for index in 0..MAX_TERMINAL_ROWS {
            sqlx::query(
                "INSERT INTO notification_outbox (
                    channel, dedup_key, kind, payload_json, suppress_until,
                    state, attempts, next_attempt_at, lease_until,
                    created_at, updated_at, sent_at, abandoned_at
                 ) VALUES ('telegram', ?, 'fixture', ?, ?, 'sent', 1, NULL,
                           NULL, ?, ?, ?, NULL)",
            )
            .bind(format!("terminal:{index}"))
            .bind(&payload)
            .bind(now + 1800)
            .bind(now)
            .bind(now)
            .bind(now)
            .execute(&mut *transaction)
            .await
            .unwrap();
        }
        transaction.commit().await.unwrap();
        let after_pages: i64 = sqlx::query_scalar("PRAGMA page_count")
            .fetch_one(&pool)
            .await
            .unwrap();
        let delta_bytes = after_pages
            .saturating_sub(before_pages)
            .saturating_mul(page_size);
        assert!(delta_bytes < 8 * 1024 * 1024, "delta={delta_bytes}");

        let outbox = NotificationOutbox::new(
            pool.clone(),
            Arc::new(NotificationService::with_test_endpoint(
                "123456:test",
                "http://127.0.0.1:9".to_string(),
            )),
        );
        let overflow =
            NotificationEvent::generic("metric:overflow", "metric.critical", "overflow", now, 1800);
        assert_eq!(
            outbox.enqueue(&overflow).await.unwrap(),
            EnqueueOutcome::Backpressure
        );
        let degraded = sqlx::query(
            "SELECT status, notification_seq, notification_delivery_status
             FROM security_events
             WHERE event_key = 'notification:delivery_degraded'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(degraded.get::<String, _>("status"), "open");
        assert_eq!(degraded.get::<i64, _>("notification_seq"), 0);
        assert!(
            degraded
                .get::<Option<String>, _>("notification_delivery_status")
                .is_none()
        );
        assert_eq!(
            outbox.run_once_at(now).await.unwrap(),
            OutboxRunOutcome::Backpressure
        );
        let degraded_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security_events
             WHERE event_key = 'notification:delivery_degraded'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(degraded_count, 1);

        sqlx::query(
            "DELETE FROM notification_outbox
             WHERE id IN (
                SELECT id FROM notification_outbox WHERE state = 'pending' LIMIT 1
             )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "DELETE FROM notification_outbox
             WHERE id IN (
                SELECT id FROM notification_outbox WHERE state = 'sent' LIMIT 1
             )",
        )
        .execute(&pool)
        .await
        .unwrap();
        outbox.maintain(now.saturating_add(1)).await.unwrap();
        let degraded_status: String = sqlx::query_scalar(
            "SELECT status FROM security_events
             WHERE event_key = 'notification:delivery_degraded'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(degraded_status, "resolved");

        drop(outbox);
        pool.close().await;
        remove_sqlite_files(&path);
    }
}
