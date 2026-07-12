//! Transactional current-only storage facade for sensitive-file integrity.

use super::*;

pub(super) const JS_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone)]
pub(super) struct FileIntegrityStorage {
    pub(super) db: SqlitePool,
    pub(super) outbox: Arc<NotificationOutbox>,
}

impl FileIntegrityStorage {
    pub(super) async fn initialize(
        db: SqlitePool,
        outbox: Arc<NotificationOutbox>,
    ) -> Result<Self, FileIntegrityInitError> {
        super::schema::initialize(&db).await?;
        Ok(Self { db, outbox })
    }

    pub(super) async fn last_scan_at(&self) -> Result<Option<i64>, sqlx::Error> {
        sqlx::query_scalar("SELECT last_scan_at FROM file_integrity_state WHERE id = 1")
            .fetch_one(&self.db)
            .await
    }

    pub(super) async fn status(&self) -> Result<FileIntegrityStatus, sqlx::Error> {
        super::state_machine::validated_status(self).await
    }

    pub(super) async fn trusted_path_ids(&self) -> Result<BTreeSet<String>, sqlx::Error> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT path_id FROM file_integrity_baseline ORDER BY path_id LIMIT 257",
        )
        .fetch_all(&self.db)
        .await?;
        if rows.len() > collector::MAX_TRACKED_PATHS
            || !rows.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(invalid_state());
        }
        Ok(rows.into_iter().collect())
    }

    pub(super) async fn publish_scan(&self, result: ScanResult) -> Result<(), sqlx::Error> {
        super::state_machine::publish_scan(self, result).await
    }

    pub(super) async fn trust_current_state(
        &self,
        request: TrustCurrentStateRequest,
    ) -> Result<TrustCurrentStateResponse, FileIntegrityOperationError> {
        super::state_machine::trust_current_state(self, request).await
    }

    pub(super) async fn re_enroll(
        &self,
        request: ReEnrollRequest,
    ) -> Result<ReEnrollResponse, FileIntegrityOperationError> {
        super::state_machine::re_enroll(self, request).await
    }
}

fn invalid_state() -> sqlx::Error {
    sqlx::Error::Protocol("invalid file-integrity state".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notifications::{NotificationOutbox, NotificationService};
    use crate::security_events::FileIntegrityDegradedReasonV1;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn test_storage() -> FileIntegrityStorage {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory SQLite should connect");
        let outbox = Arc::new(NotificationOutbox::new(
            pool.clone(),
            Arc::new(NotificationService::disabled_for_tests()),
        ));
        FileIntegrityStorage::initialize(pool, outbox)
            .await
            .expect("storage should initialize")
    }

    #[tokio::test]
    async fn initialize_returns_exact_initializing_status() {
        let storage = test_storage().await;

        assert_eq!(
            storage.status().await.expect("status should load"),
            FileIntegrityStatus {
                schema_version: 1,
                status: FileIntegrityStatusKind::Initializing,
                state_revision: Some(0),
                baseline_generation: Some(0),
                observed_generation: Some(0),
                observation_complete: false,
                trust_available: false,
                re_enroll_available: false,
                degraded_reason: None,
                last_scan_at: None,
                tracked_file_count: 0,
                drift_file_count: 0,
                coverage: FileIntegrityCoverage {
                    status: FileIntegrityCoverageStatus::Initializing,
                    unavailable_target_count: 0,
                    error_counts: Vec::new(),
                },
            }
        );
    }

    #[tokio::test]
    async fn unknown_storage_versions_project_safe_unsupported_status() {
        let storage = test_storage().await;
        sqlx::query(
            "UPDATE file_integrity_state
             SET schema_version = 9, digest_algorithm = 'future_hash',
                 digest_version = 7, manifest_version = 5, updated_at = 123",
        )
        .execute(&storage.db)
        .await
        .expect("bounded unknown versions should remain storable");

        let status = storage
            .status()
            .await
            .expect("status should degrade safely");
        assert_eq!(status.status, FileIntegrityStatusKind::Degraded);
        assert_eq!(
            status.degraded_reason,
            Some(FileIntegrityDegradedReasonV1::UnsupportedAlgorithm)
        );
        assert_eq!(status.last_scan_at, Some(123));
        assert!(!status.observation_complete);
        assert!(!status.trust_available);
        assert!(!status.re_enroll_available);
        assert_eq!(
            status.coverage.status,
            FileIntegrityCoverageStatus::Degraded
        );
    }

    #[tokio::test]
    async fn malformed_error_counts_make_status_unavailable() {
        let storage = test_storage().await;
        sqlx::query(
            "UPDATE file_integrity_state
             SET state_revision = 1, status = 'degraded',
                 degraded_reason = 'internal_error', last_scan_at = 10,
                 error_counts_json = '[}', updated_at = 10",
        )
        .execute(&storage.db)
        .await
        .expect("bounded malformed fixture should bypass only semantic validation");

        let error = storage
            .status()
            .await
            .expect_err("malformed error counts must fail closed");
        assert!(matches!(
            error,
            sqlx::Error::Protocol(message)
                if message == "invalid file-integrity state"
        ));
    }

    #[tokio::test]
    async fn trusted_path_ids_are_sorted_and_bounded() {
        let storage = test_storage().await;
        for suffix in ['c', 'a', 'b'] {
            sqlx::query(
                "INSERT INTO file_integrity_baseline
                 (path_id, logical_path, generation, target_kind, entry_state,
                  content_digest, size_bytes, mtime_unix_seconds, mode, uid, gid)
                 VALUES (?, ?, 1, 'fixed', 'regular', ?, 0, 1, 420, 0, 0)",
            )
            .bind(format!("path-v1:{}", suffix.to_string().repeat(64)))
            .bind(format!("/fixture/{suffix}"))
            .bind(vec![0_u8; 32])
            .execute(&storage.db)
            .await
            .expect("valid baseline fixture should insert");
        }

        let expected = ['a', 'b', 'c']
            .into_iter()
            .map(|suffix| format!("path-v1:{}", suffix.to_string().repeat(64)))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            storage
                .trusted_path_ids()
                .await
                .expect("bounded path IDs should load"),
            expected
        );

        sqlx::query("DELETE FROM file_integrity_baseline")
            .execute(&storage.db)
            .await
            .expect("fixture rows should clear");
        let mut transaction = storage.db.begin().await.expect("transaction should begin");
        for value in 0..=collector::MAX_TRACKED_PATHS {
            sqlx::query(
                "INSERT INTO file_integrity_baseline
                 (path_id, logical_path, generation, target_kind, entry_state,
                  content_digest, size_bytes, mtime_unix_seconds, mode, uid, gid)
                 VALUES (?, ?, 1, 'fixed', 'regular', ?, 0, 1, 420, 0, 0)",
            )
            .bind(format!("path-v1:{value:064x}"))
            .bind(format!("/fixture/{value}"))
            .bind(vec![0_u8; 32])
            .execute(&mut *transaction)
            .await
            .expect("schema intentionally leaves cardinality to the service");
        }
        transaction.commit().await.expect("fixture should commit");

        assert!(storage.trusted_path_ids().await.is_err());
    }
}
