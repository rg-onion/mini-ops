//! Enabled-only SQLite schema for sensitive-file integrity state.

use super::FileIntegrityInitError;
use sqlx::SqlitePool;

const STATE_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS file_integrity_state (
    id                       INTEGER PRIMARY KEY
                                     CHECK (typeof(id) = 'integer' AND id = 1),
    schema_version           INTEGER NOT NULL
                                     CHECK (typeof(schema_version) = 'integer' AND
                                            schema_version BETWEEN 1 AND 9007199254740991),
    digest_algorithm         TEXT NOT NULL
                                     CHECK (typeof(digest_algorithm) = 'text' AND
                                            length(CAST(digest_algorithm AS BLOB)) BETWEEN 1 AND 32 AND
                                            digest_algorithm NOT GLOB '*[^a-z0-9_-]*'),
    digest_version           INTEGER NOT NULL
                                     CHECK (typeof(digest_version) = 'integer' AND
                                            digest_version BETWEEN 1 AND 9007199254740991),
    manifest_version         INTEGER NOT NULL
                                     CHECK (typeof(manifest_version) = 'integer' AND
                                            manifest_version BETWEEN 1 AND 9007199254740991),
    state_revision           INTEGER NOT NULL
                                     CHECK (typeof(state_revision) = 'integer' AND
                                            state_revision BETWEEN 0 AND 9007199254740991),
    baseline_generation      INTEGER NOT NULL
                                     CHECK (typeof(baseline_generation) = 'integer' AND
                                            baseline_generation BETWEEN 0 AND 9007199254740991),
    observed_generation      INTEGER NOT NULL
                                     CHECK (typeof(observed_generation) = 'integer' AND
                                            observed_generation BETWEEN 0 AND 9007199254740991),
    status                   TEXT NOT NULL
                                     CHECK (status IN
                                            ('initializing','healthy','drift','degraded')),
    degraded_reason          TEXT
                                     CHECK (degraded_reason IS NULL OR degraded_reason IN
                                            ('coverage_unavailable','limit_exceeded',
                                             'deadline_exceeded','baseline_corrupt',
                                             'unsupported_algorithm','database_restore_required',
                                             'internal_error')),
    observation_complete     INTEGER NOT NULL
                                     CHECK (typeof(observation_complete) = 'integer' AND
                                            observation_complete IN (0, 1)),
    trust_available          INTEGER NOT NULL
                                     CHECK (typeof(trust_available) = 'integer' AND
                                            trust_available IN (0, 1)),
    re_enroll_available      INTEGER NOT NULL
                                     CHECK (typeof(re_enroll_available) = 'integer' AND
                                            re_enroll_available IN (0, 1)),
    baseline_manifest        BLOB
                                     CHECK (baseline_manifest IS NULL OR
                                            (typeof(baseline_manifest) = 'blob' AND
                                             length(baseline_manifest) = 32)),
    observed_manifest        BLOB
                                     CHECK (observed_manifest IS NULL OR
                                            (typeof(observed_manifest) = 'blob' AND
                                             length(observed_manifest) = 32)),
    baseline_updated_at      INTEGER
                                     CHECK (baseline_updated_at IS NULL OR
                                            (typeof(baseline_updated_at) = 'integer' AND
                                             baseline_updated_at BETWEEN 0 AND 253402300799)),
    observed_at              INTEGER
                                     CHECK (observed_at IS NULL OR
                                            (typeof(observed_at) = 'integer' AND
                                             observed_at BETWEEN 0 AND 253402300799)),
    last_scan_at             INTEGER
                                     CHECK (last_scan_at IS NULL OR
                                            (typeof(last_scan_at) = 'integer' AND
                                             last_scan_at BETWEEN 0 AND 253402300799)),
    tracked_file_count       INTEGER NOT NULL
                                     CHECK (typeof(tracked_file_count) = 'integer' AND
                                            tracked_file_count BETWEEN 0 AND 256),
    drift_file_count         INTEGER NOT NULL
                                     CHECK (typeof(drift_file_count) = 'integer' AND
                                            drift_file_count BETWEEN 0 AND 256),
    unavailable_target_count INTEGER NOT NULL
                                     CHECK (typeof(unavailable_target_count) = 'integer' AND
                                            unavailable_target_count BETWEEN 0 AND 256),
    error_counts_json        TEXT NOT NULL
                                     CHECK (typeof(error_counts_json) = 'text' AND
                                            length(CAST(error_counts_json AS BLOB)) BETWEEN 2 AND 4095),
    updated_at               INTEGER NOT NULL
                                     CHECK (typeof(updated_at) = 'integer' AND
                                            updated_at BETWEEN 0 AND 253402300799),
    CHECK (drift_file_count <= tracked_file_count),
    CHECK ((status = 'degraded' AND degraded_reason IS NOT NULL) OR
           (status != 'degraded' AND degraded_reason IS NULL)),
    CHECK ((baseline_generation = 0 AND baseline_manifest IS NULL AND
            baseline_updated_at IS NULL) OR
           (baseline_generation >= 1 AND baseline_manifest IS NOT NULL AND
            baseline_updated_at IS NOT NULL)),
    CHECK ((observed_generation = 0 AND observed_manifest IS NULL AND
            observed_at IS NULL) OR
           (observed_generation >= 1 AND observed_manifest IS NOT NULL AND
            observed_at IS NOT NULL)),
    CHECK ((status = 'initializing' AND state_revision = 0 AND
            baseline_generation = 0 AND observed_generation = 0 AND
            observation_complete = 0 AND trust_available = 0 AND
            re_enroll_available = 0 AND last_scan_at IS NULL AND
            tracked_file_count = 0 AND drift_file_count = 0 AND
            unavailable_target_count = 0 AND error_counts_json = '[]') OR
           (status != 'initializing' AND state_revision >= 1 AND
            last_scan_at IS NOT NULL)),
    CHECK (status != 'healthy' OR
           (baseline_generation >= 1 AND observed_generation >= 1 AND
            observation_complete = 1 AND trust_available = 0 AND
            re_enroll_available = 0 AND drift_file_count = 0 AND
            unavailable_target_count = 0 AND error_counts_json = '[]')),
    CHECK (status != 'drift' OR
           (baseline_generation >= 1 AND observed_generation >= 1 AND
            observation_complete = 1 AND trust_available = 1 AND
            re_enroll_available = 0 AND drift_file_count >= 1 AND
            unavailable_target_count = 0 AND error_counts_json = '[]')),
    CHECK (trust_available = 0 OR
           (status IN ('drift','degraded') AND observation_complete = 1 AND
            baseline_generation >= 1 AND observed_generation >= 1)),
    CHECK (re_enroll_available = 0 OR
           (status = 'degraded' AND degraded_reason = 'baseline_corrupt' AND
            observation_complete = 1 AND baseline_generation >= 1 AND
            observed_generation >= 1)),
    CHECK (trust_available = 0 OR re_enroll_available = 0)
) STRICT
"#;

const BASELINE_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS file_integrity_baseline (
    path_id                   TEXT PRIMARY KEY
                                   CHECK (typeof(path_id) = 'text' AND
                                          length(CAST(path_id AS BLOB)) = 72 AND
                                          substr(path_id, 1, 8) = 'path-v1:' AND
                                          substr(path_id, 9) NOT GLOB '*[^0-9a-f]*'),
    logical_path              TEXT NOT NULL UNIQUE
                                   CHECK (typeof(logical_path) = 'text' AND
                                          length(CAST(logical_path AS BLOB)) BETWEEN 2 AND 1024 AND
                                          substr(logical_path, 1, 1) = '/' AND
                                          substr(logical_path, -1, 1) != '/' AND
                                          instr(logical_path, '//') = 0 AND
                                          instr(logical_path, char(0)) = 0 AND
                                          instr(logical_path, '/./') = 0 AND
                                          instr(logical_path, '/../') = 0 AND
                                          substr(logical_path, -2) != '/.' AND
                                          substr(logical_path, -3) != '/..'),
    generation                INTEGER NOT NULL
                                   CHECK (typeof(generation) = 'integer' AND
                                          generation BETWEEN 1 AND 9007199254740991),
    target_kind               TEXT NOT NULL
                                   CHECK (target_kind IN
                                          ('fixed','directory_root','directory_child')),
    entry_state               TEXT NOT NULL
                                   CHECK (entry_state IN ('regular','directory','absent')),
    content_digest            BLOB
                                   CHECK (content_digest IS NULL OR
                                          (typeof(content_digest) = 'blob' AND
                                           length(content_digest) = 32)),
    size_bytes                INTEGER
                                   CHECK (size_bytes IS NULL OR
                                          (typeof(size_bytes) = 'integer' AND
                                           size_bytes BETWEEN 0 AND 1048576)),
    mtime_unix_seconds        INTEGER
                                   CHECK (mtime_unix_seconds IS NULL OR
                                          (typeof(mtime_unix_seconds) = 'integer' AND
                                           mtime_unix_seconds BETWEEN 0 AND 253402300799)),
    mode                      INTEGER
                                   CHECK (mode IS NULL OR
                                          (typeof(mode) = 'integer' AND mode BETWEEN 0 AND 4095)),
    uid                       INTEGER
                                   CHECK (uid IS NULL OR
                                          (typeof(uid) = 'integer' AND uid BETWEEN 0 AND 4294967295)),
    gid                       INTEGER
                                   CHECK (gid IS NULL OR
                                          (typeof(gid) = 'integer' AND gid BETWEEN 0 AND 4294967295)),
    CHECK ((target_kind IN ('fixed','directory_child') AND
            entry_state = 'regular' AND content_digest IS NOT NULL AND
            size_bytes IS NOT NULL AND mtime_unix_seconds IS NOT NULL AND
            mode IS NOT NULL AND uid IS NOT NULL AND gid IS NOT NULL) OR
           (target_kind = 'directory_root' AND entry_state = 'directory' AND
            content_digest IS NULL AND size_bytes IS NULL AND
            mtime_unix_seconds IS NULL AND mode IS NOT NULL AND
            uid IS NOT NULL AND gid IS NOT NULL) OR
           (target_kind IN ('fixed','directory_root') AND
            entry_state = 'absent' AND content_digest IS NULL AND
            size_bytes IS NULL AND mtime_unix_seconds IS NULL AND
            mode IS NULL AND uid IS NULL AND gid IS NULL))
) STRICT
"#;

const OBSERVED_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS file_integrity_observed (
    path_id                   TEXT PRIMARY KEY
                                   CHECK (typeof(path_id) = 'text' AND
                                          length(CAST(path_id AS BLOB)) = 72 AND
                                          substr(path_id, 1, 8) = 'path-v1:' AND
                                          substr(path_id, 9) NOT GLOB '*[^0-9a-f]*'),
    logical_path              TEXT NOT NULL UNIQUE
                                   CHECK (typeof(logical_path) = 'text' AND
                                          length(CAST(logical_path AS BLOB)) BETWEEN 2 AND 1024 AND
                                          substr(logical_path, 1, 1) = '/' AND
                                          substr(logical_path, -1, 1) != '/' AND
                                          instr(logical_path, '//') = 0 AND
                                          instr(logical_path, char(0)) = 0 AND
                                          instr(logical_path, '/./') = 0 AND
                                          instr(logical_path, '/../') = 0 AND
                                          substr(logical_path, -2) != '/.' AND
                                          substr(logical_path, -3) != '/..'),
    generation                INTEGER NOT NULL
                                   CHECK (typeof(generation) = 'integer' AND
                                          generation BETWEEN 1 AND 9007199254740991),
    target_kind               TEXT NOT NULL
                                   CHECK (target_kind IN
                                          ('fixed','directory_root','directory_child')),
    entry_state               TEXT NOT NULL
                                   CHECK (entry_state IN ('regular','directory','absent')),
    content_digest            BLOB
                                   CHECK (content_digest IS NULL OR
                                          (typeof(content_digest) = 'blob' AND
                                           length(content_digest) = 32)),
    size_bytes                INTEGER
                                   CHECK (size_bytes IS NULL OR
                                          (typeof(size_bytes) = 'integer' AND
                                           size_bytes BETWEEN 0 AND 9007199254740991)),
    mtime_unix_seconds        INTEGER
                                   CHECK (mtime_unix_seconds IS NULL OR
                                          (typeof(mtime_unix_seconds) = 'integer' AND
                                           mtime_unix_seconds BETWEEN 0 AND 253402300799)),
    mode                      INTEGER
                                   CHECK (mode IS NULL OR
                                          (typeof(mode) = 'integer' AND mode BETWEEN 0 AND 4095)),
    uid                       INTEGER
                                   CHECK (uid IS NULL OR
                                          (typeof(uid) = 'integer' AND uid BETWEEN 0 AND 4294967295)),
    gid                       INTEGER
                                   CHECK (gid IS NULL OR
                                          (typeof(gid) = 'integer' AND gid BETWEEN 0 AND 4294967295)),
    observation_error         TEXT
                                   CHECK (observation_error IS NULL OR observation_error IN
                                          ('permission_denied','symlink','not_regular',
                                           'file_too_large','changed_during_read',
                                           'vanished_during_scan','io_error')),
    CHECK ((observation_error IS NULL AND
            ((target_kind IN ('fixed','directory_child') AND
              entry_state = 'regular' AND content_digest IS NOT NULL AND
              size_bytes BETWEEN 0 AND 1048576 AND
              mtime_unix_seconds IS NOT NULL AND mode IS NOT NULL AND
              uid IS NOT NULL AND gid IS NOT NULL) OR
             (target_kind IN ('fixed','directory_child') AND
              entry_state = 'directory' AND content_digest IS NULL AND
              size_bytes IS NULL AND mtime_unix_seconds IS NULL AND
              mode IS NOT NULL AND uid IS NOT NULL AND gid IS NOT NULL) OR
             (target_kind IN ('fixed','directory_root') AND
              entry_state = 'absent' AND content_digest IS NULL AND
              size_bytes IS NULL AND mtime_unix_seconds IS NULL AND
              mode IS NULL AND uid IS NULL AND gid IS NULL) OR
             (target_kind = 'directory_root' AND entry_state = 'directory' AND
              content_digest IS NULL AND size_bytes IS NULL AND
              mtime_unix_seconds IS NULL AND mode IS NOT NULL AND
              uid IS NOT NULL AND gid IS NOT NULL) OR
             (target_kind = 'directory_root' AND entry_state = 'regular' AND
              content_digest IS NULL AND size_bytes IS NOT NULL AND
              mtime_unix_seconds IS NOT NULL AND mode IS NOT NULL AND
              uid IS NOT NULL AND gid IS NOT NULL))) OR
           (observation_error IS NOT NULL AND
            target_kind IN ('fixed','directory_child') AND
            ((entry_state = 'absent' AND content_digest IS NULL AND
              size_bytes IS NULL AND mtime_unix_seconds IS NULL AND
              mode IS NULL AND uid IS NULL AND gid IS NULL) OR
             (entry_state = 'regular' AND content_digest IS NULL AND
              (size_bytes IS NOT NULL OR mtime_unix_seconds IS NOT NULL OR
               mode IS NOT NULL OR uid IS NOT NULL OR gid IS NOT NULL)))))
) STRICT
"#;

const INDEX_DDL: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS idx_file_integrity_baseline_generation_path
         ON file_integrity_baseline(generation, path_id)",
    "CREATE INDEX IF NOT EXISTS idx_file_integrity_observed_generation_path
         ON file_integrity_observed(generation, path_id)",
];

const INITIAL_STATE_DML: &str = r#"
INSERT INTO file_integrity_state (
    id, schema_version, digest_algorithm, digest_version, manifest_version,
    state_revision, baseline_generation, observed_generation, status,
    degraded_reason, observation_complete, trust_available,
    re_enroll_available, baseline_manifest, observed_manifest,
    baseline_updated_at, observed_at, last_scan_at, tracked_file_count,
    drift_file_count, unavailable_target_count, error_counts_json, updated_at
) VALUES (
    1, 1, 'sha256', 1, 1,
    0, 0, 0, 'initializing',
    NULL, 0, 0,
    0, NULL, NULL,
    NULL, NULL, NULL, 0,
    0, 0, '[]', 0
)
ON CONFLICT(id) DO NOTHING
"#;

pub(super) async fn initialize(db: &SqlitePool) -> Result<(), FileIntegrityInitError> {
    let quick_check = sqlx::query_scalar::<_, String>("PRAGMA quick_check")
        .fetch_all(db)
        .await
        .map_err(|_| FileIntegrityInitError::DatabaseRestoreRequired)?;
    if !quick_check_is_exact_ok(&quick_check) {
        return Err(FileIntegrityInitError::DatabaseRestoreRequired);
    }

    let mut transaction = db
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| FileIntegrityInitError::Database)?;
    for statement in [STATE_DDL, BASELINE_DDL, OBSERVED_DDL] {
        sqlx::query(statement)
            .execute(&mut *transaction)
            .await
            .map_err(|_| FileIntegrityInitError::Database)?;
    }
    for statement in INDEX_DDL {
        sqlx::query(statement)
            .execute(&mut *transaction)
            .await
            .map_err(|_| FileIntegrityInitError::Database)?;
    }
    sqlx::query(INITIAL_STATE_DML)
        .execute(&mut *transaction)
        .await
        .map_err(|_| FileIntegrityInitError::Database)?;
    transaction
        .commit()
        .await
        .map_err(|_| FileIntegrityInitError::Database)
}

fn quick_check_is_exact_ok(rows: &[String]) -> bool {
    rows.len() == 1 && rows[0] == "ok"
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn test_pool() -> SqlitePool {
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory SQLite should connect")
    }

    #[tokio::test]
    async fn initialize_creates_bounded_initial_state() {
        let pool = test_pool().await;

        initialize(&pool).await.expect("schema should initialize");

        let state = sqlx::query(
            "SELECT schema_version, digest_algorithm, digest_version,
                    manifest_version, state_revision, baseline_generation,
                    observed_generation, status, degraded_reason,
                    observation_complete, trust_available, re_enroll_available,
                    baseline_manifest, observed_manifest, last_scan_at,
                    tracked_file_count, drift_file_count,
                    unavailable_target_count, error_counts_json, updated_at
             FROM file_integrity_state WHERE id = 1",
        )
        .fetch_one(&pool)
        .await
        .expect("singleton state should exist");
        assert_eq!(state.get::<i64, _>("schema_version"), 1);
        assert_eq!(state.get::<String, _>("digest_algorithm"), "sha256");
        assert_eq!(state.get::<i64, _>("digest_version"), 1);
        assert_eq!(state.get::<i64, _>("manifest_version"), 1);
        assert_eq!(state.get::<i64, _>("state_revision"), 0);
        assert_eq!(state.get::<i64, _>("baseline_generation"), 0);
        assert_eq!(state.get::<i64, _>("observed_generation"), 0);
        assert_eq!(state.get::<String, _>("status"), "initializing");
        assert_eq!(state.get::<Option<String>, _>("degraded_reason"), None);
        assert_eq!(state.get::<i64, _>("observation_complete"), 0);
        assert_eq!(state.get::<i64, _>("trust_available"), 0);
        assert_eq!(state.get::<i64, _>("re_enroll_available"), 0);
        assert_eq!(state.get::<Option<Vec<u8>>, _>("baseline_manifest"), None);
        assert_eq!(state.get::<Option<Vec<u8>>, _>("observed_manifest"), None);
        assert_eq!(state.get::<Option<i64>, _>("last_scan_at"), None);
        assert_eq!(state.get::<i64, _>("tracked_file_count"), 0);
        assert_eq!(state.get::<i64, _>("drift_file_count"), 0);
        assert_eq!(state.get::<i64, _>("unavailable_target_count"), 0);
        assert_eq!(state.get::<String, _>("error_counts_json"), "[]");
        assert_eq!(state.get::<i64, _>("updated_at"), 0);

        let table_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'table' AND name IN
                   ('file_integrity_state','file_integrity_baseline',
                    'file_integrity_observed')",
        )
        .fetch_one(&pool)
        .await
        .expect("schema catalog should be readable");
        assert_eq!(table_count, 3);
    }

    #[tokio::test]
    async fn initialize_is_idempotent_and_preserves_unknown_versions() {
        let pool = test_pool().await;
        initialize(&pool).await.expect("schema should initialize");
        sqlx::query(
            "UPDATE file_integrity_state
             SET schema_version = 17, digest_algorithm = 'future_hash',
                 digest_version = 23, manifest_version = 42
             WHERE id = 1",
        )
        .execute(&pool)
        .await
        .expect("unknown bounded versions must remain readable");

        initialize(&pool)
            .await
            .expect("repeated initialization should succeed");

        let values: (i64, String, i64, i64) = sqlx::query_as(
            "SELECT schema_version, digest_algorithm, digest_version,
                    manifest_version
             FROM file_integrity_state WHERE id = 1",
        )
        .fetch_one(&pool)
        .await
        .expect("state should remain readable");
        assert_eq!(values, (17, "future_hash".to_string(), 23, 42));
    }

    #[tokio::test]
    async fn row_constraints_reject_inconsistent_digest_and_metadata() {
        let pool = test_pool().await;
        initialize(&pool).await.expect("schema should initialize");
        let path_id = format!("path-v1:{}", "a".repeat(64));

        sqlx::query(
            "INSERT INTO file_integrity_baseline
             (path_id, logical_path, generation, target_kind, entry_state,
              content_digest, size_bytes, mtime_unix_seconds, mode, uid, gid)
             VALUES (?, '/etc/passwd', 1, 'fixed', 'regular', ?, 4, 1, 420, 0, 0)",
        )
        .bind(&path_id)
        .bind(vec![7_u8; 32])
        .execute(&pool)
        .await
        .expect("valid trusted regular row should insert");

        let invalid_digest = sqlx::query(
            "INSERT INTO file_integrity_baseline
             (path_id, logical_path, generation, target_kind, entry_state,
              content_digest, size_bytes, mtime_unix_seconds, mode, uid, gid)
             VALUES (?, '/etc/group', 1, 'fixed', 'regular', ?, 4, 1, 420, 0, 0)",
        )
        .bind(format!("path-v1:{}", "b".repeat(64)))
        .bind(vec![7_u8; 31])
        .execute(&pool)
        .await;
        assert!(invalid_digest.is_err());

        let invalid_observed_error = sqlx::query(
            "INSERT INTO file_integrity_observed
             (path_id, logical_path, generation, target_kind, entry_state,
              content_digest, size_bytes, mtime_unix_seconds, mode, uid, gid,
              observation_error)
             VALUES (?, '/etc/sudoers.d', 1, 'directory_root', 'absent',
                     NULL, NULL, NULL, NULL, NULL, NULL, 'permission_denied')",
        )
        .bind(format!("path-v1:{}", "c".repeat(64)))
        .execute(&pool)
        .await;
        assert!(invalid_observed_error.is_err());

        let dynamic_child_absence = sqlx::query(
            "INSERT INTO file_integrity_observed
             (path_id, logical_path, generation, target_kind, entry_state,
              content_digest, size_bytes, mtime_unix_seconds, mode, uid, gid,
              observation_error)
             VALUES (?, '/etc/sudoers.d/removed', 1, 'directory_child', 'absent',
                     NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
        )
        .bind(format!("path-v1:{}", "d".repeat(64)))
        .execute(&pool)
        .await;
        assert!(dynamic_child_absence.is_err());

        let second_singleton = sqlx::query(
            "INSERT INTO file_integrity_state
             (id, schema_version, digest_algorithm, digest_version,
              manifest_version, state_revision, baseline_generation,
              observed_generation, status, degraded_reason,
              observation_complete, trust_available, re_enroll_available,
              baseline_manifest, observed_manifest, baseline_updated_at,
              observed_at, last_scan_at, tracked_file_count, drift_file_count,
              unavailable_target_count, error_counts_json, updated_at)
             VALUES (2, 1, 'sha256', 1, 1, 0, 0, 0, 'initializing', NULL,
                     0, 0, 0, NULL, NULL, NULL, NULL, NULL, 0, 0, 0, '[]', 0)",
        )
        .execute(&pool)
        .await;
        assert!(second_singleton.is_err());
    }

    #[test]
    fn quick_check_requires_one_exact_ok_row() {
        assert!(quick_check_is_exact_ok(&["ok".to_string()]));
        assert!(!quick_check_is_exact_ok(&[]));
        assert!(!quick_check_is_exact_ok(&["OK".to_string()]));
        assert!(!quick_check_is_exact_ok(&[
            "ok".to_string(),
            "unexpected".to_string(),
        ]));
    }

    #[tokio::test]
    async fn quick_check_query_failure_requires_database_restore() {
        let pool = test_pool().await;
        pool.close().await;

        assert_eq!(
            initialize(&pool).await,
            Err(FileIntegrityInitError::DatabaseRestoreRequired)
        );
    }
}
