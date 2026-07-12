mod collector;
mod schema;
mod state_machine;
mod storage;

use crate::notifications::NotificationOutbox;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;

use collector::{FileIntegrityCollector, ScanCancellation, ScanResult};
use storage::FileIntegrityStorage;

const ENABLED_ENV: &str = "SECURITY_FILE_INTEGRITY_ENABLED";
const INTERVAL_ENV: &str = "SECURITY_FILE_INTEGRITY_INTERVAL_SECS";
const DEFAULT_INTERVAL_SECS: u64 = 300;
const MIN_INTERVAL_SECS: u64 = 60;
const MAX_INTERVAL_SECS: u64 = 86_400;
const SCAN_DEADLINE: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileIntegrityConfig {
    enabled: bool,
    interval_secs: u64,
}

impl FileIntegrityConfig {
    pub(crate) fn from_env() -> Result<Self, FileIntegrityConfigError> {
        Self::from_values(
            std::env::var_os(ENABLED_ENV).as_deref(),
            std::env::var_os(INTERVAL_ENV).as_deref(),
        )
    }

    fn from_values(
        enabled_value: Option<&OsStr>,
        interval_value: Option<&OsStr>,
    ) -> Result<Self, FileIntegrityConfigError> {
        let enabled = match enabled_value {
            None => false,
            Some(value) => match value.to_str() {
                Some("true") => true,
                Some("false") => false,
                _ => return Err(FileIntegrityConfigError::InvalidEnabledValue),
            },
        };
        let interval_secs = match interval_value {
            None => DEFAULT_INTERVAL_SECS,
            Some(value) => value
                .to_str()
                .and_then(|value| value.trim().parse::<u64>().ok())
                .ok_or(FileIntegrityConfigError::InvalidInterval)?
                .clamp(MIN_INTERVAL_SECS, MAX_INTERVAL_SECS),
        };
        Ok(Self {
            enabled,
            interval_secs,
        })
    }

    pub(crate) const fn enabled(self) -> bool {
        self.enabled
    }

    pub(crate) const fn interval_secs(self) -> u64 {
        self.interval_secs
    }

    pub(crate) fn validate_runtime_identity(
        self,
        effective_uid: u32,
    ) -> Result<(), FileIntegrityConfigError> {
        if self.enabled && effective_uid == 0 {
            return Err(FileIntegrityConfigError::UnsupportedRuntimeIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileIntegrityConfigError {
    InvalidEnabledValue,
    InvalidInterval,
    UnsupportedRuntimeIdentity,
}

impl FileIntegrityConfigError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidEnabledValue => "invalid_enabled_value",
            Self::InvalidInterval => "invalid_interval",
            Self::UnsupportedRuntimeIdentity => "unsupported_runtime_identity",
        }
    }
}

impl fmt::Display for FileIntegrityConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for FileIntegrityConfigError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FileIntegrityStatusKind {
    Disabled,
    Initializing,
    Healthy,
    Drift,
    Degraded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FileIntegrityCoverageStatus {
    Disabled,
    Initializing,
    Full,
    Degraded,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct FileIntegrityCoverage {
    pub(crate) status: FileIntegrityCoverageStatus,
    pub(crate) unavailable_target_count: u64,
    pub(crate) error_counts: Vec<crate::security_events::FileIntegrityCoverageErrorCountV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct FileIntegrityStatus {
    pub(crate) schema_version: u64,
    pub(crate) status: FileIntegrityStatusKind,
    pub(crate) state_revision: Option<u64>,
    pub(crate) baseline_generation: Option<u64>,
    pub(crate) observed_generation: Option<u64>,
    pub(crate) observation_complete: bool,
    pub(crate) trust_available: bool,
    pub(crate) re_enroll_available: bool,
    pub(crate) degraded_reason: Option<crate::security_events::FileIntegrityDegradedReasonV1>,
    pub(crate) last_scan_at: Option<i64>,
    pub(crate) tracked_file_count: u64,
    pub(crate) drift_file_count: u64,
    pub(crate) coverage: FileIntegrityCoverage,
}

impl FileIntegrityStatus {
    fn disabled() -> Self {
        Self {
            schema_version: 1,
            status: FileIntegrityStatusKind::Disabled,
            state_revision: None,
            baseline_generation: None,
            observed_generation: None,
            observation_complete: false,
            trust_available: false,
            re_enroll_available: false,
            degraded_reason: None,
            last_scan_at: None,
            tracked_file_count: 0,
            drift_file_count: 0,
            coverage: FileIntegrityCoverage {
                status: FileIntegrityCoverageStatus::Disabled,
                unavailable_target_count: 0,
                error_counts: Vec::new(),
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustCurrentStateRequest {
    pub(crate) expected_baseline_generation: u64,
    pub(crate) expected_observed_generation: u64,
    pub(crate) confirmation: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReEnrollRequest {
    pub(crate) expected_state_revision: u64,
    pub(crate) expected_observed_generation: u64,
    pub(crate) confirmation: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct TrustCurrentStateResponse {
    pub(crate) result: &'static str,
    pub(crate) status: FileIntegrityStatusKind,
    pub(crate) state_revision: u64,
    pub(crate) baseline_generation: u64,
    pub(crate) observed_generation: u64,
    pub(crate) trusted_at: i64,
    pub(crate) resolved_event_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ReEnrollResponse {
    pub(crate) result: &'static str,
    pub(crate) status: FileIntegrityStatusKind,
    pub(crate) state_revision: u64,
    pub(crate) baseline_generation: u64,
    pub(crate) observed_generation: u64,
    pub(crate) reenrolled_at: i64,
    pub(crate) resolved_event_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FileIntegrityOperationErrorCode {
    InvalidRequest,
    StaleGeneration,
    NotInitialized,
    NoDrift,
    ObservationNotTrustable,
    FeatureDisabled,
    RecoveryNotRequired,
    UnsupportedAlgorithm,
    InternalError,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct FileIntegrityOperationErrorContext {
    pub(crate) code: FileIntegrityOperationErrorCode,
    pub(crate) status: Option<FileIntegrityStatusKind>,
    pub(crate) state_revision: Option<u64>,
    pub(crate) baseline_generation: Option<u64>,
    pub(crate) observed_generation: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct FileIntegrityOperationErrorBody {
    pub(crate) error: FileIntegrityOperationErrorContext,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FileIntegrityOperationError {
    code: FileIntegrityOperationErrorCode,
    context: Option<FileIntegrityStatus>,
}

impl FileIntegrityOperationError {
    pub(crate) const fn invalid_request() -> Self {
        Self {
            code: FileIntegrityOperationErrorCode::InvalidRequest,
            context: None,
        }
    }

    fn with_status(code: FileIntegrityOperationErrorCode, status: FileIntegrityStatus) -> Self {
        Self {
            code,
            context: Some(status),
        }
    }

    pub(crate) const fn code(&self) -> FileIntegrityOperationErrorCode {
        self.code
    }

    pub(crate) const fn http_status(&self) -> u16 {
        match self.code {
            FileIntegrityOperationErrorCode::InvalidRequest => 400,
            FileIntegrityOperationErrorCode::InternalError => 500,
            _ => 409,
        }
    }

    pub(crate) fn response_body(&self) -> FileIntegrityOperationErrorBody {
        let status = self.context.as_ref();
        FileIntegrityOperationErrorBody {
            error: FileIntegrityOperationErrorContext {
                code: self.code,
                status: status.map(|value| value.status),
                state_revision: status.and_then(|value| value.state_revision),
                baseline_generation: status.and_then(|value| value.baseline_generation),
                observed_generation: status.and_then(|value| value.observed_generation),
            },
        }
    }
}

impl fmt::Display for FileIntegrityOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}", self.code())
    }
}

impl std::error::Error for FileIntegrityOperationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileIntegrityInitError {
    FeatureDisabled,
    UnsupportedRuntimeIdentity,
    DatabaseRestoreRequired,
    Database,
}

impl FileIntegrityInitError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::FeatureDisabled => "feature_disabled",
            Self::UnsupportedRuntimeIdentity => "unsupported_runtime_identity",
            Self::DatabaseRestoreRequired => "database_restore_required",
            Self::Database => "database_error",
        }
    }
}

impl fmt::Display for FileIntegrityInitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for FileIntegrityInitError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileIntegrityServiceError;

impl FileIntegrityServiceError {
    pub(crate) const fn code(self) -> &'static str {
        "file_integrity_status_unavailable"
    }
}

impl fmt::Display for FileIntegrityServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for FileIntegrityServiceError {}

enum ServiceMode {
    Disabled,
    Enabled {
        storage: FileIntegrityStorage,
        interval_secs: u64,
    },
}

pub(crate) struct FileIntegrityService {
    mode: ServiceMode,
    exclusive: Mutex<()>,
    last_scan_at: RwLock<Option<i64>>,
}

impl FileIntegrityService {
    pub(crate) fn disabled() -> Arc<Self> {
        Arc::new(Self {
            mode: ServiceMode::Disabled,
            exclusive: Mutex::new(()),
            last_scan_at: RwLock::new(None),
        })
    }

    pub(crate) async fn initialize_enabled(
        pool: SqlitePool,
        outbox: Arc<NotificationOutbox>,
        config: FileIntegrityConfig,
    ) -> Result<Arc<Self>, FileIntegrityInitError> {
        if !config.enabled() {
            return Err(FileIntegrityInitError::FeatureDisabled);
        }
        config
            .validate_runtime_identity(crate::runtime::effective_uid())
            .map_err(|_| FileIntegrityInitError::UnsupportedRuntimeIdentity)?;
        let storage = FileIntegrityStorage::initialize(pool, Arc::clone(&outbox)).await?;
        let last_scan_at = storage
            .last_scan_at()
            .await
            .map_err(|_| FileIntegrityInitError::Database)?;
        Ok(Arc::new(Self {
            mode: ServiceMode::Enabled {
                storage,
                interval_secs: config.interval_secs(),
            },
            exclusive: Mutex::new(()),
            last_scan_at: RwLock::new(last_scan_at),
        }))
    }

    pub(crate) fn start(self: Arc<Self>) -> Option<JoinHandle<()>> {
        let interval_secs = match &self.mode {
            ServiceMode::Disabled => return None,
            ServiceMode::Enabled { interval_secs, .. } => *interval_secs,
        };
        Some(tokio::spawn(async move {
            let collector = Arc::new(FileIntegrityCollector::production());
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                if let Err(error) = self.run_scan(Arc::clone(&collector)).await {
                    tracing::warn!(
                        file_integrity_error = error.code(),
                        "Sensitive-file integrity scan publication failed"
                    );
                }
            }
        }))
    }

    pub(crate) async fn status(&self) -> Result<FileIntegrityStatus, FileIntegrityServiceError> {
        let ServiceMode::Enabled { storage, .. } = &self.mode else {
            return Ok(FileIntegrityStatus::disabled());
        };
        let mut status = storage
            .status()
            .await
            .map_err(|_| FileIntegrityServiceError)?;
        if let Some(last_scan_at) = *self.last_scan_at.read().await {
            status.last_scan_at = Some(last_scan_at);
        }
        Ok(status)
    }

    pub(crate) async fn trust_current_state(
        &self,
        request: TrustCurrentStateRequest,
    ) -> Result<TrustCurrentStateResponse, FileIntegrityOperationError> {
        if request.confirmation != "trust_current_state"
            || request.expected_baseline_generation == 0
            || request.expected_baseline_generation > storage::JS_MAX_SAFE_INTEGER
            || request.expected_observed_generation == 0
            || request.expected_observed_generation > storage::JS_MAX_SAFE_INTEGER
        {
            return Err(FileIntegrityOperationError::invalid_request());
        }
        let ServiceMode::Enabled { storage, .. } = &self.mode else {
            return Err(FileIntegrityOperationError::with_status(
                FileIntegrityOperationErrorCode::FeatureDisabled,
                FileIntegrityStatus::disabled(),
            ));
        };
        let _guard = self.exclusive.lock().await;
        storage.trust_current_state(request).await
    }

    pub(crate) async fn re_enroll(
        &self,
        request: ReEnrollRequest,
    ) -> Result<ReEnrollResponse, FileIntegrityOperationError> {
        if request.confirmation != "re_enroll_from_current_observation"
            || request.expected_state_revision > storage::JS_MAX_SAFE_INTEGER
            || request.expected_observed_generation == 0
            || request.expected_observed_generation > storage::JS_MAX_SAFE_INTEGER
        {
            return Err(FileIntegrityOperationError::invalid_request());
        }
        let ServiceMode::Enabled { storage, .. } = &self.mode else {
            return Err(FileIntegrityOperationError::with_status(
                FileIntegrityOperationErrorCode::FeatureDisabled,
                FileIntegrityStatus::disabled(),
            ));
        };
        let _guard = self.exclusive.lock().await;
        storage.re_enroll(request).await
    }

    async fn run_scan(
        &self,
        collector: Arc<FileIntegrityCollector>,
    ) -> Result<(), FileIntegrityServiceError> {
        self.run_scan_with(SCAN_DEADLINE, move |cancellation, trusted_path_ids| {
            collector.scan(&cancellation, &trusted_path_ids)
        })
        .await
    }

    async fn run_scan_with<F>(
        &self,
        deadline: Duration,
        scan: F,
    ) -> Result<(), FileIntegrityServiceError>
    where
        F: FnOnce(Arc<ScanCancellation>, BTreeSet<String>) -> ScanResult + Send + 'static,
    {
        let ServiceMode::Enabled { storage, .. } = &self.mode else {
            return Ok(());
        };
        let _guard = self.exclusive.lock().await;
        let trusted_path_ids: BTreeSet<String> = storage
            .trusted_path_ids()
            .await
            .map_err(|_| FileIntegrityServiceError)?;
        let cancellation = Arc::new(ScanCancellation::new());
        let worker_cancellation = Arc::clone(&cancellation);
        let worker =
            tokio::task::spawn_blocking(move || scan(worker_cancellation, trusted_path_ids));
        tokio::pin!(worker);
        let result = match tokio::time::timeout(deadline, &mut worker).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => ScanResult::internal_error(chrono::Utc::now().timestamp()),
            Err(_) => {
                cancellation.cancel();
                let result = ScanResult::deadline_exceeded(chrono::Utc::now().timestamp());
                let observed_at = result.observed_at;
                let publication = storage
                    .publish_scan(result)
                    .await
                    .map_err(|_| FileIntegrityServiceError);
                if publication.is_ok() {
                    *self.last_scan_at.write().await = Some(observed_at);
                }
                // Keep the exclusive permit until the blocking worker has
                // really exited. Its late result is always discarded.
                let _ = worker.await;
                return publication;
            }
        };
        let observed_at = result.observed_at;
        storage
            .publish_scan(result)
            .await
            .map_err(|_| FileIntegrityServiceError)?;
        *self.last_scan_at.write().await = Some(observed_at);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn enabled_test_service() -> Arc<FileIntegrityService> {
        use crate::notifications::NotificationService;
        use crate::security_events::SecurityEventService;
        use sqlx::sqlite::SqlitePoolOptions;

        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connect service fixture database");
        SecurityEventService::init_schema(&db)
            .await
            .expect("initialize event fixture schema");
        let outbox = Arc::new(NotificationOutbox::new(
            db.clone(),
            Arc::new(NotificationService::disabled_for_tests()),
        ));
        let storage = FileIntegrityStorage::initialize(db, outbox)
            .await
            .expect("initialize integrity fixture storage");
        Arc::new(FileIntegrityService {
            mode: ServiceMode::Enabled {
                storage,
                interval_secs: MIN_INTERVAL_SECS,
            },
            exclusive: Mutex::new(()),
            last_scan_at: RwLock::new(None),
        })
    }

    #[test]
    fn config_is_exact_opt_in_and_interval_is_bounded() {
        let defaults = FileIntegrityConfig::from_values(None, None).expect("valid defaults");
        assert!(!defaults.enabled());
        assert_eq!(defaults.interval_secs(), 300);

        let minimum =
            FileIntegrityConfig::from_values(Some(OsStr::new("true")), Some(OsStr::new("1")))
                .expect("valid enabled config");
        assert!(minimum.enabled());
        assert_eq!(minimum.interval_secs(), 60);

        let maximum =
            FileIntegrityConfig::from_values(Some(OsStr::new("false")), Some(OsStr::new("999999")))
                .expect("valid disabled config");
        assert!(!maximum.enabled());
        assert_eq!(maximum.interval_secs(), 86_400);

        assert_eq!(
            FileIntegrityConfig::from_values(Some(OsStr::new("TRUE")), None),
            Err(FileIntegrityConfigError::InvalidEnabledValue)
        );
        assert_eq!(
            FileIntegrityConfig::from_values(None, Some(OsStr::new("invalid"))),
            Err(FileIntegrityConfigError::InvalidInterval)
        );
    }

    #[test]
    fn enabled_root_identity_fails_closed() {
        let enabled = FileIntegrityConfig::from_values(Some(OsStr::new("true")), None)
            .expect("enabled config");
        assert_eq!(
            enabled.validate_runtime_identity(0),
            Err(FileIntegrityConfigError::UnsupportedRuntimeIdentity)
        );
        assert!(enabled.validate_runtime_identity(1000).is_ok());

        let disabled = FileIntegrityConfig::from_values(Some(OsStr::new("false")), None)
            .expect("disabled config");
        assert!(disabled.validate_runtime_identity(0).is_ok());
    }

    #[tokio::test]
    async fn disabled_service_returns_exact_in_memory_status() {
        let service = FileIntegrityService::disabled();
        assert!(service.clone().start().is_none());
        let status = service.status().await.expect("disabled status");
        assert_eq!(status, FileIntegrityStatus::disabled());
        assert_eq!(
            serde_json::to_value(status).expect("serialize disabled status"),
            serde_json::json!({
                "schema_version": 1,
                "status": "disabled",
                "state_revision": null,
                "baseline_generation": null,
                "observed_generation": null,
                "observation_complete": false,
                "trust_available": false,
                "re_enroll_available": false,
                "degraded_reason": null,
                "last_scan_at": null,
                "tracked_file_count": 0,
                "drift_file_count": 0,
                "coverage": {
                    "status": "disabled",
                    "unavailable_target_count": 0,
                    "error_counts": []
                }
            })
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn timed_out_worker_is_joined_and_never_overlaps_the_next_scan() {
        use crate::security_events::FileIntegrityDegradedReasonV1;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use tokio::sync::oneshot;

        let service = enabled_test_service().await;
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let (first_started_tx, first_started_rx) = oneshot::channel();
        let first = {
            let service = Arc::clone(&service);
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            tokio::spawn(async move {
                service
                    .run_scan_with(Duration::from_millis(5), move |_, _| {
                        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(current, Ordering::SeqCst);
                        let _ = first_started_tx.send(());
                        std::thread::sleep(Duration::from_millis(80));
                        active.fetch_sub(1, Ordering::SeqCst);
                        ScanResult::internal_error(1_700_000_001)
                    })
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(1), first_started_rx)
            .await
            .expect("first worker should start")
            .expect("first worker start signal should arrive");

        let release_second = Arc::new(AtomicBool::new(false));
        let (second_started_tx, second_started_rx) = oneshot::channel();
        let second = {
            let service = Arc::clone(&service);
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            let release_second = Arc::clone(&release_second);
            tokio::spawn(async move {
                service
                    .run_scan_with(Duration::from_secs(1), move |_, _| {
                        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(current, Ordering::SeqCst);
                        let _ = second_started_tx.send(());
                        while !release_second.load(Ordering::SeqCst) {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        active.fetch_sub(1, Ordering::SeqCst);
                        ScanResult::deadline_exceeded(1_700_000_002)
                    })
                    .await
            })
        };

        let second_started = matches!(
            tokio::time::timeout(Duration::from_secs(1), second_started_rx).await,
            Ok(Ok(()))
        );
        let status_while_second_waits = if second_started {
            Some(service.status().await.expect("load timed-out state"))
        } else {
            None
        };
        release_second.store(true, Ordering::SeqCst);
        first
            .await
            .expect("join first scan task")
            .expect("first timed-out scan should publish");
        second
            .await
            .expect("join second scan task")
            .expect("second scan should publish");

        assert!(second_started, "second worker never acquired the permit");
        assert_eq!(peak.load(Ordering::SeqCst), 1);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(
            status_while_second_waits.and_then(|status| status.degraded_reason),
            Some(FileIntegrityDegradedReasonV1::DeadlineExceeded)
        );
    }

    #[test]
    fn worst_case_status_serialization_stays_within_four_kib() {
        use crate::security_events::{
            FileIntegrityCoverageErrorCodeV1 as ErrorCode,
            FileIntegrityCoverageErrorCountV1 as ErrorCount, FileIntegrityDegradedReasonV1,
        };

        let error_counts = [
            ErrorCode::ChangedDuringRead,
            ErrorCode::DeadlineExceeded,
            ErrorCode::DirectoryUnreadable,
            ErrorCode::FileTooLarge,
            ErrorCode::FilesystemUnclassified,
            ErrorCode::IoError,
            ErrorCode::NetworkFilesystem,
            ErrorCode::NoObservableTargets,
            ErrorCode::NotRegular,
            ErrorCode::PathNotUtf8,
            ErrorCode::PathTooLong,
            ErrorCode::PermissionDenied,
            ErrorCode::ScanByteLimit,
            ErrorCode::Symlink,
            ErrorCode::TrackedFileLimit,
            ErrorCode::UntrustedNewCoverage,
            ErrorCode::VanishedDuringScan,
        ]
        .into_iter()
        .map(|code| ErrorCount { code, count: 15 })
        .collect();
        let status = FileIntegrityStatus {
            schema_version: 1,
            status: FileIntegrityStatusKind::Degraded,
            state_revision: Some(storage::JS_MAX_SAFE_INTEGER),
            baseline_generation: Some(storage::JS_MAX_SAFE_INTEGER),
            observed_generation: Some(storage::JS_MAX_SAFE_INTEGER),
            observation_complete: false,
            trust_available: false,
            re_enroll_available: false,
            degraded_reason: Some(FileIntegrityDegradedReasonV1::InternalError),
            last_scan_at: Some(253_402_300_799),
            tracked_file_count: 256,
            drift_file_count: 256,
            coverage: FileIntegrityCoverage {
                status: FileIntegrityCoverageStatus::Degraded,
                unavailable_target_count: 256,
                error_counts,
            },
        };

        let serialized = serde_json::to_vec(&status).expect("serialize bounded status");
        assert!(serialized.len() <= 4 * 1024, "{} bytes", serialized.len());
    }
}
