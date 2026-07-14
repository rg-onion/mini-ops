use crate::certificate_probe::{
    CertificateBatchError, CertificateObservation, CertificateProbe, CertificateProbeInitError,
    CertificateTarget, CertificateTargetsConfig, ExpiryStatus, HostnameStatus, MAX_CONCURRENCY,
    MAX_CONFIG_BYTES, MAX_TARGETS, ReachabilityStatus, TrustStatus, parse_targets_config,
};
use crate::notifications::{NotificationOutbox, NotificationService};
use crate::security::SecurityCheck;
use crate::security_events::SecurityEventService;
use sqlx::{Row, SqlitePool, Transaction};
use std::collections::{BTreeSet, HashMap};
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

const ENABLED_ENV: &str = "SECURITY_CERTIFICATE_MONITOR_ENABLED";
const TARGETS_FILE_ENV: &str = "SECURITY_CERTIFICATE_TARGETS_FILE";
const INTERVAL_ENV: &str = "SECURITY_CERTIFICATE_INTERVAL_SECS";
const CONCURRENCY_ENV: &str = "SECURITY_CERTIFICATE_MAX_CONCURRENCY";
const DEFAULT_TARGETS_FILE: &str = "/etc/mini-ops/certificates.toml";
const DEFAULT_INTERVAL_SECS: u64 = 21_600;
const MIN_INTERVAL_SECS: u64 = 300;
const MAX_INTERVAL_SECS: u64 = 86_400;
const DEFAULT_CONCURRENCY: usize = 4;
const MAX_PATH_BYTES: usize = 4096;

const CURRENT_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS certificate_current (
    target_id                 TEXT PRIMARY KEY
                                   CHECK (typeof(target_id) = 'text' AND
                                          length(CAST(target_id AS BLOB)) BETWEEN 1 AND 63 AND
                                          substr(target_id, 1, 1) GLOB '[a-z0-9]' AND
                                          target_id NOT GLOB '*[^a-z0-9._-]*'),
    label                     TEXT NOT NULL
                                   CHECK (typeof(label) = 'text' AND
                                          length(CAST(label AS BLOB)) BETWEEN 1 AND 128),
    connect_host              TEXT NOT NULL
                                   CHECK (typeof(connect_host) = 'text' AND
                                          length(CAST(connect_host AS BLOB)) BETWEEN 1 AND 253),
    port                      INTEGER NOT NULL
                                   CHECK (typeof(port) = 'integer' AND port BETWEEN 1 AND 65535),
    server_name               TEXT NOT NULL
                                   CHECK (typeof(server_name) = 'text' AND
                                          length(CAST(server_name AS BLOB)) BETWEEN 1 AND 253),
    trust_profile             TEXT NOT NULL CHECK (trust_profile = 'system'),
    schema_version            INTEGER NOT NULL
                                   CHECK (typeof(schema_version) = 'integer' AND schema_version = 1),
    checked_at                INTEGER NOT NULL
                                   CHECK (typeof(checked_at) = 'integer' AND
                                          checked_at BETWEEN 0 AND 253402300799),
    duration_ms               INTEGER NOT NULL
                                   CHECK (typeof(duration_ms) = 'integer' AND
                                          duration_ms BETWEEN 0 AND 60000),
    last_success_at           INTEGER
                                   CHECK (last_success_at IS NULL OR
                                          (typeof(last_success_at) = 'integer' AND
                                           last_success_at BETWEEN 0 AND 253402300799)),
    reachability              TEXT NOT NULL CHECK (reachability IN ('reachable','unknown')),
    trust                     TEXT NOT NULL CHECK (trust IN ('valid','invalid','unknown')),
    hostname                  TEXT NOT NULL CHECK (hostname IN ('match','mismatch','unknown')),
    expiry                    TEXT NOT NULL
                                   CHECK (expiry IN ('healthy','warning','critical','expired',
                                                     'not_yet_valid','unknown')),
    not_before                INTEGER
                                   CHECK (not_before IS NULL OR
                                          (typeof(not_before) = 'integer' AND
                                           not_before BETWEEN 0 AND 253402300799)),
    not_after                 INTEGER
                                   CHECK (not_after IS NULL OR
                                          (typeof(not_after) = 'integer' AND
                                           not_after BETWEEN 0 AND 253402300799)),
    lifetime_seconds          INTEGER
                                   CHECK (lifetime_seconds IS NULL OR
                                          (typeof(lifetime_seconds) = 'integer' AND
                                           lifetime_seconds BETWEEN 1 AND 253402300799)),
    remaining_seconds         INTEGER
                                   CHECK (remaining_seconds IS NULL OR
                                          (typeof(remaining_seconds) = 'integer' AND
                                           remaining_seconds BETWEEN -253402300799 AND 253402300799)),
    issuer_organization       TEXT
                                   CHECK (issuer_organization IS NULL OR
                                          (typeof(issuer_organization) = 'text' AND
                                           length(CAST(issuer_organization AS BLOB)) BETWEEN 1 AND 128)),
    fingerprint_sha256_short  TEXT
                                   CHECK (fingerprint_sha256_short IS NULL OR
                                          (typeof(fingerprint_sha256_short) = 'text' AND
                                           length(fingerprint_sha256_short) = 16 AND
                                           fingerprint_sha256_short NOT GLOB '*[^0-9a-f]*')),
    error_code                TEXT
                                   CHECK (error_code IS NULL OR error_code IN
                                          ('dns_timeout','dns_failed','connect_timeout',
                                           'connect_refused','connect_failed','tls_timeout',
                                           'tls_handshake_failed','certificate_missing',
                                           'certificate_parse_failed','unsupported_protocol',
                                           'cancelled','internal_error')),
    updated_at                INTEGER NOT NULL
                                   CHECK (typeof(updated_at) = 'integer' AND
                                          updated_at BETWEEN 0 AND 253402300799),
    CHECK ((not_before IS NULL AND not_after IS NULL AND lifetime_seconds IS NULL AND
            remaining_seconds IS NULL) OR
           (not_before IS NOT NULL AND not_after IS NOT NULL AND
            lifetime_seconds = not_after - not_before AND
            remaining_seconds = not_after - checked_at AND not_after > not_before)),
    CHECK ((error_code IS NULL AND reachability = 'reachable' AND
            not_before IS NOT NULL AND fingerprint_sha256_short IS NOT NULL) OR
           (error_code IS NOT NULL AND not_before IS NULL AND not_after IS NULL AND
            lifetime_seconds IS NULL AND remaining_seconds IS NULL AND
            issuer_organization IS NULL AND fingerprint_sha256_short IS NULL AND
            trust = 'unknown' AND hostname = 'unknown' AND expiry = 'unknown')),
    CHECK (updated_at = checked_at)
) STRICT
"#;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CertificateMonitorConfig {
    enabled: bool,
    targets_file: PathBuf,
    interval_secs: u64,
    concurrency: usize,
}

impl CertificateMonitorConfig {
    pub(crate) fn from_env() -> Result<Self, CertificateMonitorConfigError> {
        Self::from_values(
            std::env::var_os(ENABLED_ENV).as_deref(),
            std::env::var_os(TARGETS_FILE_ENV).as_deref(),
            std::env::var_os(INTERVAL_ENV).as_deref(),
            std::env::var_os(CONCURRENCY_ENV).as_deref(),
        )
    }

    fn from_values(
        enabled_value: Option<&OsStr>,
        targets_file_value: Option<&OsStr>,
        interval_value: Option<&OsStr>,
        concurrency_value: Option<&OsStr>,
    ) -> Result<Self, CertificateMonitorConfigError> {
        let enabled = match enabled_value {
            None => false,
            Some(value) => match value.to_str() {
                Some("true") => true,
                Some("false") => false,
                _ => return Err(CertificateMonitorConfigError::EnabledValue),
            },
        };
        let targets_file = match targets_file_value {
            None => PathBuf::from(DEFAULT_TARGETS_FILE),
            Some(value) => {
                let value = value
                    .to_str()
                    .ok_or(CertificateMonitorConfigError::TargetsFile)?;
                if value.is_empty() || value.len() > MAX_PATH_BYTES {
                    return Err(CertificateMonitorConfigError::TargetsFile);
                }
                PathBuf::from(value)
            }
        };
        if !valid_absolute_path(&targets_file) {
            return Err(CertificateMonitorConfigError::TargetsFile);
        }
        let interval_secs = parse_bounded_u64(
            interval_value,
            DEFAULT_INTERVAL_SECS,
            MIN_INTERVAL_SECS,
            MAX_INTERVAL_SECS,
        )
        .ok_or(CertificateMonitorConfigError::Interval)?;
        let concurrency = parse_bounded_u64(
            concurrency_value,
            DEFAULT_CONCURRENCY as u64,
            1,
            MAX_CONCURRENCY as u64,
        )
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(CertificateMonitorConfigError::Concurrency)?;
        Ok(Self {
            enabled,
            targets_file,
            interval_secs,
            concurrency,
        })
    }

    pub(crate) const fn enabled(&self) -> bool {
        self.enabled
    }
}

fn parse_bounded_u64(value: Option<&OsStr>, default: u64, min: u64, max: u64) -> Option<u64> {
    match value {
        None => Some(default),
        Some(value) => value
            .to_str()?
            .parse::<u64>()
            .ok()
            .filter(|value| (min..=max).contains(value)),
    }
}

fn valid_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.as_os_str().as_encoded_bytes().len() <= MAX_PATH_BYTES
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CertificateMonitorConfigError {
    EnabledValue,
    TargetsFile,
    Interval,
    Concurrency,
}

impl CertificateMonitorConfigError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::EnabledValue => "invalid_enabled_value",
            Self::TargetsFile => "invalid_targets_file",
            Self::Interval => "invalid_interval",
            Self::Concurrency => "invalid_concurrency",
        }
    }
}

impl fmt::Display for CertificateMonitorConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for CertificateMonitorConfigError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CertificateMonitorInitError {
    FeatureDisabled,
    UnsafeTargetsFile,
    TargetsFileRead,
    InvalidTargets,
    SystemTrustUnavailable,
    TlsConfiguration,
    Database,
}

impl CertificateMonitorInitError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::FeatureDisabled => "feature_disabled",
            Self::UnsafeTargetsFile => "unsafe_targets_file",
            Self::TargetsFileRead => "targets_file_read",
            Self::InvalidTargets => "invalid_targets",
            Self::SystemTrustUnavailable => "system_trust_unavailable",
            Self::TlsConfiguration => "tls_configuration",
            Self::Database => "database",
        }
    }
}

impl fmt::Display for CertificateMonitorInitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for CertificateMonitorInitError {}

#[derive(Clone)]
struct CertificateStorage {
    db: SqlitePool,
    outbox: Arc<NotificationOutbox>,
    notifier: Arc<NotificationService>,
}

impl CertificateStorage {
    async fn initialize(
        db: SqlitePool,
        outbox: Arc<NotificationOutbox>,
        notifier: Arc<NotificationService>,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query(CURRENT_DDL).execute(&db).await?;
        Ok(Self {
            db,
            outbox,
            notifier,
        })
    }

    async fn publish(
        &self,
        targets: &[CertificateTarget],
        observations: &[CertificateObservation],
    ) -> Result<(), sqlx::Error> {
        if targets.is_empty()
            || targets.len() > MAX_TARGETS
            || targets.len() != observations.len()
            || targets
                .iter()
                .zip(observations)
                .any(|(target, observation)| target.id != observation.target_id)
        {
            return Err(invalid_certificate_state());
        }

        let mut transaction = self.db.begin_with("BEGIN IMMEDIATE").await?;
        self.prune_removed_targets(&mut transaction, targets)
            .await?;
        for (target, observation) in targets.iter().zip(observations) {
            upsert_current(&mut transaction, target, observation).await?;
            self.apply_observation(&mut transaction, observation)
                .await?;
        }
        transaction.commit().await
    }

    async fn prune_removed_targets(
        &self,
        transaction: &mut Transaction<'_, sqlx::Sqlite>,
        targets: &[CertificateTarget],
    ) -> Result<(), sqlx::Error> {
        let rows =
            sqlx::query("SELECT target_id FROM certificate_current ORDER BY target_id LIMIT ?")
                .bind((MAX_TARGETS + 1) as i64)
                .fetch_all(&mut **transaction)
                .await?;
        if rows.len() > MAX_TARGETS {
            return Err(invalid_certificate_state());
        }
        let configured: BTreeSet<&str> = targets.iter().map(|target| target.id.as_str()).collect();
        for row in rows {
            let target_id: String = row.try_get("target_id")?;
            if configured.contains(target_id.as_str()) {
                continue;
            }
            for finding in ["expiry", "hostname", "trust", "coverage"] {
                let check = resolved_check(&target_id, finding);
                SecurityEventService::resolve_audit_event_in_transaction(
                    transaction,
                    &check,
                    None,
                    chrono::Utc::now().timestamp(),
                )
                .await?;
            }
            sqlx::query("DELETE FROM certificate_current WHERE target_id = ?")
                .bind(&target_id)
                .execute(&mut **transaction)
                .await?;
        }
        Ok(())
    }

    async fn apply_observation(
        &self,
        transaction: &mut Transaction<'_, sqlx::Sqlite>,
        observation: &CertificateObservation,
    ) -> Result<(), sqlx::Error> {
        let lang = crate::i18n::Lang::from_headers(&crate::i18n::HeaderMap::new());

        match observation.expiry {
            ExpiryStatus::Healthy => {
                self.resolve_risk(transaction, observation, "expiry", &lang)
                    .await?;
            }
            ExpiryStatus::Warning
            | ExpiryStatus::Critical
            | ExpiryStatus::Expired
            | ExpiryStatus::NotYetValid => {
                let severity = match observation.expiry {
                    ExpiryStatus::Warning => "medium",
                    ExpiryStatus::Critical => "high",
                    ExpiryStatus::Expired => "critical",
                    ExpiryStatus::NotYetValid => "high",
                    _ => return Err(invalid_certificate_state()),
                };
                let check = risk_check(
                    observation,
                    "expiry",
                    observation.expiry.code(),
                    severity,
                    &lang,
                )?;
                let notification = risk_notification(&self.notifier, &check, false, &lang);
                SecurityEventService::upsert_audit_event_in_transaction(
                    transaction,
                    &check,
                    Some((&self.outbox, &notification)),
                    observation.checked_at,
                )
                .await?;
            }
            ExpiryStatus::Unknown => {}
        }

        match observation.hostname {
            HostnameStatus::Match => {
                self.resolve_risk(transaction, observation, "hostname", &lang)
                    .await?;
            }
            HostnameStatus::Mismatch => {
                let check = risk_check(observation, "hostname", "mismatch", "high", &lang)?;
                let notification = risk_notification(&self.notifier, &check, false, &lang);
                SecurityEventService::upsert_audit_event_in_transaction(
                    transaction,
                    &check,
                    Some((&self.outbox, &notification)),
                    observation.checked_at,
                )
                .await?;
            }
            HostnameStatus::Unknown => {}
        }

        match observation.trust {
            TrustStatus::Valid => {
                self.resolve_risk(transaction, observation, "trust", &lang)
                    .await?;
            }
            TrustStatus::Invalid => {
                let check = risk_check(observation, "trust", "invalid", "high", &lang)?;
                let notification = risk_notification(&self.notifier, &check, false, &lang);
                SecurityEventService::upsert_audit_event_in_transaction(
                    transaction,
                    &check,
                    Some((&self.outbox, &notification)),
                    observation.checked_at,
                )
                .await?;
            }
            TrustStatus::Unknown => {}
        }

        let unknown_dimensions = unknown_dimensions(observation);
        if unknown_dimensions.is_empty() && observation.error_code.is_none() {
            let check = resolved_check(&observation.target_id, "coverage");
            SecurityEventService::resolve_audit_event_in_transaction(
                transaction,
                &check,
                None,
                observation.checked_at,
            )
            .await?;
        } else {
            let check = coverage_check(observation, &unknown_dimensions, &lang)?;
            SecurityEventService::upsert_audit_event_in_transaction(
                transaction,
                &check,
                None,
                observation.checked_at,
            )
            .await?;
        }
        Ok(())
    }

    async fn resolve_risk(
        &self,
        transaction: &mut Transaction<'_, sqlx::Sqlite>,
        observation: &CertificateObservation,
        finding: &str,
        lang: &crate::i18n::Lang,
    ) -> Result<(), sqlx::Error> {
        let check = resolved_observation_check(observation, finding, lang);
        let notification = risk_notification(&self.notifier, &check, true, lang);
        SecurityEventService::resolve_audit_event_in_transaction(
            transaction,
            &check,
            Some((&self.outbox, &notification)),
            observation.checked_at,
        )
        .await?;
        Ok(())
    }
}

pub(crate) struct CertificateMonitorService {
    storage: CertificateStorage,
    probe: CertificateProbe,
    targets: Arc<Vec<CertificateTarget>>,
    interval_secs: u64,
    concurrency: usize,
    exclusive: Mutex<()>,
}

impl CertificateMonitorService {
    pub(crate) async fn initialize_enabled(
        db: SqlitePool,
        outbox: Arc<NotificationOutbox>,
        notifier: Arc<NotificationService>,
        config: CertificateMonitorConfig,
    ) -> Result<Arc<Self>, CertificateMonitorInitError> {
        if !config.enabled {
            return Err(CertificateMonitorInitError::FeatureDisabled);
        }
        let contents = load_targets_file(config.targets_file.clone()).await?;
        let CertificateTargetsConfig { targets, .. } = parse_targets_config(&contents)
            .map_err(|_| CertificateMonitorInitError::InvalidTargets)?;
        let probe = CertificateProbe::new_system().map_err(|error| match error {
            CertificateProbeInitError::SystemTrustUnavailable => {
                CertificateMonitorInitError::SystemTrustUnavailable
            }
            CertificateProbeInitError::TlsConfiguration => {
                CertificateMonitorInitError::TlsConfiguration
            }
        })?;
        let storage = CertificateStorage::initialize(db, outbox, notifier)
            .await
            .map_err(|_| CertificateMonitorInitError::Database)?;
        Ok(Arc::new(Self {
            storage,
            probe,
            targets: Arc::new(targets),
            interval_secs: config.interval_secs,
            concurrency: config.concurrency,
            exclusive: Mutex::new(()),
        }))
    }

    pub(crate) fn start(self: Arc<Self>) -> JoinHandle<()> {
        tokio::spawn(async move {
            tracing::info!(
                interval_secs = self.interval_secs,
                target_count = self.targets.len(),
                concurrency = self.concurrency,
                "Starting certificate monitor"
            );
            let mut interval =
                certificate_monitor_interval(Duration::from_secs(self.interval_secs));
            loop {
                interval.tick().await;
                if let Err(error) = self.run_once().await {
                    tracing::warn!(
                        certificate_monitor_error = error.code(),
                        "Certificate monitor cycle failed"
                    );
                }
            }
        })
    }

    async fn run_once(&self) -> Result<(), CertificateMonitorCycleError> {
        let _guard = self.exclusive.lock().await;
        let observations = self
            .probe
            .probe_all(&self.targets, self.concurrency)
            .await
            .map_err(CertificateMonitorCycleError::Batch)?;
        for observation in &observations {
            tracing::info!(
                target_id = %observation.target_id,
                duration_ms = observation.duration_ms,
                reachability = observation.reachability.code(),
                trust = observation.trust.code(),
                hostname = observation.hostname.code(),
                expiry = observation.expiry.code(),
                error_code = observation.error_code.map(|error| error.code()),
                "Certificate target observed"
            );
        }
        self.storage
            .publish(&self.targets, &observations)
            .await
            .map_err(|_| CertificateMonitorCycleError::Database)
    }
}

#[derive(Debug)]
enum CertificateMonitorCycleError {
    Batch(CertificateBatchError),
    Database,
}

impl CertificateMonitorCycleError {
    const fn code(&self) -> &'static str {
        match self {
            Self::Batch(error) => error.code(),
            Self::Database => "database",
        }
    }
}

fn certificate_monitor_interval(period: Duration) -> tokio::time::Interval {
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval
}

async fn load_targets_file(path: PathBuf) -> Result<Vec<u8>, CertificateMonitorInitError> {
    tokio::task::spawn_blocking(move || read_targets_file(&path, Path::new("/"), 0))
        .await
        .map_err(|_| CertificateMonitorInitError::TargetsFileRead)?
}

fn read_targets_file(
    path: &Path,
    trusted_root: &Path,
    expected_uid: u32,
) -> Result<Vec<u8>, CertificateMonitorInitError> {
    validate_ancestors(path, trusted_root, expected_uid)?;
    let path_metadata =
        fs::symlink_metadata(path).map_err(|_| CertificateMonitorInitError::TargetsFileRead)?;
    if path_metadata.file_type().is_symlink() {
        return Err(CertificateMonitorInitError::UnsafeTargetsFile);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| CertificateMonitorInitError::TargetsFileRead)?;
    let metadata = file
        .metadata()
        .map_err(|_| CertificateMonitorInitError::TargetsFileRead)?;
    let mode = metadata.permissions().mode();
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || mode & 0o137 != 0
        || metadata.len() > MAX_CONFIG_BYTES as u64
    {
        return Err(CertificateMonitorInitError::UnsafeTargetsFile);
    }
    let mut contents = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut contents)
        .map_err(|_| CertificateMonitorInitError::TargetsFileRead)?;
    if contents.len() > MAX_CONFIG_BYTES {
        return Err(CertificateMonitorInitError::UnsafeTargetsFile);
    }
    Ok(contents)
}

fn validate_ancestors(
    path: &Path,
    trusted_root: &Path,
    expected_uid: u32,
) -> Result<(), CertificateMonitorInitError> {
    if !path.is_absolute() || !trusted_root.is_absolute() {
        return Err(CertificateMonitorInitError::UnsafeTargetsFile);
    }
    let relative = path
        .strip_prefix(trusted_root)
        .map_err(|_| CertificateMonitorInitError::UnsafeTargetsFile)?;
    let mut current = trusted_root.to_path_buf();
    validate_directory(&current, expected_uid)?;
    let components: Vec<_> = relative.components().collect();
    if components.is_empty() {
        return Err(CertificateMonitorInitError::UnsafeTargetsFile);
    }
    for component in &components[..components.len() - 1] {
        let Component::Normal(value) = component else {
            return Err(CertificateMonitorInitError::UnsafeTargetsFile);
        };
        current.push(value);
        validate_directory(&current, expected_uid)?;
    }
    Ok(())
}

fn validate_directory(path: &Path, expected_uid: u32) -> Result<(), CertificateMonitorInitError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| CertificateMonitorInitError::UnsafeTargetsFile)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(CertificateMonitorInitError::UnsafeTargetsFile);
    }
    Ok(())
}

async fn upsert_current(
    transaction: &mut Transaction<'_, sqlx::Sqlite>,
    target: &CertificateTarget,
    observation: &CertificateObservation,
) -> Result<(), sqlx::Error> {
    let duration_ms = i64::try_from(observation.duration_ms)
        .ok()
        .filter(|value| *value <= 60_000)
        .ok_or_else(invalid_certificate_state)?;
    sqlx::query(
        "INSERT INTO certificate_current (
            target_id, label, connect_host, port, server_name, trust_profile,
            schema_version, checked_at, duration_ms, last_success_at,
            reachability, trust, hostname, expiry, not_before, not_after,
            lifetime_seconds, remaining_seconds, issuer_organization,
            fingerprint_sha256_short, error_code, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(target_id) DO UPDATE SET
            label = excluded.label,
            connect_host = excluded.connect_host,
            port = excluded.port,
            server_name = excluded.server_name,
            trust_profile = excluded.trust_profile,
            schema_version = excluded.schema_version,
            checked_at = excluded.checked_at,
            duration_ms = excluded.duration_ms,
            last_success_at = COALESCE(excluded.last_success_at, certificate_current.last_success_at),
            reachability = excluded.reachability,
            trust = excluded.trust,
            hostname = excluded.hostname,
            expiry = excluded.expiry,
            not_before = excluded.not_before,
            not_after = excluded.not_after,
            lifetime_seconds = excluded.lifetime_seconds,
            remaining_seconds = excluded.remaining_seconds,
            issuer_organization = excluded.issuer_organization,
            fingerprint_sha256_short = excluded.fingerprint_sha256_short,
            error_code = excluded.error_code,
            updated_at = excluded.updated_at",
    )
    .bind(&target.id)
    .bind(&target.label)
    .bind(&target.connect_host)
    .bind(i64::from(target.port))
    .bind(&target.server_name)
    .bind(target.trust_profile.code())
    .bind(i64::try_from(observation.schema_version).map_err(|_| invalid_certificate_state())?)
    .bind(observation.checked_at)
    .bind(duration_ms)
    .bind(observation.last_success_at)
    .bind(observation.reachability.code())
    .bind(observation.trust.code())
    .bind(observation.hostname.code())
    .bind(observation.expiry.code())
    .bind(observation.not_before)
    .bind(observation.not_after)
    .bind(observation.lifetime_seconds)
    .bind(observation.remaining_seconds)
    .bind(observation.issuer_organization.as_deref())
    .bind(observation.fingerprint_sha256_short.as_deref())
    .bind(observation.error_code.map(|error| error.code()))
    .bind(observation.checked_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn risk_check(
    observation: &CertificateObservation,
    finding: &str,
    state: &str,
    severity: &str,
    lang: &crate::i18n::Lang,
) -> Result<SecurityCheck, sqlx::Error> {
    let mut evidence = vec![
        format!("target_id={}", observation.target_id),
        format!("finding={finding}"),
        format!("state={state}"),
        format!("checked_at={}", observation.checked_at),
    ];
    if finding == "expiry" {
        let not_after = observation
            .not_after
            .ok_or_else(invalid_certificate_state)?;
        let remaining = observation
            .remaining_seconds
            .ok_or_else(invalid_certificate_state)?;
        evidence.push(format!("not_after={not_after}"));
        evidence.push(format!("remaining_seconds={remaining}"));
    }
    let name = format!(
        "{}: {}",
        crate::i18n::t(&format!("certificate.{finding}.title"), lang),
        observation.label
    );
    let message = format!(
        "{}: {}",
        crate::i18n::t(&format!("certificate.{finding}.message"), lang),
        crate::i18n::t(&format!("certificate.state.{state}"), lang)
    );
    Ok(SecurityCheck {
        id: format!("certificate.{finding}.{}", observation.target_id),
        name,
        category: "certificate".to_string(),
        severity: severity.to_string(),
        status: "FAIL".to_string(),
        message,
        evidence,
        remediation: crate::i18n::t(&format!("certificate.{finding}.remediation"), lang),
        references: Vec::new(),
        metadata: HashMap::new(),
    })
}

fn coverage_check(
    observation: &CertificateObservation,
    unknown_dimensions: &[&str],
    lang: &crate::i18n::Lang,
) -> Result<SecurityCheck, sqlx::Error> {
    if unknown_dimensions.is_empty() {
        return Err(invalid_certificate_state());
    }
    let mut evidence = vec![
        format!("target_id={}", observation.target_id),
        "finding=coverage".to_string(),
        "state=degraded".to_string(),
        format!("checked_at={}", observation.checked_at),
        format!("unknown_dimensions={}", unknown_dimensions.join(",")),
    ];
    if let Some(error) = observation.error_code {
        evidence.push(format!("error_code={}", error.code()));
    }
    Ok(SecurityCheck {
        id: format!("certificate.coverage.{}", observation.target_id),
        name: format!(
            "{}: {}",
            crate::i18n::t("certificate.coverage.title", lang),
            observation.label
        ),
        category: "certificate".to_string(),
        severity: "medium".to_string(),
        status: "WARN".to_string(),
        message: crate::i18n::t("certificate.coverage.message", lang),
        evidence,
        remediation: crate::i18n::t("certificate.coverage.remediation", lang),
        references: Vec::new(),
        metadata: HashMap::new(),
    })
}

fn resolved_check(target_id: &str, finding: &str) -> SecurityCheck {
    SecurityCheck {
        id: format!("certificate.{finding}.{target_id}"),
        name: format!("certificate.{finding}"),
        category: "certificate".to_string(),
        severity: "info".to_string(),
        status: "PASS".to_string(),
        message: "resolved".to_string(),
        evidence: Vec::new(),
        remediation: String::new(),
        references: Vec::new(),
        metadata: HashMap::new(),
    }
}

fn resolved_observation_check(
    observation: &CertificateObservation,
    finding: &str,
    lang: &crate::i18n::Lang,
) -> SecurityCheck {
    SecurityCheck {
        id: format!("certificate.{finding}.{}", observation.target_id),
        name: format!(
            "{}: {}",
            crate::i18n::t(&format!("certificate.{finding}.title"), lang),
            observation.label
        ),
        category: "certificate".to_string(),
        severity: "info".to_string(),
        status: "PASS".to_string(),
        message: crate::i18n::t("security.resolved", lang),
        evidence: Vec::new(),
        remediation: String::new(),
        references: Vec::new(),
        metadata: HashMap::new(),
    }
}

fn risk_notification(
    notifier: &NotificationService,
    check: &SecurityCheck,
    resolved: bool,
    lang: &crate::i18n::Lang,
) -> String {
    if resolved {
        notifier.render_alert_text(&format!(
            "{}\n\n{}: {}",
            crate::i18n::t("security.resolved", lang),
            crate::i18n::t("security.check", lang),
            check.id
        ))
    } else {
        notifier.render_alert_text(&format!(
            "{}\n\n{}: {}\n{}: {}",
            crate::i18n::t("security.detected", lang),
            crate::i18n::t("security.check", lang),
            check.id,
            crate::i18n::t("security.message", lang),
            check.message
        ))
    }
}

fn unknown_dimensions(observation: &CertificateObservation) -> Vec<&'static str> {
    let mut dimensions = Vec::with_capacity(4);
    if observation.reachability == ReachabilityStatus::Unknown {
        dimensions.push("reachability");
    }
    if observation.trust == TrustStatus::Unknown {
        dimensions.push("trust");
    }
    if observation.hostname == HostnameStatus::Unknown {
        dimensions.push("hostname");
    }
    if observation.expiry == ExpiryStatus::Unknown {
        dimensions.push("expiry");
    }
    dimensions
}

fn invalid_certificate_state() -> sqlx::Error {
    sqlx::Error::Protocol("invalid certificate monitor state".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate_probe::{CertificateProbeErrorCode, TrustProfile};
    use std::fs::Permissions;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    const VALID_TARGETS: &str = r#"
schema_version = 1

[[targets]]
id = "service"
label = "Service TLS"
connect_host = "service.test"
port = 443
server_name = "service.test"
trust_profile = "system"
"#;

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "mini-ops-certificate-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("test directory should be created");
            fs::set_permissions(&path, Permissions::from_mode(0o700))
                .expect("test directory should be private");
            Self { path }
        }

        fn file(&self, name: &str, contents: &[u8], mode: u32) -> PathBuf {
            let path = self.path.join(name);
            fs::write(&path, contents).expect("test file should be written");
            fs::set_permissions(&path, Permissions::from_mode(mode))
                .expect("test file mode should be set");
            path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn config_from(
        enabled: Option<&str>,
        path: Option<&str>,
        interval: Option<&str>,
        concurrency: Option<&str>,
    ) -> Result<CertificateMonitorConfig, CertificateMonitorConfigError> {
        CertificateMonitorConfig::from_values(
            enabled.map(OsStr::new),
            path.map(OsStr::new),
            interval.map(OsStr::new),
            concurrency.map(OsStr::new),
        )
    }

    #[test]
    fn config_is_strict_opt_in_and_bounded() {
        let default = config_from(None, None, None, None).expect("defaults should parse");
        assert!(!default.enabled);
        assert_eq!(default.targets_file, PathBuf::from(DEFAULT_TARGETS_FILE));
        assert_eq!(default.interval_secs, DEFAULT_INTERVAL_SECS);
        assert_eq!(default.concurrency, DEFAULT_CONCURRENCY);

        let enabled = config_from(
            Some("true"),
            Some("/etc/mini-ops/custom.toml"),
            Some("300"),
            Some("8"),
        )
        .expect("bounded explicit config should parse");
        assert!(enabled.enabled);
        assert_eq!(enabled.interval_secs, 300);
        assert_eq!(enabled.concurrency, 8);

        assert_eq!(
            config_from(Some("TRUE"), None, None, None),
            Err(CertificateMonitorConfigError::EnabledValue)
        );
        assert_eq!(
            config_from(None, Some("relative.toml"), None, None),
            Err(CertificateMonitorConfigError::TargetsFile)
        );
        assert_eq!(
            config_from(None, Some("/etc/../tmp/targets"), None, None),
            Err(CertificateMonitorConfigError::TargetsFile)
        );
        for value in ["", "299", "86401", "invalid"] {
            assert_eq!(
                config_from(None, None, Some(value), None),
                Err(CertificateMonitorConfigError::Interval)
            );
        }
        for value in ["", "0", "9", "invalid"] {
            assert_eq!(
                config_from(None, None, None, Some(value)),
                Err(CertificateMonitorConfigError::Concurrency)
            );
        }
    }

    #[test]
    fn targets_file_requires_trusted_ancestors_and_safe_final_mode() {
        let fixture = TestDirectory::new("safe-file");
        let uid = crate::runtime::effective_uid();
        let safe = fixture.file("targets.toml", VALID_TARGETS.as_bytes(), 0o640);
        assert_eq!(
            read_targets_file(&safe, &fixture.path, uid).expect("safe fixture should load"),
            VALID_TARGETS.as_bytes()
        );

        let writable = fixture.file("writable.toml", VALID_TARGETS.as_bytes(), 0o660);
        assert_eq!(
            read_targets_file(&writable, &fixture.path, uid),
            Err(CertificateMonitorInitError::UnsafeTargetsFile)
        );
        let public = fixture.file("public.toml", VALID_TARGETS.as_bytes(), 0o644);
        assert_eq!(
            read_targets_file(&public, &fixture.path, uid),
            Err(CertificateMonitorInitError::UnsafeTargetsFile)
        );
        let oversized = fixture.file("oversized.toml", &vec![b'x'; MAX_CONFIG_BYTES + 1], 0o640);
        assert_eq!(
            read_targets_file(&oversized, &fixture.path, uid),
            Err(CertificateMonitorInitError::UnsafeTargetsFile)
        );

        let link = fixture.path.join("link.toml");
        symlink(&safe, &link).expect("test symlink should be created");
        assert_eq!(
            read_targets_file(&link, &fixture.path, uid),
            Err(CertificateMonitorInitError::UnsafeTargetsFile)
        );

        let unsafe_parent = fixture.path.join("unsafe-parent");
        fs::create_dir(&unsafe_parent).expect("unsafe parent should be created");
        fs::set_permissions(&unsafe_parent, Permissions::from_mode(0o770))
            .expect("unsafe parent mode should be set");
        let nested = unsafe_parent.join("targets.toml");
        fs::write(&nested, VALID_TARGETS).expect("nested file should be written");
        fs::set_permissions(&nested, Permissions::from_mode(0o640))
            .expect("nested file mode should be set");
        assert_eq!(
            read_targets_file(&nested, &fixture.path, uid),
            Err(CertificateMonitorInitError::UnsafeTargetsFile)
        );
    }

    async fn test_storage(enabled_notifications: bool) -> CertificateStorage {
        let db = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("in-memory database should connect");
        SecurityEventService::init_schema(&db)
            .await
            .expect("security event schema should initialize");
        let notifier = if enabled_notifications {
            Arc::new(NotificationService::with_test_endpoint(
                "123456:test",
                "http://127.0.0.1:9".to_string(),
            ))
        } else {
            Arc::new(NotificationService::disabled_for_tests())
        };
        let outbox = Arc::new(NotificationOutbox::new(db.clone(), Arc::clone(&notifier)));
        CertificateStorage::initialize(db, outbox, notifier)
            .await
            .expect("certificate storage should initialize")
    }

    fn target(id: &str) -> CertificateTarget {
        CertificateTarget {
            id: id.to_string(),
            label: format!("TLS {id}"),
            connect_host: format!("{id}.test"),
            port: 443,
            server_name: format!("{id}.test"),
            trust_profile: TrustProfile::System,
        }
    }

    fn healthy_observation(target: &CertificateTarget, checked_at: i64) -> CertificateObservation {
        let not_before = checked_at - 86_400;
        let not_after = checked_at + 90 * 86_400;
        CertificateObservation {
            schema_version: 1,
            target_id: target.id.clone(),
            label: target.label.clone(),
            connect_host: target.connect_host.clone(),
            port: target.port,
            server_name: target.server_name.clone(),
            checked_at,
            duration_ms: 25,
            last_success_at: Some(checked_at),
            reachability: ReachabilityStatus::Reachable,
            trust: TrustStatus::Valid,
            hostname: HostnameStatus::Match,
            expiry: ExpiryStatus::Healthy,
            not_before: Some(not_before),
            not_after: Some(not_after),
            lifetime_seconds: Some(not_after - not_before),
            remaining_seconds: Some(not_after - checked_at),
            issuer_organization: Some("Fixture CA".to_string()),
            fingerprint_sha256_short: Some("0123456789abcdef".to_string()),
            error_code: None,
        }
    }

    fn with_expiry(
        mut observation: CertificateObservation,
        expiry: ExpiryStatus,
        remaining_seconds: i64,
    ) -> CertificateObservation {
        let not_after = observation.checked_at + remaining_seconds;
        let not_before = observation.checked_at - 90 * 86_400;
        observation.expiry = expiry;
        observation.not_before = Some(not_before);
        observation.not_after = Some(not_after);
        observation.lifetime_seconds = Some(not_after - not_before);
        observation.remaining_seconds = Some(remaining_seconds);
        observation
    }

    fn failed_observation(target: &CertificateTarget, checked_at: i64) -> CertificateObservation {
        CertificateObservation {
            schema_version: 1,
            target_id: target.id.clone(),
            label: target.label.clone(),
            connect_host: target.connect_host.clone(),
            port: target.port,
            server_name: target.server_name.clone(),
            checked_at,
            duration_ms: 50,
            last_success_at: None,
            reachability: ReachabilityStatus::Unknown,
            trust: TrustStatus::Unknown,
            hostname: HostnameStatus::Unknown,
            expiry: ExpiryStatus::Unknown,
            not_before: None,
            not_after: None,
            lifetime_seconds: None,
            remaining_seconds: None,
            issuer_organization: None,
            fingerprint_sha256_short: None,
            error_code: Some(CertificateProbeErrorCode::ConnectTimeout),
        }
    }

    async fn event_row(storage: &CertificateStorage, check_id: &str) -> (String, String, i64) {
        sqlx::query_as(
            "SELECT status, severity, notification_seq
             FROM security_events WHERE event_key = ?",
        )
        .bind(format!("audit:{check_id}"))
        .fetch_one(&storage.db)
        .await
        .expect("event row should exist")
    }

    async fn outbox_count(storage: &CertificateStorage) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM notification_outbox")
            .fetch_one(&storage.db)
            .await
            .expect("outbox count should be readable")
    }

    #[tokio::test]
    async fn expiry_transitions_are_atomic_deduplicated_and_escalate() {
        let storage = test_storage(true).await;
        let target = target("service");
        let base = 1_700_000_000_i64;

        let warning = with_expiry(
            healthy_observation(&target, base),
            ExpiryStatus::Warning,
            20 * 86_400,
        );
        storage
            .publish(
                std::slice::from_ref(&target),
                std::slice::from_ref(&warning),
            )
            .await
            .expect("warning should publish");
        assert_eq!(
            event_row(&storage, "certificate.expiry.service").await,
            ("open".to_string(), "medium".to_string(), 1)
        );
        assert_eq!(outbox_count(&storage).await, 1);
        let stored_payload: String = sqlx::query_scalar(
            "SELECT payload_json FROM notification_outbox
             WHERE source_event_key = 'audit:certificate.expiry.service'",
        )
        .fetch_one(&storage.db)
        .await
        .expect("certificate notification payload should exist");
        let stored_evidence: String = sqlx::query_scalar(
            "SELECT evidence_json FROM security_events
             WHERE event_key = 'audit:certificate.expiry.service'",
        )
        .fetch_one(&storage.db)
        .await
        .expect("certificate event evidence should exist");
        for sensitive in [
            target.label.as_str(),
            target.connect_host.as_str(),
            target.server_name.as_str(),
            "Fixture CA",
            "0123456789abcdef",
        ] {
            assert!(!stored_payload.contains(sensitive));
            assert!(!stored_evidence.contains(sensitive));
        }
        assert!(stored_payload.contains("certificate.expiry.service"));

        let repeated = with_expiry(
            healthy_observation(&target, base + 60),
            ExpiryStatus::Warning,
            20 * 86_400 - 60,
        );
        storage
            .publish(
                std::slice::from_ref(&target),
                std::slice::from_ref(&repeated),
            )
            .await
            .expect("identical warning should update without alert");
        assert_eq!(outbox_count(&storage).await, 1);

        sqlx::query(
            "UPDATE security_events SET status = 'acknowledged', acknowledged_at = ?
             WHERE event_key = 'audit:certificate.expiry.service'",
        )
        .bind(base + 61)
        .execute(&storage.db)
        .await
        .expect("event should acknowledge");
        let critical = with_expiry(
            healthy_observation(&target, base + 120),
            ExpiryStatus::Critical,
            5 * 86_400,
        );
        storage
            .publish(
                std::slice::from_ref(&target),
                std::slice::from_ref(&critical),
            )
            .await
            .expect("critical escalation should publish");
        assert_eq!(
            event_row(&storage, "certificate.expiry.service").await,
            ("open".to_string(), "high".to_string(), 2)
        );
        assert_eq!(outbox_count(&storage).await, 2);

        let expired = with_expiry(
            healthy_observation(&target, base + 180),
            ExpiryStatus::Expired,
            -60,
        );
        storage
            .publish(
                std::slice::from_ref(&target),
                std::slice::from_ref(&expired),
            )
            .await
            .expect("expired escalation should publish");
        assert_eq!(
            event_row(&storage, "certificate.expiry.service").await,
            ("open".to_string(), "critical".to_string(), 3)
        );
        assert_eq!(outbox_count(&storage).await, 3);

        let recovered = healthy_observation(&target, base + 240);
        storage
            .publish(
                std::slice::from_ref(&target),
                std::slice::from_ref(&recovered),
            )
            .await
            .expect("healthy renewal should resolve");
        assert_eq!(
            event_row(&storage, "certificate.expiry.service").await,
            ("resolved".to_string(), "critical".to_string(), 4)
        );
        assert_eq!(outbox_count(&storage).await, 4);

        storage
            .publish(
                std::slice::from_ref(&target),
                std::slice::from_ref(&recovered),
            )
            .await
            .expect("repeated healthy observation should be a no-op transition");
        assert_eq!(outbox_count(&storage).await, 4);
    }

    #[tokio::test]
    async fn unknown_opens_coverage_without_resolving_risk_and_preserves_last_success() {
        let storage = test_storage(true).await;
        let target = target("service");
        let base = 1_700_100_000_i64;
        let warning = with_expiry(
            healthy_observation(&target, base),
            ExpiryStatus::Warning,
            10 * 86_400,
        );
        storage
            .publish(
                std::slice::from_ref(&target),
                std::slice::from_ref(&warning),
            )
            .await
            .expect("warning should publish");
        let failed = failed_observation(&target, base + 300);
        storage
            .publish(std::slice::from_ref(&target), std::slice::from_ref(&failed))
            .await
            .expect("failed probe should publish degraded current state");

        assert_eq!(
            event_row(&storage, "certificate.expiry.service").await.0,
            "open"
        );
        assert_eq!(
            event_row(&storage, "certificate.coverage.service").await,
            ("open".to_string(), "medium".to_string(), 0)
        );
        assert_eq!(outbox_count(&storage).await, 1);
        let current: (Option<i64>, String, Option<String>) = sqlx::query_as(
            "SELECT last_success_at, expiry, error_code
             FROM certificate_current WHERE target_id = 'service'",
        )
        .fetch_one(&storage.db)
        .await
        .expect("current row should exist");
        assert_eq!(
            current,
            (
                Some(base),
                "unknown".to_string(),
                Some("connect_timeout".to_string())
            )
        );

        let events = SecurityEventService::new(storage.db.clone())
            .list(Some("active"), 10)
            .await
            .expect("typed event projection should succeed");
        let coverage = events
            .iter()
            .find(|event| event.event_key == "audit:certificate.coverage.service")
            .expect("coverage event should project");
        let serialized = serde_json::to_value(coverage).expect("event should serialize");
        assert_eq!(serialized["evidence"]["kind"], "audit.check_warning");
        assert_eq!(serialized["evidence"]["data"]["category"], "certificate");
        assert_eq!(
            serialized["evidence"]["data"]["evidence"][4],
            "unknown_dimensions=reachability,trust,hostname,expiry"
        );

        let stored: String = sqlx::query_scalar(
            "SELECT evidence_json FROM security_events
             WHERE event_key = 'audit:certificate.coverage.service'",
        )
        .fetch_one(&storage.db)
        .await
        .expect("stored evidence should be readable");
        let mut malformed: serde_json::Value =
            serde_json::from_str(&stored).expect("stored evidence should be JSON");
        malformed["evidence"][0] = serde_json::Value::String("target_id=other".to_string());
        sqlx::query(
            "UPDATE security_events SET evidence_json = ?
             WHERE event_key = 'audit:certificate.coverage.service'",
        )
        .bind(serde_json::to_string(&malformed).expect("malformed fixture should serialize"))
        .execute(&storage.db)
        .await
        .expect("malformed fixture should update");
        let events = SecurityEventService::new(storage.db.clone())
            .list(Some("active"), 10)
            .await
            .expect("malformed projection should remain bounded");
        let coverage = events
            .iter()
            .find(|event| event.event_key == "audit:certificate.coverage.service")
            .expect("coverage event should remain listed");
        let serialized = serde_json::to_value(coverage).expect("event should serialize");
        assert_eq!(
            serialized["evidence"]["error_code"],
            "invalid_stored_payload"
        );
        assert!(serialized["evidence"]["data"].is_null());
        assert_eq!(serialized["evidence_json"], "{}");
    }

    #[tokio::test]
    async fn hostname_and_trust_findings_are_independent() {
        let storage = test_storage(true).await;
        let target = target("service");
        let base = 1_700_200_000_i64;
        let mut risky = healthy_observation(&target, base);
        risky.hostname = HostnameStatus::Mismatch;
        risky.trust = TrustStatus::Invalid;
        storage
            .publish(std::slice::from_ref(&target), std::slice::from_ref(&risky))
            .await
            .expect("independent findings should publish");
        assert_eq!(outbox_count(&storage).await, 2);
        assert_eq!(
            event_row(&storage, "certificate.hostname.service").await.0,
            "open"
        );
        assert_eq!(
            event_row(&storage, "certificate.trust.service").await.0,
            "open"
        );

        let mut partial = healthy_observation(&target, base + 60);
        partial.trust = TrustStatus::Unknown;
        storage
            .publish(
                std::slice::from_ref(&target),
                std::slice::from_ref(&partial),
            )
            .await
            .expect("partial recovery should publish");
        assert_eq!(
            event_row(&storage, "certificate.hostname.service").await.0,
            "resolved"
        );
        assert_eq!(
            event_row(&storage, "certificate.trust.service").await.0,
            "open"
        );
        assert_eq!(
            event_row(&storage, "certificate.coverage.service").await.0,
            "open"
        );
    }

    #[tokio::test]
    async fn event_or_outbox_failure_rolls_back_current_state() {
        let storage = test_storage(true).await;
        sqlx::query(
            "CREATE TRIGGER fail_certificate_outbox BEFORE INSERT ON notification_outbox
             BEGIN SELECT RAISE(ABORT, 'fixture'); END",
        )
        .execute(&storage.db)
        .await
        .expect("failure trigger should install");
        let target = target("service");
        let warning = with_expiry(
            healthy_observation(&target, 1_700_300_000),
            ExpiryStatus::Warning,
            10 * 86_400,
        );
        assert!(
            storage
                .publish(
                    std::slice::from_ref(&target),
                    std::slice::from_ref(&warning)
                )
                .await
                .is_err()
        );
        let current_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM certificate_current")
            .fetch_one(&storage.db)
            .await
            .expect("current count should be readable");
        let event_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security_events
             WHERE event_key = 'audit:certificate.expiry.service'",
        )
        .fetch_one(&storage.db)
        .await
        .expect("event count should be readable");
        assert_eq!((current_count, event_count), (0, 0));
    }

    #[tokio::test]
    async fn removed_target_prunes_current_and_resolves_without_recovery_notification() {
        let storage = test_storage(true).await;
        let removed = target("removed");
        let warning = with_expiry(
            healthy_observation(&removed, 1_700_400_000),
            ExpiryStatus::Warning,
            10 * 86_400,
        );
        storage
            .publish(
                std::slice::from_ref(&removed),
                std::slice::from_ref(&warning),
            )
            .await
            .expect("initial target should publish");
        let retained = target("retained");
        let healthy = healthy_observation(&retained, 1_700_400_060);
        storage
            .publish(
                std::slice::from_ref(&retained),
                std::slice::from_ref(&healthy),
            )
            .await
            .expect("replacement target should publish");

        let ids: Vec<String> =
            sqlx::query_scalar("SELECT target_id FROM certificate_current ORDER BY target_id")
                .fetch_all(&storage.db)
                .await
                .expect("current IDs should be readable");
        assert_eq!(ids, vec!["retained".to_string()]);
        assert_eq!(
            event_row(&storage, "certificate.expiry.removed").await.0,
            "resolved"
        );
        assert_eq!(outbox_count(&storage).await, 1);
    }

    #[tokio::test]
    async fn scheduler_is_immediate_and_skips_missed_ticks() {
        let mut interval = certificate_monitor_interval(Duration::from_secs(300));
        assert_eq!(
            interval.missed_tick_behavior(),
            tokio::time::MissedTickBehavior::Skip
        );
        tokio::time::timeout(Duration::from_millis(50), interval.tick())
            .await
            .expect("first tick should be immediate");
    }
}
