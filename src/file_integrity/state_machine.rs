//! Transactional state machine for the current-only sensitive-file manifest.

use super::collector::{
    EntryState, FileMetadata, MAX_TRACKED_PATHS, ObservedEntry, PathObservationError, ScanError,
    ScanResult, ScanTerminalReason, TargetKind, file_integrity_path_id,
};
use super::storage::{FileIntegrityStorage, JS_MAX_SAFE_INTEGER};
use super::{
    FileIntegrityCoverage, FileIntegrityCoverageStatus, FileIntegrityOperationError,
    FileIntegrityOperationErrorCode, FileIntegrityStatus, FileIntegrityStatusKind, ReEnrollRequest,
    ReEnrollResponse, TrustCurrentStateRequest, TrustCurrentStateResponse,
};
use crate::notifications::NotificationOutbox;
use crate::security_events::{
    FileChangeKindV1, FileEvidenceMetadataV1, FileEvidenceStateV1,
    FileIntegrityBaselineReenrolledEvidenceV1, FileIntegrityCoverageDegradedEvidenceV1,
    FileIntegrityCoverageErrorCodeV1, FileIntegrityCoverageErrorCountV1,
    FileIntegrityDegradedReasonV1, FileIntegrityDriftEventText, FileIntegrityEventMutation,
    FileIntegrityReenrollReasonV1, FileObservationErrorV1, FileSensitiveChangedEvidenceV1,
    SecurityEventService,
};
use sha2::{Digest, Sha256};
use sqlx::sqlite::SqliteRow;
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use std::collections::{BTreeMap, BTreeSet};

const SCHEMA_VERSION: u64 = 1;
const DIGEST_ALGORITHM: &str = "sha256";
const DIGEST_VERSION: u64 = 1;
const MANIFEST_VERSION: u64 = 1;
const MAX_MANIFEST_BYTES: usize = 256 * 1024;
const MAX_TIMESTAMP: i64 = 253_402_300_799;
const MANIFEST_DOMAIN: &[u8] = b"mini-ops:file-integrity:manifest:v1\0";

const COVERAGE_TITLE: &str = "Integrity coverage degraded";
const COVERAGE_MESSAGE: &str = "Open the local Security page.";
const DRIFT_TITLE: &str = "Sensitive file changed";
const DRIFT_MESSAGE: &str = "Open the local Security page.";
const DRIFT_NOTIFICATION: &str =
    "Sensitive-file integrity changed: severity high, count 1. Open the local Security page.";
const RECOVERY_NOTIFICATION: &str =
    "Sensitive-file integrity recovered: severity high, count 1. Open the local Security page.";
const REENROLL_TITLE: &str = "Integrity baseline re-enrolled";
const REENROLL_MESSAGE: &str = "A new local trust baseline was explicitly enrolled.";

const FIXED_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/group",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
];
const REQUIRED_PATHS: &[&str] = &["/etc/passwd", "/etc/group"];
const DIRECTORY_ROOTS: &[&str] = &[
    "/etc/sudoers.d",
    "/etc/ssh/sshd_config.d",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
];

#[derive(Clone, Debug)]
struct StateRecord {
    schema_version: u64,
    digest_algorithm: String,
    digest_version: u64,
    manifest_version: u64,
    state_revision: u64,
    baseline_generation: u64,
    observed_generation: u64,
    status: StoredStatus,
    degraded_reason: Option<FileIntegrityDegradedReasonV1>,
    observation_complete: bool,
    trust_available: bool,
    re_enroll_available: bool,
    baseline_manifest: Option<[u8; 32]>,
    observed_manifest: Option<[u8; 32]>,
    baseline_updated_at: Option<i64>,
    observed_at: Option<i64>,
    last_scan_at: Option<i64>,
    tracked_file_count: u64,
    drift_file_count: u64,
    unavailable_target_count: u64,
    error_counts: Vec<FileIntegrityCoverageErrorCountV1>,
    updated_at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoredStatus {
    Initializing,
    Healthy,
    Drift,
    Degraded,
}

impl StoredStatus {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "initializing" => Some(Self::Initializing),
            "healthy" => Some(Self::Healthy),
            "drift" => Some(Self::Drift),
            "degraded" => Some(Self::Degraded),
            _ => None,
        }
    }

    const fn code(self) -> &'static str {
        match self {
            Self::Initializing => "initializing",
            Self::Healthy => "healthy",
            Self::Drift => "drift",
            Self::Degraded => "degraded",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredEntry {
    path_id: String,
    logical_path: String,
    generation: u64,
    target_kind: TargetKind,
    entry_state: EntryState,
    content_digest: Option<[u8; 32]>,
    metadata: FileMetadata,
    observation_error: Option<PathObservationError>,
}

impl StoredEntry {
    fn from_observed(entry: ObservedEntry, generation: u64) -> Self {
        Self {
            path_id: entry.path_id,
            logical_path: entry.logical_path,
            generation,
            target_kind: entry.target_kind,
            entry_state: entry.entry_state,
            content_digest: entry.content_digest,
            metadata: entry.metadata,
            observation_error: entry.observation_error,
        }
    }

    fn for_generation(&self, generation: u64) -> Self {
        let mut entry = self.clone();
        entry.generation = generation;
        entry.observation_error = None;
        entry
    }

    fn material_eq(&self, other: &Self) -> bool {
        self.path_id == other.path_id
            && self.logical_path == other.logical_path
            && self.target_kind == other.target_kind
            && self.entry_state == other.entry_state
            && self.content_digest == other.content_digest
            && self.metadata.size_bytes == other.metadata.size_bytes
            && self.metadata.mode == other.metadata.mode
            && self.metadata.uid == other.metadata.uid
            && self.metadata.gid == other.metadata.gid
            && self.observation_error == other.observation_error
    }
}

#[derive(Clone, Debug)]
struct DriftFact {
    evidence: FileSensitiveChangedEvidenceV1,
    material_changed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistedIntegrity {
    Valid,
    BaselineCorrupt,
    UnsupportedAlgorithm,
    InternalCorrupt,
}

#[derive(Clone, Debug)]
struct Candidate {
    rows: Vec<StoredEntry>,
    errors: Vec<FileIntegrityCoverageErrorCountV1>,
    unavailable_target_count: u64,
    execution_complete: bool,
    observation_complete: bool,
    required_targets_observed: bool,
    observed_at: i64,
    terminal_reason: Option<ScanTerminalReason>,
}

#[derive(Clone, Copy)]
enum ManifestKind {
    Baseline = 1,
    Observed = 2,
}

struct ManifestEncoder {
    bytes: Vec<u8>,
}

impl ManifestEncoder {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(16 * 1024),
        }
    }

    fn extend(&mut self, value: &[u8]) -> Result<(), sqlx::Error> {
        let next_len = self
            .bytes
            .len()
            .checked_add(value.len())
            .filter(|length| *length <= MAX_MANIFEST_BYTES)
            .ok_or_else(invalid_integrity_state)?;
        self.bytes.reserve(next_len - self.bytes.len());
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), sqlx::Error> {
        self.extend(&[value])
    }

    fn u32(&mut self, value: u32) -> Result<(), sqlx::Error> {
        self.extend(&value.to_be_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), sqlx::Error> {
        self.extend(&value.to_be_bytes())
    }

    fn i64(&mut self, value: i64) -> Result<(), sqlx::Error> {
        self.extend(&value.to_be_bytes())
    }

    fn string(&mut self, value: &str) -> Result<(), sqlx::Error> {
        let length = u32::try_from(value.len()).map_err(|_| invalid_integrity_state())?;
        self.u32(length)?;
        self.extend(value.as_bytes())
    }

    fn optional_u64(&mut self, value: Option<u64>) -> Result<(), sqlx::Error> {
        match value {
            Some(value) => {
                self.u8(1)?;
                self.u64(value)
            }
            None => self.u8(0),
        }
    }

    fn optional_i64(&mut self, value: Option<i64>) -> Result<(), sqlx::Error> {
        match value {
            Some(value) => {
                self.u8(1)?;
                self.i64(value)
            }
            None => self.u8(0),
        }
    }

    fn optional_u32(&mut self, value: Option<u32>) -> Result<(), sqlx::Error> {
        match value {
            Some(value) => {
                self.u8(1)?;
                self.u32(value)
            }
            None => self.u8(0),
        }
    }
}

fn canonical_manifest(
    kind: ManifestKind,
    generation: u64,
    rows: &[StoredEntry],
) -> Result<[u8; 32], sqlx::Error> {
    if generation == 0
        || generation > JS_MAX_SAFE_INTEGER
        || rows.len() > MAX_TRACKED_PATHS
        || !rows
            .windows(2)
            .all(|pair| pair[0].path_id < pair[1].path_id)
        || rows.iter().any(|row| row.generation != generation)
    {
        return Err(invalid_integrity_state());
    }
    let mut encoder = ManifestEncoder::new();
    encoder.extend(MANIFEST_DOMAIN)?;
    encoder.u8(kind as u8)?;
    encoder.u64(SCHEMA_VERSION)?;
    encoder.string(DIGEST_ALGORITHM)?;
    encoder.u64(DIGEST_VERSION)?;
    encoder.u64(MANIFEST_VERSION)?;
    encoder.u64(generation)?;
    encoder.u32(u32::try_from(rows.len()).map_err(|_| invalid_integrity_state())?)?;
    for row in rows {
        encoder.string(&row.path_id)?;
        encoder.string(&row.logical_path)?;
        encoder.u64(row.generation)?;
        encoder.u8(match row.target_kind {
            TargetKind::Fixed => 1,
            TargetKind::DirectoryRoot => 2,
            TargetKind::DirectoryChild => 3,
        })?;
        encoder.u8(match row.entry_state {
            EntryState::Regular => 1,
            EntryState::Directory => 2,
            EntryState::Absent => 3,
        })?;
        match row.content_digest {
            Some(digest) => {
                encoder.u8(1)?;
                encoder.extend(&digest)?;
            }
            None => encoder.u8(0)?,
        }
        encoder.optional_u64(row.metadata.size_bytes)?;
        encoder.optional_i64(row.metadata.mtime_unix_seconds)?;
        encoder.optional_u32(row.metadata.mode)?;
        encoder.optional_u32(row.metadata.uid)?;
        encoder.optional_u32(row.metadata.gid)?;
        match row.observation_error {
            Some(error) => {
                encoder.u8(1)?;
                encoder.string(error.code())?;
            }
            None => encoder.u8(0)?,
        }
    }
    Ok(Sha256::digest(&encoder.bytes).into())
}

fn manifest_payload_size(rows: &[StoredEntry]) -> Result<usize, sqlx::Error> {
    let mut size = MANIFEST_DOMAIN.len() + 1 + 8 + 4 + DIGEST_ALGORITHM.len() + 8 + 8 + 8 + 4;
    for row in rows {
        let row_size = 4usize
            .checked_add(row.path_id.len())
            .and_then(|size| size.checked_add(4 + row.logical_path.len()))
            .and_then(|size| size.checked_add(8 + 1 + 1))
            .and_then(|size| size.checked_add(1 + row.content_digest.map_or(0, |_| 32)))
            .and_then(|size| size.checked_add(1 + row.metadata.size_bytes.map_or(0, |_| 8)))
            .and_then(|size| size.checked_add(1 + row.metadata.mtime_unix_seconds.map_or(0, |_| 8)))
            .and_then(|size| size.checked_add(1 + row.metadata.mode.map_or(0, |_| 4)))
            .and_then(|size| size.checked_add(1 + row.metadata.uid.map_or(0, |_| 4)))
            .and_then(|size| size.checked_add(1 + row.metadata.gid.map_or(0, |_| 4)))
            .and_then(|size| {
                size.checked_add(
                    1 + row
                        .observation_error
                        .map_or(0, |error| 4 + error.code().len()),
                )
            })
            .ok_or_else(invalid_integrity_state)?;
        size = size
            .checked_add(row_size)
            .ok_or_else(invalid_integrity_state)?;
    }
    Ok(size)
}

fn manifest_within_budget(rows: &[StoredEntry]) -> Result<bool, sqlx::Error> {
    Ok(manifest_payload_size(rows)? <= MAX_MANIFEST_BYTES)
}

async fn load_state(transaction: &mut Transaction<'_, Sqlite>) -> Result<StateRecord, sqlx::Error> {
    let row = sqlx::query(
        "SELECT schema_version, digest_algorithm, digest_version, manifest_version,
                state_revision, baseline_generation, observed_generation, status,
                degraded_reason, observation_complete, trust_available,
                re_enroll_available, baseline_manifest, observed_manifest,
                baseline_updated_at, observed_at, last_scan_at,
                tracked_file_count, drift_file_count, unavailable_target_count,
                error_counts_json, updated_at
         FROM file_integrity_state WHERE id = 1",
    )
    .fetch_one(&mut **transaction)
    .await?;
    state_from_row(&row)
}

fn state_from_row(row: &SqliteRow) -> Result<StateRecord, sqlx::Error> {
    let status_text: String = row.try_get("status")?;
    let reason_text: Option<String> = row.try_get("degraded_reason")?;
    let error_counts_json: String = row.try_get("error_counts_json")?;
    let state = StateRecord {
        schema_version: safe_u64(row, "schema_version")?,
        digest_algorithm: row.try_get("digest_algorithm")?,
        digest_version: safe_u64(row, "digest_version")?,
        manifest_version: safe_u64(row, "manifest_version")?,
        state_revision: safe_u64(row, "state_revision")?,
        baseline_generation: safe_u64(row, "baseline_generation")?,
        observed_generation: safe_u64(row, "observed_generation")?,
        status: StoredStatus::parse(&status_text).ok_or_else(invalid_integrity_state)?,
        degraded_reason: parse_degraded_reason(reason_text.as_deref())?,
        observation_complete: bool_value(row, "observation_complete")?,
        trust_available: bool_value(row, "trust_available")?,
        re_enroll_available: bool_value(row, "re_enroll_available")?,
        baseline_manifest: optional_digest(row, "baseline_manifest")?,
        observed_manifest: optional_digest(row, "observed_manifest")?,
        baseline_updated_at: row.try_get("baseline_updated_at")?,
        observed_at: row.try_get("observed_at")?,
        last_scan_at: row.try_get("last_scan_at")?,
        tracked_file_count: bounded_count(row, "tracked_file_count")?,
        drift_file_count: bounded_count(row, "drift_file_count")?,
        unavailable_target_count: bounded_count(row, "unavailable_target_count")?,
        error_counts: parse_error_counts(&error_counts_json)?,
        updated_at: row.try_get("updated_at")?,
    };
    validate_state_shape(&state)?;
    Ok(state)
}

async fn load_baseline(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<Vec<StoredEntry>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT path_id, logical_path, generation, target_kind, entry_state,
                content_digest, size_bytes, mtime_unix_seconds, mode, uid, gid
         FROM file_integrity_baseline ORDER BY path_id LIMIT 257",
    )
    .fetch_all(&mut **transaction)
    .await?;
    rows.iter()
        .map(|row| stored_entry_from_row(row, false))
        .collect()
}

async fn load_observed(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<Vec<StoredEntry>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT path_id, logical_path, generation, target_kind, entry_state,
                content_digest, size_bytes, mtime_unix_seconds, mode, uid, gid,
                observation_error
         FROM file_integrity_observed ORDER BY path_id LIMIT 257",
    )
    .fetch_all(&mut **transaction)
    .await?;
    rows.iter()
        .map(|row| stored_entry_from_row(row, true))
        .collect()
}

fn stored_entry_from_row(row: &SqliteRow, observed: bool) -> Result<StoredEntry, sqlx::Error> {
    let digest = optional_digest(row, "content_digest")?;
    let observation_error = if observed {
        parse_observation_error(
            row.try_get::<Option<String>, _>("observation_error")?
                .as_deref(),
        )?
    } else {
        None
    };
    let entry = StoredEntry {
        path_id: row.try_get("path_id")?,
        logical_path: row.try_get("logical_path")?,
        generation: safe_u64(row, "generation")?,
        target_kind: parse_target_kind(&row.try_get::<String, _>("target_kind")?)?,
        entry_state: parse_entry_state(&row.try_get::<String, _>("entry_state")?)?,
        content_digest: digest,
        metadata: FileMetadata {
            size_bytes: optional_safe_u64(row, "size_bytes")?,
            mtime_unix_seconds: row.try_get("mtime_unix_seconds")?,
            mode: optional_u32(row, "mode")?,
            uid: optional_u32(row, "uid")?,
            gid: optional_u32(row, "gid")?,
        },
        observation_error,
    };
    Ok(entry)
}

fn validate_state_shape(state: &StateRecord) -> Result<(), sqlx::Error> {
    if state.state_revision > JS_MAX_SAFE_INTEGER
        || state.baseline_generation > JS_MAX_SAFE_INTEGER
        || state.observed_generation > JS_MAX_SAFE_INTEGER
        || state.drift_file_count > state.tracked_file_count
        || state.updated_at < 0
        || state.updated_at > MAX_TIMESTAMP
        || state
            .baseline_updated_at
            .is_some_and(|value| !(0..=MAX_TIMESTAMP).contains(&value))
        || state
            .observed_at
            .is_some_and(|value| !(0..=MAX_TIMESTAMP).contains(&value))
        || state
            .last_scan_at
            .is_some_and(|value| !(0..=MAX_TIMESTAMP).contains(&value))
        || (state.status == StoredStatus::Degraded) != state.degraded_reason.is_some()
        || state.trust_available && state.re_enroll_available
        || (state.baseline_generation == 0)
            != (state.baseline_manifest.is_none() && state.baseline_updated_at.is_none())
        || (state.observed_generation == 0)
            != (state.observed_manifest.is_none() && state.observed_at.is_none())
    {
        return Err(invalid_integrity_state());
    }
    Ok(())
}

fn validate_entry(entry: &StoredEntry, observed: bool) -> Result<(), sqlx::Error> {
    if entry.generation == 0
        || entry.generation > JS_MAX_SAFE_INTEGER
        || file_integrity_path_id(&entry.logical_path).as_deref() != Some(&entry.path_id)
        || expected_target_kind(&entry.logical_path) != Some(entry.target_kind)
        || entry
            .metadata
            .mtime_unix_seconds
            .is_some_and(|value| !(0..=MAX_TIMESTAMP).contains(&value))
        || entry.metadata.mode.is_some_and(|value| value > 0o7777)
    {
        return Err(invalid_integrity_state());
    }
    let metadata_absent = entry.metadata.size_bytes.is_none()
        && entry.metadata.mtime_unix_seconds.is_none()
        && entry.metadata.mode.is_none()
        && entry.metadata.uid.is_none()
        && entry.metadata.gid.is_none();
    let metadata_regular = entry.metadata.size_bytes.is_some()
        && entry.metadata.mtime_unix_seconds.is_some()
        && entry.metadata.mode.is_some()
        && entry.metadata.uid.is_some()
        && entry.metadata.gid.is_some();
    let metadata_directory = entry.metadata.size_bytes.is_none()
        && entry.metadata.mtime_unix_seconds.is_none()
        && entry.metadata.mode.is_some()
        && entry.metadata.uid.is_some()
        && entry.metadata.gid.is_some();
    if !observed {
        let valid = entry.observation_error.is_none()
            && match (entry.target_kind, entry.entry_state) {
                (TargetKind::Fixed | TargetKind::DirectoryChild, EntryState::Regular) => {
                    entry.content_digest.is_some()
                        && metadata_regular
                        && entry
                            .metadata
                            .size_bytes
                            .is_some_and(|size| size <= 1024 * 1024)
                }
                (TargetKind::DirectoryRoot, EntryState::Directory) => {
                    entry.content_digest.is_none() && metadata_directory
                }
                (TargetKind::Fixed | TargetKind::DirectoryRoot, EntryState::Absent) => {
                    entry.content_digest.is_none() && metadata_absent
                }
                _ => false,
            };
        return valid.then_some(()).ok_or_else(invalid_integrity_state);
    }

    let valid = match entry.observation_error {
        None => match (entry.target_kind, entry.entry_state) {
            (TargetKind::Fixed | TargetKind::DirectoryChild, EntryState::Regular) => {
                entry.content_digest.is_some()
                    && metadata_regular
                    && entry
                        .metadata
                        .size_bytes
                        .is_some_and(|size| size <= 1024 * 1024)
            }
            (TargetKind::Fixed | TargetKind::DirectoryChild, EntryState::Directory) => {
                entry.content_digest.is_none() && metadata_directory
            }
            (TargetKind::Fixed | TargetKind::DirectoryRoot, EntryState::Absent) => {
                entry.content_digest.is_none() && metadata_absent
            }
            (TargetKind::DirectoryRoot, EntryState::Directory) => {
                entry.content_digest.is_none() && metadata_directory
            }
            (TargetKind::DirectoryRoot, EntryState::Regular) => {
                entry.content_digest.is_none() && metadata_regular
            }
            _ => false,
        },
        Some(_) => {
            matches!(
                entry.target_kind,
                TargetKind::Fixed | TargetKind::DirectoryChild
            ) && entry.content_digest.is_none()
                && match entry.entry_state {
                    EntryState::Absent => metadata_absent,
                    EntryState::Regular => !metadata_absent,
                    EntryState::Directory => false,
                }
        }
    };
    valid.then_some(()).ok_or_else(invalid_integrity_state)
}

fn expected_target_kind(path: &str) -> Option<TargetKind> {
    if FIXED_PATHS.contains(&path) {
        return Some(TargetKind::Fixed);
    }
    if DIRECTORY_ROOTS.contains(&path) {
        return Some(TargetKind::DirectoryRoot);
    }
    DIRECTORY_ROOTS.iter().find_map(|root| {
        path.strip_prefix(root)
            .and_then(|suffix| suffix.strip_prefix('/'))
            .filter(|basename| {
                !basename.is_empty()
                    && basename.len() <= 255
                    && !basename.contains('/')
                    && !basename.chars().any(char::is_control)
                    && !matches!(*basename, "." | "..")
            })
            .map(|_| TargetKind::DirectoryChild)
    })
}

fn validate_persisted(
    state: &StateRecord,
    baseline: &[StoredEntry],
    observed: &[StoredEntry],
) -> Result<PersistedIntegrity, sqlx::Error> {
    if state.schema_version != SCHEMA_VERSION
        || state.digest_algorithm != DIGEST_ALGORITHM
        || state.digest_version != DIGEST_VERSION
        || state.manifest_version != MANIFEST_VERSION
    {
        return Ok(PersistedIntegrity::UnsupportedAlgorithm);
    }
    if baseline.len() > MAX_TRACKED_PATHS
        || !unique_entries(baseline)
        || baseline
            .iter()
            .any(|entry| validate_entry(entry, false).is_err())
    {
        return Ok(PersistedIntegrity::BaselineCorrupt);
    }
    if observed.len() > MAX_TRACKED_PATHS
        || !unique_entries(observed)
        || observed
            .iter()
            .any(|entry| validate_entry(entry, true).is_err())
    {
        return Ok(PersistedIntegrity::InternalCorrupt);
    }
    let baseline_valid = if state.baseline_generation == 0 {
        baseline.is_empty() && state.baseline_manifest.is_none()
    } else {
        baseline
            .iter()
            .all(|entry| entry.generation == state.baseline_generation)
            && canonical_manifest(ManifestKind::Baseline, state.baseline_generation, baseline).ok()
                == state.baseline_manifest
    };
    if !baseline_valid {
        return Ok(PersistedIntegrity::BaselineCorrupt);
    }
    let observed_valid = if state.observed_generation == 0 {
        observed.is_empty() && state.observed_manifest.is_none()
    } else {
        observed
            .iter()
            .all(|entry| entry.generation == state.observed_generation)
            && canonical_manifest(ManifestKind::Observed, state.observed_generation, observed).ok()
                == state.observed_manifest
    };
    Ok(if observed_valid {
        PersistedIntegrity::Valid
    } else {
        PersistedIntegrity::InternalCorrupt
    })
}

fn unique_entries(rows: &[StoredEntry]) -> bool {
    rows.windows(2)
        .all(|pair| pair[0].path_id < pair[1].path_id)
        && rows
            .iter()
            .map(|row| row.logical_path.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            == rows.len()
}

fn safe_u64(row: &SqliteRow, column: &str) -> Result<u64, sqlx::Error> {
    let value: i64 = row.try_get(column)?;
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= JS_MAX_SAFE_INTEGER)
        .ok_or_else(invalid_integrity_state)
}

fn optional_safe_u64(row: &SqliteRow, column: &str) -> Result<Option<u64>, sqlx::Error> {
    row.try_get::<Option<i64>, _>(column)?
        .map(|value| {
            u64::try_from(value)
                .ok()
                .filter(|value| *value <= JS_MAX_SAFE_INTEGER)
                .ok_or_else(invalid_integrity_state)
        })
        .transpose()
}

fn optional_u32(row: &SqliteRow, column: &str) -> Result<Option<u32>, sqlx::Error> {
    row.try_get::<Option<i64>, _>(column)?
        .map(|value| u32::try_from(value).map_err(|_| invalid_integrity_state()))
        .transpose()
}

fn bounded_count(row: &SqliteRow, column: &str) -> Result<u64, sqlx::Error> {
    safe_u64(row, column).and_then(|value| {
        (value <= MAX_TRACKED_PATHS as u64)
            .then_some(value)
            .ok_or_else(invalid_integrity_state)
    })
}

fn bool_value(row: &SqliteRow, column: &str) -> Result<bool, sqlx::Error> {
    match row.try_get::<i64, _>(column)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid_integrity_state()),
    }
}

fn optional_digest(row: &SqliteRow, column: &str) -> Result<Option<[u8; 32]>, sqlx::Error> {
    row.try_get::<Option<Vec<u8>>, _>(column)?
        .map(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| invalid_integrity_state()))
        .transpose()
}

fn parse_target_kind(value: &str) -> Result<TargetKind, sqlx::Error> {
    match value {
        "fixed" => Ok(TargetKind::Fixed),
        "directory_root" => Ok(TargetKind::DirectoryRoot),
        "directory_child" => Ok(TargetKind::DirectoryChild),
        _ => Err(invalid_integrity_state()),
    }
}

fn parse_entry_state(value: &str) -> Result<EntryState, sqlx::Error> {
    match value {
        "regular" => Ok(EntryState::Regular),
        "directory" => Ok(EntryState::Directory),
        "absent" => Ok(EntryState::Absent),
        _ => Err(invalid_integrity_state()),
    }
}

fn parse_observation_error(
    value: Option<&str>,
) -> Result<Option<PathObservationError>, sqlx::Error> {
    value
        .map(|value| match value {
            "permission_denied" => Ok(PathObservationError::PermissionDenied),
            "symlink" => Ok(PathObservationError::Symlink),
            "not_regular" => Ok(PathObservationError::NotRegular),
            "file_too_large" => Ok(PathObservationError::FileTooLarge),
            "changed_during_read" => Ok(PathObservationError::ChangedDuringRead),
            "vanished_during_scan" => Ok(PathObservationError::VanishedDuringScan),
            "io_error" => Ok(PathObservationError::IoError),
            _ => Err(invalid_integrity_state()),
        })
        .transpose()
}

fn parse_degraded_reason(
    value: Option<&str>,
) -> Result<Option<FileIntegrityDegradedReasonV1>, sqlx::Error> {
    value
        .map(|value| match value {
            "coverage_unavailable" => Ok(FileIntegrityDegradedReasonV1::CoverageUnavailable),
            "limit_exceeded" => Ok(FileIntegrityDegradedReasonV1::LimitExceeded),
            "deadline_exceeded" => Ok(FileIntegrityDegradedReasonV1::DeadlineExceeded),
            "baseline_corrupt" => Ok(FileIntegrityDegradedReasonV1::BaselineCorrupt),
            "unsupported_algorithm" => Ok(FileIntegrityDegradedReasonV1::UnsupportedAlgorithm),
            "database_restore_required" => {
                Ok(FileIntegrityDegradedReasonV1::DatabaseRestoreRequired)
            }
            "internal_error" => Ok(FileIntegrityDegradedReasonV1::InternalError),
            _ => Err(invalid_integrity_state()),
        })
        .transpose()
}

fn degraded_reason_code(value: FileIntegrityDegradedReasonV1) -> &'static str {
    match value {
        FileIntegrityDegradedReasonV1::CoverageUnavailable => "coverage_unavailable",
        FileIntegrityDegradedReasonV1::LimitExceeded => "limit_exceeded",
        FileIntegrityDegradedReasonV1::DeadlineExceeded => "deadline_exceeded",
        FileIntegrityDegradedReasonV1::BaselineCorrupt => "baseline_corrupt",
        FileIntegrityDegradedReasonV1::UnsupportedAlgorithm => "unsupported_algorithm",
        FileIntegrityDegradedReasonV1::DatabaseRestoreRequired => "database_restore_required",
        FileIntegrityDegradedReasonV1::InternalError => "internal_error",
    }
}

fn parse_error_counts(value: &str) -> Result<Vec<FileIntegrityCoverageErrorCountV1>, sqlx::Error> {
    let counts: Vec<FileIntegrityCoverageErrorCountV1> =
        serde_json::from_str(value).map_err(|_| invalid_integrity_state())?;
    validate_error_counts(&counts)?;
    Ok(counts)
}

fn validate_error_counts(counts: &[FileIntegrityCoverageErrorCountV1]) -> Result<(), sqlx::Error> {
    if counts.len() > 24
        || !counts.windows(2).all(|pair| pair[0].code < pair[1].code)
        || counts
            .iter()
            .any(|entry| entry.count == 0 || entry.count > 256)
        || counts
            .iter()
            .try_fold(0_u64, |total, entry| total.checked_add(entry.count))
            .is_none_or(|total| total > 256)
    {
        return Err(invalid_integrity_state());
    }
    Ok(())
}

fn normalize_scan_result(result: ScanResult, generation: u64) -> Result<Candidate, sqlx::Error> {
    if !(0..=MAX_TIMESTAMP).contains(&result.observed_at)
        || result.unavailable_target_count as usize > MAX_TRACKED_PATHS
        || result.bytes_read > 8 * 1024 * 1024
        || result.rows.len() > MAX_TRACKED_PATHS
        || (!result.execution_complete && !result.rows.is_empty())
        || (!result.execution_complete && result.observation_complete)
        || (result.execution_complete && result.terminal_reason.is_some())
    {
        return Err(invalid_integrity_state());
    }
    let mut errors = BTreeMap::<FileIntegrityCoverageErrorCodeV1, u64>::new();
    for error in result.errors {
        if error.count == 0 {
            return Err(invalid_integrity_state());
        }
        let code = coverage_code(error.error);
        let count = errors.entry(code).or_default();
        *count = count
            .checked_add(u64::from(error.count))
            .ok_or_else(invalid_integrity_state)?;
    }
    let errors = errors
        .into_iter()
        .map(|(code, count)| FileIntegrityCoverageErrorCountV1 { code, count })
        .collect::<Vec<_>>();
    validate_error_counts(&errors)?;

    let mut rows = result
        .rows
        .into_iter()
        .map(|entry| StoredEntry::from_observed(entry, generation))
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| left.path_id.cmp(&right.path_id));
    if !unique_entries(&rows) {
        return Err(invalid_integrity_state());
    }
    for row in &rows {
        validate_entry(row, true)?;
    }
    let required_targets_observed = REQUIRED_PATHS.iter().all(|required| {
        rows.iter().any(|row| {
            row.logical_path == *required
                && row.target_kind == TargetKind::Fixed
                && row.entry_state == EntryState::Regular
                && row.content_digest.is_some()
                && row.observation_error.is_none()
        })
    });
    if result.required_targets_observed != required_targets_observed {
        return Err(invalid_integrity_state());
    }
    let full_observation = FIXED_PATHS.iter().chain(DIRECTORY_ROOTS).all(|path| {
        rows.iter().any(|row| {
            row.logical_path == *path && row.observation_error.is_none() && expected_state(row)
        })
    }) && rows
        .iter()
        .all(|row| row.observation_error.is_none() && expected_state(row));
    let expected_complete = result.execution_complete
        && full_observation
        && required_targets_observed
        && errors.is_empty()
        && result.unavailable_target_count == 0;
    if result.observation_complete != expected_complete {
        return Err(invalid_integrity_state());
    }
    Ok(Candidate {
        rows,
        errors,
        unavailable_target_count: u64::from(result.unavailable_target_count),
        execution_complete: result.execution_complete,
        observation_complete: result.observation_complete,
        required_targets_observed,
        observed_at: result.observed_at,
        terminal_reason: result.terminal_reason,
    })
}

fn expected_state(entry: &StoredEntry) -> bool {
    match entry.target_kind {
        TargetKind::Fixed => {
            if REQUIRED_PATHS.contains(&entry.logical_path.as_str()) {
                entry.entry_state == EntryState::Regular
            } else {
                matches!(entry.entry_state, EntryState::Regular | EntryState::Absent)
            }
        }
        TargetKind::DirectoryRoot => {
            matches!(
                entry.entry_state,
                EntryState::Directory | EntryState::Absent
            )
        }
        TargetKind::DirectoryChild => entry.entry_state == EntryState::Regular,
    }
}

fn baseline_subset(candidate: &Candidate, generation: u64) -> Vec<StoredEntry> {
    let mut rows = candidate
        .rows
        .iter()
        .filter(|row| row.observation_error.is_none() && expected_state(row))
        .map(|row| row.for_generation(generation))
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| left.path_id.cmp(&right.path_id));
    rows
}

fn coverage_code(error: ScanError) -> FileIntegrityCoverageErrorCodeV1 {
    match error {
        ScanError::PermissionDenied => FileIntegrityCoverageErrorCodeV1::PermissionDenied,
        ScanError::Symlink => FileIntegrityCoverageErrorCodeV1::Symlink,
        ScanError::NotRegular => FileIntegrityCoverageErrorCodeV1::NotRegular,
        ScanError::FileTooLarge => FileIntegrityCoverageErrorCodeV1::FileTooLarge,
        ScanError::ChangedDuringRead => FileIntegrityCoverageErrorCodeV1::ChangedDuringRead,
        ScanError::VanishedDuringScan => FileIntegrityCoverageErrorCodeV1::VanishedDuringScan,
        ScanError::IoError => FileIntegrityCoverageErrorCodeV1::IoError,
        ScanError::TrackedFileLimit => FileIntegrityCoverageErrorCodeV1::TrackedFileLimit,
        ScanError::ScanByteLimit => FileIntegrityCoverageErrorCodeV1::ScanByteLimit,
        ScanError::DeadlineExceeded | ScanError::Cancelled => {
            FileIntegrityCoverageErrorCodeV1::DeadlineExceeded
        }
        ScanError::DirectoryUnreadable => FileIntegrityCoverageErrorCodeV1::DirectoryUnreadable,
        ScanError::PathNotUtf8 => FileIntegrityCoverageErrorCodeV1::PathNotUtf8,
        ScanError::PathTooLong => FileIntegrityCoverageErrorCodeV1::PathTooLong,
        ScanError::NetworkFilesystem => FileIntegrityCoverageErrorCodeV1::NetworkFilesystem,
        ScanError::FilesystemUnclassified => {
            FileIntegrityCoverageErrorCodeV1::FilesystemUnclassified
        }
    }
}

fn partial_reason(candidate: &Candidate) -> FileIntegrityDegradedReasonV1 {
    match candidate.terminal_reason {
        Some(ScanTerminalReason::TrackedFileLimit | ScanTerminalReason::ScanByteLimit) => {
            FileIntegrityDegradedReasonV1::LimitExceeded
        }
        Some(ScanTerminalReason::DeadlineExceeded | ScanTerminalReason::Cancelled) => {
            FileIntegrityDegradedReasonV1::DeadlineExceeded
        }
        Some(ScanTerminalReason::InternalError) => FileIntegrityDegradedReasonV1::InternalError,
        None => FileIntegrityDegradedReasonV1::CoverageUnavailable,
    }
}

fn with_no_observable_targets(
    errors: &[FileIntegrityCoverageErrorCountV1],
) -> Result<Vec<FileIntegrityCoverageErrorCountV1>, sqlx::Error> {
    let mut counts = errors
        .iter()
        .map(|entry| (entry.code, entry.count))
        .collect::<BTreeMap<_, _>>();
    counts
        .entry(FileIntegrityCoverageErrorCodeV1::NoObservableTargets)
        .or_insert(1);
    let counts = counts
        .into_iter()
        .map(|(code, count)| FileIntegrityCoverageErrorCountV1 { code, count })
        .collect::<Vec<_>>();
    validate_error_counts(&counts)?;
    Ok(counts)
}

fn with_limit_error(
    errors: &[FileIntegrityCoverageErrorCountV1],
) -> Result<Vec<FileIntegrityCoverageErrorCountV1>, sqlx::Error> {
    let mut counts = errors
        .iter()
        .map(|entry| (entry.code, entry.count))
        .collect::<BTreeMap<_, _>>();
    counts
        .entry(FileIntegrityCoverageErrorCodeV1::TrackedFileLimit)
        .or_insert(1);
    let counts = counts
        .into_iter()
        .map(|(code, count)| FileIntegrityCoverageErrorCountV1 { code, count })
        .collect::<Vec<_>>();
    validate_error_counts(&counts)?;
    Ok(counts)
}

fn with_internal_error(
    errors: &[FileIntegrityCoverageErrorCountV1],
) -> Result<Vec<FileIntegrityCoverageErrorCountV1>, sqlx::Error> {
    let mut counts = errors
        .iter()
        .map(|entry| (entry.code, entry.count))
        .collect::<BTreeMap<_, _>>();
    counts
        .entry(FileIntegrityCoverageErrorCodeV1::IoError)
        .or_insert(1);
    let counts = counts
        .into_iter()
        .map(|(code, count)| FileIntegrityCoverageErrorCountV1 { code, count })
        .collect::<Vec<_>>();
    validate_error_counts(&counts)?;
    Ok(counts)
}

fn rows_materially_equal(left: &[StoredEntry], right: &[StoredEntry]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.material_eq(right))
}

fn union_count(baseline: &[StoredEntry], candidate: &[StoredEntry]) -> Result<u64, sqlx::Error> {
    union_count_with_unresolved_active(baseline, candidate, &BTreeMap::new(), &BTreeSet::new())
}

fn union_count_with_unresolved_active(
    baseline: &[StoredEntry],
    candidate: &[StoredEntry],
    active: &BTreeMap<String, String>,
    unresolved_active: &BTreeSet<String>,
) -> Result<u64, sqlx::Error> {
    let mut by_id = BTreeMap::<String, String>::new();
    let mut by_path = BTreeMap::<String, String>::new();
    for entry in baseline.iter().chain(candidate) {
        insert_union_identity(
            &mut by_id,
            &mut by_path,
            &entry.path_id,
            &entry.logical_path,
        )?;
    }
    for path_id in unresolved_active {
        let logical_path = active.get(path_id).ok_or_else(invalid_integrity_state)?;
        insert_union_identity(&mut by_id, &mut by_path, path_id, logical_path)?;
    }
    Ok(by_id.len() as u64)
}

fn insert_union_identity(
    by_id: &mut BTreeMap<String, String>,
    by_path: &mut BTreeMap<String, String>,
    path_id: &str,
    logical_path: &str,
) -> Result<(), sqlx::Error> {
    if by_id
        .get(path_id)
        .is_some_and(|existing| existing != logical_path)
        || by_path
            .get(logical_path)
            .is_some_and(|existing| existing != path_id)
    {
        return Err(invalid_integrity_state());
    }
    by_id.insert(path_id.to_owned(), logical_path.to_owned());
    by_path.insert(logical_path.to_owned(), path_id.to_owned());
    Ok(())
}

fn compare_drift(
    baseline: &[StoredEntry],
    old_observed: &[StoredEntry],
    candidate: &[StoredEntry],
    baseline_generation: u64,
    observed_generation: u64,
    observed_at: i64,
) -> (
    Vec<DriftFact>,
    BTreeSet<String>,
    BTreeMap<String, String>,
    BTreeSet<String>,
) {
    let baseline_by_id = baseline
        .iter()
        .map(|entry| (entry.path_id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let old_by_id = old_observed
        .iter()
        .map(|entry| (entry.path_id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let candidate_by_id = candidate
        .iter()
        .map(|entry| (entry.path_id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let baseline_roots = baseline
        .iter()
        .filter(|entry| entry.target_kind == TargetKind::DirectoryRoot)
        .map(|entry| entry.logical_path.as_str())
        .collect::<BTreeSet<_>>();
    let candidate_roots = candidate
        .iter()
        .filter(|entry| {
            entry.target_kind == TargetKind::DirectoryRoot
                && entry.entry_state == EntryState::Directory
                && entry.observation_error.is_none()
        })
        .map(|entry| entry.logical_path.as_str())
        .collect::<BTreeSet<_>>();
    let mut facts = BTreeMap::<String, DriftFact>::new();
    let mut untrusted = BTreeSet::new();
    let mut all_paths = BTreeMap::new();
    let mut unresolved_paths = BTreeSet::new();
    for entry in baseline.iter().chain(old_observed).chain(candidate) {
        all_paths.insert(entry.path_id.clone(), entry.logical_path.clone());
    }

    for baseline_entry in baseline {
        if let Some(observed_entry) = candidate_by_id.get(baseline_entry.path_id.as_str()) {
            if let Some(evidence) = drift_evidence(
                baseline_entry,
                observed_entry,
                baseline_generation,
                observed_generation,
                observed_at,
            ) {
                let material_changed = old_by_id
                    .get(baseline_entry.path_id.as_str())
                    .is_none_or(|old| !old.material_eq(observed_entry));
                facts.insert(
                    baseline_entry.path_id.clone(),
                    DriftFact {
                        evidence,
                        material_changed,
                    },
                );
            }
            continue;
        }
        if baseline_entry.target_kind == TargetKind::DirectoryChild
            && directory_root_for_child(&baseline_entry.logical_path)
                .is_some_and(|root| candidate_roots.contains(root))
        {
            let absent = synthetic_absent(baseline_entry);
            if let Some(evidence) = drift_evidence(
                baseline_entry,
                &absent,
                baseline_generation,
                observed_generation,
                observed_at,
            ) {
                facts.insert(
                    baseline_entry.path_id.clone(),
                    DriftFact {
                        evidence,
                        material_changed: old_by_id.contains_key(baseline_entry.path_id.as_str()),
                    },
                );
            }
        } else {
            unresolved_paths.insert(baseline_entry.path_id.clone());
        }
    }

    for observed_entry in candidate {
        if baseline_by_id.contains_key(observed_entry.path_id.as_str())
            || observed_entry.observation_error.is_some()
        {
            continue;
        }
        let trusted_new_path = match observed_entry.target_kind {
            TargetKind::DirectoryChild => directory_root_for_child(&observed_entry.logical_path)
                .is_some_and(|root| baseline_roots.contains(root)),
            TargetKind::Fixed | TargetKind::DirectoryRoot => false,
        };
        if !trusted_new_path {
            untrusted.insert(observed_entry.path_id.clone());
            continue;
        }
        let absent = synthetic_absent(observed_entry);
        if let Some(evidence) = drift_evidence(
            &absent,
            observed_entry,
            baseline_generation,
            observed_generation,
            observed_at,
        ) {
            facts.insert(
                observed_entry.path_id.clone(),
                DriftFact {
                    evidence,
                    material_changed: old_by_id
                        .get(observed_entry.path_id.as_str())
                        .is_none_or(|old| !old.material_eq(observed_entry)),
                },
            );
        }
    }
    for old_entry in old_observed {
        if old_entry.target_kind == TargetKind::DirectoryChild
            && !candidate_by_id.contains_key(old_entry.path_id.as_str())
            && !baseline_by_id.contains_key(old_entry.path_id.as_str())
            && directory_root_for_child(&old_entry.logical_path)
                .is_none_or(|root| !candidate_roots.contains(root))
        {
            unresolved_paths.insert(old_entry.path_id.clone());
        }
    }
    (
        facts.into_values().collect(),
        untrusted,
        all_paths,
        unresolved_paths,
    )
}

fn directory_root_for_child(path: &str) -> Option<&'static str> {
    DIRECTORY_ROOTS.iter().copied().find(|root| {
        path.strip_prefix(root)
            .and_then(|suffix| suffix.strip_prefix('/'))
            .is_some_and(|basename| !basename.is_empty() && !basename.contains('/'))
    })
}

fn synthetic_absent(template: &StoredEntry) -> StoredEntry {
    StoredEntry {
        path_id: template.path_id.clone(),
        logical_path: template.logical_path.clone(),
        generation: template.generation,
        target_kind: template.target_kind,
        entry_state: EntryState::Absent,
        content_digest: None,
        metadata: FileMetadata {
            size_bytes: None,
            mtime_unix_seconds: None,
            mode: None,
            uid: None,
            gid: None,
        },
        observation_error: None,
    }
}

fn drift_evidence(
    baseline: &StoredEntry,
    observed: &StoredEntry,
    baseline_generation: u64,
    observed_generation: u64,
    observed_at: i64,
) -> Option<FileSensitiveChangedEvidenceV1> {
    let mut kinds = BTreeSet::new();
    if observed.observation_error.is_some() {
        kinds.insert(FileChangeKindV1::Unreadable);
        add_owner_and_mode_changes(&mut kinds, baseline, observed);
    } else {
        let baseline_present = baseline.entry_state != EntryState::Absent;
        let observed_present = observed.entry_state != EntryState::Absent;
        if !baseline_present && observed_present {
            kinds.insert(FileChangeKindV1::Added);
        }
        if baseline_present && !observed_present {
            kinds.insert(FileChangeKindV1::Removed);
        }
        if observed_wrong_type(observed) {
            kinds.insert(FileChangeKindV1::TypeChanged);
        }
        if baseline.entry_state == EntryState::Regular
            && observed.entry_state == EntryState::Regular
            && (baseline.content_digest != observed.content_digest
                || baseline.metadata.size_bytes != observed.metadata.size_bytes)
        {
            kinds.insert(FileChangeKindV1::ContentChanged);
        }
        add_owner_and_mode_changes(&mut kinds, baseline, observed);
    }
    if kinds.is_empty() {
        return None;
    }
    Some(FileSensitiveChangedEvidenceV1 {
        path_id: observed.path_id.clone(),
        logical_path: observed.logical_path.clone(),
        change_kinds: kinds.into_iter().collect(),
        baseline_generation,
        observed_generation,
        baseline_metadata: evidence_metadata(baseline),
        observed_metadata: evidence_metadata(observed),
        observed_at,
        observation_error: observed.observation_error.map(evidence_observation_error),
    })
}

fn observed_wrong_type(entry: &StoredEntry) -> bool {
    match entry.target_kind {
        TargetKind::DirectoryRoot => entry.entry_state == EntryState::Regular,
        TargetKind::Fixed | TargetKind::DirectoryChild => {
            entry.entry_state == EntryState::Directory
        }
    }
}

fn add_owner_and_mode_changes(
    kinds: &mut BTreeSet<FileChangeKindV1>,
    baseline: &StoredEntry,
    observed: &StoredEntry,
) {
    if baseline.entry_state != EntryState::Absent && observed.entry_state != EntryState::Absent {
        if baseline.metadata.mode.is_some()
            && observed.metadata.mode.is_some()
            && baseline.metadata.mode != observed.metadata.mode
        {
            kinds.insert(FileChangeKindV1::PermissionsChanged);
        }
        if (baseline.metadata.uid.is_some()
            && observed.metadata.uid.is_some()
            && baseline.metadata.uid != observed.metadata.uid)
            || (baseline.metadata.gid.is_some()
                && observed.metadata.gid.is_some()
                && baseline.metadata.gid != observed.metadata.gid)
        {
            kinds.insert(FileChangeKindV1::OwnerChanged);
        }
    }
}

fn evidence_metadata(entry: &StoredEntry) -> FileEvidenceMetadataV1 {
    FileEvidenceMetadataV1 {
        state: match entry.entry_state {
            EntryState::Regular => FileEvidenceStateV1::Regular,
            EntryState::Directory => FileEvidenceStateV1::Directory,
            EntryState::Absent => FileEvidenceStateV1::Absent,
        },
        size_bytes: entry.metadata.size_bytes,
        mtime_unix_seconds: entry.metadata.mtime_unix_seconds,
        mode: entry.metadata.mode,
        uid: entry.metadata.uid,
        gid: entry.metadata.gid,
    }
}

fn evidence_observation_error(error: PathObservationError) -> FileObservationErrorV1 {
    match error {
        PathObservationError::PermissionDenied => FileObservationErrorV1::PermissionDenied,
        PathObservationError::Symlink => FileObservationErrorV1::Symlink,
        PathObservationError::NotRegular => FileObservationErrorV1::NotRegular,
        PathObservationError::FileTooLarge => FileObservationErrorV1::FileTooLarge,
        PathObservationError::ChangedDuringRead => FileObservationErrorV1::ChangedDuringRead,
        PathObservationError::VanishedDuringScan => FileObservationErrorV1::VanishedDuringScan,
        PathObservationError::IoError => FileObservationErrorV1::IoError,
    }
}

fn merge_untrusted_coverage(
    candidate: &Candidate,
    untrusted_count: usize,
) -> Result<(Vec<FileIntegrityCoverageErrorCountV1>, u64), sqlx::Error> {
    let mut errors = candidate
        .errors
        .iter()
        .map(|entry| (entry.code, entry.count))
        .collect::<BTreeMap<_, _>>();
    if untrusted_count != 0 {
        errors.insert(
            FileIntegrityCoverageErrorCodeV1::UntrustedNewCoverage,
            untrusted_count as u64,
        );
    }
    let errors = errors
        .into_iter()
        .map(|(code, count)| FileIntegrityCoverageErrorCountV1 { code, count })
        .collect::<Vec<_>>();
    validate_error_counts(&errors)?;
    Ok((errors, candidate.unavailable_target_count))
}

fn sole_untrusted(errors: &[FileIntegrityCoverageErrorCountV1]) -> bool {
    errors.len() == 1 && errors[0].code == FileIntegrityCoverageErrorCodeV1::UntrustedNewCoverage
}

fn trustable_observed_snapshot(rows: &[StoredEntry]) -> Result<bool, sqlx::Error> {
    if rows.is_empty() || rows.len() > MAX_TRACKED_PATHS || !unique_entries(rows) {
        return Ok(false);
    }
    for row in rows {
        validate_entry(row, true)?;
        if row.observation_error.is_some() || !expected_state(row) {
            return Ok(false);
        }
    }
    Ok(FIXED_PATHS
        .iter()
        .chain(DIRECTORY_ROOTS)
        .all(|path| rows.iter().any(|row| row.logical_path == *path))
        && REQUIRED_PATHS.iter().all(|path| {
            rows.iter().any(|row| {
                row.logical_path == *path
                    && row.entry_state == EntryState::Regular
                    && row.content_digest.is_some()
            })
        }))
}

fn independently_complete_candidate(candidate: &Candidate) -> Result<bool, sqlx::Error> {
    Ok(candidate.execution_complete
        && candidate.observation_complete
        && candidate.required_targets_observed
        && candidate.errors.is_empty()
        && candidate.unavailable_target_count == 0
        && trustable_observed_snapshot(&candidate.rows)?)
}

fn observed_manifest_matches(state: &StateRecord, observed: &[StoredEntry]) -> bool {
    state.observed_generation >= 1
        && observed
            .iter()
            .all(|entry| entry.generation == state.observed_generation)
        && canonical_manifest(ManifestKind::Observed, state.observed_generation, observed).ok()
            == state.observed_manifest
}

async fn publish_baseline_corrupt(
    transaction: &mut Transaction<'_, Sqlite>,
    state: &StateRecord,
    baseline: &[StoredEntry],
    old_observed: &[StoredEntry],
    mut candidate: Candidate,
) -> Result<(), sqlx::Error> {
    let recovery_ready = state.baseline_generation >= 1
        && candidate.execution_complete
        && candidate.observation_complete
        && candidate.errors.is_empty()
        && candidate.unavailable_target_count == 0
        && trustable_observed_snapshot(&candidate.rows)?;
    if !recovery_ready {
        return publish_degraded(
            transaction,
            state,
            &candidate,
            FileIntegrityDegradedReasonV1::BaselineCorrupt,
            candidate.errors.clone(),
        )
        .await;
    }
    let tracked_file_count = union_count(baseline, &candidate.rows)?;
    if tracked_file_count > MAX_TRACKED_PATHS as u64 {
        let errors = with_limit_error(&candidate.errors)?;
        return publish_degraded(
            transaction,
            state,
            &candidate,
            FileIntegrityDegradedReasonV1::LimitExceeded,
            errors,
        )
        .await;
    }
    if !manifest_within_budget(&candidate.rows)? {
        return publish_degraded(
            transaction,
            state,
            &candidate,
            FileIntegrityDegradedReasonV1::BaselineCorrupt,
            with_limit_error(&candidate.errors)?,
        )
        .await;
    }
    let recovery_snapshot_already_materialized = state.status == StoredStatus::Degraded
        && state.degraded_reason == Some(FileIntegrityDegradedReasonV1::BaselineCorrupt)
        && state.re_enroll_available
        && state.observation_complete;
    let snapshot_changed = !recovery_snapshot_already_materialized
        || !observed_manifest_matches(state, old_observed)
        || !rows_materially_equal(old_observed, &candidate.rows);
    let observed_generation = if snapshot_changed {
        next_revision(state.observed_generation)?
    } else {
        state.observed_generation
    };
    let mut next = state.clone();
    if snapshot_changed {
        for row in &mut candidate.rows {
            row.generation = observed_generation;
        }
        let manifest =
            canonical_manifest(ManifestKind::Observed, observed_generation, &candidate.rows)?;
        replace_observed(transaction, &candidate.rows).await?;
        next.observed_generation = observed_generation;
        next.observed_manifest = Some(manifest);
        next.observed_at = Some(candidate.observed_at);
    }
    let drift_file_count = state.drift_file_count.min(tracked_file_count);
    let state_changed = snapshot_changed
        || state.status != StoredStatus::Degraded
        || state.degraded_reason != Some(FileIntegrityDegradedReasonV1::BaselineCorrupt)
        || !state.observation_complete
        || state.trust_available
        || !state.re_enroll_available
        || state.tracked_file_count != tracked_file_count
        || state.drift_file_count != drift_file_count
        || state.unavailable_target_count != 0
        || !state.error_counts.is_empty();
    if state_changed {
        next.state_revision = next_revision(state.state_revision)?;
        next.status = StoredStatus::Degraded;
        next.degraded_reason = Some(FileIntegrityDegradedReasonV1::BaselineCorrupt);
        next.observation_complete = true;
        next.trust_available = false;
        next.re_enroll_available = true;
        next.tracked_file_count = tracked_file_count;
        next.drift_file_count = drift_file_count;
        next.unavailable_target_count = 0;
        next.error_counts.clear();
        next.last_scan_at = Some(candidate.observed_at);
        next.updated_at = candidate.observed_at;
        update_state(transaction, &next).await?;
    }
    upsert_coverage_event(transaction, &next, candidate.observed_at).await?;
    Ok(())
}

async fn publish_degraded(
    transaction: &mut Transaction<'_, Sqlite>,
    state: &StateRecord,
    candidate: &Candidate,
    reason: FileIntegrityDegradedReasonV1,
    errors: Vec<FileIntegrityCoverageErrorCountV1>,
) -> Result<(), sqlx::Error> {
    validate_error_counts(&errors)?;
    let material_changed = state.status != StoredStatus::Degraded
        || state.degraded_reason != Some(reason)
        || state.observation_complete
        || state.trust_available
        || state.re_enroll_available
        || state.unavailable_target_count != candidate.unavailable_target_count
        || state.error_counts != errors;
    let mut next = state.clone();
    if material_changed {
        next.state_revision = next_revision(state.state_revision)?;
        next.status = StoredStatus::Degraded;
        next.degraded_reason = Some(reason);
        next.observation_complete = false;
        next.trust_available = false;
        next.re_enroll_available = false;
        next.unavailable_target_count = candidate.unavailable_target_count;
        next.error_counts = errors.clone();
        next.last_scan_at = Some(candidate.observed_at);
        next.updated_at = candidate.observed_at;
        update_state(transaction, &next).await?;
    }
    upsert_coverage_event(transaction, &next, candidate.observed_at).await?;
    Ok(())
}

async fn enroll_first_baseline(
    transaction: &mut Transaction<'_, Sqlite>,
    _outbox: &NotificationOutbox,
    state: &StateRecord,
    candidate: Candidate,
) -> Result<(), sqlx::Error> {
    if state.baseline_generation != 0
        || state.observed_generation != 0
        || !candidate.execution_complete
        || !candidate.required_targets_observed
    {
        return Err(invalid_integrity_state());
    }
    let baseline_generation = 1;
    let observed_generation = 1;
    let baseline = baseline_subset(&candidate, baseline_generation);
    if !REQUIRED_PATHS
        .iter()
        .all(|path| baseline.iter().any(|entry| entry.logical_path == *path))
        || baseline.is_empty()
        || candidate.rows.is_empty()
        || candidate.rows.len() > MAX_TRACKED_PATHS
    {
        return Err(invalid_integrity_state());
    }
    for entry in &baseline {
        validate_entry(entry, false)?;
    }
    if !manifest_within_budget(&baseline)? || !manifest_within_budget(&candidate.rows)? {
        let errors = with_limit_error(&candidate.errors)?;
        return publish_degraded(
            transaction,
            state,
            &candidate,
            FileIntegrityDegradedReasonV1::LimitExceeded,
            errors,
        )
        .await;
    }
    let baseline_manifest =
        canonical_manifest(ManifestKind::Baseline, baseline_generation, &baseline)?;
    let observed_manifest =
        canonical_manifest(ManifestKind::Observed, observed_generation, &candidate.rows)?;

    sqlx::query("DELETE FROM file_integrity_baseline")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM file_integrity_observed")
        .execute(&mut **transaction)
        .await?;
    for entry in &baseline {
        insert_baseline_entry(transaction, entry).await?;
    }
    for entry in &candidate.rows {
        insert_observed_entry(transaction, entry).await?;
    }

    let healthy = candidate.observation_complete
        && candidate.errors.is_empty()
        && candidate.unavailable_target_count == 0;
    let mut next = state.clone();
    next.state_revision = next_revision(state.state_revision)?;
    next.baseline_generation = baseline_generation;
    next.observed_generation = observed_generation;
    next.status = if healthy {
        StoredStatus::Healthy
    } else {
        StoredStatus::Degraded
    };
    next.degraded_reason = (!healthy).then_some(FileIntegrityDegradedReasonV1::CoverageUnavailable);
    next.observation_complete = candidate.observation_complete;
    next.trust_available = false;
    next.re_enroll_available = false;
    next.baseline_manifest = Some(baseline_manifest);
    next.observed_manifest = Some(observed_manifest);
    next.baseline_updated_at = Some(candidate.observed_at);
    next.observed_at = Some(candidate.observed_at);
    next.last_scan_at = Some(candidate.observed_at);
    next.tracked_file_count = candidate.rows.len() as u64;
    next.drift_file_count = 0;
    next.unavailable_target_count = candidate.unavailable_target_count;
    next.error_counts = candidate.errors;
    next.updated_at = candidate.observed_at;
    update_state(transaction, &next).await?;

    if healthy {
        SecurityEventService::resolve_file_integrity_coverage_degraded_in_transaction(
            transaction,
            candidate.observed_at,
        )
        .await?;
    } else {
        upsert_coverage_event(transaction, &next, candidate.observed_at).await?;
    }
    Ok(())
}

async fn publish_post_baseline(
    transaction: &mut Transaction<'_, Sqlite>,
    outbox: &NotificationOutbox,
    state: &StateRecord,
    baseline: &[StoredEntry],
    old_observed: &[StoredEntry],
    mut candidate: Candidate,
) -> Result<(), sqlx::Error> {
    if state.baseline_generation == 0 || state.observed_generation == 0 {
        return Err(invalid_integrity_state());
    }
    if !candidate.execution_complete {
        return publish_degraded(
            transaction,
            state,
            &candidate,
            partial_reason(&candidate),
            candidate.errors.clone(),
        )
        .await;
    }
    let tracked_file_count = union_count(baseline, &candidate.rows)?;
    if tracked_file_count > MAX_TRACKED_PATHS as u64 {
        let errors = with_limit_error(&candidate.errors)?;
        return publish_degraded(
            transaction,
            state,
            &candidate,
            FileIntegrityDegradedReasonV1::LimitExceeded,
            errors,
        )
        .await;
    }
    let snapshot_changed = !rows_materially_equal(old_observed, &candidate.rows);
    if snapshot_changed && !manifest_within_budget(&candidate.rows)? {
        let errors = with_limit_error(&candidate.errors)?;
        return publish_degraded(
            transaction,
            state,
            &candidate,
            FileIntegrityDegradedReasonV1::LimitExceeded,
            errors,
        )
        .await;
    }
    let observed_generation = if snapshot_changed {
        next_revision(state.observed_generation)?
    } else {
        state.observed_generation
    };
    if snapshot_changed {
        for row in &mut candidate.rows {
            row.generation = observed_generation;
        }
    }
    let (drift, untrusted, mut all_paths, mut unresolved_paths) = compare_drift(
        baseline,
        old_observed,
        &candidate.rows,
        state.baseline_generation,
        observed_generation,
        candidate.observed_at,
    );
    let drift_ids = drift
        .iter()
        .map(|fact| fact.evidence.path_id.clone())
        .collect::<BTreeSet<_>>();
    let active_drift = load_active_drift_identities(transaction).await?;
    let candidate_by_id = candidate
        .rows
        .iter()
        .map(|row| (row.path_id.as_str(), row))
        .collect::<BTreeMap<_, _>>();
    let readable_roots = candidate
        .rows
        .iter()
        .filter(|row| {
            row.target_kind == TargetKind::DirectoryRoot
                && row.entry_state == EntryState::Directory
                && row.observation_error.is_none()
        })
        .map(|row| row.logical_path.as_str())
        .collect::<BTreeSet<_>>();
    for (path_id, logical_path) in &active_drift {
        all_paths
            .entry(path_id.clone())
            .or_insert_with(|| logical_path.clone());
        if drift_ids.contains(path_id) {
            continue;
        }
        match candidate_by_id.get(path_id.as_str()) {
            Some(row) if row.observation_error.is_some() || !expected_state(row) => {
                unresolved_paths.insert(path_id.clone());
            }
            Some(_) => {}
            None => {
                let absence_proven = directory_root_for_child(logical_path)
                    .is_some_and(|root| readable_roots.contains(root));
                if !absence_proven {
                    unresolved_paths.insert(path_id.clone());
                }
            }
        }
    }
    let unresolved_active = active_drift
        .keys()
        .filter(|path_id| unresolved_paths.contains(*path_id))
        .cloned()
        .collect::<BTreeSet<_>>();
    let tracked_file_count = union_count_with_unresolved_active(
        baseline,
        &candidate.rows,
        &active_drift,
        &unresolved_active,
    )?;
    if tracked_file_count > MAX_TRACKED_PATHS as u64 {
        let errors = with_limit_error(&candidate.errors)?;
        return publish_degraded(
            transaction,
            state,
            &candidate,
            FileIntegrityDegradedReasonV1::LimitExceeded,
            errors,
        )
        .await;
    }
    let (errors, unavailable_target_count) = merge_untrusted_coverage(&candidate, untrusted.len())?;
    let drift_file_count = drift_ids.union(&unresolved_active).count() as u64;
    if drift_file_count > tracked_file_count {
        return Err(invalid_integrity_state());
    }
    let has_coverage_gap =
        !errors.is_empty() || unavailable_target_count != 0 || !candidate.observation_complete;
    let status = if has_coverage_gap {
        StoredStatus::Degraded
    } else if drift_file_count == 0 {
        StoredStatus::Healthy
    } else {
        StoredStatus::Drift
    };
    let degraded_reason = (status == StoredStatus::Degraded)
        .then_some(FileIntegrityDegradedReasonV1::CoverageUnavailable);
    let trust_available = match status {
        StoredStatus::Drift => true,
        StoredStatus::Degraded => candidate.observation_complete && sole_untrusted(&errors),
        StoredStatus::Initializing | StoredStatus::Healthy => false,
    };
    let state_changed = snapshot_changed
        || state.status != status
        || state.degraded_reason != degraded_reason
        || state.observation_complete != candidate.observation_complete
        || state.trust_available != trust_available
        || state.re_enroll_available
        || state.tracked_file_count != tracked_file_count
        || state.drift_file_count != drift_file_count
        || state.unavailable_target_count != unavailable_target_count
        || state.error_counts != errors;

    let mut next = state.clone();
    if snapshot_changed {
        let manifest =
            canonical_manifest(ManifestKind::Observed, observed_generation, &candidate.rows)?;
        replace_observed(transaction, &candidate.rows).await?;
        next.observed_generation = observed_generation;
        next.observed_manifest = Some(manifest);
        next.observed_at = Some(candidate.observed_at);
    }
    if state_changed {
        next.state_revision = next_revision(state.state_revision)?;
        next.status = status;
        next.degraded_reason = degraded_reason;
        next.observation_complete = candidate.observation_complete;
        next.trust_available = trust_available;
        next.re_enroll_available = false;
        next.tracked_file_count = tracked_file_count;
        next.drift_file_count = drift_file_count;
        next.unavailable_target_count = unavailable_target_count;
        next.error_counts = errors;
        next.last_scan_at = Some(candidate.observed_at);
        next.updated_at = candidate.observed_at;
        update_state(transaction, &next).await?;
    }

    for fact in &drift {
        SecurityEventService::upsert_file_integrity_drift_in_transaction(
            transaction,
            outbox,
            &fact.evidence,
            FileIntegrityDriftEventText {
                title: DRIFT_TITLE,
                message: DRIFT_MESSAGE,
                notification: DRIFT_NOTIFICATION,
            },
            fact.material_changed,
            candidate.observed_at,
        )
        .await?;
    }
    for (path_id, logical_path) in all_paths {
        if drift_ids.contains(&path_id) || unresolved_paths.contains(&path_id) {
            continue;
        }
        SecurityEventService::resolve_file_integrity_drift_in_transaction(
            transaction,
            outbox,
            &path_id,
            &logical_path,
            RECOVERY_NOTIFICATION,
            candidate.observed_at,
        )
        .await?;
    }
    if status == StoredStatus::Degraded {
        upsert_coverage_event(transaction, &next, candidate.observed_at).await?;
    } else {
        SecurityEventService::resolve_file_integrity_coverage_degraded_in_transaction(
            transaction,
            candidate.observed_at,
        )
        .await?;
    }
    Ok(())
}

async fn replace_observed(
    transaction: &mut Transaction<'_, Sqlite>,
    rows: &[StoredEntry],
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM file_integrity_observed")
        .execute(&mut **transaction)
        .await?;
    for row in rows {
        insert_observed_entry(transaction, row).await?;
    }
    Ok(())
}

async fn upsert_coverage_event(
    transaction: &mut Transaction<'_, Sqlite>,
    state: &StateRecord,
    observed_at: i64,
) -> Result<FileIntegrityEventMutation, sqlx::Error> {
    let evidence = FileIntegrityCoverageDegradedEvidenceV1 {
        degraded_reason: state.degraded_reason.ok_or_else(invalid_integrity_state)?,
        state_revision: state.state_revision,
        baseline_generation: state.baseline_generation,
        observed_generation: state.observed_generation,
        observation_complete: state.observation_complete,
        observed_at,
        tracked_file_count: state.tracked_file_count,
        drift_file_count: state.drift_file_count,
        unavailable_target_count: state.unavailable_target_count,
        error_counts: state.error_counts.clone(),
    };
    SecurityEventService::upsert_file_integrity_coverage_degraded_in_transaction(
        transaction,
        &evidence,
        COVERAGE_TITLE,
        COVERAGE_MESSAGE,
        observed_at,
    )
    .await
}

async fn update_state(
    transaction: &mut Transaction<'_, Sqlite>,
    state: &StateRecord,
) -> Result<(), sqlx::Error> {
    validate_state_shape(state)?;
    let error_counts_json =
        serde_json::to_string(&state.error_counts).map_err(|_| invalid_integrity_state())?;
    if error_counts_json.len() >= 4096 {
        return Err(invalid_integrity_state());
    }
    let result = sqlx::query(
        "UPDATE file_integrity_state
         SET schema_version = ?, digest_algorithm = ?, digest_version = ?,
             manifest_version = ?, state_revision = ?, baseline_generation = ?,
             observed_generation = ?, status = ?, degraded_reason = ?,
             observation_complete = ?, trust_available = ?, re_enroll_available = ?,
             baseline_manifest = ?, observed_manifest = ?, baseline_updated_at = ?,
             observed_at = ?, last_scan_at = ?, tracked_file_count = ?,
             drift_file_count = ?, unavailable_target_count = ?,
             error_counts_json = ?, updated_at = ?
         WHERE id = 1",
    )
    .bind(to_i64(state.schema_version)?)
    .bind(&state.digest_algorithm)
    .bind(to_i64(state.digest_version)?)
    .bind(to_i64(state.manifest_version)?)
    .bind(to_i64(state.state_revision)?)
    .bind(to_i64(state.baseline_generation)?)
    .bind(to_i64(state.observed_generation)?)
    .bind(state.status.code())
    .bind(state.degraded_reason.map(degraded_reason_code))
    .bind(i64::from(state.observation_complete))
    .bind(i64::from(state.trust_available))
    .bind(i64::from(state.re_enroll_available))
    .bind(state.baseline_manifest.map(|value| value.to_vec()))
    .bind(state.observed_manifest.map(|value| value.to_vec()))
    .bind(state.baseline_updated_at)
    .bind(state.observed_at)
    .bind(state.last_scan_at)
    .bind(to_i64(state.tracked_file_count)?)
    .bind(to_i64(state.drift_file_count)?)
    .bind(to_i64(state.unavailable_target_count)?)
    .bind(error_counts_json)
    .bind(state.updated_at)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(invalid_integrity_state());
    }
    Ok(())
}

async fn insert_baseline_entry(
    transaction: &mut Transaction<'_, Sqlite>,
    entry: &StoredEntry,
) -> Result<(), sqlx::Error> {
    validate_entry(entry, false)?;
    sqlx::query(
        "INSERT INTO file_integrity_baseline (
            path_id, logical_path, generation, target_kind, entry_state,
            content_digest, size_bytes, mtime_unix_seconds, mode, uid, gid
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&entry.path_id)
    .bind(&entry.logical_path)
    .bind(to_i64(entry.generation)?)
    .bind(entry.target_kind.code())
    .bind(entry.entry_state.code())
    .bind(entry.content_digest.map(|value| value.to_vec()))
    .bind(optional_i64(entry.metadata.size_bytes)?)
    .bind(entry.metadata.mtime_unix_seconds)
    .bind(entry.metadata.mode.map(i64::from))
    .bind(entry.metadata.uid.map(i64::from))
    .bind(entry.metadata.gid.map(i64::from))
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_observed_entry(
    transaction: &mut Transaction<'_, Sqlite>,
    entry: &StoredEntry,
) -> Result<(), sqlx::Error> {
    validate_entry(entry, true)?;
    sqlx::query(
        "INSERT INTO file_integrity_observed (
            path_id, logical_path, generation, target_kind, entry_state,
            content_digest, size_bytes, mtime_unix_seconds, mode, uid, gid,
            observation_error
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&entry.path_id)
    .bind(&entry.logical_path)
    .bind(to_i64(entry.generation)?)
    .bind(entry.target_kind.code())
    .bind(entry.entry_state.code())
    .bind(entry.content_digest.map(|value| value.to_vec()))
    .bind(optional_i64(entry.metadata.size_bytes)?)
    .bind(entry.metadata.mtime_unix_seconds)
    .bind(entry.metadata.mode.map(i64::from))
    .bind(entry.metadata.uid.map(i64::from))
    .bind(entry.metadata.gid.map(i64::from))
    .bind(entry.observation_error.map(PathObservationError::code))
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn next_revision(value: u64) -> Result<u64, sqlx::Error> {
    value
        .checked_add(1)
        .filter(|value| *value <= JS_MAX_SAFE_INTEGER)
        .ok_or_else(invalid_integrity_state)
}

fn to_i64(value: u64) -> Result<i64, sqlx::Error> {
    i64::try_from(value)
        .ok()
        .filter(|_| value <= JS_MAX_SAFE_INTEGER)
        .ok_or_else(invalid_integrity_state)
}

fn optional_i64(value: Option<u64>) -> Result<Option<i64>, sqlx::Error> {
    value.map(to_i64).transpose()
}

pub(super) async fn publish_scan(
    storage: &FileIntegrityStorage,
    result: ScanResult,
) -> Result<(), sqlx::Error> {
    publish_scan_inner(&storage.db, &storage.outbox, result).await
}

pub(super) async fn validated_status(
    storage: &FileIntegrityStorage,
) -> Result<FileIntegrityStatus, sqlx::Error> {
    let mut transaction = storage.db.begin().await?;
    let state = load_state(&mut transaction).await?;
    let baseline = load_baseline(&mut transaction).await?;
    let observed = load_observed(&mut transaction).await?;
    let integrity = validate_persisted(&state, &baseline, &observed)?;
    transaction.rollback().await?;
    Ok(match integrity {
        PersistedIntegrity::Valid if generation_exhausted(&state) => {
            synthetic_degraded_status(&state, FileIntegrityDegradedReasonV1::InternalError, false)
        }
        PersistedIntegrity::Valid => state_status(&state),
        PersistedIntegrity::UnsupportedAlgorithm => synthetic_degraded_status(
            &state,
            FileIntegrityDegradedReasonV1::UnsupportedAlgorithm,
            false,
        ),
        PersistedIntegrity::BaselineCorrupt => {
            let recovery_ready = state.status == StoredStatus::Degraded
                && state.degraded_reason == Some(FileIntegrityDegradedReasonV1::BaselineCorrupt)
                && state.re_enroll_available
                && state.observation_complete
                && state.unavailable_target_count == 0
                && state.error_counts.is_empty()
                && observed_manifest_matches(&state, &observed)
                && trustable_observed_snapshot(&observed)?;
            synthetic_degraded_status(
                &state,
                FileIntegrityDegradedReasonV1::BaselineCorrupt,
                recovery_ready,
            )
        }
        PersistedIntegrity::InternalCorrupt => {
            synthetic_degraded_status(&state, FileIntegrityDegradedReasonV1::InternalError, false)
        }
    })
}

pub(super) async fn trust_current_state(
    storage: &FileIntegrityStorage,
    request: TrustCurrentStateRequest,
) -> Result<TrustCurrentStateResponse, FileIntegrityOperationError> {
    trust_current_state_inner(&storage.db, &storage.outbox, request).await
}

pub(super) async fn re_enroll(
    storage: &FileIntegrityStorage,
    request: ReEnrollRequest,
) -> Result<ReEnrollResponse, FileIntegrityOperationError> {
    re_enroll_inner(&storage.db, &storage.outbox, request).await
}

async fn publish_scan_inner(
    db: &SqlitePool,
    outbox: &NotificationOutbox,
    result: ScanResult,
) -> Result<(), sqlx::Error> {
    let fallback_observed_at = result.observed_at.clamp(0, MAX_TIMESTAMP);
    let mut transaction = db.begin_with("BEGIN IMMEDIATE").await?;
    let state = load_state(&mut transaction).await?;
    let baseline = load_baseline(&mut transaction).await?;
    let observed = load_observed(&mut transaction).await?;
    let persisted = validate_persisted(&state, &baseline, &observed)?;
    let candidate_generation = state
        .observed_generation
        .checked_add(1)
        .filter(|generation| *generation <= JS_MAX_SAFE_INTEGER)
        .unwrap_or_else(|| state.observed_generation.max(1));
    let candidate =
        normalize_scan_result(result, candidate_generation).unwrap_or_else(|_| Candidate {
            rows: Vec::new(),
            errors: vec![FileIntegrityCoverageErrorCountV1 {
                code: FileIntegrityCoverageErrorCodeV1::IoError,
                count: 1,
            }],
            unavailable_target_count: 1,
            execution_complete: false,
            observation_complete: false,
            required_targets_observed: false,
            observed_at: fallback_observed_at,
            terminal_reason: Some(ScanTerminalReason::InternalError),
        });
    match persisted {
        PersistedIntegrity::Valid => {}
        PersistedIntegrity::UnsupportedAlgorithm => {
            publish_degraded(
                &mut transaction,
                &state,
                &candidate,
                FileIntegrityDegradedReasonV1::UnsupportedAlgorithm,
                candidate.errors.clone(),
            )
            .await?;
            transaction.commit().await?;
            return Ok(());
        }
        PersistedIntegrity::BaselineCorrupt => {
            publish_baseline_corrupt(&mut transaction, &state, &baseline, &observed, candidate)
                .await?;
            transaction.commit().await?;
            return Ok(());
        }
        PersistedIntegrity::InternalCorrupt if independently_complete_candidate(&candidate)? => {
            // A fresh complete scan is independent evidence for replacing only
            // the corrupt observed snapshot. The trusted baseline remains the
            // comparison source and is never advanced by this recovery path.
            publish_post_baseline(&mut transaction, outbox, &state, &baseline, &[], candidate)
                .await?;
            transaction.commit().await?;
            return Ok(());
        }
        PersistedIntegrity::InternalCorrupt => {
            publish_degraded(
                &mut transaction,
                &state,
                &candidate,
                FileIntegrityDegradedReasonV1::InternalError,
                candidate.errors.clone(),
            )
            .await?;
            transaction.commit().await?;
            return Ok(());
        }
    }

    if generation_exhausted(&state) {
        let errors = with_internal_error(&candidate.errors)?;
        publish_degraded(
            &mut transaction,
            &state,
            &candidate,
            FileIntegrityDegradedReasonV1::InternalError,
            errors,
        )
        .await?;
        transaction.commit().await?;
        return Ok(());
    }

    if state.baseline_generation != 0 {
        publish_post_baseline(
            &mut transaction,
            outbox,
            &state,
            &baseline,
            &observed,
            candidate,
        )
        .await?;
        return transaction.commit().await;
    }

    if !candidate.execution_complete || !candidate.required_targets_observed {
        let errors = if candidate.execution_complete && !candidate.required_targets_observed {
            with_no_observable_targets(&candidate.errors)?
        } else {
            candidate.errors.clone()
        };
        let reason = partial_reason(&candidate);
        publish_degraded(&mut transaction, &state, &candidate, reason, errors).await?;
        transaction.commit().await?;
        return Ok(());
    }

    enroll_first_baseline(&mut transaction, outbox, &state, candidate).await?;
    transaction.commit().await
}

async fn trust_current_state_inner(
    db: &SqlitePool,
    outbox: &NotificationOutbox,
    request: TrustCurrentStateRequest,
) -> Result<TrustCurrentStateResponse, FileIntegrityOperationError> {
    trust_current_state_at(db, outbox, request, chrono::Utc::now().timestamp()).await
}

async fn re_enroll_inner(
    db: &SqlitePool,
    outbox: &NotificationOutbox,
    request: ReEnrollRequest,
) -> Result<ReEnrollResponse, FileIntegrityOperationError> {
    re_enroll_at(db, outbox, request, chrono::Utc::now().timestamp()).await
}

async fn trust_current_state_at(
    db: &SqlitePool,
    outbox: &NotificationOutbox,
    request: TrustCurrentStateRequest,
    now: i64,
) -> Result<TrustCurrentStateResponse, FileIntegrityOperationError> {
    if request.confirmation != "trust_current_state"
        || request.expected_baseline_generation == 0
        || request.expected_baseline_generation > JS_MAX_SAFE_INTEGER
        || request.expected_observed_generation == 0
        || request.expected_observed_generation > JS_MAX_SAFE_INTEGER
        || !(0..=MAX_TIMESTAMP).contains(&now)
    {
        return Err(FileIntegrityOperationError::invalid_request());
    }
    let mut transaction = db
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| internal_operation_error(None))?;
    let state = load_state(&mut transaction)
        .await
        .map_err(|_| internal_operation_error(None))?;
    if !versions_supported(&state) {
        return Err(operation_error(
            FileIntegrityOperationErrorCode::UnsupportedAlgorithm,
            &state,
        ));
    }
    if state.baseline_generation == 0 {
        return Err(operation_error(
            FileIntegrityOperationErrorCode::NotInitialized,
            &state,
        ));
    }
    if request.expected_baseline_generation != state.baseline_generation
        || request.expected_observed_generation != state.observed_generation
    {
        return Err(operation_error(
            FileIntegrityOperationErrorCode::StaleGeneration,
            &state,
        ));
    }
    let baseline = load_baseline(&mut transaction)
        .await
        .map_err(|_| internal_operation_error(Some(&state)))?;
    let observed = load_observed(&mut transaction)
        .await
        .map_err(|_| internal_operation_error(Some(&state)))?;
    match validate_persisted(&state, &baseline, &observed)
        .map_err(|_| internal_operation_error(Some(&state)))?
    {
        PersistedIntegrity::Valid => {}
        PersistedIntegrity::UnsupportedAlgorithm => {
            return Err(operation_error(
                FileIntegrityOperationErrorCode::UnsupportedAlgorithm,
                &state,
            ));
        }
        PersistedIntegrity::BaselineCorrupt | PersistedIntegrity::InternalCorrupt => {
            return Err(operation_error(
                FileIntegrityOperationErrorCode::ObservationNotTrustable,
                &state,
            ));
        }
    }
    let full_drift = state.status == StoredStatus::Drift
        && state.observation_complete
        && state.unavailable_target_count == 0
        && state.error_counts.is_empty()
        && state.drift_file_count > 0;
    let sole_untrusted_coverage = state.status == StoredStatus::Degraded
        && state.degraded_reason == Some(FileIntegrityDegradedReasonV1::CoverageUnavailable)
        && state.observation_complete
        && state.unavailable_target_count == 0
        && sole_untrusted(&state.error_counts);
    if state.status == StoredStatus::Healthy {
        return Err(operation_error(
            FileIntegrityOperationErrorCode::NoDrift,
            &state,
        ));
    }
    if !state.trust_available
        || state.re_enroll_available
        || (!full_drift && !sole_untrusted_coverage)
        || !trustable_observed_snapshot(&observed)
            .map_err(|_| internal_operation_error(Some(&state)))?
        || !observed_manifest_matches(&state, &observed)
    {
        return Err(operation_error(
            FileIntegrityOperationErrorCode::ObservationNotTrustable,
            &state,
        ));
    }
    if operation_generation_exhausted(&state) {
        return Err(exhausted_operation_error(&state));
    }
    let new_baseline_generation = next_revision(state.baseline_generation)
        .map_err(|_| internal_operation_error(Some(&state)))?;
    let new_state_revision =
        next_revision(state.state_revision).map_err(|_| internal_operation_error(Some(&state)))?;
    let new_baseline = baseline_from_observed(&observed, new_baseline_generation)
        .map_err(|_| internal_operation_error(Some(&state)))?;
    if !manifest_within_budget(&new_baseline).map_err(|_| internal_operation_error(Some(&state)))? {
        return Err(operation_error(
            FileIntegrityOperationErrorCode::ObservationNotTrustable,
            &state,
        ));
    }
    let new_baseline_manifest = canonical_manifest(
        ManifestKind::Baseline,
        new_baseline_generation,
        &new_baseline,
    )
    .map_err(|_| internal_operation_error(Some(&state)))?;
    if !cas_trust_state(&mut transaction, &state, &request)
        .await
        .map_err(|_| internal_operation_error(Some(&state)))?
    {
        return Err(operation_error(
            FileIntegrityOperationErrorCode::StaleGeneration,
            &state,
        ));
    }
    replace_baseline(&mut transaction, &new_baseline)
        .await
        .map_err(|_| internal_operation_error(Some(&state)))?;
    let resolved_event_count = resolve_integrity_events(&mut transaction, outbox, now)
        .await
        .map_err(|_| internal_operation_error(Some(&state)))?;
    let mut next = state.clone();
    next.state_revision = new_state_revision;
    next.baseline_generation = new_baseline_generation;
    next.status = StoredStatus::Healthy;
    next.degraded_reason = None;
    next.observation_complete = true;
    next.trust_available = false;
    next.re_enroll_available = false;
    next.baseline_manifest = Some(new_baseline_manifest);
    next.baseline_updated_at = Some(now);
    next.tracked_file_count = observed.len() as u64;
    next.drift_file_count = 0;
    next.unavailable_target_count = 0;
    next.error_counts.clear();
    next.updated_at = now;
    update_state(&mut transaction, &next)
        .await
        .map_err(|_| internal_operation_error(Some(&state)))?;
    transaction
        .commit()
        .await
        .map_err(|_| internal_operation_error(Some(&state)))?;
    Ok(TrustCurrentStateResponse {
        result: "trusted",
        status: FileIntegrityStatusKind::Healthy,
        state_revision: new_state_revision,
        baseline_generation: new_baseline_generation,
        observed_generation: state.observed_generation,
        trusted_at: now,
        resolved_event_count,
    })
}

async fn re_enroll_at(
    db: &SqlitePool,
    outbox: &NotificationOutbox,
    request: ReEnrollRequest,
    now: i64,
) -> Result<ReEnrollResponse, FileIntegrityOperationError> {
    if request.confirmation != "re_enroll_from_current_observation"
        || request.expected_state_revision > JS_MAX_SAFE_INTEGER
        || request.expected_observed_generation == 0
        || request.expected_observed_generation > JS_MAX_SAFE_INTEGER
        || !(0..=MAX_TIMESTAMP).contains(&now)
    {
        return Err(FileIntegrityOperationError::invalid_request());
    }
    let mut transaction = db
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| internal_operation_error(None))?;
    let state = load_state(&mut transaction)
        .await
        .map_err(|_| internal_operation_error(None))?;
    if !versions_supported(&state) {
        return Err(operation_error(
            FileIntegrityOperationErrorCode::UnsupportedAlgorithm,
            &state,
        ));
    }
    if request.expected_state_revision != state.state_revision
        || request.expected_observed_generation != state.observed_generation
    {
        return Err(operation_error(
            FileIntegrityOperationErrorCode::StaleGeneration,
            &state,
        ));
    }
    let baseline = load_baseline(&mut transaction)
        .await
        .map_err(|_| internal_operation_error(Some(&state)))?;
    let observed = load_observed(&mut transaction)
        .await
        .map_err(|_| internal_operation_error(Some(&state)))?;
    let persisted = validate_persisted(&state, &baseline, &observed)
        .map_err(|_| internal_operation_error(Some(&state)))?;
    if persisted == PersistedIntegrity::UnsupportedAlgorithm {
        return Err(operation_error(
            FileIntegrityOperationErrorCode::UnsupportedAlgorithm,
            &state,
        ));
    }
    if persisted != PersistedIntegrity::BaselineCorrupt
        || state.status != StoredStatus::Degraded
        || state.degraded_reason != Some(FileIntegrityDegradedReasonV1::BaselineCorrupt)
        || !state.re_enroll_available
    {
        return Err(operation_error(
            FileIntegrityOperationErrorCode::RecoveryNotRequired,
            &state,
        ));
    }
    if !state.observation_complete
        || state.trust_available
        || state.unavailable_target_count != 0
        || !state.error_counts.is_empty()
        || !trustable_observed_snapshot(&observed)
            .map_err(|_| internal_operation_error(Some(&state)))?
        || !observed_manifest_matches(&state, &observed)
    {
        return Err(operation_error(
            FileIntegrityOperationErrorCode::ObservationNotTrustable,
            &state,
        ));
    }
    if operation_generation_exhausted(&state) {
        return Err(exhausted_operation_error(&state));
    }
    let new_baseline_generation = next_revision(state.baseline_generation)
        .map_err(|_| internal_operation_error(Some(&state)))?;
    let new_state_revision =
        next_revision(state.state_revision).map_err(|_| internal_operation_error(Some(&state)))?;
    let new_baseline = baseline_from_observed(&observed, new_baseline_generation)
        .map_err(|_| internal_operation_error(Some(&state)))?;
    if !manifest_within_budget(&new_baseline).map_err(|_| internal_operation_error(Some(&state)))? {
        return Err(operation_error(
            FileIntegrityOperationErrorCode::ObservationNotTrustable,
            &state,
        ));
    }
    let new_baseline_manifest = canonical_manifest(
        ManifestKind::Baseline,
        new_baseline_generation,
        &new_baseline,
    )
    .map_err(|_| internal_operation_error(Some(&state)))?;
    if !cas_re_enroll_state(&mut transaction, &state, &request)
        .await
        .map_err(|_| internal_operation_error(Some(&state)))?
    {
        return Err(operation_error(
            FileIntegrityOperationErrorCode::StaleGeneration,
            &state,
        ));
    }
    replace_baseline(&mut transaction, &new_baseline)
        .await
        .map_err(|_| internal_operation_error(Some(&state)))?;
    let resolved_event_count = resolve_integrity_events(&mut transaction, outbox, now)
        .await
        .map_err(|_| internal_operation_error(Some(&state)))?;
    SecurityEventService::insert_file_integrity_baseline_reenrolled_in_transaction(
        &mut transaction,
        &FileIntegrityBaselineReenrolledEvidenceV1 {
            reason: FileIntegrityReenrollReasonV1::BaselineCorrupt,
            old_baseline_generation: state.baseline_generation,
            new_baseline_generation,
            state_revision: new_state_revision,
            observed_generation: state.observed_generation,
            reenrolled_at: now,
        },
        REENROLL_TITLE,
        REENROLL_MESSAGE,
    )
    .await
    .map_err(|_| internal_operation_error(Some(&state)))?;
    let mut next = state.clone();
    next.state_revision = new_state_revision;
    next.baseline_generation = new_baseline_generation;
    next.status = StoredStatus::Healthy;
    next.degraded_reason = None;
    next.observation_complete = true;
    next.trust_available = false;
    next.re_enroll_available = false;
    next.baseline_manifest = Some(new_baseline_manifest);
    next.baseline_updated_at = Some(now);
    next.tracked_file_count = observed.len() as u64;
    next.drift_file_count = 0;
    next.unavailable_target_count = 0;
    next.error_counts.clear();
    next.updated_at = now;
    update_state(&mut transaction, &next)
        .await
        .map_err(|_| internal_operation_error(Some(&state)))?;
    transaction
        .commit()
        .await
        .map_err(|_| internal_operation_error(Some(&state)))?;
    Ok(ReEnrollResponse {
        result: "reenrolled",
        status: FileIntegrityStatusKind::Healthy,
        state_revision: new_state_revision,
        baseline_generation: new_baseline_generation,
        observed_generation: state.observed_generation,
        reenrolled_at: now,
        resolved_event_count,
    })
}

fn versions_supported(state: &StateRecord) -> bool {
    state.schema_version == SCHEMA_VERSION
        && state.digest_algorithm == DIGEST_ALGORITHM
        && state.digest_version == DIGEST_VERSION
        && state.manifest_version == MANIFEST_VERSION
}

fn generation_exhausted(state: &StateRecord) -> bool {
    state.state_revision == JS_MAX_SAFE_INTEGER
        || state.baseline_generation == JS_MAX_SAFE_INTEGER
        || state.observed_generation == JS_MAX_SAFE_INTEGER
}

fn operation_generation_exhausted(state: &StateRecord) -> bool {
    state.state_revision >= JS_MAX_SAFE_INTEGER - 1
        || state.baseline_generation >= JS_MAX_SAFE_INTEGER - 1
        || state.observed_generation == JS_MAX_SAFE_INTEGER
}

fn baseline_from_observed(
    observed: &[StoredEntry],
    generation: u64,
) -> Result<Vec<StoredEntry>, sqlx::Error> {
    if !trustable_observed_snapshot(observed)? {
        return Err(invalid_integrity_state());
    }
    let mut baseline = observed
        .iter()
        .map(|entry| entry.for_generation(generation))
        .collect::<Vec<_>>();
    baseline.sort_by(|left, right| left.path_id.cmp(&right.path_id));
    for entry in &baseline {
        validate_entry(entry, false)?;
    }
    Ok(baseline)
}

async fn replace_baseline(
    transaction: &mut Transaction<'_, Sqlite>,
    rows: &[StoredEntry],
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM file_integrity_baseline")
        .execute(&mut **transaction)
        .await?;
    for row in rows {
        insert_baseline_entry(transaction, row).await?;
    }
    Ok(())
}

async fn cas_trust_state(
    transaction: &mut Transaction<'_, Sqlite>,
    state: &StateRecord,
    request: &TrustCurrentStateRequest,
) -> Result<bool, sqlx::Error> {
    if operation_generation_exhausted(state) {
        return Err(invalid_integrity_state());
    }
    let result = sqlx::query(
        "UPDATE file_integrity_state SET updated_at = updated_at
         WHERE id = 1 AND state_revision = ? AND baseline_generation = ?
           AND observed_generation = ? AND trust_available = 1
           AND observation_complete = 1 AND re_enroll_available = 0
           AND state_revision < ? AND baseline_generation < ?
           AND observed_generation < ?",
    )
    .bind(to_i64(state.state_revision)?)
    .bind(to_i64(request.expected_baseline_generation)?)
    .bind(to_i64(request.expected_observed_generation)?)
    .bind(to_i64(JS_MAX_SAFE_INTEGER - 1)?)
    .bind(to_i64(JS_MAX_SAFE_INTEGER - 1)?)
    .bind(to_i64(JS_MAX_SAFE_INTEGER)?)
    .execute(&mut **transaction)
    .await?;
    Ok(result.rows_affected() == 1)
}

async fn cas_re_enroll_state(
    transaction: &mut Transaction<'_, Sqlite>,
    state: &StateRecord,
    request: &ReEnrollRequest,
) -> Result<bool, sqlx::Error> {
    if operation_generation_exhausted(state) {
        return Err(invalid_integrity_state());
    }
    let result = sqlx::query(
        "UPDATE file_integrity_state SET updated_at = updated_at
         WHERE id = 1 AND state_revision = ? AND observed_generation = ?
           AND status = 'degraded' AND degraded_reason = 'baseline_corrupt'
           AND observation_complete = 1 AND re_enroll_available = 1
           AND trust_available = 0 AND state_revision < ?
           AND baseline_generation < ? AND observed_generation < ?",
    )
    .bind(to_i64(request.expected_state_revision)?)
    .bind(to_i64(request.expected_observed_generation)?)
    .bind(to_i64(JS_MAX_SAFE_INTEGER - 1)?)
    .bind(to_i64(JS_MAX_SAFE_INTEGER - 1)?)
    .bind(to_i64(JS_MAX_SAFE_INTEGER)?)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() == 1 && request.expected_state_revision == state.state_revision {
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn resolve_integrity_events(
    transaction: &mut Transaction<'_, Sqlite>,
    outbox: &NotificationOutbox,
    now: i64,
) -> Result<u64, sqlx::Error> {
    let active = load_active_drift_identities(transaction).await?;
    let mut resolved = 0_u64;
    for (path_id, logical_path) in active {
        if SecurityEventService::resolve_file_integrity_drift_in_transaction(
            transaction,
            outbox,
            &path_id,
            &logical_path,
            RECOVERY_NOTIFICATION,
            now,
        )
        .await?
            == FileIntegrityEventMutation::Resolved
        {
            resolved += 1;
        }
    }
    if SecurityEventService::resolve_file_integrity_coverage_degraded_in_transaction(
        transaction,
        now,
    )
    .await?
        == FileIntegrityEventMutation::Resolved
    {
        resolved += 1;
    }
    if resolved > 257 {
        return Err(invalid_integrity_state());
    }
    Ok(resolved)
}

async fn load_active_drift_identities(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<BTreeMap<String, String>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT event_key, evidence_json FROM security_events
         WHERE event_type = 'file.sensitive_changed'
           AND status IN ('open', 'acknowledged')
         ORDER BY event_key LIMIT 257",
    )
    .fetch_all(&mut **transaction)
    .await?;
    if rows.len() > MAX_TRACKED_PATHS {
        return Err(invalid_integrity_state());
    }
    let mut identities = BTreeMap::new();
    for row in rows {
        let event_key: String = row.try_get("event_key")?;
        let evidence: FileSensitiveChangedEvidenceV1 =
            serde_json::from_str(&row.try_get::<String, _>("evidence_json")?)
                .map_err(|_| invalid_integrity_state())?;
        if event_key != format!("file:sensitive_changed:{}", evidence.path_id)
            || file_integrity_path_id(&evidence.logical_path).as_deref()
                != Some(evidence.path_id.as_str())
            || identities
                .insert(evidence.path_id.clone(), evidence.logical_path.clone())
                .is_some()
        {
            return Err(invalid_integrity_state());
        }
    }
    Ok(identities)
}

fn operation_error(
    code: FileIntegrityOperationErrorCode,
    state: &StateRecord,
) -> FileIntegrityOperationError {
    FileIntegrityOperationError::with_status(code, state_status(state))
}

fn internal_operation_error(state: Option<&StateRecord>) -> FileIntegrityOperationError {
    match state {
        Some(state) => operation_error(FileIntegrityOperationErrorCode::InternalError, state),
        None => FileIntegrityOperationError {
            code: FileIntegrityOperationErrorCode::InternalError,
            context: None,
        },
    }
}

fn exhausted_operation_error(state: &StateRecord) -> FileIntegrityOperationError {
    FileIntegrityOperationError::with_status(
        FileIntegrityOperationErrorCode::InternalError,
        synthetic_degraded_status(state, FileIntegrityDegradedReasonV1::InternalError, false),
    )
}

fn state_status(state: &StateRecord) -> FileIntegrityStatus {
    let coverage_status = match state.status {
        StoredStatus::Initializing => FileIntegrityCoverageStatus::Initializing,
        StoredStatus::Healthy | StoredStatus::Drift => FileIntegrityCoverageStatus::Full,
        StoredStatus::Degraded
            if state.unavailable_target_count == 0 && state.error_counts.is_empty() =>
        {
            FileIntegrityCoverageStatus::Full
        }
        StoredStatus::Degraded => FileIntegrityCoverageStatus::Degraded,
    };
    FileIntegrityStatus {
        schema_version: SCHEMA_VERSION,
        status: match state.status {
            StoredStatus::Initializing => FileIntegrityStatusKind::Initializing,
            StoredStatus::Healthy => FileIntegrityStatusKind::Healthy,
            StoredStatus::Drift => FileIntegrityStatusKind::Drift,
            StoredStatus::Degraded => FileIntegrityStatusKind::Degraded,
        },
        state_revision: Some(state.state_revision),
        baseline_generation: Some(state.baseline_generation),
        observed_generation: Some(state.observed_generation),
        observation_complete: state.observation_complete,
        trust_available: state.trust_available,
        re_enroll_available: state.re_enroll_available,
        degraded_reason: state.degraded_reason,
        last_scan_at: state.last_scan_at,
        tracked_file_count: state.tracked_file_count,
        drift_file_count: state.drift_file_count,
        coverage: FileIntegrityCoverage {
            status: coverage_status,
            unavailable_target_count: state.unavailable_target_count,
            error_counts: state.error_counts.clone(),
        },
    }
}

fn synthetic_degraded_status(
    state: &StateRecord,
    reason: FileIntegrityDegradedReasonV1,
    re_enroll_available: bool,
) -> FileIntegrityStatus {
    let mut status = state_status(state);
    status.status = FileIntegrityStatusKind::Degraded;
    status.observation_complete = re_enroll_available;
    status.trust_available = false;
    status.re_enroll_available = re_enroll_available;
    status.degraded_reason = Some(reason);
    status.last_scan_at = Some(state.last_scan_at.unwrap_or(state.updated_at));
    status.coverage.status = if re_enroll_available
        && status.coverage.unavailable_target_count == 0
        && status.coverage.error_counts.is_empty()
    {
        FileIntegrityCoverageStatus::Full
    } else {
        FileIntegrityCoverageStatus::Degraded
    };
    status
}

#[cfg(test)]
mod tests {
    use super::super::collector::ScanErrorCount;
    use super::*;
    use crate::notifications::NotificationService;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::Arc;

    const NOW: i64 = 1_700_000_000;

    async fn test_context() -> (SqlitePool, NotificationOutbox) {
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connect state-machine test database");
        super::super::schema::initialize(&db)
            .await
            .expect("initialize integrity schema");
        SecurityEventService::init_schema(&db)
            .await
            .expect("initialize event schema");
        let outbox = NotificationOutbox::new(
            db.clone(),
            Arc::new(NotificationService::disabled_for_tests()),
        );
        (db, outbox)
    }

    fn absent(path: &str, target_kind: TargetKind) -> ObservedEntry {
        ObservedEntry {
            path_id: file_integrity_path_id(path).expect("allowlisted fixture path"),
            logical_path: path.to_owned(),
            target_kind,
            entry_state: EntryState::Absent,
            content_digest: None,
            metadata: FileMetadata {
                size_bytes: None,
                mtime_unix_seconds: None,
                mode: None,
                uid: None,
                gid: None,
            },
            observation_error: None,
        }
    }

    fn regular(path: &str, content: &[u8]) -> ObservedEntry {
        regular_target(path, TargetKind::Fixed, content)
    }

    fn regular_target(path: &str, target_kind: TargetKind, content: &[u8]) -> ObservedEntry {
        ObservedEntry {
            path_id: file_integrity_path_id(path).expect("allowlisted fixture path"),
            logical_path: path.to_owned(),
            target_kind,
            entry_state: EntryState::Regular,
            content_digest: Some(Sha256::digest(content).into()),
            metadata: FileMetadata {
                size_bytes: Some(content.len() as u64),
                mtime_unix_seconds: Some(NOW - 1),
                mode: Some(0o644),
                uid: Some(0),
                gid: Some(0),
            },
            observation_error: None,
        }
    }

    fn directory(path: &str, target_kind: TargetKind) -> ObservedEntry {
        ObservedEntry {
            path_id: file_integrity_path_id(path).expect("allowlisted fixture path"),
            logical_path: path.to_owned(),
            target_kind,
            entry_state: EntryState::Directory,
            content_digest: None,
            metadata: FileMetadata {
                size_bytes: None,
                mtime_unix_seconds: None,
                mode: Some(0o755),
                uid: Some(0),
                gid: Some(0),
            },
            observation_error: None,
        }
    }

    fn unavailable(path: &str, error: PathObservationError) -> ObservedEntry {
        let target_kind = expected_target_kind(path).expect("allowlisted fixture target");
        ObservedEntry {
            path_id: file_integrity_path_id(path).expect("allowlisted fixture path"),
            logical_path: path.to_owned(),
            target_kind,
            entry_state: EntryState::Absent,
            content_digest: None,
            metadata: FileMetadata {
                size_bytes: None,
                mtime_unix_seconds: None,
                mode: None,
                uid: None,
                gid: None,
            },
            observation_error: Some(error),
        }
    }

    fn replace_row(scan: &mut ScanResult, logical_path: &str, replacement: ObservedEntry) {
        let row = scan
            .rows
            .iter_mut()
            .find(|row| row.logical_path == logical_path)
            .expect("replace existing fixture row");
        *row = replacement;
    }

    fn remove_row(scan: &mut ScanResult, logical_path: &str) {
        let before = scan.rows.len();
        scan.rows.retain(|row| row.logical_path != logical_path);
        assert_eq!(scan.rows.len() + 1, before, "remove fixture row");
    }

    fn scan_error(error: ScanError, count: u16) -> ScanErrorCount {
        ScanErrorCount { error, count }
    }

    async fn install_write_probe(db: &SqlitePool) {
        sqlx::query("CREATE TABLE state_machine_write_probe (writes INTEGER NOT NULL)")
            .execute(db)
            .await
            .expect("create write probe");
        sqlx::query("INSERT INTO state_machine_write_probe VALUES (0)")
            .execute(db)
            .await
            .expect("initialize write probe");
        for statement in [
            "CREATE TRIGGER probe_state_update AFTER UPDATE ON file_integrity_state BEGIN UPDATE state_machine_write_probe SET writes = writes + 1; END",
            "CREATE TRIGGER probe_baseline_insert AFTER INSERT ON file_integrity_baseline BEGIN UPDATE state_machine_write_probe SET writes = writes + 1; END",
            "CREATE TRIGGER probe_baseline_update AFTER UPDATE ON file_integrity_baseline BEGIN UPDATE state_machine_write_probe SET writes = writes + 1; END",
            "CREATE TRIGGER probe_baseline_delete AFTER DELETE ON file_integrity_baseline BEGIN UPDATE state_machine_write_probe SET writes = writes + 1; END",
            "CREATE TRIGGER probe_observed_insert AFTER INSERT ON file_integrity_observed BEGIN UPDATE state_machine_write_probe SET writes = writes + 1; END",
            "CREATE TRIGGER probe_observed_update AFTER UPDATE ON file_integrity_observed BEGIN UPDATE state_machine_write_probe SET writes = writes + 1; END",
            "CREATE TRIGGER probe_observed_delete AFTER DELETE ON file_integrity_observed BEGIN UPDATE state_machine_write_probe SET writes = writes + 1; END",
            "CREATE TRIGGER probe_events_insert AFTER INSERT ON security_events BEGIN UPDATE state_machine_write_probe SET writes = writes + 1; END",
            "CREATE TRIGGER probe_events_update AFTER UPDATE ON security_events BEGIN UPDATE state_machine_write_probe SET writes = writes + 1; END",
        ] {
            sqlx::query(statement)
                .execute(db)
                .await
                .expect("install write probe trigger");
        }
    }

    fn complete_scan() -> ScanResult {
        let mut rows = vec![
            regular("/etc/passwd", b"passwd"),
            regular("/etc/group", b"group"),
            absent("/etc/sudoers", TargetKind::Fixed),
            absent("/etc/ssh/sshd_config", TargetKind::Fixed),
            absent("/etc/crontab", TargetKind::Fixed),
        ];
        rows.extend(
            DIRECTORY_ROOTS
                .iter()
                .map(|path| absent(path, TargetKind::DirectoryRoot)),
        );
        ScanResult {
            rows,
            execution_complete: true,
            observation_complete: true,
            required_targets_observed: true,
            errors: Vec::new(),
            unavailable_target_count: 0,
            bytes_read: 11,
            observed_at: NOW,
            terminal_reason: None,
        }
    }

    #[tokio::test]
    async fn first_complete_scan_enrolls_current_baseline_atomically() {
        let (db, outbox) = test_context().await;
        publish_scan_inner(&db, &outbox, complete_scan())
            .await
            .expect("publish first complete scan");

        let state = sqlx::query(
            "SELECT state_revision, baseline_generation, observed_generation,
                    status, degraded_reason, observation_complete,
                    baseline_manifest, observed_manifest, tracked_file_count,
                    drift_file_count, error_counts_json
             FROM file_integrity_state WHERE id = 1",
        )
        .fetch_one(&db)
        .await
        .expect("load enrolled state");
        assert_eq!(state.get::<i64, _>("state_revision"), 1);
        assert_eq!(state.get::<i64, _>("baseline_generation"), 1);
        assert_eq!(state.get::<i64, _>("observed_generation"), 1);
        assert_eq!(state.get::<String, _>("status"), "healthy");
        assert_eq!(state.get::<Option<String>, _>("degraded_reason"), None);
        assert_eq!(state.get::<i64, _>("observation_complete"), 1);
        assert_eq!(state.get::<i64, _>("tracked_file_count"), 11);
        assert_eq!(state.get::<i64, _>("drift_file_count"), 0);
        assert_eq!(state.get::<String, _>("error_counts_json"), "[]");
        let baseline_manifest: Vec<u8> = state.get("baseline_manifest");
        let observed_manifest: Vec<u8> = state.get("observed_manifest");
        assert_eq!(baseline_manifest.len(), 32);
        assert_eq!(observed_manifest.len(), 32);
        assert_ne!(baseline_manifest, observed_manifest);

        let baseline_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM file_integrity_baseline")
                .fetch_one(&db)
                .await
                .expect("count baseline rows");
        let observed_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM file_integrity_observed")
                .fetch_one(&db)
                .await
                .expect("count observed rows");
        let event_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_events")
            .fetch_one(&db)
            .await
            .expect("count integrity events");
        assert_eq!((baseline_count, observed_count, event_count), (11, 11, 0));
    }

    #[tokio::test]
    async fn partial_deadline_publishes_only_bounded_degraded_singleton() {
        let (db, outbox) = test_context().await;
        publish_scan_inner(&db, &outbox, ScanResult::deadline_exceeded(NOW))
            .await
            .expect("publish deadline result");

        let state = sqlx::query(
            "SELECT state_revision, baseline_generation, observed_generation,
                    status, degraded_reason, observation_complete,
                    baseline_manifest, observed_manifest, tracked_file_count,
                    unavailable_target_count, error_counts_json
             FROM file_integrity_state WHERE id = 1",
        )
        .fetch_one(&db)
        .await
        .expect("load deadline state");
        assert_eq!(state.get::<i64, _>("state_revision"), 1);
        assert_eq!(state.get::<i64, _>("baseline_generation"), 0);
        assert_eq!(state.get::<i64, _>("observed_generation"), 0);
        assert_eq!(state.get::<String, _>("status"), "degraded");
        assert_eq!(
            state.get::<Option<String>, _>("degraded_reason").as_deref(),
            Some("deadline_exceeded")
        );
        assert_eq!(state.get::<i64, _>("observation_complete"), 0);
        assert!(
            state
                .get::<Option<Vec<u8>>, _>("baseline_manifest")
                .is_none()
        );
        assert!(
            state
                .get::<Option<Vec<u8>>, _>("observed_manifest")
                .is_none()
        );
        assert_eq!(state.get::<i64, _>("tracked_file_count"), 0);
        assert_eq!(state.get::<i64, _>("unavailable_target_count"), 1);
        assert_eq!(
            state.get::<String, _>("error_counts_json"),
            r#"[{"code":"deadline_exceeded","count":1}]"#
        );

        let baseline_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM file_integrity_baseline")
                .fetch_one(&db)
                .await
                .expect("count baseline rows");
        let observed_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM file_integrity_observed")
                .fetch_one(&db)
                .await
                .expect("count observed rows");
        let event = sqlx::query(
            "SELECT event_key, event_type, status, evidence_json
             FROM security_events",
        )
        .fetch_one(&db)
        .await
        .expect("load coverage event");
        assert_eq!((baseline_count, observed_count), (0, 0));
        assert_eq!(
            event.get::<String, _>("event_key"),
            "file:integrity_coverage_degraded"
        );
        assert_eq!(
            event.get::<String, _>("event_type"),
            "file.integrity_coverage_degraded"
        );
        assert_eq!(event.get::<String, _>("status"), "open");
        let evidence: String = event.get("evidence_json");
        assert!(!evidence.contains("logical_path"));
        assert!(!evidence.contains("content_digest"));
    }

    #[tokio::test]
    async fn unchanged_and_mtime_only_scan_is_write_free() {
        let (db, outbox) = test_context().await;
        publish_scan_inner(&db, &outbox, complete_scan())
            .await
            .expect("enroll baseline");
        install_write_probe(&db).await;

        let mut unchanged = complete_scan();
        unchanged.observed_at = NOW + 1;
        unchanged
            .rows
            .iter_mut()
            .find(|row| row.logical_path == "/etc/passwd")
            .expect("passwd fixture row")
            .metadata
            .mtime_unix_seconds = Some(NOW);
        publish_scan_inner(&db, &outbox, unchanged)
            .await
            .expect("publish unchanged scan");

        let writes: i64 = sqlx::query_scalar("SELECT writes FROM state_machine_write_probe")
            .fetch_one(&db)
            .await
            .expect("read write probe");
        let state: (i64, i64, i64, String) = sqlx::query_as(
            "SELECT state_revision, baseline_generation, observed_generation, status
             FROM file_integrity_state WHERE id = 1",
        )
        .fetch_one(&db)
        .await
        .expect("load unchanged state");
        assert_eq!(writes, 0);
        assert_eq!(state, (1, 1, 1, "healthy".to_owned()));
    }

    #[tokio::test]
    async fn same_size_digest_incident_repeats_resolves_and_reopens_without_trust() {
        let (db, outbox) = test_context().await;
        let mut trusted = complete_scan();
        replace_row(
            &mut trusted,
            "/etc/sudoers",
            regular("/etc/sudoers", b"alpha\n"),
        );
        publish_scan_inner(&db, &outbox, trusted.clone())
            .await
            .expect("enroll content fixture");

        let mut changed = trusted.clone();
        changed.observed_at = NOW + 1;
        replace_row(
            &mut changed,
            "/etc/sudoers",
            regular("/etc/sudoers", b"omega\n"),
        );
        publish_scan_inner(&db, &outbox, changed.clone())
            .await
            .expect("publish same-size digest drift");
        let drift_state: (i64, i64, i64, String, i64) = sqlx::query_as(
            "SELECT state_revision, baseline_generation, observed_generation,
                    status, drift_file_count
             FROM file_integrity_state WHERE id = 1",
        )
        .fetch_one(&db)
        .await
        .expect("load drift state");
        assert_eq!(drift_state, (2, 1, 2, "drift".to_owned(), 1));
        let event = sqlx::query(
            "SELECT status, first_seen, last_seen, notification_seq, evidence_json
             FROM security_events WHERE event_type = 'file.sensitive_changed'",
        )
        .fetch_one(&db)
        .await
        .expect("load content event");
        assert_eq!(event.get::<String, _>("status"), "open");
        assert_eq!(event.get::<i64, _>("notification_seq"), 1);
        let evidence: FileSensitiveChangedEvidenceV1 =
            serde_json::from_str(&event.get::<String, _>("evidence_json"))
                .expect("parse content evidence");
        assert_eq!(
            evidence.change_kinds,
            vec![FileChangeKindV1::ContentChanged]
        );
        assert_eq!(
            evidence.baseline_metadata.size_bytes,
            evidence.observed_metadata.size_bytes
        );

        let mut repeated = changed.clone();
        repeated.observed_at = NOW + 2;
        publish_scan_inner(&db, &outbox, repeated.clone())
            .await
            .expect("repeat identical drift");
        let repeated_state: (i64, i64) = sqlx::query_as(
            "SELECT state_revision, observed_generation FROM file_integrity_state WHERE id = 1",
        )
        .fetch_one(&db)
        .await
        .expect("load repeated state");
        let repeated_event: (i64, i64) = sqlx::query_as(
            "SELECT last_seen, notification_seq FROM security_events
             WHERE event_type = 'file.sensitive_changed'",
        )
        .fetch_one(&db)
        .await
        .expect("load repeated event");
        assert_eq!(repeated_state, (2, 2));
        assert_eq!(repeated_event, (NOW + 1, 1));

        sqlx::query(
            "UPDATE security_events SET status = 'acknowledged', acknowledged_at = ?
             WHERE event_type = 'file.sensitive_changed'",
        )
        .bind(NOW + 2)
        .execute(&db)
        .await
        .expect("acknowledge drift event");
        repeated.observed_at = NOW + 3;
        publish_scan_inner(&db, &outbox, repeated)
            .await
            .expect("repeat acknowledged drift");
        let acknowledged: (String, i64, i64) = sqlx::query_as(
            "SELECT security_events.status, baseline_generation, observed_generation
             FROM security_events, file_integrity_state
             WHERE security_events.event_type = 'file.sensitive_changed'
               AND file_integrity_state.id = 1",
        )
        .fetch_one(&db)
        .await
        .expect("load acknowledged state");
        assert_eq!(acknowledged, ("acknowledged".to_owned(), 1, 2));

        let mut reverted = trusted.clone();
        reverted.observed_at = NOW + 4;
        publish_scan_inner(&db, &outbox, reverted)
            .await
            .expect("revert to baseline");
        let resolved: (String, i64, i64) = sqlx::query_as(
            "SELECT security_events.status, file_integrity_state.state_revision,
                    security_events.notification_seq
             FROM security_events, file_integrity_state
             WHERE security_events.event_type = 'file.sensitive_changed'
               AND file_integrity_state.id = 1",
        )
        .fetch_one(&db)
        .await
        .expect("load resolved event");
        assert_eq!(resolved, ("resolved".to_owned(), 3, 2));

        changed.observed_at = NOW + 5;
        publish_scan_inner(&db, &outbox, changed)
            .await
            .expect("reopen content drift");
        let reopened: (String, i64, i64, i64) = sqlx::query_as(
            "SELECT security_events.status, security_events.first_seen,
                    security_events.notification_seq,
                    file_integrity_state.state_revision
             FROM security_events, file_integrity_state
             WHERE security_events.event_type = 'file.sensitive_changed'
               AND file_integrity_state.id = 1",
        )
        .fetch_one(&db)
        .await
        .expect("load reopened event");
        assert_eq!(reopened, ("open".to_owned(), NOW + 5, 3, 4));
    }

    #[tokio::test]
    async fn post_baseline_change_kinds_are_exact_and_bounded() {
        let (db, outbox) = test_context().await;
        let mut trusted = complete_scan();
        replace_row(
            &mut trusted,
            "/etc/sudoers",
            regular("/etc/sudoers", b"alpha\n"),
        );
        replace_row(
            &mut trusted,
            "/etc/crontab",
            regular("/etc/crontab", b"cron\n"),
        );
        replace_row(
            &mut trusted,
            "/etc/cron.d",
            directory("/etc/cron.d", TargetKind::DirectoryRoot),
        );
        trusted.rows.push(regular_target(
            "/etc/cron.d/removed",
            TargetKind::DirectoryChild,
            b"removed\n",
        ));
        publish_scan_inner(&db, &outbox, trusted.clone())
            .await
            .expect("enroll change-kind fixture");

        let mut changed = trusted;
        changed.observed_at = NOW + 1;
        changed.observation_complete = false;
        changed.required_targets_observed = false;
        changed.unavailable_target_count = 2;
        changed.errors = vec![
            scan_error(ScanError::PermissionDenied, 1),
            scan_error(ScanError::NotRegular, 1),
        ];
        replace_row(
            &mut changed,
            "/etc/passwd",
            unavailable("/etc/passwd", PathObservationError::PermissionDenied),
        );
        let mut group = regular("/etc/group", b"group");
        group.metadata.mode = Some(0o600);
        group.metadata.uid = Some(1000);
        replace_row(&mut changed, "/etc/group", group);
        replace_row(
            &mut changed,
            "/etc/sudoers",
            regular("/etc/sudoers", b"omega\n"),
        );
        replace_row(
            &mut changed,
            "/etc/crontab",
            absent("/etc/crontab", TargetKind::Fixed),
        );
        replace_row(
            &mut changed,
            "/etc/ssh/sshd_config",
            directory("/etc/ssh/sshd_config", TargetKind::Fixed),
        );
        remove_row(&mut changed, "/etc/cron.d/removed");
        changed.rows.push(regular_target(
            "/etc/cron.d/added",
            TargetKind::DirectoryChild,
            b"added\n",
        ));

        publish_scan_inner(&db, &outbox, changed)
            .await
            .expect("publish change-kind matrix");
        let state: (String, i64, i64, i64) = sqlx::query_as(
            "SELECT status, drift_file_count, unavailable_target_count, trust_available
             FROM file_integrity_state WHERE id = 1",
        )
        .fetch_one(&db)
        .await
        .expect("load degraded drift state");
        assert_eq!(state, ("degraded".to_owned(), 7, 2, 0));

        let rows = sqlx::query(
            "SELECT evidence_json FROM security_events
             WHERE event_type = 'file.sensitive_changed' ORDER BY event_key",
        )
        .fetch_all(&db)
        .await
        .expect("load drift evidence rows");
        assert_eq!(rows.len(), 7);
        let evidence = rows
            .into_iter()
            .map(|row| {
                let evidence: FileSensitiveChangedEvidenceV1 =
                    serde_json::from_str(&row.get::<String, _>("evidence_json"))
                        .expect("parse drift evidence");
                (evidence.logical_path.clone(), evidence)
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            evidence["/etc/passwd"].change_kinds,
            vec![FileChangeKindV1::Unreadable]
        );
        assert_eq!(
            evidence["/etc/group"].change_kinds,
            vec![
                FileChangeKindV1::OwnerChanged,
                FileChangeKindV1::PermissionsChanged
            ]
        );
        assert_eq!(
            evidence["/etc/sudoers"].change_kinds,
            vec![FileChangeKindV1::ContentChanged]
        );
        assert_eq!(
            evidence["/etc/crontab"].change_kinds,
            vec![FileChangeKindV1::Removed]
        );
        assert_eq!(
            evidence["/etc/ssh/sshd_config"].change_kinds,
            vec![FileChangeKindV1::Added, FileChangeKindV1::TypeChanged]
        );
        assert_eq!(
            evidence["/etc/cron.d/added"].change_kinds,
            vec![FileChangeKindV1::Added]
        );
        assert_eq!(
            evidence["/etc/cron.d/removed"].change_kinds,
            vec![FileChangeKindV1::Removed]
        );
    }

    #[tokio::test]
    async fn missing_root_marker_recovers_as_trustable_untrusted_coverage() {
        let (db, outbox) = test_context().await;
        let mut initial = complete_scan();
        remove_row(&mut initial, "/etc/cron.d");
        initial.observation_complete = false;
        initial.unavailable_target_count = 1;
        initial.errors = vec![scan_error(ScanError::DirectoryUnreadable, 1)];
        publish_scan_inner(&db, &outbox, initial)
            .await
            .expect("enroll without unreadable root marker");

        let mut recovered = complete_scan();
        recovered.observed_at = NOW + 1;
        replace_row(
            &mut recovered,
            "/etc/cron.d",
            directory("/etc/cron.d", TargetKind::DirectoryRoot),
        );
        recovered.rows.push(regular_target(
            "/etc/cron.d/new-job",
            TargetKind::DirectoryChild,
            b"job\n",
        ));
        publish_scan_inner(&db, &outbox, recovered)
            .await
            .expect("publish newly observable root");

        let state = sqlx::query(
            "SELECT status, degraded_reason, observation_complete, trust_available,
                    unavailable_target_count, error_counts_json,
                    baseline_generation, observed_generation
             FROM file_integrity_state WHERE id = 1",
        )
        .fetch_one(&db)
        .await
        .expect("load untrusted coverage state");
        assert_eq!(state.get::<String, _>("status"), "degraded");
        assert_eq!(
            state.get::<Option<String>, _>("degraded_reason").as_deref(),
            Some("coverage_unavailable")
        );
        assert_eq!(state.get::<i64, _>("observation_complete"), 1);
        assert_eq!(state.get::<i64, _>("trust_available"), 1);
        assert_eq!(state.get::<i64, _>("unavailable_target_count"), 0);
        assert_eq!(
            state.get::<String, _>("error_counts_json"),
            r#"[{"code":"untrusted_new_coverage","count":2}]"#
        );
        assert_eq!(state.get::<i64, _>("baseline_generation"), 1);
        assert_eq!(state.get::<i64, _>("observed_generation"), 2);
        let path_events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security_events WHERE event_type = 'file.sensitive_changed'",
        )
        .fetch_one(&db)
        .await
        .expect("count path events");
        assert_eq!(path_events, 0);
    }

    #[tokio::test]
    async fn unreadable_root_does_not_resolve_active_added_child() {
        let (db, outbox) = test_context().await;
        let mut trusted = complete_scan();
        replace_row(
            &mut trusted,
            "/etc/cron.d",
            directory("/etc/cron.d", TargetKind::DirectoryRoot),
        );
        publish_scan_inner(&db, &outbox, trusted.clone())
            .await
            .expect("enroll trusted directory marker");

        let mut added = trusted.clone();
        added.observed_at = NOW + 1;
        added.rows.push(regular_target(
            "/etc/cron.d/added",
            TargetKind::DirectoryChild,
            b"job\n",
        ));
        publish_scan_inner(&db, &outbox, added.clone())
            .await
            .expect("publish added child");

        let mut unreadable = added;
        unreadable.observed_at = NOW + 2;
        unreadable.observation_complete = false;
        unreadable.unavailable_target_count = 1;
        unreadable.errors = vec![scan_error(ScanError::DirectoryUnreadable, 1)];
        remove_row(&mut unreadable, "/etc/cron.d");
        remove_row(&mut unreadable, "/etc/cron.d/added");
        publish_scan_inner(&db, &outbox, unreadable)
            .await
            .expect("publish unreadable root");

        let event_status: String = sqlx::query_scalar(
            "SELECT status FROM security_events
             WHERE event_type = 'file.sensitive_changed'",
        )
        .fetch_one(&db)
        .await
        .expect("load child incident");
        let state: (String, i64) = sqlx::query_as(
            "SELECT status, drift_file_count FROM file_integrity_state WHERE id = 1",
        )
        .fetch_one(&db)
        .await
        .expect("load unreadable state");
        assert_eq!(event_status, "open");
        assert_eq!(state, ("degraded".to_owned(), 1));

        let mut proven_absent = trusted.clone();
        proven_absent.observed_at = NOW + 3;
        publish_scan_inner(&db, &outbox, proven_absent)
            .await
            .expect("publish readable root with child absent");
        let resolved: (String, String, i64) = sqlx::query_as(
            "SELECT security_events.status, file_integrity_state.status,
                    file_integrity_state.drift_file_count
             FROM security_events, file_integrity_state
             WHERE security_events.event_type = 'file.sensitive_changed'
               AND file_integrity_state.id = 1",
        )
        .fetch_one(&db)
        .await
        .expect("load proven child recovery");
        assert_eq!(resolved, ("resolved".to_owned(), "healthy".to_owned(), 0));

        let mut readded = trusted;
        readded.observed_at = NOW + 4;
        readded.rows.push(regular_target(
            "/etc/cron.d/added",
            TargetKind::DirectoryChild,
            b"job\n",
        ));
        publish_scan_inner(&db, &outbox, readded)
            .await
            .expect("re-add child after proven absence");
        let reopened: (String, i64, String, i64) = sqlx::query_as(
            "SELECT security_events.status, security_events.first_seen,
                    file_integrity_state.status, file_integrity_state.drift_file_count
             FROM security_events, file_integrity_state
             WHERE security_events.event_type = 'file.sensitive_changed'
               AND file_integrity_state.id = 1",
        )
        .fetch_one(&db)
        .await
        .expect("load re-opened child incident");
        assert_eq!(
            reopened,
            ("open".to_owned(), NOW + 4, "drift".to_owned(), 1)
        );
    }

    #[tokio::test]
    async fn inconclusive_added_child_keeps_its_active_identity() {
        let (db, outbox) = test_context().await;
        let mut trusted = complete_scan();
        replace_row(
            &mut trusted,
            "/etc/cron.d",
            directory("/etc/cron.d", TargetKind::DirectoryRoot),
        );
        publish_scan_inner(&db, &outbox, trusted.clone())
            .await
            .expect("enroll conclusive-child fixture");

        let mut added = trusted;
        added.observed_at = NOW + 1;
        added.rows.push(regular_target(
            "/etc/cron.d/added",
            TargetKind::DirectoryChild,
            b"job\n",
        ));
        publish_scan_inner(&db, &outbox, added.clone())
            .await
            .expect("open added-child incident");
        let before: (String, i64, i64) = sqlx::query_as(
            "SELECT status, last_seen, notification_seq FROM security_events
             WHERE event_type = 'file.sensitive_changed'",
        )
        .fetch_one(&db)
        .await
        .expect("load initial child incident");

        let mut inconclusive = added;
        inconclusive.observed_at = NOW + 2;
        inconclusive.observation_complete = false;
        inconclusive.unavailable_target_count = 1;
        inconclusive.errors = vec![scan_error(ScanError::PermissionDenied, 1)];
        replace_row(
            &mut inconclusive,
            "/etc/cron.d/added",
            unavailable("/etc/cron.d/added", PathObservationError::PermissionDenied),
        );
        publish_scan_inner(&db, &outbox, inconclusive)
            .await
            .expect("publish inconclusive added child");

        let after: (String, i64, i64) = sqlx::query_as(
            "SELECT status, last_seen, notification_seq FROM security_events
             WHERE event_type = 'file.sensitive_changed'",
        )
        .fetch_one(&db)
        .await
        .expect("load retained child incident");
        let state: (String, i64, i64) = sqlx::query_as(
            "SELECT status, tracked_file_count, drift_file_count
             FROM file_integrity_state WHERE id = 1",
        )
        .fetch_one(&db)
        .await
        .expect("load inconclusive child state");
        assert_eq!(before, after);
        assert_eq!(after.0, "open");
        assert_eq!(state, ("degraded".to_owned(), 12, 1));
    }

    #[tokio::test]
    async fn unresolved_active_union_is_bounded_before_snapshot_or_event_writes() {
        let (db, outbox) = test_context().await;
        let mut trusted = complete_scan();
        replace_row(
            &mut trusted,
            "/etc/cron.d",
            directory("/etc/cron.d", TargetKind::DirectoryRoot),
        );
        publish_scan_inner(&db, &outbox, trusted.clone())
            .await
            .expect("enroll maximum-active fixture");

        let mut added = trusted.clone();
        added.observed_at = NOW + 1;
        for index in 0..245 {
            added.rows.push(regular_target(
                &format!("/etc/cron.d/active-{index:03}"),
                TargetKind::DirectoryChild,
                b"job\n",
            ));
        }
        assert_eq!(added.rows.len(), MAX_TRACKED_PATHS);
        publish_scan_inner(&db, &outbox, added)
            .await
            .expect("open maximum active child set");

        let mut unreadable = trusted.clone();
        unreadable.observed_at = NOW + 2;
        unreadable.observation_complete = false;
        unreadable.unavailable_target_count = 1;
        unreadable.errors = vec![scan_error(ScanError::DirectoryUnreadable, 1)];
        remove_row(&mut unreadable, "/etc/cron.d");
        publish_scan_inner(&db, &outbox, unreadable)
            .await
            .expect("retain maximum active set across unreadable root");

        let state_before: (String, String, i64, i64, i64, i64, Vec<u8>) = sqlx::query_as(
            "SELECT status, degraded_reason, state_revision, observed_generation,
                    tracked_file_count, drift_file_count, observed_manifest
             FROM file_integrity_state WHERE id = 1",
        )
        .fetch_one(&db)
        .await
        .expect("load exact-cap active state");
        assert_eq!(
            (&state_before.0, &state_before.1),
            (&"degraded".to_owned(), &"coverage_unavailable".to_owned())
        );
        assert_eq!((state_before.2, state_before.3), (3, 3));
        assert_eq!((state_before.4, state_before.5), (256, 245));
        let active_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security_events
             WHERE event_type = 'file.sensitive_changed'
               AND status IN ('open','acknowledged')",
        )
        .fetch_one(&db)
        .await
        .expect("count retained active identities");
        assert_eq!(active_count, 245);

        let observed_before: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT path_id, logical_path, generation
             FROM file_integrity_observed ORDER BY path_id",
        )
        .fetch_all(&db)
        .await
        .expect("snapshot observed rows before overflow");
        let events_before: Vec<(String, String, i64, i64, i64, String)> = sqlx::query_as(
            "SELECT event_key, status, first_seen, last_seen, notification_seq, evidence_json
             FROM security_events WHERE event_type = 'file.sensitive_changed'
             ORDER BY event_key",
        )
        .fetch_all(&db)
        .await
        .expect("snapshot path events before overflow");
        let outbox_before: Vec<(i64, String, String)> =
            sqlx::query_as("SELECT id, state, payload_json FROM notification_outbox ORDER BY id")
                .fetch_all(&db)
                .await
                .expect("snapshot outbox before overflow");

        let mut overflow = trusted;
        overflow.observed_at = NOW + 3;
        overflow.observation_complete = false;
        overflow.unavailable_target_count = 1;
        overflow.errors = vec![scan_error(ScanError::DirectoryUnreadable, 1)];
        remove_row(&mut overflow, "/etc/cron.d");
        replace_row(
            &mut overflow,
            "/etc/cron.daily",
            directory("/etc/cron.daily", TargetKind::DirectoryRoot),
        );
        overflow.rows.push(regular_target(
            "/etc/cron.daily/overflow",
            TargetKind::DirectoryChild,
            b"job\n",
        ));
        publish_scan_inner(&db, &outbox, overflow)
            .await
            .expect("publish effective active-union overflow");

        let state_after: (String, String, i64, i64, i64, i64, Vec<u8>, String) = sqlx::query_as(
            "SELECT status, degraded_reason, state_revision, observed_generation,
                        tracked_file_count, drift_file_count, observed_manifest,
                        error_counts_json
                 FROM file_integrity_state WHERE id = 1",
        )
        .fetch_one(&db)
        .await
        .expect("load overflow state");
        assert_eq!(
            (&state_after.0, &state_after.1),
            (&"degraded".to_owned(), &"limit_exceeded".to_owned())
        );
        assert_eq!((state_after.2, state_after.3), (4, 3));
        assert_eq!((state_after.4, state_after.5), (256, 245));
        assert_eq!(state_after.6, state_before.6);
        assert_eq!(
            state_after.7,
            r#"[{"code":"directory_unreadable","count":1},{"code":"tracked_file_limit","count":1}]"#
        );
        let observed_after: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT path_id, logical_path, generation
             FROM file_integrity_observed ORDER BY path_id",
        )
        .fetch_all(&db)
        .await
        .expect("snapshot observed rows after overflow");
        let events_after: Vec<(String, String, i64, i64, i64, String)> = sqlx::query_as(
            "SELECT event_key, status, first_seen, last_seen, notification_seq, evidence_json
             FROM security_events WHERE event_type = 'file.sensitive_changed'
             ORDER BY event_key",
        )
        .fetch_all(&db)
        .await
        .expect("snapshot path events after overflow");
        let outbox_after: Vec<(i64, String, String)> =
            sqlx::query_as("SELECT id, state, payload_json FROM notification_outbox ORDER BY id")
                .fetch_all(&db)
                .await
                .expect("snapshot outbox after overflow");
        assert_eq!(observed_after, observed_before);
        assert_eq!(events_after, events_before);
        assert_eq!(outbox_after, outbox_before);
        let overflow_event: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security_events
             WHERE event_key = ?",
        )
        .bind(format!(
            "file:sensitive_changed:{}",
            file_integrity_path_id("/etc/cron.daily/overflow").expect("overflow path id")
        ))
        .fetch_one(&db)
        .await
        .expect("count forbidden overflow event");
        assert_eq!(overflow_event, 0);
    }

    #[test]
    fn canonical_payload_budget_rejects_oversized_encoding() {
        let template = StoredEntry {
            path_id: format!("path-v1:{}", "a".repeat(64)),
            logical_path: format!("/{}", "x".repeat(1023)),
            generation: 1,
            target_kind: TargetKind::DirectoryChild,
            entry_state: EntryState::Regular,
            content_digest: Some([7; 32]),
            metadata: FileMetadata {
                size_bytes: Some(1),
                mtime_unix_seconds: Some(NOW),
                mode: Some(0o600),
                uid: Some(1),
                gid: Some(1),
            },
            observation_error: None,
        };
        let rows = (0..MAX_TRACKED_PATHS)
            .map(|index| {
                let mut row = template.clone();
                row.path_id = format!("path-v1:{index:064x}");
                row
            })
            .collect::<Vec<_>>();
        assert!(!manifest_within_budget(&rows).expect("measure encoded payload"));
        assert!(canonical_manifest(ManifestKind::Observed, 1, &rows).is_err());
    }

    async fn enroll_content_drift(
        db: &SqlitePool,
        outbox: &NotificationOutbox,
    ) -> (ScanResult, ScanResult) {
        let mut trusted = complete_scan();
        replace_row(
            &mut trusted,
            "/etc/sudoers",
            regular("/etc/sudoers", b"alpha\n"),
        );
        publish_scan_inner(db, outbox, trusted.clone())
            .await
            .expect("enroll trust fixture");
        let mut changed = trusted.clone();
        changed.observed_at = NOW + 1;
        replace_row(
            &mut changed,
            "/etc/sudoers",
            regular("/etc/sudoers", b"omega\n"),
        );
        publish_scan_inner(db, outbox, changed.clone())
            .await
            .expect("publish trust fixture drift");
        (trusted, changed)
    }

    #[tokio::test]
    async fn active_baseline_error_is_counted_once() {
        let (db, outbox) = test_context().await;
        let (_, mut unreadable) = enroll_content_drift(&db, &outbox).await;
        unreadable.observed_at = NOW + 2;
        unreadable.observation_complete = false;
        unreadable.unavailable_target_count = 1;
        unreadable.errors = vec![scan_error(ScanError::PermissionDenied, 1)];
        replace_row(
            &mut unreadable,
            "/etc/sudoers",
            unavailable("/etc/sudoers", PathObservationError::PermissionDenied),
        );
        publish_scan_inner(&db, &outbox, unreadable)
            .await
            .expect("publish unreadable active baseline path");

        let state: (String, i64, i64) = sqlx::query_as(
            "SELECT status, tracked_file_count, drift_file_count
             FROM file_integrity_state WHERE id = 1",
        )
        .fetch_one(&db)
        .await
        .expect("load unreadable baseline state");
        let evidence: FileSensitiveChangedEvidenceV1 = serde_json::from_str(
            &sqlx::query_scalar::<_, String>(
                "SELECT evidence_json FROM security_events
                 WHERE event_type = 'file.sensitive_changed'",
            )
            .fetch_one(&db)
            .await
            .expect("load unreadable baseline evidence"),
        )
        .expect("parse unreadable baseline evidence");
        assert_eq!(state, ("degraded".to_owned(), 11, 1));
        assert_eq!(evidence.change_kinds, vec![FileChangeKindV1::Unreadable]);
    }

    async fn corrupt_baseline_and_publish_recovery_scan(
        db: &SqlitePool,
        outbox: &NotificationOutbox,
    ) {
        publish_scan_inner(db, outbox, complete_scan())
            .await
            .expect("enroll corruption fixture");
        sqlx::query("UPDATE file_integrity_state SET baseline_manifest = ? WHERE id = 1")
            .bind(vec![0x55_u8; 32])
            .execute(db)
            .await
            .expect("corrupt baseline manifest");
        let mut recovery = complete_scan();
        recovery.observed_at = NOW + 1;
        publish_scan_inner(db, outbox, recovery)
            .await
            .expect("publish independent recovery scan");
    }

    async fn rewrite_generation_fixture(
        db: &SqlitePool,
        state_revision: u64,
        baseline_generation: u64,
        observed_generation: u64,
        baseline_corrupt: bool,
    ) {
        let mut transaction = db
            .begin_with("BEGIN IMMEDIATE")
            .await
            .expect("begin generation fixture rewrite");
        let mut baseline = load_baseline(&mut transaction)
            .await
            .expect("load generation fixture baseline");
        let mut observed = load_observed(&mut transaction)
            .await
            .expect("load generation fixture observation");
        for row in &mut baseline {
            row.generation = baseline_generation;
        }
        for row in &mut observed {
            row.generation = observed_generation;
        }
        let baseline_manifest = if baseline_corrupt {
            [0x55_u8; 32]
        } else {
            canonical_manifest(ManifestKind::Baseline, baseline_generation, &baseline)
                .expect("encode generation fixture baseline")
        };
        let observed_manifest =
            canonical_manifest(ManifestKind::Observed, observed_generation, &observed)
                .expect("encode generation fixture observation");
        sqlx::query("UPDATE file_integrity_baseline SET generation = ?")
            .bind(baseline_generation as i64)
            .execute(&mut *transaction)
            .await
            .expect("rewrite baseline row generations");
        sqlx::query("UPDATE file_integrity_observed SET generation = ?")
            .bind(observed_generation as i64)
            .execute(&mut *transaction)
            .await
            .expect("rewrite observed row generations");
        sqlx::query(
            "UPDATE file_integrity_state
             SET state_revision = ?, baseline_generation = ?, observed_generation = ?,
                 baseline_manifest = ?, observed_manifest = ?
             WHERE id = 1",
        )
        .bind(state_revision as i64)
        .bind(baseline_generation as i64)
        .bind(observed_generation as i64)
        .bind(baseline_manifest.to_vec())
        .bind(observed_manifest.to_vec())
        .execute(&mut *transaction)
        .await
        .expect("rewrite state generation fixture");
        transaction
            .commit()
            .await
            .expect("commit generation fixture rewrite");
    }

    #[tokio::test]
    async fn trust_cas_is_atomic_stale_safe_and_resolves_drift() {
        let (db, outbox) = test_context().await;
        enroll_content_drift(&db, &outbox).await;
        let request = TrustCurrentStateRequest {
            expected_baseline_generation: 1,
            expected_observed_generation: 2,
            confirmation: "trust_current_state".to_owned(),
        };
        let response = trust_current_state_at(&db, &outbox, request.clone(), NOW + 2)
            .await
            .expect("trust current observation");
        assert_eq!(response.result, "trusted");
        assert_eq!(response.status, FileIntegrityStatusKind::Healthy);
        assert_eq!(response.state_revision, 3);
        assert_eq!(response.baseline_generation, 2);
        assert_eq!(response.observed_generation, 2);
        assert_eq!(response.resolved_event_count, 1);

        let state: (String, i64, i64, i64) = sqlx::query_as(
            "SELECT status, state_revision, baseline_generation, observed_generation
             FROM file_integrity_state WHERE id = 1",
        )
        .fetch_one(&db)
        .await
        .expect("load trusted state");
        assert_eq!(state, ("healthy".to_owned(), 3, 2, 2));
        let event_status: String = sqlx::query_scalar(
            "SELECT status FROM security_events WHERE event_type = 'file.sensitive_changed'",
        )
        .fetch_one(&db)
        .await
        .expect("load resolved drift");
        assert_eq!(event_status, "resolved");

        let stale = trust_current_state_at(&db, &outbox, request, NOW + 3)
            .await
            .expect_err("second trust must be stale");
        assert_eq!(
            stale.code(),
            FileIntegrityOperationErrorCode::StaleGeneration
        );
    }

    #[tokio::test]
    async fn concurrent_trust_has_exactly_one_success() {
        let (db, outbox) = test_context().await;
        enroll_content_drift(&db, &outbox).await;
        let request = TrustCurrentStateRequest {
            expected_baseline_generation: 1,
            expected_observed_generation: 2,
            confirmation: "trust_current_state".to_owned(),
        };
        let (left, right) = tokio::join!(
            trust_current_state_at(&db, &outbox, request.clone(), NOW + 2),
            trust_current_state_at(&db, &outbox, request, NOW + 2)
        );
        let successes = usize::from(left.is_ok()) + usize::from(right.is_ok());
        let stale = [left.as_ref().err(), right.as_ref().err()]
            .into_iter()
            .flatten()
            .filter(|error| error.code() == FileIntegrityOperationErrorCode::StaleGeneration)
            .count();
        assert_eq!((successes, stale), (1, 1));
    }

    #[tokio::test]
    async fn trust_failure_rolls_back_baseline_and_state() {
        let (db, outbox) = test_context().await;
        enroll_content_drift(&db, &outbox).await;
        sqlx::query(
            "UPDATE security_events SET evidence_json = '{}'
             WHERE event_type = 'file.sensitive_changed'",
        )
        .execute(&db)
        .await
        .expect("inject invalid active event");
        let error = trust_current_state_at(
            &db,
            &outbox,
            TrustCurrentStateRequest {
                expected_baseline_generation: 1,
                expected_observed_generation: 2,
                confirmation: "trust_current_state".to_owned(),
            },
            NOW + 2,
        )
        .await
        .expect_err("invalid event must roll trust back");
        assert_eq!(error.code(), FileIntegrityOperationErrorCode::InternalError);
        let state: (String, i64, i64) = sqlx::query_as(
            "SELECT status, state_revision, baseline_generation
             FROM file_integrity_state WHERE id = 1",
        )
        .fetch_one(&db)
        .await
        .expect("load rolled-back state");
        assert_eq!(state, ("drift".to_owned(), 2, 1));
    }

    #[tokio::test]
    async fn baseline_corruption_requires_fresh_complete_scan_and_reenrolls_privately() {
        let (db, outbox) = test_context().await;
        publish_scan_inner(&db, &outbox, complete_scan())
            .await
            .expect("enroll corruption status fixture");
        sqlx::query("UPDATE file_integrity_state SET baseline_manifest = ? WHERE id = 1")
            .bind(vec![0x33_u8; 32])
            .execute(&db)
            .await
            .expect("tamper baseline manifest");
        let storage = FileIntegrityStorage {
            db: db.clone(),
            outbox: Arc::new(outbox.clone()),
        };
        let before_scan = validated_status(&storage)
            .await
            .expect("project corrupt status safely");
        assert_eq!(before_scan.status, FileIntegrityStatusKind::Degraded);
        assert_eq!(
            before_scan.degraded_reason,
            Some(FileIntegrityDegradedReasonV1::BaselineCorrupt)
        );
        assert!(!before_scan.re_enroll_available);

        let mut recovery = complete_scan();
        recovery.observed_at = NOW + 1;
        publish_scan_inner(&db, &outbox, recovery)
            .await
            .expect("publish fresh complete recovery observation");
        let ready: (String, i64, i64, i64) = sqlx::query_as(
            "SELECT degraded_reason, state_revision, observed_generation,
                    re_enroll_available FROM file_integrity_state WHERE id = 1",
        )
        .fetch_one(&db)
        .await
        .expect("load recovery-ready state");
        assert_eq!(ready, ("baseline_corrupt".to_owned(), 2, 2, 1));

        install_write_probe(&db).await;
        let mut repeated_recovery = complete_scan();
        repeated_recovery.observed_at = NOW + 2;
        publish_scan_inner(&db, &outbox, repeated_recovery)
            .await
            .expect("repeat identical recovery observation");
        let writes: i64 = sqlx::query_scalar("SELECT writes FROM state_machine_write_probe")
            .fetch_one(&db)
            .await
            .expect("read recovery write probe");
        assert_eq!(writes, 0);

        let response = re_enroll_at(
            &db,
            &outbox,
            ReEnrollRequest {
                expected_state_revision: 2,
                expected_observed_generation: 2,
                confirmation: "re_enroll_from_current_observation".to_owned(),
            },
            NOW + 3,
        )
        .await
        .expect("re-enroll corrupt baseline");
        assert_eq!(response.result, "reenrolled");
        assert_eq!(response.status, FileIntegrityStatusKind::Healthy);
        assert_eq!(response.state_revision, 3);
        assert_eq!(response.baseline_generation, 2);
        assert_eq!(response.observed_generation, 2);
        assert_eq!(response.resolved_event_count, 1);
        let audit: String = sqlx::query_scalar(
            "SELECT evidence_json FROM security_events
             WHERE event_type = 'file.integrity_baseline_reenrolled'",
        )
        .fetch_one(&db)
        .await
        .expect("load re-enrollment audit");
        assert!(!audit.contains("logical_path"));
        assert!(!audit.contains("content_digest"));
        let response_json = serde_json::to_string(&response).expect("serialize response");
        assert!(!response_json.contains("path-v1:"));
        assert!(!response_json.contains("digest"));
    }

    #[tokio::test]
    async fn reenroll_is_stale_safe_concurrent_and_rejects_unknown_algorithm() {
        let (db, outbox) = test_context().await;
        corrupt_baseline_and_publish_recovery_scan(&db, &outbox).await;
        let stale = re_enroll_at(
            &db,
            &outbox,
            ReEnrollRequest {
                expected_state_revision: 1,
                expected_observed_generation: 1,
                confirmation: "re_enroll_from_current_observation".to_owned(),
            },
            NOW + 2,
        )
        .await
        .expect_err("stale recovery CAS must fail");
        assert_eq!(
            stale.code(),
            FileIntegrityOperationErrorCode::StaleGeneration
        );

        sqlx::query("UPDATE file_integrity_state SET digest_algorithm = 'sha512' WHERE id = 1")
            .execute(&db)
            .await
            .expect("inject unsupported digest algorithm");
        let unsupported = re_enroll_at(
            &db,
            &outbox,
            ReEnrollRequest {
                expected_state_revision: 2,
                expected_observed_generation: 1,
                confirmation: "re_enroll_from_current_observation".to_owned(),
            },
            NOW + 2,
        )
        .await
        .expect_err("unknown algorithm must not be overwritten");
        assert_eq!(
            unsupported.code(),
            FileIntegrityOperationErrorCode::UnsupportedAlgorithm
        );
        let baseline_generation: i64 =
            sqlx::query_scalar("SELECT baseline_generation FROM file_integrity_state WHERE id = 1")
                .fetch_one(&db)
                .await
                .expect("load unchanged baseline generation");
        assert_eq!(baseline_generation, 1);

        sqlx::query("UPDATE file_integrity_state SET digest_algorithm = 'sha256' WHERE id = 1")
            .execute(&db)
            .await
            .expect("restore supported algorithm");
        let request = ReEnrollRequest {
            expected_state_revision: 2,
            expected_observed_generation: 2,
            confirmation: "re_enroll_from_current_observation".to_owned(),
        };
        let (left, right) = tokio::join!(
            re_enroll_at(&db, &outbox, request.clone(), NOW + 3),
            re_enroll_at(&db, &outbox, request, NOW + 3)
        );
        let successes = usize::from(left.is_ok()) + usize::from(right.is_ok());
        let stale = [left.as_ref().err(), right.as_ref().err()]
            .into_iter()
            .flatten()
            .filter(|error| error.code() == FileIntegrityOperationErrorCode::StaleGeneration)
            .count();
        assert_eq!((successes, stale), (1, 1));
    }

    #[tokio::test]
    async fn semantic_row_corruption_projects_closed_reasons() {
        let (baseline_db, baseline_outbox) = test_context().await;
        publish_scan_inner(&baseline_db, &baseline_outbox, complete_scan())
            .await
            .expect("enroll semantic baseline fixture");
        sqlx::query(
            "UPDATE file_integrity_baseline SET target_kind = 'directory_child'
             WHERE logical_path = '/etc/passwd'",
        )
        .execute(&baseline_db)
        .await
        .expect("inject semantic baseline mismatch");
        let baseline_storage = FileIntegrityStorage {
            db: baseline_db,
            outbox: Arc::new(baseline_outbox),
        };
        let baseline_status = validated_status(&baseline_storage)
            .await
            .expect("project semantic baseline corruption");
        assert_eq!(
            baseline_status.degraded_reason,
            Some(FileIntegrityDegradedReasonV1::BaselineCorrupt)
        );

        let (observed_db, observed_outbox) = test_context().await;
        publish_scan_inner(&observed_db, &observed_outbox, complete_scan())
            .await
            .expect("enroll semantic observed fixture");
        sqlx::query(
            "UPDATE file_integrity_observed SET target_kind = 'directory_child'
             WHERE logical_path = '/etc/passwd'",
        )
        .execute(&observed_db)
        .await
        .expect("inject semantic observed mismatch");
        let observed_storage = FileIntegrityStorage {
            db: observed_db.clone(),
            outbox: Arc::new(observed_outbox.clone()),
        };
        let observed_status = validated_status(&observed_storage)
            .await
            .expect("project semantic observed corruption");
        assert_eq!(
            observed_status.degraded_reason,
            Some(FileIntegrityDegradedReasonV1::InternalError)
        );

        publish_scan_inner(
            &observed_db,
            &observed_outbox,
            ScanResult::deadline_exceeded(NOW + 1),
        )
        .await
        .expect("keep corrupt observed snapshot closed on partial scan");
        let partial: (String, String, i64, i64, i64) = sqlx::query_as(
            "SELECT status, degraded_reason, state_revision, observed_generation,
                    (SELECT COUNT(*) FROM security_events
                     WHERE event_type = 'file.sensitive_changed')
             FROM file_integrity_state WHERE id = 1",
        )
        .fetch_one(&observed_db)
        .await
        .expect("load partial observed-corruption state");
        assert_eq!(
            partial,
            ("degraded".to_owned(), "internal_error".to_owned(), 2, 1, 0)
        );
        let still_corrupt: String = sqlx::query_scalar(
            "SELECT target_kind FROM file_integrity_observed
             WHERE logical_path = '/etc/passwd'",
        )
        .fetch_one(&observed_db)
        .await
        .expect("load preserved corrupt observed row");
        assert_eq!(still_corrupt, "directory_child");

        let baseline_before: (i64, Vec<u8>, Vec<(String, String, i64)>) = (
            sqlx::query_scalar("SELECT baseline_generation FROM file_integrity_state WHERE id = 1")
                .fetch_one(&observed_db)
                .await
                .expect("load baseline generation before observed repair"),
            sqlx::query_scalar("SELECT baseline_manifest FROM file_integrity_state WHERE id = 1")
                .fetch_one(&observed_db)
                .await
                .expect("load baseline manifest before observed repair"),
            sqlx::query_as(
                "SELECT path_id, logical_path, generation
                 FROM file_integrity_baseline ORDER BY path_id",
            )
            .fetch_all(&observed_db)
            .await
            .expect("load baseline rows before observed repair"),
        );
        let mut repaired = complete_scan();
        repaired.observed_at = NOW + 2;
        publish_scan_inner(&observed_db, &observed_outbox, repaired)
            .await
            .expect("repair semantic observed corruption from complete scan");
        let recovered: (String, i64, i64, i64) = sqlx::query_as(
            "SELECT status, state_revision, baseline_generation, observed_generation
             FROM file_integrity_state WHERE id = 1",
        )
        .fetch_one(&observed_db)
        .await
        .expect("load recovered observed state");
        assert_eq!(recovered, ("healthy".to_owned(), 3, 1, 2));
        let baseline_after: (i64, Vec<u8>, Vec<(String, String, i64)>) = (
            sqlx::query_scalar("SELECT baseline_generation FROM file_integrity_state WHERE id = 1")
                .fetch_one(&observed_db)
                .await
                .expect("load baseline generation after observed repair"),
            sqlx::query_scalar("SELECT baseline_manifest FROM file_integrity_state WHERE id = 1")
                .fetch_one(&observed_db)
                .await
                .expect("load baseline manifest after observed repair"),
            sqlx::query_as(
                "SELECT path_id, logical_path, generation
                 FROM file_integrity_baseline ORDER BY path_id",
            )
            .fetch_all(&observed_db)
            .await
            .expect("load baseline rows after observed repair"),
        );
        assert_eq!(baseline_after, baseline_before);
    }

    #[tokio::test]
    async fn observed_manifest_corruption_recovers_to_fresh_drift_without_advancing_baseline() {
        let (db, outbox) = test_context().await;
        let mut trusted = complete_scan();
        replace_row(
            &mut trusted,
            "/etc/sudoers",
            regular("/etc/sudoers", b"alpha\n"),
        );
        publish_scan_inner(&db, &outbox, trusted.clone())
            .await
            .expect("enroll observed-manifest fixture");
        let baseline_before: (i64, Vec<u8>, Vec<(String, Option<Vec<u8>>, i64)>) = (
            sqlx::query_scalar("SELECT baseline_generation FROM file_integrity_state WHERE id = 1")
                .fetch_one(&db)
                .await
                .expect("load baseline generation before manifest repair"),
            sqlx::query_scalar("SELECT baseline_manifest FROM file_integrity_state WHERE id = 1")
                .fetch_one(&db)
                .await
                .expect("load baseline manifest before manifest repair"),
            sqlx::query_as(
                "SELECT path_id, content_digest, generation
                 FROM file_integrity_baseline ORDER BY path_id",
            )
            .fetch_all(&db)
            .await
            .expect("load baseline rows before manifest repair"),
        );
        sqlx::query("UPDATE file_integrity_state SET observed_manifest = ? WHERE id = 1")
            .bind(vec![0x6a_u8; 32])
            .execute(&db)
            .await
            .expect("corrupt observed manifest");

        let mut changed = trusted;
        changed.observed_at = NOW + 1;
        replace_row(
            &mut changed,
            "/etc/sudoers",
            regular("/etc/sudoers", b"omega\n"),
        );
        publish_scan_inner(&db, &outbox, changed)
            .await
            .expect("repair observed manifest into fresh drift");

        let state: (String, i64, i64, i64) = sqlx::query_as(
            "SELECT status, state_revision, baseline_generation, observed_generation
             FROM file_integrity_state WHERE id = 1",
        )
        .fetch_one(&db)
        .await
        .expect("load manifest-repaired state");
        assert_eq!(state, ("drift".to_owned(), 2, 1, 2));
        let evidence: FileSensitiveChangedEvidenceV1 = serde_json::from_str(
            &sqlx::query_scalar::<_, String>(
                "SELECT evidence_json FROM security_events
                 WHERE event_type = 'file.sensitive_changed'",
            )
            .fetch_one(&db)
            .await
            .expect("load manifest-repair drift evidence"),
        )
        .expect("parse manifest-repair drift evidence");
        assert_eq!(
            evidence.change_kinds,
            vec![FileChangeKindV1::ContentChanged]
        );
        let baseline_after: (i64, Vec<u8>, Vec<(String, Option<Vec<u8>>, i64)>) = (
            sqlx::query_scalar("SELECT baseline_generation FROM file_integrity_state WHERE id = 1")
                .fetch_one(&db)
                .await
                .expect("load baseline generation after manifest repair"),
            sqlx::query_scalar("SELECT baseline_manifest FROM file_integrity_state WHERE id = 1")
                .fetch_one(&db)
                .await
                .expect("load baseline manifest after manifest repair"),
            sqlx::query_as(
                "SELECT path_id, content_digest, generation
                 FROM file_integrity_baseline ORDER BY path_id",
            )
            .fetch_all(&db)
            .await
            .expect("load baseline rows after manifest repair"),
        );
        assert_eq!(baseline_after, baseline_before);
    }

    #[tokio::test]
    async fn baseline_candidate_union_overflow_is_atomic_limit_degradation() {
        let (db, outbox) = test_context().await;
        let mut trusted = complete_scan();
        replace_row(
            &mut trusted,
            "/etc/cron.d",
            directory("/etc/cron.d", TargetKind::DirectoryRoot),
        );
        for index in 0..245 {
            trusted.rows.push(regular_target(
                &format!("/etc/cron.d/base-{index:03}"),
                TargetKind::DirectoryChild,
                b"x",
            ));
        }
        assert_eq!(trusted.rows.len(), MAX_TRACKED_PATHS);
        publish_scan_inner(&db, &outbox, trusted.clone())
            .await
            .expect("enroll maximum baseline");

        let mut disjoint = trusted;
        disjoint.observed_at = NOW + 1;
        disjoint
            .rows
            .retain(|row| !row.logical_path.starts_with("/etc/cron.d/base-"));
        for index in 0..245 {
            disjoint.rows.push(regular_target(
                &format!("/etc/cron.d/new-{index:03}"),
                TargetKind::DirectoryChild,
                b"y",
            ));
        }
        assert_eq!(disjoint.rows.len(), MAX_TRACKED_PATHS);
        publish_scan_inner(&db, &outbox, disjoint)
            .await
            .expect("publish union overflow as degradation");

        let state: (String, String, i64, i64, String) = sqlx::query_as(
            "SELECT status, degraded_reason, baseline_generation,
                    observed_generation, error_counts_json
             FROM file_integrity_state WHERE id = 1",
        )
        .fetch_one(&db)
        .await
        .expect("load union limit state");
        assert_eq!(state.0, "degraded");
        assert_eq!(state.1, "limit_exceeded");
        assert_eq!((state.2, state.3), (1, 1));
        assert_eq!(state.4, r#"[{"code":"tracked_file_limit","count":1}]"#);
        let observed_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM file_integrity_observed")
                .fetch_one(&db)
                .await
                .expect("count preserved observed rows");
        let path_events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security_events WHERE event_type = 'file.sensitive_changed'",
        )
        .fetch_one(&db)
        .await
        .expect("count absent path events");
        assert_eq!((observed_count, path_events), (256, 0));
    }

    #[tokio::test]
    #[ignore = "explicit Linux P8.3 storage/privacy gate"]
    async fn p83_linux_storage_and_privacy_gate() {
        use std::fs;
        use std::path::{Path, PathBuf};
        use std::time::{SystemTime, UNIX_EPOCH};

        struct MeasurementDb(PathBuf);

        impl Drop for MeasurementDb {
            fn drop(&mut self) {
                for suffix in ["", "-wal", "-shm"] {
                    let _ = fs::remove_file(format!("{}{suffix}", self.0.display()));
                }
            }
        }

        fn footprint(path: &Path) -> u64 {
            ["", "-wal", "-shm"]
                .into_iter()
                .filter_map(|suffix| {
                    fs::metadata(format!("{}{suffix}", path.display()))
                        .ok()
                        .map(|metadata| metadata.len())
                })
                .sum()
        }

        const SENTINEL: &[u8] = b"MINI_OPS_RAW_SENTINEL_P83_7b1f6d";
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("measurement clock after epoch")
            .as_nanos();
        let guard = MeasurementDb(std::env::temp_dir().join(format!(
            "mini-ops-p83-storage-{}-{nonce}.db",
            std::process::id()
        )));
        let database_url = format!("sqlite://{}?mode=rwc", guard.0.display());
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .expect("connect file-backed measurement database");
        SecurityEventService::init_schema(&db)
            .await
            .expect("initialize pre-existing event schema");
        let before_integrity_bytes = footprint(&guard.0);
        super::super::schema::initialize(&db)
            .await
            .expect("initialize integrity schema");
        let after_schema_bytes = footprint(&guard.0);
        let outbox = NotificationOutbox::new(
            db.clone(),
            Arc::new(NotificationService::with_test_endpoint(
                "123456:test",
                "http://127.0.0.1:9".to_owned(),
            )),
        );

        let mut baseline_scan = complete_scan();
        replace_row(
            &mut baseline_scan,
            "/etc/passwd",
            regular("/etc/passwd", SENTINEL),
        );
        publish_scan_inner(&db, &outbox, baseline_scan.clone())
            .await
            .expect("publish measurement baseline");
        let after_baseline_bytes = footprint(&guard.0);
        let mut transaction = db.begin().await.expect("begin baseline measurement read");
        let baseline = load_baseline(&mut transaction)
            .await
            .expect("load measured baseline");
        transaction
            .rollback()
            .await
            .expect("close measurement read transaction");
        let baseline_payload_bytes =
            manifest_payload_size(&baseline).expect("measure canonical baseline payload");

        let mut drift = baseline_scan;
        drift.observed_at = NOW + 1;
        replace_row(
            &mut drift,
            "/etc/passwd",
            regular("/etc/passwd", b"MINI_OPS_REPLACEMENT_P83_7b1f6d"),
        );
        publish_scan_inner(&db, &outbox, drift)
            .await
            .expect("publish measurement drift");
        let after_drift_bytes = footprint(&guard.0);
        let trust = trust_current_state_at(
            &db,
            &outbox,
            TrustCurrentStateRequest {
                expected_baseline_generation: 1,
                expected_observed_generation: 2,
                confirmation: "trust_current_state".to_owned(),
            },
            NOW + 2,
        )
        .await
        .expect("trust measured drift");
        let after_trust_bytes = footprint(&guard.0);

        let storage = FileIntegrityStorage {
            db: db.clone(),
            outbox: Arc::new(outbox.clone()),
        };
        let mut surfaces = vec![
            serde_json::to_string(
                &validated_status(&storage)
                    .await
                    .expect("project measured status"),
            )
            .expect("serialize measured status"),
            serde_json::to_string(&trust).expect("serialize measured trust response"),
        ];
        surfaces.extend(
            sqlx::query_scalar::<_, String>(
                "SELECT evidence_json || title || message FROM security_events ORDER BY id",
            )
            .fetch_all(&db)
            .await
            .expect("load measured event surfaces"),
        );
        surfaces.extend(
            sqlx::query_scalar::<_, String>(
                "SELECT payload_json FROM notification_outbox ORDER BY id",
            )
            .fetch_all(&db)
            .await
            .expect("load measured notification surfaces"),
        );
        let digest_hex = Sha256::digest(SENTINEL)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        for surface in &surfaces {
            assert!(!surface.contains(std::str::from_utf8(SENTINEL).expect("UTF-8 sentinel")));
            assert!(!surface.contains(&digest_hex));
        }

        db.close().await;
        let final_bytes = footprint(&guard.0);
        let raw_database = fs::read(&guard.0).expect("read measured SQLite file");
        assert!(
            !raw_database
                .windows(SENTINEL.len())
                .any(|window| window == SENTINEL)
        );
        let growth_bytes = final_bytes.saturating_sub(before_integrity_bytes);
        eprintln!(
            "{}",
            serde_json::json!({
                "before_integrity_bytes": before_integrity_bytes,
                "after_schema_bytes": after_schema_bytes,
                "after_baseline_bytes": after_baseline_bytes,
                "after_drift_bytes": after_drift_bytes,
                "after_trust_bytes": after_trust_bytes,
                "final_db_wal_shm_bytes": final_bytes,
                "integrity_growth_bytes": growth_bytes,
                "baseline_payload_bytes": baseline_payload_bytes,
                "surface_count": surfaces.len(),
            })
        );
        assert!(baseline_payload_bytes < MAX_MANIFEST_BYTES);
        assert!(
            growth_bytes < 1024 * 1024,
            "SQLite growth: {growth_bytes} bytes"
        );
    }

    #[tokio::test]
    async fn safe_integer_exhaustion_never_projects_healthy() {
        let (db, outbox) = test_context().await;
        publish_scan_inner(&db, &outbox, complete_scan())
            .await
            .expect("enroll exhaustion fixture");
        sqlx::query("UPDATE file_integrity_state SET state_revision = ? WHERE id = 1")
            .bind(JS_MAX_SAFE_INTEGER as i64)
            .execute(&db)
            .await
            .expect("exhaust state revision");
        let storage = FileIntegrityStorage {
            db,
            outbox: Arc::new(outbox),
        };
        let status = validated_status(&storage)
            .await
            .expect("project exhausted state safely");
        assert_eq!(status.status, FileIntegrityStatusKind::Degraded);
        assert_eq!(
            status.degraded_reason,
            Some(FileIntegrityDegradedReasonV1::InternalError)
        );
        assert!(!status.observation_complete);
        assert!(!status.trust_available);
        assert!(!status.re_enroll_available);
    }

    #[tokio::test]
    async fn trust_rejects_generation_exhaustion_and_headroom_loss_without_writes() {
        for (column, value) in [
            ("state_revision", JS_MAX_SAFE_INTEGER),
            ("baseline_generation", JS_MAX_SAFE_INTEGER),
            ("observed_generation", JS_MAX_SAFE_INTEGER),
            ("state_revision", JS_MAX_SAFE_INTEGER - 1),
            ("baseline_generation", JS_MAX_SAFE_INTEGER - 1),
        ] {
            let (db, outbox) = test_context().await;
            enroll_content_drift(&db, &outbox).await;
            let state_revision = if column == "state_revision" { value } else { 2 };
            let baseline_generation = if column == "baseline_generation" {
                value
            } else {
                1
            };
            let observed_generation = if column == "observed_generation" {
                value
            } else {
                2
            };
            rewrite_generation_fixture(
                &db,
                state_revision,
                baseline_generation,
                observed_generation,
                false,
            )
            .await;
            let stale = trust_current_state_at(
                &db,
                &outbox,
                TrustCurrentStateRequest {
                    expected_baseline_generation: baseline_generation,
                    expected_observed_generation: observed_generation - 1,
                    confirmation: "trust_current_state".to_owned(),
                },
                NOW + 2,
            )
            .await
            .expect_err("stale exhausted trust must preserve CAS precedence");
            assert_eq!(
                stale.code(),
                FileIntegrityOperationErrorCode::StaleGeneration
            );
            install_write_probe(&db).await;

            let error = trust_current_state_at(
                &db,
                &outbox,
                TrustCurrentStateRequest {
                    expected_baseline_generation: baseline_generation,
                    expected_observed_generation: observed_generation,
                    confirmation: "trust_current_state".to_owned(),
                },
                NOW + 2,
            )
            .await
            .expect_err("exhausted trust must fail closed");
            assert_eq!(error.code(), FileIntegrityOperationErrorCode::InternalError);
            assert_eq!(
                error.response_body().error.status,
                Some(FileIntegrityStatusKind::Degraded)
            );
            let writes: i64 = sqlx::query_scalar("SELECT writes FROM state_machine_write_probe")
                .fetch_one(&db)
                .await
                .expect("load trust exhaustion write count");
            let active_events: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM security_events
                 WHERE event_type = 'file.sensitive_changed'
                   AND status IN ('open','acknowledged')",
            )
            .fetch_one(&db)
            .await
            .expect("count preserved trust events");
            assert_eq!((writes, active_events), (0, 1));
        }
    }

    #[tokio::test]
    async fn reenroll_rejects_generation_exhaustion_and_headroom_loss_without_writes() {
        for (column, value) in [
            ("state_revision", JS_MAX_SAFE_INTEGER),
            ("baseline_generation", JS_MAX_SAFE_INTEGER),
            ("observed_generation", JS_MAX_SAFE_INTEGER),
            ("state_revision", JS_MAX_SAFE_INTEGER - 1),
            ("baseline_generation", JS_MAX_SAFE_INTEGER - 1),
        ] {
            let (db, outbox) = test_context().await;
            corrupt_baseline_and_publish_recovery_scan(&db, &outbox).await;
            let state_revision = if column == "state_revision" { value } else { 2 };
            let baseline_generation = if column == "baseline_generation" {
                value
            } else {
                1
            };
            let observed_generation = if column == "observed_generation" {
                value
            } else {
                2
            };
            rewrite_generation_fixture(
                &db,
                state_revision,
                baseline_generation,
                observed_generation,
                true,
            )
            .await;
            let stale = re_enroll_at(
                &db,
                &outbox,
                ReEnrollRequest {
                    expected_state_revision: state_revision - 1,
                    expected_observed_generation: observed_generation,
                    confirmation: "re_enroll_from_current_observation".to_owned(),
                },
                NOW + 2,
            )
            .await
            .expect_err("stale exhausted re-enrollment must preserve CAS precedence");
            assert_eq!(
                stale.code(),
                FileIntegrityOperationErrorCode::StaleGeneration
            );
            install_write_probe(&db).await;

            let error = re_enroll_at(
                &db,
                &outbox,
                ReEnrollRequest {
                    expected_state_revision: state_revision,
                    expected_observed_generation: observed_generation,
                    confirmation: "re_enroll_from_current_observation".to_owned(),
                },
                NOW + 2,
            )
            .await
            .expect_err("exhausted re-enrollment must fail closed");
            assert_eq!(error.code(), FileIntegrityOperationErrorCode::InternalError);
            assert_eq!(
                error.response_body().error.status,
                Some(FileIntegrityStatusKind::Degraded)
            );
            let writes: i64 = sqlx::query_scalar("SELECT writes FROM state_machine_write_probe")
                .fetch_one(&db)
                .await
                .expect("load re-enroll exhaustion write count");
            let audit_events: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM security_events
                 WHERE event_type = 'file.integrity_baseline_reenrolled'",
            )
            .fetch_one(&db)
            .await
            .expect("count forbidden re-enroll audits");
            assert_eq!((writes, audit_events), (0, 0));
        }
    }

    #[tokio::test]
    async fn reenroll_cas_rechecks_generation_headroom() {
        let (db, outbox) = test_context().await;
        corrupt_baseline_and_publish_recovery_scan(&db, &outbox).await;
        let mut transaction = db
            .begin_with("BEGIN IMMEDIATE")
            .await
            .expect("begin re-enroll CAS fixture");
        let state = load_state(&mut transaction)
            .await
            .expect("load pre-race re-enroll state");
        sqlx::query("UPDATE file_integrity_state SET baseline_generation = ? WHERE id = 1")
            .bind((JS_MAX_SAFE_INTEGER - 1) as i64)
            .execute(&mut *transaction)
            .await
            .expect("inject CAS generation headroom loss");
        let accepted = cas_re_enroll_state(
            &mut transaction,
            &state,
            &ReEnrollRequest {
                expected_state_revision: state.state_revision,
                expected_observed_generation: state.observed_generation,
                confirmation: "re_enroll_from_current_observation".to_owned(),
            },
        )
        .await
        .expect("evaluate re-enroll CAS headroom");
        assert!(!accepted);
        transaction
            .rollback()
            .await
            .expect("rollback re-enroll CAS fixture");
    }
}

fn invalid_integrity_state() -> sqlx::Error {
    sqlx::Error::Protocol("invalid file-integrity state".to_owned())
}
