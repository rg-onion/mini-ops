use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) const MAX_TRACKED_PATHS: usize = 256;
pub(crate) const MAX_FILE_BYTES: u64 = 1024 * 1024;
pub(crate) const MAX_SCAN_BYTES: u64 = 8 * 1024 * 1024;
pub(crate) const READ_BUFFER_BYTES: usize = 64 * 1024;
pub(crate) const SCAN_DEADLINE: Duration = Duration::from_secs(15);

const MAX_LOGICAL_PATH_BYTES: usize = 1024;
const PATH_ID_DOMAIN: &[u8] = b"mini-ops:file-integrity:path:v1\0";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum TargetKind {
    Fixed,
    DirectoryRoot,
    DirectoryChild,
}

impl TargetKind {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::DirectoryRoot => "directory_root",
            Self::DirectoryChild => "directory_child",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum EntryState {
    Regular,
    Directory,
    Absent,
}

impl EntryState {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Regular => "regular",
            Self::Directory => "directory",
            Self::Absent => "absent",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileMetadata {
    pub(crate) size_bytes: Option<u64>,
    pub(crate) mtime_unix_seconds: Option<i64>,
    pub(crate) mode: Option<u32>,
    pub(crate) uid: Option<u32>,
    pub(crate) gid: Option<u32>,
}

impl FileMetadata {
    const ABSENT: Self = Self {
        size_bytes: None,
        mtime_unix_seconds: None,
        mode: None,
        uid: None,
        gid: None,
    };
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum PathObservationError {
    PermissionDenied,
    Symlink,
    NotRegular,
    FileTooLarge,
    ChangedDuringRead,
    VanishedDuringScan,
    IoError,
}

impl PathObservationError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::PermissionDenied => "permission_denied",
            Self::Symlink => "symlink",
            Self::NotRegular => "not_regular",
            Self::FileTooLarge => "file_too_large",
            Self::ChangedDuringRead => "changed_during_read",
            Self::VanishedDuringScan => "vanished_during_scan",
            Self::IoError => "io_error",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum ScanError {
    PermissionDenied,
    Symlink,
    NotRegular,
    FileTooLarge,
    ChangedDuringRead,
    VanishedDuringScan,
    IoError,
    TrackedFileLimit,
    ScanByteLimit,
    DeadlineExceeded,
    Cancelled,
    DirectoryUnreadable,
    PathNotUtf8,
    PathTooLong,
    NetworkFilesystem,
    FilesystemUnclassified,
}

impl From<PathObservationError> for ScanError {
    fn from(value: PathObservationError) -> Self {
        match value {
            PathObservationError::PermissionDenied => Self::PermissionDenied,
            PathObservationError::Symlink => Self::Symlink,
            PathObservationError::NotRegular => Self::NotRegular,
            PathObservationError::FileTooLarge => Self::FileTooLarge,
            PathObservationError::ChangedDuringRead => Self::ChangedDuringRead,
            PathObservationError::VanishedDuringScan => Self::VanishedDuringScan,
            PathObservationError::IoError => Self::IoError,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScanErrorCount {
    pub(crate) error: ScanError,
    pub(crate) count: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedEntry {
    pub(crate) path_id: String,
    pub(crate) logical_path: String,
    pub(crate) target_kind: TargetKind,
    pub(crate) entry_state: EntryState,
    pub(crate) content_digest: Option<[u8; 32]>,
    pub(crate) metadata: FileMetadata,
    pub(crate) observation_error: Option<PathObservationError>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScanResult {
    pub(crate) rows: Vec<ObservedEntry>,
    pub(crate) execution_complete: bool,
    pub(crate) observation_complete: bool,
    pub(crate) required_targets_observed: bool,
    pub(crate) errors: Vec<ScanErrorCount>,
    pub(crate) unavailable_target_count: u16,
    pub(crate) bytes_read: u64,
    pub(crate) observed_at: i64,
    pub(crate) terminal_reason: Option<ScanTerminalReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScanTerminalReason {
    TrackedFileLimit,
    ScanByteLimit,
    DeadlineExceeded,
    Cancelled,
    InternalError,
}

impl ScanResult {
    pub(crate) fn deadline_exceeded(observed_at: i64) -> Self {
        Self::terminal(
            observed_at,
            ScanError::DeadlineExceeded,
            ScanTerminalReason::DeadlineExceeded,
        )
    }

    pub(crate) fn internal_error(observed_at: i64) -> Self {
        Self::terminal(
            observed_at,
            ScanError::IoError,
            ScanTerminalReason::InternalError,
        )
    }

    fn terminal(observed_at: i64, error: ScanError, terminal_reason: ScanTerminalReason) -> Self {
        Self {
            rows: Vec::new(),
            execution_complete: false,
            observation_complete: false,
            required_targets_observed: false,
            errors: vec![ScanErrorCount { error, count: 1 }],
            unavailable_target_count: 1,
            bytes_read: 0,
            observed_at,
            terminal_reason: Some(terminal_reason),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ScanCancellation {
    cancelled: Arc<AtomicBool>,
}

impl ScanCancellation {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct FileIntegrityCollector {
    physical_root: PathBuf,
}

impl FileIntegrityCollector {
    pub(crate) fn production() -> Self {
        Self {
            physical_root: PathBuf::from("/"),
        }
    }

    #[cfg(test)]
    fn for_test_root(physical_root: PathBuf) -> Self {
        Self { physical_root }
    }

    pub(crate) fn scan(
        &self,
        cancellation: &ScanCancellation,
        trusted_path_ids: &BTreeSet<String>,
    ) -> ScanResult {
        self.scan_until(
            cancellation,
            Instant::now() + SCAN_DEADLINE,
            trusted_path_ids,
        )
    }

    fn scan_until(
        &self,
        cancellation: &ScanCancellation,
        deadline: Instant,
        trusted_path_ids: &BTreeSet<String>,
    ) -> ScanResult {
        let observed_at = unix_timestamp();
        let mut state = ScanState::new(cancellation, deadline, trusted_path_ids, observed_at);
        state.run(&self.physical_root);
        state.finish()
    }
}

#[derive(Clone, Copy)]
struct FixedTarget {
    logical_path: &'static str,
    required: bool,
}

const FIXED_TARGETS: &[FixedTarget] = &[
    FixedTarget {
        logical_path: "/etc/passwd",
        required: true,
    },
    FixedTarget {
        logical_path: "/etc/group",
        required: true,
    },
    FixedTarget {
        logical_path: "/etc/sudoers",
        required: false,
    },
    FixedTarget {
        logical_path: "/etc/ssh/sshd_config",
        required: false,
    },
    FixedTarget {
        logical_path: "/etc/crontab",
        required: false,
    },
];

const DIRECTORY_ROOTS: &[&str] = &[
    "/etc/sudoers.d",
    "/etc/ssh/sshd_config.d",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
];

struct ScanState<'a> {
    cancellation: &'a ScanCancellation,
    deadline: Instant,
    trusted_path_ids: &'a BTreeSet<String>,
    rows: Vec<ObservedEntry>,
    candidate_path_ids: BTreeSet<String>,
    error_counts: BTreeMap<ScanError, u16>,
    unavailable_target_count: u16,
    bytes_read: u64,
    execution_complete: bool,
    observation_complete: bool,
    required_targets_observed: bool,
    observed_at: i64,
    terminal_reason: Option<ScanTerminalReason>,
}

impl<'a> ScanState<'a> {
    fn new(
        cancellation: &'a ScanCancellation,
        deadline: Instant,
        trusted_path_ids: &'a BTreeSet<String>,
        observed_at: i64,
    ) -> Self {
        Self {
            cancellation,
            deadline,
            trusted_path_ids,
            rows: Vec::new(),
            candidate_path_ids: BTreeSet::new(),
            error_counts: BTreeMap::new(),
            unavailable_target_count: 0,
            bytes_read: 0,
            execution_complete: true,
            observation_complete: true,
            required_targets_observed: true,
            observed_at,
            terminal_reason: None,
        }
    }

    fn run(&mut self, physical_root: &Path) {
        if self.trusted_path_ids.len() > MAX_TRACKED_PATHS {
            self.hard_stop(
                ScanError::TrackedFileLimit,
                Some(ScanTerminalReason::TrackedFileLimit),
            );
            return;
        }

        for target in FIXED_TARGETS {
            if !self.register_logical_path(target.logical_path) {
                return;
            }
        }
        for logical_path in DIRECTORY_ROOTS {
            if !self.register_logical_path(logical_path) {
                return;
            }
        }

        if self.check_stop() {
            return;
        }
        let root_fd = match open_absolute_directory(physical_root) {
            Ok(fd) => fd,
            Err(_) => {
                self.record_error(ScanError::IoError);
                self.hard_stop_without_error(Some(ScanTerminalReason::InternalError));
                return;
            }
        };

        for target in FIXED_TARGETS {
            if !self.scan_fixed(root_fd.as_raw_fd(), *target) {
                return;
            }
        }
        for logical_path in DIRECTORY_ROOTS {
            if !self.scan_directory(root_fd.as_raw_fd(), logical_path) {
                return;
            }
        }
    }

    fn scan_fixed(&mut self, root_fd: RawFd, target: FixedTarget) -> bool {
        let (parent_fd, name) = match self.open_parent(root_fd, target.logical_path) {
            Ok(value) => value,
            Err(OpenPathError::Absent) => {
                self.push_absent(target.logical_path, TargetKind::Fixed);
                if target.required {
                    self.mark_required_unavailable(ScanError::NotRegular);
                }
                return true;
            }
            Err(OpenPathError::Stopped) => return false,
            Err(error) => {
                let observation_error = path_error_for_open(error);
                self.push_path_error(
                    target.logical_path,
                    TargetKind::Fixed,
                    observation_error,
                    target.required,
                );
                return true;
            }
        };

        if self.check_stop() {
            return false;
        }
        let fd = match openat_owned(
            parent_fd.as_raw_fd(),
            &name,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        ) {
            Ok(fd) => fd,
            Err(error) => {
                match classify_final_open_error(parent_fd.as_raw_fd(), &name, &error) {
                    OpenPathError::Absent => {
                        self.push_absent(target.logical_path, TargetKind::Fixed);
                        if target.required {
                            self.mark_required_unavailable(ScanError::NotRegular);
                        }
                    }
                    OpenPathError::Stopped => return false,
                    classified => self.push_path_error(
                        target.logical_path,
                        TargetKind::Fixed,
                        path_error_for_open(classified),
                        target.required,
                    ),
                }
                return true;
            }
        };

        self.observe_file(target.logical_path, TargetKind::Fixed, fd, target.required)
    }

    fn scan_directory(&mut self, root_fd: RawFd, logical_path: &str) -> bool {
        let (parent_fd, name) = match self.open_parent(root_fd, logical_path) {
            Ok(value) => value,
            Err(OpenPathError::Absent) => {
                self.push_absent(logical_path, TargetKind::DirectoryRoot);
                return true;
            }
            Err(OpenPathError::Stopped) => return false,
            Err(error) => {
                self.mark_directory_unavailable(error);
                return true;
            }
        };

        if self.check_stop() {
            return false;
        }
        let directory_fd = match openat_owned(
            parent_fd.as_raw_fd(),
            &name,
            libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
        ) {
            Ok(fd) => fd,
            Err(error) => {
                let classified = classify_final_open_error(parent_fd.as_raw_fd(), &name, &error);
                match classified {
                    OpenPathError::Absent => {
                        self.push_absent(logical_path, TargetKind::DirectoryRoot)
                    }
                    OpenPathError::Stopped => return false,
                    OpenPathError::NotRegular | OpenPathError::Symlink => {
                        if !self.observe_wrong_directory_root(
                            parent_fd.as_raw_fd(),
                            &name,
                            logical_path,
                        ) {
                            return false;
                        }
                    }
                    other => self.mark_directory_unavailable(other),
                }
                return true;
            }
        };

        let directory_stat = match fstat_fd(directory_fd.as_raw_fd()) {
            Ok(stat) if file_type(&stat) == FileType::Directory => stat,
            Ok(_) => {
                self.mark_coverage_unavailable(ScanError::NotRegular);
                return true;
            }
            Err(_) => {
                self.mark_coverage_unavailable(ScanError::IoError);
                return true;
            }
        };
        if let Err(error) = allowed_filesystem(directory_fd.as_raw_fd()) {
            self.mark_coverage_unavailable(error);
            return true;
        }

        if self.check_stop() {
            return false;
        }
        let enumeration_fd = match openat_owned(
            directory_fd.as_raw_fd(),
            dot_cstring(),
            libc::O_RDONLY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_DIRECTORY,
        ) {
            Ok(fd) => fd,
            Err(error) if is_permission_denied(&error) => {
                self.mark_coverage_unavailable(ScanError::DirectoryUnreadable);
                return true;
            }
            Err(_) => {
                self.mark_coverage_unavailable(ScanError::IoError);
                return true;
            }
        };
        if let Err(error) = allowed_filesystem(enumeration_fd.as_raw_fd()) {
            self.mark_coverage_unavailable(error);
            return true;
        }

        let child_names = match self.enumerate_children(enumeration_fd, logical_path) {
            Ok(Some(names)) => names,
            Ok(None) => return true,
            Err(()) => return false,
        };
        self.push_entry(ObservedEntry {
            path_id: stable_path_id(logical_path),
            logical_path: logical_path.to_owned(),
            target_kind: TargetKind::DirectoryRoot,
            entry_state: EntryState::Directory,
            content_digest: None,
            metadata: directory_metadata(&directory_stat),
            observation_error: None,
        });

        for child_name in child_names {
            if !self.scan_child(directory_fd.as_raw_fd(), logical_path, &child_name) {
                return false;
            }
        }
        true
    }

    fn enumerate_children(
        &mut self,
        enumeration_fd: OwnedFd,
        logical_root: &str,
    ) -> Result<Option<Vec<String>>, ()> {
        let mut stream = match DirectoryStream::new(enumeration_fd) {
            Ok(stream) => stream,
            Err(_) => {
                self.mark_coverage_unavailable(ScanError::IoError);
                return Ok(None);
            }
        };
        let mut names = Vec::new();
        loop {
            if self.check_stop() {
                return Err(());
            }
            let raw_name = match stream.next_name() {
                Ok(Some(name)) => name,
                Ok(None) => break,
                Err(_) => {
                    self.hard_stop(ScanError::IoError, None);
                    return Err(());
                }
            };
            if raw_name.as_slice() == b"." || raw_name.as_slice() == b".." {
                continue;
            }
            let child_name = match String::from_utf8(raw_name) {
                Ok(name) if valid_child_name(&name) => name,
                Ok(_) => {
                    self.hard_stop(ScanError::PathTooLong, None);
                    return Err(());
                }
                Err(_) => {
                    self.hard_stop(ScanError::PathNotUtf8, None);
                    return Err(());
                }
            };
            let logical_path = format!("{logical_root}/{child_name}");
            if logical_path.len() > MAX_LOGICAL_PATH_BYTES {
                self.hard_stop(ScanError::PathTooLong, None);
                return Err(());
            }
            if !self.register_logical_path(&logical_path) {
                return Err(());
            }
            names.push(child_name);
        }
        names.sort_unstable();
        Ok(Some(names))
    }

    fn scan_child(&mut self, directory_fd: RawFd, logical_root: &str, name: &str) -> bool {
        let logical_path = format!("{logical_root}/{name}");
        let c_name = match CString::new(name.as_bytes()) {
            Ok(name) => name,
            Err(_) => {
                self.hard_stop(ScanError::PathTooLong, None);
                return false;
            }
        };
        if self.check_stop() {
            return false;
        }
        let fd = match openat_owned(
            directory_fd,
            &c_name,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        ) {
            Ok(fd) => fd,
            Err(error) => {
                let classified = classify_final_open_error(directory_fd, &c_name, &error);
                let observation_error = if classified == OpenPathError::Absent {
                    PathObservationError::VanishedDuringScan
                } else {
                    path_error_for_open(classified)
                };
                self.push_path_error(
                    &logical_path,
                    TargetKind::DirectoryChild,
                    observation_error,
                    false,
                );
                return true;
            }
        };
        self.observe_file(&logical_path, TargetKind::DirectoryChild, fd, false)
    }

    fn observe_file(
        &mut self,
        logical_path: &str,
        target_kind: TargetKind,
        fd: OwnedFd,
        required: bool,
    ) -> bool {
        let before = match fstat_fd(fd.as_raw_fd()) {
            Ok(stat) => stat,
            Err(_) => {
                self.push_path_error(
                    logical_path,
                    target_kind,
                    PathObservationError::IoError,
                    required,
                );
                return true;
            }
        };
        match file_type(&before) {
            FileType::Regular | FileType::Directory => {
                if let Err(error) = allowed_filesystem(fd.as_raw_fd()) {
                    self.mark_coverage_unavailable(error);
                    if required {
                        self.required_targets_observed = false;
                    }
                    return true;
                }
            }
            FileType::Other => {
                self.push_path_error(
                    logical_path,
                    target_kind,
                    PathObservationError::NotRegular,
                    required,
                );
                return true;
            }
        }

        if file_type(&before) == FileType::Directory {
            self.mark_coverage_unavailable(ScanError::NotRegular);
            if required {
                self.required_targets_observed = false;
            }
            self.push_entry(ObservedEntry {
                path_id: stable_path_id(logical_path),
                logical_path: logical_path.to_owned(),
                target_kind,
                entry_state: EntryState::Directory,
                content_digest: None,
                metadata: directory_metadata(&before),
                observation_error: None,
            });
            return true;
        }

        self.read_regular(logical_path, target_kind, fd, before, required)
    }

    fn read_regular(
        &mut self,
        logical_path: &str,
        target_kind: TargetKind,
        fd: OwnedFd,
        before: libc::stat,
        required: bool,
    ) -> bool {
        let Some(initial_size) = nonnegative_size(&before) else {
            self.push_path_error(
                logical_path,
                target_kind,
                PathObservationError::IoError,
                required,
            );
            return true;
        };
        if initial_size > MAX_FILE_BYTES {
            self.push_regular_error(
                logical_path,
                target_kind,
                &before,
                PathObservationError::FileTooLarge,
                required,
            );
            return true;
        }
        if self
            .bytes_read
            .checked_add(initial_size)
            .is_none_or(|total| total > MAX_SCAN_BYTES)
        {
            self.hard_stop(
                ScanError::ScanByteLimit,
                Some(ScanTerminalReason::ScanByteLimit),
            );
            return false;
        }

        let mut file = File::from(fd);
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; READ_BUFFER_BYTES];
        let mut file_bytes = 0_u64;
        loop {
            if self.check_stop() {
                return false;
            }
            if file_bytes == initial_size {
                break;
            }
            let remaining_file = initial_size - file_bytes;
            let remaining_scan = MAX_SCAN_BYTES - self.bytes_read;
            let read_len = remaining_file
                .min(remaining_scan)
                .min(READ_BUFFER_BYTES as u64) as usize;
            if read_len == 0 {
                self.hard_stop(
                    ScanError::ScanByteLimit,
                    Some(ScanTerminalReason::ScanByteLimit),
                );
                return false;
            }
            let bytes = match file.read(&mut buffer[..read_len]) {
                Ok(0) => break,
                Ok(bytes) => bytes,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    self.push_regular_error(
                        logical_path,
                        target_kind,
                        &before,
                        PathObservationError::IoError,
                        required,
                    );
                    return true;
                }
            };
            self.bytes_read += bytes as u64;
            file_bytes += bytes as u64;
            if self.check_stop() {
                return false;
            }
            hasher.update(&buffer[..bytes]);
        }

        let after = match fstat_fd(file.as_raw_fd()) {
            Ok(stat) => stat,
            Err(_) => {
                self.push_regular_error(
                    logical_path,
                    target_kind,
                    &before,
                    PathObservationError::IoError,
                    required,
                );
                return true;
            }
        };
        if file_bytes != initial_size || !same_open_file(&before, &after) {
            let error = if nonnegative_size(&after).is_some_and(|size| size > MAX_FILE_BYTES) {
                PathObservationError::FileTooLarge
            } else {
                PathObservationError::ChangedDuringRead
            };
            self.push_regular_error(logical_path, target_kind, &after, error, required);
            return true;
        }

        let digest: [u8; 32] = hasher.finalize().into();
        self.push_entry(ObservedEntry {
            path_id: stable_path_id(logical_path),
            logical_path: logical_path.to_owned(),
            target_kind,
            entry_state: EntryState::Regular,
            content_digest: Some(digest),
            metadata: regular_metadata(&after),
            observation_error: None,
        });
        true
    }

    fn observe_wrong_directory_root(
        &mut self,
        parent_fd: RawFd,
        name: &CStr,
        logical_path: &str,
    ) -> bool {
        if self.check_stop() {
            return false;
        }
        let fd = match openat_owned(
            parent_fd,
            name,
            libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        ) {
            Ok(fd) => fd,
            Err(error) => {
                let classified = classify_final_open_error(parent_fd, name, &error);
                if classified == OpenPathError::Absent {
                    self.push_absent(logical_path, TargetKind::DirectoryRoot);
                } else {
                    self.mark_directory_unavailable(classified);
                }
                return true;
            }
        };
        let stat = match fstat_fd(fd.as_raw_fd()) {
            Ok(stat) => stat,
            Err(_) => {
                self.mark_coverage_unavailable(ScanError::IoError);
                return true;
            }
        };
        match file_type(&stat) {
            FileType::Regular => {
                if let Err(error) = allowed_filesystem(fd.as_raw_fd()) {
                    self.mark_coverage_unavailable(error);
                    return true;
                }
                self.mark_coverage_unavailable(ScanError::NotRegular);
                self.push_entry(ObservedEntry {
                    path_id: stable_path_id(logical_path),
                    logical_path: logical_path.to_owned(),
                    target_kind: TargetKind::DirectoryRoot,
                    entry_state: EntryState::Regular,
                    content_digest: None,
                    metadata: regular_metadata(&stat),
                    observation_error: None,
                });
            }
            FileType::Directory => self.mark_coverage_unavailable(ScanError::IoError),
            FileType::Other => {
                let error = if is_symlink(&stat) {
                    ScanError::Symlink
                } else {
                    ScanError::NotRegular
                };
                self.mark_coverage_unavailable(error);
            }
        }
        true
    }

    fn open_parent(
        &mut self,
        root_fd: RawFd,
        logical_path: &str,
    ) -> Result<(OwnedFd, CString), OpenPathError> {
        let mut components = logical_path.trim_start_matches('/').split('/').peekable();
        let mut current: Option<OwnedFd> = None;
        while let Some(component) = components.next() {
            let name =
                CString::new(component.as_bytes()).map_err(|_| OpenPathError::PathTooLong)?;
            if components.peek().is_none() {
                let parent = current.ok_or(OpenPathError::NotRegular)?;
                return Ok((parent, name));
            }
            if self.check_stop() {
                return Err(OpenPathError::Stopped);
            }
            let parent_fd = current.as_ref().map_or(root_fd, AsRawFd::as_raw_fd);
            let next = openat_owned(
                parent_fd,
                &name,
                libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
            )
            .map_err(|error| classify_final_open_error(parent_fd, &name, &error))?;
            current = Some(next);
        }
        Err(OpenPathError::NotRegular)
    }

    fn push_absent(&mut self, logical_path: &str, target_kind: TargetKind) {
        self.push_entry(ObservedEntry {
            path_id: stable_path_id(logical_path),
            logical_path: logical_path.to_owned(),
            target_kind,
            entry_state: EntryState::Absent,
            content_digest: None,
            metadata: FileMetadata::ABSENT,
            observation_error: None,
        });
    }

    fn push_path_error(
        &mut self,
        logical_path: &str,
        target_kind: TargetKind,
        error: PathObservationError,
        required: bool,
    ) {
        self.observation_complete = false;
        if required {
            self.required_targets_observed = false;
        }
        self.unavailable_target_count = self.unavailable_target_count.saturating_add(1).min(256);
        self.record_error(error.into());
        self.push_entry(ObservedEntry {
            path_id: stable_path_id(logical_path),
            logical_path: logical_path.to_owned(),
            target_kind,
            entry_state: EntryState::Absent,
            content_digest: None,
            metadata: FileMetadata::ABSENT,
            observation_error: Some(error),
        });
    }

    fn push_regular_error(
        &mut self,
        logical_path: &str,
        target_kind: TargetKind,
        stat: &libc::stat,
        error: PathObservationError,
        required: bool,
    ) {
        self.observation_complete = false;
        if required {
            self.required_targets_observed = false;
        }
        self.unavailable_target_count = self.unavailable_target_count.saturating_add(1).min(256);
        self.record_error(error.into());
        self.push_entry(ObservedEntry {
            path_id: stable_path_id(logical_path),
            logical_path: logical_path.to_owned(),
            target_kind,
            entry_state: EntryState::Regular,
            content_digest: None,
            metadata: regular_metadata(stat),
            observation_error: Some(error),
        });
    }

    fn mark_required_unavailable(&mut self, error: ScanError) {
        self.required_targets_observed = false;
        self.mark_coverage_unavailable(error);
    }

    fn mark_directory_unavailable(&mut self, error: OpenPathError) {
        let error = match error {
            OpenPathError::PermissionDenied => ScanError::DirectoryUnreadable,
            OpenPathError::Symlink => ScanError::Symlink,
            OpenPathError::NotRegular => ScanError::NotRegular,
            OpenPathError::PathTooLong => ScanError::PathTooLong,
            OpenPathError::Absent => return,
            OpenPathError::Stopped => return,
            OpenPathError::IoError => ScanError::IoError,
        };
        self.mark_coverage_unavailable(error);
    }

    fn mark_coverage_unavailable(&mut self, error: ScanError) {
        self.observation_complete = false;
        self.unavailable_target_count = self.unavailable_target_count.saturating_add(1).min(256);
        self.record_error(error);
    }

    fn push_entry(&mut self, entry: ObservedEntry) {
        self.rows.push(entry);
    }

    fn register_logical_path(&mut self, logical_path: &str) -> bool {
        let Some(path_id) = file_integrity_path_id(logical_path) else {
            self.hard_stop(ScanError::PathTooLong, None);
            return false;
        };
        self.candidate_path_ids.insert(path_id);
        let union_count = self
            .candidate_path_ids
            .union(self.trusted_path_ids)
            .take(MAX_TRACKED_PATHS + 1)
            .count();
        if union_count > MAX_TRACKED_PATHS {
            self.hard_stop(
                ScanError::TrackedFileLimit,
                Some(ScanTerminalReason::TrackedFileLimit),
            );
            return false;
        }
        true
    }

    fn check_stop(&mut self) -> bool {
        if self.cancellation.is_cancelled() {
            self.hard_stop(ScanError::Cancelled, Some(ScanTerminalReason::Cancelled));
            return true;
        }
        if Instant::now() >= self.deadline {
            self.hard_stop(
                ScanError::DeadlineExceeded,
                Some(ScanTerminalReason::DeadlineExceeded),
            );
            return true;
        }
        false
    }

    fn hard_stop(&mut self, error: ScanError, terminal_reason: Option<ScanTerminalReason>) {
        self.record_error(error);
        self.hard_stop_without_error(terminal_reason);
    }

    fn hard_stop_without_error(&mut self, terminal_reason: Option<ScanTerminalReason>) {
        self.rows.clear();
        self.execution_complete = false;
        self.observation_complete = false;
        self.required_targets_observed = false;
        self.unavailable_target_count = self.unavailable_target_count.saturating_add(1).min(256);
        self.terminal_reason = terminal_reason;
    }

    fn record_error(&mut self, error: ScanError) {
        let count = self.error_counts.entry(error).or_insert(0);
        *count = count.saturating_add(1).min(MAX_TRACKED_PATHS as u16);
    }

    fn finish(mut self) -> ScanResult {
        self.rows
            .sort_by(|left, right| left.path_id.cmp(&right.path_id));
        ScanResult {
            rows: self.rows,
            execution_complete: self.execution_complete,
            observation_complete: self.observation_complete,
            required_targets_observed: self.required_targets_observed,
            errors: self
                .error_counts
                .into_iter()
                .map(|(error, count)| ScanErrorCount { error, count })
                .collect(),
            unavailable_target_count: self.unavailable_target_count,
            bytes_read: self.bytes_read,
            observed_at: self.observed_at,
            terminal_reason: self.terminal_reason,
        }
    }
}

pub(crate) fn file_integrity_path_id(logical_path: &str) -> Option<String> {
    if !valid_logical_path(logical_path) {
        return None;
    }
    Some(compute_path_id(logical_path))
}

fn compute_path_id(logical_path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PATH_ID_DOMAIN);
    hasher.update(logical_path.as_bytes());
    let digest = hasher.finalize();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut path_id = String::with_capacity("path-v1:".len() + digest.len() * 2);
    path_id.push_str("path-v1:");
    for byte in digest {
        path_id.push(char::from(HEX[usize::from(byte >> 4)]));
        path_id.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    path_id
}

fn valid_logical_path(logical_path: &str) -> bool {
    if logical_path.len() > MAX_LOGICAL_PATH_BYTES || !logical_path.starts_with('/') {
        return false;
    }
    if FIXED_TARGETS
        .iter()
        .any(|target| target.logical_path == logical_path)
        || DIRECTORY_ROOTS.contains(&logical_path)
    {
        return true;
    }
    DIRECTORY_ROOTS.iter().any(|root| {
        logical_path
            .strip_prefix(root)
            .and_then(|suffix| suffix.strip_prefix('/'))
            .is_some_and(valid_child_name)
    })
}

fn valid_child_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.chars().any(char::is_control)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenPathError {
    Absent,
    PermissionDenied,
    Symlink,
    NotRegular,
    PathTooLong,
    IoError,
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileType {
    Regular,
    Directory,
    Other,
}

fn path_error_for_open(error: OpenPathError) -> PathObservationError {
    match error {
        OpenPathError::PermissionDenied => PathObservationError::PermissionDenied,
        OpenPathError::Symlink => PathObservationError::Symlink,
        OpenPathError::Absent => PathObservationError::VanishedDuringScan,
        OpenPathError::NotRegular | OpenPathError::PathTooLong => PathObservationError::NotRegular,
        OpenPathError::IoError | OpenPathError::Stopped => PathObservationError::IoError,
    }
}

fn stable_path_id(logical_path: &str) -> String {
    debug_assert!(valid_logical_path(logical_path));
    // Callers construct paths exclusively from the immutable allowlist and a
    // previously validated direct-child basename.
    compute_path_id(logical_path)
}

fn open_absolute_directory(path: &Path) -> io::Result<OwnedFd> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    open_owned(
        &path,
        libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
    )
}

fn open_owned(path: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: `path` is NUL-terminated and the returned descriptor is adopted
    // exactly once when `open` succeeds.
    let fd = unsafe { libc::open(path.as_ptr(), flags) };
    owned_fd_from_result(fd)
}

fn openat_owned(dir_fd: RawFd, path: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: `dir_fd` is a live descriptor owned by the caller, `path` is
    // NUL-terminated, and the new descriptor is adopted exactly once.
    let fd = unsafe { libc::openat(dir_fd, path.as_ptr(), flags) };
    owned_fd_from_result(fd)
}

fn owned_fd_from_result(fd: libc::c_int) -> io::Result<OwnedFd> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: a non-negative result from open/openat is a newly owned fd.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn classify_final_open_error(dir_fd: RawFd, name: &CStr, error: &io::Error) -> OpenPathError {
    match error.raw_os_error() {
        Some(libc::ENOENT) => OpenPathError::Absent,
        Some(libc::EACCES) | Some(libc::EPERM) => OpenPathError::PermissionDenied,
        Some(libc::ENAMETOOLONG) => OpenPathError::PathTooLong,
        Some(libc::ELOOP) => OpenPathError::Symlink,
        Some(libc::ENOTDIR) | Some(libc::ENXIO) | Some(libc::ENODEV) => {
            match fstatat_nofollow(dir_fd, name) {
                Ok(stat) if is_symlink(&stat) => OpenPathError::Symlink,
                Ok(_) => OpenPathError::NotRegular,
                Err(stat_error) if stat_error.raw_os_error() == Some(libc::ENOENT) => {
                    OpenPathError::Absent
                }
                Err(stat_error) if is_permission_denied(&stat_error) => {
                    OpenPathError::PermissionDenied
                }
                Err(_) => OpenPathError::IoError,
            }
        }
        _ => match fstatat_nofollow(dir_fd, name) {
            Ok(stat) if is_symlink(&stat) => OpenPathError::Symlink,
            Ok(stat) if file_type(&stat) == FileType::Other => OpenPathError::NotRegular,
            _ => OpenPathError::IoError,
        },
    }
}

fn fstat_fd(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: zero is a valid initial byte representation for `stat`, and
    // `fstat` initializes it before success is returned.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: `fd` is live for this call and `stat` points to writable storage.
    if unsafe { libc::fstat(fd, &mut stat) } == 0 {
        Ok(stat)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn fstatat_nofollow(dir_fd: RawFd, name: &CStr) -> io::Result<libc::stat> {
    // SAFETY: zero is a valid initial byte representation for `stat`, and
    // `fstatat` initializes it before success is returned.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: `dir_fd` and `name` remain valid for the call, and the output
    // pointer references writable storage.
    if unsafe { libc::fstatat(dir_fd, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } == 0 {
        Ok(stat)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn file_type(stat: &libc::stat) -> FileType {
    match stat.st_mode & libc::S_IFMT {
        libc::S_IFREG => FileType::Regular,
        libc::S_IFDIR => FileType::Directory,
        _ => FileType::Other,
    }
}

fn is_symlink(stat: &libc::stat) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFLNK
}

fn nonnegative_size(stat: &libc::stat) -> Option<u64> {
    u64::try_from(stat.st_size).ok()
}

fn regular_metadata(stat: &libc::stat) -> FileMetadata {
    FileMetadata {
        size_bytes: nonnegative_size(stat),
        mtime_unix_seconds: Some(stat.st_mtime),
        mode: Some(stat.st_mode & 0o7777),
        uid: Some(stat.st_uid),
        gid: Some(stat.st_gid),
    }
}

fn directory_metadata(stat: &libc::stat) -> FileMetadata {
    FileMetadata {
        size_bytes: None,
        mtime_unix_seconds: None,
        mode: Some(stat.st_mode & 0o7777),
        uid: Some(stat.st_uid),
        gid: Some(stat.st_gid),
    }
}

fn same_open_file(before: &libc::stat, after: &libc::stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_size == after.st_size
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

fn allowed_filesystem(fd: RawFd) -> Result<(), ScanError> {
    // SAFETY: zero is a valid initial byte representation for `statfs`, and
    // `fstatfs` initializes it before success is returned.
    let mut statfs = unsafe { std::mem::zeroed::<libc::statfs>() };
    // SAFETY: `fd` is live and the output pointer references writable storage.
    if unsafe { libc::fstatfs(fd, &mut statfs) } != 0 {
        return Err(ScanError::IoError);
    }
    classify_filesystem_magic(statfs.f_type as u64)
}

fn classify_filesystem_magic(magic: u64) -> Result<(), ScanError> {
    if LOCAL_FILESYSTEM_MAGICS.contains(&magic) {
        Ok(())
    } else if NETWORK_OR_FUSE_FILESYSTEM_MAGICS.contains(&magic) {
        Err(ScanError::NetworkFilesystem)
    } else {
        Err(ScanError::FilesystemUnclassified)
    }
}

// Closed Linux filesystem registry v1. ext2/3/4 share EXT_SUPER_MAGIC.
const LOCAL_FILESYSTEM_MAGICS: &[u64] = &[
    0x0000_ef53, // ext2/3/4
    0x5846_5342, // xfs
    0x9123_683e, // btrfs
    0xf2f5_2010, // f2fs
    0x2fc1_2fc1, // zfs
    0x0102_1994, // tmpfs
    0x8584_58f6, // ramfs
    0x794c_7630, // overlayfs
    0x7371_7368, // squashfs
];

const NETWORK_OR_FUSE_FILESYSTEM_MAGICS: &[u64] = &[
    0x0000_6969, // nfs
    0xff53_4d42, // cifs/smb
    0x517b,      // smb
    0x7375_7245, // coda
    0x5346_414f, // afs
    0x0000_564c, // ncp
    0x0102_1997, // 9p
    0x00c3_6400, // ceph
    0x6573_5546, // fuse
    0x6573_5543, // fusectl
];

fn is_permission_denied(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EACCES) | Some(libc::EPERM))
}

fn dot_cstring() -> &'static CStr {
    c"."
}

struct DirectoryStream(*mut libc::DIR);

impl DirectoryStream {
    fn new(fd: OwnedFd) -> io::Result<Self> {
        let raw_fd = fd.into_raw_fd();
        // SAFETY: ownership of `raw_fd` is transferred to `fdopendir` on
        // success. On failure we reconstruct and immediately drop it.
        let directory = unsafe { libc::fdopendir(raw_fd) };
        if directory.is_null() {
            // SAFETY: fdopendir failed and therefore did not take ownership.
            drop(unsafe { OwnedFd::from_raw_fd(raw_fd) });
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(directory))
        }
    }

    fn next_name(&mut self) -> io::Result<Option<Vec<u8>>> {
        // Linux exposes thread-local errno through `__errno_location`.
        // SAFETY: the returned pointer is valid for the current thread.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: `self.0` is a live DIR pointer owned by this object.
        let entry = unsafe { libc::readdir(self.0) };
        if entry.is_null() {
            // SAFETY: the errno pointer is valid for the current thread.
            let errno = unsafe { *libc::__errno_location() };
            return if errno == 0 {
                Ok(None)
            } else {
                Err(io::Error::from_raw_os_error(errno))
            };
        }
        // SAFETY: readdir returned a live entry whose d_name is NUL-terminated
        // until the next call on this DIR stream; copy it immediately.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        Ok(Some(name.to_bytes().to_vec()))
    }
}

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: this object uniquely owns the live DIR pointer.
        let _ = unsafe { libc::closedir(self.0) };
    }
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CString, OsString};
    use std::fs::{self, FileTimes, OpenOptions};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    struct TempRoot {
        path: PathBuf,
    }

    impl TempRoot {
        fn new(label: &str) -> Self {
            let id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "mini-ops-integrity-{label}-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create integrity fixture root");
            Self { path }
        }

        fn physical(&self, logical_path: &str) -> PathBuf {
            self.path.join(logical_path.trim_start_matches('/'))
        }

        fn create_dir(&self, logical_path: &str) {
            fs::create_dir_all(self.physical(logical_path)).expect("create fixture directory");
        }

        fn write(&self, logical_path: &str, contents: &[u8]) {
            let path = self.physical(logical_path);
            fs::create_dir_all(path.parent().expect("fixture path has parent"))
                .expect("create fixture parent");
            fs::write(path, contents).expect("write fixture file");
        }

        fn sparse_file(&self, logical_path: &str, size: u64) {
            let path = self.physical(logical_path);
            fs::create_dir_all(path.parent().expect("fixture path has parent"))
                .expect("create fixture parent");
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .expect("create sparse fixture file")
                .set_len(size)
                .expect("size sparse fixture file");
        }

        fn collector(&self) -> FileIntegrityCollector {
            FileIntegrityCollector::for_test_root(self.path.clone())
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn required_fixture(label: &str) -> TempRoot {
        let fixture = TempRoot::new(label);
        fixture.write("/etc/passwd", b"root:x:0:0::/root:/bin/sh\n");
        fixture.write("/etc/group", b"root:x:0:\n");
        fixture
    }

    fn scan(fixture: &TempRoot) -> ScanResult {
        fixture
            .collector()
            .scan(&ScanCancellation::new(), &BTreeSet::new())
    }

    fn row<'a>(result: &'a ScanResult, logical_path: &str) -> &'a ObservedEntry {
        result
            .rows
            .iter()
            .find(|row| row.logical_path == logical_path)
            .expect("expected observed row")
    }

    fn has_error(result: &ScanResult, expected: ScanError) -> bool {
        result
            .errors
            .iter()
            .any(|entry| entry.error == expected && entry.count > 0)
    }

    #[test]
    fn baseline_scan_is_complete_and_path_ids_are_private_and_stable() {
        let fixture = required_fixture("baseline");
        let result = scan(&fixture);

        assert!(result.execution_complete);
        assert!(result.observation_complete);
        assert!(result.required_targets_observed);
        assert!(result.errors.is_empty());
        assert_eq!(
            result.rows.len(),
            FIXED_TARGETS.len() + DIRECTORY_ROOTS.len()
        );
        assert_eq!(row(&result, "/etc/passwd").entry_state, EntryState::Regular);
        assert_eq!(row(&result, "/etc/sudoers").entry_state, EntryState::Absent);
        assert_eq!(
            row(&result, "/etc/cron.daily").entry_state,
            EntryState::Absent
        );

        let first = file_integrity_path_id("/etc/passwd").expect("allowlisted path id");
        let second = file_integrity_path_id("/etc/passwd").expect("stable path id");
        assert_eq!(first, second);
        assert_eq!(first.len(), "path-v1:".len() + 64);
        assert!(first.starts_with("path-v1:"));
        assert!(!first.contains("passwd"));
        assert!(
            first["path-v1:".len()..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        );
        assert!(file_integrity_path_id("/etc/cron.d/job").is_some());
        assert!(file_integrity_path_id("/etc/cron.d/nested/job").is_none());
        assert!(file_integrity_path_id("/tmp/not-allowlisted").is_none());
    }

    #[test]
    fn same_size_same_mtime_content_change_changes_digest() {
        let fixture = required_fixture("same-size");
        fixture.write("/etc/sudoers", b"alpha\n");
        let before = scan(&fixture);
        let before_row = row(&before, "/etc/sudoers");
        let before_digest = before_row.content_digest.expect("initial digest");
        let before_size = before_row.metadata.size_bytes;
        let path = fixture.physical("/etc/sudoers");
        let before_mtime = fs::metadata(&path)
            .and_then(|metadata| metadata.modified())
            .expect("read initial fixture mtime");

        fixture.write("/etc/sudoers", b"omega\n");
        OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open fixture to restore mtime")
            .set_times(FileTimes::new().set_modified(before_mtime))
            .expect("restore fixture mtime");
        let after = scan(&fixture);
        let after_row = row(&after, "/etc/sudoers");

        assert_eq!(after_row.metadata.size_bytes, before_size);
        assert_eq!(
            after_row.metadata.mtime_unix_seconds,
            before_row.metadata.mtime_unix_seconds
        );
        assert_eq!(
            fs::metadata(&path)
                .and_then(|metadata| metadata.modified())
                .expect("read restored fixture mtime"),
            before_mtime
        );
        assert_ne!(after_row.content_digest, Some(before_digest));
        assert!(after.observation_complete);
    }

    #[test]
    fn symlink_and_special_child_are_never_read_or_disclosed() {
        let fixture = required_fixture("nofollow");
        const SENTINEL: &str = "MINI_OPS_RAW_SENTINEL_7d4a";
        let sentinel_path = fixture.physical("/private-target");
        fs::write(&sentinel_path, SENTINEL).expect("write symlink sentinel");
        symlink(&sentinel_path, fixture.physical("/etc/sudoers")).expect("create fixture symlink");
        fixture.create_dir("/etc/cron.d");
        let fifo_path = fixture.physical("/etc/cron.d/blocked-pipe");
        let fifo = CString::new(fifo_path.as_os_str().as_bytes()).expect("fifo fixture path");
        // SAFETY: `fifo` is a valid NUL-terminated path in the disposable tree.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        let result = scan(&fixture);
        assert!(result.execution_complete);
        assert!(!result.observation_complete);
        assert_eq!(
            row(&result, "/etc/sudoers").observation_error,
            Some(PathObservationError::Symlink)
        );
        assert_eq!(
            row(&result, "/etc/cron.d/blocked-pipe").observation_error,
            Some(PathObservationError::NotRegular)
        );
        assert!(has_error(&result, ScanError::Symlink));
        assert!(has_error(&result, ScanError::NotRegular));
        let rendered = format!("{result:?}");
        assert!(!rendered.contains(SENTINEL));
        assert!(!rendered.contains(sentinel_path.to_string_lossy().as_ref()));
    }

    #[test]
    fn directory_scan_is_direct_child_only_and_does_not_recurse() {
        let fixture = required_fixture("direct-child");
        fixture.write("/etc/cron.d/direct", b"direct-content");
        fixture.write("/etc/cron.d/nested/hidden", b"MUST_NOT_BE_READ_OR_REPORTED");

        let result = scan(&fixture);
        assert!(result.execution_complete);
        assert_eq!(
            row(&result, "/etc/cron.d").entry_state,
            EntryState::Directory
        );
        assert_eq!(
            row(&result, "/etc/cron.d/direct").entry_state,
            EntryState::Regular
        );
        assert_eq!(
            row(&result, "/etc/cron.d/nested").entry_state,
            EntryState::Directory
        );
        assert!(
            result
                .rows
                .iter()
                .all(|entry| entry.logical_path != "/etc/cron.d/nested/hidden")
        );
        assert!(!format!("{result:?}").contains("MUST_NOT_BE_READ_OR_REPORTED"));
    }

    #[test]
    fn oversized_file_is_closed_degraded_without_content_read() {
        let fixture = required_fixture("oversized");
        fixture.sparse_file("/etc/sudoers", MAX_FILE_BYTES + 1);
        let required_bytes = fs::metadata(fixture.physical("/etc/passwd"))
            .expect("passwd metadata")
            .len()
            + fs::metadata(fixture.physical("/etc/group"))
                .expect("group metadata")
                .len();

        let result = scan(&fixture);
        assert!(result.execution_complete);
        assert!(!result.observation_complete);
        assert_eq!(result.bytes_read, required_bytes);
        assert_eq!(
            row(&result, "/etc/sudoers").observation_error,
            Some(PathObservationError::FileTooLarge)
        );
        assert!(has_error(&result, ScanError::FileTooLarge));
    }

    #[test]
    fn permission_denial_is_closed_degraded_without_raw_error() {
        assert!(is_permission_denied(&io::Error::from_raw_os_error(
            libc::EACCES
        )));
        assert!(is_permission_denied(&io::Error::from_raw_os_error(
            libc::EPERM
        )));

        // Root intentionally bypasses ordinary Unix mode denial. The mapping
        // assertions above remain deterministic for root-only CI; the actual
        // low-privilege collector path is exercised whenever its supported
        // runtime identity is used.
        if crate::runtime::effective_uid() == 0 {
            return;
        }
        let fixture = required_fixture("permission-denied");
        fixture.write("/etc/sudoers", b"MUST_NOT_BE_READ");
        let path = fixture.physical("/etc/sudoers");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000))
            .expect("remove fixture read permission");

        let result = scan(&fixture);
        assert!(result.execution_complete);
        assert!(!result.observation_complete);
        assert_eq!(
            row(&result, "/etc/sudoers").observation_error,
            Some(PathObservationError::PermissionDenied)
        );
        assert!(has_error(&result, ScanError::PermissionDenied));
        assert!(!format!("{result:?}").contains("MUST_NOT_BE_READ"));
    }

    #[test]
    fn scan_byte_and_union_path_caps_discard_partial_rows() {
        let byte_fixture = TempRoot::new("byte-cap");
        byte_fixture.write("/etc/passwd", b"");
        byte_fixture.write("/etc/group", b"");
        for index in 0..9 {
            byte_fixture.sparse_file(&format!("/etc/cron.d/file-{index:02}"), MAX_FILE_BYTES);
        }
        let byte_result = scan(&byte_fixture);
        assert!(!byte_result.execution_complete);
        assert!(byte_result.rows.is_empty());
        assert_eq!(byte_result.bytes_read, MAX_SCAN_BYTES);
        assert_eq!(
            byte_result.terminal_reason,
            Some(ScanTerminalReason::ScanByteLimit)
        );
        assert!(has_error(&byte_result, ScanError::ScanByteLimit));

        let path_fixture = required_fixture("path-cap");
        for index in 0..246 {
            path_fixture.write(&format!("/etc/cron.d/path-{index:03}"), b"");
        }
        let path_result = scan(&path_fixture);
        assert!(!path_result.execution_complete);
        assert!(path_result.rows.is_empty());
        assert_eq!(
            path_result.terminal_reason,
            Some(ScanTerminalReason::TrackedFileLimit)
        );
        assert!(has_error(&path_result, ScanError::TrackedFileLimit));

        let union_fixture = required_fixture("disjoint-union-cap");
        for index in 0..245 {
            union_fixture.write(&format!("/etc/cron.d/path-{index:03}"), b"");
        }
        let exact_candidate = scan(&union_fixture);
        assert!(exact_candidate.execution_complete);
        assert_eq!(exact_candidate.rows.len(), MAX_TRACKED_PATHS);
        let candidate_ids = exact_candidate
            .rows
            .iter()
            .map(|entry| entry.path_id.clone())
            .collect::<BTreeSet<_>>();
        let trusted = (0..MAX_TRACKED_PATHS)
            .map(|index| format!("path-v1:{index:064x}"))
            .collect::<BTreeSet<_>>();
        assert!(candidate_ids.is_disjoint(&trusted));
        let union_result = union_fixture
            .collector()
            .scan(&ScanCancellation::new(), &trusted);
        assert!(!union_result.execution_complete);
        assert!(union_result.rows.is_empty());
        assert_eq!(union_result.bytes_read, 0);
        assert!(has_error(&union_result, ScanError::TrackedFileLimit));
    }

    #[test]
    fn cancellation_and_deadline_stop_before_filesystem_reads() {
        let fixture = required_fixture("stop");
        let cancellation = ScanCancellation::new();
        cancellation.cancel();
        let cancelled = fixture.collector().scan(&cancellation, &BTreeSet::new());
        assert!(!cancelled.execution_complete);
        assert!(cancelled.rows.is_empty());
        assert_eq!(cancelled.bytes_read, 0);
        assert_eq!(
            cancelled.terminal_reason,
            Some(ScanTerminalReason::Cancelled)
        );

        let deadline = fixture.collector().scan_until(
            &ScanCancellation::new(),
            Instant::now(),
            &BTreeSet::new(),
        );
        assert!(!deadline.execution_complete);
        assert!(deadline.rows.is_empty());
        assert_eq!(deadline.bytes_read, 0);
        assert_eq!(
            deadline.terminal_reason,
            Some(ScanTerminalReason::DeadlineExceeded)
        );
        assert!(has_error(&deadline, ScanError::DeadlineExceeded));
    }

    #[test]
    fn non_utf8_child_is_partial_without_raw_name_projection() {
        let fixture = required_fixture("non-utf8");
        fixture.create_dir("/etc/cron.d");
        let raw_name = OsString::from_vec(vec![b'b', b'a', b'd', b'-', 0xff]);
        fs::write(fixture.physical("/etc/cron.d").join(raw_name), b"sentinel")
            .expect("write non-UTF8 fixture");

        let result = scan(&fixture);
        assert!(!result.execution_complete);
        assert!(result.rows.is_empty());
        assert!(has_error(&result, ScanError::PathNotUtf8));
    }

    #[test]
    fn control_character_child_is_rejected_before_content_read() {
        let fixture = required_fixture("control-child");
        fixture.write("/etc/cron.d/bad\nname", b"MUST_NOT_BE_READ");

        let result = scan(&fixture);
        assert!(!result.execution_complete);
        assert!(result.rows.is_empty());
        assert!(has_error(&result, ScanError::PathTooLong));
        assert!(!format!("{result:?}").contains("MUST_NOT_BE_READ"));
    }

    fn proc_status_kib(field: &str) -> u64 {
        let status = fs::read_to_string("/proc/self/status").expect("read Linux process status");
        let prefix = format!("{field}:");
        status
            .lines()
            .find_map(|line| {
                line.strip_prefix(&prefix)
                    .and_then(|value| value.split_whitespace().next())
                    .and_then(|value| value.parse().ok())
            })
            .expect("requested process status field")
    }

    fn process_cpu_time() -> Duration {
        let mut value = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `value` points to writable storage for one timespec and the
        // process CPU clock does not depend on external pointers.
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut value) },
            0
        );
        Duration::new(
            u64::try_from(value.tv_sec).expect("non-negative process CPU seconds"),
            u32::try_from(value.tv_nsec).expect("bounded process CPU nanoseconds"),
        )
    }

    #[test]
    #[ignore = "explicit Linux P8.3 resource gate"]
    fn p83_linux_collector_resource_gate() {
        const SCANS: u32 = 10;
        let fixture = required_fixture("resource-gate");
        fixture.write("/etc/sudoers", b"root ALL=(ALL:ALL) ALL\n");
        fixture.write("/etc/ssh/sshd_config", b"PasswordAuthentication no\n");
        fixture.write("/etc/cron.d/mini-ops", b"17 * * * * root true\n");
        let collector = fixture.collector();
        let warmup = collector.scan(&ScanCancellation::new(), &BTreeSet::new());
        assert!(warmup.execution_complete);
        assert!(warmup.observation_complete);

        let baseline_rss_kib = proc_status_kib("VmRSS");
        let baseline_hwm_kib = proc_status_kib("VmHWM");
        let cpu_before = process_cpu_time();
        let mut max_scan = Duration::ZERO;
        for _ in 0..SCANS {
            let started = Instant::now();
            let result = collector.scan(&ScanCancellation::new(), &BTreeSet::new());
            max_scan = max_scan.max(started.elapsed());
            assert!(result.execution_complete);
            assert!(result.observation_complete);
            assert!(result.errors.is_empty());
        }
        let cpu_used = process_cpu_time()
            .checked_sub(cpu_before)
            .expect("monotonic process CPU clock");
        let final_rss_kib = proc_status_kib("VmRSS");
        let peak_hwm_kib = proc_status_kib("VmHWM");
        let peak_delta_kib = peak_hwm_kib
            .saturating_sub(baseline_hwm_kib)
            .max(final_rss_kib.saturating_sub(baseline_rss_kib));
        let average_cpu_percent_at_300s =
            cpu_used.as_secs_f64() / (f64::from(SCANS) * 300.0) * 100.0;

        eprintln!(
            "{}",
            serde_json::json!({
                "scans": SCANS,
                "baseline_rss_kib": baseline_rss_kib,
                "final_rss_kib": final_rss_kib,
                "baseline_hwm_kib": baseline_hwm_kib,
                "peak_hwm_kib": peak_hwm_kib,
                "peak_delta_kib": peak_delta_kib,
                "max_scan_micros": max_scan.as_micros(),
                "process_cpu_micros": cpu_used.as_micros(),
                "average_cpu_percent_at_300s": average_cpu_percent_at_300s,
            })
        );
        assert!(
            peak_delta_kib < 5 * 1024,
            "peak RSS delta: {peak_delta_kib} KiB"
        );
        assert!(max_scan < Duration::from_secs(1), "slow scan: {max_scan:?}");
        assert!(
            average_cpu_percent_at_300s < 1.0,
            "average CPU: {average_cpu_percent_at_300s:.6}%"
        );
    }

    #[test]
    fn filesystem_magic_registry_is_closed() {
        for magic in LOCAL_FILESYSTEM_MAGICS {
            assert_eq!(classify_filesystem_magic(*magic), Ok(()));
        }
        for magic in NETWORK_OR_FUSE_FILESYSTEM_MAGICS {
            assert_eq!(
                classify_filesystem_magic(*magic),
                Err(ScanError::NetworkFilesystem)
            );
        }
        assert_eq!(
            classify_filesystem_magic(0xfeed_f00d),
            Err(ScanError::FilesystemUnclassified)
        );
    }
}
