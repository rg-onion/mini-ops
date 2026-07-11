use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::{
    ffi::{OsStr, OsString},
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    str::FromStr,
};

pub const STANDALONE_DATABASE_URL: &str = "sqlite:mini-ops.db";
pub const MANAGED_DATABASE_URL: &str = "sqlite:///var/lib/mini-ops/mini-ops.db";
pub const STANDALONE_INTERNAL_TOKEN_PATH: &str = "mini-ops-internal.token";
pub const MANAGED_INTERNAL_TOKEN_PATH: &str = "/run/mini-ops/internal.token";

const MANAGED_STATE_DIRECTORY: &str = "/var/lib/mini-ops";
const MANAGED_RUNTIME_DIRECTORY: &str = "/run/mini-ops";
const PRIVATE_FILE_MODE: u32 = 0o600;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeMode {
    Standalone,
    Managed,
}

impl RuntimeMode {
    pub fn detect() -> Self {
        Self::from_state_directory(std::env::var_os("STATE_DIRECTORY").as_deref())
    }

    pub fn from_state_directory(state_directory: Option<&OsStr>) -> Self {
        match state_directory {
            Some(value) if !value.is_empty() => Self::Managed,
            _ => Self::Standalone,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    InvalidDatabaseUrl,
    ManagedDatabaseNotFileBacked,
    DatabaseOutsideManagedState,
    DatabaseConnectFailed,
    UnsafeDatabaseFile,
    DatabasePermissionFailed,
    InvalidInternalTokenPath,
    UnsafeInternalTokenPath,
    InternalTokenWriteFailed,
    InternalTokenSyncFailed,
}

impl RuntimeError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidDatabaseUrl => "invalid_database_url",
            Self::ManagedDatabaseNotFileBacked => "managed_database_not_file_backed",
            Self::DatabaseOutsideManagedState => "database_outside_managed_state",
            Self::DatabaseConnectFailed => "database_connect_failed",
            Self::UnsafeDatabaseFile => "unsafe_database_file",
            Self::DatabasePermissionFailed => "database_permission_failed",
            Self::InvalidInternalTokenPath => "invalid_internal_token_path",
            Self::UnsafeInternalTokenPath => "unsafe_internal_token_path",
            Self::InternalTokenWriteFailed => "internal_token_write_failed",
            Self::InternalTokenSyncFailed => "internal_token_sync_failed",
        }
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidDatabaseUrl => "DATABASE_URL is not a valid SQLite URL",
            Self::ManagedDatabaseNotFileBacked => {
                "managed DATABASE_URL must reference a persistent file-backed database"
            }
            Self::DatabaseOutsideManagedState => {
                "managed DATABASE_URL must resolve inside the private state directory"
            }
            Self::DatabaseConnectFailed => "the configured SQLite database could not be opened",
            Self::UnsafeDatabaseFile => "a SQLite state file is not a safe regular file",
            Self::DatabasePermissionFailed => {
                "private SQLite state-file permissions could not be enforced"
            }
            Self::InvalidInternalTokenPath => {
                "the internal token path is not valid for this runtime mode"
            }
            Self::UnsafeInternalTokenPath => {
                "the internal token path is not a safe regular-file location"
            }
            Self::InternalTokenWriteFailed => "the internal token could not be written atomically",
            Self::InternalTokenSyncFailed => "the internal token could not be durably synchronized",
        };

        formatter.write_str(message)
    }
}

impl std::error::Error for RuntimeError {}

pub fn enforce_private_process_umask() {
    // SAFETY: Mini-Ops sets one process-wide restrictive umask at the start of
    // main, before it creates state files or spawns application tasks.
    unsafe {
        libc::umask(0o077);
    }
}

pub fn resolve_database_url(
    configured: Option<&str>,
    mode: RuntimeMode,
) -> Result<String, RuntimeError> {
    match configured {
        Some(value) if value.trim().is_empty() => Err(RuntimeError::InvalidDatabaseUrl),
        Some(value) => Ok(value.trim().to_owned()),
        None if mode == RuntimeMode::Managed => Ok(MANAGED_DATABASE_URL.to_owned()),
        None => Ok(STANDALONE_DATABASE_URL.to_owned()),
    }
}

pub fn resolve_internal_token_path(
    configured: Option<&OsStr>,
    mode: RuntimeMode,
) -> Result<PathBuf, RuntimeError> {
    let explicitly_configured = configured.is_some();
    let path = match configured {
        Some(value) if value.is_empty() => return Err(RuntimeError::InvalidInternalTokenPath),
        Some(value) => PathBuf::from(value),
        None if mode == RuntimeMode::Managed => PathBuf::from(MANAGED_INTERNAL_TOKEN_PATH),
        None => PathBuf::from(STANDALONE_INTERNAL_TOKEN_PATH),
    };

    if explicitly_configured && !path.is_absolute() {
        return Err(RuntimeError::InvalidInternalTokenPath);
    }

    if mode == RuntimeMode::Managed && !is_managed_path(&path, Path::new(MANAGED_RUNTIME_DIRECTORY))
    {
        return Err(RuntimeError::InvalidInternalTokenPath);
    }

    Ok(path)
}

pub fn sqlite_connect_options(
    database_url: &str,
    mode: RuntimeMode,
) -> Result<SqliteConnectOptions, RuntimeError> {
    let options = SqliteConnectOptions::from_str(database_url)
        .map_err(|_| RuntimeError::InvalidDatabaseUrl)?
        .create_if_missing(true);

    if mode == RuntimeMode::Managed && sqlite_url_is_in_memory(database_url) {
        return Err(RuntimeError::ManagedDatabaseNotFileBacked);
    }

    if mode == RuntimeMode::Managed
        && !is_managed_path(options.get_filename(), Path::new(MANAGED_STATE_DIRECTORY))
    {
        return Err(RuntimeError::DatabaseOutsideManagedState);
    }

    Ok(options)
}

pub async fn connect_sqlite_pool(
    database_url: &str,
    mode: RuntimeMode,
    max_connections: u32,
) -> Result<SqlitePool, RuntimeError> {
    let options = sqlite_connect_options(database_url, mode)?;
    let database_path =
        (!sqlite_url_is_in_memory(database_url)).then(|| options.get_filename().to_owned());
    if let Some(path) = database_path.as_deref() {
        prepare_sqlite_file(path)?;
    }
    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .connect_with(options)
        .await
        .map_err(|_| RuntimeError::DatabaseConnectFailed)?;

    if let Some(path) = database_path.as_deref()
        && let Err(error) = ensure_sqlite_private_files(path)
    {
        pool.close().await;
        return Err(error);
    }

    Ok(pool)
}

pub fn ensure_sqlite_private_database(
    database_url: &str,
    mode: RuntimeMode,
) -> Result<(), RuntimeError> {
    let options = sqlite_connect_options(database_url, mode)?;
    if sqlite_url_is_in_memory(database_url) {
        return Ok(());
    }
    ensure_sqlite_private_files(options.get_filename())
}

pub fn ensure_sqlite_private_files(database_path: &Path) -> Result<(), RuntimeError> {
    validate_private_parent(database_path, RuntimeError::UnsafeDatabaseFile)?;
    harden_sqlite_file(database_path, false)?;
    for suffix in ["-journal", "-wal", "-shm"] {
        harden_sqlite_file(&path_with_suffix(database_path, suffix), true)?;
    }

    Ok(())
}

pub fn write_internal_token_atomic(path: &Path, token: &str) -> Result<(), RuntimeError> {
    if token.is_empty() {
        return Err(RuntimeError::InternalTokenWriteFailed);
    }

    let parent = validate_private_parent(path, RuntimeError::UnsafeInternalTokenPath)?;

    ensure_safe_token_target(path)?;

    let file_name = path
        .file_name()
        .filter(|value| !value.is_empty())
        .ok_or(RuntimeError::InvalidInternalTokenPath)?;
    let temporary_path = parent.join(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        uuid::Uuid::new_v4()
    ));
    let mut cleanup = TemporaryFile::new(temporary_path);

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(cleanup.path())
        .map_err(|_| RuntimeError::InternalTokenWriteFailed)?;
    file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
        .map_err(|_| RuntimeError::InternalTokenWriteFailed)?;
    file.write_all(token.as_bytes())
        .map_err(|_| RuntimeError::InternalTokenWriteFailed)?;
    file.sync_all()
        .map_err(|_| RuntimeError::InternalTokenSyncFailed)?;
    drop(file);

    ensure_safe_token_target(path)?;
    fs::rename(cleanup.path(), path).map_err(|_| RuntimeError::InternalTokenWriteFailed)?;
    cleanup.disarm();

    let target_metadata =
        fs::symlink_metadata(path).map_err(|_| RuntimeError::InternalTokenWriteFailed)?;
    if !owned_private_regular_file(&target_metadata) {
        return Err(RuntimeError::UnsafeInternalTokenPath);
    }

    sync_directory(parent).map_err(|_| RuntimeError::InternalTokenSyncFailed)
}

pub fn persist_and_publish_internal_token<F>(
    path: &Path,
    token: String,
    publish: F,
) -> Result<(), RuntimeError>
where
    F: FnOnce(String),
{
    write_internal_token_atomic(path, &token)?;
    publish(token);
    Ok(())
}

fn sqlite_url_is_in_memory(database_url: &str) -> bool {
    let value = database_url
        .trim()
        .trim_start_matches("sqlite://")
        .trim_start_matches("sqlite:");
    let mut parts = value.splitn(2, '?');
    if parts.next() == Some(":memory:") {
        return true;
    }

    parts.next().is_some_and(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .any(|(key, value)| key == "mode" && value == "memory")
    })
}

fn prepare_sqlite_file(path: &Path) -> Result<(), RuntimeError> {
    let parent = validate_private_parent(path, RuntimeError::UnsafeDatabaseFile)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !owned_regular_file(&metadata) {
                return Err(RuntimeError::UnsafeDatabaseFile);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let file = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .mode(PRIVATE_FILE_MODE)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(path)
                .map_err(|_| RuntimeError::UnsafeDatabaseFile)?;
            file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
                .map_err(|_| RuntimeError::DatabasePermissionFailed)?;
            file.sync_all()
                .map_err(|_| RuntimeError::DatabasePermissionFailed)?;
            drop(file);
            sync_directory(parent).map_err(|_| RuntimeError::DatabasePermissionFailed)?;
        }
        Err(_) => return Err(RuntimeError::UnsafeDatabaseFile),
    }

    harden_sqlite_file(path, false)
}

fn validate_private_parent(path: &Path, error: RuntimeError) -> Result<&Path, RuntimeError> {
    if path.file_name().is_none() {
        return Err(error);
    }
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut current = if parent.is_absolute() {
        PathBuf::from("/")
    } else {
        PathBuf::from(".")
    };

    for component in parent.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => continue,
            std::path::Component::Normal(value) => current.push(value),
            std::path::Component::ParentDir | std::path::Component::Prefix(_) => {
                return Err(error);
            }
        }
        let metadata = fs::symlink_metadata(&current).map_err(|_| error)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(error);
        }
    }

    let metadata = fs::symlink_metadata(parent).map_err(|_| error)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != effective_uid()
        || metadata.gid() != effective_gid()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(error);
    }

    Ok(parent)
}

fn owned_regular_file(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == effective_uid()
        && metadata.gid() == effective_gid()
}

fn owned_private_regular_file(metadata: &fs::Metadata) -> bool {
    owned_regular_file(metadata) && metadata.permissions().mode() & 0o077 == 0
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn effective_gid() -> u32 {
    // SAFETY: getegid has no preconditions and cannot fail.
    unsafe { libc::getegid() }
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?
        .sync_all()
}

fn is_managed_path(path: &Path, root: &Path) -> bool {
    if !path.is_absolute() || path == root {
        return false;
    }

    path.strip_prefix(root).is_ok_and(|relative| {
        relative
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
    })
}

fn harden_sqlite_file(path: &Path, optional: bool) -> Result<(), RuntimeError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if optional && error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(RuntimeError::DatabasePermissionFailed),
    };

    if !owned_regular_file(&metadata) {
        return Err(RuntimeError::UnsafeDatabaseFile);
    }

    match fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_FILE_MODE)) {
        Ok(()) => {}
        Err(error) if optional && error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(RuntimeError::DatabasePermissionFailed),
    }

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) if owned_regular_file(&metadata) => metadata,
        Err(error) if optional && error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        _ => return Err(RuntimeError::UnsafeDatabaseFile),
    };
    if !owned_private_regular_file(&metadata) {
        return Err(RuntimeError::DatabasePermissionFailed);
    }

    Ok(())
}

fn ensure_safe_token_target(path: &Path) -> Result<(), RuntimeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if owned_private_regular_file(&metadata) => Ok(()),
        Ok(_) => Err(RuntimeError::UnsafeInternalTokenPath),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(RuntimeError::UnsafeInternalTokenPath),
    }
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = OsString::from(path.as_os_str());
    value.push(suffix);
    PathBuf::from(value)
}

struct TemporaryFile {
    path: PathBuf,
    armed: bool,
}

impl TemporaryFile {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::time::Duration;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "mini-ops-runtime-{label}-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&path).expect("create test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("set test-directory mode");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn runtime_mode_uses_systemd_state_directory_presence() {
        assert_eq!(
            RuntimeMode::from_state_directory(None),
            RuntimeMode::Standalone
        );
        assert_eq!(
            RuntimeMode::from_state_directory(Some(OsStr::new(""))),
            RuntimeMode::Standalone
        );
        assert_eq!(
            RuntimeMode::from_state_directory(Some(OsStr::new("/var/lib/mini-ops"))),
            RuntimeMode::Managed
        );
    }

    #[test]
    fn managed_systemd_unit_keeps_code_read_only_and_state_private() {
        let unit = include_str!("../scripts/mini-ops.service");
        for directive in [
            "User=miniops",
            "Group=miniops",
            "WorkingDirectory=/var/lib/mini-ops",
            "ExecStart=/opt/mini-ops/mini-ops",
            "StateDirectory=mini-ops",
            "StateDirectoryMode=0700",
            "RuntimeDirectory=mini-ops",
            "RuntimeDirectoryMode=0700",
            "UMask=0077",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "ReadWritePaths=/var/lib/mini-ops /run/mini-ops",
        ] {
            assert!(unit.lines().any(|line| line == directive), "{directive}");
        }
        assert!(!unit.contains("SupplementaryGroups=docker"));
        assert!(!unit.contains("ReadWritePaths=/opt/mini-ops"));
    }

    #[tokio::test]
    async fn legacy_deploy_scripts_fail_before_build_or_network_activity() {
        for script in ["scripts/deploy.sh", "scripts/provision.sh"] {
            let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(script);
            let output = tokio::process::Command::new("/bin/bash")
                .arg(path)
                .env_clear()
                .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
                .kill_on_drop(true)
                .output()
                .await
                .expect("run disabled deploy script fixture");
            assert!(!output.status.success(), "{script} must remain disabled");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("disabled"),
                "{script} must explain its hard stop"
            );
            assert!(output.stdout.is_empty());
        }
    }

    #[tokio::test]
    async fn managed_bootstrap_dry_run_keeps_safe_defaults_without_network() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/bootstrap_server.sh");
        let output = tokio::process::Command::new("/bin/bash")
            .arg(path)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("DEPLOY_HOST", "192.0.2.10")
            .env("DEPLOY_DRY_RUN", "1")
            .kill_on_drop(true)
            .output()
            .await
            .expect("run managed bootstrap dry-run fixture");
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let plan = String::from_utf8_lossy(&output.stdout);
        for boundary in [
            "app-user=miniops app-bind=127.0.0.1:3000",
            "host-key=strict-existing-key",
            "docker=unchanged nginx=disabled firewall=unchanged ssh-alerts=disabled",
            "network=not-executed build=not-executed mutation=not-executed",
        ] {
            assert!(
                plan.contains(boundary),
                "missing dry-run boundary: {boundary}"
            );
        }
    }

    #[test]
    fn managed_defaults_and_boundaries_are_private() {
        assert_eq!(
            resolve_database_url(None, RuntimeMode::Managed).expect("managed database URL"),
            MANAGED_DATABASE_URL
        );
        assert_eq!(
            resolve_internal_token_path(None, RuntimeMode::Managed).expect("managed token path"),
            Path::new(MANAGED_INTERNAL_TOKEN_PATH)
        );
        assert_eq!(
            sqlite_connect_options("sqlite:///opt/mini-ops/mini-ops.db", RuntimeMode::Managed)
                .expect_err("managed database outside state must fail"),
            RuntimeError::DatabaseOutsideManagedState
        );
        assert_eq!(
            resolve_internal_token_path(
                Some(OsStr::new("/opt/mini-ops/internal.token")),
                RuntimeMode::Managed
            )
            .expect_err("managed token outside runtime must fail"),
            RuntimeError::InvalidInternalTokenPath
        );
        assert_eq!(
            sqlite_connect_options("sqlite::memory:", RuntimeMode::Managed)
                .expect_err("managed database must be persistent"),
            RuntimeError::ManagedDatabaseNotFileBacked
        );
        assert_eq!(
            resolve_internal_token_path(
                Some(OsStr::new("relative.token")),
                RuntimeMode::Standalone
            )
            .expect_err("explicit token paths must be absolute"),
            RuntimeError::InvalidInternalTokenPath
        );
    }

    #[tokio::test]
    async fn custom_database_url_creates_only_requested_private_file() {
        let directory = TestDirectory::new("database");
        let database_path = directory.path().join("custom.db");
        let stray_path = directory.path().join("mini-ops.db");
        let database_url = format!("sqlite://{}", database_path.display());

        let options = sqlite_connect_options(&database_url, RuntimeMode::Standalone)
            .expect("parse custom database URL");
        assert_eq!(options.get_filename(), database_path);

        let pool = connect_sqlite_pool(&database_url, RuntimeMode::Standalone, 1)
            .await
            .expect("connect custom database");
        sqlx::query("CREATE TABLE mode_test (id INTEGER PRIMARY KEY)")
            .execute(&pool)
            .await
            .expect("write custom database");
        pool.close().await;

        assert!(database_path.is_file());
        assert!(!stray_path.exists());
        assert_eq!(
            fs::metadata(&database_path)
                .expect("database metadata")
                .permissions()
                .mode()
                & 0o777,
            PRIVATE_FILE_MODE
        );
        let metadata = fs::metadata(&database_path).expect("database ownership metadata");
        assert_eq!(metadata.uid(), effective_uid());
        assert_eq!(metadata.gid(), effective_gid());
    }

    #[tokio::test]
    async fn standalone_in_memory_database_remains_supported_without_state_file() {
        let before = generated_sqlx_memory_files();
        for database_url in [
            "sqlite::memory:",
            "sqlite::memory:?cache=shared",
            "sqlite://?mode=%6demory&cache=private",
        ] {
            let pool = connect_sqlite_pool(database_url, RuntimeMode::Standalone, 1)
                .await
                .expect("standalone in-memory database should connect");
            sqlx::query("CREATE TABLE memory_test (id INTEGER PRIMARY KEY)")
                .execute(&pool)
                .await
                .expect("in-memory schema should be writable");
            pool.close().await;
        }
        assert_eq!(generated_sqlx_memory_files(), before);
    }

    fn generated_sqlx_memory_files() -> Vec<OsString> {
        let mut files = fs::read_dir(".")
            .expect("read current directory")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .filter(|name| name.to_string_lossy().starts_with("file:sqlx-in-memory-"))
            .collect::<Vec<_>>();
        files.sort();
        files
    }

    #[tokio::test]
    async fn sqlite_connect_rejects_target_and_ancestor_symlinks_before_open() {
        let directory = TestDirectory::new("database-symlink");
        let outside = TestDirectory::new("database-outside");
        let outside_target = outside.path().join("target.db");
        fs::write(&outside_target, b"sentinel").expect("write outside target");

        let target_symlink = directory.path().join("target.db");
        symlink(&outside_target, &target_symlink).expect("create target symlink");
        let target_url = format!("sqlite://{}", target_symlink.display());
        assert_eq!(
            connect_sqlite_pool(&target_url, RuntimeMode::Standalone, 1)
                .await
                .expect_err("target symlink must fail before SQLx opens it"),
            RuntimeError::UnsafeDatabaseFile
        );
        assert_eq!(
            fs::read(&outside_target).expect("outside target remains readable"),
            b"sentinel"
        );

        let ancestor_symlink = directory.path().join("link");
        symlink(outside.path(), &ancestor_symlink).expect("create ancestor symlink");
        let escaped_path = ancestor_symlink.join("escaped.db");
        let escaped_url = format!("sqlite://{}", escaped_path.display());
        assert_eq!(
            connect_sqlite_pool(&escaped_url, RuntimeMode::Standalone, 1)
                .await
                .expect_err("ancestor symlink must fail before SQLx creates a database"),
            RuntimeError::UnsafeDatabaseFile
        );
        assert!(!outside.path().join("escaped.db").exists());
    }

    #[test]
    fn sqlite_sidecars_are_restricted_and_symlinks_are_rejected() {
        let directory = TestDirectory::new("sidecars");
        let database_path = directory.path().join("state.db");
        fs::write(&database_path, b"").expect("create database fixture");
        for suffix in ["-journal", "-wal", "-shm"] {
            let sidecar = path_with_suffix(&database_path, suffix);
            fs::write(&sidecar, b"").expect("create sidecar fixture");
            fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o666))
                .expect("set permissive fixture mode");
        }

        ensure_sqlite_private_files(&database_path).expect("harden SQLite fixtures");
        for path in std::iter::once(database_path.clone()).chain(
            ["-journal", "-wal", "-shm"]
                .into_iter()
                .map(|suffix| path_with_suffix(&database_path, suffix)),
        ) {
            assert_eq!(
                fs::metadata(path)
                    .expect("fixture metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                PRIVATE_FILE_MODE
            );
        }

        let symlink_path = directory.path().join("unsafe.db");
        symlink(&database_path, &symlink_path).expect("create database symlink");
        assert_eq!(
            ensure_sqlite_private_files(&symlink_path).expect_err("database symlink must fail"),
            RuntimeError::UnsafeDatabaseFile
        );
    }

    #[test]
    fn internal_token_rotation_is_atomic_private_and_same_directory() {
        let directory = TestDirectory::new("token");
        let token_path = directory.path().join("internal.token");

        write_internal_token_atomic(&token_path, "first-token").expect("write first token");
        write_internal_token_atomic(&token_path, "second-token").expect("rotate token");

        assert_eq!(
            fs::read_to_string(&token_path).expect("read token fixture"),
            "second-token"
        );
        assert_eq!(
            fs::metadata(&token_path)
                .expect("token metadata")
                .permissions()
                .mode()
                & 0o777,
            PRIVATE_FILE_MODE
        );
        let metadata = fs::metadata(&token_path).expect("token ownership metadata");
        assert_eq!(metadata.uid(), effective_uid());
        assert_eq!(metadata.gid(), effective_gid());
        let temporary_files = fs::read_dir(directory.path())
            .expect("read token directory")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(temporary_files, 0);
    }

    #[test]
    fn internal_token_symlink_failure_is_redacted() {
        let directory = TestDirectory::new("token-symlink");
        let target = directory.path().join("target");
        let token_path = directory.path().join("internal.token");
        fs::write(&target, "unchanged").expect("write symlink target");
        symlink(&target, &token_path).expect("create token symlink");

        let sentinel = "sentinel-secret-token";
        let error = write_internal_token_atomic(&token_path, sentinel)
            .expect_err("token symlink must fail");
        assert_eq!(error, RuntimeError::UnsafeInternalTokenPath);
        assert!(!error.to_string().contains(sentinel));
        assert_eq!(
            fs::read_to_string(target).expect("read target"),
            "unchanged"
        );
    }

    #[test]
    fn internal_token_rejects_symlink_ancestor_and_never_publishes_on_failure() {
        let directory = TestDirectory::new("token-ancestor");
        let outside = TestDirectory::new("token-outside");
        let link = directory.path().join("link");
        symlink(outside.path(), &link).expect("create token ancestor symlink");
        let token_path = link.join("internal.token");
        let published = std::sync::atomic::AtomicBool::new(false);

        let error = persist_and_publish_internal_token(
            &token_path,
            "sentinel-secret-token".to_string(),
            |_| published.store(true, std::sync::atomic::Ordering::SeqCst),
        )
        .expect_err("unsafe token path must fail before in-memory publication");

        assert_eq!(error, RuntimeError::UnsafeInternalTokenPath);
        assert!(!published.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!outside.path().join("internal.token").exists());
    }

    #[tokio::test]
    async fn ssh_hook_bypasses_proxy_and_keeps_sentinel_out_of_process_output() {
        if effective_uid() == 0 {
            return;
        }

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let api = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake loopback API");
        let proxy = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake inherited proxy");
        let api_url = format!(
            "http://{}/api/internal/ssh-login",
            api.local_addr().expect("fake API address")
        );
        let proxy_url = format!("http://{}", proxy.local_addr().expect("fake proxy address"));
        let sentinel = format!("sentinel-token-{}", uuid::Uuid::new_v4().simple());
        let payload = r#"{"user":"fixture","ip":"127.0.0.1","method":"ssh","timestamp":1}"#;
        let expected_payload = payload.as_bytes().to_vec();

        let api_task = tokio::spawn(async move {
            let (mut stream, _) = tokio::time::timeout(Duration::from_secs(3), api.accept())
                .await
                .expect("hook should reach loopback API")
                .expect("accept loopback request");
            let mut request = Vec::new();
            let mut chunk = [0_u8; 2048];
            while !request
                .windows(expected_payload.len())
                .any(|window| window == expected_payload)
            {
                let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut chunk))
                    .await
                    .expect("bounded request read")
                    .expect("read loopback request");
                if read == 0 || request.len() > 8 * 1024 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .await
                .expect("write fake API response");
            request
        });
        let proxy_task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(1), proxy.accept()).await
        });

        let hook = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/ssh-alert.sh");
        let mut command = tokio::process::Command::new("/bin/bash");
        command
            .arg("-c")
            .arg(
                "source \"$HOOK_PATH\"; mini_ops_send_payload \"$SENTINEL_TOKEN\" \"$PAYLOAD\" \"$API_URL\"",
            )
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("MINI_OPS_SSH_ALERT_LIBRARY_MODE", "1")
            .env("HOOK_PATH", hook)
            .env("SENTINEL_TOKEN", &sentinel)
            .env("PAYLOAD", payload)
            .env("API_URL", &api_url)
            .env("http_proxy", &proxy_url)
            .env("HTTP_PROXY", &proxy_url)
            .env("CURL_HOME", "/definitely/untrusted")
            .kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(4), command.output())
            .await
            .expect("hook fixture deadline")
            .expect("run hook sender fixture");
        let request = api_task.await.expect("join fake API capture");
        let proxy_result = proxy_task.await.expect("join fake proxy capture");

        assert!(output.status.success());
        assert!(proxy_result.is_err(), "hook must bypass inherited proxy");
        let request_text = String::from_utf8(request).expect("captured request is HTTP text");
        assert!(request_text.contains(&format!("Authorization: Bearer {sentinel}")));
        assert!(!String::from_utf8_lossy(&output.stdout).contains(&sentinel));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(&sentinel));
    }
}
