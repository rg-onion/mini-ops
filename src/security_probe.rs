use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use tokio::sync::{Notify, mpsc};

pub(crate) const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
pub(crate) const DOCKER_PROBE_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const AUDIT_COLLECTION_DEADLINE: Duration = Duration::from_secs(20);
pub(crate) const OUTPUT_CAP_BYTES: usize = 64 * 1024;
const PROCESS_CLEANUP_GRACE: Duration = Duration::from_millis(500);
const STREAM_DRAIN_GRACE: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnknownReason {
    MissingExecutable,
    PermissionDenied,
    Timeout,
    NonzeroExit,
    EmptyOutput,
    MalformedOutput,
    OutputTruncated,
    Cancelled,
    IoError,
    AuditDeadlineExceeded,
}

impl UnknownReason {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::MissingExecutable => "missing_executable",
            Self::PermissionDenied => "permission_denied",
            Self::Timeout => "timeout",
            Self::NonzeroExit => "nonzero_exit",
            Self::EmptyOutput => "empty_output",
            Self::MalformedOutput => "malformed_output",
            Self::OutputTruncated => "output_truncated",
            Self::Cancelled => "cancelled",
            Self::IoError => "io_error",
            Self::AuditDeadlineExceeded => "audit_deadline_exceeded",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Fact<T> {
    Known(T),
    Unknown(UnknownReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BoundedOutput {
    pub(crate) bytes: Vec<u8>,
    pub(crate) truncated: bool,
}

impl BoundedOutput {
    fn empty() -> Self {
        Self {
            bytes: Vec::new(),
            truncated: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProbeCompletion {
    Exited(i32),
    Signaled,
    TimedOut,
    Cancelled,
    SpawnFailed(UnknownReason),
    WaitFailed,
}

#[derive(Clone, Debug)]
pub(crate) struct ProbeOutcome {
    pub(crate) completion: ProbeCompletion,
    pub(crate) stdout: BoundedOutput,
    pub(crate) stderr: BoundedOutput,
    pub(crate) elapsed: Duration,
    cancellation_reason: Option<UnknownReason>,
}

impl ProbeOutcome {
    pub(crate) fn parse_stdout<T>(
        &self,
        parser: impl FnOnce(&str) -> Result<T, UnknownReason>,
    ) -> Fact<T> {
        if self.stdout.truncated || self.stderr.truncated {
            return Fact::Unknown(UnknownReason::OutputTruncated);
        }
        if self.elapsed > AUDIT_COLLECTION_DEADLINE {
            return Fact::Unknown(UnknownReason::AuditDeadlineExceeded);
        }

        match self.completion {
            ProbeCompletion::Exited(0) => {}
            ProbeCompletion::Exited(_) | ProbeCompletion::Signaled => {
                return Fact::Unknown(UnknownReason::NonzeroExit);
            }
            ProbeCompletion::TimedOut => return Fact::Unknown(UnknownReason::Timeout),
            ProbeCompletion::Cancelled => {
                return Fact::Unknown(self.cancellation_reason.unwrap_or(UnknownReason::Cancelled));
            }
            ProbeCompletion::SpawnFailed(reason) => return Fact::Unknown(reason),
            ProbeCompletion::WaitFailed => return Fact::Unknown(UnknownReason::IoError),
        }

        let Ok(stdout) = std::str::from_utf8(&self.stdout.bytes) else {
            return Fact::Unknown(UnknownReason::MalformedOutput);
        };
        if stdout.trim().is_empty() {
            return Fact::Unknown(UnknownReason::EmptyOutput);
        }

        match parser(stdout) {
            Ok(value) => Fact::Known(value),
            Err(reason) => Fact::Unknown(reason),
        }
    }

    fn spawn_failed(reason: UnknownReason, elapsed: Duration) -> Self {
        Self {
            completion: ProbeCompletion::SpawnFailed(reason),
            stdout: BoundedOutput::empty(),
            stderr: BoundedOutput::empty(),
            elapsed,
            cancellation_reason: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProbeProgram {
    Sshd,
    Ufw,
    Lsblk,
    Systemctl,
    Ss,
}

impl ProbeProgram {
    const fn candidates(self) -> &'static [&'static str] {
        match self {
            Self::Sshd => &["/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd", "/bin/sshd"],
            Self::Ufw => &["/usr/sbin/ufw", "/usr/bin/ufw", "/sbin/ufw", "/bin/ufw"],
            Self::Lsblk => &[
                "/usr/bin/lsblk",
                "/usr/sbin/lsblk",
                "/bin/lsblk",
                "/sbin/lsblk",
            ],
            Self::Systemctl => &[
                "/usr/bin/systemctl",
                "/usr/sbin/systemctl",
                "/bin/systemctl",
                "/sbin/systemctl",
            ],
            Self::Ss => &["/usr/bin/ss", "/usr/sbin/ss", "/bin/ss", "/sbin/ss"],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CancellationReason {
    Cancelled,
    AuditDeadlineExceeded,
}

impl CancellationReason {
    pub(crate) const fn unknown_reason(self) -> UnknownReason {
        match self {
            Self::Cancelled => UnknownReason::Cancelled,
            Self::AuditDeadlineExceeded => UnknownReason::AuditDeadlineExceeded,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ProbeCancellation {
    inner: Arc<CancellationInner>,
}

#[derive(Debug)]
struct CancellationInner {
    state: AtomicU8,
    notify: Notify,
}

impl ProbeCancellation {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(CancellationInner {
                state: AtomicU8::new(0),
                notify: Notify::new(),
            }),
        }
    }

    pub(crate) fn cancel(&self, reason: CancellationReason) {
        let value = match reason {
            CancellationReason::Cancelled => 1,
            CancellationReason::AuditDeadlineExceeded => 2,
        };
        if self
            .inner
            .state
            .compare_exchange(0, value, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.inner.notify.notify_waiters();
        }
    }

    pub(crate) fn reason(&self) -> Option<CancellationReason> {
        match self.inner.state.load(Ordering::Acquire) {
            1 => Some(CancellationReason::Cancelled),
            2 => Some(CancellationReason::AuditDeadlineExceeded),
            _ => None,
        }
    }

    pub(crate) async fn cancelled(&self) -> CancellationReason {
        loop {
            if let Some(reason) = self.reason() {
                return reason;
            }
            let notified = self.inner.notify.notified();
            if let Some(reason) = self.reason() {
                return reason;
            }
            notified.await;
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum StreamEvent {
    Truncated,
    ReadFailed,
}

#[derive(Debug)]
struct StreamReadResult {
    output: BoundedOutput,
    failed: bool,
}

pub(crate) struct ProbeRunner;

impl ProbeRunner {
    pub(crate) async fn run(
        program: ProbeProgram,
        args: &[&str],
        timeout: Duration,
        cancellation: &ProbeCancellation,
    ) -> ProbeOutcome {
        let started = Instant::now();
        let deadline = tokio::time::Instant::now() + timeout;
        let executable = tokio::select! {
            biased;
            reason = cancellation.cancelled() => {
                return Self::cancelled_outcome(started, reason);
            }
            _ = tokio::time::sleep_until(deadline) => {
                return Self::timed_out_outcome(started);
            }
            result = resolve_system_executable(program) => match result {
                Ok(path) => path,
                Err(reason) => return ProbeOutcome::spawn_failed(reason, started.elapsed()),
            },
        };

        Self::run_path(executable, args, deadline, cancellation, started).await
    }

    #[cfg(test)]
    async fn run_test_path(
        executable: PathBuf,
        args: &[&str],
        timeout: Duration,
        cancellation: &ProbeCancellation,
    ) -> ProbeOutcome {
        let started = Instant::now();
        let deadline = tokio::time::Instant::now() + timeout;
        tokio::select! {
            biased;
            reason = cancellation.cancelled() => {
                return Self::cancelled_outcome(started, reason);
            }
            _ = tokio::time::sleep_until(deadline) => {
                return Self::timed_out_outcome(started);
            }
            result = validate_executable(&executable) => {
                if let Err(reason) = result {
                    return ProbeOutcome::spawn_failed(reason, started.elapsed());
                }
            }
        }
        Self::run_path(executable, args, deadline, cancellation, started).await
    }

    async fn run_path(
        executable: PathBuf,
        args: &[&str],
        deadline: tokio::time::Instant,
        cancellation: &ProbeCancellation,
        started: Instant,
    ) -> ProbeOutcome {
        if let Some(reason) = cancellation.reason() {
            return ProbeOutcome {
                completion: ProbeCompletion::Cancelled,
                stdout: BoundedOutput::empty(),
                stderr: BoundedOutput::empty(),
                elapsed: started.elapsed(),
                cancellation_reason: Some(reason.unknown_reason()),
            };
        }

        let mut command = Command::new(executable);
        command
            .args(args)
            .env_clear()
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                return ProbeOutcome::spawn_failed(io_error_reason(&error), started.elapsed());
            }
        };
        let Some(process_group) = child.id() else {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return ProbeOutcome {
                completion: ProbeCompletion::WaitFailed,
                stdout: BoundedOutput::empty(),
                stderr: BoundedOutput::empty(),
                elapsed: started.elapsed(),
                cancellation_reason: None,
            };
        };
        let mut process_group_guard = ProcessGroupGuard::new(process_group);

        let Some(stdout) = child.stdout.take() else {
            terminate_and_reap(&mut child, process_group).await;
            return ProbeOutcome {
                completion: ProbeCompletion::WaitFailed,
                stdout: BoundedOutput::empty(),
                stderr: BoundedOutput::empty(),
                elapsed: started.elapsed(),
                cancellation_reason: None,
            };
        };
        let Some(stderr) = child.stderr.take() else {
            terminate_and_reap(&mut child, process_group).await;
            return ProbeOutcome {
                completion: ProbeCompletion::WaitFailed,
                stdout: BoundedOutput::empty(),
                stderr: BoundedOutput::empty(),
                elapsed: started.elapsed(),
                cancellation_reason: None,
            };
        };

        let (event_tx, mut event_rx) = mpsc::channel(4);
        let stdout_task = tokio::spawn(read_bounded(stdout, event_tx.clone()));
        let stderr_task = tokio::spawn(read_bounded(stderr, event_tx.clone()));

        enum RunState {
            Exited(Result<std::process::ExitStatus, ()>),
            TimedOut,
            Cancelled(CancellationReason),
            Stream(StreamEvent),
        }

        let run_state = {
            let wait = child.wait();
            tokio::pin!(wait);

            tokio::select! {
                biased;
                reason = cancellation.cancelled() => RunState::Cancelled(reason),
                _ = tokio::time::sleep_until(deadline) => RunState::TimedOut,
                Some(event) = event_rx.recv() => RunState::Stream(event),
                status = &mut wait => RunState::Exited(status.map_err(|_| ())),
            }
        };

        let (completion, cancellation_reason) = match run_state {
            RunState::Exited(Ok(status)) => {
                // The leader may exit while descendants still hold inherited pipes.
                // Terminate the residual process group before awaiting pipe readers.
                kill_process_group(process_group);
                let completion = match status.code() {
                    Some(code) => ProbeCompletion::Exited(code),
                    None => ProbeCompletion::Signaled,
                };
                (completion, None)
            }
            RunState::Exited(Err(())) => {
                let _ = terminate_and_reap(&mut child, process_group).await;
                (ProbeCompletion::WaitFailed, None)
            }
            RunState::TimedOut => {
                let completion = if terminate_and_reap(&mut child, process_group).await {
                    ProbeCompletion::TimedOut
                } else {
                    ProbeCompletion::WaitFailed
                };
                (completion, None)
            }
            RunState::Cancelled(reason) => {
                let completion = if terminate_and_reap(&mut child, process_group).await {
                    ProbeCompletion::Cancelled
                } else {
                    ProbeCompletion::WaitFailed
                };
                (completion, Some(reason.unknown_reason()))
            }
            RunState::Stream(StreamEvent::Truncated) => {
                let completion = if terminate_and_reap(&mut child, process_group).await {
                    ProbeCompletion::Signaled
                } else {
                    ProbeCompletion::WaitFailed
                };
                (completion, None)
            }
            RunState::Stream(StreamEvent::ReadFailed) => {
                let _ = terminate_and_reap(&mut child, process_group).await;
                (ProbeCompletion::WaitFailed, None)
            }
        };

        let (stdout, stderr) = join_streams_bounded(stdout_task, stderr_task).await;
        let completion = if stdout.failed || stderr.failed {
            ProbeCompletion::WaitFailed
        } else {
            completion
        };
        process_group_guard.disarm();

        ProbeOutcome {
            completion,
            stdout: stdout.output,
            stderr: stderr.output,
            elapsed: started.elapsed(),
            cancellation_reason,
        }
    }

    fn timed_out_outcome(started: Instant) -> ProbeOutcome {
        ProbeOutcome {
            completion: ProbeCompletion::TimedOut,
            stdout: BoundedOutput::empty(),
            stderr: BoundedOutput::empty(),
            elapsed: started.elapsed(),
            cancellation_reason: None,
        }
    }

    fn cancelled_outcome(started: Instant, reason: CancellationReason) -> ProbeOutcome {
        ProbeOutcome {
            completion: ProbeCompletion::Cancelled,
            stdout: BoundedOutput::empty(),
            stderr: BoundedOutput::empty(),
            elapsed: started.elapsed(),
            cancellation_reason: Some(reason.unknown_reason()),
        }
    }
}

async fn resolve_system_executable(program: ProbeProgram) -> Result<PathBuf, UnknownReason> {
    let mut saw_io_error = false;
    for candidate in program.candidates() {
        let path = Path::new(candidate);
        match validate_executable(path).await {
            Ok(()) => return Ok(path.to_path_buf()),
            Err(UnknownReason::MissingExecutable) => {}
            Err(UnknownReason::IoError) => saw_io_error = true,
            Err(reason) => return Err(reason),
        }
    }

    if saw_io_error {
        Err(UnknownReason::IoError)
    } else {
        Err(UnknownReason::MissingExecutable)
    }
}

async fn validate_executable(path: &Path) -> Result<(), UnknownReason> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|error| io_error_reason(&error))?;
    let mode = metadata.permissions().mode();
    if !metadata.is_file() || mode & 0o111 == 0 || mode & 0o022 != 0 {
        return Err(UnknownReason::PermissionDenied);
    }
    Ok(())
}

fn io_error_reason(error: &io::Error) -> UnknownReason {
    match error.kind() {
        io::ErrorKind::NotFound => UnknownReason::MissingExecutable,
        io::ErrorKind::PermissionDenied => UnknownReason::PermissionDenied,
        _ => UnknownReason::IoError,
    }
}

async fn read_bounded<R>(mut reader: R, event_tx: mpsc::Sender<StreamEvent>) -> StreamReadResult
where
    R: AsyncRead + Unpin,
{
    let mut output = BoundedOutput::empty();
    let mut chunk = [0_u8; 8192];

    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => {
                return StreamReadResult {
                    output,
                    failed: false,
                };
            }
            Ok(read) => {
                let remaining = OUTPUT_CAP_BYTES.saturating_sub(output.bytes.len());
                let retained = remaining.min(read);
                output.bytes.extend_from_slice(&chunk[..retained]);
                if retained < read {
                    output.truncated = true;
                    let _ = event_tx.send(StreamEvent::Truncated).await;
                    return StreamReadResult {
                        output,
                        failed: false,
                    };
                }
            }
            Err(_) => {
                let _ = event_tx.send(StreamEvent::ReadFailed).await;
                return StreamReadResult {
                    output,
                    failed: true,
                };
            }
        }
    }
}

async fn join_streams_bounded(
    stdout_task: tokio::task::JoinHandle<StreamReadResult>,
    stderr_task: tokio::task::JoinHandle<StreamReadResult>,
) -> (StreamReadResult, StreamReadResult) {
    tokio::join!(
        join_stream_bounded(stdout_task),
        join_stream_bounded(stderr_task)
    )
}

async fn join_stream_bounded(
    mut task: tokio::task::JoinHandle<StreamReadResult>,
) -> StreamReadResult {
    match tokio::time::timeout(STREAM_DRAIN_GRACE, &mut task).await {
        Ok(result) => stream_task_result(result),
        Err(_) => {
            task.abort();
            let _ = task.await;
            failed_stream_result()
        }
    }
}

fn stream_task_result(
    result: Result<StreamReadResult, tokio::task::JoinError>,
) -> StreamReadResult {
    result.unwrap_or_else(|_| failed_stream_result())
}

fn failed_stream_result() -> StreamReadResult {
    StreamReadResult {
        output: BoundedOutput::empty(),
        failed: true,
    }
}

fn kill_process_group(process_group: u32) {
    let Ok(process_group) = i32::try_from(process_group) else {
        return;
    };
    // SAFETY: `kill` is called with a negative, validated child PID so the signal
    // is scoped to the process group created for this probe. ESRCH is harmless.
    let _ = unsafe { libc::kill(-process_group, libc::SIGKILL) };
}

struct ProcessGroupGuard {
    process_group: u32,
    armed: bool,
}

impl ProcessGroupGuard {
    fn new(process_group: u32) -> Self {
        Self {
            process_group,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if self.armed {
            kill_process_group(self.process_group);
        }
    }
}

async fn terminate_and_reap(child: &mut Child, process_group: u32) -> bool {
    kill_process_group(process_group);
    let _ = child.start_kill();
    matches!(
        tokio::time::timeout(PROCESS_CLEANUP_GRACE, child.wait()).await,
        Ok(Ok(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestExecutable {
        directory: PathBuf,
        path: PathBuf,
    }

    impl TestExecutable {
        fn new(body: &str) -> Self {
            let sequence = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "mini-ops-probe-{}-{}",
                std::process::id(),
                sequence
            ));
            std::fs::create_dir(&directory).expect("test directory should be created");
            let path = directory.join("probe");
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o700)
                .open(&path)
                .expect("test executable should be created");
            writeln!(file, "#!/bin/sh\n{body}").expect("test executable should be written");
            file.sync_all().expect("test executable should be synced");
            Self { directory, path }
        }

        fn marker(&self) -> PathBuf {
            self.directory.join("marker")
        }
    }

    impl Drop for TestExecutable {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    async fn run_test(
        executable: &TestExecutable,
        args: &[&str],
        timeout: Duration,
    ) -> ProbeOutcome {
        ProbeRunner::run_test_path(
            executable.path.clone(),
            args,
            timeout,
            &ProbeCancellation::new(),
        )
        .await
    }

    #[tokio::test]
    async fn missing_executable_is_unknown() {
        let path = std::env::temp_dir().join("mini-ops-probe-definitely-missing");
        let outcome =
            ProbeRunner::run_test_path(path, &[], DEFAULT_PROBE_TIMEOUT, &ProbeCancellation::new())
                .await;

        assert_eq!(
            outcome.parse_stdout::<String>(|value| Ok(value.to_string())),
            Fact::Unknown(UnknownReason::MissingExecutable)
        );
    }

    #[tokio::test]
    async fn nonzero_exit_is_unknown_and_stderr_is_bounded() {
        let executable = TestExecutable::new("printf 'bounded failure' >&2\nexit 1");
        let outcome = run_test(&executable, &[], DEFAULT_PROBE_TIMEOUT).await;

        assert_eq!(outcome.completion, ProbeCompletion::Exited(1));
        assert!(outcome.stderr.bytes.len() <= OUTPUT_CAP_BYTES);
        assert_eq!(
            outcome.parse_stdout::<String>(|value| Ok(value.to_string())),
            Fact::Unknown(UnknownReason::NonzeroExit)
        );
    }

    #[tokio::test]
    async fn empty_success_is_unknown() {
        let executable = TestExecutable::new("exit 0");
        let outcome = run_test(&executable, &[], DEFAULT_PROBE_TIMEOUT).await;

        assert_eq!(
            outcome.parse_stdout::<String>(|value| Ok(value.to_string())),
            Fact::Unknown(UnknownReason::EmptyOutput)
        );
    }

    #[tokio::test]
    async fn malformed_success_is_unknown() {
        let executable = TestExecutable::new("printf 'not-valid\\n'");
        let outcome = run_test(&executable, &[], DEFAULT_PROBE_TIMEOUT).await;
        let fact = outcome.parse_stdout(|value| {
            value
                .strip_prefix("expected=")
                .map(str::to_string)
                .ok_or(UnknownReason::MalformedOutput)
        });

        assert_eq!(fact, Fact::Unknown(UnknownReason::MalformedOutput));
    }

    #[tokio::test]
    async fn timeout_kills_and_reaps_process() {
        let executable =
            TestExecutable::new("printf '%s\\n' \"$$\"\nwhile :; do /usr/bin/sleep 1; done");
        // Give a loaded CI worker enough time to start the shell and publish
        // its PID before exercising the timeout/reap path.
        let outcome = run_test(&executable, &[], Duration::from_secs(1)).await;
        let pid = parse_pid(&outcome.stdout.bytes);

        assert_eq!(outcome.completion, ProbeCompletion::TimedOut);
        assert_eq!(
            outcome.parse_stdout::<String>(|value| Ok(value.to_string())),
            Fact::Unknown(UnknownReason::Timeout)
        );
        assert_pid_exits(pid).await;
    }

    #[tokio::test]
    async fn oversized_stdout_terminates_process_group() {
        let executable = TestExecutable::new(
            "/usr/bin/head -c 70000 /dev/zero\nwhile :; do /usr/bin/sleep 1; done",
        );
        let outcome = run_test(&executable, &[], DEFAULT_PROBE_TIMEOUT).await;

        assert_eq!(outcome.stdout.bytes.len(), OUTPUT_CAP_BYTES);
        assert!(outcome.stdout.truncated);
        assert!(outcome.elapsed < DEFAULT_PROBE_TIMEOUT);
        assert_eq!(
            outcome.parse_stdout::<String>(|value| Ok(value.to_string())),
            Fact::Unknown(UnknownReason::OutputTruncated)
        );
    }

    #[tokio::test]
    async fn oversized_stderr_terminates_process_group() {
        let executable = TestExecutable::new(
            "/usr/bin/head -c 70000 /dev/zero >&2\nwhile :; do /usr/bin/sleep 1; done",
        );
        let outcome = run_test(&executable, &[], DEFAULT_PROBE_TIMEOUT).await;

        assert_eq!(outcome.stderr.bytes.len(), OUTPUT_CAP_BYTES);
        assert!(outcome.stderr.truncated);
        assert!(outcome.elapsed < DEFAULT_PROBE_TIMEOUT);
        assert_eq!(
            outcome.parse_stdout::<String>(|value| Ok(value.to_string())),
            Fact::Unknown(UnknownReason::OutputTruncated)
        );
    }

    #[tokio::test]
    async fn cancellation_kills_and_reaps_process() {
        let executable = TestExecutable::new(
            "printf ready > \"$1\"\nprintf '%s\\n' \"$$\"\nwhile :; do /usr/bin/sleep 1; done",
        );
        let marker = executable.marker();
        let marker_arg = marker.to_string_lossy().to_string();
        let cancellation = ProbeCancellation::new();
        let task_cancellation = cancellation.clone();
        let executable_path = executable.path.clone();
        let task = tokio::spawn(async move {
            let args = [marker_arg.as_str()];
            ProbeRunner::run_test_path(
                executable_path,
                &args,
                DEFAULT_PROBE_TIMEOUT,
                &task_cancellation,
            )
            .await
        });

        for _ in 0..50 {
            if marker.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(marker.exists(), "probe did not reach cancellation fixture");
        cancellation.cancel(CancellationReason::Cancelled);
        let outcome = task.await.expect("probe task should complete");
        let pid = parse_pid(&outcome.stdout.bytes);

        assert_eq!(outcome.completion, ProbeCompletion::Cancelled);
        assert_eq!(
            outcome.parse_stdout::<String>(|value| Ok(value.to_string())),
            Fact::Unknown(UnknownReason::Cancelled)
        );
        assert_pid_exits(pid).await;
    }

    #[tokio::test]
    async fn timeout_kills_descendant_process_group() {
        let executable = TestExecutable::new(
            "(/usr/bin/sleep 1; printf survived > \"$1\") &\nprintf '%s\\n' \"$!\"\nwhile :; do /usr/bin/sleep 1; done",
        );
        let marker = executable.marker();
        let marker_arg = marker.to_string_lossy().to_string();
        let outcome = run_test(
            &executable,
            &[marker_arg.as_str()],
            Duration::from_millis(100),
        )
        .await;
        let descendant_pid = parse_pid(&outcome.stdout.bytes);

        assert_eq!(outcome.completion, ProbeCompletion::TimedOut);
        assert_pid_exits(descendant_pid).await;
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        assert!(!marker.exists(), "descendant survived process-group kill");
    }

    #[tokio::test]
    async fn parent_exit_kills_descendant_holding_output_pipes() {
        let executable = TestExecutable::new("(/usr/bin/sleep 5) &\nprintf '%s\\n' \"$!\"\nexit 0");
        let outcome = run_test(&executable, &[], DEFAULT_PROBE_TIMEOUT).await;
        let descendant_pid = parse_pid(&outcome.stdout.bytes);

        assert_eq!(outcome.completion, ProbeCompletion::Exited(0));
        assert!(outcome.elapsed < Duration::from_secs(1));
        assert_pid_exits(descendant_pid).await;
    }

    #[tokio::test]
    async fn partial_stream_drain_timeout_is_bounded_without_repolling_completed_handle() {
        let executable = TestExecutable::new(
            "exec 1>&-\n/usr/bin/setsid /bin/sh -c 'printf \"%s\" \"$$\" > \"$1\"; exec /usr/bin/sleep 5' mini-ops-fixture \"$1\" &\nwhile [ ! -s \"$1\" ]; do /usr/bin/sleep 0.01; done\nexit 0",
        );
        let marker = executable.marker();
        let marker_arg = marker.to_string_lossy().to_string();
        let outcome = run_test(&executable, &[marker_arg.as_str()], DEFAULT_PROBE_TIMEOUT).await;

        assert_eq!(outcome.completion, ProbeCompletion::WaitFailed);
        assert!(outcome.elapsed < Duration::from_secs(1));

        for _ in 0..50 {
            if marker.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let escaped_pid = std::fs::read_to_string(&marker)
            .expect("escaped fixture should record its PID")
            .parse::<i32>()
            .expect("escaped fixture PID should be numeric");
        // SAFETY: this PID belongs to the test-only escaped sleep fixture.
        let _ = unsafe { libc::kill(escaped_pid, libc::SIGKILL) };
        assert_pid_exits(escaped_pid as u32).await;
    }

    #[tokio::test]
    async fn audit_deadline_reason_is_preserved() {
        let executable = TestExecutable::new("while :; do /usr/bin/sleep 1; done");
        let cancellation = ProbeCancellation::new();
        cancellation.cancel(CancellationReason::AuditDeadlineExceeded);
        let outcome = ProbeRunner::run_test_path(
            executable.path.clone(),
            &[],
            DEFAULT_PROBE_TIMEOUT,
            &cancellation,
        )
        .await;

        assert_eq!(
            outcome.parse_stdout::<String>(|value| Ok(value.to_string())),
            Fact::Unknown(UnknownReason::AuditDeadlineExceeded)
        );
    }

    fn parse_pid(output: &[u8]) -> u32 {
        std::str::from_utf8(output)
            .expect("PID output should be UTF-8")
            .lines()
            .next()
            .expect("PID output should contain a line")
            .parse()
            .expect("PID output should be numeric")
    }

    async fn assert_pid_exits(pid: u32) {
        let pid = i32::try_from(pid).expect("test PID should fit i32");
        for _ in 0..50 {
            // SAFETY: signal 0 performs an existence check and does not mutate the process.
            let result = unsafe { libc::kill(pid, 0) };
            if result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("probe process {pid} was not reaped");
    }
}
