use crate::history::{DeploymentRecord, HistoryManager};
use axum::{
    Json,
    extract::State,
    http::{StatusCode, header},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
};
use futures_util::{StreamExt, stream};
use serde::Serialize;
use std::{
    collections::VecDeque,
    convert::Infallible,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::process::Child;

const UPDATE_LOG_BUFFER_LIMIT: usize = 500;
const WEB_UPDATE_ENV: &str = "MINI_OPS_ALLOW_WEB_UPDATE";
const WEB_UPDATE_TIMEOUT_ENV: &str = "MINI_OPS_WEB_UPDATE_TIMEOUT_SECS";
const DEFAULT_WEB_UPDATE_TIMEOUT_SECS: u64 = 1800;
const MIN_WEB_UPDATE_TIMEOUT_SECS: u64 = 60;
const MAX_WEB_UPDATE_TIMEOUT_SECS: u64 = 86_400;

#[derive(Serialize)]
struct ApiErrorEnvelope {
    error: ApiError,
}

#[derive(Serialize)]
struct ApiError {
    code: &'static str,
}

pub(crate) fn api_error_response(status: StatusCode, code: &'static str) -> Response {
    (
        status,
        Json(ApiErrorEnvelope {
            error: ApiError { code },
        }),
    )
        .into_response()
}

#[derive(Clone)]
pub struct DeploymentService {
    tx: tokio::sync::broadcast::Sender<String>,
    active: Arc<AtomicBool>,
    log_buffer: Arc<tokio::sync::Mutex<VecDeque<String>>>,
}

#[derive(Debug)]
pub enum UpdateStartError {
    AlreadyRunning,
}

impl DeploymentService {
    pub fn new() -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(100);
        Self {
            tx,
            active: Arc::new(AtomicBool::new(false)),
            log_buffer: Arc::new(tokio::sync::Mutex::new(VecDeque::with_capacity(
                UPDATE_LOG_BUFFER_LIMIT,
            ))),
        }
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<String> {
        self.tx.subscribe()
    }

    pub async fn recent_logs(&self) -> Vec<String> {
        self.log_buffer.lock().await.iter().cloned().collect()
    }

    pub fn start_update(
        &self,
        history: Arc<HistoryManager>,
        record: DeploymentRecord,
    ) -> Result<(), UpdateStartError> {
        if self
            .active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(UpdateStartError::AlreadyRunning);
        }

        history.add_record(record.clone());

        let service = self.clone();
        tokio::spawn(async move {
            service.run_update_task(history, record.id).await;
        });

        Ok(())
    }

    async fn run_update_task(self, history: Arc<HistoryManager>, record_id: String) {
        self.publish("🚀 Starting experimental source build...")
            .await;

        match self.run_update_command().await {
            Ok(()) => {
                self.publish(
                    "✅ Source build complete; install and service restart are still required.",
                )
                .await;
                history.update_record_status(
                    &record_id,
                    "success",
                    "Source build complete; install and service restart required",
                );
            }
            Err(e) => {
                self.publish(format!("❌ Source build failed: {}", e)).await;
                history.update_record_status(&record_id, "failed", &e);
            }
        }

        self.active.store(false, Ordering::Release);
    }

    async fn run_update_command(&self) -> Result<(), String> {
        use tokio::process::Command;

        let mut cmd = Command::new("bash");
        cmd.arg("./scripts/update.sh");
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
        cmd.kill_on_drop(true);
        cmd.process_group(0);

        let child = cmd
            .spawn()
            .map_err(|_| "source_build_start_failed".to_string())?;
        let update_timeout = web_update_timeout();
        let status = wait_for_process_group(child, update_timeout).await?;

        if status.success() {
            Ok(())
        } else {
            Err("source_build_command_failed".to_string())
        }
    }

    async fn publish(&self, message: impl Into<String>) {
        let message = message.into();
        let _ = self.tx.send(message.clone());

        let mut buffer = self.log_buffer.lock().await;
        buffer.push_back(message);
        while buffer.len() > UPDATE_LOG_BUFFER_LIMIT {
            buffer.pop_front();
        }
    }
}

async fn wait_for_process_group(
    mut child: Child,
    timeout: Duration,
) -> Result<std::process::ExitStatus, String> {
    let Some(process_group) = child.id() else {
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Err("source_build_wait_failed".to_string());
    };
    let mut guard = ProcessGroupGuard::new(process_group);

    let result = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => Ok(status),
        Ok(Err(_)) => {
            terminate_process_group(&mut child, process_group).await;
            Err("source_build_wait_failed".to_string())
        }
        Err(_) => {
            terminate_process_group(&mut child, process_group).await;
            Err("source_build_timed_out".to_string())
        }
    };

    // The shell can exit while descendants still mutate checkout/build files.
    // Clear the dedicated group before releasing the single-flight flag.
    kill_process_group(process_group);
    guard.disarm();
    result
}

async fn terminate_process_group(child: &mut Child, process_group: u32) {
    kill_process_group(process_group);
    let _ = child.start_kill();
    let _ = child.wait().await;
}

fn kill_process_group(process_group: u32) {
    let Ok(process_group) = i32::try_from(process_group) else {
        return;
    };
    // SAFETY: the negative PID targets only the dedicated process group created
    // for this source-build job. ESRCH means it has already exited.
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

fn web_update_timeout() -> Duration {
    let seconds =
        parse_web_update_timeout_secs(std::env::var(WEB_UPDATE_TIMEOUT_ENV).ok().as_deref());

    Duration::from_secs(seconds)
}

fn parse_web_update_timeout_secs(value: Option<&str>) -> u64 {
    value
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|value| value.clamp(MIN_WEB_UPDATE_TIMEOUT_SECS, MAX_WEB_UPDATE_TIMEOUT_SECS))
        .unwrap_or(DEFAULT_WEB_UPDATE_TIMEOUT_SECS)
}

fn web_update_enabled(value: Option<&str>) -> bool {
    value == Some("true")
}

fn trigger_update_response<F>(enabled: bool, start: F) -> Response
where
    F: FnOnce() -> Result<(), UpdateStartError>,
{
    if !enabled {
        return api_error_response(StatusCode::FORBIDDEN, "capability_disabled");
    }

    match start() {
        Ok(()) => (
            StatusCode::OK,
            "Source build triggered. Connect to the log stream for progress; install and restart remain manual.",
        )
            .into_response(),
        Err(UpdateStartError::AlreadyRunning) => {
            (StatusCode::CONFLICT, "A source build is already running.").into_response()
        }
    }
}

pub async fn trigger_update_handler(
    State(state): State<Arc<DeploymentService>>,
    State(history): State<Arc<HistoryManager>>,
) -> Response {
    let enabled = web_update_enabled(std::env::var(WEB_UPDATE_ENV).ok().as_deref());

    trigger_update_response(enabled, || {
        let record = DeploymentRecord {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            action: "update".to_string(),
            details: "Experimental source build triggered".to_string(),
            status: "in_progress".to_string(),
            image_id: None,
            container_name: Some("mini-ops".to_string()),
        };

        state.start_update(history, record)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn web_update_timeout_parser_uses_default_and_bounds() {
        assert_eq!(
            parse_web_update_timeout_secs(None),
            DEFAULT_WEB_UPDATE_TIMEOUT_SECS
        );
        assert_eq!(
            parse_web_update_timeout_secs(Some("not-a-number")),
            DEFAULT_WEB_UPDATE_TIMEOUT_SECS
        );
        assert_eq!(
            parse_web_update_timeout_secs(Some("1")),
            MIN_WEB_UPDATE_TIMEOUT_SECS
        );
        assert_eq!(
            parse_web_update_timeout_secs(Some("999999")),
            MAX_WEB_UPDATE_TIMEOUT_SECS
        );
        assert_eq!(parse_web_update_timeout_secs(Some("120")), 120);
    }

    #[test]
    fn web_update_gate_requires_exact_lowercase_true() {
        assert!(web_update_enabled(Some("true")));
        for value in [None, Some(""), Some(" true "), Some("TRUE"), Some("1")] {
            assert!(!web_update_enabled(value));
        }
    }

    #[test]
    fn disabled_web_update_has_zero_start_history_or_file_side_effects() {
        let command_calls = AtomicUsize::new(0);
        let history_writes = AtomicUsize::new(0);
        let file_writes = AtomicUsize::new(0);

        let response = trigger_update_response(false, || {
            command_calls.fetch_add(1, Ordering::SeqCst);
            history_writes.fetch_add(1, Ordering::SeqCst);
            file_writes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(command_calls.load(Ordering::SeqCst), 0);
        assert_eq!(history_writes.load(Ordering::SeqCst), 0);
        assert_eq!(file_writes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn source_build_timeout_terminates_descendant_process_group() {
        let marker = std::env::temp_dir().join(format!(
            "mini-ops-update-descendant-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let marker_arg = marker.to_string_lossy().to_string();
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .args([
                "-c",
                "/usr/bin/sleep 30 & printf '%s' \"$!\" > \"$1\"; wait",
                "mini-ops-test",
                marker_arg.as_str(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .process_group(0);

        let child = command.spawn().expect("test process should start");
        let error = wait_for_process_group(child, Duration::from_millis(500))
            .await
            .expect_err("test process should time out");
        assert_eq!(error, "source_build_timed_out");

        let descendant_pid = std::fs::read_to_string(&marker)
            .expect("test shell should record descendant PID")
            .parse::<i32>()
            .expect("descendant PID should be numeric");
        for _ in 0..50 {
            // SAFETY: signal 0 only checks whether the fixture process exists.
            if unsafe { libc::kill(descendant_pid, 0) } == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            {
                let _ = std::fs::remove_file(&marker);
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let _ = std::fs::remove_file(&marker);
        panic!("source-build descendant survived process-group termination");
    }
}

pub async fn deploy_logs_sse_handler(State(state): State<Arc<DeploymentService>>) -> Response {
    let snapshot = state.recent_logs().await;
    let rx = state.subscribe();
    let replay_stream = stream::iter(
        snapshot
            .into_iter()
            .map(|msg| Ok::<Event, Infallible>(Event::default().data(msg))),
    );
    let sse_stream = stream::unfold(rx, |mut rx| async move {
        match rx.recv().await {
            Ok(msg) => Some((Ok::<Event, Infallible>(Event::default().data(msg)), rx)),
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => Some((
                Ok(Event::default().data("⚠️ Log stream lagged, some lines were skipped")),
                rx,
            )),
            Err(tokio::sync::broadcast::error::RecvError::Closed) => None,
        }
    });

    (
        [(header::CACHE_CONTROL, "no-cache")],
        Sse::new(replay_stream.chain(sse_stream)).keep_alive(KeepAlive::default()),
    )
        .into_response()
}
