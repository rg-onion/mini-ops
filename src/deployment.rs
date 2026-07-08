use crate::history::{DeploymentRecord, HistoryManager};
use axum::{
    extract::State,
    http::{StatusCode, header},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
};
use futures_util::{StreamExt, stream};
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

const UPDATE_LOG_BUFFER_LIMIT: usize = 500;
const WEB_UPDATE_ENV: &str = "MINI_OPS_ALLOW_WEB_UPDATE";
const WEB_UPDATE_TIMEOUT_ENV: &str = "MINI_OPS_WEB_UPDATE_TIMEOUT_SECS";
const DEFAULT_WEB_UPDATE_TIMEOUT_SECS: u64 = 1800;
const MIN_WEB_UPDATE_TIMEOUT_SECS: u64 = 60;
const MAX_WEB_UPDATE_TIMEOUT_SECS: u64 = 86_400;

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
        self.publish("🚀 Starting update process...").await;

        match self.run_update_command().await {
            Ok(()) => {
                self.publish("✅ Update complete! Service restart may be required.")
                    .await;
                history.update_record_status(&record_id, "success", "Agent update completed");
            }
            Err(e) => {
                self.publish(format!("❌ Update failed: {}", e)).await;
                history.update_record_status(&record_id, "failed", &e);
            }
        }

        self.active.store(false, Ordering::Release);
    }

    async fn run_update_command(&self) -> Result<(), String> {
        use tokio::io::{AsyncBufReadExt, BufReader};
        use tokio::process::Command;

        let mut cmd = Command::new("bash");
        cmd.arg("./scripts/update.sh");
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed to start update script: {}", e))?;

        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill().await;
            return Err("Failed to open update stdout".to_string());
        };
        let Some(stderr) = child.stderr.take() else {
            let _ = child.kill().await;
            return Err("Failed to open update stderr".to_string());
        };

        let mut stdout_reader = BufReader::new(stdout).lines();
        let mut stderr_reader = BufReader::new(stderr).lines();
        let mut stdout_done = false;
        let mut stderr_done = false;
        let mut read_error = None;
        let update_timeout = web_update_timeout();
        let timeout = tokio::time::sleep(update_timeout);
        tokio::pin!(timeout);

        while (!stdout_done || !stderr_done) && read_error.is_none() {
            tokio::select! {
                _ = &mut timeout => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    return Err(format!(
                        "Update timed out after {} seconds",
                        update_timeout.as_secs()
                    ));
                }
                result = stdout_reader.next_line(), if !stdout_done => {
                    match result {
                        Ok(Some(line)) => self.publish(format!("STDOUT: {}", line)).await,
                        Ok(None) => stdout_done = true,
                        Err(e) => read_error = Some(format!("Failed to read update stdout: {}", e)),
                    }
                }
                result = stderr_reader.next_line(), if !stderr_done => {
                    match result {
                        Ok(Some(line)) => self.publish(format!("STDERR: {}", line)).await,
                        Ok(None) => stderr_done = true,
                        Err(e) => read_error = Some(format!("Failed to read update stderr: {}", e)),
                    }
                }
            }
        }

        if let Some(e) = read_error {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(e);
        }

        let status = tokio::select! {
            _ = &mut timeout => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(format!(
                    "Update timed out after {} seconds",
                    update_timeout.as_secs()
                ));
            }
            status = child.wait() => {
                status.map_err(|e| format!("Failed to wait on update script: {}", e))?
            }
        };

        if status.success() {
            Ok(())
        } else {
            Err(format!("Update script exited with {}", status))
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

pub async fn trigger_update_handler(
    State(state): State<Arc<DeploymentService>>,
    State(history): State<Arc<HistoryManager>>,
) -> Response {
    if std::env::var(WEB_UPDATE_ENV).as_deref() != Ok("true") {
        return (
            StatusCode::FORBIDDEN,
            format!(
                "Web-triggered updates are disabled. Set {}=true to enable them explicitly.",
                WEB_UPDATE_ENV
            ),
        )
            .into_response();
    }

    let record = DeploymentRecord {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        action: "update".to_string(),
        details: "Agent Update Triggered".to_string(),
        status: "in_progress".to_string(),
        image_id: None, // Agent update is source-based for now
        container_name: Some("mini-ops".to_string()),
    };

    match state.start_update(history, record) {
        Ok(()) => (
            StatusCode::OK,
            "Update triggered. Connect to stream for logs.",
        )
            .into_response(),
        Err(UpdateStartError::AlreadyRunning) => {
            (StatusCode::CONFLICT, "An update is already running.").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
