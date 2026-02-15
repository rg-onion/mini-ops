use std::sync::Arc;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{sse::{Event, KeepAlive, Sse}, IntoResponse, Response},
};
use futures_util::stream;
use crate::history::{HistoryManager, DeploymentRecord};

#[derive(Clone)]
pub struct DeploymentService {
    tx: tokio::sync::broadcast::Sender<String>,
}

impl DeploymentService {
    pub fn new() -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(100);
        Self { tx }
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<String> {
        self.tx.subscribe()
    }

    pub async fn run_update_stream(&self) {
        use std::process::Stdio;
        use tokio::io::{AsyncBufReadExt, BufReader};
        use tokio::process::Command;

        let tx = self.tx.clone();
        
        tokio::spawn(async move {
            let _ = tx.send("🚀 Starting update process...".to_string());
            
            let mut cmd = Command::new("bash");
            cmd.arg("./scripts/update.sh");
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());

            let mut child = match cmd.spawn() {
                Ok(child) => child,
                Err(e) => {
                    let _ = tx.send(format!("❌ Failed to start script: {}", e));
                    return;
                }
            };

            let stdout = child.stdout.take().expect("Failed to open stdout");
            let stderr = child.stderr.take().expect("Failed to open stderr");

            let mut stdout_reader = BufReader::new(stdout).lines();
            let mut stderr_reader = BufReader::new(stderr).lines();

            loop {
                tokio::select! {
                    result = stdout_reader.next_line() => {
                        match result {
                            Ok(Some(line)) => { let _ = tx.send(format!("STDOUT: {}", line)); }
                            Ok(None) => break, // EOF
                            Err(_) => break,
                        }
                    }
                    result = stderr_reader.next_line() => {
                        match result {
                            Ok(Some(line)) => { let _ = tx.send(format!("STDERR: {}", line)); }
                            Ok(None) => break, // EOF
                            Err(_) => break,
                        }
                    }
                }
            }

            match child.wait().await {
                Ok(status) => {
                    if status.success() {
                        let _ = tx.send("✅ Update complete! Service restarting...".to_string());
                    } else {
                        let _ = tx.send(format!("❌ Update failed with status: {}", status));
                    }
                }
                Err(e) => {
                    let _ = tx.send(format!("❌ Failed to wait on child: {}", e));
                }
            }
        });
    }
}

pub async fn trigger_update_handler(
    State(state): State<Arc<DeploymentService>>,
    State(history): State<Arc<HistoryManager>>,
) -> Response {
    // Record deployment
     history.add_record(DeploymentRecord {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        action: "update".to_string(),
        details: "Agent Update Triggered".to_string(),
        status: "in_progress".to_string(),
        image_id: None, // Agent update is source-based for now
        container_name: Some("mini-ops".to_string()),
    });
    
    state.run_update_stream().await;
    (StatusCode::OK, "Update triggered. Connect to stream for logs.").into_response()
}

pub async fn deploy_logs_sse_handler(
    State(state): State<Arc<DeploymentService>>,
) -> Response {
    let rx = state.subscribe();
    let sse_stream = stream::unfold(rx, |mut rx| async move {
        match rx.recv().await {
            Ok(msg) => Some((Ok::<Event, std::convert::Infallible>(Event::default().data(msg)), rx)),
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                Some((Ok(Event::default().data("⚠️ Log stream lagged, some lines were skipped")), rx))
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => None,
        }
    });

    (
        [(header::CACHE_CONTROL, "no-cache")],
        Sse::new(sse_stream).keep_alive(KeepAlive::default()),
    )
        .into_response()
}
