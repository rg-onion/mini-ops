mod metrics;
mod notifications;
mod docker;
mod deployment;
mod disk_ops;
mod auth;
mod history;
mod security;
mod i18n;
mod ssh_alerts;

use security::{SecurityAuditor, SecurityCheck, SecurityMonitor};
use ssh_alerts::{SshAlertsService, SshLoginEvent};

use rand::Rng;

use axum::{
    extract::{Path, State, FromRef, Query},
    http::{header, StatusCode},
    middleware,
    response::{IntoResponse, Response, sse::{Event, Sse}},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use metrics::{MetricsState, SystemStats};
use notifications::NotificationService;
use docker::DockerService;
use deployment::{DeploymentService, deploy_logs_sse_handler, trigger_update_handler};
use disk_ops::{DiskOps, DiskUsageBreakdown};
use history::HistoryManager;
use auth::auth_middleware;
use rust_embed::RustEmbed;
use sqlx::sqlite::SqlitePoolOptions;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::trace::TraceLayer;

#[derive(RustEmbed)]
#[folder = "frontend/dist"]
struct Asset;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    
    // Check or generate AUTH_TOKEN
    if std::env::var("AUTH_TOKEN").is_err() {
        let token: String = (0..32)
            .map(|_| {
                let idx = rand::rng().random_range(0..62);
                let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                chars[idx] as char
            })
            .collect();

        let preview = format!("{}***", &token.chars().take(6).collect::<String>());
        println!("\n\n WARNING: AUTH_TOKEN not found. Generated and persisted to .env.");
        println!(" Token preview: {}", preview);
        println!(" Please rotate it for production use.\n\n");

        // Save to .env
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(".env") {
            writeln!(file, "AUTH_TOKEN={}", token).ok();
        }

        // Set for current process
        unsafe { std::env::set_var("AUTH_TOKEN", token); }
    }
    
    // Initialize tracing with RUST_LOG support
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into())
        )
        .init();

    // 1. Setup Database
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:mini-ops.db".to_string());
    
    // Create file if not exists for sqlite
    if !std::path::Path::new("mini-ops.db").exists() {
        std::fs::File::create("mini-ops.db").unwrap();
    }

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Could not connect to database");

    // Initialize schema
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cpu_usage REAL,
            memory_used INTEGER,
            memory_total INTEGER,
            disk_used INTEGER,
            disk_total INTEGER,
            timestamp INTEGER
        )"
    )
    .execute(&pool)
    .await
    .expect("Could not initialize schema");

    // Initialize SSH Alerts tables
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS ssh_logins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT NOT NULL,
            ip TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            method TEXT NOT NULL,
            notified BOOLEAN DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS trusted_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            description TEXT,
            added_at INTEGER NOT NULL
        );"
    )
    .execute(&pool)
    .await
    .expect("Could not initialize SSH alerts schema");

    // 2. Setup Services
    let metrics_state = Arc::new(MetricsState::new());
    let notifications = Arc::new(NotificationService::new());
    
    // Start Security Monitor
    let security_monitor = Arc::new(SecurityMonitor::new(notifications.clone()));
    tokio::spawn(async move {
        security_monitor.run_loop().await;
    });

    // Setup SSH Alerts
    let ssh_alerts_service = Arc::new(SshAlertsService::new(pool.clone(), notifications.clone()));
    
    // Generate and save internal token
    let internal_token = uuid::Uuid::new_v4().to_string();
    if let Err(e) = std::fs::write("/tmp/mini-ops-internal.token", &internal_token) {
        tracing::error!("Failed to write internal token: {}", e);
    } else {
        // Build script requires 600 permissions
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata("/tmp/mini-ops-internal.token") {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions("/tmp/mini-ops-internal.token", perms);
        }
    }
    ssh_alerts_service.set_token(internal_token);

    let docker_service = match DockerService::new() {
        Ok(s) => Some(Arc::new(s)),
        Err(e) => {
            tracing::error!("Failed to initialize Docker service: {}", e);
            None
        }
    };

    let deployment_service = Arc::new(DeploymentService::new());
    let history_manager = Arc::new(HistoryManager::new("history.json"));
    
    // 3. Start Background Task for Metrics & Alerts
    let metrics_clone = Arc::clone(&metrics_state);
    let notifier_clone = Arc::clone(&notifications);
    let pool_clone = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            metrics_clone.refresh();
            let stats = metrics_clone.get_current();
            
            // Check for critical alerts
            let lang = i18n::Lang::from_headers(&header::HeaderMap::new());
            if stats.cpu_usage > 95.0 {
                notifier_clone.send_alert(&i18n::t_val("alert.critical_cpu", &lang, &format!("{:.1}", stats.cpu_usage))).await;
            }
            let disk_percent = (stats.disk_used as f64 / stats.disk_total as f64) * 100.0;
            if disk_percent > 90.0 {
                notifier_clone.send_alert(&i18n::t_val("alert.low_disk", &lang, &format!("{:.1}", disk_percent))).await;
            }

            let _ = sqlx::query(
                "INSERT INTO metrics (cpu_usage, memory_used, memory_total, disk_used, disk_total, timestamp) VALUES (?, ?, ?, ?, ?, ?)"
            )
            .bind(stats.cpu_usage)
            .bind(stats.memory_used as i64)
            .bind(stats.memory_total as i64)
            .bind(stats.disk_used as i64)
            .bind(stats.disk_total as i64)
            .bind(stats.timestamp)
            .execute(&pool_clone)
            .await;
        }
    });

    // 4. Setup Router
    let protected_api = Router::new()
        .route("/stats", get(get_stats_handler))
        .route("/stats/history", get(get_history_handler))
        .route("/history", get(list_deployments_handler))
        .route("/test-notification", post(test_notification_handler))
        .route("/docker/containers", get(list_containers_handler))
        .route("/docker/containers/{id}/{action}", post(container_action_handler))
        .route("/docker/containers/{id}/logs", get(docker_logs_sse_handler)) // SSE by default now
        .route("/disk/usage", get(get_disk_usage_handler))
        .route("/disk/clean", post(clean_disk_handler))
        .route("/deploy/webhook", post(trigger_update_handler))
        .route("/deploy/logs", get(deploy_logs_sse_handler))
        .route("/security/audit", get(get_security_audit_handler))
        .route("/ssh/logs", get(get_ssh_logs_handler))
        .route("/ssh/trusted-ips", get(get_trusted_ips_handler))
        .route("/ssh/trusted-ips", post(add_trusted_ip_handler))
        .route("/ssh/trusted-ips/{id}", post(delete_trusted_ip_handler))
        .route("/ssh/setup-alerts", post(setup_ssh_alerts_handler))
        .route("/version", get(get_version_handler));

    let internal_api = Router::new()
        .route("/internal/ssh-login", post(ssh_login_handler));

    let api_routes = Router::new()
        .merge(protected_api.layer(middleware::from_fn(auth_middleware)))
        .merge(internal_api);

    let app = Router::new()
        .nest("/api", api_routes)
        .route("/", get(index_handler))
        .route("/index.html", get(index_handler))
        .route("/{*path}", get(handler)) // Modern catch-all
        .layer(TraceLayer::new_for_http())
        .with_state(AppState { 
            metrics: metrics_state, 
            db: pool, 
            notifier: notifications, 
            docker: docker_service,
            deployment: deployment_service,
            history: history_manager,
            ssh_alerts: ssh_alerts_service,
        });

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("Mini-Ops listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(Clone)]
struct AppState {
    metrics: Arc<MetricsState>,
    db: sqlx::SqlitePool,
    notifier: Arc<NotificationService>,
    docker: Option<Arc<DockerService>>,
    deployment: Arc<DeploymentService>,
    history: Arc<HistoryManager>,
    ssh_alerts: Arc<SshAlertsService>,
}

impl FromRef<AppState> for Arc<DeploymentService> {
    fn from_ref(state: &AppState) -> Self {
        state.deployment.clone()
    }
}

impl FromRef<AppState> for Arc<HistoryManager> {
    fn from_ref(state: &AppState) -> Self {
        state.history.clone()
    }
}

async fn get_stats_handler(State(state): State<AppState>) -> Json<SystemStats> {
    Json(state.metrics.get_current())
}

async fn get_history_handler(State(state): State<AppState>) -> Json<Vec<SystemStats>> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT cpu_usage, memory_used, memory_total, disk_used, disk_total, timestamp FROM metrics ORDER BY timestamp DESC LIMIT 60"
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    
    let stats = rows.into_iter().map(|row| {
        SystemStats {
            cpu_usage: row.get::<f64, _>("cpu_usage") as f32,
            memory_used: row.get::<i64, _>("memory_used") as u64,
            memory_total: row.get::<i64, _>("memory_total") as u64,
            disk_used: row.get::<i64, _>("disk_used") as u64,
            disk_total: row.get::<i64, _>("disk_total") as u64,
            timestamp: row.get::<i64, _>("timestamp"),
        }
    }).collect();

    Json(stats)
}

async fn list_deployments_handler(State(state): State<AppState>) -> Json<Vec<history::DeploymentRecord>> {
    Json(state.history.get_history())
}

async fn test_notification_handler(State(state): State<AppState>, headers: header::HeaderMap) -> impl IntoResponse {
    let lang = i18n::Lang::from_headers(&headers);
    state.notifier.send_alert(&i18n::t("alert.test", &lang)).await;
    StatusCode::OK
}

async fn list_containers_handler(State(state): State<AppState>) -> Response {
    if let Some(docker) = &state.docker {
        match docker.list_containers().await {
            Ok(containers) => Json(containers).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
        }
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "Docker integration is not available").into_response()
    }
}

async fn container_action_handler(
    State(state): State<AppState>,
    Path((id, action)): Path<(String, String)>,
) -> Response {
    if let Some(docker) = &state.docker {
        let result = match action.as_str() {
            "start" => docker.start_container(&id).await,
            "stop" => docker.stop_container(&id).await,
            "restart" => docker.restart_container(&id).await,
            _ => return (StatusCode::BAD_REQUEST, "Invalid action. Use start, stop, or restart").into_response(),
        };

        match result {
            Ok(_) => StatusCode::OK.into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
        }
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "Docker integration is not available").into_response()
    }
}

/// Параметры запроса для фильтрации логов.
#[derive(serde::Deserialize)]
struct LogParams {
    /// Timestamp начала логов
    since: Option<i64>,
    /// Количество строк с конца
    tail: Option<String>,
}

/// SSE-based log streaming
/// SSE-обработчик для потоковой передачи логов Docker.
/// 
/// Поддерживает параметры запроса:
/// * `since` - (i64) время начала (Unix timestamp)
/// * `tail` - (String) количество строк с конца
async fn docker_logs_sse_handler(
    Path(id): Path<String>,
    Query(params): Query<LogParams>,
    State(state): State<AppState>,
) -> Response {
    use futures_util::StreamExt;
    use std::convert::Infallible;
    use tokio_stream::wrappers::ReceiverStream;

    tracing::info!("SSE Stream requested for container: {}", id);

    let docker = match &state.docker {
        Some(d) => d.clone(),
        None => return (StatusCode::SERVICE_UNAVAILABLE, "Docker not available").into_response(),
    };

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(100);
    let container_id = id.clone();

    // Validate tail parameter to prevent resource exhaustion
    let safe_tail = match params.tail.as_deref() {
        Some("all") => Some("10000".to_string()),
        Some(t) => {
            if let Ok(val) = t.parse::<u32>() {
                Some(std::cmp::min(val, 10000).to_string())
            } else {
                Some("100".to_string())
            }
        },
        None => Some("100".to_string()),
    };

    tokio::spawn(async move {
        let mut stream = docker.logs_stream(&container_id, params.since, safe_tail);
        while let Some(result) = stream.next().await {
            let event = match result {
                Ok(line) => Event::default().data(line),
                Err(e) => {
                    tracing::error!("Log stream error for {}: {}", container_id, e);
                    Event::default().data(format!("Error: {}", e))
                }
            };
            if tx.send(Ok(event)).await.is_err() {
                break;
            }
        }
    });

    Sse::new(ReceiverStream::new(rx))
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response()
}

async fn get_disk_usage_handler() -> Json<DiskUsageBreakdown> {
    Json(DiskOps::get_usage("."))
}

#[derive(serde::Deserialize)]
struct CleanRequest {
    target: String,
}

async fn clean_disk_handler(Json(payload): Json<CleanRequest>) -> Response {
    let result = match payload.target.as_str() {
        "target" => DiskOps::clean_target(".").await,
        "node_modules" => DiskOps::clean_node_modules(".").await,
        "docker" => DiskOps::clean_docker().await,
        "logs" => DiskOps::clean_logs().await,
        _ => Err("Invalid target".to_string()),
    };

    match result {
        Ok(msg) => (StatusCode::OK, msg).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

async fn index_handler() -> impl IntoResponse {
    serve_file("index.html")
}

async fn handler(Path(path): Path<String>) -> impl IntoResponse {
    serve_file(&path)
}

fn serve_file(path: &str) -> Response {
    if let Some(content) = Asset::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return ([(header::CONTENT_TYPE, mime.as_ref())], content.data).into_response();
    }

    if path.starts_with("assets/") {
         return (StatusCode::NOT_FOUND, "Asset not found").into_response();
    }

    if let Some(content) = Asset::get("index.html") {
        let mime = mime_guess::mime::TEXT_HTML;
        return ([(header::CONTENT_TYPE, mime.as_ref())], content.data).into_response();
    }

    (StatusCode::NOT_FOUND, "index.html not found").into_response()
}

async fn get_security_audit_handler(headers: header::HeaderMap) -> Json<Vec<SecurityCheck>> {
    let lang = i18n::Lang::from_headers(&headers);
    Json(SecurityAuditor::run_audit(&lang).await)
}

async fn get_version_handler() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

async fn ssh_login_handler(
    State(state): State<AppState>,
    headers: header::HeaderMap,
    Json(event): Json<SshLoginEvent>,
) -> Response {
    let token = headers.get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or("");
    
    match state.ssh_alerts.handle_login(event, token).await {
            Ok(_) => StatusCode::OK.into_response(),
            Err(e) => {
                tracing::warn!("Failed SSH login alert attempt: {}", e);
                (StatusCode::UNAUTHORIZED, e).into_response()
            },
    }
}

async fn get_ssh_logs_handler(State(state): State<AppState>) -> Response {
    match state.ssh_alerts.get_logs().await {
        Ok(logs) => Json(logs).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_trusted_ips_handler(State(state): State<AppState>) -> Response {
    match state.ssh_alerts.get_trusted_ips().await {
        Ok(ips) => Json(ips).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct AddIpRequest {
    ip: String,
    description: Option<String>,
}

async fn add_trusted_ip_handler(
    State(state): State<AppState>,
    Json(payload): Json<AddIpRequest>,
) -> Response {
    match state.ssh_alerts.add_trusted_ip(payload.ip, payload.description).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn delete_trusted_ip_handler(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Response {
    match state.ssh_alerts.delete_trusted_ip(id).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn setup_ssh_alerts_handler() -> Response {
    use std::process::Command;
    match Command::new("sudo").arg("./scripts/setup_ssh_alerts.sh").output() {
        Ok(output) => {
            if output.status.success() {
                StatusCode::OK.into_response()
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, String::from_utf8_lossy(&output.stderr).to_string()).into_response()
            }
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
