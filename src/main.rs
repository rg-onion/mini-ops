mod auth;
mod cloud_payload;
mod cloud_push;
mod deployment;
mod disk_ops;
mod docker;
mod history;
mod i18n;
mod metrics;
mod notifications;
mod retention;
mod security;
mod security_events;
mod ssh_alerts;

use security::{SecurityAuditCache, SecurityCheck, SecurityMonitor};
use security_events::{SecurityEvent, SecurityEventService};
use ssh_alerts::{SshAlertsService, SshLoginEvent};

use rand::Rng;

use auth::auth_middleware;
use axum::{
    Json, Router,
    extract::{FromRef, Path, Query, State},
    http::{StatusCode, header},
    middleware,
    response::{
        IntoResponse, Response,
        sse::{Event, Sse},
    },
    routing::{delete, get, post},
};
use deployment::{DeploymentService, deploy_logs_sse_handler, trigger_update_handler};
use disk_ops::{DiskOps, DiskUsageBreakdown};
use docker::DockerService;
use history::HistoryManager;
use metrics::{MetricsState, SystemStats};
use notifications::NotificationService;
use rust_embed::RustEmbed;
use serde::Deserialize;
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

    let auth_token = match resolve_auth_token() {
        Ok(token) => token,
        Err(e) => {
            eprintln!("CRITICAL: {}", e);
            std::process::exit(1);
        }
    };

    // Initialize auth token in OnceLock — safe, called before any threads are spawned
    auth::init_token(auth_token);

    // Initialize tracing with RUST_LOG support
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // 1. Setup Database
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:mini-ops.db".to_string());

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
        )",
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
        );",
    )
    .execute(&pool)
    .await
    .expect("Could not initialize SSH alerts schema");

    SecurityEventService::init_schema(&pool)
        .await
        .expect("Could not initialize security events schema");

    retention::init_indexes(&pool)
        .await
        .expect("Could not initialize retention indexes");

    // 2. Setup Services
    let metrics_state = Arc::new(MetricsState::new());
    let notifications = Arc::new(NotificationService::new());
    let retention_config = retention::RetentionConfig::from_env();
    let security_audit_cache = SecurityAuditCache::from_env();
    let security_events = Arc::new(SecurityEventService::new(pool.clone()));

    let docker_service = match DockerService::new() {
        Ok(s) => Some(Arc::new(s)),
        Err(e) => {
            tracing::error!("Failed to initialize Docker service: {}", e);
            None
        }
    };

    // Start Security Monitor
    let security_monitor = Arc::new(SecurityMonitor::new(
        notifications.clone(),
        docker_service.clone(),
        security_events.clone(),
    ));
    tokio::spawn(async move {
        security_monitor.run_loop().await;
    });

    // Setup SSH Alerts
    let ssh_alerts_service = Arc::new(SshAlertsService::new(
        pool.clone(),
        notifications.clone(),
        security_events.clone(),
        retention_config.ssh_logins_retention_days,
    ));

    // Generate and save internal token
    let internal_token = uuid::Uuid::new_v4().to_string();
    let internal_token_path = std::env::var("MINI_OPS_INTERNAL_TOKEN_FILE")
        .ok()
        .filter(|path| !path.trim().is_empty())
        .unwrap_or_else(|| "mini-ops-internal.token".to_string());
    if let Err(e) = write_internal_token(&internal_token_path, &internal_token) {
        tracing::error!(
            "Failed to write internal token to {}: {}",
            internal_token_path,
            e
        );
    }
    ssh_alerts_service.set_token(internal_token);

    let deployment_service = Arc::new(DeploymentService::new());
    let history_manager = Arc::new(HistoryManager::new("history.json"));

    // Cloud Push (optional)
    if std::env::var("CLOUD_PUSH_ENABLED").as_deref() == Ok("true") {
        match (
            std::env::var("CLOUD_HUB_URL"),
            std::env::var("CLOUD_AGENT_ID"),
            std::env::var("CLOUD_AGENT_TOKEN"),
        ) {
            (Ok(hub_url), Ok(agent_id), Ok(agent_token)) => {
                let interval = std::env::var("CLOUD_PUSH_INTERVAL")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(60u64);
                let config = cloud_push::CloudPushConfig {
                    hub_url,
                    agent_id,
                    agent_token,
                    push_interval_secs: interval,
                };
                match cloud_push::CloudPushService::new(config) {
                    Ok(svc) => {
                        Arc::new(svc).start(
                            Arc::clone(&metrics_state),
                            docker_service.clone(),
                            Arc::clone(&ssh_alerts_service),
                        );
                        tracing::info!("Cloud push enabled, interval={}s", interval);
                    }
                    Err(e) => {
                        tracing::error!("Cloud push disabled: {}", e);
                    }
                }
            }
            _ => tracing::warn!(
                "CLOUD_PUSH_ENABLED=true but CLOUD_HUB_URL/CLOUD_AGENT_ID/CLOUD_AGENT_TOKEN missing"
            ),
        }
    }

    // 3. Start Background Task for Metrics & Alerts
    let metrics_clone = Arc::clone(&metrics_state);
    let notifier_clone = Arc::clone(&notifications);
    let pool_clone = pool.clone();
    let metrics_retention_hours = retention_config.metrics_retention_hours;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        let mut next_metrics_cleanup_at = 0_i64;
        loop {
            interval.tick().await;
            metrics_clone.refresh();
            let stats = metrics_clone.get_current();

            // Check for critical alerts
            let lang = i18n::Lang::from_headers(&header::HeaderMap::new());
            if stats.cpu_usage > 95.0 {
                notifier_clone
                    .send_alert(&i18n::t_val(
                        "alert.critical_cpu",
                        &lang,
                        &format!("{:.1}", stats.cpu_usage),
                    ))
                    .await;
            }
            let disk_percent = (stats.disk_used as f64 / stats.disk_total as f64) * 100.0;
            if disk_percent > 90.0 {
                notifier_clone
                    .send_alert(&i18n::t_val(
                        "alert.low_disk",
                        &lang,
                        &format!("{:.1}", disk_percent),
                    ))
                    .await;
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

            if stats.timestamp >= next_metrics_cleanup_at {
                match retention::prune_metrics(
                    &pool_clone,
                    stats.timestamp,
                    metrics_retention_hours,
                )
                .await
                {
                    Ok(rows) if rows > 0 => {
                        tracing::info!("Pruned {} old metrics rows", rows);
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!("Failed to prune old metrics rows: {}", e);
                    }
                }
                next_metrics_cleanup_at = stats.timestamp.saturating_add(3600);
            }
        }
    });

    // 4. Setup Router
    let protected_api = Router::new()
        .route("/stats", get(get_stats_handler))
        .route("/stats/history", get(get_history_handler))
        .route("/history", get(list_deployments_handler))
        .route("/test-notification", post(test_notification_handler))
        .route("/docker/containers", get(list_containers_handler))
        .route(
            "/docker/containers/{id}/{action}",
            post(container_action_handler),
        )
        .route("/docker/containers/{id}/logs", get(docker_logs_sse_handler)) // SSE by default now
        .route("/disk/usage", get(get_disk_usage_handler))
        .route("/disk/clean", post(clean_disk_handler))
        .route("/deploy/webhook", post(trigger_update_handler))
        .route("/deploy/logs", get(deploy_logs_sse_handler))
        .route("/security/audit", get(get_security_audit_handler))
        .route("/security/events", get(get_security_events_handler))
        .route(
            "/security/events/{id}/ack",
            post(ack_security_event_handler),
        )
        .route("/ssh/logs", get(get_ssh_logs_handler))
        .route("/ssh/trusted-ips", get(get_trusted_ips_handler))
        .route("/ssh/trusted-ips", post(add_trusted_ip_handler))
        .route("/ssh/trusted-ips/{id}", delete(delete_trusted_ip_handler))
        .route("/ssh/setup-alerts", post(setup_ssh_alerts_handler))
        .route("/version", get(get_version_handler));

    let internal_api = Router::new().route("/internal/ssh-login", post(ssh_login_handler));

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
            security_events,
            security_audit_cache,
        });

    let app_host = std::env::var("APP_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let app_port = std::env::var("APP_PORT").unwrap_or_else(|_| "3000".to_string());
    let addr_str = format!("{}:{}", app_host, app_port);
    let addr: SocketAddr = addr_str
        .parse()
        .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 3000)));

    tracing::info!("Mini-Ops listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn write_internal_token(path: &str, token: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let path = std::path::Path::new(path);
    if let Ok(metadata) = std::fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        return Err(std::io::Error::other(
            "refusing to write internal token through symlink",
        ));
    }

    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(token.as_bytes())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn resolve_auth_token() -> Result<String, String> {
    match std::env::var("AUTH_TOKEN") {
        Ok(token) if !token.trim().is_empty() => {
            let token = token.trim().to_string();
            validate_auth_token(&token)?;
            Ok(token)
        }
        _ => {
            let token = generate_auth_token();
            persist_auth_token_to_env(".env", &token).map_err(|e| {
                format!(
                    "AUTH_TOKEN is missing and could not be persisted to .env: {}",
                    e
                )
            })?;
            eprintln!(
                "WARNING: AUTH_TOKEN was missing. Generated a strong token and persisted it to .env with 0600 permissions."
            );
            Ok(token)
        }
    }
}

fn validate_auth_token(token: &str) -> Result<(), String> {
    if auth_token_is_placeholder(token) {
        return Err(
            "AUTH_TOKEN is set to a known placeholder. Generate a strong token with `openssl rand -hex 32`."
                .to_string(),
        );
    }

    if token.len() < 32 && std::env::var("MINI_OPS_ALLOW_WEAK_AUTH_TOKEN").as_deref() != Ok("true")
    {
        return Err(
            "AUTH_TOKEN must be at least 32 characters. Set MINI_OPS_ALLOW_WEAK_AUTH_TOKEN=true only for local testing."
                .to_string(),
        );
    }

    Ok(())
}

fn auth_token_is_placeholder(token: &str) -> bool {
    let normalized = token.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "your_secret_token_here"
            | "your_secret_token"
            | "your_strong_token"
            | "change-me"
            | "change-me-strong-random-token"
            | "your-random-secure-string-at-least-32-chars"
            | "your_auth_token"
            | "auth_token"
            | "token"
    )
}

fn generate_auth_token() -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..64)
        .map(|_| {
            let idx = rand::rng().random_range(0..CHARS.len());
            CHARS[idx] as char
        })
        .collect()
}

fn persist_auth_token_to_env(path: &str, token: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let path = std::path::Path::new(path);
    if let Ok(metadata) = std::fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        return Err(std::io::Error::other(
            "refusing to write AUTH_TOKEN through symlink",
        ));
    }

    let existing = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };

    let mut replaced = false;
    let mut lines = Vec::new();
    for line in existing.lines() {
        if line.starts_with("AUTH_TOKEN=") {
            if !replaced {
                lines.push(format!("AUTH_TOKEN={}", token));
                replaced = true;
            }
        } else {
            lines.push(line.to_string());
        }
    }

    if !replaced {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push(format!("AUTH_TOKEN={}", token));
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(lines.join("\n").as_bytes())?;
    file.write_all(b"\n")?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
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
    security_events: Arc<SecurityEventService>,
    security_audit_cache: SecurityAuditCache,
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

    let stats = rows
        .into_iter()
        .map(|row| SystemStats {
            cpu_usage: row.get::<f64, _>("cpu_usage") as f32,
            memory_used: row.get::<i64, _>("memory_used") as u64,
            memory_total: row.get::<i64, _>("memory_total") as u64,
            disk_used: row.get::<i64, _>("disk_used") as u64,
            disk_total: row.get::<i64, _>("disk_total") as u64,
            timestamp: row.get::<i64, _>("timestamp"),
        })
        .collect();

    Json(stats)
}

async fn list_deployments_handler(
    State(state): State<AppState>,
) -> Json<Vec<history::DeploymentRecord>> {
    Json(state.history.get_history())
}

async fn test_notification_handler(
    State(state): State<AppState>,
    headers: header::HeaderMap,
) -> impl IntoResponse {
    let lang = i18n::Lang::from_headers(&headers);
    state
        .notifier
        .send_alert(&i18n::t("alert.test", &lang))
        .await;
    StatusCode::OK
}

async fn list_containers_handler(State(state): State<AppState>) -> Response {
    if let Some(docker) = &state.docker {
        match docker.list_containers().await {
            Ok(containers) => Json(containers).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
        }
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Docker integration is not available",
        )
            .into_response()
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
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    "Invalid action. Use start, stop, or restart",
                )
                    .into_response();
            }
        };

        match result {
            Ok(_) => StatusCode::OK.into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
        }
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Docker integration is not available",
        )
            .into_response()
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
        }
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

async fn get_security_audit_handler(
    State(state): State<AppState>,
    headers: header::HeaderMap,
) -> Json<Vec<SecurityCheck>> {
    let lang = i18n::Lang::from_headers(&headers);
    Json(
        state
            .security_audit_cache
            .get_or_run(lang, state.docker.as_deref())
            .await,
    )
}

#[derive(Deserialize)]
struct SecurityEventsParams {
    status: Option<String>,
    limit: Option<i64>,
}

async fn get_security_events_handler(
    State(state): State<AppState>,
    Query(params): Query<SecurityEventsParams>,
) -> Response {
    let status = params.status.as_deref();
    let limit = params.limit.unwrap_or(100);

    match state.security_events.list(status, limit).await {
        Ok(events) => Json::<Vec<SecurityEvent>>(events).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn ack_security_event_handler(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Response {
    match state.security_events.acknowledge(id).await {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_version_handler() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

async fn ssh_login_handler(
    State(state): State<AppState>,
    headers: header::HeaderMap,
    Json(event): Json<SshLoginEvent>,
) -> Response {
    let token = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or("");

    match state.ssh_alerts.handle_login(event, token).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => {
            tracing::warn!("Failed SSH login alert attempt: {}", e);
            (StatusCode::UNAUTHORIZED, e).into_response()
        }
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
    match state
        .ssh_alerts
        .add_trusted_ip(payload.ip, payload.description)
        .await
    {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn delete_trusted_ip_handler(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match state.ssh_alerts.delete_trusted_ip(id).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn setup_ssh_alerts_handler() -> Response {
    use std::process::{Command, Output};

    if std::env::var("MINI_OPS_ALLOW_SYSTEM_SETUP").as_deref() != Ok("true") {
        return (
            StatusCode::FORBIDDEN,
            "System setup from the web UI is disabled. Set MINI_OPS_ALLOW_SYSTEM_SETUP=true to enable it explicitly.",
        )
            .into_response();
    }

    let script_path = std::env::current_dir()
        .map(|d| d.join("scripts/setup_ssh_alerts.sh"))
        .unwrap_or_else(|_| std::path::PathBuf::from("/opt/mini-ops/scripts/setup_ssh_alerts.sh"));

    let direct_output = Command::new(&script_path).output();
    let output: Result<Output, std::io::Error> = match direct_output {
        Ok(output) if output.status.success() => Ok(output),
        _ => Command::new("/usr/bin/sudo")
            .arg("-n")
            .arg(&script_path)
            .output(),
    };

    match output {
        Ok(output) => {
            if output.status.success() {
                StatusCode::OK.into_response()
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    String::from_utf8_lossy(&output.stderr).to_string(),
                )
                    .into_response()
            }
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
