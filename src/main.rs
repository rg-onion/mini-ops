mod auth;
// C1 is an intentionally isolated probe core. C2 will wire scheduling and
// persistence after the observation contract has stabilized.
#[allow(dead_code)]
mod certificate_probe;
mod cloud_payload;
mod cloud_push;
mod deployment;
mod disk_ops;
mod docker;
mod file_integrity;
mod history;
mod i18n;
mod metrics;
mod notifications;
mod retention;
mod runtime;
mod security;
mod security_events;
mod security_snapshot;
mod ssh_alerts;

use security::SecurityMonitor;
use security_events::{SecurityEvent, SecurityEventService};
use security_snapshot::{
    SecurityAuditSnapshot, SecuritySnapshotService, SecuritySnapshotUnavailable,
};
use ssh_alerts::{SshAlertsService, SshLoginEvent};

use rand::Rng;

use auth::auth_middleware;
use axum::{
    Json, Router,
    extract::{FromRef, Path, Query, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{
        IntoResponse, Response,
        sse::{Event, Sse},
    },
    routing::{delete, get, post},
};
use deployment::{
    DeploymentService, api_error_response, deploy_logs_sse_handler, trigger_update_handler,
};
use disk_ops::{DiskOps, DiskUsageBreakdown};
use docker::DockerService;
use file_integrity::{
    FileIntegrityConfig, FileIntegrityOperationError, FileIntegrityService, ReEnrollRequest,
    TrustCurrentStateRequest,
};
use history::HistoryManager;
use metrics::{MetricsState, SystemStats};
use notifications::{
    NotificationEvent, NotificationOutbox, NotificationOutcome, NotificationService,
};
use rust_embed::RustEmbed;
use serde::{Deserialize, de::DeserializeOwned};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::{Level, Metadata};
use tracing_subscriber::{filter::filter_fn, layer::SubscriberExt, util::SubscriberInitExt};

const DISK_CLEANUP_ENV: &str = "MINI_OPS_ALLOW_DISK_CLEANUP";
const RESTRICTED_LOG_TARGETS: &[&str] = &[
    "bollard",
    "h2",
    "hyper",
    "hyper_rustls",
    "hyper_util",
    "reqwest",
    "rustls",
    "tokio_rustls",
];

#[derive(Clone, Copy)]
struct DiskCleanupGate {
    enabled: bool,
}

impl DiskCleanupGate {
    fn from_env() -> Self {
        Self {
            enabled: disk_cleanup_enabled(std::env::var(DISK_CLEANUP_ENV).ok().as_deref()),
        }
    }
}

fn disk_cleanup_enabled(value: Option<&str>) -> bool {
    value == Some("true")
}

async fn require_disk_cleanup(
    State(gate): State<DiskCleanupGate>,
    request: Request,
    next: Next,
) -> Response {
    if !gate.enabled {
        return api_error_response(StatusCode::FORBIDDEN, "capability_disabled");
    }

    next.run(request).await
}

#[derive(RustEmbed)]
#[folder = "frontend/dist"]
struct Asset;

#[tokio::main]
async fn main() {
    runtime::enforce_private_process_umask();
    let runtime_mode = runtime::RuntimeMode::detect();
    if runtime_mode == runtime::RuntimeMode::Standalone {
        dotenvy::dotenv().ok();
    }

    let file_integrity_config = FileIntegrityConfig::from_env().unwrap_or_else(|error| {
        eprintln!("CRITICAL: file_integrity_configuration: {}", error.code());
        std::process::exit(1);
    });
    file_integrity_config
        .validate_runtime_identity(runtime::effective_uid())
        .unwrap_or_else(|error| {
            eprintln!("CRITICAL: file_integrity_configuration: {}", error.code());
            std::process::exit(1);
        });

    let auth_token = match resolve_auth_token(runtime_mode) {
        Ok(token) => token,
        Err(e) => {
            eprintln!("CRITICAL: {}", e);
            std::process::exit(1);
        }
    };

    // Initialize auth token in OnceLock — safe, called before any threads are spawned
    auth::init_token(auth_token);

    init_tracing();

    // 1. Setup Database
    let configured_database_url = std::env::var("DATABASE_URL").ok();
    let database_url =
        runtime::resolve_database_url(configured_database_url.as_deref(), runtime_mode)
            .unwrap_or_else(|error| exit_with_runtime_error("database_configuration", error));
    runtime::sqlite_connect_options(&database_url, runtime_mode)
        .unwrap_or_else(|error| exit_with_runtime_error("database_configuration", error));
    let pool = runtime::connect_sqlite_pool(&database_url, runtime_mode, 5)
        .await
        .unwrap_or_else(|error| exit_with_runtime_error("database_connection", error));

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

    runtime::ensure_sqlite_private_database(&database_url, runtime_mode)
        .unwrap_or_else(|error| exit_with_runtime_error("database_permissions", error));

    // 2. Setup Services
    let metrics_state = Arc::new(MetricsState::new());
    let notifications = Arc::new(NotificationService::new());
    let retention_config = retention::RetentionConfig::from_env();
    let security_events = Arc::new(SecurityEventService::new(pool.clone()));
    let notification_outbox =
        Arc::new(NotificationOutbox::new(pool.clone(), notifications.clone()));
    let file_integrity = if file_integrity_config.enabled() {
        FileIntegrityService::initialize_enabled(
            pool.clone(),
            Arc::clone(&notification_outbox),
            file_integrity_config,
        )
        .await
        .unwrap_or_else(|error| {
            eprintln!("CRITICAL: file_integrity_initialization: {}", error.code());
            std::process::exit(1);
        })
    } else {
        FileIntegrityService::disabled()
    };

    let docker_service = match DockerService::new() {
        Ok(s) => Some(Arc::new(s)),
        Err(_) => {
            tracing::error!(
                docker_error = "initialization_failed",
                "Docker integration unavailable"
            );
            None
        }
    };
    let security_snapshots = SecuritySnapshotService::from_env(docker_service.clone());

    // Setup SSH Alerts
    let ssh_alerts_service = Arc::new(SshAlertsService::new(
        pool.clone(),
        notifications.clone(),
        security_events.clone(),
        notification_outbox.clone(),
        retention_config.ssh_logins_retention_days,
    ));

    // Generate and save internal token
    let internal_token = uuid::Uuid::new_v4().to_string();
    let configured_internal_token_path = std::env::var_os("MINI_OPS_INTERNAL_TOKEN_FILE");
    let internal_token_path = runtime::resolve_internal_token_path(
        configured_internal_token_path.as_deref(),
        runtime_mode,
    )
    .unwrap_or_else(|error| exit_with_runtime_error("internal_token_path", error));
    runtime::persist_and_publish_internal_token(&internal_token_path, internal_token, |token| {
        ssh_alerts_service.set_token(token)
    })
    .unwrap_or_else(|error| exit_with_runtime_error("internal_token_write", error));

    let _notification_worker = Arc::clone(&notification_outbox).start();
    let _file_integrity_worker = Arc::clone(&file_integrity).start();

    // Start the monitor only after all fail-fast runtime state is ready.
    let security_monitor = Arc::new(SecurityMonitor::new(
        notifications.clone(),
        notification_outbox.clone(),
        Arc::clone(&security_snapshots),
        security_events.clone(),
    ));
    tokio::spawn(async move {
        security_monitor.run_loop().await;
    });

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
                let interval = match std::env::var_os("CLOUD_PUSH_INTERVAL") {
                    None => cloud_push::parse_push_interval(None),
                    Some(value) => value
                        .to_str()
                        .ok_or(cloud_push::CloudPushIntervalError::Invalid)
                        .and_then(|value| cloud_push::parse_push_interval(Some(value))),
                };
                match interval {
                    Ok(interval) => {
                        let config = cloud_push::CloudPushConfig {
                            hub_url,
                            agent_id,
                            agent_token,
                            push_interval_secs: interval,
                        };
                        match cloud_push::CloudPushService::new(
                            config,
                            Arc::clone(&security_snapshots),
                        ) {
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
                    Err(error) => tracing::warn!(
                        configuration_error = error.code(),
                        "Cloud push disabled: invalid CLOUD_PUSH_INTERVAL"
                    ),
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
    let notification_outbox_clone = Arc::clone(&notification_outbox);
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
                let message = i18n::t_val(
                    "alert.critical_cpu",
                    &lang,
                    &format!("{:.1}", stats.cpu_usage),
                );
                let event = NotificationEvent::generic(
                    "metric:cpu:critical",
                    "metric.cpu.critical",
                    notifier_clone.render_alert_text(&message),
                    stats.timestamp,
                    1800,
                );
                if notification_outbox_clone.enqueue(&event).await.is_err() {
                    tracing::warn!(
                        delivery_error = "database",
                        "Could not enqueue CPU notification"
                    );
                }
            }
            let disk_percent = (stats.disk_used as f64 / stats.disk_total as f64) * 100.0;
            if disk_percent > 90.0 {
                let message = i18n::t_val("alert.low_disk", &lang, &format!("{:.1}", disk_percent));
                let event = NotificationEvent::generic(
                    "metric:disk:low",
                    "metric.disk.low",
                    notifier_clone.render_alert_text(&message),
                    stats.timestamp,
                    1800,
                );
                if notification_outbox_clone.enqueue(&event).await.is_err() {
                    tracing::warn!(
                        delivery_error = "database",
                        "Could not enqueue disk notification"
                    );
                }
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
        .route(
            "/disk/clean",
            post(clean_disk_handler).route_layer(middleware::from_fn_with_state(
                DiskCleanupGate::from_env(),
                require_disk_cleanup,
            )),
        )
        .route("/deploy/webhook", post(trigger_update_handler))
        .route("/deploy/logs", get(deploy_logs_sse_handler))
        .route("/security/audit", get(get_security_audit_handler))
        .route(
            "/security/file-integrity/status",
            get(get_file_integrity_status_handler),
        )
        .route(
            "/security/file-integrity/trust-current-state",
            post(trust_file_integrity_state_handler),
        )
        .route(
            "/security/file-integrity/re-enroll",
            post(re_enroll_file_integrity_handler),
        )
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
            security_snapshots,
            file_integrity,
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

fn init_tracing() {
    let env_filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    tracing_subscriber::registry()
        .with(env_filter)
        .with(filter_fn(dependency_log_allowed))
        .with(tracing_subscriber::fmt::layer())
        .init();
}

fn dependency_log_allowed(metadata: &Metadata<'_>) -> bool {
    let restricted = RESTRICTED_LOG_TARGETS.iter().any(|target| {
        metadata.target() == *target
            || metadata
                .target()
                .strip_prefix(target)
                .is_some_and(|suffix| suffix.starts_with("::"))
    });
    !restricted || *metadata.level() <= Level::WARN
}

fn exit_with_runtime_error(context: &'static str, error: runtime::RuntimeError) -> ! {
    eprintln!(
        "CRITICAL: startup_error context={} code={}: {}",
        context,
        error.code(),
        error
    );
    std::process::exit(1);
}

fn resolve_auth_token(mode: runtime::RuntimeMode) -> Result<String, String> {
    match configured_auth_token(std::env::var("AUTH_TOKEN").ok().as_deref(), mode)? {
        Some(token) => Ok(token),
        None => {
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

fn configured_auth_token(
    configured: Option<&str>,
    mode: runtime::RuntimeMode,
) -> Result<Option<String>, String> {
    configured_auth_token_with_weak_override(
        configured,
        mode,
        std::env::var("MINI_OPS_ALLOW_WEAK_AUTH_TOKEN").as_deref() == Ok("true"),
    )
}

fn configured_auth_token_with_weak_override(
    configured: Option<&str>,
    mode: runtime::RuntimeMode,
    weak_override: bool,
) -> Result<Option<String>, String> {
    if let Some(token) = configured.map(str::trim).filter(|token| !token.is_empty()) {
        validate_auth_token(
            token,
            mode == runtime::RuntimeMode::Standalone && weak_override,
        )?;
        return Ok(Some(token.to_string()));
    }

    if mode == runtime::RuntimeMode::Managed {
        return Err(
            "AUTH_TOKEN is required in managed mode and must be provided by EnvironmentFile"
                .to_string(),
        );
    }

    Ok(None)
}

fn validate_auth_token(token: &str, allow_weak_local_token: bool) -> Result<(), String> {
    if auth_token_is_placeholder(token) {
        return Err(
            "AUTH_TOKEN is set to a known placeholder. Generate a strong token with `openssl rand -hex 32`."
                .to_string(),
        );
    }

    if token.len() < 32 && !allow_weak_local_token {
        return Err(
            "AUTH_TOKEN must be at least 32 characters. The weak-token override is available only in standalone local mode."
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
    security_snapshots: Arc<SecuritySnapshotService>,
    file_integrity: Arc<FileIntegrityService>,
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
    let outcome = state
        .notifier
        .send_alert(&i18n::t("alert.test", &lang))
        .await;
    let status = match outcome {
        NotificationOutcome::Sent => StatusCode::OK,
        NotificationOutcome::Disabled => StatusCode::SERVICE_UNAVAILABLE,
        NotificationOutcome::Suppressed => StatusCode::TOO_MANY_REQUESTS,
        NotificationOutcome::Failed { .. } => StatusCode::BAD_GATEWAY,
    };
    (status, Json(outcome)).into_response()
}

async fn list_containers_handler(State(state): State<AppState>) -> Response {
    if let Some(docker) = &state.docker {
        match docker.list_containers().await {
            Ok(containers) => Json(containers).into_response(),
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "docker_list_failed").into_response(),
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
    if !docker::is_valid_container_target(&id) {
        return (StatusCode::BAD_REQUEST, "invalid_container_target").into_response();
    }
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
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "docker_action_failed").into_response(),
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

    if !docker::is_valid_container_target(&id) {
        return (StatusCode::BAD_REQUEST, "invalid_container_target").into_response();
    }
    tracing::info!("Docker SSE log stream requested");

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
                Err(_) => {
                    tracing::error!(
                        docker_error = "log_stream_failed",
                        "Docker log stream failed"
                    );
                    Event::default().data("Error: docker_log_stream_failed")
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
    Json(DiskOps::get_usage(".").await)
}

#[derive(serde::Deserialize)]
struct CleanRequest {
    target: String,
}

#[derive(Clone, Copy)]
enum DiskCleanupTarget {
    Target,
    NodeModules,
    Logs,
}

async fn clean_disk_handler(Json(payload): Json<CleanRequest>) -> Response {
    dispatch_disk_cleanup(&payload.target, |target| async move {
        match target {
            DiskCleanupTarget::Target => DiskOps::clean_target(".").await,
            DiskCleanupTarget::NodeModules => DiskOps::clean_node_modules(".").await,
            DiskCleanupTarget::Logs => DiskOps::clean_logs().await,
        }
    })
    .await
}

async fn dispatch_disk_cleanup<F, Fut>(target: &str, execute: F) -> Response
where
    F: FnOnce(DiskCleanupTarget) -> Fut,
    Fut: std::future::Future<Output = Result<String, String>>,
{
    let target = match target {
        "target" => DiskCleanupTarget::Target,
        "node_modules" => DiskCleanupTarget::NodeModules,
        "logs" => DiskCleanupTarget::Logs,
        "docker" => {
            return api_error_response(StatusCode::FORBIDDEN, "operation_unavailable");
        }
        _ => return api_error_response(StatusCode::BAD_REQUEST, "invalid_target"),
    };

    match execute(target).await {
        Ok(msg) => (StatusCode::OK, msg).into_response(),
        Err(_) => api_error_response(StatusCode::INTERNAL_SERVER_ERROR, "operation_failed"),
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
) -> Response {
    let lang = i18n::Lang::from_headers(&headers);
    let result = state
        .security_snapshots
        .get_or_refresh(state.security_snapshots.api_cache_ttl())
        .await;
    security_audit_result_response(result, &lang)
}

fn security_audit_result_response(
    result: Result<Arc<SecurityAuditSnapshot>, SecuritySnapshotUnavailable>,
    lang: &i18n::Lang,
) -> Response {
    match result {
        Ok(snapshot) => security_audit_snapshot_response(&snapshot, lang),
        Err(_) => api_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "security_audit_unavailable",
        ),
    }
}

fn security_audit_snapshot_response(
    snapshot: &SecurityAuditSnapshot,
    lang: &i18n::Lang,
) -> Response {
    let identity = snapshot.identity();
    let epoch = identity.collector_epoch().to_string();
    let generation = identity.generation().to_string();
    let collected_at = snapshot.collected_at().to_string();
    let Ok(epoch) = header::HeaderValue::from_str(&epoch) else {
        return api_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "security_audit_unavailable",
        );
    };
    let Ok(generation) = header::HeaderValue::from_str(&generation) else {
        return api_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "security_audit_unavailable",
        );
    };
    let Ok(collected_at) = header::HeaderValue::from_str(&collected_at) else {
        return api_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "security_audit_unavailable",
        );
    };

    let mut response = Json(snapshot.project(lang)).into_response();
    response
        .headers_mut()
        .insert("x-security-collector-epoch", epoch);
    response
        .headers_mut()
        .insert("x-security-generation", generation);
    response
        .headers_mut()
        .insert("x-security-collected-at", collected_at);
    response.headers_mut().insert(
        "x-security-collection-status",
        header::HeaderValue::from_static(snapshot.collection_status().code()),
    );
    response
}

async fn get_file_integrity_status_handler(State(state): State<AppState>) -> Response {
    match state.file_integrity.status().await {
        Ok(status) => Json(status).into_response(),
        Err(error) => api_error_response(StatusCode::INTERNAL_SERVER_ERROR, error.code()),
    }
}

async fn trust_file_integrity_state_handler(
    State(state): State<AppState>,
    request: Request,
) -> Response {
    let payload = match read_bounded_json_body::<TrustCurrentStateRequest>(request).await {
        Ok(payload) => payload,
        Err(error) => return file_integrity_operation_error_response(error),
    };
    match state.file_integrity.trust_current_state(payload).await {
        Ok(result) => Json(result).into_response(),
        Err(error) => file_integrity_operation_error_response(error),
    }
}

async fn re_enroll_file_integrity_handler(
    State(state): State<AppState>,
    request: Request,
) -> Response {
    let payload = match read_bounded_json_body::<ReEnrollRequest>(request).await {
        Ok(payload) => payload,
        Err(error) => return file_integrity_operation_error_response(error),
    };
    match state.file_integrity.re_enroll(payload).await {
        Ok(result) => Json(result).into_response(),
        Err(error) => file_integrity_operation_error_response(error),
    }
}

async fn read_bounded_json_body<T: DeserializeOwned>(
    request: Request,
) -> Result<T, FileIntegrityOperationError> {
    const MAX_BODY_BYTES: usize = 1024;
    let bytes = axum::body::to_bytes(request.into_body(), MAX_BODY_BYTES)
        .await
        .map_err(|_| FileIntegrityOperationError::invalid_request())?;
    serde_json::from_slice(&bytes).map_err(|_| FileIntegrityOperationError::invalid_request())
}

fn file_integrity_operation_error_response(error: FileIntegrityOperationError) -> Response {
    let status =
        StatusCode::from_u16(error.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(error.response_body())).into_response()
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

    security_events_list_response(state.security_events.list(status, limit).await)
}

fn security_events_list_response(result: Result<Vec<SecurityEvent>, sqlx::Error>) -> Response {
    match result {
        Ok(events) => Json::<Vec<SecurityEvent>>(events).into_response(),
        Err(_) => api_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "security_events_unavailable",
        ),
    }
}

async fn ack_security_event_handler(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Response {
    security_event_ack_response(state.security_events.acknowledge(id).await)
}

fn security_event_ack_response(result: Result<bool, sqlx::Error>) -> Response {
    match result {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => api_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "security_event_ack_failed",
        ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::{Request as HttpRequest, header::CONTENT_TYPE},
    };
    use serde_json::Value;
    use std::io::{self, Write};
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use tower::Service;

    #[derive(Clone)]
    struct SharedLogWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedLogWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .write(bytes)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct SideEffectCounters {
        command_calls: AtomicUsize,
        history_writes: AtomicUsize,
        file_writes: AtomicUsize,
    }

    #[test]
    fn dependency_log_ceiling_blocks_raw_debug_payloads() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let writer = SharedLogWriter(Arc::clone(&captured));
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new("trace"))
            .with(filter_fn(dependency_log_allowed))
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .without_time()
                    .with_writer(move || writer.clone()),
            );

        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(
                target: "bollard::docker",
                payload = "BOLLARD_ENV_SENTINEL=secret",
                "decoded inspect response"
            );
            tracing::trace!(
                target: "reqwest::connect",
                uri = "https://provider.invalid/bot123456:TELEGRAM_TOKEN_SENTINEL/send",
                "request bytes"
            );
            tracing::warn!(target: "bollard::docker", code = "dependency_warning");
            tracing::debug!(target: "mini_ops::tests", "app_debug_visible");
        });

        let output = String::from_utf8(
            captured
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
        )
        .expect("captured logs should be UTF-8");
        assert!(!output.contains("BOLLARD_ENV_SENTINEL"));
        assert!(!output.contains("TELEGRAM_TOKEN_SENTINEL"));
        assert!(output.contains("dependency_warning"));
        assert!(output.contains("app_debug_visible"));
    }

    async fn counted_cleanup_handler(
        State(counters): State<Arc<SideEffectCounters>>,
        Json(_payload): Json<CleanRequest>,
    ) -> StatusCode {
        counters.command_calls.fetch_add(1, Ordering::SeqCst);
        counters.history_writes.fetch_add(1, Ordering::SeqCst);
        counters.file_writes.fetch_add(1, Ordering::SeqCst);
        StatusCode::OK
    }

    async fn assert_error_code(response: Response, expected: &str) {
        let body = to_bytes(response.into_body(), 1024)
            .await
            .expect("bounded error body should be readable");
        let value: Value =
            serde_json::from_slice(&body).expect("error response should contain valid JSON");
        assert_eq!(value["error"]["code"], expected);
    }

    #[tokio::test]
    async fn file_integrity_action_body_is_exact_and_bounded() {
        let request = HttpRequest::builder()
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"expected_baseline_generation":1,"expected_observed_generation":2,"confirmation":"trust_current_state"}"#,
            ))
            .expect("request should build");
        let parsed = read_bounded_json_body::<TrustCurrentStateRequest>(request)
            .await
            .expect("exact request should parse");
        assert_eq!(parsed.expected_baseline_generation, 1);
        assert_eq!(parsed.expected_observed_generation, 2);

        let unknown = HttpRequest::builder()
            .body(Body::from(
                r#"{"expected_baseline_generation":1,"expected_observed_generation":2,"confirmation":"trust_current_state","extra":true}"#,
            ))
            .expect("request should build");
        assert_eq!(
            read_bounded_json_body::<TrustCurrentStateRequest>(unknown)
                .await
                .expect_err("unknown field must fail")
                .code(),
            file_integrity::FileIntegrityOperationErrorCode::InvalidRequest
        );

        let oversized = HttpRequest::builder()
            .body(Body::from(vec![b'x'; 1025]))
            .expect("request should build");
        assert!(
            read_bounded_json_body::<TrustCurrentStateRequest>(oversized)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn file_integrity_invalid_request_envelope_is_exact_and_redacted() {
        let response =
            file_integrity_operation_error_response(FileIntegrityOperationError::invalid_request());
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), 1024)
            .await
            .expect("bounded response body");
        let value: Value = serde_json::from_slice(&body).expect("valid JSON envelope");
        assert_eq!(
            value,
            serde_json::json!({
                "error": {
                    "code": "invalid_request",
                    "status": null,
                    "state_revision": null,
                    "baseline_generation": null,
                    "observed_generation": null
                }
            })
        );
    }

    #[test]
    fn disk_cleanup_gate_requires_exact_lowercase_true() {
        assert!(disk_cleanup_enabled(Some("true")));
        for value in [None, Some(""), Some(" true "), Some("TRUE"), Some("1")] {
            assert!(!disk_cleanup_enabled(value));
        }
    }

    #[test]
    fn managed_mode_requires_preconfigured_auth_token() {
        for configured in [None, Some(""), Some("   ")] {
            let error = configured_auth_token(configured, runtime::RuntimeMode::Managed)
                .expect_err("managed mode must not generate or persist AUTH_TOKEN");
            assert!(error.contains("required in managed mode"));
        }
        assert!(
            configured_auth_token_with_weak_override(
                Some("short-token"),
                runtime::RuntimeMode::Managed,
                true,
            )
            .is_err(),
            "managed mode must ignore the standalone weak-token override"
        );
    }

    #[test]
    fn standalone_mode_preserves_local_auth_token_generation_path() {
        assert_eq!(
            configured_auth_token(None, runtime::RuntimeMode::Standalone)
                .expect("standalone missing token should remain generatable"),
            None
        );
        let token = "a".repeat(64);
        assert_eq!(
            configured_auth_token(Some(&token), runtime::RuntimeMode::Standalone)
                .expect("strong standalone token should be accepted"),
            Some(token)
        );
    }

    #[tokio::test]
    async fn disabled_malformed_disk_post_is_rejected_before_parsing_or_side_effects() {
        let counters = Arc::new(SideEffectCounters::default());
        let mut app = Router::new()
            .route(
                "/disk/clean",
                post(counted_cleanup_handler).route_layer(middleware::from_fn_with_state(
                    DiskCleanupGate { enabled: false },
                    require_disk_cleanup,
                )),
            )
            .with_state(counters.clone());
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/disk/clean")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from("{not-json"))
            .expect("test request should build");

        let response = Service::call(&mut app, request)
            .await
            .expect("test router should respond");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_error_code(response, "capability_disabled").await;
        assert_eq!(counters.command_calls.load(Ordering::SeqCst), 0);
        assert_eq!(counters.history_writes.load(Ordering::SeqCst), 0);
        assert_eq!(counters.file_writes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn docker_cleanup_is_unavailable_without_executor_side_effects() {
        let counters = Arc::new(SideEffectCounters::default());
        let captured = counters.clone();

        let response = dispatch_disk_cleanup("docker", move |_target| async move {
            captured.command_calls.fetch_add(1, Ordering::SeqCst);
            captured.history_writes.fetch_add(1, Ordering::SeqCst);
            captured.file_writes.fetch_add(1, Ordering::SeqCst);
            Ok("unexpected".to_string())
        })
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_error_code(response, "operation_unavailable").await;
        assert_eq!(counters.command_calls.load(Ordering::SeqCst), 0);
        assert_eq!(counters.history_writes.load(Ordering::SeqCst), 0);
        assert_eq!(counters.file_writes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn security_audit_response_keeps_array_body_and_adds_snapshot_headers() {
        let counter = Arc::new(AtomicUsize::new(0));
        let snapshots = SecuritySnapshotService::test_service(counter);
        snapshots
            .publish_test_snapshot(std::time::Duration::ZERO, false)
            .await;
        let snapshot = snapshots
            .latest()
            .await
            .expect("test snapshot should be published");

        let response = security_audit_snapshot_response(&snapshot, &i18n::Lang::RU);
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .contains_key("x-security-collector-epoch")
        );
        assert_eq!(
            response.headers()["x-security-generation"],
            snapshot.identity().generation().to_string()
        );
        assert_eq!(
            response.headers()["x-security-collected-at"],
            snapshot.collected_at().to_string()
        );
        assert_eq!(response.headers()["x-security-collection-status"], "full");

        let body = to_bytes(response.into_body(), 32 * 1024)
            .await
            .expect("bounded audit response should be readable");
        let value: Value = serde_json::from_slice(&body).expect("audit body should be JSON");
        assert!(value.is_array(), "legacy API body must remain an array");
    }

    #[tokio::test]
    async fn unavailable_security_snapshot_maps_to_generic_typed_503() {
        let response =
            security_audit_result_response(Err(SecuritySnapshotUnavailable), &i18n::Lang::EN);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_error_code(response, "security_audit_unavailable").await;
    }

    #[tokio::test]
    async fn security_event_database_errors_use_closed_api_codes() {
        let list_response = security_events_list_response(Err(sqlx::Error::Protocol(
            "RAW_SQL_SENTINEL".to_string(),
        )));
        assert_eq!(list_response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_error_code(list_response, "security_events_unavailable").await;

        let ack_response =
            security_event_ack_response(Err(sqlx::Error::Protocol("RAW_SQL_SENTINEL".to_string())));
        assert_eq!(ack_response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_error_code(ack_response, "security_event_ack_failed").await;
    }
}
