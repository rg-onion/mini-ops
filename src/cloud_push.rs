use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use reqwest::StatusCode;
use tracing::{info, warn};
use url::{Host, Url};
use uuid::Uuid;

use crate::certificate_monitor::{
    CertificateMonitorService, CertificateMonitorState, CertificateMonitorStatus,
};
use crate::cloud_payload::{
    CertificateMetrics, CertificateMetricsStatus, CertificateObservationFreshness,
    CertificateTargetMetrics, FLEET_OBSERVATION_SCHEMA_VERSION, FleetObservation,
    SecurityFindingCounts, SecurityMetrics, SecurityMetricsStatus, SystemMetrics,
};
use crate::i18n::Lang;
use crate::metrics::MetricsState;
use crate::security::{SecurityAuditor, SecurityCheck};
use crate::security_snapshot::{SecurityCollectionStatus, SecuritySnapshotService};

const DEFAULT_PUSH_INTERVAL_SECS: u64 = 300;
const MIN_PUSH_INTERVAL_SECS: u64 = 60;
const MAX_PUSH_INTERVAL_SECS: u64 = 86_400;
const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
const OBSERVATION_PATH: &str = "/api/v1/agent-observations";
const CLOCK_SKEW_TOLERANCE_SECS: i64 = 300;
const CERTIFICATE_STATUS_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CloudPushIntervalError {
    Blank,
    Invalid,
    OutOfRange,
}

impl CloudPushIntervalError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Blank => "blank_interval",
            Self::Invalid => "invalid_interval",
            Self::OutOfRange => "interval_out_of_range",
        }
    }
}

pub(crate) fn parse_push_interval(value: Option<&str>) -> Result<u64, CloudPushIntervalError> {
    let Some(value) = value else {
        return Ok(DEFAULT_PUSH_INTERVAL_SECS);
    };
    let value = value.trim();
    if value.is_empty() {
        return Err(CloudPushIntervalError::Blank);
    }
    let seconds = value
        .parse::<u64>()
        .map_err(|_| CloudPushIntervalError::Invalid)?;
    if !(MIN_PUSH_INTERVAL_SECS..=MAX_PUSH_INTERVAL_SECS).contains(&seconds) {
        return Err(CloudPushIntervalError::OutOfRange);
    }
    Ok(seconds)
}

pub(crate) struct CloudPushConfig {
    pub(crate) hub_url: String,
    pub(crate) agent_token: String,
    pub(crate) push_interval_secs: u64,
    pub(crate) allow_http: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CloudPushConfigError {
    MissingRequiredConfig,
    InvalidInterval,
    InvalidHubUrl,
    HubUrlMustBeOrigin,
    HttpsRequired,
    HttpRequiresLoopback,
    BlankToken,
    ClientInit,
}

impl CloudPushConfigError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::MissingRequiredConfig => "missing_required_config",
            Self::InvalidInterval => "invalid_interval",
            Self::InvalidHubUrl => "invalid_hub_url",
            Self::HubUrlMustBeOrigin => "hub_url_must_be_origin",
            Self::HttpsRequired => "https_required",
            Self::HttpRequiresLoopback => "http_requires_loopback",
            Self::BlankToken => "blank_agent_token",
            Self::ClientInit => "client_init_failed",
        }
    }
}

pub(crate) struct CloudPushService {
    config: CloudPushConfig,
    observation_url: Url,
    client: reqwest::Client,
    security_snapshots: Arc<SecuritySnapshotService>,
    security_snapshot_max_age: Duration,
    certificate_monitor: Option<Arc<CertificateMonitorService>>,
}

impl CloudPushService {
    pub(crate) fn new(
        config: CloudPushConfig,
        security_snapshots: Arc<SecuritySnapshotService>,
        certificate_monitor: Option<Arc<CertificateMonitorService>>,
    ) -> Result<Self, CloudPushConfigError> {
        if !(MIN_PUSH_INTERVAL_SECS..=MAX_PUSH_INTERVAL_SECS).contains(&config.push_interval_secs) {
            return Err(CloudPushConfigError::InvalidInterval);
        }
        if config.agent_token.trim().is_empty() {
            return Err(CloudPushConfigError::BlankToken);
        }

        let observation_url = observation_url(&config.hub_url, config.allow_http)?;
        if config.allow_http && observation_url.scheme() == "http" {
            warn!(
                "Cloud push uses loopback plaintext HTTP for local development; never use this override in production"
            );
        }

        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| CloudPushConfigError::ClientInit)?;

        let security_snapshot_max_age = Duration::from_secs(
            security_snapshots
                .audit_interval()
                .as_secs()
                .saturating_mul(2),
        );
        Ok(Self {
            config,
            observation_url,
            client,
            security_snapshots,
            security_snapshot_max_age,
            certificate_monitor,
        })
    }

    pub(crate) fn start(self: Arc<Self>, metrics: Arc<MetricsState>) {
        tokio::spawn(async move {
            let push_interval = Duration::from_secs(self.config.push_interval_secs);
            let first_tick = first_push_tick(tokio::time::Instant::now(), push_interval);
            let mut interval = tokio::time::interval_at(first_tick, push_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut previous_delivery_ok = None;

            loop {
                interval.tick().await;
                match self.push_once(&metrics).await {
                    Ok(()) => {
                        if previous_delivery_ok != Some(true) {
                            info!("Fleet observation delivery available");
                        }
                        previous_delivery_ok = Some(true);
                    }
                    Err(code) => {
                        if previous_delivery_ok == Some(true) {
                            warn!(delivery_error = code, "Fleet observation delivery degraded");
                        } else if previous_delivery_ok.is_none() {
                            warn!(
                                delivery_error = code,
                                "Fleet observation delivery unavailable"
                            );
                        }
                        previous_delivery_ok = Some(false);
                    }
                }
            }
        });
    }

    async fn push_once(&self, metrics: &MetricsState) -> Result<(), &'static str> {
        let payload = self.build_payload(metrics).await;
        let observation_id = payload.observation_id.to_string();
        let body = serde_json::to_vec(&payload).map_err(|_| "payload_serialization_failed")?;
        if body.len() > MAX_PAYLOAD_BYTES {
            return Err("payload_too_large");
        }

        let response = self
            .client
            .post(self.observation_url.clone())
            .bearer_auth(&self.config.agent_token)
            .header("Idempotency-Key", observation_id)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| "request_failed")?;

        classify_response_status(response.status())
    }

    async fn build_payload(&self, metrics: &MetricsState) -> FleetObservation {
        let observed_at = chrono::Utc::now().timestamp();
        FleetObservation {
            schema_version: FLEET_OBSERVATION_SCHEMA_VERSION,
            observation_id: Uuid::new_v4(),
            observed_at,
            agent_version: env!("CARGO_PKG_VERSION"),
            system: system_metrics(metrics),
            security: self.security_metrics().await,
            certificates: self.certificate_metrics(observed_at).await,
        }
    }

    async fn security_metrics(&self) -> SecurityMetrics {
        let Some(snapshot) = self.security_snapshots.latest().await else {
            return unavailable_security_metrics(SecurityMetricsStatus::Missing, None);
        };
        let collected_at = Some(snapshot.collected_at());
        if snapshot.age() > self.security_snapshot_max_age {
            return unavailable_security_metrics(SecurityMetricsStatus::Stale, collected_at);
        }
        if snapshot.collection_status() != SecurityCollectionStatus::Full {
            return unavailable_security_metrics(SecurityMetricsStatus::Degraded, collected_at);
        }

        let checks = snapshot.project(&Lang::EN);
        SecurityMetrics {
            status: SecurityMetricsStatus::Available,
            collected_at,
            score: Some(SecurityAuditor::calculate_score(&checks)),
            findings: Some(count_security_findings(&checks)),
        }
    }

    async fn certificate_metrics(&self, observed_at: i64) -> CertificateMetrics {
        let Some(service) = &self.certificate_monitor else {
            return CertificateMetrics {
                status: CertificateMetricsStatus::Disabled,
                interval_seconds: None,
                targets: Vec::new(),
            };
        };
        let Ok(Ok(status)) =
            tokio::time::timeout(CERTIFICATE_STATUS_TIMEOUT, service.status()).await
        else {
            return CertificateMetrics {
                status: CertificateMetricsStatus::Unavailable,
                interval_seconds: None,
                targets: Vec::new(),
            };
        };
        project_certificate_status(status, observed_at)
    }
}

fn observation_url(value: &str, allow_http: bool) -> Result<Url, CloudPushConfigError> {
    let mut url = Url::parse(value).map_err(|_| CloudPushConfigError::InvalidHubUrl)?;
    if url.cannot_be_a_base() || url.host().is_none() {
        return Err(CloudPushConfigError::InvalidHubUrl);
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(CloudPushConfigError::HubUrlMustBeOrigin);
    }

    match url.scheme() {
        "https" => {}
        "http" if !allow_http => return Err(CloudPushConfigError::HttpsRequired),
        "http" if !is_loopback_host(url.host()) => {
            return Err(CloudPushConfigError::HttpRequiresLoopback);
        }
        "http" => {}
        _ => return Err(CloudPushConfigError::HttpsRequired),
    }

    url.set_path(OBSERVATION_PATH);
    Ok(url)
}

fn is_loopback_host(host: Option<Host<&str>>) -> bool {
    match host {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
        Some(Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
        None => false,
    }
}

fn system_metrics(metrics: &MetricsState) -> SystemMetrics {
    let stats = metrics.get_current();
    let load_average = sysinfo::System::load_average();
    SystemMetrics {
        collected_at: stats.timestamp,
        cpu_usage_percent: finite_f32(stats.cpu_usage),
        memory_total_bytes: stats.memory_total,
        memory_used_bytes: stats.memory_used.min(stats.memory_total),
        disk_total_bytes: stats.disk_total,
        disk_used_bytes: stats.disk_used.min(stats.disk_total),
        load_average_1m: finite_f64_to_f32(load_average.one),
        load_average_5m: finite_f64_to_f32(load_average.five),
        load_average_15m: finite_f64_to_f32(load_average.fifteen),
        uptime_seconds: sysinfo::System::uptime(),
    }
}

fn finite_f32(value: f32) -> Option<f32> {
    value.is_finite().then_some(value.max(0.0))
}

fn finite_f64_to_f32(value: f64) -> Option<f32> {
    value
        .is_finite()
        .then(|| value.max(0.0) as f32)
        .filter(|value| value.is_finite())
}

fn unavailable_security_metrics(
    status: SecurityMetricsStatus,
    collected_at: Option<i64>,
) -> SecurityMetrics {
    SecurityMetrics {
        status,
        collected_at,
        score: None,
        findings: None,
    }
}

fn count_security_findings(checks: &[SecurityCheck]) -> SecurityFindingCounts {
    let mut counts = SecurityFindingCounts {
        pass: 0,
        warn: 0,
        fail: 0,
    };
    for check in checks {
        match check.status.as_str() {
            "PASS" => counts.pass = counts.pass.saturating_add(1),
            "WARN" => counts.warn = counts.warn.saturating_add(1),
            "FAIL" => counts.fail = counts.fail.saturating_add(1),
            _ => {}
        }
    }
    counts
}

fn project_certificate_status(
    status: CertificateMonitorStatus,
    observed_at: i64,
) -> CertificateMetrics {
    if status.status != CertificateMonitorState::Enabled {
        return CertificateMetrics {
            status: CertificateMetricsStatus::Disabled,
            interval_seconds: None,
            targets: Vec::new(),
        };
    }
    let Some(interval_seconds) = status.interval_seconds else {
        return CertificateMetrics {
            status: CertificateMetricsStatus::Unavailable,
            interval_seconds: None,
            targets: Vec::new(),
        };
    };

    let targets = status
        .targets
        .into_iter()
        .map(|target| {
            let Some(observation) = target.observation else {
                return CertificateTargetMetrics {
                    target_id: target.target_id,
                    server_name: target.server_name,
                    port: target.port,
                    freshness: CertificateObservationFreshness::Pending,
                    checked_at: None,
                    last_success_at: None,
                    reachability: None,
                    trust: None,
                    hostname: None,
                    expiry: None,
                    not_after: None,
                    error_code: None,
                };
            };
            CertificateTargetMetrics {
                target_id: target.target_id,
                server_name: target.server_name,
                port: target.port,
                freshness: certificate_freshness(
                    observation.checked_at,
                    observed_at,
                    interval_seconds,
                ),
                checked_at: Some(observation.checked_at),
                last_success_at: observation.last_success_at,
                reachability: Some(observation.reachability),
                trust: Some(observation.trust),
                hostname: Some(observation.hostname),
                expiry: Some(observation.expiry),
                not_after: observation.not_after,
                error_code: observation.error_code,
            }
        })
        .collect();

    CertificateMetrics {
        status: CertificateMetricsStatus::Enabled,
        interval_seconds: Some(interval_seconds),
        targets,
    }
}

fn certificate_freshness(
    checked_at: i64,
    observed_at: i64,
    interval_seconds: u64,
) -> CertificateObservationFreshness {
    let Ok(interval_seconds) = i64::try_from(interval_seconds) else {
        return CertificateObservationFreshness::Stale;
    };
    if checked_at > observed_at.saturating_add(CLOCK_SKEW_TOLERANCE_SECS) {
        return CertificateObservationFreshness::Stale;
    }
    let maximum_age = interval_seconds.saturating_mul(2);
    if observed_at.saturating_sub(checked_at) <= maximum_age {
        CertificateObservationFreshness::Fresh
    } else {
        CertificateObservationFreshness::Stale
    }
}

fn classify_response_status(status: StatusCode) -> Result<(), &'static str> {
    if status.is_success() {
        return Ok(());
    }
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err("authentication_rejected"),
        StatusCode::TOO_MANY_REQUESTS => Err("rate_limited"),
        status if status.is_server_error() => Err("hub_unavailable"),
        _ => Err("contract_rejected"),
    }
}

fn first_push_tick(startup: tokio::time::Instant, interval: Duration) -> tokio::time::Instant {
    startup + interval
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate_monitor::{
        CertificateCurrentObservation, CertificateTargetStatus, MANUAL_REFRESH_COOLDOWN_SECS,
    };
    use crate::certificate_probe::{
        CertificateProbeErrorCode, ExpiryStatus, HostnameStatus, ReachabilityStatus, TrustStatus,
    };
    use axum::Router;
    use axum::body::Bytes;
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::routing::post;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::{Mutex, oneshot};

    type CaptureSender = Arc<Mutex<Option<oneshot::Sender<(HeaderMap, Bytes)>>>>;

    async fn capture_observation(
        State(sender): State<CaptureSender>,
        headers: HeaderMap,
        body: Bytes,
    ) -> StatusCode {
        if let Some(sender) = sender.lock().await.take() {
            let _ = sender.send((headers, body));
        }
        StatusCode::ACCEPTED
    }

    fn test_service(snapshots: Arc<SecuritySnapshotService>) -> CloudPushService {
        CloudPushService::new(
            CloudPushConfig {
                hub_url: "https://cloud.invalid".to_string(),
                agent_token: "redacted-test-token".to_string(),
                push_interval_secs: 300,
                allow_http: false,
            },
            snapshots,
            None,
        )
        .expect("valid test cloud configuration")
    }

    #[test]
    fn cloud_push_interval_matrix_is_fail_closed() {
        assert_eq!(parse_push_interval(None), Ok(300));
        assert_eq!(
            parse_push_interval(Some("")),
            Err(CloudPushIntervalError::Blank)
        );
        assert_eq!(
            parse_push_interval(Some("  ")),
            Err(CloudPushIntervalError::Blank)
        );
        assert_eq!(
            parse_push_interval(Some("invalid")),
            Err(CloudPushIntervalError::Invalid)
        );
        for value in ["0", "59", "86401"] {
            assert_eq!(
                parse_push_interval(Some(value)),
                Err(CloudPushIntervalError::OutOfRange)
            );
        }
        assert_eq!(parse_push_interval(Some("60")), Ok(60));
        assert_eq!(parse_push_interval(Some("86400")), Ok(86_400));
    }

    #[test]
    fn cloud_hub_url_is_an_origin_and_plaintext_is_loopback_only() {
        assert_eq!(
            observation_url("https://fleet.example", false)
                .expect("https origin")
                .as_str(),
            "https://fleet.example/api/v1/agent-observations"
        );
        assert_eq!(
            observation_url("http://127.0.0.1:8080", true)
                .expect("loopback development origin")
                .as_str(),
            "http://127.0.0.1:8080/api/v1/agent-observations"
        );
        assert_eq!(
            observation_url("http://fleet.example", false),
            Err(CloudPushConfigError::HttpsRequired)
        );
        assert_eq!(
            observation_url("http://fleet.example", true),
            Err(CloudPushConfigError::HttpRequiresLoopback)
        );
        for value in [
            "https://user@fleet.example",
            "https://fleet.example/base",
            "https://fleet.example?query=1",
            "https://fleet.example#fragment",
        ] {
            assert_eq!(
                observation_url(value, false),
                Err(CloudPushConfigError::HubUrlMustBeOrigin)
            );
        }
    }

    #[test]
    fn missing_required_cloud_config_uses_a_closed_error_code() {
        assert_eq!(
            CloudPushConfigError::MissingRequiredConfig.code(),
            "missing_required_config"
        );
    }

    #[test]
    fn first_cloud_tick_is_delayed_by_the_validated_interval() {
        let startup = tokio::time::Instant::now();
        let interval = Duration::from_secs(300);
        assert_eq!(first_push_tick(startup, interval), startup + interval);
        assert!(first_push_tick(startup, interval) > startup);
    }

    #[tokio::test]
    async fn cloud_request_uses_token_bound_idempotent_v1_contract() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback receiver");
        let address = listener.local_addr().expect("loopback receiver address");
        let (sender, receiver) = oneshot::channel();
        let app = Router::new()
            .route(OBSERVATION_PATH, post(capture_observation))
            .with_state(Arc::new(Mutex::new(Some(sender))));
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve loopback receiver");
        });

        let snapshots = SecuritySnapshotService::test_service(Arc::new(AtomicUsize::new(0)));
        let service = CloudPushService::new(
            CloudPushConfig {
                hub_url: format!("http://{address}"),
                agent_token: "request-contract-test-token".to_string(),
                push_interval_secs: 300,
                allow_http: true,
            },
            snapshots,
            None,
        )
        .expect("loopback development cloud configuration");

        service
            .push_once(&MetricsState::new())
            .await
            .expect("accepted v1 observation");
        let (headers, body) = tokio::time::timeout(Duration::from_secs(1), receiver)
            .await
            .expect("capture timeout")
            .expect("capture channel");
        server.abort();
        let _ = server.await;

        assert!(body.len() <= MAX_PAYLOAD_BYTES);
        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("parse captured observation");
        let observation_id = json["observation_id"].as_str().expect("observation UUID");
        assert_eq!(
            headers
                .get("Idempotency-Key")
                .and_then(|value| value.to_str().ok()),
            Some(observation_id)
        );
        assert_eq!(
            headers
                .get(reqwest::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer request-contract-test-token")
        );
        assert_eq!(
            headers
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        assert!(json.get("agent_id").is_none());
        assert!(
            !body
                .windows(b"request-contract-test-token".len())
                .any(|window| window == b"request-contract-test-token")
        );
    }

    #[tokio::test]
    async fn cloud_projects_fresh_snapshot_without_running_collector() {
        let counter = Arc::new(AtomicUsize::new(0));
        let snapshots = SecuritySnapshotService::test_service(Arc::clone(&counter));
        snapshots.publish_test_snapshot(Duration::ZERO, false).await;
        let service = test_service(snapshots);

        let security = service.security_metrics().await;
        assert_eq!(security.status, SecurityMetricsStatus::Available);
        assert!(security.score.is_some());
        assert!(security.findings.is_some());
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cloud_preserves_missing_stale_and_degraded_security_truth() {
        let counter = Arc::new(AtomicUsize::new(0));

        let missing_snapshots = SecuritySnapshotService::test_service(Arc::clone(&counter));
        let missing = test_service(missing_snapshots);
        let security = missing.security_metrics().await;
        assert_eq!(security.status, SecurityMetricsStatus::Missing);
        assert!(security.score.is_none());

        let stale_snapshots = SecuritySnapshotService::test_service(Arc::clone(&counter));
        stale_snapshots
            .publish_test_snapshot(Duration::from_secs(601), false)
            .await;
        let stale = test_service(stale_snapshots);
        let security = stale.security_metrics().await;
        assert_eq!(security.status, SecurityMetricsStatus::Stale);
        assert!(security.score.is_none());

        let degraded_snapshots = SecuritySnapshotService::test_service(Arc::clone(&counter));
        degraded_snapshots
            .publish_test_snapshot(Duration::ZERO, true)
            .await;
        let degraded = test_service(degraded_snapshots);
        let security = degraded.security_metrics().await;
        assert_eq!(security.status, SecurityMetricsStatus::Degraded);
        assert!(security.score.is_none());

        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn fleet_observation_v1_has_exact_minimized_top_level_shape() {
        let counter = Arc::new(AtomicUsize::new(0));
        let snapshots = SecuritySnapshotService::test_service(counter);
        let service = test_service(snapshots);
        let metrics = MetricsState::new();

        let payload = service.build_payload(&metrics).await;
        let body = serde_json::to_vec(&payload).expect("serialize v1 observation");
        assert!(body.len() < MAX_PAYLOAD_BYTES);
        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("parse serialized v1 observation");
        let keys = json
            .as_object()
            .expect("observation object")
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            keys,
            std::collections::BTreeSet::from([
                "agent_version",
                "certificates",
                "observation_id",
                "observed_at",
                "schema_version",
                "security",
                "system",
            ])
        );
        for forbidden in [
            "agent_id",
            "docker",
            "hostname",
            "last_ssh_login",
            "open_ports",
            "server_name",
            "trusted_ips",
        ] {
            assert!(
                json.get(forbidden).is_none(),
                "forbidden field: {forbidden}"
            );
        }
        assert_eq!(
            json.pointer("/security/status")
                .and_then(|value| value.as_str()),
            Some("missing")
        );
        assert_eq!(
            json.pointer("/certificates/status")
                .and_then(|value| value.as_str()),
            Some("disabled")
        );
    }

    #[test]
    fn certificate_projection_is_minimized_and_marks_freshness() {
        let status = CertificateMonitorStatus {
            schema_version: 1,
            status: CertificateMonitorState::Enabled,
            interval_seconds: Some(86_400),
            refresh_cooldown_seconds: MANUAL_REFRESH_COOLDOWN_SECS,
            earliest_expiry_at: Some(2_000_000),
            targets: vec![CertificateTargetStatus {
                target_id: "crm-edge".to_string(),
                label: "private customer label sentinel".to_string(),
                connect_host: "192.0.2.10".to_string(),
                port: 443,
                server_name: "crm.example.test".to_string(),
                observation: Some(CertificateCurrentObservation {
                    schema_version: 1,
                    checked_at: 1_000_000,
                    duration_ms: 42,
                    last_success_at: Some(1_000_000),
                    reachability: ReachabilityStatus::Reachable,
                    trust: TrustStatus::Valid,
                    hostname: HostnameStatus::Match,
                    expiry: ExpiryStatus::Healthy,
                    not_before: Some(900_000),
                    not_after: Some(2_000_000),
                    remaining_seconds: Some(1_000_000),
                    error_code: None,
                }),
            }],
        };
        let projected = project_certificate_status(status, 1_100_000);
        assert_eq!(projected.status, CertificateMetricsStatus::Enabled);
        assert_eq!(
            projected.targets[0].freshness,
            CertificateObservationFreshness::Fresh
        );
        let json = serde_json::to_string(&projected).expect("serialize certificate projection");
        assert!(json.contains("crm.example.test"));
        assert!(!json.contains("private customer label sentinel"));
        assert!(!json.contains("192.0.2.10"));
        assert!(!json.contains("duration_ms"));
        assert!(!json.contains("not_before"));
        assert!(!json.contains("remaining_seconds"));
        assert!(!json.contains("fingerprint"));
    }

    #[test]
    fn certificate_projection_marks_pending_stale_failure_without_false_health() {
        let status = CertificateMonitorStatus {
            schema_version: 1,
            status: CertificateMonitorState::Enabled,
            interval_seconds: Some(300),
            refresh_cooldown_seconds: MANUAL_REFRESH_COOLDOWN_SECS,
            earliest_expiry_at: None,
            targets: vec![
                CertificateTargetStatus {
                    target_id: "pending".to_string(),
                    label: "Pending".to_string(),
                    connect_host: "pending.example".to_string(),
                    port: 443,
                    server_name: "pending.example".to_string(),
                    observation: None,
                },
                CertificateTargetStatus {
                    target_id: "failed".to_string(),
                    label: "Failed".to_string(),
                    connect_host: "failed.example".to_string(),
                    port: 443,
                    server_name: "failed.example".to_string(),
                    observation: Some(CertificateCurrentObservation {
                        schema_version: 1,
                        checked_at: 1_000,
                        duration_ms: 10_000,
                        last_success_at: None,
                        reachability: ReachabilityStatus::Unknown,
                        trust: TrustStatus::Unknown,
                        hostname: HostnameStatus::Unknown,
                        expiry: ExpiryStatus::Unknown,
                        not_before: None,
                        not_after: None,
                        remaining_seconds: None,
                        error_code: Some(CertificateProbeErrorCode::ConnectTimeout),
                    }),
                },
            ],
        };
        let projected = project_certificate_status(status, 2_000);
        assert_eq!(
            projected.targets[0].freshness,
            CertificateObservationFreshness::Pending
        );
        assert_eq!(
            projected.targets[1].freshness,
            CertificateObservationFreshness::Stale
        );
        assert_eq!(
            projected.targets[1].error_code,
            Some(CertificateProbeErrorCode::ConnectTimeout)
        );
        assert_eq!(projected.targets[1].expiry, Some(ExpiryStatus::Unknown));
    }

    #[test]
    fn response_statuses_use_closed_delivery_codes() {
        assert_eq!(classify_response_status(StatusCode::ACCEPTED), Ok(()));
        assert_eq!(
            classify_response_status(StatusCode::UNAUTHORIZED),
            Err("authentication_rejected")
        );
        assert_eq!(
            classify_response_status(StatusCode::TOO_MANY_REQUESTS),
            Err("rate_limited")
        );
        assert_eq!(
            classify_response_status(StatusCode::BAD_GATEWAY),
            Err("hub_unavailable")
        );
        assert_eq!(
            classify_response_status(StatusCode::UNPROCESSABLE_ENTITY),
            Err("contract_rejected")
        );
    }
}
