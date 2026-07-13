use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tracing::{info, warn};

use crate::cloud_payload::{
    AlertsMetrics, CloudPayload, ContainerMetrics, DockerMetrics, SecurityMetrics, SshLoginInfo,
    SystemMetrics,
};
use crate::docker::DockerService;
use crate::i18n::Lang;
use crate::metrics::MetricsState;
use crate::security::{SecurityAuditor, SecurityCheck};
use crate::security_snapshot::{SecurityCollectionStatus, SecuritySnapshotService};
use crate::ssh_alerts::SshAlertsService;

const DEFAULT_PUSH_INTERVAL_SECS: u64 = 60;
const MIN_PUSH_INTERVAL_SECS: u64 = 60;
const MAX_PUSH_INTERVAL_SECS: u64 = 86_400;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloudPushIntervalError {
    Blank,
    Invalid,
    OutOfRange,
}

impl CloudPushIntervalError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Blank => "blank_interval",
            Self::Invalid => "invalid_interval",
            Self::OutOfRange => "interval_out_of_range",
        }
    }
}

pub fn parse_push_interval(value: Option<&str>) -> Result<u64, CloudPushIntervalError> {
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

pub struct CloudPushConfig {
    pub hub_url: String,
    pub agent_id: String,
    pub agent_token: String,
    pub push_interval_secs: u64,
}

pub struct CloudPushService {
    config: CloudPushConfig,
    client: reqwest::Client,
    security_snapshots: Arc<SecuritySnapshotService>,
    security_snapshot_max_age: Duration,
}

impl CloudPushService {
    /// Creates a new CloudPushService.
    ///
    /// Requires HTTPS by default. Set `CLOUD_PUSH_ALLOW_HTTP=true` only for
    /// local development/testing — never in production.
    pub fn new(
        config: CloudPushConfig,
        security_snapshots: Arc<SecuritySnapshotService>,
    ) -> Result<Self, String> {
        if !(MIN_PUSH_INTERVAL_SECS..=MAX_PUSH_INTERVAL_SECS).contains(&config.push_interval_secs) {
            return Err("CLOUD_PUSH_INTERVAL is outside the supported range".to_string());
        }
        let allow_http = std::env::var("CLOUD_PUSH_ALLOW_HTTP").as_deref() == Ok("true");

        if !config.hub_url.starts_with("https://") {
            if allow_http {
                warn!(
                    "Cloud push: CLOUD_PUSH_ALLOW_HTTP=true — sending data over plaintext HTTP. \
                     Do NOT use in production."
                );
            } else {
                return Err(
                    "CLOUD_HUB_URL must use HTTPS; CLOUD_PUSH_ALLOW_HTTP is development-only"
                        .to_string(),
                );
            }
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| "cloud_client_init_failed".to_string())?;

        let security_snapshot_max_age = Duration::from_secs(
            security_snapshots
                .audit_interval()
                .as_secs()
                .saturating_mul(2),
        );
        Ok(Self {
            config,
            client,
            security_snapshots,
            security_snapshot_max_age,
        })
    }

    pub fn start(
        self: Arc<Self>,
        metrics: Arc<MetricsState>,
        docker: Option<Arc<DockerService>>,
        ssh_alerts: Arc<SshAlertsService>,
    ) {
        tokio::spawn(async move {
            let push_interval = Duration::from_secs(self.config.push_interval_secs);
            let first_tick = first_push_tick(tokio::time::Instant::now(), push_interval);
            let mut interval = tokio::time::interval_at(first_tick, push_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut backoff_secs: u64 = 1;
            loop {
                interval.tick().await;
                match self.push_once(&metrics, docker.as_ref(), &ssh_alerts).await {
                    Ok(()) => {
                        backoff_secs = 1;
                    }
                    Err(e) => {
                        warn!("Cloud push failed: {}. Retry in {}s", e, backoff_secs);
                        tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                        backoff_secs = (backoff_secs * 2).min(60);
                    }
                }
            }
        });
    }

    async fn push_once(
        &self,
        metrics: &MetricsState,
        docker: Option<&Arc<DockerService>>,
        ssh_alerts: &SshAlertsService,
    ) -> Result<(), String> {
        let checks = match self.security_checks_for_push().await {
            Ok(checks) => checks,
            Err(reason) => {
                warn!(
                    snapshot_status = reason.code(),
                    "Cloud push skipped: security snapshot is not publishable"
                );
                return Ok(());
            }
        };
        let payload = self
            .build_payload(metrics, docker, ssh_alerts, &checks)
            .await?;
        let resp = self
            .client
            .post(format!("{}/api/v1/agents/push", self.config.hub_url))
            .bearer_auth(&self.config.agent_token)
            .json(&payload)
            .send()
            .await
            .map_err(|_| "cloud_request_failed".to_string())?;

        if resp.status().is_success() {
            info!("Cloud push OK");
            Ok(())
        } else if resp.status() == 401 {
            warn!("Cloud push 401 — invalid token");
            Ok(()) // не backoff, продолжаем
        } else {
            Err(format!("Hub returned {}", resp.status()))
        }
    }

    async fn build_payload(
        &self,
        metrics: &MetricsState,
        docker: Option<&Arc<DockerService>>,
        ssh_alerts: &SshAlertsService,
        checks: &[SecurityCheck],
    ) -> Result<CloudPayload, String> {
        // System metrics
        let stats = metrics.get_current();

        let memory_total_mb = stats.memory_total / 1024 / 1024;
        let memory_used_mb = stats.memory_used / 1024 / 1024;
        let memory_usage_percent = if stats.memory_total > 0 {
            (stats.memory_used as f32 / stats.memory_total as f32) * 100.0
        } else {
            0.0
        };

        let disk_total_gb = stats.disk_total as f64 / 1024.0 / 1024.0 / 1024.0;
        let disk_used_gb = stats.disk_used as f64 / 1024.0 / 1024.0 / 1024.0;
        let disk_usage_percent = if stats.disk_total > 0 {
            (stats.disk_used as f32 / stats.disk_total as f32) * 100.0
        } else {
            0.0
        };

        let load_avg = sysinfo::System::load_average();
        let uptime_seconds = sysinfo::System::uptime();
        let os_name = sysinfo::System::name().unwrap_or_default();
        let kernel_version = sysinfo::System::kernel_version().unwrap_or_default();

        let system = SystemMetrics {
            cpu_usage_percent: stats.cpu_usage,
            memory_total_mb,
            memory_used_mb,
            memory_usage_percent,
            disk_total_gb,
            disk_used_gb,
            disk_usage_percent,
            load_average_1m: load_avg.one as f32,
            load_average_5m: load_avg.five as f32,
            load_average_15m: load_avg.fifteen as f32,
            uptime_seconds,
            os_name,
            kernel_version,
        };

        // Docker metrics
        let docker_metrics = if let Some(svc) = docker {
            match svc.list_containers().await {
                Ok(containers) => {
                    let mut total_running = 0u32;
                    let mut total_stopped = 0u32;
                    let container_metrics: Vec<ContainerMetrics> = containers
                        .into_iter()
                        .map(|c| {
                            if c.state.to_lowercase() == "running" {
                                total_running += 1;
                            } else {
                                total_stopped += 1;
                            }
                            ContainerMetrics {
                                id: c.id,
                                name: c.name,
                                image: c.image,
                                state: c.state,
                                status: c.status,
                                cpu_percent: 0.0,
                                memory_mb: 0,
                            }
                        })
                        .collect();
                    DockerMetrics {
                        containers: container_metrics,
                        total_running,
                        total_stopped,
                    }
                }
                Err(_) => {
                    warn!(
                        docker_error = "list_failed",
                        "Cloud push could not collect Docker container metrics"
                    );
                    DockerMetrics {
                        containers: vec![],
                        total_running: 0,
                        total_stopped: 0,
                    }
                }
            }
        } else {
            DockerMetrics {
                containers: vec![],
                total_running: 0,
                total_stopped: 0,
            }
        };

        // Security metrics
        let ssh_hardening_score = SecurityAuditor::calculate_score(checks);
        let fail2ban_active = checks
            .iter()
            .any(|c| c.id == "intrusion.fail2ban" && c.status == "PASS");
        let ufw_enabled = checks
            .iter()
            .any(|c| c.id == "firewall.ufw" && c.status == "PASS");
        let open_ports = SecurityAuditor::extract_open_ports(checks);

        // SSH alerts
        let logs = ssh_alerts
            .get_logs()
            .await
            .map_err(|_| "ssh_logs_unavailable".to_string())?;
        let trusted_ips_list = ssh_alerts
            .get_trusted_ips()
            .await
            .map_err(|_| "trusted_ips_unavailable".to_string())?;
        let trusted_ip_strings: Vec<String> =
            trusted_ips_list.iter().map(|t| t.ip.clone()).collect();

        let last_ssh_login = logs.into_iter().next().map(|log| {
            let is_trusted = trusted_ip_strings.contains(&log.ip);
            let timestamp: DateTime<Utc> =
                DateTime::from_timestamp(log.timestamp, 0).unwrap_or_else(Utc::now);
            SshLoginInfo {
                user: log.user,
                ip: log.ip,
                timestamp,
                is_trusted,
            }
        });

        let security = SecurityMetrics {
            ssh_hardening_score,
            fail2ban_active,
            ufw_enabled,
            open_ports,
            last_ssh_login,
            trusted_ips: trusted_ip_strings,
        };

        // Server name / hostname
        let server_name = std::env::var("SERVER_NAME")
            .unwrap_or_else(|_| sysinfo::System::host_name().unwrap_or_default());
        let hostname = sysinfo::System::host_name().unwrap_or_default();

        Ok(CloudPayload {
            agent_id: self.config.agent_id.clone(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            server_name,
            hostname,
            timestamp: Utc::now(),
            system,
            docker: docker_metrics,
            security,
            alerts: AlertsMetrics { active: vec![] },
        })
    }

    async fn security_checks_for_push(&self) -> Result<Vec<SecurityCheck>, SnapshotSkipReason> {
        let snapshot = self
            .security_snapshots
            .latest()
            .await
            .ok_or(SnapshotSkipReason::Missing)?;
        if snapshot.age() > self.security_snapshot_max_age {
            return Err(SnapshotSkipReason::Stale);
        }
        if snapshot.collection_status() != SecurityCollectionStatus::Full {
            return Err(SnapshotSkipReason::Degraded);
        }
        Ok(snapshot.project(&Lang::EN))
    }
}

fn first_push_tick(startup: tokio::time::Instant, interval: Duration) -> tokio::time::Instant {
    startup + interval
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnapshotSkipReason {
    Missing,
    Stale,
    Degraded,
}

impl SnapshotSkipReason {
    const fn code(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Stale => "stale",
            Self::Degraded => "degraded",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn test_service(snapshots: Arc<SecuritySnapshotService>) -> CloudPushService {
        CloudPushService::new(
            CloudPushConfig {
                hub_url: "https://cloud.invalid".to_string(),
                agent_id: "test-agent".to_string(),
                agent_token: "redacted-test-token".to_string(),
                push_interval_secs: 60,
            },
            snapshots,
        )
        .expect("valid test cloud configuration")
    }

    #[test]
    fn cloud_push_interval_matrix_is_fail_closed() {
        assert_eq!(parse_push_interval(None), Ok(60));
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
    fn first_cloud_tick_is_delayed_by_the_validated_interval() {
        let startup = tokio::time::Instant::now();
        let interval = Duration::from_secs(60);
        assert_eq!(first_push_tick(startup, interval), startup + interval);
        assert!(first_push_tick(startup, interval) > startup);
    }

    #[tokio::test]
    async fn cloud_reads_fresh_snapshot_without_running_collector() {
        let counter = Arc::new(AtomicUsize::new(0));
        let snapshots = SecuritySnapshotService::test_service(Arc::clone(&counter));
        snapshots.publish_test_snapshot(Duration::ZERO, false).await;
        let service = test_service(snapshots);

        let checks = service
            .security_checks_for_push()
            .await
            .expect("fresh full snapshot should be usable");
        assert!(!checks.is_empty());
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cloud_skips_stale_missing_and_degraded_snapshots_without_runner() {
        let counter = Arc::new(AtomicUsize::new(0));

        let missing_snapshots = SecuritySnapshotService::test_service(Arc::clone(&counter));
        let missing = test_service(missing_snapshots);
        assert!(matches!(
            missing.security_checks_for_push().await,
            Err(SnapshotSkipReason::Missing)
        ));

        let stale_snapshots = SecuritySnapshotService::test_service(Arc::clone(&counter));
        stale_snapshots
            .publish_test_snapshot(Duration::from_secs(601), false)
            .await;
        let stale = test_service(stale_snapshots);
        assert!(matches!(
            stale.security_checks_for_push().await,
            Err(SnapshotSkipReason::Stale)
        ));

        let degraded_snapshots = SecuritySnapshotService::test_service(Arc::clone(&counter));
        degraded_snapshots
            .publish_test_snapshot(Duration::ZERO, true)
            .await;
        let degraded = test_service(degraded_snapshots);
        assert!(matches!(
            degraded.security_checks_for_push().await,
            Err(SnapshotSkipReason::Degraded)
        ));

        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }
}
