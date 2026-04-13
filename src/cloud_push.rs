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
use crate::security::SecurityAuditor;
use crate::ssh_alerts::SshAlertsService;

pub struct CloudPushConfig {
    pub hub_url: String,
    pub agent_id: String,
    pub agent_token: String,
    pub push_interval_secs: u64,
}

pub struct CloudPushService {
    config: CloudPushConfig,
    client: reqwest::Client,
}

impl CloudPushService {
    /// Creates a new CloudPushService.
    ///
    /// Requires HTTPS by default. Set `CLOUD_PUSH_ALLOW_HTTP=true` only for
    /// local development/testing — never in production.
    pub fn new(config: CloudPushConfig) -> Result<Self, String> {
        let allow_http = std::env::var("CLOUD_PUSH_ALLOW_HTTP").as_deref() == Ok("true");

        if !config.hub_url.starts_with("https://") {
            if allow_http {
                warn!(
                    "Cloud push: CLOUD_PUSH_ALLOW_HTTP=true — sending data over plaintext HTTP to '{}'. \
                     Do NOT use in production.",
                    config.hub_url
                );
            } else {
                return Err(format!(
                    "CLOUD_HUB_URL must use HTTPS (got: '{}'). \
                     Set CLOUD_PUSH_ALLOW_HTTP=true to override for local testing only.",
                    config.hub_url
                ));
            }
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| e.to_string())?;

        Ok(Self { config, client })
    }

    pub fn start(
        self: Arc<Self>,
        metrics: Arc<MetricsState>,
        docker: Option<Arc<DockerService>>,
        ssh_alerts: Arc<SshAlertsService>,
    ) {
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(self.config.push_interval_secs));
            let mut backoff_secs: u64 = 1;
            loop {
                interval.tick().await;
                match self
                    .push_once(&metrics, docker.as_ref(), &ssh_alerts)
                    .await
                {
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
        let payload = self.build_payload(metrics, docker, ssh_alerts).await?;
        let resp = self
            .client
            .post(format!("{}/api/v1/agents/push", self.config.hub_url))
            .bearer_auth(&self.config.agent_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| e.to_string())?;

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
                Err(e) => {
                    warn!("Cloud push: failed to list containers: {}", e);
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
        let lang = Lang::EN;
        let checks = SecurityAuditor::run_audit(&lang).await;
        let pass_count = checks.iter().filter(|c| c.status == "PASS").count();
        let ssh_hardening_score = (pass_count as u32 * 100) / 7;
        let fail2ban_active = checks
            .iter()
            .any(|c| c.name.contains("Fail2Ban") && c.status == "PASS");
        let ufw_enabled = checks
            .iter()
            .any(|c| c.name.contains("UFW") && c.status == "PASS");

        // SSH alerts
        let logs = ssh_alerts
            .get_logs()
            .await
            .map_err(|e| e.to_string())?;
        let trusted_ips_list = ssh_alerts
            .get_trusted_ips()
            .await
            .map_err(|e| e.to_string())?;
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
            open_ports: Vec::new(),
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
}
