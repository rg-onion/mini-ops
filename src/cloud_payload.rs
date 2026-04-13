use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Serialize)]
pub struct SystemMetrics {
    pub cpu_usage_percent: f32,
    pub memory_total_mb: u64,
    pub memory_used_mb: u64,
    pub memory_usage_percent: f32,
    pub disk_total_gb: f64,
    pub disk_used_gb: f64,
    pub disk_usage_percent: f32,
    pub load_average_1m: f32,
    pub load_average_5m: f32,
    pub load_average_15m: f32,
    pub uptime_seconds: u64,
    pub os_name: String,
    pub kernel_version: String,
}

#[derive(Serialize)]
pub struct ContainerMetrics {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    pub cpu_percent: f32,
    pub memory_mb: u64,
}

#[derive(Serialize)]
pub struct DockerMetrics {
    pub containers: Vec<ContainerMetrics>,
    pub total_running: u32,
    pub total_stopped: u32,
}

#[derive(Serialize)]
pub struct SshLoginInfo {
    pub user: String,
    pub ip: String,
    pub timestamp: DateTime<Utc>,
    pub is_trusted: bool,
}

#[derive(Serialize)]
pub struct SecurityMetrics {
    pub ssh_hardening_score: u32,
    pub fail2ban_active: bool,
    pub ufw_enabled: bool,
    pub open_ports: Vec<u16>,
    /// Last SSH login event: username + source IP + timestamp.
    /// Sent to the Hub so the commercial dashboard can show login activity
    /// across multiple servers in one place. Never collected unless
    /// CLOUD_PUSH_ENABLED=true is explicitly set by the operator.
    pub last_ssh_login: Option<SshLoginInfo>,
    /// IPs the operator marked as trusted in the local panel.
    /// Sent so the Hub can correlate alerts correctly (e.g. suppress
    /// false-positive alerts for known admin IPs). Same opt-in guarantee
    /// as last_ssh_login above.
    pub trusted_ips: Vec<String>,
}

#[derive(Serialize)]
pub struct AlertMetric {
    pub alert_type: String,
    pub severity: String,
    pub message: String,
    pub since: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct AlertsMetrics {
    pub active: Vec<AlertMetric>,
}

#[derive(Serialize)]
pub struct CloudPayload {
    pub agent_id: String,
    pub agent_version: String,
    pub server_name: String,
    pub hostname: String,
    pub timestamp: DateTime<Utc>,
    pub system: SystemMetrics,
    pub docker: DockerMetrics,
    pub security: SecurityMetrics,
    pub alerts: AlertsMetrics,
}
