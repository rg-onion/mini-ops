use crate::certificate_probe::{
    CertificateProbeErrorCode, ExpiryStatus, HostnameStatus, ReachabilityStatus, TrustStatus,
};
use serde::Serialize;
use uuid::Uuid;

pub(crate) const FLEET_OBSERVATION_SCHEMA_VERSION: u64 = 1;

#[derive(Debug, Serialize)]
pub(crate) struct FleetObservation {
    pub(crate) schema_version: u64,
    pub(crate) observation_id: Uuid,
    pub(crate) observed_at: i64,
    pub(crate) agent_version: &'static str,
    pub(crate) system: SystemMetrics,
    pub(crate) security: SecurityMetrics,
    pub(crate) certificates: CertificateMetrics,
}

#[derive(Debug, Serialize)]
pub(crate) struct SystemMetrics {
    pub(crate) collected_at: i64,
    pub(crate) cpu_usage_percent: Option<f32>,
    pub(crate) memory_total_bytes: u64,
    pub(crate) memory_used_bytes: u64,
    pub(crate) disk_total_bytes: u64,
    pub(crate) disk_used_bytes: u64,
    pub(crate) load_average_1m: Option<f32>,
    pub(crate) load_average_5m: Option<f32>,
    pub(crate) load_average_15m: Option<f32>,
    pub(crate) uptime_seconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SecurityMetricsStatus {
    Available,
    Missing,
    Stale,
    Degraded,
}

#[derive(Debug, Serialize)]
pub(crate) struct SecurityFindingCounts {
    pub(crate) pass: u32,
    pub(crate) warn: u32,
    pub(crate) fail: u32,
}

#[derive(Debug, Serialize)]
pub(crate) struct SecurityMetrics {
    pub(crate) status: SecurityMetricsStatus,
    pub(crate) collected_at: Option<i64>,
    pub(crate) score: Option<u32>,
    pub(crate) findings: Option<SecurityFindingCounts>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CertificateMetricsStatus {
    Disabled,
    Enabled,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CertificateObservationFreshness {
    Pending,
    Fresh,
    Stale,
}

#[derive(Debug, Serialize)]
pub(crate) struct CertificateTargetMetrics {
    pub(crate) target_id: String,
    pub(crate) server_name: String,
    pub(crate) port: u16,
    pub(crate) freshness: CertificateObservationFreshness,
    pub(crate) checked_at: Option<i64>,
    pub(crate) last_success_at: Option<i64>,
    pub(crate) reachability: Option<ReachabilityStatus>,
    pub(crate) trust: Option<TrustStatus>,
    pub(crate) hostname: Option<HostnameStatus>,
    pub(crate) expiry: Option<ExpiryStatus>,
    pub(crate) not_after: Option<i64>,
    pub(crate) error_code: Option<CertificateProbeErrorCode>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CertificateMetrics {
    pub(crate) status: CertificateMetricsStatus,
    pub(crate) interval_seconds: Option<u64>,
    pub(crate) targets: Vec<CertificateTargetMetrics>,
}
