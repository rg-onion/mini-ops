use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::{Mutex, watch};
use uuid::Uuid;

use crate::docker::DockerService;
use crate::i18n::Lang;
use crate::security::{SecurityAuditor, SecurityCheck};

const SNAPSHOT_SIZE_LIMIT_BYTES: usize = 256 * 1024;
const SNAPSHOT_WAIT_DEADLINE: Duration = Duration::from_secs(21);
const REQUIRED_CHECK_IDS: [&str; 9] = [
    "ssh.root_login",
    "ssh.password_auth",
    "firewall.ufw",
    "docker.socket_permissions",
    "system.disk_encryption",
    "intrusion.fail2ban",
    "network.listening_ports",
    "docker.tcp_api",
    "docker.container_hardening",
];

type CollectorFuture<'a> = Pin<Box<dyn Future<Output = Vec<SecurityCheck>> + Send + 'a>>;

trait SecuritySnapshotCollector: Send + Sync {
    fn collect(&self) -> CollectorFuture<'_>;
}

struct SystemSecurityCollector {
    docker: Option<Arc<DockerService>>,
}

impl SecuritySnapshotCollector for SystemSecurityCollector {
    fn collect(&self) -> CollectorFuture<'_> {
        // The legacy auditor still renders a transient projection while it
        // probes. `publish_checks` immediately strips those localized strings;
        // only stable facts and localization keys enter the shared snapshot.
        Box::pin(async move { SecurityAuditor::run_audit(&Lang::EN, self.docker.as_deref()).await })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityCollectionStatus {
    Full,
    Degraded,
}

impl SecurityCollectionStatus {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Degraded => "degraded",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecuritySnapshotIdentity {
    collector_epoch: Uuid,
    generation: u64,
}

impl SecuritySnapshotIdentity {
    pub fn collector_epoch(self) -> Uuid {
        self.collector_epoch
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Debug, Serialize)]
struct SecurityCheckFact {
    id: String,
    category: String,
    severity: String,
    status: String,
    evidence: Vec<String>,
    references: Vec<String>,
    metadata: std::collections::HashMap<String, Vec<String>>,
    name_key: &'static str,
    message_key: &'static str,
    message_detail: Option<String>,
    remediation_key: &'static str,
}

impl SecurityCheckFact {
    fn from_check(check: SecurityCheck) -> Option<Self> {
        let (name_key, message_key, message_detail, remediation_key) = presentation_for(&check)?;
        Some(Self {
            id: check.id,
            category: check.category,
            severity: check.severity,
            status: check.status,
            evidence: check.evidence,
            references: check.references,
            metadata: check.metadata,
            name_key,
            message_key,
            message_detail,
            remediation_key,
        })
    }

    fn project(&self, lang: &Lang) -> SecurityCheck {
        let message = crate::i18n::t(self.message_key, lang);
        SecurityCheck {
            id: self.id.clone(),
            name: crate::i18n::t(self.name_key, lang),
            category: self.category.clone(),
            severity: self.severity.clone(),
            status: self.status.clone(),
            message: self
                .message_detail
                .as_ref()
                .map_or(message.clone(), |detail| format!("{message}: {detail}")),
            evidence: self.evidence.clone(),
            remediation: crate::i18n::t(self.remediation_key, lang),
            references: self.references.clone(),
            metadata: self.metadata.clone(),
        }
    }

    fn degraded(code: &'static str) -> Self {
        Self {
            id: "audit.collection".to_string(),
            category: "system".to_string(),
            severity: "high".to_string(),
            status: "WARN".to_string(),
            evidence: vec![format!("snapshot_error={code}")],
            references: Vec::new(),
            metadata: std::collections::HashMap::new(),
            name_key: "audit.collection.name",
            message_key: "audit.collection.degraded",
            message_detail: None,
            remediation_key: "audit.collection.remediation",
        }
    }
}

fn presentation_for(
    check: &SecurityCheck,
) -> Option<(&'static str, &'static str, Option<String>, &'static str)> {
    let presentation = match check.id.as_str() {
        "audit.collection" => (
            "audit.collection.name",
            "audit.collection.error",
            None,
            "audit.collection.remediation",
        ),
        "ssh.root_login" => {
            let message_key = match check.status.as_str() {
                "PASS" => "audit.ssh_root.pass",
                "FAIL" => "audit.ssh_root.fail",
                "WARN"
                    if check
                        .evidence
                        .iter()
                        .any(|value| value == "effective_config=false")
                        || !check
                            .evidence
                            .iter()
                            .any(|value| value.starts_with("permitrootlogin=")) =>
                {
                    "audit.ssh_config.warn"
                }
                "WARN"
                    if check.evidence.iter().any(|value| {
                        matches!(
                            value.as_str(),
                            "permitrootlogin=prohibit-password"
                                | "permitrootlogin=without-password"
                                | "permitrootlogin=forced-commands-only"
                        )
                    }) =>
                {
                    "audit.ssh_root.warn_restricted"
                }
                _ => "audit.ssh_root.warn_unknown",
            };
            (
                "audit.ssh_root.name",
                message_key,
                None,
                "audit.ssh_root.remediation",
            )
        }
        "ssh.password_auth" => (
            "audit.ssh_passwd.name",
            match check.status.as_str() {
                "PASS" => "audit.ssh_passwd.pass",
                "FAIL" => "audit.ssh_passwd.fail",
                _ => "audit.ssh_config.warn",
            },
            None,
            "audit.ssh_passwd.remediation",
        ),
        "firewall.ufw" => (
            "audit.ufw.name",
            match check.status.as_str() {
                "PASS" => "audit.ufw.pass",
                "FAIL" => "audit.ufw.fail",
                _ => "audit.ufw.error",
            },
            None,
            "audit.ufw.remediation",
        ),
        "docker.socket_permissions" => (
            "audit.docker_sock.name",
            match check.status.as_str() {
                "PASS" => "audit.docker_sock.pass",
                "FAIL" => "audit.docker_sock.fail",
                _ => "audit.docker_sock.warn",
            },
            None,
            "audit.docker_sock.remediation",
        ),
        "system.disk_encryption" => (
            "audit.disk_enc.name",
            if check.status == "PASS" {
                "audit.disk_enc.pass"
            } else if check.evidence.is_empty() {
                "audit.disk_enc.warn"
            } else {
                "audit.disk_enc.error"
            },
            None,
            "audit.disk_enc.remediation",
        ),
        "intrusion.fail2ban" => (
            "audit.fail2ban.name",
            if check.status == "PASS" {
                "audit.fail2ban.pass"
            } else {
                "audit.fail2ban.warn"
            },
            None,
            "audit.fail2ban.remediation",
        ),
        "network.listening_ports" => {
            let suspicious = check
                .metadata
                .get("suspicious_ports")
                .filter(|values| !values.is_empty());
            let (message_key, detail) = if let Some(values) = suspicious {
                ("audit.ports.warn", Some(values.join(", ")))
            } else if check.metadata.contains_key("invalid_allowed_port_count") {
                ("audit.ports.config_error", None)
            } else if check.status == "PASS" {
                ("audit.ports.pass", None)
            } else {
                ("audit.ports.error", None)
            };
            (
                "audit.ports.name",
                message_key,
                detail,
                "audit.ports.remediation",
            )
        }
        "docker.tcp_api" => {
            let public_ports = check
                .metadata
                .get("public_listeners")
                .into_iter()
                .flatten()
                .filter_map(|listener| listener.rsplit(':').next()?.parse::<u16>().ok())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .map(|port| port.to_string())
                .collect::<Vec<_>>();
            let (message_key, detail) = if check.status == "PASS" {
                ("audit.docker_api.pass", None)
            } else if !public_ports.is_empty() {
                ("audit.docker_api.fail", Some(public_ports.join(", ")))
            } else if check.metadata.contains_key("loopback_listeners") {
                ("audit.docker_api.fail", None)
            } else {
                ("audit.ports.error", None)
            };
            (
                "audit.docker_api.name",
                message_key,
                detail,
                "audit.docker_api.remediation",
            )
        }
        "docker.container_hardening" => {
            let risk_count = check
                .metadata
                .get("risk_count")
                .and_then(|values| values.first())
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or_else(|| {
                    check
                        .metadata
                        .iter()
                        .filter(|(key, _)| key.ends_with("_risks"))
                        .map(|(_, values)| values.len())
                        .sum::<usize>()
                });
            let (message_key, detail) = if risk_count > 0 {
                ("audit.docker_containers.fail", Some(risk_count.to_string()))
            } else if check.status == "PASS" && !check.references.is_empty() {
                ("audit.docker_containers.pass", None)
            } else if check.status == "PASS" {
                ("audit.docker_containers.no_runtime", None)
            } else if check
                .evidence
                .iter()
                .any(|value| value == "probe_error=timeout")
            {
                ("audit.docker_containers.timeout", None)
            } else if check.evidence.is_empty() {
                ("audit.docker_containers.unavailable", None)
            } else {
                ("audit.docker_containers.error", None)
            };
            (
                "audit.docker_containers.name",
                message_key,
                detail,
                "audit.docker_containers.remediation",
            )
        }
        _ => return None,
    };
    Some(presentation)
}

#[derive(Debug)]
pub struct SecurityAuditSnapshot {
    identity: SecuritySnapshotIdentity,
    collected_at: i64,
    collected_instant: Instant,
    collection_status: SecurityCollectionStatus,
    facts: Vec<SecurityCheckFact>,
}

impl SecurityAuditSnapshot {
    pub const fn identity(&self) -> SecuritySnapshotIdentity {
        self.identity
    }

    pub const fn collected_at(&self) -> i64 {
        self.collected_at
    }

    pub const fn collection_status(&self) -> SecurityCollectionStatus {
        self.collection_status
    }

    pub fn age(&self) -> Duration {
        self.collected_instant.elapsed()
    }

    pub fn project(&self, lang: &Lang) -> Vec<SecurityCheck> {
        self.facts.iter().map(|fact| fact.project(lang)).collect()
    }

    #[cfg(test)]
    fn serialized_size(&self) -> usize {
        serialized_snapshot_size(
            self.identity.collector_epoch,
            self.identity.generation,
            self.collected_at,
            self.collection_status,
            &self.facts,
        )
        .unwrap_or(usize::MAX)
    }
}

#[derive(Default)]
struct SnapshotState {
    latest: Option<Arc<SecurityAuditSnapshot>>,
    refreshing: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecuritySnapshotUnavailable;

pub struct SecuritySnapshotService {
    collector_epoch: Uuid,
    collector: Arc<dyn SecuritySnapshotCollector>,
    state: Mutex<SnapshotState>,
    changed: watch::Sender<u64>,
    api_cache_ttl: Duration,
    audit_interval: Duration,
    wait_deadline: Duration,
}

impl SecuritySnapshotService {
    pub fn from_env(docker: Option<Arc<DockerService>>) -> Arc<Self> {
        Arc::new(Self {
            collector_epoch: Uuid::new_v4(),
            collector: Arc::new(SystemSecurityCollector { docker }),
            state: Mutex::new(SnapshotState::default()),
            changed: watch::channel(0).0,
            api_cache_ttl: env_duration_secs("SECURITY_AUDIT_CACHE_TTL_SECS", 30, 0, 3600),
            audit_interval: env_duration_secs("SECURITY_AUDIT_INTERVAL_SECS", 300, 60, 86_400),
            wait_deadline: SNAPSHOT_WAIT_DEADLINE,
        })
    }

    #[cfg(test)]
    fn with_collector(
        collector: Arc<dyn SecuritySnapshotCollector>,
        api_cache_ttl: Duration,
        audit_interval: Duration,
    ) -> Arc<Self> {
        Self::with_collector_and_deadline(
            collector,
            api_cache_ttl,
            audit_interval,
            SNAPSHOT_WAIT_DEADLINE,
        )
    }

    #[cfg(test)]
    fn with_collector_and_deadline(
        collector: Arc<dyn SecuritySnapshotCollector>,
        api_cache_ttl: Duration,
        audit_interval: Duration,
        wait_deadline: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            collector_epoch: Uuid::new_v4(),
            collector,
            state: Mutex::new(SnapshotState::default()),
            changed: watch::channel(0).0,
            api_cache_ttl,
            audit_interval,
            wait_deadline,
        })
    }

    pub const fn api_cache_ttl(&self) -> Duration {
        self.api_cache_ttl
    }

    pub const fn audit_interval(&self) -> Duration {
        self.audit_interval
    }

    pub async fn latest(&self) -> Option<Arc<SecurityAuditSnapshot>> {
        self.state.lock().await.latest.clone()
    }

    pub async fn get_or_refresh(
        self: &Arc<Self>,
        max_age: Duration,
    ) -> Result<Arc<SecurityAuditSnapshot>, SecuritySnapshotUnavailable> {
        let (observed_generation, start_refresh, mut changed) = {
            let mut state = self.state.lock().await;
            if max_age > Duration::ZERO
                && let Some(snapshot) = state.latest.as_ref()
                && snapshot.age() <= max_age
            {
                return Ok(Arc::clone(snapshot));
            }

            let observed_generation = state
                .latest
                .as_ref()
                .map_or(0, |snapshot| snapshot.identity.generation);
            let start_refresh = !state.refreshing;
            if start_refresh {
                state.refreshing = true;
            }
            (observed_generation, start_refresh, self.changed.subscribe())
        };

        if start_refresh {
            let service = Arc::clone(self);
            tokio::spawn(async move {
                service.refresh_owned().await;
            });
        }

        let deadline = tokio::time::sleep(self.wait_deadline);
        tokio::pin!(deadline);
        loop {
            {
                let state = self.state.lock().await;
                if !state.refreshing {
                    return state
                        .latest
                        .as_ref()
                        .filter(|snapshot| snapshot.identity.generation > observed_generation)
                        .cloned()
                        .ok_or(SecuritySnapshotUnavailable);
                }
            }

            tokio::select! {
                result = changed.changed() => {
                    if result.is_err() {
                        return Err(SecuritySnapshotUnavailable);
                    }
                }
                _ = &mut deadline => {
                    return self
                        .latest()
                        .await
                        .filter(|snapshot| snapshot.identity.generation > observed_generation)
                        .ok_or(SecuritySnapshotUnavailable);
                }
            }
        }
    }

    async fn refresh_owned(self: Arc<Self>) {
        let collector = Arc::clone(&self.collector);
        let checks = match tokio::spawn(async move { collector.collect().await }).await {
            Ok(checks) => checks,
            Err(_) => {
                tracing::warn!(
                    snapshot_error = "collector_task_failed",
                    "Security snapshot collection failed"
                );
                Vec::new()
            }
        };
        self.publish_checks(checks, Instant::now()).await;
    }

    async fn publish_checks(&self, checks: Vec<SecurityCheck>, collected_instant: Instant) {
        let complete = collection_is_complete(&checks);
        let explicitly_degraded = checks.len() == 1
            && checks[0].id == "audit.collection"
            && checks[0].status == "WARN"
            && check_has_unknown_facts(&checks[0]);
        let has_unknown_facts = checks.iter().any(check_has_unknown_facts);
        let facts = if complete || explicitly_degraded {
            checks
                .into_iter()
                .map(SecurityCheckFact::from_check)
                .collect::<Option<Vec<_>>>()
        } else {
            None
        };
        let (mut status, mut facts) = match (facts, explicitly_degraded) {
            (Some(facts), false) if !has_unknown_facts => (SecurityCollectionStatus::Full, facts),
            (Some(mut facts), false) => {
                facts.push(SecurityCheckFact::degraded("unknown_facts"));
                (SecurityCollectionStatus::Degraded, facts)
            }
            (Some(facts), true) => (SecurityCollectionStatus::Degraded, facts),
            (None, _) => (
                SecurityCollectionStatus::Degraded,
                vec![SecurityCheckFact::degraded("incomplete_collection")],
            ),
        };

        let mut state = self.state.lock().await;
        let Some(generation) = state.latest.as_ref().map_or(Some(1), |snapshot| {
            snapshot.identity.generation.checked_add(1)
        }) else {
            state.refreshing = false;
            drop(state);
            tracing::warn!(
                snapshot_error = "generation_exhausted",
                "Security snapshot refresh was not publishable"
            );
            self.signal_changed();
            return;
        };

        let collected_at = chrono::Utc::now().timestamp();
        let mut serialized_size = serialized_snapshot_size(
            self.collector_epoch,
            generation,
            collected_at,
            status,
            &facts,
        );
        if serialized_size.is_none_or(|size| size >= SNAPSHOT_SIZE_LIMIT_BYTES) {
            status = SecurityCollectionStatus::Degraded;
            facts = vec![SecurityCheckFact::degraded("size_limit")];
            serialized_size = serialized_snapshot_size(
                self.collector_epoch,
                generation,
                collected_at,
                status,
                &facts,
            );
        }

        let Some(_serialized_size) =
            serialized_size.filter(|size| *size < SNAPSHOT_SIZE_LIMIT_BYTES)
        else {
            state.refreshing = false;
            drop(state);
            tracing::warn!(
                snapshot_error = "serialization",
                "Security snapshot refresh was not publishable"
            );
            self.signal_changed();
            return;
        };
        state.latest = Some(Arc::new(SecurityAuditSnapshot {
            identity: SecuritySnapshotIdentity {
                collector_epoch: self.collector_epoch,
                generation,
            },
            collected_at,
            collected_instant,
            collection_status: status,
            facts,
        }));
        state.refreshing = false;
        drop(state);
        self.signal_changed();
    }

    #[cfg(test)]
    pub(crate) fn test_service(counter: Arc<std::sync::atomic::AtomicUsize>) -> Arc<Self> {
        Self::with_collector(
            Arc::new(TestCountingCollector {
                counter,
                delay: Duration::ZERO,
            }),
            Duration::from_secs(30),
            Duration::from_secs(300),
        )
    }

    #[cfg(test)]
    pub(crate) fn test_degraded_then_full_service(
        counter: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Arc<Self> {
        Self::with_collector(
            Arc::new(TestDegradedThenFullCollector { counter }),
            Duration::ZERO,
            Duration::from_secs(300),
        )
    }

    #[cfg(test)]
    pub(crate) async fn publish_test_snapshot(&self, age: Duration, degraded: bool) {
        let collected_instant = Instant::now().checked_sub(age).unwrap_or_else(Instant::now);
        let mut checks = test_checks();
        if degraded && let Some(check) = checks.iter_mut().find(|check| check.id == "firewall.ufw")
        {
            *check = test_check("firewall.ufw", "WARN");
        }
        self.publish_checks(checks, collected_instant).await;
    }

    fn signal_changed(&self) {
        self.changed
            .send_modify(|revision| *revision = revision.wrapping_add(1));
    }
}

fn collection_is_complete(checks: &[SecurityCheck]) -> bool {
    if checks.len() != REQUIRED_CHECK_IDS.len()
        || checks
            .iter()
            .any(|check| !matches!(check.status.as_str(), "PASS" | "FAIL" | "WARN"))
    {
        return false;
    }
    let ids = checks
        .iter()
        .map(|check| check.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    ids.len() == REQUIRED_CHECK_IDS.len()
        && REQUIRED_CHECK_IDS
            .iter()
            .all(|required| ids.contains(required))
}

fn check_has_unknown_facts(check: &SecurityCheck) -> bool {
    if check.evidence.iter().any(|fact| {
        fact.starts_with("probe_error=")
            || fact.starts_with("config_error=")
            || fact.starts_with("snapshot_error=")
            || fact.ends_with("=unknown")
    }) {
        return true;
    }
    if check.status != "WARN" {
        return false;
    }

    let proven_known_warn = match check.id.as_str() {
        "ssh.root_login" => check.evidence.iter().any(|fact| {
            matches!(
                fact.as_str(),
                "permitrootlogin=prohibit-password"
                    | "permitrootlogin=without-password"
                    | "permitrootlogin=forced-commands-only"
            )
        }),
        "system.disk_encryption" => check.evidence.is_empty(),
        "network.listening_ports" => check
            .metadata
            .get("suspicious_ports")
            .is_some_and(|ports| !ports.is_empty()),
        "docker.tcp_api" => check
            .metadata
            .get("loopback_listeners")
            .is_some_and(|listeners| !listeners.is_empty()),
        "docker.container_hardening" => check
            .metadata
            .get("risk_count")
            .and_then(|values| values.first())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|count| count > 0),
        _ => false,
    };
    !proven_known_warn
}

#[derive(Serialize)]
struct SerializedSnapshot<'a> {
    collector_epoch: Uuid,
    generation: u64,
    collected_at: i64,
    collection_status: SecurityCollectionStatus,
    facts: &'a [SecurityCheckFact],
}

fn serialized_snapshot_size(
    collector_epoch: Uuid,
    generation: u64,
    collected_at: i64,
    collection_status: SecurityCollectionStatus,
    facts: &[SecurityCheckFact],
) -> Option<usize> {
    serde_json::to_vec(&SerializedSnapshot {
        collector_epoch,
        generation,
        collected_at,
        collection_status,
        facts,
    })
    .ok()
    .map(|serialized| serialized.len())
}

fn env_duration_secs(key: &str, default: u64, min: u64, max: u64) -> Duration {
    parse_duration_secs(std::env::var(key).ok().as_deref(), default, min, max)
}

fn parse_duration_secs(value: Option<&str>, default: u64, min: u64, max: u64) -> Duration {
    let seconds = value
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|value| value.clamp(min, max))
        .unwrap_or(default);
    Duration::from_secs(seconds)
}

#[cfg(test)]
fn test_check(id: &str, status: &str) -> SecurityCheck {
    SecurityCheck {
        id: id.to_string(),
        name: "unused localized name".to_string(),
        category: "firewall".to_string(),
        severity: "high".to_string(),
        status: status.to_string(),
        message: "unused localized message".to_string(),
        evidence: vec![if id == "ssh.root_login" {
            "permitrootlogin=no".to_string()
        } else if status == "PASS" {
            "known=true".to_string()
        } else {
            "probe_error=timeout".to_string()
        }],
        remediation: "unused localized remediation".to_string(),
        references: if id == "docker.container_hardening" {
            vec!["https://docs.docker.com/engine/security/".to_string()]
        } else {
            Vec::new()
        },
        metadata: std::collections::HashMap::new(),
    }
}

#[cfg(test)]
fn test_checks() -> Vec<SecurityCheck> {
    REQUIRED_CHECK_IDS
        .iter()
        .map(|id| test_check(id, "PASS"))
        .collect()
}

#[cfg(test)]
struct TestCountingCollector {
    counter: Arc<std::sync::atomic::AtomicUsize>,
    delay: Duration,
}

#[cfg(test)]
struct TestDegradedThenFullCollector {
    counter: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(test)]
impl SecuritySnapshotCollector for TestCountingCollector {
    fn collect(&self) -> CollectorFuture<'_> {
        Box::pin(async move {
            self.counter
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            test_checks()
        })
    }
}

#[cfg(test)]
impl SecuritySnapshotCollector for TestDegradedThenFullCollector {
    fn collect(&self) -> CollectorFuture<'_> {
        Box::pin(async move {
            let call = self
                .counter
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut checks = test_checks();
            if call == 0
                && let Some(check) = checks.iter_mut().find(|check| check.id == "firewall.ufw")
            {
                *check = test_check("firewall.ufw", "WARN");
            }
            checks
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::future::join_all;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn delayed_service(counter: Arc<AtomicUsize>) -> Arc<SecuritySnapshotService> {
        SecuritySnapshotService::with_collector(
            Arc::new(TestCountingCollector {
                counter,
                delay: Duration::from_millis(40),
            }),
            Duration::ZERO,
            Duration::from_secs(300),
        )
    }

    #[tokio::test]
    async fn concurrent_zero_ttl_refreshes_are_single_flight() {
        let counter = Arc::new(AtomicUsize::new(0));
        let service = delayed_service(Arc::clone(&counter));
        let requests = (0..24).map(|_| {
            let service = Arc::clone(&service);
            async move {
                service
                    .get_or_refresh(Duration::ZERO)
                    .await
                    .expect("shared refresh should publish")
                    .identity()
            }
        });
        let identities = join_all(requests).await;

        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(identities.iter().all(|identity| *identity == identities[0]));

        let second = service
            .get_or_refresh(Duration::ZERO)
            .await
            .expect("sequential zero-TTL request should refresh");
        assert_eq!(counter.load(Ordering::SeqCst), 2);
        assert_eq!(second.identity().generation(), 2);
    }

    #[tokio::test]
    async fn language_projection_preserves_snapshot_identity_without_collection() {
        let counter = Arc::new(AtomicUsize::new(0));
        let service = SecuritySnapshotService::test_service(Arc::clone(&counter));
        let snapshot = service
            .get_or_refresh(Duration::ZERO)
            .await
            .expect("test snapshot should publish");
        let identity = snapshot.identity();
        let en = snapshot.project(&Lang::EN);
        let ru = snapshot.project(&Lang::RU);

        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(snapshot.identity(), identity);
        assert_eq!(en[0].id, ru[0].id);
        assert_ne!(en[0].name, ru[0].name);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn fail_and_warn_projection_matrix_preserves_machine_facts() {
        for (index, id) in REQUIRED_CHECK_IDS.iter().enumerate() {
            let status = if index % 2 == 0 { "WARN" } else { "FAIL" };
            let check = test_check(id, status);
            let fact = SecurityCheckFact::from_check(check)
                .expect("every required check must have a neutral projection");
            let en = fact.project(&Lang::EN);
            let ru = fact.project(&Lang::RU);

            assert_eq!(en.id, ru.id);
            assert_eq!(en.category, ru.category);
            assert_eq!(en.severity, ru.severity);
            assert_eq!(en.status, status);
            assert_eq!(en.status, ru.status);
            assert_eq!(en.evidence, ru.evidence);
            assert_eq!(en.metadata, ru.metadata);
            assert!(en.name != ru.name || en.message != ru.message);
        }
    }

    #[test]
    fn docker_risk_projection_uses_untruncated_stable_count_fact() {
        let mut check = test_check("docker.container_hardening", "FAIL");
        check.metadata.insert(
            "critical_risks".to_string(),
            (0..128).map(|value| format!("risk-{value}")).collect(),
        );
        check
            .metadata
            .insert("risk_count".to_string(), vec!["513".to_string()]);
        let fact = SecurityCheckFact::from_check(check)
            .expect("Docker risk facts should have a projection");

        for lang in [Lang::EN, Lang::RU] {
            let projected = fact.project(&lang);
            assert!(projected.message.ends_with(": 513"));
            assert_eq!(projected.metadata["risk_count"], vec!["513"]);
        }
    }

    #[tokio::test]
    async fn cancelled_consumer_does_not_cancel_owned_refresh() {
        let counter = Arc::new(AtomicUsize::new(0));
        let service = delayed_service(Arc::clone(&counter));
        let request_service = Arc::clone(&service);
        let request =
            tokio::spawn(async move { request_service.get_or_refresh(Duration::ZERO).await });

        while counter.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        request.abort();
        tokio::time::sleep(Duration::from_millis(80)).await;

        let published = service.latest().await.expect("owned refresh should finish");
        assert_eq!(published.identity().generation(), 1);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failed_refresh_deadline_never_returns_the_old_stale_snapshot() {
        struct NeverCollector;
        impl SecuritySnapshotCollector for NeverCollector {
            fn collect(&self) -> CollectorFuture<'_> {
                Box::pin(std::future::pending())
            }
        }

        let service = SecuritySnapshotService::with_collector_and_deadline(
            Arc::new(NeverCollector),
            Duration::ZERO,
            Duration::from_secs(300),
            Duration::from_millis(10),
        );
        service
            .publish_test_snapshot(Duration::from_secs(60), false)
            .await;
        let old_identity = service
            .latest()
            .await
            .expect("stale fixture should exist")
            .identity();

        let result = service.get_or_refresh(Duration::from_secs(1)).await;
        assert!(matches!(result, Err(SecuritySnapshotUnavailable)));
        assert_eq!(
            service
                .latest()
                .await
                .expect("old snapshot remains stored but not publishable")
                .identity(),
            old_identity
        );
    }

    #[tokio::test]
    async fn snapshot_is_bounded_and_empty_collection_is_degraded() {
        struct EmptyCollector;
        impl SecuritySnapshotCollector for EmptyCollector {
            fn collect(&self) -> CollectorFuture<'_> {
                Box::pin(async { Vec::new() })
            }
        }

        let service = SecuritySnapshotService::with_collector(
            Arc::new(EmptyCollector),
            Duration::ZERO,
            Duration::from_secs(300),
        );
        let snapshot = service
            .get_or_refresh(Duration::ZERO)
            .await
            .expect("degraded snapshot remains publishable");

        assert_eq!(
            snapshot.collection_status(),
            SecurityCollectionStatus::Degraded
        );
        assert!(snapshot.serialized_size() < SNAPSHOT_SIZE_LIMIT_BYTES);
        let checks = snapshot.project(&Lang::EN);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].status, "WARN");
    }

    #[tokio::test]
    async fn malformed_collection_pass_is_replaced_by_a_degraded_warning() {
        let service = SecuritySnapshotService::test_service(Arc::new(AtomicUsize::new(0)));
        let mut malformed = SecurityCheckFact::degraded("invalid_fixture").project(&Lang::EN);
        malformed.status = "PASS".to_string();

        service
            .publish_checks(vec![malformed], Instant::now())
            .await;
        let snapshot = service.latest().await.expect("snapshot should publish");
        let checks = snapshot.project(&Lang::EN);

        assert_eq!(
            snapshot.collection_status(),
            SecurityCollectionStatus::Degraded
        );
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].id, "audit.collection");
        assert_eq!(checks[0].status, "WARN");
        assert_eq!(checks[0].evidence, ["snapshot_error=incomplete_collection"]);
    }

    #[tokio::test]
    async fn oversized_snapshot_is_replaced_by_a_bounded_degraded_fact() {
        struct OversizedCollector;
        impl SecuritySnapshotCollector for OversizedCollector {
            fn collect(&self) -> CollectorFuture<'_> {
                Box::pin(async {
                    let mut checks = test_checks();
                    checks[0].metadata.insert(
                        "oversized_fixture".to_string(),
                        vec!["x".repeat(SNAPSHOT_SIZE_LIMIT_BYTES)],
                    );
                    checks
                })
            }
        }

        let service = SecuritySnapshotService::with_collector(
            Arc::new(OversizedCollector),
            Duration::ZERO,
            Duration::from_secs(300),
        );
        let snapshot = service
            .get_or_refresh(Duration::ZERO)
            .await
            .expect("bounded degraded snapshot should publish");

        assert_eq!(
            snapshot.collection_status(),
            SecurityCollectionStatus::Degraded
        );
        assert!(snapshot.serialized_size() < SNAPSHOT_SIZE_LIMIT_BYTES);
        let checks = snapshot.project(&Lang::EN);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].evidence, ["snapshot_error=size_limit"]);
    }

    #[tokio::test]
    async fn unknown_facts_are_retained_in_a_degraded_snapshot() {
        let counter = Arc::new(AtomicUsize::new(0));
        let service = SecuritySnapshotService::test_service(counter);
        service.publish_test_snapshot(Duration::ZERO, true).await;
        let snapshot = service.latest().await.expect("snapshot should publish");
        let checks = snapshot.project(&Lang::EN);

        assert_eq!(
            snapshot.collection_status(),
            SecurityCollectionStatus::Degraded
        );
        assert_eq!(checks.len(), REQUIRED_CHECK_IDS.len() + 1);
        assert!(checks.iter().any(|check| {
            check.status == "WARN"
                && check
                    .evidence
                    .iter()
                    .any(|fact| fact == "probe_error=timeout")
        }));
        assert!(checks.iter().any(|check| {
            check.id == "audit.collection"
                && check.status == "WARN"
                && check.evidence == ["snapshot_error=unknown_facts"]
        }));
    }

    #[tokio::test]
    async fn ssh_unknown_and_docker_unavailable_are_degraded_without_probe_error_prefix() {
        let mut fixtures = Vec::new();

        let mut ssh_unknown = test_checks();
        let ssh = ssh_unknown
            .iter_mut()
            .find(|check| check.id == "ssh.root_login")
            .expect("SSH root fixture should exist");
        ssh.status = "WARN".to_string();
        ssh.evidence = vec!["permitrootlogin=unknown".to_string()];
        fixtures.push(ssh_unknown);

        let mut docker_unavailable = test_checks();
        let docker = docker_unavailable
            .iter_mut()
            .find(|check| check.id == "docker.container_hardening")
            .expect("Docker fixture should exist");
        docker.status = "WARN".to_string();
        docker.evidence.clear();
        docker.references.clear();
        docker.metadata.clear();
        fixtures.push(docker_unavailable);

        for checks in fixtures {
            let service = SecuritySnapshotService::test_service(Arc::new(AtomicUsize::new(0)));
            service.publish_checks(checks, Instant::now()).await;
            let snapshot = service.latest().await.expect("snapshot should publish");
            let projected = snapshot.project(&Lang::EN);
            assert_eq!(
                snapshot.collection_status(),
                SecurityCollectionStatus::Degraded
            );
            assert_eq!(projected.len(), REQUIRED_CHECK_IDS.len() + 1);
            assert!(projected.iter().any(|check| check.id == "audit.collection"));
        }
    }

    #[tokio::test]
    async fn proven_known_warn_facts_remain_full() {
        let mut checks = test_checks();
        for check in &mut checks {
            match check.id.as_str() {
                "ssh.root_login" => {
                    check.status = "WARN".to_string();
                    check.evidence = vec!["permitrootlogin=prohibit-password".to_string()];
                }
                "system.disk_encryption" => {
                    check.status = "WARN".to_string();
                    check.evidence.clear();
                }
                "network.listening_ports" => {
                    check.status = "WARN".to_string();
                    check
                        .metadata
                        .insert("suspicious_ports".to_string(), vec!["5432".to_string()]);
                }
                "docker.tcp_api" => {
                    check.status = "WARN".to_string();
                    check.metadata.insert(
                        "loopback_listeners".to_string(),
                        vec!["tcp://127.0.0.1:2375".to_string()],
                    );
                }
                "docker.container_hardening" => {
                    check.status = "WARN".to_string();
                    check
                        .metadata
                        .insert("risk_count".to_string(), vec!["1".to_string()]);
                }
                _ => {}
            }
        }
        let service = SecuritySnapshotService::test_service(Arc::new(AtomicUsize::new(0)));
        service.publish_checks(checks, Instant::now()).await;
        let snapshot = service.latest().await.expect("snapshot should publish");

        assert_eq!(snapshot.collection_status(), SecurityCollectionStatus::Full);
        assert_eq!(snapshot.project(&Lang::EN).len(), REQUIRED_CHECK_IDS.len());
    }

    #[test]
    fn audit_interval_and_cache_ttl_parser_preserve_bounds() {
        assert_eq!(parse_duration_secs(None, 300, 60, 86_400).as_secs(), 300);
        assert_eq!(
            parse_duration_secs(Some("0"), 300, 60, 86_400).as_secs(),
            60
        );
        assert_eq!(
            parse_duration_secs(Some("99999"), 300, 60, 86_400).as_secs(),
            86_400
        );
        assert_eq!(parse_duration_secs(Some("0"), 30, 0, 3600).as_secs(), 0);
    }
}
