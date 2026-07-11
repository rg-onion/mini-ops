use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[path = "security_probe.rs"]
mod probe;

use probe::{
    AUDIT_COLLECTION_DEADLINE, CancellationReason, DEFAULT_PROBE_TIMEOUT, DOCKER_PROBE_TIMEOUT,
    Fact, OUTPUT_CAP_BYTES, ProbeCancellation, ProbeProgram, ProbeRunner, UnknownReason,
};

use crate::docker::DockerService;
use crate::i18n::Lang;
use crate::notifications::NotificationService;
use crate::security_events::SecurityEventService;

const AUDIT_SHUTDOWN_GRACE: Duration = Duration::from_secs(1);
const FILE_READ_SHUTDOWN_GRACE: Duration = Duration::from_millis(250);

#[derive(Serialize, Clone, Debug)]
pub struct SecurityCheck {
    pub id: String,
    pub name: String,
    pub category: String,
    pub severity: String,
    pub status: String, // "PASS", "FAIL", "WARN"
    pub message: String,
    pub evidence: Vec<String>,
    pub remediation: String,
    pub references: Vec<String>,
    pub metadata: HashMap<String, Vec<String>>,
}

impl SecurityCheck {
    fn new(
        id: &str,
        name: String,
        category: &str,
        severity: &str,
        status: &str,
        message: String,
        remediation: String,
    ) -> Self {
        Self {
            id: id.to_string(),
            name,
            category: category.to_string(),
            severity: severity.to_string(),
            status: status.to_string(),
            message,
            evidence: Vec::new(),
            remediation,
            references: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    fn with_evidence(mut self, evidence: Vec<String>) -> Self {
        self.evidence = bounded_strings(evidence, 4 * 1024, 128);
        self
    }

    fn with_references(mut self, references: Vec<&str>) -> Self {
        self.references = references.into_iter().map(str::to_string).collect();
        self
    }

    fn with_metadata(mut self, key: &str, values: Vec<String>) -> Self {
        self.metadata
            .insert(key.to_string(), bounded_strings(values, 4 * 1024, 128));
        self
    }
}

fn bounded_strings(values: Vec<String>, byte_cap: usize, item_cap: usize) -> Vec<String> {
    let mut remaining = byte_cap;
    values
        .into_iter()
        .take(item_cap)
        .filter_map(|value| {
            if remaining == 0 {
                return None;
            }
            let keep = value
                .char_indices()
                .map(|(index, _)| index)
                .chain(std::iter::once(value.len()))
                .take_while(|index| *index <= remaining)
                .last()
                .unwrap_or(0);
            remaining = remaining.saturating_sub(keep);
            Some(value[..keep].to_string())
        })
        .collect()
}

fn unknown_evidence(reason: UnknownReason) -> Vec<String> {
    vec![format!("probe_error={}", reason.code())]
}

fn filesystem_unknown_reason(error: &std::io::Error) -> UnknownReason {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => UnknownReason::PermissionDenied,
        _ => UnknownReason::IoError,
    }
}

async fn read_bounded_text_file(
    path: &'static str,
    cancellation: &ProbeCancellation,
) -> Result<String, UnknownReason> {
    let mut task = tokio::task::spawn_blocking(move || {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::PermissionDenied => UnknownReason::PermissionDenied,
                _ => UnknownReason::IoError,
            })?;
        if !file
            .metadata()
            .map_err(|_| UnknownReason::IoError)?
            .is_file()
        {
            return Err(UnknownReason::IoError);
        }
        let mut bytes = Vec::with_capacity(OUTPUT_CAP_BYTES.min(8192));
        file.take((OUTPUT_CAP_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| UnknownReason::IoError)?;
        if bytes.len() > OUTPUT_CAP_BYTES {
            return Err(UnknownReason::OutputTruncated);
        }
        String::from_utf8(bytes).map_err(|_| UnknownReason::MalformedOutput)
    });

    tokio::select! {
        biased;
        reason = cancellation.cancelled() => {
            let _ = tokio::time::timeout(FILE_READ_SHUTDOWN_GRACE, &mut task).await;
            Err(reason.unknown_reason())
        }
        _ = tokio::time::sleep(DEFAULT_PROBE_TIMEOUT) => {
            let _ = tokio::time::timeout(FILE_READ_SHUTDOWN_GRACE, &mut task).await;
            Err(UnknownReason::Timeout)
        }
        result = &mut task => {
            result.map_err(|_| UnknownReason::IoError)?
        }
    }
}

#[derive(Debug, Clone)]
struct SshdConfig {
    values: HashMap<String, String>,
    source: String,
    effective: bool,
    probe_error: Option<UnknownReason>,
}

impl SshdConfig {
    fn get(&self, key: &str) -> Option<&str> {
        self.values
            .get(&key.to_ascii_lowercase())
            .map(String::as_str)
    }
}

struct PortScanResult {
    check: SecurityCheck,
    open_ports: Fact<Vec<u16>>,
}

#[derive(Debug)]
struct ListeningSocket {
    protocol: String,
    address: String,
    port: u16,
    is_loopback: bool,
}

struct ListeningPortBaseline {
    allowed_public_ports: Vec<u16>,
    allowed_loopback_ports: Vec<u16>,
    invalid_token_count: usize,
}

pub struct SecurityAuditor;

#[derive(Clone)]
pub struct SecurityAuditCache {
    ttl: Duration,
    cached: Arc<Mutex<Option<CachedSecurityAudit>>>,
}

#[derive(Clone)]
struct CachedSecurityAudit {
    lang: Lang,
    created_at: Instant,
    checks: Vec<SecurityCheck>,
}

impl SecurityAuditCache {
    pub fn from_env() -> Self {
        Self {
            ttl: env_duration_secs("SECURITY_AUDIT_CACHE_TTL_SECS", 30, 0, 3600),
            cached: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn get_or_run(
        &self,
        lang: Lang,
        docker: Option<&DockerService>,
    ) -> Vec<SecurityCheck> {
        if self.ttl.as_secs() > 0 {
            let cached = self.cached.lock().await;
            if let Some(cached) = cached.as_ref()
                && cached.lang == lang
                && cached.created_at.elapsed() < self.ttl
            {
                return cached.checks.clone();
            }
        }

        let checks = SecurityAuditor::run_audit(&lang, docker).await;

        if self.ttl.as_secs() > 0 {
            let mut cached = self.cached.lock().await;
            *cached = Some(CachedSecurityAudit {
                lang,
                created_at: Instant::now(),
                checks: checks.clone(),
            });
        }

        checks
    }
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

impl SecurityAuditor {
    pub async fn run_audit(lang: &Lang, docker: Option<&DockerService>) -> Vec<SecurityCheck> {
        let cancellation = ProbeCancellation::new();
        let collection = Self::collect_audit(lang, docker, &cancellation);
        tokio::pin!(collection);
        let collection_window = AUDIT_COLLECTION_DEADLINE.saturating_sub(AUDIT_SHUTDOWN_GRACE);

        tokio::select! {
            checks = &mut collection => checks,
            _ = tokio::time::sleep(collection_window) => {
                cancellation.cancel(CancellationReason::AuditDeadlineExceeded);
                match tokio::time::timeout(AUDIT_SHUTDOWN_GRACE, &mut collection).await {
                    Ok(checks) => checks,
                    Err(_) => vec![Self::deadline_exceeded_check(lang)],
                }
            }
        }
    }

    fn deadline_exceeded_check(lang: &Lang) -> SecurityCheck {
        SecurityCheck::new(
            "audit.collection",
            crate::i18n::t("audit.collection.name", lang),
            "system",
            "high",
            "WARN",
            crate::i18n::t("audit.collection.error", lang),
            crate::i18n::t("audit.collection.remediation", lang),
        )
        .with_evidence(unknown_evidence(UnknownReason::AuditDeadlineExceeded))
    }

    async fn collect_audit(
        lang: &Lang,
        docker: Option<&DockerService>,
        cancellation: &ProbeCancellation,
    ) -> Vec<SecurityCheck> {
        let mut checks = Vec::new();
        let (
            sshd_config,
            ufw,
            docker_socket,
            disk_encryption,
            fail2ban,
            port_scan,
            docker_containers,
        ) = tokio::join!(
            Self::load_effective_sshd_config(cancellation),
            Self::check_ufw_status(lang, cancellation),
            Self::check_docker_socket(lang),
            Self::check_disk_encryption(lang, cancellation),
            Self::check_fail2ban_status(lang, cancellation),
            Self::check_listening_ports(lang, cancellation),
            Self::check_docker_container_risks(lang, docker, cancellation),
        );

        checks.push(Self::check_ssh_root_login(lang, sshd_config.as_ref()));
        checks.push(Self::check_ssh_password_auth(lang, sshd_config.as_ref()));
        checks.push(ufw);
        checks.push(docker_socket);
        checks.push(disk_encryption);
        checks.push(fail2ban);
        let open_ports = port_scan.open_ports.clone();
        checks.push(port_scan.check);
        checks.push(Self::check_docker_tcp_api_ports(lang, &open_ports));
        checks.push(docker_containers);

        checks
    }

    pub fn calculate_score(checks: &[SecurityCheck]) -> u32 {
        let total_weight: u32 = checks.iter().map(Self::severity_weight).sum();
        if total_weight == 0 {
            return 100;
        }

        let earned: u32 = checks
            .iter()
            .map(|check| {
                let weight = Self::severity_weight(check);
                match check.status.as_str() {
                    "PASS" => weight,
                    "WARN" => weight / 2,
                    "FAIL" => 0,
                    _ => weight / 2,
                }
            })
            .sum();

        ((earned * 100) / total_weight).min(100)
    }

    pub fn extract_open_ports(checks: &[SecurityCheck]) -> Vec<u16> {
        let mut ports = checks
            .iter()
            .find(|check| check.id == "network.listening_ports")
            .and_then(|check| check.metadata.get("open_ports"))
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|port| port.parse::<u16>().ok())
            .collect::<Vec<_>>();

        ports.sort_unstable();
        ports.dedup();
        ports
    }

    fn severity_weight(check: &SecurityCheck) -> u32 {
        match check.severity.as_str() {
            "critical" => 35,
            "high" => 25,
            "medium" => 15,
            "low" => 8,
            _ => 3,
        }
    }

    async fn load_effective_sshd_config(
        cancellation: &ProbeCancellation,
    ) -> Result<SshdConfig, UnknownReason> {
        let outcome = ProbeRunner::run(
            ProbeProgram::Sshd,
            &["-T"],
            DEFAULT_PROBE_TIMEOUT,
            cancellation,
        )
        .await;

        match outcome.parse_stdout(|stdout| {
            let config = Self::parse_sshd_config_output(stdout, "sshd -T");
            if config.values.is_empty() {
                Err(UnknownReason::MalformedOutput)
            } else {
                Ok(config)
            }
        }) {
            Fact::Known(config) => Ok(config),
            Fact::Unknown(probe_error) => {
                let content = read_bounded_text_file("/etc/ssh/sshd_config", cancellation).await?;
                let mut config = Self::parse_sshd_config_output(&content, "/etc/ssh/sshd_config");
                if config.values.is_empty() {
                    return Err(UnknownReason::MalformedOutput);
                }
                config.effective = false;
                config.probe_error = Some(probe_error);
                Ok(config)
            }
        }
    }

    fn parse_sshd_config_output(content: &str, source: &str) -> SshdConfig {
        let mut values = HashMap::new();

        for line in content.lines() {
            let clean = line.split('#').next().unwrap_or("").trim();
            if clean.is_empty() {
                continue;
            }

            let mut parts = clean.split_whitespace();
            if let Some(key) = parts.next() {
                let value = parts.collect::<Vec<_>>().join(" ");
                if !value.is_empty() {
                    values.entry(key.to_ascii_lowercase()).or_insert(value);
                }
            }
        }

        SshdConfig {
            values,
            source: source.to_string(),
            effective: true,
            probe_error: None,
        }
    }

    fn check_ssh_root_login(
        lang: &Lang,
        sshd_config: Result<&SshdConfig, &UnknownReason>,
    ) -> SecurityCheck {
        let name = crate::i18n::t("audit.ssh_root.name", lang);
        let remediation = crate::i18n::t("audit.ssh_root.remediation", lang);

        let config = match sshd_config {
            Ok(config) => config,
            Err(e) => {
                return SecurityCheck::new(
                    "ssh.root_login",
                    name,
                    "ssh",
                    "medium",
                    "WARN",
                    crate::i18n::t("audit.ssh_config.warn", lang),
                    remediation,
                )
                .with_evidence(unknown_evidence(*e));
            }
        };

        if !config.effective {
            return SecurityCheck::new(
                "ssh.root_login",
                name,
                "ssh",
                "medium",
                "WARN",
                crate::i18n::t("audit.ssh_config.warn", lang),
                remediation,
            )
            .with_evidence(unknown_evidence(
                config.probe_error.unwrap_or(UnknownReason::MalformedOutput),
            ));
        }

        let value = config.get("permitrootlogin").unwrap_or("unknown");
        let evidence = vec![
            format!("source={}", config.source),
            format!("permitrootlogin={}", value),
        ];

        match value {
            "no" => SecurityCheck::new(
                "ssh.root_login",
                name,
                "ssh",
                "medium",
                "PASS",
                crate::i18n::t("audit.ssh_root.pass", lang),
                remediation,
            )
            .with_evidence(evidence),
            "yes" => SecurityCheck::new(
                "ssh.root_login",
                name,
                "ssh",
                "high",
                "FAIL",
                crate::i18n::t("audit.ssh_root.fail", lang),
                remediation,
            )
            .with_evidence(evidence),
            "prohibit-password" | "without-password" | "forced-commands-only" => {
                SecurityCheck::new(
                    "ssh.root_login",
                    name,
                    "ssh",
                    "medium",
                    "WARN",
                    crate::i18n::t("audit.ssh_root.warn_restricted", lang),
                    remediation,
                )
                .with_evidence(evidence)
            }
            _ => SecurityCheck::new(
                "ssh.root_login",
                name,
                "ssh",
                "medium",
                "WARN",
                crate::i18n::t("audit.ssh_root.warn_unknown", lang),
                remediation,
            )
            .with_evidence(evidence),
        }
    }

    fn check_ssh_password_auth(
        lang: &Lang,
        sshd_config: Result<&SshdConfig, &UnknownReason>,
    ) -> SecurityCheck {
        let name = crate::i18n::t("audit.ssh_passwd.name", lang);
        let remediation = crate::i18n::t("audit.ssh_passwd.remediation", lang);

        let config = match sshd_config {
            Ok(config) => config,
            Err(e) => {
                return SecurityCheck::new(
                    "ssh.password_auth",
                    name,
                    "ssh",
                    "high",
                    "WARN",
                    crate::i18n::t("audit.ssh_config.warn", lang),
                    remediation,
                )
                .with_evidence(unknown_evidence(*e));
            }
        };

        if !config.effective {
            return SecurityCheck::new(
                "ssh.password_auth",
                name,
                "ssh",
                "high",
                "WARN",
                crate::i18n::t("audit.ssh_config.warn", lang),
                remediation,
            )
            .with_evidence(unknown_evidence(
                config.probe_error.unwrap_or(UnknownReason::MalformedOutput),
            ));
        }

        let value = config.get("passwordauthentication").unwrap_or("unknown");
        let evidence = vec![
            format!("source={}", config.source),
            format!("passwordauthentication={}", value),
        ];

        if value == "no" {
            SecurityCheck::new(
                "ssh.password_auth",
                name,
                "ssh",
                "high",
                "PASS",
                crate::i18n::t("audit.ssh_passwd.pass", lang),
                remediation,
            )
            .with_evidence(evidence)
        } else {
            SecurityCheck::new(
                "ssh.password_auth",
                name,
                "ssh",
                "high",
                "FAIL",
                crate::i18n::t("audit.ssh_passwd.fail", lang),
                remediation,
            )
            .with_evidence(evidence)
        }
    }

    async fn check_ufw_status(lang: &Lang, cancellation: &ProbeCancellation) -> SecurityCheck {
        let name = crate::i18n::t("audit.ufw.name", lang);
        let remediation = crate::i18n::t("audit.ufw.remediation", lang);
        let outcome = ProbeRunner::run(
            ProbeProgram::Ufw,
            &["status"],
            DEFAULT_PROBE_TIMEOUT,
            cancellation,
        )
        .await;
        let active = outcome.parse_stdout(|stdout| {
            if stdout.lines().any(|line| line.trim() == "Status: active") {
                Ok(true)
            } else if stdout.lines().any(|line| line.trim() == "Status: inactive") {
                Ok(false)
            } else {
                Err(UnknownReason::MalformedOutput)
            }
        });

        match active {
            Fact::Known(true) => SecurityCheck::new(
                "firewall.ufw",
                name,
                "firewall",
                "high",
                "PASS",
                crate::i18n::t("audit.ufw.pass", lang),
                remediation,
            )
            .with_evidence(vec!["ufw_status=active".to_string()]),
            Fact::Known(false) => SecurityCheck::new(
                "firewall.ufw",
                name,
                "firewall",
                "high",
                "FAIL",
                crate::i18n::t("audit.ufw.fail", lang),
                remediation,
            )
            .with_evidence(vec!["ufw_status=inactive".to_string()]),
            Fact::Unknown(reason) => SecurityCheck::new(
                "firewall.ufw",
                name,
                "firewall",
                "high",
                "WARN",
                crate::i18n::t("audit.ufw.error", lang),
                remediation,
            )
            .with_evidence(unknown_evidence(reason)),
        }
    }

    async fn check_docker_socket(lang: &Lang) -> SecurityCheck {
        let name = crate::i18n::t("audit.docker_sock.name", lang);
        let remediation = crate::i18n::t("audit.docker_sock.remediation", lang);
        let path = "/var/run/docker.sock";

        match tokio::fs::metadata(path).await {
            Ok(metadata) => {
                let mode = metadata.permissions().mode() & 0o777;
                let evidence = vec![format!("path={} mode={:o}", path, mode)];

                if mode & 0o002 != 0 {
                    return SecurityCheck::new(
                        "docker.socket_permissions",
                        name,
                        "docker",
                        "critical",
                        "FAIL",
                        crate::i18n::t("audit.docker_sock.fail", lang),
                        remediation,
                    )
                    .with_evidence(evidence);
                }

                SecurityCheck::new(
                    "docker.socket_permissions",
                    name,
                    "docker",
                    "critical",
                    "PASS",
                    crate::i18n::t("audit.docker_sock.pass", lang),
                    remediation,
                )
                .with_evidence(evidence)
            }
            Err(error) => SecurityCheck::new(
                "docker.socket_permissions",
                name,
                "docker",
                "low",
                "WARN",
                crate::i18n::t("audit.docker_sock.warn", lang),
                remediation,
            )
            .with_evidence(unknown_evidence(filesystem_unknown_reason(&error))),
        }
    }

    async fn check_disk_encryption(lang: &Lang, cancellation: &ProbeCancellation) -> SecurityCheck {
        let name = crate::i18n::t("audit.disk_enc.name", lang);
        let remediation = crate::i18n::t("audit.disk_enc.remediation", lang);
        let outcome = ProbeRunner::run(
            ProbeProgram::Lsblk,
            &["-o", "TYPE"],
            DEFAULT_PROBE_TIMEOUT,
            cancellation,
        )
        .await;
        let encrypted = outcome.parse_stdout(|stdout| {
            let mut lines = stdout
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty());
            if lines.next() != Some("TYPE") {
                return Err(UnknownReason::MalformedOutput);
            }
            Ok(lines.any(|line| line == "crypt"))
        });

        match encrypted {
            Fact::Known(true) => SecurityCheck::new(
                "system.disk_encryption",
                name,
                "system",
                "low",
                "PASS",
                crate::i18n::t("audit.disk_enc.pass", lang),
                remediation,
            )
            .with_evidence(vec!["lsblk_type=crypt".to_string()]),
            Fact::Known(false) => SecurityCheck::new(
                "system.disk_encryption",
                name,
                "system",
                "low",
                "WARN",
                crate::i18n::t("audit.disk_enc.warn", lang),
                remediation,
            ),
            Fact::Unknown(reason) => SecurityCheck::new(
                "system.disk_encryption",
                name,
                "system",
                "low",
                "WARN",
                crate::i18n::t("audit.disk_enc.error", lang),
                remediation,
            )
            .with_evidence(unknown_evidence(reason)),
        }
    }

    async fn check_fail2ban_status(lang: &Lang, cancellation: &ProbeCancellation) -> SecurityCheck {
        let name = crate::i18n::t("audit.fail2ban.name", lang);
        let remediation = crate::i18n::t("audit.fail2ban.remediation", lang);
        let outcome = ProbeRunner::run(
            ProbeProgram::Systemctl,
            &["is-active", "fail2ban"],
            DEFAULT_PROBE_TIMEOUT,
            cancellation,
        )
        .await;
        let active = outcome.parse_stdout(|stdout| {
            if stdout.trim() == "active" {
                Ok(())
            } else {
                Err(UnknownReason::MalformedOutput)
            }
        });

        match active {
            Fact::Known(()) => SecurityCheck::new(
                "intrusion.fail2ban",
                name,
                "intrusion",
                "medium",
                "PASS",
                crate::i18n::t("audit.fail2ban.pass", lang),
                remediation,
            )
            .with_evidence(vec!["systemctl is-active fail2ban=active".to_string()]),
            Fact::Unknown(reason) => SecurityCheck::new(
                "intrusion.fail2ban",
                name,
                "intrusion",
                "medium",
                "WARN",
                crate::i18n::t("audit.fail2ban.warn", lang),
                remediation,
            )
            .with_evidence(unknown_evidence(reason)),
        }
    }

    async fn check_listening_ports(
        lang: &Lang,
        cancellation: &ProbeCancellation,
    ) -> PortScanResult {
        let name = crate::i18n::t("audit.ports.name", lang);
        let remediation = crate::i18n::t("audit.ports.remediation", lang);
        let outcome = ProbeRunner::run(
            ProbeProgram::Ss,
            &["-H", "-tuln"],
            DEFAULT_PROBE_TIMEOUT,
            cancellation,
        )
        .await;
        let sockets = outcome.parse_stdout(Self::parse_listening_sockets);

        match sockets {
            Fact::Known(mut listening_sockets) => {
                listening_sockets.sort_by(|a, b| {
                    a.port
                        .cmp(&b.port)
                        .then_with(|| a.protocol.cmp(&b.protocol))
                        .then_with(|| a.address.cmp(&b.address))
                });

                let mut open_ports = listening_sockets
                    .iter()
                    .map(|socket| socket.port)
                    .collect::<Vec<_>>();
                open_ports.sort_unstable();
                open_ports.dedup();

                let nginx_port = std::env::var("DEPLOY_NGINX_PORT")
                    .ok()
                    .and_then(|port| port.parse::<u16>().ok())
                    .unwrap_or(8090);
                let app_port = std::env::var("APP_PORT")
                    .ok()
                    .and_then(|port| port.parse::<u16>().ok())
                    .unwrap_or(3000);
                let baseline = Self::listening_port_baseline(
                    app_port,
                    nginx_port,
                    std::env::var("SECURITY_ALLOWED_PUBLIC_PORTS")
                        .ok()
                        .as_deref(),
                    std::env::var("SECURITY_ALLOWED_LOOPBACK_PORTS")
                        .ok()
                        .as_deref(),
                );

                let mut unexpected_listeners = listening_sockets
                    .iter()
                    .filter(|socket| {
                        if baseline.allowed_public_ports.contains(&socket.port) {
                            return false;
                        }
                        !(socket.is_loopback
                            && baseline.allowed_loopback_ports.contains(&socket.port))
                    })
                    .map(Self::format_listening_socket)
                    .collect::<Vec<_>>();
                unexpected_listeners.sort();
                unexpected_listeners.dedup();

                let mut suspicious = listening_sockets
                    .iter()
                    .filter(|socket| {
                        if baseline.allowed_public_ports.contains(&socket.port) {
                            return false;
                        }
                        !(socket.is_loopback
                            && baseline.allowed_loopback_ports.contains(&socket.port))
                    })
                    .map(|socket| socket.port)
                    .collect::<Vec<_>>();
                suspicious.sort_unstable();
                suspicious.dedup();

                let open_port_strings = open_ports.iter().map(u16::to_string).collect::<Vec<_>>();
                let suspicious_strings = suspicious.iter().map(u16::to_string).collect::<Vec<_>>();
                let allowed_public_port_strings = baseline
                    .allowed_public_ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>();
                let allowed_loopback_port_strings = baseline
                    .allowed_loopback_ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>();

                let mut check = if suspicious.is_empty() {
                    SecurityCheck::new(
                        "network.listening_ports",
                        name,
                        "network",
                        "medium",
                        "PASS",
                        crate::i18n::t("audit.ports.pass", lang),
                        remediation,
                    )
                } else {
                    SecurityCheck::new(
                        "network.listening_ports",
                        name,
                        "network",
                        "medium",
                        "WARN",
                        format!(
                            "{}: {}",
                            crate::i18n::t("audit.ports.warn", lang),
                            suspicious_strings.join(", ")
                        ),
                        remediation,
                    )
                    .with_metadata("suspicious_ports", suspicious_strings)
                    .with_metadata("unexpected_listeners", unexpected_listeners)
                }
                .with_metadata("open_ports", open_port_strings)
                .with_metadata("allowed_public_ports", allowed_public_port_strings)
                .with_metadata("allowed_loopback_ports", allowed_loopback_port_strings);

                if baseline.invalid_token_count > 0 {
                    if check.status == "PASS" {
                        check.status = "WARN".to_string();
                        check.message = crate::i18n::t("audit.ports.config_error", lang);
                    }
                    check = check
                        .with_metadata(
                            "invalid_allowed_port_count",
                            vec![baseline.invalid_token_count.to_string()],
                        )
                        .with_evidence(vec![
                            "config_error=invalid_allowed_port".to_string(),
                            format!(
                                "invalid_allowed_port_count={}",
                                baseline.invalid_token_count
                            ),
                        ]);
                }

                PortScanResult {
                    check,
                    open_ports: Fact::Known(open_ports),
                }
            }
            Fact::Unknown(reason) => PortScanResult {
                check: SecurityCheck::new(
                    "network.listening_ports",
                    name,
                    "network",
                    "medium",
                    "WARN",
                    crate::i18n::t("audit.ports.error", lang),
                    remediation,
                )
                .with_evidence(unknown_evidence(reason)),
                open_ports: Fact::Unknown(reason),
            },
        }
    }

    fn listening_port_baseline(
        app_port: u16,
        nginx_port: u16,
        extra_public_ports: Option<&str>,
        extra_loopback_ports: Option<&str>,
    ) -> ListeningPortBaseline {
        let mut invalid_token_count = 0_usize;
        let mut allowed_public_ports = vec![22, 80, 443, nginx_port];
        let mut allowed_loopback_ports = vec![app_port];

        Self::extend_ports_from_env(
            &mut allowed_public_ports,
            &mut invalid_token_count,
            extra_public_ports,
        );
        Self::extend_ports_from_env(
            &mut allowed_loopback_ports,
            &mut invalid_token_count,
            extra_loopback_ports,
        );

        allowed_public_ports.sort_unstable();
        allowed_public_ports.dedup();
        allowed_loopback_ports.sort_unstable();
        allowed_loopback_ports.dedup();
        ListeningPortBaseline {
            allowed_public_ports,
            allowed_loopback_ports,
            invalid_token_count,
        }
    }

    fn extend_ports_from_env(
        ports: &mut Vec<u16>,
        invalid_token_count: &mut usize,
        value: Option<&str>,
    ) {
        for token in value
            .unwrap_or_default()
            .split(|c: char| c == ',' || c == ';' || c.is_ascii_whitespace())
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            match token.parse::<u16>() {
                Ok(port) => ports.push(port),
                Err(_) => *invalid_token_count = invalid_token_count.saturating_add(1),
            }
        }
    }

    fn parse_listening_sockets(ss_output: &str) -> Result<Vec<ListeningSocket>, UnknownReason> {
        let mut sockets = Vec::new();
        for line in ss_output
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            let mut parts = line.split_whitespace();
            let protocol = parts
                .next()
                .filter(|value| !value.is_empty())
                .ok_or(UnknownReason::MalformedOutput)?;
            let state = parts.next().ok_or(UnknownReason::MalformedOutput)?;
            if state != "LISTEN" && state != "UNCONN" {
                return Err(UnknownReason::MalformedOutput);
            }
            let _receive_queue = parts.next().ok_or(UnknownReason::MalformedOutput)?;
            let _send_queue = parts.next().ok_or(UnknownReason::MalformedOutput)?;
            let local_address = parts.next().ok_or(UnknownReason::MalformedOutput)?;
            let (address, port) =
                Self::parse_local_address(local_address).ok_or(UnknownReason::MalformedOutput)?;
            sockets.push(ListeningSocket {
                protocol: protocol.to_string(),
                is_loopback: Self::is_loopback_address(&address),
                address,
                port,
            });
        }

        if sockets.is_empty() {
            Err(UnknownReason::MalformedOutput)
        } else {
            Ok(sockets)
        }
    }

    fn parse_local_address(local_address: &str) -> Option<(String, u16)> {
        if let Some(rest) = local_address.strip_prefix('[') {
            let (address, rest) = rest.split_once(']')?;
            let port = rest.strip_prefix(':')?.parse::<u16>().ok()?;
            return Some((address.to_string(), port));
        }

        let (address, port) = local_address.rsplit_once(':')?;
        Some((address.to_string(), port.parse::<u16>().ok()?))
    }

    fn is_loopback_address(address: &str) -> bool {
        let address = address
            .trim_matches(['[', ']'])
            .split('%')
            .next()
            .unwrap_or(address);

        address == "localhost" || address == "::1" || address.starts_with("127.")
    }

    fn format_listening_socket(socket: &ListeningSocket) -> String {
        format!("{}://{}:{}", socket.protocol, socket.address, socket.port)
    }

    fn check_docker_tcp_api_ports(lang: &Lang, open_ports: &Fact<Vec<u16>>) -> SecurityCheck {
        let name = crate::i18n::t("audit.docker_api.name", lang);
        let remediation = crate::i18n::t("audit.docker_api.remediation", lang);
        let open_ports = match open_ports {
            Fact::Known(open_ports) => open_ports,
            Fact::Unknown(reason) => {
                return SecurityCheck::new(
                    "docker.tcp_api",
                    name,
                    "docker",
                    "critical",
                    "WARN",
                    crate::i18n::t("audit.ports.error", lang),
                    remediation,
                )
                .with_evidence(unknown_evidence(*reason));
            }
        };
        let exposed = open_ports
            .iter()
            .copied()
            .filter(|port| *port == 2375 || *port == 2376)
            .collect::<Vec<_>>();
        if exposed.is_empty() {
            SecurityCheck::new(
                "docker.tcp_api",
                name,
                "docker",
                "critical",
                "PASS",
                crate::i18n::t("audit.docker_api.pass", lang),
                remediation,
            )
        } else {
            SecurityCheck::new(
                "docker.tcp_api",
                name,
                "docker",
                if exposed.contains(&2375) {
                    "critical"
                } else {
                    "high"
                },
                "FAIL",
                format!(
                    "{}: {}",
                    crate::i18n::t("audit.docker_api.fail", lang),
                    exposed
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                remediation,
            )
            .with_evidence(
                exposed
                    .iter()
                    .map(|port| format!("docker_api_port={}", port))
                    .collect(),
            )
        }
    }

    async fn check_docker_container_risks(
        lang: &Lang,
        docker: Option<&DockerService>,
        cancellation: &ProbeCancellation,
    ) -> SecurityCheck {
        let name = crate::i18n::t("audit.docker_containers.name", lang);
        let remediation = crate::i18n::t("audit.docker_containers.remediation", lang);

        let Some(docker) = docker else {
            let socket = tokio::fs::metadata("/var/run/docker.sock").await;
            let (status, message, evidence) = match socket {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (
                    "PASS",
                    crate::i18n::t("audit.docker_containers.no_runtime", lang),
                    Vec::new(),
                ),
                Ok(_) => (
                    "WARN",
                    crate::i18n::t("audit.docker_containers.unavailable", lang),
                    Vec::new(),
                ),
                Err(error) => (
                    "WARN",
                    crate::i18n::t("audit.docker_containers.error", lang),
                    unknown_evidence(filesystem_unknown_reason(&error)),
                ),
            };

            return SecurityCheck::new(
                "docker.container_hardening",
                name,
                "docker",
                "high",
                status,
                message,
                remediation,
            )
            .with_evidence(evidence);
        };

        let docker_timeout = env_duration_secs(
            "SECURITY_AUDIT_DOCKER_TIMEOUT_SECS",
            DOCKER_PROBE_TIMEOUT.as_secs(),
            1,
            DOCKER_PROBE_TIMEOUT.as_secs(),
        );
        enum DockerAuditResult<T> {
            Completed(T),
            TimedOut,
            Cancelled(UnknownReason),
        }
        let audit_result = tokio::select! {
            result = tokio::time::timeout(docker_timeout, docker.audit_security_risks()) => {
                match result {
                    Ok(result) => DockerAuditResult::Completed(result),
                    Err(_) => DockerAuditResult::TimedOut,
                }
            }
            reason = cancellation.cancelled() => {
                DockerAuditResult::Cancelled(match reason {
                    CancellationReason::Cancelled => UnknownReason::Cancelled,
                    CancellationReason::AuditDeadlineExceeded => UnknownReason::AuditDeadlineExceeded,
                })
            }
        };

        match audit_result {
            DockerAuditResult::TimedOut => SecurityCheck::new(
                "docker.container_hardening",
                name,
                "docker",
                "high",
                "WARN",
                crate::i18n::t("audit.docker_containers.timeout", lang),
                remediation,
            )
            .with_evidence(unknown_evidence(UnknownReason::Timeout)),
            DockerAuditResult::Cancelled(reason) => SecurityCheck::new(
                "docker.container_hardening",
                name,
                "docker",
                "high",
                "WARN",
                crate::i18n::t("audit.docker_containers.error", lang),
                remediation,
            )
            .with_evidence(unknown_evidence(reason)),
            DockerAuditResult::Completed(Ok(risks)) if risks.is_empty() => SecurityCheck::new(
                "docker.container_hardening",
                name,
                "docker",
                "high",
                "PASS",
                crate::i18n::t("audit.docker_containers.pass", lang),
                remediation,
            )
            .with_references(vec!["https://docs.docker.com/engine/security/"]),
            DockerAuditResult::Completed(Ok(risks)) => {
                let has_critical = risks.iter().any(|risk| risk.severity == "critical");
                let has_high = risks.iter().any(|risk| risk.severity == "high");
                let severity = if has_critical {
                    "critical"
                } else if has_high {
                    "high"
                } else {
                    "medium"
                };
                let status = if has_critical || has_high {
                    "FAIL"
                } else {
                    "WARN"
                };
                let evidence = risks
                    .iter()
                    .take(128)
                    .map(|risk| format!("{}: {}", risk.finding, risk.evidence))
                    .collect::<Vec<_>>();

                let mut by_severity: HashMap<String, Vec<String>> = HashMap::new();
                for risk in risks.iter().take(128) {
                    by_severity
                        .entry(risk.severity.clone())
                        .or_default()
                        .push(risk.finding.clone());
                }

                let mut check = SecurityCheck::new(
                    "docker.container_hardening",
                    name,
                    "docker",
                    severity,
                    status,
                    format!(
                        "{}: {}",
                        crate::i18n::t("audit.docker_containers.fail", lang),
                        risks.len()
                    ),
                    remediation,
                )
                .with_evidence(evidence)
                .with_references(vec!["https://docs.docker.com/engine/security/"]);

                for (severity, values) in by_severity {
                    check = check.with_metadata(&format!("{}_risks", severity), values);
                }

                check
            }
            DockerAuditResult::Completed(Err(_)) => SecurityCheck::new(
                "docker.container_hardening",
                name,
                "docker",
                "high",
                "WARN",
                crate::i18n::t("audit.docker_containers.error", lang),
                remediation,
            )
            .with_evidence(unknown_evidence(UnknownReason::IoError)),
        }
    }
}

pub struct SecurityMonitor {
    notifier: Arc<NotificationService>,
    docker: Option<Arc<DockerService>>,
    events: Arc<SecurityEventService>,
    interval: Duration,
}

impl SecurityMonitor {
    pub fn new(
        notifier: Arc<NotificationService>,
        docker: Option<Arc<DockerService>>,
        events: Arc<SecurityEventService>,
    ) -> Self {
        Self {
            notifier,
            docker,
            events,
            interval: env_duration_secs("SECURITY_AUDIT_INTERVAL_SECS", 300, 60, 86_400),
        }
    }

    pub async fn run_loop(self: Arc<Self>) {
        tracing::info!(
            "Starting Security Monitor Loop with interval={}s",
            self.interval.as_secs()
        );
        let mut interval = tokio::time::interval(self.interval);

        loop {
            interval.tick().await;
            self.check_once().await;
        }
    }

    async fn check_once(&self) {
        let default_lang = Lang::from_headers(&crate::i18n::HeaderMap::new());
        let checks = SecurityAuditor::run_audit(&default_lang, self.docker.as_deref()).await;

        let mut alerts = Vec::new();
        for check in &checks {
            if check.status == "FAIL" {
                match self.events.raise_audit_event(check).await {
                    Ok(true) => alerts.push(format!(
                        "{}\n\n{}: {}\n{}: {}",
                        crate::i18n::t("security.detected", &default_lang),
                        crate::i18n::t("security.check", &default_lang),
                        check.name,
                        crate::i18n::t("security.message", &default_lang),
                        check.message
                    )),
                    Ok(false) => {}
                    Err(e) => tracing::warn!(
                        "Failed to persist security event for check {}: {}",
                        check.id,
                        e
                    ),
                }
            } else if check.status == "WARN" {
                if let Err(e) = self.events.raise_audit_event(check).await {
                    tracing::warn!(
                        "Failed to persist warning security event for check {}: {}",
                        check.id,
                        e
                    );
                }
            } else if check.status == "PASS" {
                match self.events.resolve_audit_event(check).await {
                    Ok(true) => alerts.push(format!(
                        "{}\n\n{}: {}",
                        crate::i18n::t("security.resolved", &default_lang),
                        crate::i18n::t("security.check", &default_lang),
                        check.name
                    )),
                    Ok(false) => {}
                    Err(e) => tracing::warn!(
                        "Failed to resolve security event for check {}: {}",
                        check.id,
                        e
                    ),
                }
            }
        }

        if let Err(e) = self.events.cleanup_if_due().await {
            tracing::warn!("Failed to clean up old security events: {}", e);
        }

        for alert in alerts {
            self.notifier.send_alert(&alert).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sshd_config_output_normalizes_keys() {
        let config = SecurityAuditor::parse_sshd_config_output(
            "PermitRootLogin prohibit-password\nPermitRootLogin yes\nPasswordAuthentication no\n# ignored yes\n",
            "test",
        );

        assert_eq!(config.get("permitrootlogin"), Some("prohibit-password"));
        assert_eq!(config.get("PasswordAuthentication"), Some("no"));
        assert_eq!(config.get("ignored"), None);
    }

    #[test]
    fn test_parse_listening_sockets_extracts_ports() {
        let output = "\
tcp LISTEN 0 4096 127.0.0.1:3000 0.0.0.0:*
tcp LISTEN 0 128 [::]:22 [::]:*
udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*
";

        let mut ports = SecurityAuditor::parse_listening_sockets(output)
            .expect("valid ss output")
            .into_iter()
            .map(|socket| socket.port)
            .collect::<Vec<_>>();
        ports.sort_unstable();
        assert_eq!(ports, vec![22, 3000, 5353]);
    }

    #[test]
    fn test_listening_port_baseline_adds_extra_ports_and_dedupes() {
        let baseline = SecurityAuditor::listening_port_baseline(
            3000,
            8090,
            Some("81;82\n22"),
            Some("53, 9001,3000"),
        );

        assert_eq!(
            baseline.allowed_public_ports,
            vec![22, 80, 81, 82, 443, 8090]
        );
        assert_eq!(baseline.allowed_loopback_ports, vec![53, 3000, 9001]);
        assert_eq!(baseline.invalid_token_count, 0);
    }

    #[test]
    fn test_listening_port_baseline_counts_invalid_tokens_without_storing_values() {
        let baseline = SecurityAuditor::listening_port_baseline(
            3000,
            8090,
            Some("5435,bad"),
            Some("70000,bad"),
        );

        assert_eq!(baseline.allowed_public_ports, vec![22, 80, 443, 5435, 8090]);
        assert_eq!(baseline.allowed_loopback_ports, vec![3000]);
        assert_eq!(baseline.invalid_token_count, 3);
    }

    #[test]
    fn test_parse_listening_sockets_marks_loopback() {
        let output = "\
tcp LISTEN 0 4096 127.0.0.1:3000 0.0.0.0:*
tcp LISTEN 0 4096 0.0.0.0:5435 0.0.0.0:*
tcp LISTEN 0 128 [::1]:9001 [::]:*
";

        let sockets = SecurityAuditor::parse_listening_sockets(output).expect("valid ss output");
        let loopback_ports = sockets
            .iter()
            .filter(|socket| socket.is_loopback)
            .map(|socket| socket.port)
            .collect::<Vec<_>>();
        let public_ports = sockets
            .iter()
            .filter(|socket| !socket.is_loopback)
            .map(|socket| socket.port)
            .collect::<Vec<_>>();

        assert_eq!(loopback_ports, vec![3000, 9001]);
        assert_eq!(public_ports, vec![5435]);
    }

    #[test]
    fn test_parse_listening_sockets_rejects_mixed_malformed_output() {
        let output = "\
tcp LISTEN 0 4096 127.0.0.1:3000 0.0.0.0:*
this line is not valid ss output
";

        assert_eq!(
            SecurityAuditor::parse_listening_sockets(output)
                .expect_err("mixed malformed output must remain unknown"),
            UnknownReason::MalformedOutput
        );
    }

    #[test]
    fn test_unknown_port_fact_keeps_dependent_docker_check_unknown() {
        let lang = Lang::EN;
        let check = SecurityAuditor::check_docker_tcp_api_ports(
            &lang,
            &Fact::Unknown(UnknownReason::Timeout),
        );

        assert_eq!(check.status, "WARN");
        assert_eq!(check.evidence, vec!["probe_error=timeout"]);
    }

    #[test]
    fn test_evidence_and_metadata_are_bounded() {
        let check = SecurityCheck::new(
            "bounded",
            "bounded".to_string(),
            "test",
            "low",
            "WARN",
            "bounded".to_string(),
            "bounded".to_string(),
        )
        .with_evidence(vec!["x".repeat(8 * 1024)])
        .with_metadata("items", (0..256).map(|value| value.to_string()).collect());

        assert!(check.evidence.iter().map(String::len).sum::<usize>() <= 4 * 1024);
        assert_eq!(check.metadata["items"].len(), 128);
    }

    #[test]
    fn test_calculate_score_weights_failures_by_severity() {
        let checks = vec![
            SecurityCheck::new(
                "critical.fail",
                "critical".to_string(),
                "test",
                "critical",
                "FAIL",
                "failed".to_string(),
                "fix".to_string(),
            ),
            SecurityCheck::new(
                "low.pass",
                "low".to_string(),
                "test",
                "low",
                "PASS",
                "passed".to_string(),
                "fix".to_string(),
            ),
        ];

        assert_eq!(SecurityAuditor::calculate_score(&checks), 18);
    }

    #[test]
    fn test_parse_duration_secs_uses_default_and_clamps_bounds() {
        assert_eq!(parse_duration_secs(None, 30, 0, 120).as_secs(), 30);
        assert_eq!(
            parse_duration_secs(Some("not-a-number"), 30, 0, 120).as_secs(),
            30
        );
        assert_eq!(parse_duration_secs(Some("0"), 30, 5, 120).as_secs(), 5);
        assert_eq!(parse_duration_secs(Some("999"), 30, 5, 120).as_secs(), 120);
        assert_eq!(parse_duration_secs(Some("60"), 30, 5, 120).as_secs(), 60);
    }
}
