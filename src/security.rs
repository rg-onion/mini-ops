use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[path = "security_probe.rs"]
mod probe;

use probe::{
    AUDIT_COLLECTION_DEADLINE, CancellationReason, DEFAULT_PROBE_TIMEOUT, DOCKER_PROBE_TIMEOUT,
    Fact, OUTPUT_CAP_BYTES, ProbeCancellation, ProbeProgram, ProbeRunner, UnknownReason,
};

use crate::docker::{DockerSecurityIncompleteReason, DockerSecurityRisk, DockerService};
use crate::i18n::Lang;
use crate::notifications::{NotificationOutbox, NotificationService};
use crate::security_events::SecurityEventService;
use crate::security_snapshot::{
    SecurityCollectionStatus, SecuritySnapshotIdentity, SecuritySnapshotService,
};

const AUDIT_SHUTDOWN_GRACE: Duration = Duration::from_secs(1);
const FILE_READ_SHUTDOWN_GRACE: Duration = Duration::from_millis(250);
const MONITOR_SNAPSHOT_MAX_AGE: Duration = Duration::ZERO;
// `sshd -T` needs concrete connection contexts to evaluate `Match` blocks.
// Reserved non-loopback addresses deliberately avoid treating localhost-only
// exceptions as representative remote SSH state. Root-login and ordinary-user
// password checks must not share a root-only context.
const SSHD_ROOT_EVALUATION_CONTEXT: &str =
    "user=root,host=security-audit.invalid,addr=198.51.100.10,laddr=192.0.2.10,lport=22";
const SSHD_PASSWORD_EVALUATION_CONTEXT: &str =
    "user=nobody,host=security-audit.invalid,addr=198.51.100.10,laddr=192.0.2.10,lport=22";
const SSHD_EFFECTIVE_SOURCE: &str = "sshd -T -C";

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

fn docker_socket_facts(metadata: &fs::Metadata) -> Result<(u32, u32, u32), UnknownReason> {
    if !metadata.file_type().is_socket() {
        return Err(UnknownReason::MalformedOutput);
    }

    Ok((
        metadata.permissions().mode() & 0o777,
        metadata.uid(),
        metadata.gid(),
    ))
}

fn docker_audit_severity_status(
    risks: &[DockerSecurityRisk],
    has_incomplete_facts: bool,
) -> (&'static str, &'static str) {
    let has_critical = risks.iter().any(|risk| risk.severity == "critical");
    let has_high = risks.iter().any(|risk| risk.severity == "high");
    if has_critical {
        ("critical", "FAIL")
    } else if has_high {
        ("high", "FAIL")
    } else if has_incomplete_facts {
        ("high", "WARN")
    } else {
        ("medium", "WARN")
    }
}

fn docker_audit_evidence(
    risks: &[DockerSecurityRisk],
    incomplete_reasons: &[DockerSecurityIncompleteReason],
) -> Vec<String> {
    let mut evidence = incomplete_reasons
        .iter()
        .map(|reason| format!("docker_audit_incomplete={}", reason.code()))
        .collect::<Vec<_>>();
    let risk_evidence_limit = 128usize.saturating_sub(evidence.len());
    evidence.extend(
        risks
            .iter()
            .take(risk_evidence_limit)
            .map(|risk| format!("{}: {}", risk.finding, risk.evidence)),
    );
    evidence
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
    evaluation_context: Option<String>,
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
    listeners: Fact<Vec<ListeningSocket>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ListenerScope {
    Loopback,
    Wildcard,
    NonLoopback,
}

impl ListenerScope {
    const fn code(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Wildcard => "wildcard",
            Self::NonLoopback => "non_loopback",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ListeningSocket {
    protocol: String,
    address: String,
    port: u16,
    scope: ListenerScope,
}

impl ListeningSocket {
    fn is_loopback(&self) -> bool {
        self.scope == ListenerScope::Loopback
    }

    fn is_externally_reachable(&self) -> bool {
        self.scope != ListenerScope::Loopback
    }
}

#[derive(Debug, Deserialize)]
struct LsblkOutput {
    blockdevices: Vec<LsblkDevice>,
}

#[derive(Debug, Deserialize)]
struct LsblkDevice {
    name: String,
    #[serde(rename = "type")]
    device_type: String,
    mountpoints: Option<Vec<Option<String>>>,
    #[serde(default)]
    children: Vec<LsblkDevice>,
}

struct ListeningPortBaseline {
    allowed_public_ports: Vec<u16>,
    allowed_loopback_ports: Vec<u16>,
    invalid_token_count: usize,
}

pub struct SecurityAuditor;

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
            sshd_root_config,
            sshd_password_config,
            ufw,
            docker_socket,
            disk_encryption,
            fail2ban,
            port_scan,
            docker_containers,
        ) = tokio::join!(
            Self::load_effective_sshd_config(SSHD_ROOT_EVALUATION_CONTEXT, cancellation),
            Self::load_effective_sshd_config(SSHD_PASSWORD_EVALUATION_CONTEXT, cancellation),
            Self::check_ufw_status(lang, cancellation),
            Self::check_docker_socket(lang),
            Self::check_disk_encryption(lang, cancellation),
            Self::check_fail2ban_status(lang, cancellation),
            Self::check_listening_ports(lang, cancellation),
            Self::check_docker_container_risks(lang, docker, cancellation),
        );

        checks.push(Self::check_ssh_root_login(lang, sshd_root_config.as_ref()));
        checks.push(Self::check_ssh_password_auth(
            lang,
            sshd_password_config.as_ref(),
        ));
        checks.push(ufw);
        checks.push(docker_socket);
        checks.push(disk_encryption);
        checks.push(fail2ban);
        let listeners = port_scan.listeners.clone();
        checks.push(port_scan.check);
        checks.push(Self::check_docker_tcp_api_ports(lang, &listeners));
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
        evaluation_context: &'static str,
        cancellation: &ProbeCancellation,
    ) -> Result<SshdConfig, UnknownReason> {
        let outcome = ProbeRunner::run(
            ProbeProgram::Sshd,
            &["-T", "-C", evaluation_context],
            DEFAULT_PROBE_TIMEOUT,
            cancellation,
        )
        .await;

        match outcome.parse_stdout(|stdout| {
            Self::parse_effective_sshd_config_output(stdout, evaluation_context)
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
            evaluation_context: None,
            effective: false,
            probe_error: None,
        }
    }

    fn parse_effective_sshd_config_output(
        content: &str,
        evaluation_context: &str,
    ) -> Result<SshdConfig, UnknownReason> {
        const REQUIRED_KEYS: [&str; 4] = [
            "permitrootlogin",
            "passwordauthentication",
            "kbdinteractiveauthentication",
            "usepam",
        ];

        let mut values = HashMap::new();
        let mut required_key_counts = HashMap::new();

        for line in content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            let mut parts = line.split_whitespace();
            let key = parts
                .next()
                .filter(|key| {
                    key.chars()
                        .all(|character| character.is_ascii_alphanumeric())
                })
                .ok_or(UnknownReason::MalformedOutput)?
                .to_ascii_lowercase();
            let value = parts.collect::<Vec<_>>().join(" ");
            if value.is_empty() {
                return Err(UnknownReason::MalformedOutput);
            }

            if REQUIRED_KEYS.contains(&key.as_str()) {
                let count = required_key_counts.entry(key.clone()).or_insert(0_usize);
                *count = count.saturating_add(1);
                if *count > 1 {
                    return Err(UnknownReason::MalformedOutput);
                }
            }
            values.entry(key).or_insert(value);
        }

        if values.is_empty()
            || REQUIRED_KEYS
                .iter()
                .any(|key| required_key_counts.get(*key) != Some(&1))
        {
            return Err(UnknownReason::MalformedOutput);
        }

        let permit_root_login = values
            .get("permitrootlogin")
            .map(|value| value.to_ascii_lowercase())
            .ok_or(UnknownReason::MalformedOutput)?;
        if !matches!(
            permit_root_login.as_str(),
            "yes" | "no" | "prohibit-password" | "without-password" | "forced-commands-only"
        ) {
            return Err(UnknownReason::MalformedOutput);
        }
        for key in [
            "passwordauthentication",
            "kbdinteractiveauthentication",
            "usepam",
        ] {
            if !matches!(
                values.get(key).map(|value| value.to_ascii_lowercase()),
                Some(value) if value == "yes" || value == "no"
            ) {
                return Err(UnknownReason::MalformedOutput);
            }
        }

        Ok(SshdConfig {
            values,
            source: SSHD_EFFECTIVE_SOURCE.to_string(),
            evaluation_context: Some(evaluation_context.to_string()),
            effective: true,
            probe_error: None,
        })
    }

    fn sshd_config_evidence(config: &SshdConfig) -> Vec<String> {
        let mut evidence = vec![format!("source={}", config.source)];
        if let Some(context) = config.evaluation_context.as_deref() {
            evidence.push(format!("evaluation_context={context}"));
        }
        evidence
    }

    fn fallback_sshd_evidence(config: &SshdConfig) -> Vec<String> {
        let mut evidence = Self::sshd_config_evidence(config);
        evidence.push("effective_config=false".to_string());
        evidence.extend(unknown_evidence(
            config.probe_error.unwrap_or(UnknownReason::MalformedOutput),
        ));
        evidence
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
            .with_evidence(Self::fallback_sshd_evidence(config));
        }

        let value = config.get("permitrootlogin").unwrap_or("unknown");
        let mut evidence = Self::sshd_config_evidence(config);
        evidence.push(format!("permitrootlogin={value}"));

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
            .with_evidence(Self::fallback_sshd_evidence(config));
        }

        let password_authentication = config.get("passwordauthentication").unwrap_or("unknown");
        let keyboard_interactive = config
            .get("kbdinteractiveauthentication")
            .unwrap_or("unknown");
        let use_pam = config.get("usepam").unwrap_or("unknown");
        let mut evidence = Self::sshd_config_evidence(config);
        evidence.extend([
            format!("passwordauthentication={password_authentication}"),
            format!("kbdinteractiveauthentication={keyboard_interactive}"),
            format!("usepam={use_pam}"),
        ]);

        if !matches!(password_authentication, "yes" | "no")
            || !matches!(keyboard_interactive, "yes" | "no")
            || !matches!(use_pam, "yes" | "no")
        {
            return SecurityCheck::new(
                "ssh.password_auth",
                name,
                "ssh",
                "high",
                "WARN",
                crate::i18n::t("audit.ssh_config.warn", lang),
                remediation,
            )
            .with_evidence(evidence);
        }

        if password_authentication == "no" && keyboard_interactive == "no" {
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
        let active = outcome.parse_stdout(Self::parse_ufw_status_output);

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

    fn parse_ufw_status_output(stdout: &str) -> Result<bool, UnknownReason> {
        let mut active_count = 0usize;
        let mut inactive_count = 0usize;
        for line in stdout.lines().map(str::trim) {
            match line {
                "Status: active" => active_count = active_count.saturating_add(1),
                "Status: inactive" => inactive_count = inactive_count.saturating_add(1),
                line if line
                    .get(.."Status:".len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("Status:")) =>
                {
                    return Err(UnknownReason::MalformedOutput);
                }
                _ => {}
            }
        }
        match (active_count, inactive_count) {
            (1, 0) => Ok(true),
            (0, 1) => Ok(false),
            _ => Err(UnknownReason::MalformedOutput),
        }
    }

    async fn check_docker_socket(lang: &Lang) -> SecurityCheck {
        let name = crate::i18n::t("audit.docker_sock.name", lang);
        let remediation = crate::i18n::t("audit.docker_sock.remediation", lang);
        let path = "/var/run/docker.sock";

        match tokio::fs::symlink_metadata(path).await {
            Ok(metadata) => match docker_socket_facts(&metadata) {
                Ok((mode, uid, gid)) => {
                    let evidence = vec![format!(
                        "path={} mode={:o} uid={} gid={}",
                        path, mode, uid, gid
                    )];

                    if mode & 0o002 != 0 || uid != 0 {
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
                Err(reason) => SecurityCheck::new(
                    "docker.socket_permissions",
                    name,
                    "docker",
                    "low",
                    "WARN",
                    crate::i18n::t("audit.docker_sock.warn", lang),
                    remediation,
                )
                .with_evidence(unknown_evidence(reason)),
            },
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
            &["--json", "--tree", "--output", "NAME,TYPE,MOUNTPOINTS"],
            DEFAULT_PROBE_TIMEOUT,
            cancellation,
        )
        .await;
        let encrypted = outcome.parse_stdout(Self::parse_root_backing_encryption);

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
            .with_evidence(vec!["root_backing_chain=encrypted".to_string()]),
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

    fn parse_root_backing_encryption(stdout: &str) -> Result<bool, UnknownReason> {
        let output = serde_json::from_str::<LsblkOutput>(stdout)
            .map_err(|_| UnknownReason::MalformedOutput)?;
        if output.blockdevices.is_empty() {
            return Err(UnknownReason::MalformedOutput);
        }

        let mut root_mounts = Vec::new();
        for device in &output.blockdevices {
            Self::collect_root_mount_encryption(device, false, &mut root_mounts)?;
        }

        match root_mounts.as_slice() {
            [encrypted] => Ok(*encrypted),
            _ => Err(UnknownReason::MalformedOutput),
        }
    }

    fn collect_root_mount_encryption(
        device: &LsblkDevice,
        encrypted_ancestor: bool,
        root_mounts: &mut Vec<bool>,
    ) -> Result<(), UnknownReason> {
        if device.name.trim().is_empty() || device.device_type.trim().is_empty() {
            return Err(UnknownReason::MalformedOutput);
        }

        let encrypted = encrypted_ancestor || device.device_type == "crypt";
        if device.mountpoints.as_ref().is_some_and(|mountpoints| {
            mountpoints
                .iter()
                .any(|mountpoint| mountpoint.as_deref() == Some("/"))
        }) {
            root_mounts.push(encrypted);
        }

        for child in &device.children {
            Self::collect_root_mount_encryption(child, encrypted, root_mounts)?;
        }
        Ok(())
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
                        .then_with(|| a.scope.code().cmp(b.scope.code()))
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
                        !(socket.is_loopback()
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
                        !(socket.is_loopback()
                            && baseline.allowed_loopback_ports.contains(&socket.port))
                    })
                    .map(|socket| socket.port)
                    .collect::<Vec<_>>();
                suspicious.sort_unstable();
                suspicious.dedup();

                let open_port_strings = open_ports.iter().map(u16::to_string).collect::<Vec<_>>();
                let suspicious_strings = suspicious.iter().map(u16::to_string).collect::<Vec<_>>();
                let listener_strings = listening_sockets
                    .iter()
                    .map(Self::format_listening_socket)
                    .collect::<Vec<_>>();
                let loopback_listener_strings = listening_sockets
                    .iter()
                    .filter(|socket| socket.is_loopback())
                    .map(Self::format_listening_socket)
                    .collect::<Vec<_>>();
                let non_loopback_listener_strings = listening_sockets
                    .iter()
                    .filter(|socket| socket.is_externally_reachable())
                    .map(Self::format_listening_socket)
                    .collect::<Vec<_>>();
                let wildcard_listener_strings = listening_sockets
                    .iter()
                    .filter(|socket| socket.scope == ListenerScope::Wildcard)
                    .map(Self::format_listening_socket)
                    .collect::<Vec<_>>();
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
                .with_metadata("listeners", listener_strings)
                .with_metadata("loopback_listeners", loopback_listener_strings)
                .with_metadata("non_loopback_listeners", non_loopback_listener_strings)
                .with_metadata("wildcard_listeners", wildcard_listener_strings)
                .with_metadata("allowed_public_ports", allowed_public_port_strings)
                .with_metadata("allowed_loopback_ports", allowed_loopback_port_strings);

                check = Self::apply_invalid_allowed_port_warning(
                    lang,
                    check,
                    baseline.invalid_token_count,
                );

                PortScanResult {
                    check,
                    listeners: Fact::Known(listening_sockets),
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
                listeners: Fact::Unknown(reason),
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
                Ok(port) if port != 0 => ports.push(port),
                Err(_) => *invalid_token_count = invalid_token_count.saturating_add(1),
                Ok(_) => *invalid_token_count = invalid_token_count.saturating_add(1),
            }
        }
    }

    fn apply_invalid_allowed_port_warning(
        lang: &Lang,
        mut check: SecurityCheck,
        invalid_token_count: usize,
    ) -> SecurityCheck {
        if invalid_token_count == 0 {
            return check;
        }
        if check.status == "PASS" {
            check.status = "WARN".to_string();
            check.message = crate::i18n::t("audit.ports.config_error", lang);
        }
        check
            .with_metadata(
                "invalid_allowed_port_count",
                vec![invalid_token_count.to_string()],
            )
            .with_evidence(vec![
                "config_error=invalid_allowed_port".to_string(),
                format!("invalid_allowed_port_count={invalid_token_count}"),
            ])
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
                .filter(|value| matches!(*value, "tcp" | "udp"))
                .ok_or(UnknownReason::MalformedOutput)?;
            let state = parts.next().ok_or(UnknownReason::MalformedOutput)?;
            let valid_state = (protocol == "tcp" && state == "LISTEN")
                || (protocol == "udp" && matches!(state, "UNCONN" | "LISTEN"));
            if !valid_state {
                return Err(UnknownReason::MalformedOutput);
            }
            parts
                .next()
                .and_then(|queue| queue.parse::<u64>().ok())
                .ok_or(UnknownReason::MalformedOutput)?;
            parts
                .next()
                .and_then(|queue| queue.parse::<u64>().ok())
                .ok_or(UnknownReason::MalformedOutput)?;
            let local_address = parts.next().ok_or(UnknownReason::MalformedOutput)?;
            parts
                .next()
                .filter(|peer_address| !peer_address.is_empty())
                .ok_or(UnknownReason::MalformedOutput)?;
            let (address, port) =
                Self::parse_local_address(local_address).ok_or(UnknownReason::MalformedOutput)?;
            let scope =
                Self::classify_listener_scope(&address).ok_or(UnknownReason::MalformedOutput)?;
            sockets.push(ListeningSocket {
                protocol: protocol.to_string(),
                address,
                port,
                scope,
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

    fn classify_listener_scope(address: &str) -> Option<ListenerScope> {
        let address = address.trim_matches(['[', ']']);
        if address == "*" {
            return Some(ListenerScope::Wildcard);
        }

        let address_without_zone = address.split('%').next()?;
        match address_without_zone.parse::<IpAddr>().ok()? {
            IpAddr::V4(address) if address.is_unspecified() => Some(ListenerScope::Wildcard),
            IpAddr::V6(address) if address.is_unspecified() => Some(ListenerScope::Wildcard),
            IpAddr::V4(address) if address.is_loopback() => Some(ListenerScope::Loopback),
            IpAddr::V6(address)
                if address.is_loopback()
                    || address
                        .to_ipv4_mapped()
                        .is_some_and(|mapped| mapped.is_loopback()) =>
            {
                Some(ListenerScope::Loopback)
            }
            _ => Some(ListenerScope::NonLoopback),
        }
    }

    fn format_listening_socket(socket: &ListeningSocket) -> String {
        let address = if socket.address.contains(':') {
            format!("[{}]", socket.address)
        } else {
            socket.address.clone()
        };
        format!("{}://{}:{}", socket.protocol, address, socket.port)
    }

    fn check_docker_tcp_api_ports(
        lang: &Lang,
        listeners: &Fact<Vec<ListeningSocket>>,
    ) -> SecurityCheck {
        let name = crate::i18n::t("audit.docker_api.name", lang);
        let remediation = crate::i18n::t("audit.docker_api.remediation", lang);
        let listeners = match listeners {
            Fact::Known(listeners) => listeners,
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

        let docker_listeners = listeners
            .iter()
            .filter(|listener| listener.protocol == "tcp" && matches!(listener.port, 2375 | 2376))
            .collect::<Vec<_>>();
        let public_listeners = docker_listeners
            .iter()
            .copied()
            .filter(|listener| listener.is_externally_reachable())
            .collect::<Vec<_>>();
        let loopback_listeners = docker_listeners
            .iter()
            .copied()
            .filter(|listener| listener.is_loopback())
            .collect::<Vec<_>>();

        if docker_listeners.is_empty() {
            SecurityCheck::new(
                "docker.tcp_api",
                name,
                "docker",
                "critical",
                "PASS",
                crate::i18n::t("audit.docker_api.pass", lang),
                remediation,
            )
        } else if public_listeners.is_empty() {
            let listener_strings = loopback_listeners
                .iter()
                .map(|listener| Self::format_listening_socket(listener))
                .collect::<Vec<_>>();
            SecurityCheck::new(
                "docker.tcp_api",
                name,
                "docker",
                "medium",
                "WARN",
                crate::i18n::t("audit.docker_api.fail", lang),
                remediation,
            )
            .with_evidence(
                loopback_listeners
                    .iter()
                    .map(|listener| {
                        format!(
                            "docker_api_listener={} scope={}",
                            Self::format_listening_socket(listener),
                            listener.scope.code()
                        )
                    })
                    .collect(),
            )
            .with_metadata("loopback_listeners", listener_strings)
        } else {
            let public_listener_strings = public_listeners
                .iter()
                .map(|listener| Self::format_listening_socket(listener))
                .collect::<Vec<_>>();
            let loopback_listener_strings = loopback_listeners
                .iter()
                .map(|listener| Self::format_listening_socket(listener))
                .collect::<Vec<_>>();
            let mut exposed_ports = public_listeners
                .iter()
                .map(|listener| listener.port)
                .collect::<Vec<_>>();
            exposed_ports.sort_unstable();
            exposed_ports.dedup();

            SecurityCheck::new(
                "docker.tcp_api",
                name,
                "docker",
                if exposed_ports.contains(&2375) {
                    "critical"
                } else {
                    "high"
                },
                "FAIL",
                format!(
                    "{}: {}",
                    crate::i18n::t("audit.docker_api.fail", lang),
                    exposed_ports
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                remediation,
            )
            .with_evidence(
                public_listeners
                    .iter()
                    .map(|listener| {
                        format!(
                            "docker_api_port={} listener={} scope={}",
                            listener.port,
                            Self::format_listening_socket(listener),
                            listener.scope.code()
                        )
                    })
                    .collect(),
            )
            .with_metadata("public_listeners", public_listener_strings)
            .with_metadata("loopback_listeners", loopback_listener_strings)
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
            Cancelled(UnknownReason),
        }
        let audit_result = tokio::select! {
            result = docker.audit_security_risks(docker_timeout) => DockerAuditResult::Completed(result),
            reason = cancellation.cancelled() => {
                DockerAuditResult::Cancelled(match reason {
                    CancellationReason::Cancelled => UnknownReason::Cancelled,
                    CancellationReason::AuditDeadlineExceeded => UnknownReason::AuditDeadlineExceeded,
                })
            }
        };

        match audit_result {
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
            DockerAuditResult::Completed(outcome)
                if outcome.risks.is_empty() && outcome.incomplete_reasons.is_empty() =>
            {
                SecurityCheck::new(
                    "docker.container_hardening",
                    name,
                    "docker",
                    "high",
                    "PASS",
                    crate::i18n::t("audit.docker_containers.pass", lang),
                    remediation,
                )
                .with_references(vec!["https://docs.docker.com/engine/security/"])
            }
            DockerAuditResult::Completed(outcome) => {
                let risks = outcome.risks;
                let mut incomplete_reasons = outcome.incomplete_reasons;
                incomplete_reasons.sort_by_key(|reason| reason.code());
                let (severity, status) =
                    docker_audit_severity_status(&risks, !incomplete_reasons.is_empty());
                let evidence = docker_audit_evidence(&risks, &incomplete_reasons);

                let mut by_severity: HashMap<String, Vec<String>> = HashMap::new();
                for risk in risks.iter().take(128) {
                    by_severity
                        .entry(risk.severity.clone())
                        .or_default()
                        .push(risk.finding.clone());
                }

                let message = if risks.is_empty() {
                    crate::i18n::t("audit.docker_containers.error", lang)
                } else {
                    format!(
                        "{}: {}",
                        crate::i18n::t("audit.docker_containers.fail", lang),
                        risks.len()
                    )
                };
                let mut check = SecurityCheck::new(
                    "docker.container_hardening",
                    name,
                    "docker",
                    severity,
                    status,
                    message,
                    remediation,
                )
                .with_evidence(evidence)
                .with_references(vec!["https://docs.docker.com/engine/security/"])
                .with_metadata("risk_count", vec![risks.len().to_string()]);

                for (severity, values) in by_severity {
                    check = check.with_metadata(&format!("{}_risks", severity), values);
                }

                check
            }
        }
    }
}

pub struct SecurityMonitor {
    notifier: Arc<NotificationService>,
    outbox: Arc<NotificationOutbox>,
    snapshots: Arc<SecuritySnapshotService>,
    events: Arc<SecurityEventService>,
    interval: Duration,
    processed_snapshots: SnapshotIdentityTracker,
}

#[derive(Default)]
struct SnapshotIdentityTracker {
    last_processed: Mutex<Option<SecuritySnapshotIdentity>>,
}

impl SnapshotIdentityTracker {
    async fn claim(&self, identity: SecuritySnapshotIdentity) -> bool {
        let mut last_processed = self.last_processed.lock().await;
        if last_processed.as_ref() == Some(&identity) {
            return false;
        }
        *last_processed = Some(identity);
        true
    }
}

impl SecurityMonitor {
    pub fn new(
        notifier: Arc<NotificationService>,
        outbox: Arc<NotificationOutbox>,
        snapshots: Arc<SecuritySnapshotService>,
        events: Arc<SecurityEventService>,
    ) -> Self {
        let interval = snapshots.audit_interval();
        Self {
            notifier,
            outbox,
            snapshots,
            events,
            interval,
            processed_snapshots: SnapshotIdentityTracker::default(),
        }
    }

    pub async fn run_loop(self: Arc<Self>) {
        tracing::info!(
            "Starting Security Monitor Loop with interval={}s",
            self.interval.as_secs()
        );
        let mut interval = security_monitor_interval(self.interval);

        loop {
            interval.tick().await;
            self.check_once().await;
        }
    }

    async fn check_once(&self) {
        let default_lang = Lang::from_headers(&crate::i18n::HeaderMap::new());
        let snapshot = match self
            .snapshots
            .get_or_refresh(MONITOR_SNAPSHOT_MAX_AGE)
            .await
        {
            Ok(snapshot) => snapshot,
            Err(_) => {
                tracing::warn!(
                    snapshot_error = "unavailable",
                    "Security monitor skipped audit transitions"
                );
                return;
            }
        };
        let identity = snapshot.identity();
        if !self.processed_snapshots.claim(identity).await {
            return;
        }
        if snapshot.collection_status() == SecurityCollectionStatus::Full {
            let collection_check = SecurityCheck::new(
                "audit.collection",
                crate::i18n::t("audit.collection.name", &default_lang),
                "system",
                "high",
                "PASS",
                crate::i18n::t("security.resolved", &default_lang),
                crate::i18n::t("audit.collection.remediation", &default_lang),
            );
            let recovery_text = self.notifier.render_alert_text(&format!(
                "{}\n\n{}: {}",
                crate::i18n::t("security.resolved", &default_lang),
                crate::i18n::t("security.check", &default_lang),
                collection_check.name
            ));
            if self
                .events
                .resolve_audit_event_with_notification(
                    &collection_check,
                    &self.outbox,
                    &recovery_text,
                )
                .await
                .is_err()
            {
                tracing::warn!(
                    event_error = "database",
                    check_id = "audit.collection",
                    "Failed to resolve recovered collection event"
                );
            }
        }
        let checks = snapshot.project(&default_lang);

        for check in &checks {
            if check.status == "FAIL" {
                let alert = self.notifier.render_alert_text(&format!(
                    "{}\n\n{}: {}\n{}: {}",
                    crate::i18n::t("security.detected", &default_lang),
                    crate::i18n::t("security.check", &default_lang),
                    check.name,
                    crate::i18n::t("security.message", &default_lang),
                    check.message
                ));
                if self
                    .events
                    .raise_audit_event_with_notification(check, &self.outbox, &alert)
                    .await
                    .is_err()
                {
                    tracing::warn!(
                        event_error = "database",
                        check_id = %check.id,
                        "Failed to persist security event and notification"
                    );
                }
            } else if check.status == "WARN" {
                if self.events.raise_audit_event(check).await.is_err() {
                    tracing::warn!(
                        event_error = "database",
                        check_id = %check.id,
                        "Failed to persist warning security event"
                    );
                }
            } else if check.status == "PASS" {
                let alert = self.notifier.render_alert_text(&format!(
                    "{}\n\n{}: {}",
                    crate::i18n::t("security.resolved", &default_lang),
                    crate::i18n::t("security.check", &default_lang),
                    check.name
                ));
                if self
                    .events
                    .resolve_audit_event_with_notification(check, &self.outbox, &alert)
                    .await
                    .is_err()
                {
                    tracing::warn!(
                        event_error = "database",
                        check_id = %check.id,
                        "Failed to resolve security event and notification"
                    );
                }
            }
        }

        if self.events.cleanup_if_due().await.is_err() {
            tracing::warn!(
                event_error = "database",
                "Failed to clean up old security events"
            );
        }
    }
}

fn security_monitor_interval(period: Duration) -> tokio::time::Interval {
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval
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

    fn effective_sshd_fixture(
        permit_root_login: &str,
        password_authentication: &str,
        keyboard_interactive_authentication: &str,
        use_pam: &str,
    ) -> String {
        format!(
            "permitrootlogin {permit_root_login}\n\
             passwordauthentication {password_authentication}\n\
             kbdinteractiveauthentication {keyboard_interactive_authentication}\n\
             usepam {use_pam}\n\
             port 22\n"
        )
    }

    #[test]
    fn test_effective_sshd_config_requires_complete_valid_bounded_facts() {
        let complete = effective_sshd_fixture("no", "no", "no", "yes");
        let root_config = SecurityAuditor::parse_effective_sshd_config_output(
            &complete,
            SSHD_ROOT_EVALUATION_CONTEXT,
        )
        .expect("complete root-context sshd -T facts should parse");
        let password_config = SecurityAuditor::parse_effective_sshd_config_output(
            &complete,
            SSHD_PASSWORD_EVALUATION_CONTEXT,
        )
        .expect("complete password-context sshd -T facts should parse");

        assert!(root_config.effective);
        assert_eq!(root_config.source, SSHD_EFFECTIVE_SOURCE);
        assert_eq!(
            root_config.evaluation_context.as_deref(),
            Some(SSHD_ROOT_EVALUATION_CONTEXT)
        );
        assert_eq!(
            SecurityAuditor::check_ssh_root_login(&Lang::EN, Ok(&root_config)).status,
            "PASS"
        );
        let password_check =
            SecurityAuditor::check_ssh_password_auth(&Lang::EN, Ok(&password_config));
        assert_eq!(password_check.status, "PASS");
        assert!(password_check.evidence.iter().any(|value| {
            value == &format!("evaluation_context={SSHD_PASSWORD_EVALUATION_CONTEXT}")
        }));
        assert!(!SSHD_ROOT_EVALUATION_CONTEXT.contains("laddr=127."));
        assert!(!SSHD_PASSWORD_EVALUATION_CONTEXT.contains("laddr=127."));

        let missing_pam =
            "permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\n";
        assert_eq!(
            SecurityAuditor::parse_effective_sshd_config_output(
                missing_pam,
                SSHD_ROOT_EVALUATION_CONTEXT,
            )
            .expect_err("incomplete effective output must remain unknown"),
            UnknownReason::MalformedOutput
        );
        let duplicate = format!("{complete}passwordauthentication no\n");
        assert_eq!(
            SecurityAuditor::parse_effective_sshd_config_output(
                &duplicate,
                SSHD_ROOT_EVALUATION_CONTEXT,
            )
            .expect_err("ambiguous effective output must remain unknown"),
            UnknownReason::MalformedOutput
        );
    }

    #[test]
    fn test_password_check_does_not_reuse_root_only_match_context() {
        let root_exception = effective_sshd_fixture("no", "no", "no", "yes");
        let ordinary_user = effective_sshd_fixture("no", "yes", "yes", "yes");
        let root_config = SecurityAuditor::parse_effective_sshd_config_output(
            &root_exception,
            SSHD_ROOT_EVALUATION_CONTEXT,
        )
        .expect("root-only effective config should parse");
        let password_config = SecurityAuditor::parse_effective_sshd_config_output(
            &ordinary_user,
            SSHD_PASSWORD_EVALUATION_CONTEXT,
        )
        .expect("ordinary-user effective config should parse");

        assert_eq!(
            SecurityAuditor::check_ssh_root_login(&Lang::EN, Ok(&root_config)).status,
            "PASS"
        );
        let password_check =
            SecurityAuditor::check_ssh_password_auth(&Lang::EN, Ok(&password_config));
        assert_eq!(password_check.status, "FAIL");
        assert!(password_check.evidence.iter().any(|value| {
            value == &format!("evaluation_context={SSHD_PASSWORD_EVALUATION_CONTEXT}")
        }));
    }

    #[test]
    fn test_sshd_fallback_config_never_proves_pass() {
        let mut fallback = SecurityAuditor::parse_sshd_config_output(
            "PermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\n",
            "/etc/ssh/sshd_config",
        );
        fallback.probe_error = Some(UnknownReason::MissingExecutable);

        let root_check = SecurityAuditor::check_ssh_root_login(&Lang::EN, Ok(&fallback));
        let password_check = SecurityAuditor::check_ssh_password_auth(&Lang::EN, Ok(&fallback));
        assert_eq!(root_check.status, "WARN");
        assert_eq!(password_check.status, "WARN");
        assert!(
            root_check
                .evidence
                .iter()
                .any(|value| value == "effective_config=false")
        );
        assert!(
            password_check
                .evidence
                .iter()
                .any(|value| value == "probe_error=missing_executable")
        );
    }

    #[test]
    fn test_ssh_password_check_covers_keyboard_interactive_pam_path() {
        let keyboard_interactive = effective_sshd_fixture("no", "no", "yes", "yes");
        let config = SecurityAuditor::parse_effective_sshd_config_output(
            &keyboard_interactive,
            SSHD_PASSWORD_EVALUATION_CONTEXT,
        )
        .expect("effective keyboard-interactive config should parse");
        let check = SecurityAuditor::check_ssh_password_auth(&Lang::EN, Ok(&config));

        assert_eq!(check.status, "FAIL");
        assert!(
            check
                .evidence
                .iter()
                .any(|value| value == "kbdinteractiveauthentication=yes")
        );
        assert!(check.evidence.iter().any(|value| value == "usepam=yes"));
    }

    #[test]
    fn test_root_encryption_requires_crypt_in_root_backing_chain() {
        let unrelated_encrypted_volume = r#"{
            "blockdevices": [
                {
                    "name": "/dev/vda",
                    "type": "disk",
                    "mountpoints": [null],
                    "children": [
                        {"name": "/dev/vda1", "type": "part", "mountpoints": ["/"]}
                    ]
                },
                {
                    "name": "/dev/vdb",
                    "type": "disk",
                    "mountpoints": [null],
                    "children": [
                        {"name": "/dev/mapper/vault", "type": "crypt", "mountpoints": ["/srv"]}
                    ]
                }
            ]
        }"#;
        assert!(
            !SecurityAuditor::parse_root_backing_encryption(unrelated_encrypted_volume)
                .expect("valid unencrypted root tree should be known")
        );

        let encrypted_root = r#"{
            "blockdevices": [
                {
                    "name": "/dev/vda",
                    "type": "disk",
                    "mountpoints": [null],
                    "children": [
                        {
                            "name": "/dev/vda2",
                            "type": "part",
                            "mountpoints": [null],
                            "children": [
                                {
                                    "name": "/dev/mapper/cryptroot",
                                    "type": "crypt",
                                    "mountpoints": [null],
                                    "children": [
                                        {"name": "/dev/mapper/vg-root", "type": "lvm", "mountpoints": ["/"]}
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }"#;
        assert!(
            SecurityAuditor::parse_root_backing_encryption(encrypted_root)
                .expect("encrypted root backing tree should be proven")
        );
    }

    #[test]
    fn test_root_encryption_missing_or_ambiguous_root_is_unknown() {
        let no_root = r#"{
            "blockdevices": [
                {"name": "/dev/vda", "type": "disk", "mountpoints": [null]}
            ]
        }"#;
        assert_eq!(
            SecurityAuditor::parse_root_backing_encryption(no_root)
                .expect_err("missing root mount must remain unknown"),
            UnknownReason::MalformedOutput
        );

        let two_roots = r#"{
            "blockdevices": [
                {"name": "/dev/vda1", "type": "part", "mountpoints": ["/"]},
                {"name": "/dev/vdb1", "type": "crypt", "mountpoints": ["/"]}
            ]
        }"#;
        assert_eq!(
            SecurityAuditor::parse_root_backing_encryption(two_roots)
                .expect_err("ambiguous root backing tree must remain unknown"),
            UnknownReason::MalformedOutput
        );
    }

    #[test]
    fn test_ufw_status_requires_one_unambiguous_status_line() {
        assert_eq!(
            SecurityAuditor::parse_ufw_status_output("Status: active\n"),
            Ok(true)
        );
        assert_eq!(
            SecurityAuditor::parse_ufw_status_output("header\n Status: inactive \nfooter\n"),
            Ok(false)
        );
        for ambiguous in [
            "",
            "Status: unknown\n",
            "Status: active\nStatus: unknown\n",
            "Status: active\nstatus: unknown\n",
            "Status: active\nStatus: inactive\n",
            "Status: active\nStatus: active\n",
            "Status: inactive\nStatus: inactive\n",
        ] {
            assert_eq!(
                SecurityAuditor::parse_ufw_status_output(ambiguous),
                Err(UnknownReason::MalformedOutput),
                "ambiguous UFW output must remain unknown: {ambiguous:?}"
            );
        }
    }

    #[test]
    fn docker_socket_check_requires_a_real_final_unix_socket() {
        use std::os::unix::net::UnixListener;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let fixture = std::env::temp_dir().join(format!(
            "mini-ops-docker-socket-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&fixture).expect("fixture directory should be created");

        let socket_path = fixture.join("docker.sock");
        let listener = UnixListener::bind(&socket_path).expect("fixture socket should bind");
        let socket_metadata =
            fs::symlink_metadata(&socket_path).expect("fixture socket metadata should exist");
        assert_eq!(
            docker_socket_facts(&socket_metadata),
            Ok((
                socket_metadata.permissions().mode() & 0o777,
                socket_metadata.uid(),
                socket_metadata.gid()
            ))
        );

        let regular_path = fixture.join("regular");
        fs::write(&regular_path, b"not a socket").expect("fixture file should be written");
        assert_eq!(
            docker_socket_facts(
                &fs::symlink_metadata(&regular_path)
                    .expect("fixture regular metadata should exist")
            ),
            Err(UnknownReason::MalformedOutput)
        );

        let symlink_path = fixture.join("socket-link");
        std::os::unix::fs::symlink(&socket_path, &symlink_path)
            .expect("fixture symlink should be created");
        assert_eq!(
            docker_socket_facts(
                &fs::symlink_metadata(&symlink_path)
                    .expect("fixture symlink metadata should exist")
            ),
            Err(UnknownReason::MalformedOutput)
        );

        drop(listener);
        fs::remove_dir_all(&fixture).expect("fixture directory should be removed");
    }

    #[test]
    fn incomplete_docker_facts_do_not_hide_known_failures() {
        let critical = DockerSecurityRisk {
            severity: "critical".to_string(),
            finding: "fixture".to_string(),
            evidence: "container=fixture privileged=true".to_string(),
        };
        assert_eq!(
            docker_audit_severity_status(&[critical], true),
            ("critical", "FAIL")
        );

        let high = DockerSecurityRisk {
            severity: "high".to_string(),
            finding: "fixture".to_string(),
            evidence: "container=fixture seccomp=disabled".to_string(),
        };
        assert_eq!(
            docker_audit_severity_status(&[high], true),
            ("high", "FAIL")
        );
        assert_eq!(docker_audit_severity_status(&[], true), ("high", "WARN"));

        let long_risk = DockerSecurityRisk {
            severity: "medium".to_string(),
            finding: "fixture".to_string(),
            evidence: "x".repeat(8 * 1024),
        };
        let bounded = bounded_strings(
            docker_audit_evidence(
                &[long_risk],
                &[DockerSecurityIncompleteReason::MissingMounts],
            ),
            4 * 1024,
            128,
        );
        assert_eq!(
            bounded.first().map(String::as_str),
            Some("docker_audit_incomplete=missing_mounts")
        );
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
            Some("5435,0,bad"),
            Some("70000,bad"),
        );

        assert_eq!(baseline.allowed_public_ports, vec![22, 80, 443, 5435, 8090]);
        assert_eq!(baseline.allowed_loopback_ports, vec![3000]);
        assert_eq!(baseline.invalid_token_count, 4);
    }

    #[test]
    fn test_invalid_allowed_port_tokens_force_warn_without_raw_values() {
        let pass = SecurityCheck::new(
            "network.listening_ports",
            "Listening ports".to_string(),
            "network",
            "medium",
            "PASS",
            "Expected listeners".to_string(),
            "Review listeners".to_string(),
        );
        let check = SecurityAuditor::apply_invalid_allowed_port_warning(&Lang::EN, pass, 3);

        assert_eq!(check.status, "WARN");
        assert_eq!(check.evidence[0], "config_error=invalid_allowed_port");
        assert_eq!(check.metadata["invalid_allowed_port_count"], vec!["3"]);
        assert!(
            check
                .evidence
                .iter()
                .all(|value| !value.contains("bad") && !value.contains("70000"))
        );
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
            .filter(|socket| socket.is_loopback())
            .map(|socket| socket.port)
            .collect::<Vec<_>>();
        let public_ports = sockets
            .iter()
            .filter(|socket| !socket.is_loopback())
            .map(|socket| socket.port)
            .collect::<Vec<_>>();

        assert_eq!(loopback_ports, vec![3000, 9001]);
        assert_eq!(public_ports, vec![5435]);
    }

    #[test]
    fn test_listener_facts_preserve_protocol_address_and_scope() {
        let output = "\
tcp LISTEN 0 4096 127.0.0.1:3000 0.0.0.0:*\n\
tcp LISTEN 0 4096 192.0.2.10:443 0.0.0.0:*\n\
tcp LISTEN 0 4096 [::]:22 [::]:*\n\
udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*\n";

        let sockets = SecurityAuditor::parse_listening_sockets(output)
            .expect("valid listener facts should parse");
        assert_eq!(
            sockets,
            vec![
                ListeningSocket {
                    protocol: "tcp".to_string(),
                    address: "127.0.0.1".to_string(),
                    port: 3000,
                    scope: ListenerScope::Loopback,
                },
                ListeningSocket {
                    protocol: "tcp".to_string(),
                    address: "192.0.2.10".to_string(),
                    port: 443,
                    scope: ListenerScope::NonLoopback,
                },
                ListeningSocket {
                    protocol: "tcp".to_string(),
                    address: "::".to_string(),
                    port: 22,
                    scope: ListenerScope::Wildcard,
                },
                ListeningSocket {
                    protocol: "udp".to_string(),
                    address: "0.0.0.0".to_string(),
                    port: 5353,
                    scope: ListenerScope::Wildcard,
                },
            ]
        );
        assert_eq!(
            SecurityAuditor::format_listening_socket(&sockets[2]),
            "tcp://[::]:22"
        );
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
        for reason in [
            UnknownReason::NonzeroExit,
            UnknownReason::EmptyOutput,
            UnknownReason::MalformedOutput,
            UnknownReason::Timeout,
        ] {
            let check =
                SecurityAuditor::check_docker_tcp_api_ports(&Lang::EN, &Fact::Unknown(reason));

            assert_eq!(check.status, "WARN");
            assert_eq!(
                check.evidence,
                vec![format!("probe_error={}", reason.code())]
            );
        }
    }

    #[test]
    fn test_docker_tcp_api_distinguishes_public_wildcard_and_loopback_listeners() {
        let public = SecurityAuditor::parse_listening_sockets(
            "tcp LISTEN 0 4096 192.0.2.10:2375 0.0.0.0:*\n",
        )
        .expect("public Docker listener should parse");
        let public_check =
            SecurityAuditor::check_docker_tcp_api_ports(&Lang::EN, &Fact::Known(public));
        assert_eq!(public_check.status, "FAIL");
        assert_eq!(public_check.severity, "critical");
        assert_eq!(
            public_check.metadata["public_listeners"],
            vec!["tcp://192.0.2.10:2375"]
        );
        assert!(
            public_check
                .evidence
                .iter()
                .any(|value| value.contains("scope=non_loopback"))
        );

        let wildcard =
            SecurityAuditor::parse_listening_sockets("tcp LISTEN 0 4096 [::]:2376 [::]:*\n")
                .expect("wildcard Docker listener should parse");
        let wildcard_check =
            SecurityAuditor::check_docker_tcp_api_ports(&Lang::EN, &Fact::Known(wildcard));
        assert_eq!(wildcard_check.status, "FAIL");
        assert_eq!(wildcard_check.severity, "high");
        assert!(
            wildcard_check
                .evidence
                .iter()
                .any(|value| value.contains("scope=wildcard"))
        );

        let loopback = SecurityAuditor::parse_listening_sockets(
            "tcp LISTEN 0 4096 127.0.0.1:2375 0.0.0.0:*\n",
        )
        .expect("loopback Docker listener should parse");
        let loopback_check =
            SecurityAuditor::check_docker_tcp_api_ports(&Lang::EN, &Fact::Known(loopback));
        assert_eq!(loopback_check.status, "WARN");
        assert_eq!(loopback_check.severity, "medium");
        assert_eq!(
            loopback_check.metadata["loopback_listeners"],
            vec!["tcp://127.0.0.1:2375"]
        );
    }

    #[test]
    fn test_docker_tcp_api_ignores_udp_port_number_and_has_stable_transitions() {
        let udp_only =
            SecurityAuditor::parse_listening_sockets("udp UNCONN 0 0 0.0.0.0:2375 0.0.0.0:*\n")
                .expect("UDP listener should parse");
        let pass = SecurityAuditor::check_docker_tcp_api_ports(&Lang::EN, &Fact::Known(udp_only));
        let warn = SecurityAuditor::check_docker_tcp_api_ports(
            &Lang::EN,
            &Fact::Unknown(UnknownReason::Timeout),
        );
        let public =
            SecurityAuditor::parse_listening_sockets("tcp LISTEN 0 4096 0.0.0.0:2375 0.0.0.0:*\n")
                .expect("public listener should parse");
        let fail = SecurityAuditor::check_docker_tcp_api_ports(&Lang::EN, &Fact::Known(public));

        assert_eq!(
            [
                warn.status.as_str(),
                fail.status.as_str(),
                pass.status.as_str()
            ],
            ["WARN", "FAIL", "PASS"]
        );
        assert_eq!(warn.id, fail.id);
        assert_eq!(fail.id, pass.id);
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

    #[tokio::test]
    async fn monitor_identity_tracker_claims_each_snapshot_once() {
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let snapshots = SecuritySnapshotService::test_service(counter);
        snapshots.publish_test_snapshot(Duration::ZERO, false).await;
        let first = snapshots
            .latest()
            .await
            .expect("first test snapshot should exist")
            .identity();
        let tracker = SnapshotIdentityTracker::default();

        assert!(tracker.claim(first).await);
        assert!(!tracker.claim(first).await);

        snapshots.publish_test_snapshot(Duration::ZERO, false).await;
        let second = snapshots
            .latest()
            .await
            .expect("second test snapshot should exist")
            .identity();
        assert_ne!(first, second);
        assert!(tracker.claim(second).await);
    }

    #[tokio::test]
    async fn monitor_zero_max_age_refreshes_each_sequential_tick() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let counter = Arc::new(AtomicUsize::new(0));
        let snapshots = SecuritySnapshotService::test_service(Arc::clone(&counter));
        let first = snapshots
            .get_or_refresh(MONITOR_SNAPSHOT_MAX_AGE)
            .await
            .expect("first monitor tick should publish");
        let second = snapshots
            .get_or_refresh(MONITOR_SNAPSHOT_MAX_AGE)
            .await
            .expect("second monitor tick should publish");

        assert_eq!(counter.load(Ordering::SeqCst), 2);
        assert_eq!(first.identity().generation(), 1);
        assert_eq!(second.identity().generation(), 2);
    }

    #[tokio::test]
    async fn monitor_skips_missed_ticks_instead_of_bursting_audits() {
        let interval = security_monitor_interval(Duration::from_secs(60));
        assert_eq!(
            interval.missed_tick_behavior(),
            tokio::time::MissedTickBehavior::Skip
        );
    }

    #[tokio::test]
    async fn full_snapshot_resolves_collection_warning_without_notification() {
        use sqlx::sqlite::SqlitePoolOptions;
        use std::sync::atomic::AtomicUsize;

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory database should open");
        SecurityEventService::init_schema(&pool)
            .await
            .expect("security event schema should initialize");
        let events = Arc::new(SecurityEventService::new(pool.clone()));
        let notifier = Arc::new(NotificationService::new());
        let outbox = Arc::new(NotificationOutbox::new(pool.clone(), notifier.clone()));
        let counter = Arc::new(AtomicUsize::new(0));
        let snapshots =
            SecuritySnapshotService::test_degraded_then_full_service(Arc::clone(&counter));
        let monitor = SecurityMonitor::new(notifier, outbox, snapshots, Arc::clone(&events));
        monitor.check_once().await;
        let active = events
            .list(Some("active"), 100)
            .await
            .expect("active events should be readable");
        assert!(active.iter().any(|event| {
            event.event_key == "audit:audit.collection" && event.event_type == "audit.check_warning"
        }));
        assert!(active.iter().any(|event| {
            event.event_key == "audit:firewall.ufw" && event.event_type == "audit.check_warning"
        }));

        monitor.check_once().await;

        let resolved = events
            .list(Some("resolved"), 100)
            .await
            .expect("resolved events should be readable");
        assert!(resolved.iter().any(|event| {
            event.event_key == "audit:audit.collection" && event.event_type == "audit.check_warning"
        }));
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 2);
        let outbox_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notification_outbox")
            .fetch_one(&pool)
            .await
            .expect("outbox count should be readable");
        assert_eq!(outbox_rows, 0);
    }
}
