use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::docker::DockerService;
use crate::i18n::Lang;
use crate::notifications::NotificationService;
use crate::security_events::SecurityEventService;

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
        self.evidence = evidence;
        self
    }

    fn with_references(mut self, references: Vec<&str>) -> Self {
        self.references = references.into_iter().map(str::to_string).collect();
        self
    }

    fn with_metadata(mut self, key: &str, values: Vec<String>) -> Self {
        self.metadata.insert(key.to_string(), values);
        self
    }
}

#[derive(Debug, Clone)]
struct SshdConfig {
    values: HashMap<String, String>,
    source: String,
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
    open_ports: Vec<u16>,
}

struct ListeningSocket {
    protocol: String,
    address: String,
    port: u16,
    is_loopback: bool,
}

struct ListeningPortBaseline {
    allowed_public_ports: Vec<u16>,
    allowed_loopback_ports: Vec<u16>,
    invalid_tokens: Vec<String>,
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
        let mut checks = Vec::new();

        let sshd_config = Self::load_effective_sshd_config();
        checks.push(Self::check_ssh_root_login(lang, sshd_config.as_ref()));
        checks.push(Self::check_ssh_password_auth(lang, sshd_config.as_ref()));
        checks.push(Self::check_ufw_status(lang));
        checks.push(Self::check_docker_socket(lang));
        checks.push(Self::check_disk_encryption(lang));
        checks.push(Self::check_fail2ban_status(lang));

        let port_scan = Self::check_listening_ports(lang);
        let open_ports = port_scan.open_ports.clone();
        checks.push(port_scan.check);
        checks.push(Self::check_docker_tcp_api_ports(lang, &open_ports));
        checks.push(Self::check_docker_container_risks(lang, docker).await);

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

    fn find_system_binary(name: &str) -> Option<PathBuf> {
        let standard_paths = [
            format!("/usr/sbin/{}", name),
            format!("/usr/bin/{}", name),
            format!("/sbin/{}", name),
            format!("/bin/{}", name),
        ];

        for path_str in &standard_paths {
            let path = Path::new(path_str);
            if path.exists()
                && path.is_file()
                && let Ok(metadata) = fs::metadata(path)
                && metadata.permissions().mode() & 0o111 != 0
            {
                tracing::debug!("Found {} at {}", name, path_str);
                return Some(path.to_path_buf());
            }
        }

        tracing::debug!("Binary '{}' not found in standard paths", name);
        None
    }

    fn load_effective_sshd_config() -> Result<SshdConfig, String> {
        if let Some(sshd_path) = Self::find_system_binary("sshd") {
            match Command::new(&sshd_path).arg("-T").output() {
                Ok(output) if output.status.success() => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if !stdout.trim().is_empty() {
                        return Ok(Self::parse_sshd_config_output(&stdout, "sshd -T"));
                    }
                }
                Ok(output) => {
                    tracing::warn!(
                        "sshd -T failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                Err(e) => tracing::warn!("Failed to execute sshd -T: {}", e),
            }
        }

        fs::read_to_string("/etc/ssh/sshd_config")
            .map(|content| Self::parse_sshd_config_output(&content, "/etc/ssh/sshd_config"))
            .map_err(|e| format!("Could not load sshd config: {}", e))
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
        }
    }

    fn check_ssh_root_login(
        lang: &Lang,
        sshd_config: Result<&SshdConfig, &String>,
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
                .with_evidence(vec![e.to_string()]);
            }
        };

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
        sshd_config: Result<&SshdConfig, &String>,
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
                .with_evidence(vec![e.to_string()]);
            }
        };

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

    fn check_ufw_status(lang: &Lang) -> SecurityCheck {
        let name = crate::i18n::t("audit.ufw.name", lang);
        let remediation = crate::i18n::t("audit.ufw.remediation", lang);
        let ufw_path = Self::find_system_binary("ufw").unwrap_or_else(|| PathBuf::from("ufw"));

        match Command::new(&ufw_path).arg("status").output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let evidence = vec![stdout.lines().next().unwrap_or_default().to_string()];

                if output.status.success() {
                    if stdout.contains("Status: active") {
                        SecurityCheck::new(
                            "firewall.ufw",
                            name,
                            "firewall",
                            "high",
                            "PASS",
                            crate::i18n::t("audit.ufw.pass", lang),
                            remediation,
                        )
                        .with_evidence(evidence)
                    } else {
                        SecurityCheck::new(
                            "firewall.ufw",
                            name,
                            "firewall",
                            "high",
                            "FAIL",
                            crate::i18n::t("audit.ufw.fail", lang),
                            remediation,
                        )
                        .with_evidence(evidence)
                    }
                } else {
                    tracing::warn!(
                        "UFW command failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    SecurityCheck::new(
                        "firewall.ufw",
                        name,
                        "firewall",
                        "high",
                        "WARN",
                        crate::i18n::t("audit.ufw.error", lang),
                        remediation,
                    )
                    .with_evidence(vec![String::from_utf8_lossy(&output.stderr).to_string()])
                }
            }
            Err(e) => SecurityCheck::new(
                "firewall.ufw",
                name,
                "firewall",
                "high",
                "WARN",
                crate::i18n::t("audit.ufw.warn", lang),
                remediation,
            )
            .with_evidence(vec![e.to_string()]),
        }
    }

    fn check_docker_socket(lang: &Lang) -> SecurityCheck {
        let name = crate::i18n::t("audit.docker_sock.name", lang);
        let remediation = crate::i18n::t("audit.docker_sock.remediation", lang);
        let path = "/var/run/docker.sock";

        if let Ok(metadata) = fs::metadata(path) {
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
        } else {
            SecurityCheck::new(
                "docker.socket_permissions",
                name,
                "docker",
                "low",
                "WARN",
                crate::i18n::t("audit.docker_sock.warn", lang),
                remediation,
            )
        }
    }

    fn check_disk_encryption(lang: &Lang) -> SecurityCheck {
        let name = crate::i18n::t("audit.disk_enc.name", lang);
        let remediation = crate::i18n::t("audit.disk_enc.remediation", lang);
        let lsblk_path =
            Self::find_system_binary("lsblk").unwrap_or_else(|| PathBuf::from("lsblk"));

        if let Ok(output) = Command::new(&lsblk_path).args(["-o", "TYPE"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("crypt") {
                SecurityCheck::new(
                    "system.disk_encryption",
                    name,
                    "system",
                    "low",
                    "PASS",
                    crate::i18n::t("audit.disk_enc.pass", lang),
                    remediation,
                )
                .with_evidence(vec!["lsblk_type=crypt".to_string()])
            } else {
                SecurityCheck::new(
                    "system.disk_encryption",
                    name,
                    "system",
                    "low",
                    "WARN",
                    crate::i18n::t("audit.disk_enc.warn", lang),
                    remediation,
                )
            }
        } else {
            SecurityCheck::new(
                "system.disk_encryption",
                name,
                "system",
                "low",
                "WARN",
                crate::i18n::t("audit.disk_enc.error", lang),
                remediation,
            )
        }
    }

    fn check_fail2ban_status(lang: &Lang) -> SecurityCheck {
        let name = crate::i18n::t("audit.fail2ban.name", lang);
        let remediation = crate::i18n::t("audit.fail2ban.remediation", lang);
        let systemctl_path =
            Self::find_system_binary("systemctl").unwrap_or_else(|| PathBuf::from("systemctl"));

        match Command::new(&systemctl_path)
            .args(["is-active", "fail2ban"])
            .output()
        {
            Ok(output) if output.status.success() => SecurityCheck::new(
                "intrusion.fail2ban",
                name,
                "intrusion",
                "medium",
                "PASS",
                crate::i18n::t("audit.fail2ban.pass", lang),
                remediation,
            )
            .with_evidence(vec!["systemctl is-active fail2ban=active".to_string()]),
            Ok(output) => SecurityCheck::new(
                "intrusion.fail2ban",
                name,
                "intrusion",
                "medium",
                "WARN",
                crate::i18n::t("audit.fail2ban.warn", lang),
                remediation,
            )
            .with_evidence(vec![
                String::from_utf8_lossy(&output.stdout).trim().to_string(),
            ]),
            Err(e) => SecurityCheck::new(
                "intrusion.fail2ban",
                name,
                "intrusion",
                "medium",
                "WARN",
                crate::i18n::t("audit.fail2ban.missing", lang),
                remediation,
            )
            .with_evidence(vec![e.to_string()]),
        }
    }

    fn check_listening_ports(lang: &Lang) -> PortScanResult {
        let name = crate::i18n::t("audit.ports.name", lang);
        let remediation = crate::i18n::t("audit.ports.remediation", lang);
        let ss_path = Self::find_system_binary("ss").unwrap_or_else(|| PathBuf::from("ss"));

        if let Ok(output) = Command::new(&ss_path).args(["-H", "-tuln"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut listening_sockets = Self::parse_listening_sockets(&stdout);
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
                    !(socket.is_loopback && baseline.allowed_loopback_ports.contains(&socket.port))
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
                    !(socket.is_loopback && baseline.allowed_loopback_ports.contains(&socket.port))
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

            if !baseline.invalid_tokens.is_empty() {
                check = check
                    .with_metadata("invalid_allowed_ports", baseline.invalid_tokens.clone())
                    .with_evidence(
                        baseline
                            .invalid_tokens
                            .iter()
                            .map(|token| format!("ignored_allowed_port={}", token))
                            .collect(),
                    );
            }

            PortScanResult { check, open_ports }
        } else {
            PortScanResult {
                check: SecurityCheck::new(
                    "network.listening_ports",
                    name,
                    "network",
                    "medium",
                    "WARN",
                    crate::i18n::t("audit.ports.error", lang),
                    remediation,
                ),
                open_ports: Vec::new(),
            }
        }
    }

    fn listening_port_baseline(
        app_port: u16,
        nginx_port: u16,
        extra_public_ports: Option<&str>,
        extra_loopback_ports: Option<&str>,
    ) -> ListeningPortBaseline {
        let mut invalid_tokens = Vec::new();
        let mut allowed_public_ports = vec![22, 80, 443, nginx_port];
        let mut allowed_loopback_ports = vec![app_port];

        Self::extend_ports_from_env(
            &mut allowed_public_ports,
            &mut invalid_tokens,
            extra_public_ports,
        );
        Self::extend_ports_from_env(
            &mut allowed_loopback_ports,
            &mut invalid_tokens,
            extra_loopback_ports,
        );

        allowed_public_ports.sort_unstable();
        allowed_public_ports.dedup();
        allowed_loopback_ports.sort_unstable();
        allowed_loopback_ports.dedup();
        invalid_tokens.sort();
        invalid_tokens.dedup();

        ListeningPortBaseline {
            allowed_public_ports,
            allowed_loopback_ports,
            invalid_tokens,
        }
    }

    fn extend_ports_from_env(
        ports: &mut Vec<u16>,
        invalid_tokens: &mut Vec<String>,
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
                Err(_) => invalid_tokens.push(token.to_string()),
            }
        }
    }

    fn parse_listening_sockets(ss_output: &str) -> Vec<ListeningSocket> {
        ss_output
            .lines()
            .filter(|line| line.contains("LISTEN") || line.contains("UNCONN"))
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                let protocol = parts.next()?.to_string();
                let local_address = parts.nth(3)?;
                let (address, port) = Self::parse_local_address(local_address)?;
                Some(ListeningSocket {
                    protocol,
                    is_loopback: Self::is_loopback_address(&address),
                    address,
                    port,
                })
            })
            .collect()
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

    fn check_docker_tcp_api_ports(lang: &Lang, open_ports: &[u16]) -> SecurityCheck {
        let exposed = open_ports
            .iter()
            .copied()
            .filter(|port| *port == 2375 || *port == 2376)
            .collect::<Vec<_>>();
        let name = crate::i18n::t("audit.docker_api.name", lang);
        let remediation = crate::i18n::t("audit.docker_api.remediation", lang);

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
    ) -> SecurityCheck {
        let name = crate::i18n::t("audit.docker_containers.name", lang);
        let remediation = crate::i18n::t("audit.docker_containers.remediation", lang);

        let Some(docker) = docker else {
            let status = if Path::new("/var/run/docker.sock").exists() {
                "WARN"
            } else {
                "PASS"
            };
            let message = if status == "PASS" {
                crate::i18n::t("audit.docker_containers.no_runtime", lang)
            } else {
                crate::i18n::t("audit.docker_containers.unavailable", lang)
            };

            return SecurityCheck::new(
                "docker.container_hardening",
                name,
                "docker",
                "high",
                status,
                message,
                remediation,
            );
        };

        let docker_timeout = env_duration_secs("SECURITY_AUDIT_DOCKER_TIMEOUT_SECS", 10, 1, 120);
        let audit_result =
            tokio::time::timeout(docker_timeout, docker.audit_security_risks()).await;

        match audit_result {
            Err(_) => SecurityCheck::new(
                "docker.container_hardening",
                name,
                "docker",
                "high",
                "WARN",
                crate::i18n::t("audit.docker_containers.timeout", lang),
                remediation,
            )
            .with_evidence(vec![format!("timeout_secs={}", docker_timeout.as_secs())]),
            Ok(Ok(risks)) if risks.is_empty() => SecurityCheck::new(
                "docker.container_hardening",
                name,
                "docker",
                "high",
                "PASS",
                crate::i18n::t("audit.docker_containers.pass", lang),
                remediation,
            )
            .with_references(vec!["https://docs.docker.com/engine/security/"]),
            Ok(Ok(risks)) => {
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
                    .map(|risk| format!("{}: {}", risk.finding, risk.evidence))
                    .collect::<Vec<_>>();

                let mut by_severity: HashMap<String, Vec<String>> = HashMap::new();
                for risk in &risks {
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
            Ok(Err(e)) => SecurityCheck::new(
                "docker.container_hardening",
                name,
                "docker",
                "high",
                "WARN",
                crate::i18n::t("audit.docker_containers.error", lang),
                remediation,
            )
            .with_evidence(vec![e]),
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
    fn test_find_system_binary_existing() {
        let result = SecurityAuditor::find_system_binary("ls");
        assert!(
            result.is_some(),
            "Binary 'ls' should be found in standard paths"
        );

        let path = result.unwrap();
        assert!(path.exists());
        assert!(path.is_file());
    }

    #[test]
    fn test_find_system_binary_nonexistent() {
        let result = SecurityAuditor::find_system_binary("nonexistent_binary_xyz123");
        assert!(result.is_none(), "Nonexistent binary should not be found");
    }

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
        assert!(baseline.invalid_tokens.is_empty());
    }

    #[test]
    fn test_listening_port_baseline_keeps_invalid_tokens() {
        let baseline = SecurityAuditor::listening_port_baseline(
            3000,
            8090,
            Some("5435,bad"),
            Some("70000,bad"),
        );

        assert_eq!(baseline.allowed_public_ports, vec![22, 80, 443, 5435, 8090]);
        assert_eq!(baseline.allowed_loopback_ports, vec![3000]);
        assert_eq!(baseline.invalid_tokens, vec!["70000", "bad"]);
    }

    #[test]
    fn test_parse_listening_sockets_marks_loopback() {
        let output = "\
tcp LISTEN 0 4096 127.0.0.1:3000 0.0.0.0:*
tcp LISTEN 0 4096 0.0.0.0:5435 0.0.0.0:*
tcp LISTEN 0 128 [::1]:9001 [::]:*
";

        let sockets = SecurityAuditor::parse_listening_sockets(output);
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
