use serde::Serialize;
use std::fs;
use std::process::Command;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use crate::notifications::NotificationService;
use crate::i18n::Lang;
use std::time::Duration;

#[derive(Serialize, Clone)]
pub struct SecurityCheck {
    pub name: String,
    pub status: String, // "PASS", "FAIL", "WARN"
    pub message: String,
}

pub struct SecurityAuditor;

impl SecurityAuditor {
    pub async fn run_audit(lang: &Lang) -> Vec<SecurityCheck> {
        let mut checks = Vec::new();

        checks.push(Self::check_ssh_root_login(lang));
        checks.push(Self::check_ufw_status(lang));
        checks.push(Self::check_docker_socket(lang));
        checks.push(Self::check_disk_encryption(lang));
        checks.push(Self::check_fail2ban_status(lang));
        checks.push(Self::check_ssh_password_auth(lang));
        checks.push(Self::check_listening_ports(lang));

        checks
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
            if path.exists() && path.is_file() {
                if let Ok(metadata) = fs::metadata(path) {
                    #[cfg(unix)]
                    {
                        if metadata.permissions().mode() & 0o111 != 0 {
                            tracing::debug!("Found {} at {}", name, path_str);
                            return Some(path.to_path_buf());
                        }
                    }
                }
            }
        }
        
        tracing::debug!("Binary '{}' not found in standard paths", name);
        None
    }

    fn check_ssh_root_login(lang: &Lang) -> SecurityCheck {
        let path = "/etc/ssh/sshd_config";
        if let Ok(content) = fs::read_to_string(path) {
            let permit_root = content.lines()
                .find(|l| l.trim().starts_with("PermitRootLogin"));
            
            if let Some(line) = permit_root {
                if line.contains("yes") {
                    return SecurityCheck {
                        name: crate::i18n::t("audit.ssh_root.name", lang),
                        status: "FAIL".to_string(),
                        message: crate::i18n::t("audit.ssh_root.fail", lang),
                    };
                }
            }
            SecurityCheck {
                name: crate::i18n::t("audit.ssh_root.name", lang),
                status: "PASS".to_string(),
                message: crate::i18n::t("audit.ssh_root.pass", lang),
            }
        } else {
            SecurityCheck {
                name: crate::i18n::t("audit.ssh_root.name", lang),
                status: "WARN".to_string(),
                message: crate::i18n::t("audit.ssh_config.warn", lang),
            }
        }
    }

    fn check_ufw_status(lang: &Lang) -> SecurityCheck {
        // Try to find ufw binary
        let ufw_path = Self::find_system_binary("ufw")
            .unwrap_or_else(|| PathBuf::from("ufw")); // Fallback to PATH
        
        match Command::new(&ufw_path).arg("status").output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                
                if output.status.success() {
                    if stdout.contains("Status: active") {
                        SecurityCheck {
                            name: crate::i18n::t("audit.ufw.name", lang),
                            status: "PASS".to_string(),
                            message: crate::i18n::t("audit.ufw.pass", lang),
                        }
                    } else {
                        SecurityCheck {
                            name: crate::i18n::t("audit.ufw.name", lang),
                            status: "FAIL".to_string(),
                            message: crate::i18n::t("audit.ufw.fail", lang),
                        }
                    }
                } else {
                    // UFW found but command failed (e.g., permission denied)
                    tracing::warn!("UFW command failed: {}", String::from_utf8_lossy(&output.stderr));
                    SecurityCheck {
                        name: crate::i18n::t("audit.ufw.name", lang),
                        status: "WARN".to_string(),
                        message: crate::i18n::t("audit.ufw.error", lang),
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to execute UFW: {}", e);
                SecurityCheck {
                    name: crate::i18n::t("audit.ufw.name", lang),
                    status: "WARN".to_string(),
                    message: crate::i18n::t("audit.ufw.warn", lang),
                }
            }
        }
    }

    fn check_docker_socket(lang: &Lang) -> SecurityCheck {
        let path = "/var/run/docker.sock";
        if let Ok(metadata) = fs::metadata(path) {
            let mode = metadata.permissions().mode();
            // Check if world writable (o+w is the last bit of the last octal: 0o002)
            if mode & 0o002 != 0 {
                 return SecurityCheck {
                    name: crate::i18n::t("audit.docker_sock.name", lang),
                    status: "FAIL".to_string(),
                    message: crate::i18n::t("audit.docker_sock.fail", lang),
                };
            }
            SecurityCheck {
                name: crate::i18n::t("audit.docker_sock.name", lang),
                status: "PASS".to_string(),
                message: crate::i18n::t("audit.docker_sock.pass", lang),
            }
        } else {
            SecurityCheck {
                name: crate::i18n::t("audit.docker_sock.name", lang),
                status: "WARN".to_string(),
                message: crate::i18n::t("audit.docker_sock.warn", lang),
            }
        }
    }
    
    fn check_disk_encryption(lang: &Lang) -> SecurityCheck {
        // Basic check for LUKS in lsblk
        let lsblk_path = Self::find_system_binary("lsblk")
            .unwrap_or_else(|| PathBuf::from("lsblk"));
            
        if let Ok(output) = Command::new(&lsblk_path).args(&["-o", "TYPE"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("crypt") {
                SecurityCheck {
                    name: crate::i18n::t("audit.disk_enc.name", lang),
                    status: "PASS".to_string(),
                    message: crate::i18n::t("audit.disk_enc.pass", lang),
                }
            } else {
                SecurityCheck {
                    name: crate::i18n::t("audit.disk_enc.name", lang),
                    status: "WARN".to_string(),
                    message: crate::i18n::t("audit.disk_enc.warn", lang),
                }
            }
        } else {
            SecurityCheck {
                name: crate::i18n::t("audit.disk_enc.name", lang),
                status: "WARN".to_string(),
                message: crate::i18n::t("audit.disk_enc.error", lang),
            }
        }
    }

    /// Проверяет статус сервиса Fail2Ban.
    fn check_fail2ban_status(lang: &Lang) -> SecurityCheck {
        let systemctl_path = Self::find_system_binary("systemctl")
            .unwrap_or_else(|| PathBuf::from("systemctl"));
        
        match Command::new(&systemctl_path).args(&["is-active", "fail2ban"]).output() {
            Ok(output) => {
                if output.status.success() {
                    SecurityCheck {
                        name: crate::i18n::t("audit.fail2ban.name", lang),
                        status: "PASS".to_string(),
                        message: crate::i18n::t("audit.fail2ban.pass", lang),
                    }
                } else {
                    SecurityCheck {
                        name: crate::i18n::t("audit.fail2ban.name", lang),
                        status: "WARN".to_string(),
                        message: crate::i18n::t("audit.fail2ban.warn", lang),
                    }
                }
            }
            Err(_) => {
                SecurityCheck {
                    name: crate::i18n::t("audit.fail2ban.name", lang),
                    status: "WARN".to_string(),
                    message: crate::i18n::t("audit.fail2ban.missing", lang),
                }
            }
        }
    }

    /// Проверяет, отключена ли аутентификация по паролю в SSH.
    fn check_ssh_password_auth(lang: &Lang) -> SecurityCheck {
        if let Ok(content) = fs::read_to_string("/etc/ssh/sshd_config") {
            let password_auth = content.lines()
                .find(|l| {
                    let trim = l.trim();
                    trim.starts_with("PasswordAuthentication") && !trim.starts_with("#")
                });
            
            if let Some(line) = password_auth {
                if line.contains("no") {
                    return SecurityCheck {
                        name: crate::i18n::t("audit.ssh_passwd.name", lang),
                        status: "PASS".to_string(),
                        message: crate::i18n::t("audit.ssh_passwd.pass", lang),
                    };
                }
            }
            SecurityCheck {
                name: crate::i18n::t("audit.ssh_passwd.name", lang),
                status: "FAIL".to_string(),
                message: crate::i18n::t("audit.ssh_passwd.fail", lang),
            }
        } else {
            SecurityCheck {
                name: crate::i18n::t("audit.ssh_passwd.name", lang),
                status: "WARN".to_string(),
                message: crate::i18n::t("audit.ssh_config.warn", lang),
            }
        }
    }

    /// Сканирует открытые порты и ищет подозрительные (не входящие в белый список).
    fn check_listening_ports(lang: &Lang) -> SecurityCheck {
        let ss_path = Self::find_system_binary("ss")
            .unwrap_or_else(|| PathBuf::from("ss"));
        
        if let Ok(output) = Command::new(&ss_path).args(&["-tulpn"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let allowed_ports = ["22", "80", "443", "3000"];
            
            let mut suspicious = Vec::new();
            for line in stdout.lines() {
                if line.contains("LISTEN") {
                    // Extract port using simple split
                    if let Some(local_part) = line.split_whitespace().nth(4) {
                        if let Some(port) = local_part.split(':').last() {
                            if !allowed_ports.contains(&port) {
                                suspicious.push(port.to_string());
                            }
                        }
                    }
                }
            }
            
            suspicious.sort();
            suspicious.dedup();

            if suspicious.is_empty() {
                SecurityCheck {
                    name: crate::i18n::t("audit.ports.name", lang),
                    status: "PASS".to_string(),
                    message: crate::i18n::t("audit.ports.pass", lang),
                }
            } else {
                SecurityCheck {
                    name: crate::i18n::t("audit.ports.name", lang),
                    status: "WARN".to_string(),
                    message: format!("{}: {}", crate::i18n::t("audit.ports.warn", lang), suspicious.join(", ")),
                }
            }
        } else {
            SecurityCheck {
                name: crate::i18n::t("audit.ports.name", lang),
                status: "WARN".to_string(),
                message: crate::i18n::t("audit.ports.error", lang),
            }
        }
    }
}

pub struct SecurityMonitor {
    notifier: Arc<NotificationService>,
    last_states: Mutex<HashMap<String, String>>,
}

impl SecurityMonitor {
    pub fn new(notifier: Arc<NotificationService>) -> Self {
        Self {
            notifier,
            last_states: Mutex::new(HashMap::new()),
        }
    }

    pub async fn run_loop(self: Arc<Self>) {
        tracing::info!("Starting Security Monitor Loop...");
        let mut interval = tokio::time::interval(Duration::from_secs(60)); 

        loop {
            interval.tick().await;
            self.check_once().await;
        }
    }

    async fn check_once(&self) {
        // Background loop uses default language from env
        let default_lang = Lang::from_headers(&crate::i18n::HeaderMap::new());
        let checks = SecurityAuditor::run_audit(&default_lang).await;
        
        // 1. Calculate alerts to send (synchronous part)
        let mut alerts = Vec::new();
        {
            let mut states = self.last_states.lock().unwrap();
            for check in &checks {
                let old_status = states.get(&check.name).cloned().unwrap_or_else(|| "UNKNOWN".to_string());
                
                if check.status == "FAIL" && old_status != "FAIL" {
                     alerts.push(format!("{}\n\n{}: {}\n{}: {}", 
                        crate::i18n::t("security.detected", &default_lang),
                        crate::i18n::t("security.check", &default_lang), check.name,
                        crate::i18n::t("security.message", &default_lang), check.message));
                } else if check.status == "PASS" && old_status == "FAIL" {
                     alerts.push(format!("{}\n\n{}: {}", 
                        crate::i18n::t("security.resolved", &default_lang),
                        crate::i18n::t("security.check", &default_lang), check.name));
                }
                
                states.insert(check.name.clone(), check.status.clone());
            }
        } // Drop mutex guard here

        // 2. Send alerts (async part)
        for num_alert in alerts {
            self.notifier.send_alert(&num_alert).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_find_system_binary_existing() {
        // Test with common binary that should exist on Linux
        let result = SecurityAuditor::find_system_binary("ls");
        assert!(result.is_some(), "Binary 'ls' should be found in standard paths");
        
        let path = result.unwrap();
        assert!(path.exists());
        assert!(path.is_file());
    }

    #[test]
    fn test_find_system_binary_nonexistent() {
        let result = SecurityAuditor::find_system_binary("nonexistent_binary_xyz123");
        assert!(result.is_none(), "Nonexistent binary should not be found");
    }
}
