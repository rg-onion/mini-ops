use bollard::Docker;
use bollard::query_parameters::{
    InspectContainerOptions, ListContainersOptions, LogsOptions, RestartContainerOptions,
    StartContainerOptions, StopContainerOptions,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub state: String, // running, exited, etc.
    pub ports: String,
}

#[derive(Debug, Clone)]
pub struct DockerSecurityRisk {
    pub severity: String,
    pub finding: String,
    pub evidence: String,
}

pub struct DockerService {
    docker: Docker,
}

impl DockerService {
    pub fn new() -> Result<Self, String> {
        let docker = Docker::connect_with_socket_defaults()
            .map_err(|e| format!("Failed to connect to Docker: {}", e))?;
        Ok(Self { docker })
    }

    pub async fn list_containers(&self) -> Result<Vec<ContainerInfo>, String> {
        let options = ListContainersOptions {
            all: true,
            ..Default::default()
        };

        let containers = self
            .docker
            .list_containers(Some(options))
            .await
            .map_err(|e| format!("Failed to list containers: {}", e))?;

        let result = containers
            .into_iter()
            .map(|c| {
                let name = c
                    .names
                    .clone()
                    .unwrap_or_default()
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string())
                    .trim_start_matches('/')
                    .to_string();

                let ports = c
                    .ports
                    .clone()
                    .unwrap_or_default()
                    .iter()
                    .map(|p| format!("{}:{}", p.public_port.unwrap_or(0), p.private_port))
                    .collect::<Vec<_>>()
                    .join(", ");

                ContainerInfo {
                    id: c.id.unwrap_or_default(),
                    name,
                    image: c.image.unwrap_or_default(),
                    status: c.status.unwrap_or_default(),
                    state: c
                        .state
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    ports,
                }
            })
            .collect();

        Ok(result)
    }

    pub async fn audit_security_risks(&self) -> Result<Vec<DockerSecurityRisk>, String> {
        let containers = self.list_containers().await?;
        let mut risks = Vec::new();

        for container in containers {
            let inspect = self
                .docker
                .inspect_container(&container.id, None::<InspectContainerOptions>)
                .await
                .map_err(|e| format!("Failed to inspect container {}: {}", container.name, e))?;

            let container_name = inspect
                .name
                .as_deref()
                .unwrap_or(&container.name)
                .trim_start_matches('/')
                .to_string();

            if let Some(host_config) = inspect.host_config.as_ref() {
                if host_config.privileged == Some(true) {
                    risks.push(DockerSecurityRisk {
                        severity: "critical".to_string(),
                        finding: "Privileged container".to_string(),
                        evidence: format!("container={} privileged=true", container_name),
                    });
                }

                Self::push_host_namespace_risk(
                    &mut risks,
                    &container_name,
                    "network_mode",
                    host_config.network_mode.as_deref(),
                    "host network namespace",
                    "high",
                );
                Self::push_host_namespace_risk(
                    &mut risks,
                    &container_name,
                    "pid_mode",
                    host_config.pid_mode.as_deref(),
                    "host PID namespace",
                    "high",
                );
                Self::push_host_namespace_risk(
                    &mut risks,
                    &container_name,
                    "ipc_mode",
                    host_config.ipc_mode.as_deref(),
                    "host IPC namespace",
                    "medium",
                );
                Self::push_host_namespace_risk(
                    &mut risks,
                    &container_name,
                    "userns_mode",
                    host_config.userns_mode.as_deref(),
                    "host user namespace",
                    "medium",
                );

                if host_config
                    .cgroupns_mode
                    .as_ref()
                    .map(|mode| mode.as_ref() == "host")
                    .unwrap_or(false)
                {
                    risks.push(DockerSecurityRisk {
                        severity: "medium".to_string(),
                        finding: "Host cgroup namespace".to_string(),
                        evidence: format!("container={} cgroupns_mode=host", container_name),
                    });
                }

                if let Some(caps) = host_config.cap_add.as_ref() {
                    for cap in caps {
                        if let Some((severity, normalized)) = Self::dangerous_capability(cap) {
                            risks.push(DockerSecurityRisk {
                                severity: severity.to_string(),
                                finding: "Dangerous Linux capability".to_string(),
                                evidence: format!(
                                    "container={} cap_add={}",
                                    container_name, normalized
                                ),
                            });
                        }
                    }
                }

                if let Some(security_opts) = host_config.security_opt.as_ref() {
                    for opt in security_opts {
                        let lower = opt.to_lowercase();
                        if lower == "seccomp=unconfined" || lower == "apparmor=unconfined" {
                            risks.push(DockerSecurityRisk {
                                severity: "high".to_string(),
                                finding: "Container security profile disabled".to_string(),
                                evidence: format!(
                                    "container={} security_opt={}",
                                    container_name, opt
                                ),
                            });
                        } else if lower == "no-new-privileges:false" {
                            risks.push(DockerSecurityRisk {
                                severity: "medium".to_string(),
                                finding: "no-new-privileges disabled".to_string(),
                                evidence: format!(
                                    "container={} security_opt={}",
                                    container_name, opt
                                ),
                            });
                        }
                    }
                }
            }

            if inspect
                .app_armor_profile
                .as_deref()
                .map(|profile| profile.eq_ignore_ascii_case("unconfined"))
                .unwrap_or(false)
            {
                risks.push(DockerSecurityRisk {
                    severity: "high".to_string(),
                    finding: "AppArmor unconfined".to_string(),
                    evidence: format!("container={} app_armor_profile=unconfined", container_name),
                });
            }

            if let Some(mounts) = inspect.mounts.as_ref() {
                for mount in mounts {
                    let mount_type = mount.typ.as_ref().map(|typ| typ.as_ref()).unwrap_or("");
                    if mount_type != "bind" {
                        continue;
                    }

                    let source = mount.source.as_deref().unwrap_or_default();
                    let destination = mount.destination.as_deref().unwrap_or_default();
                    let writable = mount.rw.unwrap_or(false);

                    if let Some((severity, label)) = Self::sensitive_mount(source, writable) {
                        risks.push(DockerSecurityRisk {
                            severity: severity.to_string(),
                            finding: "Sensitive host bind mount".to_string(),
                            evidence: format!(
                                "container={} source={} target={} rw={} surface={}",
                                container_name, source, destination, writable, label
                            ),
                        });
                    }
                }
            }
        }

        Ok(risks)
    }

    fn push_host_namespace_risk(
        risks: &mut Vec<DockerSecurityRisk>,
        container_name: &str,
        key: &str,
        value: Option<&str>,
        finding: &str,
        severity: &str,
    ) {
        if value == Some("host") {
            risks.push(DockerSecurityRisk {
                severity: severity.to_string(),
                finding: finding.to_string(),
                evidence: format!("container={} {}=host", container_name, key),
            });
        }
    }

    fn dangerous_capability(capability: &str) -> Option<(&'static str, String)> {
        let normalized = capability
            .trim()
            .trim_start_matches("CAP_")
            .to_ascii_uppercase();

        match normalized.as_str() {
            "ALL" | "SYS_ADMIN" | "SYS_MODULE" => Some(("critical", normalized)),
            "SYS_PTRACE" | "NET_ADMIN" | "SYS_RAWIO" | "DAC_READ_SEARCH" | "DAC_OVERRIDE" => {
                Some(("high", normalized))
            }
            _ => None,
        }
    }

    fn sensitive_mount(source: &str, writable: bool) -> Option<(&'static str, &'static str)> {
        const EXACT_HIGH: &[(&str, &str)] = &[
            ("/", "host_root"),
            ("/var/run/docker.sock", "docker_socket"),
            ("/run/docker.sock", "docker_socket"),
            ("/run/containerd/containerd.sock", "containerd_socket"),
        ];
        const PREFIXES: &[(&str, &str)] = &[
            ("/etc", "host_config"),
            ("/root", "root_home"),
            ("/proc", "procfs"),
            ("/sys", "sysfs"),
            ("/var/lib/docker", "docker_state"),
            ("/var/lib/containerd", "containerd_state"),
            ("/var/lib/kubelet", "kubelet_state"),
            ("/opt/cni/bin", "cni_plugins"),
        ];

        for (path, label) in EXACT_HIGH {
            if source == *path {
                return Some(("critical", label));
            }
        }

        for (path, label) in PREFIXES {
            if source == *path || source.starts_with(&format!("{}/", path.trim_end_matches('/'))) {
                return Some((if writable { "high" } else { "medium" }, label));
            }
        }

        None
    }

    pub async fn start_container(&self, id: &str) -> Result<(), String> {
        tracing::info!("Starting container: {}", id);
        self.docker
            .start_container(id, None::<StartContainerOptions>)
            .await
            .map_err(|e| {
                tracing::error!("Failed to start container {}: {}", id, e);
                format!("Failed to start container: {}", e)
            })
    }

    pub async fn stop_container(&self, id: &str) -> Result<(), String> {
        tracing::info!("Stopping container: {}", id);
        self.docker
            .stop_container(id, None::<StopContainerOptions>)
            .await
            .map_err(|e| {
                tracing::error!("Failed to stop container {}: {}", id, e);
                format!("Failed to stop container: {}", e)
            })
    }

    pub async fn restart_container(&self, id: &str) -> Result<(), String> {
        tracing::info!("Restarting container: {}", id);
        self.docker
            .restart_container(id, None::<RestartContainerOptions>)
            .await
            .map_err(|e| {
                tracing::error!("Failed to restart container {}: {}", id, e);
                format!("Failed to restart container: {}", e)
            })
    }

    /// Создает поток логов контейнера с поддержкой фильтрации.
    ///
    /// # Аргументы
    /// * `id` - ID контейнера
    /// * `since` - Опциональный timestamp (Unix), начиная с которого нужны логи
    /// * `tail` - Количество строк с конца ("all" или число)
    pub fn logs_stream(
        &self,
        id: &str,
        since: Option<i64>,
        tail: Option<String>,
    ) -> impl futures_util::Stream<Item = Result<String, String>> {
        use futures_util::StreamExt;
        tracing::info!(
            "Creating log stream for container: {} (since: {:?}, tail: {:?})",
            id,
            since,
            tail
        );

        let options = Some(LogsOptions {
            follow: true,
            stdout: true,
            stderr: true,
            tail: tail.unwrap_or_else(|| "100".to_string()),
            since: since.unwrap_or(0) as i32,
            ..Default::default()
        });

        self.docker.logs(id, options).map(|res| match res {
            Ok(log) => Ok(log.to_string()),
            Err(e) => Err(format!("Log error: {}", e)),
        })
    }
}
