use bollard::query_parameters::{ListContainersOptions, RestartContainerOptions, StartContainerOptions, StopContainerOptions, LogsOptions};
use bollard::Docker;
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

        let containers = self.docker.list_containers(Some(options)).await
            .map_err(|e| format!("Failed to list containers: {}", e))?;

        let result = containers.into_iter().map(|c| {
            let name = c.names.clone().unwrap_or_default()
                .first().cloned().unwrap_or_else(|| "unknown".to_string())
                .trim_start_matches('/').to_string();

            let ports = c.ports.clone().unwrap_or_default().iter()
                .map(|p| format!("{}:{}", p.public_port.unwrap_or(0), p.private_port))
                .collect::<Vec<_>>().join(", ");

            ContainerInfo {
                id: c.id.unwrap_or_default(),
                name,
                image: c.image.unwrap_or_default(),
                status: c.status.unwrap_or_default(),
                state: c.state.map(|s| s.to_string()).unwrap_or_else(|| "unknown".to_string()),
                ports,
            }
        }).collect();

        Ok(result)
    }

    pub async fn start_container(&self, id: &str) -> Result<(), String> {
        tracing::info!("Starting container: {}", id);
        self.docker.start_container(id, None::<StartContainerOptions>).await
            .map_err(|e| {
                tracing::error!("Failed to start container {}: {}", id, e);
                format!("Failed to start container: {}", e)
            })
    }

    pub async fn stop_container(&self, id: &str) -> Result<(), String> {
        tracing::info!("Stopping container: {}", id);
        self.docker.stop_container(id, None::<StopContainerOptions>).await
            .map_err(|e| {
                tracing::error!("Failed to stop container {}: {}", id, e);
                format!("Failed to stop container: {}", e)
            })
    }

    pub async fn restart_container(&self, id: &str) -> Result<(), String> {
        tracing::info!("Restarting container: {}", id);
        self.docker.restart_container(id, None::<RestartContainerOptions>).await
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
        tail: Option<String>
    ) -> impl futures_util::Stream<Item = Result<String, String>> {
        use futures_util::StreamExt;
        tracing::info!("Creating log stream for container: {} (since: {:?}, tail: {:?})", id, since, tail);

        let options = Some(LogsOptions {
            follow: true,
            stdout: true,
            stderr: true,
            tail: tail.unwrap_or_else(|| "100".to_string()),
            since: since.unwrap_or(0) as i32,
            ..Default::default()
        });

        self.docker.logs(id, options).map(|res| {
            match res {
                Ok(log) => Ok(log.to_string()),
                Err(e) => Err(format!("Log error: {}", e)),
            }
        })
    }
}
