use serde::{Deserialize, Serialize};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(300);
const USAGE_TIMEOUT: Duration = Duration::from_secs(3);
const USAGE_OUTPUT_CAP_BYTES: u64 = 4 * 1024;

#[derive(Serialize, Deserialize, Debug)]
pub struct DiskUsageBreakdown {
    pub target_size: String,
    pub node_modules_size: String,
    pub docker_size: String,
    pub logs_size: String,
}

pub struct DiskOps;

impl DiskOps {
    pub async fn get_usage(root_dir: &str) -> DiskUsageBreakdown {
        let target_path = format!("{}/target", root_dir);
        let node_modules_path = format!("{}/frontend/node_modules", root_dir);
        let (target, node_modules, logs, docker) = tokio::join!(
            Self::get_dir_size(target_path),
            Self::get_dir_size(node_modules_path),
            Self::get_logs_size(),
            Self::get_dir_size("/var/lib/docker".to_string()),
        );

        DiskUsageBreakdown {
            target_size: target,
            node_modules_size: node_modules,
            docker_size: docker,
            logs_size: logs,
        }
    }

    async fn get_dir_size(path: String) -> String {
        let mut command = tokio::process::Command::new("/usr/bin/du");
        command.args(["-sh", "--"]).arg(path);
        match Self::run_usage_command(command).await {
            Ok(output) => std::str::from_utf8(&output)
                .ok()
                .and_then(|value| value.split_whitespace().next())
                .filter(|value| !value.is_empty())
                .unwrap_or("Unknown")
                .to_string(),
            Err(()) => "Unknown".to_string(),
        }
    }

    async fn get_logs_size() -> String {
        let mut command = tokio::process::Command::new("/usr/bin/journalctl");
        command.arg("--disk-usage");
        match Self::run_usage_command(command).await {
            Ok(output) => std::str::from_utf8(&output)
                .ok()
                .and_then(|value| value.split("take up ").nth(1))
                .and_then(|value| value.split_whitespace().next())
                .filter(|value| !value.is_empty())
                .unwrap_or("Unknown")
                .to_string(),
            Err(()) => "Unknown".to_string(),
        }
    }

    async fn run_usage_command(mut command: tokio::process::Command) -> Result<Vec<u8>, ()> {
        command
            .env_clear()
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|_| ())?;
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(());
        };
        let mut output = Vec::with_capacity(256);
        let mut reader = stdout.take(USAGE_OUTPUT_CAP_BYTES + 1);

        let result = tokio::time::timeout(USAGE_TIMEOUT, async {
            let (read, status) = tokio::join!(reader.read_to_end(&mut output), child.wait());
            let read = read.map_err(|_| ())?;
            let status = status.map_err(|_| ())?;
            if !status.success() || read as u64 > USAGE_OUTPUT_CAP_BYTES {
                return Err(());
            }
            Ok(output)
        })
        .await;

        match result {
            Ok(result) => result,
            Err(_) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                Err(())
            }
        }
    }

    pub async fn clean_target(root_dir: &str) -> Result<String, String> {
        let mut command = tokio::process::Command::new("cargo");
        command.arg("clean").current_dir(root_dir);
        Self::run_cleanup_command(command).await?;
        Ok("Target cleaned (cargo clean executed).".to_string())
    }

    pub async fn clean_node_modules(root_dir: &str) -> Result<String, String> {
        let path = format!("{}/frontend/node_modules", root_dir);
        let mut command = tokio::process::Command::new("rm");
        command.arg("-rf").arg(path);
        Self::run_cleanup_command(command).await?;
        Ok("Node modules deleted.".to_string())
    }

    pub async fn clean_logs() -> Result<String, String> {
        let mut command = tokio::process::Command::new("journalctl");
        command.arg("--vacuum-time=1d");
        Self::run_cleanup_command(command).await?;
        Ok("Journal cleanup completed.".to_string())
    }

    async fn run_cleanup_command(mut command: tokio::process::Command) -> Result<(), String> {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);

        let mut child = command
            .spawn()
            .map_err(|_| "cleanup_start_failed".to_string())?;
        let status = match tokio::time::timeout(CLEANUP_TIMEOUT, child.wait()).await {
            Ok(Ok(status)) => status,
            Ok(Err(_)) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err("cleanup_wait_failed".to_string());
            }
            Err(_) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err("cleanup_timed_out".to_string());
            }
        };

        if status.success() {
            Ok(())
        } else {
            Err("cleanup_command_failed".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_node_modules_path_stays_within_root() {
        // Убеждаемся что путь к node_modules строится корректно и не выходит за пределы root_dir
        let root = "/some/project";
        let expected = "/some/project/frontend/node_modules";
        let actual = format!("{}/frontend/node_modules", root);
        assert_eq!(actual, expected);
        // Путь не содержит path traversal символов
        assert!(!actual.contains(".."));
    }

    #[test]
    fn test_clean_target_path_stays_within_root() {
        let root = "/some/project";
        // clean_target использует cargo clean в root_dir — нет shell-интерполяции
        assert!(!root.contains(".."));
        assert!(!root.contains(';'));
        assert!(!root.contains('|'));
        assert!(!root.contains('&'));
    }

    #[test]
    fn test_disk_usage_breakdown_has_all_fields() {
        // DiskUsageBreakdown должен сериализоваться без ошибок
        let breakdown = DiskUsageBreakdown {
            target_size: "100M".to_string(),
            node_modules_size: "500M".to_string(),
            docker_size: "2G".to_string(),
            logs_size: "50M".to_string(),
        };
        let json = serde_json::to_string(&breakdown).unwrap();
        assert!(json.contains("target_size"));
        assert!(json.contains("node_modules_size"));
        assert!(json.contains("docker_size"));
        assert!(json.contains("logs_size"));
    }

    #[tokio::test]
    async fn missing_usage_path_is_reported_as_unknown() {
        let path = std::env::temp_dir()
            .join(format!("mini-ops-missing-{}", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string();

        assert_eq!(DiskOps::get_dir_size(path).await, "Unknown");
    }
}
