use std::process::Command;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct DiskUsageBreakdown {
    pub target_size: String,
    pub node_modules_size: String,
    pub docker_size: String,
    pub logs_size: String,
}

pub struct DiskOps;

impl DiskOps {
    pub fn get_usage(root_dir: &str) -> DiskUsageBreakdown {
        let target = Self::get_dir_size(&format!("{}/target", root_dir));
        let node_modules = Self::get_dir_size(&format!("{}/frontend/node_modules", root_dir));
        let logs = Self::get_logs_size();
        let docker = Self::get_docker_size();

        DiskUsageBreakdown {
            target_size: target,
            node_modules_size: node_modules,
            docker_size: docker,
            logs_size: logs,
        }
    }

    fn get_dir_size(path: &str) -> String {
        let output = Command::new("du")
            .arg("-sh")
            .arg(path)
            .output();

        match output {
            Ok(o) if o.status.success() => {
                let out = String::from_utf8_lossy(&o.stdout);
                out.split_whitespace().next().unwrap_or("0B").to_string()
            }
            _ => "0B".to_string(),
        }
    }

    fn get_logs_size() -> String {
         let output = Command::new("journalctl")
            .arg("--disk-usage")
            .output();
         // Output format: "Archived and active journals take up 16.0M in the file system."
         // We need to parse this. Or just use du on /var/log/journal if we have access.
         // Let's rely on journalctl output parsing for now, or just say "Unknown".
         
        match output {
            Ok(o) if o.status.success() => {
                let out = String::from_utf8_lossy(&o.stdout);
                // Extract size string? It's human readable text.
                // Simple regex or split?
                // "take up 16.0M"
                 out.split("take up ").nth(1)
                    .and_then(|s| s.split(" ").next())
                    .unwrap_or("Unknown")
                    .to_string()
            }
            _ => "Unknown".to_string(),
        }
    }

    fn get_docker_size() -> String {
        // docker system df --format "{{.Size}}" prints multiple lines (Images, Containers, Volumes, Build Cache)
        // We probably want a summary or just "Total".
        // simpler: docker system df -v ? 
        // Let's just run `du -sh /var/lib/docker` if we are root?
        // Since we are running as root (currently), du /var/lib/docker is accurate.
        
        Self::get_dir_size("/var/lib/docker")
    }

    pub async fn clean_target(root_dir: &str) -> Result<String, String> {
        let output = Command::new("cargo")
            .arg("clean")
            .current_dir(root_dir)
            .output()
            .map_err(|e| e.to_string())?;

        if output.status.success() {
             Ok("Target cleaned (cargo clean executed).".to_string())
        } else {
             Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    pub async fn clean_node_modules(root_dir: &str) -> Result<String, String> {
        let path = format!("{}/frontend/node_modules", root_dir);
        let output = Command::new("rm")
            .arg("-rf")
            .arg(path)
            .output()
            .map_err(|e| e.to_string())?;
            
        if output.status.success() {
             Ok("Node modules deleted.".to_string())
        } else {
             Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    pub async fn clean_docker() -> Result<String, String> {
         let output = Command::new("docker")
            .arg("system")
            .arg("prune")
            .arg("-af") // -a: all unused images, -f: force
            .output()
            .map_err(|e| e.to_string())?;

        if output.status.success() {
             let out = String::from_utf8_lossy(&output.stdout).to_string();
             if out.trim().is_empty() {
                 Ok("Docker Prune finished (No output).".to_string())
             } else {
                 Ok(out)
             }
        } else {
             Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }
    
    pub async fn clean_logs() -> Result<String, String> {
         let output = Command::new("journalctl")
            .arg("--vacuum-time=1d") 
            .output()
            .map_err(|e| e.to_string())?;

        if output.status.success() {
         let out = String::from_utf8_lossy(&output.stderr).to_string(); // Journalctl prints to stderr
         if out.trim().is_empty() {
              Ok("Logs vacuumed (No output).".to_string())
         } else {
              Ok(out)
         }
    } else {
         Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
    }
}
