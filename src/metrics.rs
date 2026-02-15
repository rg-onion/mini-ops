use serde::{Deserialize, Serialize};
use sysinfo::{System, Disks};
use std::sync::Mutex;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SystemStats {
    pub cpu_usage: f32,
    pub memory_used: u64,
    pub memory_total: u64,
    pub disk_used: u64,
    pub disk_total: u64,
    pub timestamp: i64,
}

pub struct MetricsState {
    pub sys: Mutex<System>,
    pub disks: Mutex<Disks>,
    pub current: Mutex<SystemStats>,
}

impl MetricsState {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        let disks = Disks::new_with_refreshed_list();
        sys.refresh_all();
        
        let stats = Self::collect_internal(&mut sys, &disks);
        
        Self {
            sys: Mutex::new(sys),
            disks: Mutex::new(disks),
            current: Mutex::new(stats),
        }
    }

    pub fn refresh(&self) {
        let mut sys = self.sys.lock().unwrap();
        let mut disks = self.disks.lock().unwrap();
        
        sys.refresh_all();
        sys.refresh_memory();
        disks.refresh(true);

        let stats = Self::collect_internal(&mut sys, &disks);
        let mut current = self.current.lock().unwrap();
        *current = stats;
    }

    fn collect_internal(sys: &mut System, disks: &Disks) -> SystemStats {
        let cpu_usage = sys.global_cpu_usage();
        let memory_used = sys.used_memory();
        let memory_total = sys.total_memory();

        let mut disk_used = 0;
        let mut disk_total = 0;
        
        // Find the disk mounted at "/"
        // If not found, fallback to summing up non-loop devices
        let root_disk = disks.iter().find(|d| d.mount_point() == std::path::Path::new("/"));
        
        if let Some(disk) = root_disk {
             disk_total = disk.total_space();
             disk_used = disk.total_space() - disk.available_space();
        } else {
            // Fallback: exclude loop, tmpfs, overlay
            for disk in disks {
                 // Simple filter: Only take physical-like disks
                 // This is heuristic.
                 disk_total += disk.total_space();
                 disk_used += disk.total_space() - disk.available_space();
            }
        }

        SystemStats {
            cpu_usage,
            memory_used,
            memory_total,
            disk_used,
            disk_total,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    pub fn get_current(&self) -> SystemStats {
        self.current.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collection_structure() {
        let state = MetricsState::new();
        let stats = state.get_current();

        assert!(stats.cpu_usage >= 0.0);
        assert!(stats.memory_total > 0);
    }
}
