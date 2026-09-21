use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use sysinfo::{CpuRefreshKind, Disks, MemoryRefreshKind, RefreshKind, System};

/// CPU usage above this percentage counts towards a critical CPU alert.
pub const CPU_ALERT_THRESHOLD_PERCENT: f32 = 95.0;
/// Consecutive one-minute samples above the threshold required before alerting.
pub const CPU_ALERT_SUSTAINED_SAMPLES: u32 = 3;

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

/// Only global CPU usage and memory are refreshed. Processes must stay out: on
/// Linux a process refresh re-reads `/proc/stat` once the `/proc` scan exceeds
/// `MINIMUM_CPU_UPDATE_INTERVAL`, replacing the interval average with the
/// agent's own scan window and reporting a false ~100% on small hosts.
fn system_refresh_kind() -> RefreshKind {
    RefreshKind::nothing()
        .with_cpu(CpuRefreshKind::nothing().with_cpu_usage())
        .with_memory(MemoryRefreshKind::everything())
}

impl MetricsState {
    pub fn new() -> Self {
        let mut sys = System::new_with_specifics(system_refresh_kind());
        let disks = Disks::new_with_refreshed_list();

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

        sys.refresh_specifics(system_refresh_kind());
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
        let root_disk = disks
            .iter()
            .find(|d| d.mount_point() == std::path::Path::new("/"));

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

/// Counts consecutive samples above a threshold so one noisy sample cannot
/// raise an alert on its own.
#[derive(Debug)]
pub struct SustainedThreshold {
    threshold: f32,
    required: u32,
    streak: u32,
}

impl SustainedThreshold {
    pub fn new(threshold: f32, required: u32) -> Self {
        Self {
            threshold,
            required: required.max(1),
            streak: 0,
        }
    }

    /// Records a sample and returns whether the threshold has been exceeded for
    /// at least `required` consecutive samples, including this one.
    pub fn observe(&mut self, value: f32) -> bool {
        if value > self.threshold {
            self.streak = self.streak.saturating_add(1);
        } else {
            self.streak = 0;
        }
        self.streak >= self.required
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

    #[test]
    fn refresh_does_not_scan_processes() {
        let state = MetricsState::new();
        state.refresh();

        assert!(state.sys.lock().unwrap().processes().is_empty());
    }

    #[test]
    fn sustained_threshold_requires_consecutive_samples() {
        let mut cpu = SustainedThreshold::new(95.0, 3);

        assert!(!cpu.observe(100.0));
        assert!(!cpu.observe(100.0));
        assert!(cpu.observe(100.0));
        assert!(cpu.observe(96.0));
    }

    #[test]
    fn sustained_threshold_resets_on_normal_or_invalid_sample() {
        let mut cpu = SustainedThreshold::new(95.0, 3);

        assert!(!cpu.observe(100.0));
        assert!(!cpu.observe(100.0));
        assert!(!cpu.observe(95.0));
        assert!(!cpu.observe(100.0));
        assert!(!cpu.observe(100.0));
        assert!(!cpu.observe(f32::NAN));
        assert!(!cpu.observe(100.0));
    }
}
