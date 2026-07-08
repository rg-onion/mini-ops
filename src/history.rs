use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentRecord {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub action: String, // "update", "rollback"
    pub details: String,
    pub status: String, // "in_progress", "success", "failed"
    pub image_id: Option<String>,
    pub container_name: Option<String>,
}

#[derive(Clone)]
pub struct HistoryManager {
    file_path: String,
}

impl HistoryManager {
    pub fn new(file_path: &str) -> Self {
        Self {
            file_path: file_path.to_string(),
        }
    }

    pub fn get_history(&self) -> Vec<DeploymentRecord> {
        if !Path::new(&self.file_path).exists() {
            return Vec::new();
        }

        let content = fs::read_to_string(&self.file_path).unwrap_or_else(|_| "[]".to_string());
        serde_json::from_str(&content).unwrap_or_else(|_| Vec::new())
    }

    pub fn add_record(&self, record: DeploymentRecord) {
        let mut history = self.get_history();
        history.push(record);

        // Keep only last 50 records
        if history.len() > 50 {
            let overflow = history.len() - 50;
            history.drain(0..overflow);
        }

        self.write_history(&history);
    }

    pub fn update_record_status(&self, id: &str, status: &str, details: &str) -> bool {
        let mut history = self.get_history();
        let Some(record) = history.iter_mut().rev().find(|record| record.id == id) else {
            return false;
        };

        record.status = status.to_string();
        record.details = details.to_string();
        self.write_history(&history);
        true
    }

    fn write_history(&self, history: &[DeploymentRecord]) {
        let content = serde_json::to_string_pretty(history).unwrap_or_default();
        let _ = fs::write(&self.file_path, content);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_history_path() -> String {
        let mut path = std::env::temp_dir();
        path.push(format!("mini-ops-history-{}.json", uuid::Uuid::new_v4()));
        path.to_string_lossy().into_owned()
    }

    fn record(id: &str, status: &str) -> DeploymentRecord {
        DeploymentRecord {
            id: id.to_string(),
            timestamp: Utc::now(),
            action: "update".to_string(),
            details: "initial".to_string(),
            status: status.to_string(),
            image_id: None,
            container_name: Some("mini-ops".to_string()),
        }
    }

    #[test]
    fn update_record_status_updates_existing_record() {
        let path = temp_history_path();
        let manager = HistoryManager::new(&path);

        manager.add_record(record("first", "in_progress"));

        assert!(manager.update_record_status("first", "success", "completed"));

        let history = manager.get_history();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, "success");
        assert_eq!(history[0].details, "completed");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn update_record_status_returns_false_for_missing_record() {
        let path = temp_history_path();
        let manager = HistoryManager::new(&path);

        manager.add_record(record("first", "in_progress"));

        assert!(!manager.update_record_status("missing", "failed", "not found"));
        assert_eq!(manager.get_history()[0].status, "in_progress");

        let _ = fs::remove_file(path);
    }
}
