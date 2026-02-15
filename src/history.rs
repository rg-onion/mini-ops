use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentRecord {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub action: String, // "update", "rollback"
    pub details: String, 
    pub status: String, // "success", "failed"
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
            history.remove(0);
        }

        let content = serde_json::to_string_pretty(&history).unwrap_or_default();
        let _ = fs::write(&self.file_path, content);
    }
}
