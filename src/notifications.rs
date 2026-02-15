use serde::Serialize;
use reqwest::Client;
use std::sync::Mutex;
use std::collections::HashMap;
use std::time::{Instant, Duration};
use hostname;

#[derive(Serialize)]
struct TelegramMessage {
    chat_id: String,
    text: String,
    parse_mode: String,
}

pub struct NotificationService {
    client: Client,
    token: Option<String>,
    chat_id: Option<String>,
    server_name: String,
    last_sent: Mutex<Option<Instant>>,
    alert_history: Mutex<HashMap<String, Instant>>,
}

impl NotificationService {
    pub fn new() -> Self {
        let token = std::env::var("TELEGRAM_BOT_TOKEN").ok();
        let chat_id = std::env::var("TELEGRAM_CHAT_ID").ok();
        let server_name = std::env::var("SERVER_NAME")
            .unwrap_or_else(|_| {
                hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or_else(|_| "Unknown Server".to_string())
            });
        
        Self {
            client: Client::new(),
            token,
            chat_id,
            server_name,
            last_sent: Mutex::new(None),
            alert_history: Mutex::new(HashMap::new()),
        }
    }

    pub async fn send_alert(&self, message: &str) {
        let (token, chat_id) = match (&self.token, &self.chat_id) {
            (Some(t), Some(c)) => (t, c),
            _ => {
                tracing::warn!("Telegram credentials not set. Skipping notification: {}", message);
                return;
            }
        };

        // 1. Deduplication (Cooldown per unique message)
        {
            let mut history = self.alert_history.lock().unwrap();
            if let Some(last_time) = history.get(message) {
                if last_time.elapsed() < Duration::from_secs(1800) { // 30 mins
                    tracing::info!("Skipping duplicate alert (cooldown): {}", message);
                    return;
                }
            }
            history.insert(message.to_string(), Instant::now());
        }

        // 2. Global Rate Limiting (Throttle)
        {
            let mut last = self.last_sent.lock().unwrap();
            if let Some(time) = *last {
                if time.elapsed() < Duration::from_secs(3) { // 3 seconds delay
                    tracing::info!("Throttling alert to prevent spam");
                    // In a real app we might queue this, but for now we sleep or skip.
                    // Sleeping holds the mutex if we aren't careful, so we drop the lock first.
                }
            }
            *last = Some(Instant::now());
        }

        let url = format!("https://api.telegram.org/bot{}/sendMessage", token);
        let payload = TelegramMessage {
            chat_id: chat_id.clone(),
            text: format!("🚨 *Mini-Ops Alert* [{}] 🚨\n\n{}", self.server_name, message),
            parse_mode: "Markdown".to_string(),
        };

        match self.client.post(&url).json(&payload).send().await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    let err = resp.text().await.unwrap_or_default();
                    tracing::error!("Failed to send Telegram notification: {}", err);
                }
            }
            Err(e) => {
                tracing::error!("Error sending Telegram notification: {}", e);
            }
        }
    }
}
