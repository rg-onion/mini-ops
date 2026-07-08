use sqlx::SqlitePool;

const DEFAULT_METRICS_RETENTION_HOURS: i64 = 168;
const DEFAULT_SSH_LOGINS_RETENTION_DAYS: i64 = 90;
const MAX_METRICS_RETENTION_HOURS: i64 = 24 * 365 * 5;
const MAX_SSH_LOGINS_RETENTION_DAYS: i64 = 365 * 5;

#[derive(Debug, Clone, Copy)]
pub struct RetentionConfig {
    pub metrics_retention_hours: i64,
    pub ssh_logins_retention_days: i64,
}

impl RetentionConfig {
    pub fn from_env() -> Self {
        Self {
            metrics_retention_hours: parse_bounded_i64(
                std::env::var("METRICS_RETENTION_HOURS").ok().as_deref(),
                DEFAULT_METRICS_RETENTION_HOURS,
                1,
                MAX_METRICS_RETENTION_HOURS,
            ),
            ssh_logins_retention_days: parse_bounded_i64(
                std::env::var("SSH_LOGINS_RETENTION_DAYS").ok().as_deref(),
                DEFAULT_SSH_LOGINS_RETENTION_DAYS,
                1,
                MAX_SSH_LOGINS_RETENTION_DAYS,
            ),
        }
    }
}

fn parse_bounded_i64(value: Option<&str>, default: i64, min: i64, max: i64) -> i64 {
    value
        .and_then(|value| value.trim().parse::<i64>().ok())
        .map(|value| value.clamp(min, max))
        .unwrap_or(default)
}

pub async fn init_indexes(db: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_metrics_timestamp
            ON metrics(timestamp)",
    )
    .execute(db)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_ssh_logins_timestamp
            ON ssh_logins(timestamp)",
    )
    .execute(db)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_ssh_logins_ip_timestamp
            ON ssh_logins(ip, timestamp)",
    )
    .execute(db)
    .await?;

    Ok(())
}

pub async fn prune_metrics(
    db: &SqlitePool,
    now: i64,
    retention_hours: i64,
) -> Result<u64, sqlx::Error> {
    let cutoff = now.saturating_sub(retention_hours.saturating_mul(3600));
    let result = sqlx::query("DELETE FROM metrics WHERE timestamp < ?")
        .bind(cutoff)
        .execute(db)
        .await?;

    Ok(result.rows_affected())
}

pub async fn prune_ssh_logins(
    db: &SqlitePool,
    now: i64,
    retention_days: i64,
) -> Result<u64, sqlx::Error> {
    let cutoff = now.saturating_sub(retention_days.saturating_mul(24 * 3600));
    let result = sqlx::query("DELETE FROM ssh_logins WHERE timestamp < ?")
        .bind(cutoff)
        .execute(db)
        .await?;

    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    #[test]
    fn parse_bounded_i64_uses_default_for_missing_or_invalid_values() {
        assert_eq!(parse_bounded_i64(None, 10, 1, 100), 10);
        assert_eq!(parse_bounded_i64(Some("not-a-number"), 10, 1, 100), 10);
    }

    #[test]
    fn parse_bounded_i64_clamps_out_of_range_values() {
        assert_eq!(parse_bounded_i64(Some("0"), 10, 1, 100), 1);
        assert_eq!(parse_bounded_i64(Some("101"), 10, 1, 100), 100);
        assert_eq!(parse_bounded_i64(Some("42"), 10, 1, 100), 42);
    }

    #[tokio::test]
    async fn prune_metrics_deletes_rows_older_than_cutoff() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory sqlite should connect");

        sqlx::query(
            "CREATE TABLE metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cpu_usage REAL,
                memory_used INTEGER,
                memory_total INTEGER,
                disk_used INTEGER,
                disk_total INTEGER,
                timestamp INTEGER
            )",
        )
        .execute(&pool)
        .await
        .expect("metrics table should initialize");

        for timestamp in [1_000_i64, 9_000] {
            sqlx::query(
                "INSERT INTO metrics (
                    cpu_usage, memory_used, memory_total, disk_used, disk_total, timestamp
                ) VALUES (1.0, 1, 2, 3, 4, ?)",
            )
            .bind(timestamp)
            .execute(&pool)
            .await
            .expect("metric row should insert");
        }

        let deleted = prune_metrics(&pool, 10_000, 1).await.unwrap();
        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM metrics")
            .fetch_one(&pool)
            .await
            .unwrap();

        assert_eq!(deleted, 1);
        assert_eq!(remaining, 1);
    }

    #[tokio::test]
    async fn prune_ssh_logins_deletes_rows_older_than_cutoff() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory sqlite should connect");

        sqlx::query(
            "CREATE TABLE ssh_logins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT NOT NULL,
                ip TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                method TEXT NOT NULL,
                notified BOOLEAN DEFAULT 0
            )",
        )
        .execute(&pool)
        .await
        .expect("ssh_logins table should initialize");

        for timestamp in [1_000_i64, 90_000] {
            sqlx::query(
                "INSERT INTO ssh_logins (user, ip, timestamp, method, notified)
                VALUES ('root', '127.0.0.1', ?, 'ssh', 1)",
            )
            .bind(timestamp)
            .execute(&pool)
            .await
            .expect("ssh login row should insert");
        }

        let deleted = prune_ssh_logins(&pool, 100_000, 1).await.unwrap();
        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ssh_logins")
            .fetch_one(&pool)
            .await
            .unwrap();

        assert_eq!(deleted, 1);
        assert_eq!(remaining, 1);
    }
}
