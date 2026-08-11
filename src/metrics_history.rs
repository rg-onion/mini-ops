use crate::metrics::SystemStats;
use serde::Serialize;
use sqlx::{Row, SqlitePool};
use std::collections::{BTreeMap, btree_map::Entry};

const MAX_RESPONSE_POINTS: usize = 1_500;
const MAX_SOURCE_ROWS: usize = 12_000;
const NOMINAL_RAW_INTERVAL_SECONDS: i64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HistoryWindow {
    OneHour,
    SixHours,
    TwentyFourHours,
    SevenDays,
}

impl HistoryWindow {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "1h" => Some(Self::OneHour),
            "6h" => Some(Self::SixHours),
            "24h" => Some(Self::TwentyFourHours),
            "7d" => Some(Self::SevenDays),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::OneHour => "1h",
            Self::SixHours => "6h",
            Self::TwentyFourHours => "24h",
            Self::SevenDays => "7d",
        }
    }

    fn seconds(self) -> i64 {
        match self {
            Self::OneHour => 60 * 60,
            Self::SixHours => 6 * 60 * 60,
            Self::TwentyFourHours => 24 * 60 * 60,
            Self::SevenDays => 7 * 24 * 60 * 60,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestedResolution {
    Auto,
    Raw,
    FiveMinutes,
    OneHour,
}

impl RequestedResolution {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "raw" => Some(Self::Raw),
            "5m" => Some(Self::FiveMinutes),
            "1h" => Some(Self::OneHour),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EffectiveResolution {
    Raw,
    FiveMinutes,
    OneHour,
}

impl EffectiveResolution {
    fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::FiveMinutes => "5m",
            Self::OneHour => "1h",
        }
    }

    fn interval_seconds(self) -> i64 {
        match self {
            Self::Raw => NOMINAL_RAW_INTERVAL_SECONDS,
            Self::FiveMinutes => 5 * 60,
            Self::OneHour => 60 * 60,
        }
    }

    fn coarser(self) -> Option<Self> {
        match self {
            Self::Raw => Some(Self::FiveMinutes),
            Self::FiveMinutes => Some(Self::OneHour),
            Self::OneHour => None,
        }
    }
}

impl From<RequestedResolution> for EffectiveResolution {
    fn from(value: RequestedResolution) -> Self {
        match value {
            RequestedResolution::Auto | RequestedResolution::Raw => Self::Raw,
            RequestedResolution::FiveMinutes => Self::FiveMinutes,
            RequestedResolution::OneHour => Self::OneHour,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HistoryQuery {
    window: HistoryWindow,
    resolution: RequestedResolution,
}

impl HistoryQuery {
    fn initial_resolution(self) -> EffectiveResolution {
        if self.resolution != RequestedResolution::Auto {
            return self.resolution.into();
        }

        [
            EffectiveResolution::Raw,
            EffectiveResolution::FiveMinutes,
            EffectiveResolution::OneHour,
        ]
        .into_iter()
        .find(|resolution| estimated_point_count(self.window, *resolution) <= MAX_RESPONSE_POINTS)
        .unwrap_or(EffectiveResolution::OneHour)
    }

    fn is_auto(self) -> bool {
        self.resolution == RequestedResolution::Auto
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HistoryError {
    InvalidQuery,
    ResolutionTooFine,
    Unavailable,
}

#[derive(Debug, Serialize)]
pub(crate) struct HistoryResponse {
    schema_version: u8,
    window: &'static str,
    resolution: &'static str,
    requested_start: i64,
    oldest_timestamp: Option<i64>,
    newest_timestamp: Option<i64>,
    partial: bool,
    points: Vec<HistoryPoint>,
}

#[derive(Debug, Serialize)]
struct HistoryPoint {
    timestamp: i64,
    sample_count: u64,
    cpu_percent: PercentSummary,
    memory_percent: Option<PercentSummary>,
    disk_percent: Option<PercentSummary>,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct PercentSummary {
    avg: f64,
    max: f64,
}

#[derive(Clone, Copy, Debug)]
struct RawMetricRow {
    timestamp: i64,
    cpu_percent: f64,
    memory_percent: Option<f64>,
    disk_percent: Option<f64>,
}

#[derive(Debug)]
struct OptionalAccumulator {
    sum: f64,
    max: f64,
    count: u64,
}

impl OptionalAccumulator {
    fn new() -> Self {
        Self {
            sum: 0.0,
            max: 0.0,
            count: 0,
        }
    }

    fn add(&mut self, value: Option<f64>) {
        let Some(value) = value else {
            return;
        };
        self.sum += value;
        self.max = if self.count == 0 {
            value
        } else {
            self.max.max(value)
        };
        self.count += 1;
    }

    fn finish(self) -> Option<PercentSummary> {
        (self.count > 0).then_some(PercentSummary {
            avg: (self.sum / self.count as f64).clamp(0.0, self.max),
            max: self.max,
        })
    }
}

#[derive(Debug)]
struct BucketAccumulator {
    sample_count: u64,
    cpu_sum: f64,
    cpu_max: f64,
    memory: OptionalAccumulator,
    disk: OptionalAccumulator,
}

impl BucketAccumulator {
    fn new(row: &RawMetricRow) -> Self {
        let mut memory = OptionalAccumulator::new();
        memory.add(row.memory_percent);
        let mut disk = OptionalAccumulator::new();
        disk.add(row.disk_percent);
        Self {
            sample_count: 1,
            cpu_sum: row.cpu_percent,
            cpu_max: row.cpu_percent,
            memory,
            disk,
        }
    }

    fn add(&mut self, row: &RawMetricRow) {
        self.sample_count += 1;
        self.cpu_sum += row.cpu_percent;
        self.cpu_max = self.cpu_max.max(row.cpu_percent);
        self.memory.add(row.memory_percent);
        self.disk.add(row.disk_percent);
    }

    fn into_point(self, timestamp: i64) -> HistoryPoint {
        HistoryPoint {
            timestamp,
            sample_count: self.sample_count,
            cpu_percent: PercentSummary {
                avg: (self.cpu_sum / self.sample_count as f64).clamp(0.0, self.cpu_max),
                max: self.cpu_max,
            },
            memory_percent: self.memory.finish(),
            disk_percent: self.disk.finish(),
        }
    }
}

pub(crate) fn parse_history_query(
    raw_query: Option<&str>,
) -> Result<Option<HistoryQuery>, HistoryError> {
    let Some(raw_query) = raw_query else {
        return Ok(None);
    };
    if raw_query.is_empty() {
        return Err(HistoryError::InvalidQuery);
    }

    let mut window = None;
    let mut resolution = None;
    for (key, value) in url::form_urlencoded::parse(raw_query.as_bytes()) {
        match key.as_ref() {
            "window" if window.is_none() => {
                window = HistoryWindow::parse(value.as_ref());
                if window.is_none() {
                    return Err(HistoryError::InvalidQuery);
                }
            }
            "resolution" if resolution.is_none() => {
                resolution = RequestedResolution::parse(value.as_ref());
                if resolution.is_none() {
                    return Err(HistoryError::InvalidQuery);
                }
            }
            _ => return Err(HistoryError::InvalidQuery),
        }
    }

    let Some(window) = window else {
        return Err(HistoryError::InvalidQuery);
    };
    let resolution = resolution.unwrap_or(RequestedResolution::Auto);
    if resolution != RequestedResolution::Auto
        && estimated_point_count(window, resolution.into()) > MAX_RESPONSE_POINTS
    {
        return Err(HistoryError::ResolutionTooFine);
    }

    Ok(Some(HistoryQuery { window, resolution }))
}

pub(crate) async fn fetch_legacy_history(
    db: &SqlitePool,
) -> Result<Vec<SystemStats>, HistoryError> {
    let rows = sqlx::query(
        "SELECT cpu_usage, memory_used, memory_total, disk_used, disk_total, timestamp \
         FROM metrics ORDER BY timestamp DESC LIMIT 60",
    )
    .fetch_all(db)
    .await
    .map_err(|_| HistoryError::Unavailable)?;

    rows.into_iter()
        .map(|row| {
            Ok(SystemStats {
                cpu_usage: row
                    .try_get::<f64, _>("cpu_usage")
                    .map_err(|_| HistoryError::Unavailable)? as f32,
                memory_used: row
                    .try_get::<i64, _>("memory_used")
                    .map_err(|_| HistoryError::Unavailable)? as u64,
                memory_total: row
                    .try_get::<i64, _>("memory_total")
                    .map_err(|_| HistoryError::Unavailable)? as u64,
                disk_used: row
                    .try_get::<i64, _>("disk_used")
                    .map_err(|_| HistoryError::Unavailable)? as u64,
                disk_total: row
                    .try_get::<i64, _>("disk_total")
                    .map_err(|_| HistoryError::Unavailable)? as u64,
                timestamp: row
                    .try_get::<i64, _>("timestamp")
                    .map_err(|_| HistoryError::Unavailable)?,
            })
        })
        .collect()
}

pub(crate) async fn fetch_history(
    db: &SqlitePool,
    query: HistoryQuery,
    now: i64,
) -> Result<HistoryResponse, HistoryError> {
    let requested_start = now.saturating_sub(query.window.seconds());
    let rows = fetch_source_rows(db, requested_start, now).await?;
    let oldest_timestamp = rows.first().map(|row| row.timestamp);
    let newest_timestamp = rows.last().map(|row| row.timestamp);
    let mut resolution = query.initial_resolution();

    loop {
        let points = build_points(&rows, resolution);
        if points.len() <= MAX_RESPONSE_POINTS {
            let partial = oldest_timestamp.is_some_and(|oldest| {
                oldest > requested_start.saturating_add(NOMINAL_RAW_INTERVAL_SECONDS)
            });
            return Ok(HistoryResponse {
                schema_version: 1,
                window: query.window.as_str(),
                resolution: resolution.as_str(),
                requested_start,
                oldest_timestamp,
                newest_timestamp,
                partial,
                points,
            });
        }

        if !query.is_auto() {
            return Err(HistoryError::ResolutionTooFine);
        }
        let Some(coarser) = resolution.coarser() else {
            return Err(HistoryError::Unavailable);
        };
        resolution = coarser;
    }
}

async fn fetch_source_rows(
    db: &SqlitePool,
    requested_start: i64,
    now: i64,
) -> Result<Vec<RawMetricRow>, HistoryError> {
    let rows = sqlx::query(
        "SELECT cpu_usage, memory_used, memory_total, disk_used, disk_total, timestamp \
         FROM metrics \
         WHERE timestamp >= ? AND timestamp <= ? \
         ORDER BY timestamp ASC, id ASC \
         LIMIT ?",
    )
    .bind(requested_start)
    .bind(now)
    .bind((MAX_SOURCE_ROWS + 1) as i64)
    .fetch_all(db)
    .await
    .map_err(|_| HistoryError::Unavailable)?;

    if rows.len() > MAX_SOURCE_ROWS {
        return Err(HistoryError::Unavailable);
    }

    rows.into_iter()
        .map(|row| {
            let cpu_percent = row
                .try_get::<Option<f64>, _>("cpu_usage")
                .map_err(|_| HistoryError::Unavailable)?
                .filter(|value| value.is_finite() && (0.0..=100.0).contains(value))
                .ok_or(HistoryError::Unavailable)?;
            let memory_used = row
                .try_get::<Option<i64>, _>("memory_used")
                .map_err(|_| HistoryError::Unavailable)?;
            let memory_total = row
                .try_get::<Option<i64>, _>("memory_total")
                .map_err(|_| HistoryError::Unavailable)?;
            let disk_used = row
                .try_get::<Option<i64>, _>("disk_used")
                .map_err(|_| HistoryError::Unavailable)?;
            let disk_total = row
                .try_get::<Option<i64>, _>("disk_total")
                .map_err(|_| HistoryError::Unavailable)?;

            Ok(RawMetricRow {
                timestamp: row
                    .try_get::<i64, _>("timestamp")
                    .map_err(|_| HistoryError::Unavailable)?,
                cpu_percent,
                memory_percent: percent(memory_used, memory_total),
                disk_percent: percent(disk_used, disk_total),
            })
        })
        .collect()
}

fn build_points(rows: &[RawMetricRow], resolution: EffectiveResolution) -> Vec<HistoryPoint> {
    if resolution == EffectiveResolution::Raw {
        return rows
            .iter()
            .map(|row| HistoryPoint {
                timestamp: row.timestamp,
                sample_count: 1,
                cpu_percent: PercentSummary {
                    avg: row.cpu_percent,
                    max: row.cpu_percent,
                },
                memory_percent: row.memory_percent.map(|value| PercentSummary {
                    avg: value,
                    max: value,
                }),
                disk_percent: row.disk_percent.map(|value| PercentSummary {
                    avg: value,
                    max: value,
                }),
            })
            .collect();
    }

    let interval = resolution.interval_seconds();
    let mut buckets = BTreeMap::<i64, BucketAccumulator>::new();
    for row in rows {
        let bucket_timestamp = row.timestamp.div_euclid(interval) * interval;
        match buckets.entry(bucket_timestamp) {
            Entry::Vacant(entry) => {
                entry.insert(BucketAccumulator::new(row));
            }
            Entry::Occupied(mut entry) => entry.get_mut().add(row),
        }
    }

    buckets
        .into_iter()
        .map(|(timestamp, bucket)| bucket.into_point(timestamp))
        .collect()
}

fn percent(used: Option<i64>, total: Option<i64>) -> Option<f64> {
    let (Some(used), Some(total)) = (used, total) else {
        return None;
    };
    if used < 0 || total <= 0 || used > total {
        return None;
    }

    let value = used as f64 * 100.0 / total as f64;
    value.is_finite().then_some(value)
}

fn estimated_point_count(window: HistoryWindow, resolution: EffectiveResolution) -> usize {
    let interval = resolution.interval_seconds();
    let intervals = window.seconds().saturating_add(interval - 1) / interval;
    intervals.saturating_add(1) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn test_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory SQLite should connect");
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
        .expect("metrics table should be created");
        sqlx::query("CREATE INDEX idx_metrics_timestamp ON metrics(timestamp)")
            .execute(&pool)
            .await
            .expect("metrics timestamp index should be created");
        pool
    }

    async fn insert_metric(
        pool: &SqlitePool,
        cpu: f64,
        memory_used: i64,
        memory_total: i64,
        disk_used: i64,
        disk_total: i64,
        timestamp: i64,
    ) {
        sqlx::query(
            "INSERT INTO metrics (
                cpu_usage, memory_used, memory_total, disk_used, disk_total, timestamp
             ) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(cpu)
        .bind(memory_used)
        .bind(memory_total)
        .bind(disk_used)
        .bind(disk_total)
        .bind(timestamp)
        .execute(pool)
        .await
        .expect("metric should be inserted");
    }

    fn query(raw: &str) -> HistoryQuery {
        parse_history_query(Some(raw))
            .expect("query should be valid")
            .expect("query should select windowed history")
    }

    #[test]
    fn parses_supported_queries_and_preserves_no_query_legacy_mode() {
        assert_eq!(parse_history_query(None), Ok(None));

        let parsed = query("window=6h");
        assert_eq!(parsed.window, HistoryWindow::SixHours);
        assert_eq!(parsed.resolution, RequestedResolution::Auto);

        let parsed = query("resolution=5m&window=24h");
        assert_eq!(parsed.window, HistoryWindow::TwentyFourHours);
        assert_eq!(parsed.resolution, RequestedResolution::FiveMinutes);
    }

    #[test]
    fn rejects_missing_unknown_duplicate_and_invalid_query_fields() {
        for raw in [
            "",
            "resolution=raw",
            "window=2h",
            "window=1h&resolution=15m",
            "window=1h&unknown=value",
            "window=1h&window=6h",
            "window=1h&resolution=raw&resolution=5m",
        ] {
            assert_eq!(
                parse_history_query(Some(raw)),
                Err(HistoryError::InvalidQuery),
                "unexpected result for {raw}"
            );
        }
    }

    #[test]
    fn auto_selects_a_bounded_effective_resolution() {
        for (window, expected) in [
            ("1h", EffectiveResolution::Raw),
            ("6h", EffectiveResolution::Raw),
            ("24h", EffectiveResolution::Raw),
            ("7d", EffectiveResolution::OneHour),
        ] {
            let parsed = query(&format!("window={window}"));
            assert_eq!(parsed.initial_resolution(), expected);
            assert!(estimated_point_count(parsed.window, expected) <= MAX_RESPONSE_POINTS);
        }
    }

    #[test]
    fn rejects_explicit_resolutions_that_cannot_fit_the_window_bound() {
        for raw in ["window=7d&resolution=raw", "window=7d&resolution=5m"] {
            assert_eq!(
                parse_history_query(Some(raw)),
                Err(HistoryError::ResolutionTooFine)
            );
        }
        assert!(parse_history_query(Some("window=7d&resolution=1h")).is_ok());
    }

    #[tokio::test]
    async fn empty_history_is_not_partial_and_has_null_bounds() {
        let pool = test_pool().await;
        let response = fetch_history(&pool, query("window=1h"), 1_800_000_000)
            .await
            .expect("empty history should be available");

        assert!(response.points.is_empty());
        assert_eq!(response.oldest_timestamp, None);
        assert_eq!(response.newest_timestamp, None);
        assert!(!response.partial);
    }

    #[tokio::test]
    async fn partial_uses_actual_oldest_sample_with_resolution_tolerance() {
        let pool = test_pool().await;
        let now = 1_800_000_000;
        let requested_start = now - HistoryWindow::OneHour.seconds();
        insert_metric(&pool, 10.0, 10, 100, 10, 100, requested_start + 61).await;

        let response = fetch_history(&pool, query("window=1h"), now)
            .await
            .expect("history should load");
        assert_eq!(response.oldest_timestamp, Some(requested_start + 61));
        assert!(response.partial);

        let pool = test_pool().await;
        insert_metric(&pool, 10.0, 10, 100, 10, 100, requested_start + 60).await;
        let response = fetch_history(&pool, query("window=1h"), now)
            .await
            .expect("history should load");
        assert!(!response.partial);
    }

    #[tokio::test]
    async fn aggregation_preserves_average_max_and_sample_count() {
        let pool = test_pool().await;
        let now = 1_800_000_000;
        insert_metric(&pool, 10.0, 10, 100, 25, 100, now - 120).await;
        insert_metric(&pool, 90.0, 50, 100, 75, 100, now - 60).await;

        let response = fetch_history(&pool, query("window=1h&resolution=5m"), now)
            .await
            .expect("history should load");
        assert_eq!(response.points.len(), 1);
        let point = &response.points[0];
        assert_eq!(point.sample_count, 2);
        assert_eq!(point.cpu_percent.avg, 50.0);
        assert_eq!(point.cpu_percent.max, 90.0);
        let memory = point.memory_percent.expect("memory summary should exist");
        assert_eq!(memory.avg, 30.0);
        assert_eq!(memory.max, 50.0);
        let disk = point.disk_percent.expect("disk summary should exist");
        assert_eq!(disk.avg, 50.0);
        assert_eq!(disk.max, 75.0);
    }

    #[tokio::test]
    async fn invalid_totals_are_null_instead_of_zero() {
        let pool = test_pool().await;
        let now = 1_800_000_000;
        insert_metric(&pool, 15.0, 10, 0, 20, 10, now - 60).await;

        let response = fetch_history(&pool, query("window=1h&resolution=raw"), now)
            .await
            .expect("history should load");
        assert_eq!(response.points.len(), 1);
        assert!(response.points[0].memory_percent.is_none());
        assert!(response.points[0].disk_percent.is_none());
    }

    #[tokio::test]
    async fn invalid_cpu_is_not_clamped_into_a_valid_aggregate() {
        let pool = test_pool().await;
        let now = 1_800_000_000;
        insert_metric(&pool, 101.0, 10, 100, 10, 100, now - 60).await;

        assert!(matches!(
            fetch_history(&pool, query("window=1h"), now).await,
            Err(HistoryError::Unavailable)
        ));
    }

    #[tokio::test]
    async fn auto_falls_back_when_actual_raw_rows_exceed_response_bound() {
        let pool = test_pool().await;
        let now = 1_800_000_000;
        let start = now - HistoryWindow::TwentyFourHours.seconds();
        let mut transaction = pool.begin().await.expect("transaction should start");
        for offset in 1..=2_000_i64 {
            sqlx::query(
                "INSERT INTO metrics (
                    cpu_usage, memory_used, memory_total, disk_used, disk_total, timestamp
                 ) VALUES (10.0, 10, 100, 10, 100, ?)",
            )
            .bind(start + offset)
            .execute(&mut *transaction)
            .await
            .expect("metric should be inserted");
        }
        transaction
            .commit()
            .await
            .expect("transaction should commit");

        let response = fetch_history(&pool, query("window=24h"), now)
            .await
            .expect("auto history should load");
        assert_eq!(response.resolution, "5m");
        assert!(response.points.len() <= MAX_RESPONSE_POINTS);

        assert!(matches!(
            fetch_history(&pool, query("window=24h&resolution=raw"), now).await,
            Err(HistoryError::ResolutionTooFine)
        ));
    }

    #[tokio::test]
    async fn legacy_history_remains_newest_first_and_limited_to_sixty_rows() {
        let pool = test_pool().await;
        for timestamp in 1..=65_i64 {
            insert_metric(&pool, timestamp as f64, 10, 100, 10, 100, timestamp).await;
        }

        let response = fetch_legacy_history(&pool)
            .await
            .expect("legacy history should load");
        assert_eq!(response.len(), 60);
        assert_eq!(response.first().map(|point| point.timestamp), Some(65));
        assert_eq!(response.last().map(|point| point.timestamp), Some(6));
    }

    #[tokio::test]
    async fn database_failures_are_not_mapped_to_empty_success() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory SQLite should connect");

        assert!(matches!(
            fetch_legacy_history(&pool).await,
            Err(HistoryError::Unavailable)
        ));
        assert!(matches!(
            fetch_history(&pool, query("window=1h"), 1_800_000_000).await,
            Err(HistoryError::Unavailable)
        ));
    }
}
