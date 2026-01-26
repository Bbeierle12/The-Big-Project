//! Job scheduler with SQLite persistence.
//!
//! Provides a tick-based scheduler that queries enabled jobs from the database
//! and dispatches them based on interval or cron triggers.

use std::collections::HashMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use netsec_events::EventBus;
use netsec_models::event::{EventType, NetsecEvent};
use sqlx::SqlitePool;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinHandle;

#[derive(Debug, Error)]
pub enum SchedulerError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("invalid trigger args: {0}")]
    InvalidTrigger(String),
    #[error("job not found: {0}")]
    JobNotFound(String),
}

pub type SchedulerResult<T> = Result<T, SchedulerError>;

/// Parse interval trigger_args JSON: `{"interval_secs": 3600}` -> Duration.
pub fn parse_interval_args(args: &str) -> SchedulerResult<Duration> {
    let parsed: serde_json::Value =
        serde_json::from_str(args).map_err(|e| SchedulerError::InvalidTrigger(e.to_string()))?;

    let secs = parsed
        .get("interval_secs")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            SchedulerError::InvalidTrigger("missing or invalid 'interval_secs' field".to_string())
        })?;

    Ok(Duration::from_secs(secs))
}

/// Check if an interval job is due based on its last_run and interval.
///
/// Returns `true` if:
/// - `last_run` is `None` (first run)
/// - The elapsed time since `last_run` exceeds the interval
pub fn is_interval_due(last_run: Option<&str>, interval: Duration) -> bool {
    match last_run {
        None => true,
        Some(last) => {
            let Ok(last_dt) = DateTime::parse_from_rfc3339(last) else {
                return true; // Can't parse -> treat as overdue
            };
            let elapsed = Utc::now().signed_duration_since(last_dt.with_timezone(&Utc));
            elapsed.to_std().unwrap_or(Duration::ZERO) >= interval
        }
    }
}

/// Parse cron trigger_args JSON: `{"cron": "0 * * * *"}` -> cron expression string.
pub fn parse_cron_args(args: &str) -> SchedulerResult<String> {
    let parsed: serde_json::Value =
        serde_json::from_str(args).map_err(|e| SchedulerError::InvalidTrigger(e.to_string()))?;

    parsed
        .get("cron")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            SchedulerError::InvalidTrigger("missing or invalid 'cron' field".to_string())
        })
}

/// Simplified cron check: is the expression due at the given time?
///
/// Supports common patterns:
/// - `* * * * *` — every minute (always true)
/// - `0 * * * *` — hourly (minute == 0)
/// - `0 0 * * *` — daily (minute == 0, hour == 0)
/// - `0 0 * * 0` — weekly on Sunday (minute == 0, hour == 0, weekday == Sun)
///
/// For unrecognized patterns, returns `false`.
pub fn is_cron_due(cron_expr: &str, now: &DateTime<Utc>) -> bool {
    let parts: Vec<&str> = cron_expr.trim().split_whitespace().collect();
    if parts.len() != 5 {
        return false;
    }

    let minute = now.format("%M").to_string().parse::<u32>().unwrap_or(0);
    let hour = now.format("%H").to_string().parse::<u32>().unwrap_or(0);
    let weekday = now.format("%w").to_string().parse::<u32>().unwrap_or(0);

    // Check minute field
    let minute_match = match parts[0] {
        "*" => true,
        val => val.parse::<u32>().map(|v| v == minute).unwrap_or(false),
    };

    // Check hour field
    let hour_match = match parts[1] {
        "*" => true,
        val => val.parse::<u32>().map(|v| v == hour).unwrap_or(false),
    };

    // Check day of month field (simplified: just wildcard)
    let dom_match = parts[2] == "*";

    // Check month field (simplified: just wildcard)
    let month_match = parts[3] == "*";

    // Check day of week field
    let dow_match = match parts[4] {
        "*" => true,
        val => val.parse::<u32>().map(|v| v == weekday).unwrap_or(false),
    };

    minute_match && hour_match && dom_match && month_match && dow_match
}

/// Job scheduler with tick-based dispatch.
pub struct Scheduler {
    pool: SqlitePool,
    event_bus: EventBus,
    tick_interval: Duration,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl Scheduler {
    /// Create a new scheduler.
    pub fn new(pool: SqlitePool, event_bus: EventBus, tick_interval: Duration) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            pool,
            event_bus,
            tick_interval,
            shutdown_tx,
            shutdown_rx,
        }
    }

    /// Start the scheduler tick loop in a background task.
    ///
    /// Every `tick_interval`, queries enabled jobs from the database and
    /// checks if each is due. For due jobs, publishes a `ScanStarted` event.
    pub fn start(&self) -> JoinHandle<()> {
        let pool = self.pool.clone();
        let event_bus = self.event_bus.clone();
        let tick_interval = self.tick_interval;
        let mut shutdown_rx = self.shutdown_rx.clone();

        tokio::spawn(async move {
            let mut last_runs: HashMap<String, String> = HashMap::new();

            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            tracing::info!("Scheduler shutting down");
                            break;
                        }
                    }
                    _ = tokio::time::sleep(tick_interval) => {
                        let jobs = match netsec_db::repo::scheduled_jobs::list_enabled(&pool).await {
                            Ok(jobs) => jobs,
                            Err(e) => {
                                tracing::error!("Failed to query jobs: {e}");
                                continue;
                            }
                        };

                        let now = Utc::now();

                        for job in &jobs {
                            let is_due = match job.trigger_type.as_str() {
                                "interval" => {
                                    match parse_interval_args(&job.trigger_args) {
                                        Ok(interval) => {
                                            let last = last_runs.get(&job.id).map(|s| s.as_str());
                                            is_interval_due(last, interval)
                                        }
                                        Err(e) => {
                                            tracing::warn!("Invalid interval args for job {}: {e}", job.id);
                                            false
                                        }
                                    }
                                }
                                "cron" => {
                                    match parse_cron_args(&job.trigger_args) {
                                        Ok(expr) => is_cron_due(&expr, &now),
                                        Err(e) => {
                                            tracing::warn!("Invalid cron args for job {}: {e}", job.id);
                                            false
                                        }
                                    }
                                }
                                _ => false,
                            };

                            if is_due {
                                let event = NetsecEvent::new(
                                    EventType::ScanStarted,
                                    serde_json::json!({
                                        "job_id": job.id,
                                        "task_type": job.task_type,
                                        "task_params": job.task_params,
                                    }),
                                );
                                let _ = event_bus.publish(event);
                                last_runs.insert(job.id.clone(), now.to_rfc3339());
                                tracing::info!("Dispatched job {}: {}", job.id, job.task_type);
                            }
                        }
                    }
                }
            }
        })
    }

    /// Signal the scheduler to shut down.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_parse_interval_args_valid() {
        let result = parse_interval_args(r#"{"interval_secs": 3600}"#).unwrap();
        assert_eq!(result, Duration::from_secs(3600));
    }

    #[test]
    fn test_parse_interval_args_invalid() {
        let result = parse_interval_args("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_interval_args_missing_field() {
        let result = parse_interval_args("{}");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("interval_secs"));
    }

    #[test]
    fn test_is_interval_due_no_last_run() {
        assert!(is_interval_due(None, Duration::from_secs(3600)));
    }

    #[test]
    fn test_is_interval_due_not_yet() {
        // Last run is "now" -> not yet due
        let now = Utc::now().to_rfc3339();
        assert!(!is_interval_due(Some(&now), Duration::from_secs(3600)));
    }

    #[test]
    fn test_is_interval_due_past() {
        // Last run was 2 hours ago, interval is 1 hour -> due
        let two_hours_ago = (Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
        assert!(is_interval_due(
            Some(&two_hours_ago),
            Duration::from_secs(3600)
        ));
    }

    #[test]
    fn test_parse_cron_args_valid() {
        let result = parse_cron_args(r#"{"cron": "0 * * * *"}"#).unwrap();
        assert_eq!(result, "0 * * * *");
    }

    #[test]
    fn test_is_cron_due_every_minute() {
        let now = Utc::now();
        assert!(is_cron_due("* * * * *", &now));
    }

    #[test]
    fn test_is_cron_due_hourly() {
        // Create a time where minute == 0
        let at_zero = Utc.with_ymd_and_hms(2024, 6, 15, 14, 0, 0).unwrap();
        assert!(is_cron_due("0 * * * *", &at_zero));

        // Create a time where minute != 0
        let at_thirty = Utc.with_ymd_and_hms(2024, 6, 15, 14, 30, 0).unwrap();
        assert!(!is_cron_due("0 * * * *", &at_thirty));
    }
}
