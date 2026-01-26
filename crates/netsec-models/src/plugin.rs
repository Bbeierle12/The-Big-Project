//! Plugin system model types.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Plugin categories.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PluginCategory {
    NetworkScanner,
    IdsIps,
    VulnerabilityScanner,
    TrafficAnalyzer,
    MalwareScanner,
    LogAnalyzer,
    HostMonitor,
    AccessControl,
    RouterConnector,
    ThreatHunter,
    WebScanner,
    CredentialTester,
    ReportGenerator,
}

/// Plugin operational status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginStatus {
    Available,
    Unavailable,
    Running,
    Error,
}

/// Scheduled job trigger type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TriggerType {
    Cron,
    Interval,
}

impl TriggerType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cron => "cron",
            Self::Interval => "interval",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "cron" => Self::Cron,
            _ => Self::Interval,
        }
    }
}

/// A scheduled job record (database row).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct ScheduledJob {
    pub id: String,
    pub trigger_type: String,
    pub trigger_args: String,
    pub task_type: String,
    pub task_params: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl ScheduledJob {
    pub fn new(trigger_type: TriggerType, task_type: String) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            id: Uuid::new_v4().to_string(),
            trigger_type: trigger_type.as_str().to_string(),
            trigger_args: "{}".to_string(),
            task_type,
            task_params: "{}".to_string(),
            enabled: true,
            created_at: now.clone(),
            updated_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduled_job_serde_roundtrip() {
        let job = ScheduledJob::new(TriggerType::Cron, "full_scan".into());
        let json = serde_json::to_string(&job).unwrap();
        let back: ScheduledJob = serde_json::from_str(&json).unwrap();
        assert_eq!(back.trigger_type, "cron");
        assert_eq!(back.task_type, "full_scan");
        assert!(back.enabled);
    }

    // A4: TriggerType enum roundtrip
    #[test]
    fn test_trigger_type_roundtrip() {
        for t in [TriggerType::Cron, TriggerType::Interval] {
            assert_eq!(TriggerType::from_str_lossy(t.as_str()), t);
        }
    }

    // A5: from_str_lossy fallback test
    #[test]
    fn test_trigger_type_from_str_lossy_fallback() {
        assert_eq!(TriggerType::from_str_lossy("garbage"), TriggerType::Interval);
        assert_eq!(TriggerType::from_str_lossy(""), TriggerType::Interval);
    }

    // A7: Constructor defaults
    #[test]
    fn test_scheduled_job_constructor_defaults() {
        let job = ScheduledJob::new(TriggerType::Interval, "port_scan".into());
        assert_eq!(job.trigger_type, "interval");
        assert_eq!(job.task_type, "port_scan");
        assert_eq!(job.trigger_args, "{}");
        assert_eq!(job.task_params, "{}");
        assert!(job.enabled);
        uuid::Uuid::parse_str(&job.id).expect("id should be valid UUID");
        assert!(!job.created_at.is_empty());
        assert!(!job.updated_at.is_empty());
    }
}
