//! Plugin system model types.

use serde::{Deserialize, Serialize};

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

/// A scheduled job record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledJob {
    pub id: uuid::Uuid,
    pub trigger_type: TriggerType,
    pub trigger_args: serde_json::Value,
    pub task_type: String,
    pub task_params: serde_json::Value,
    pub enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}
