//! Alert model types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Alert severity levels.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Alert status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    New,
    Acknowledged,
    Resolved,
    FalsePositive,
}

/// Alert category.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertCategory {
    Intrusion,
    Malware,
    Vulnerability,
    PolicyViolation,
    Anomaly,
    NetworkThreat,
    Other,
}

/// A security alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: Uuid,
    pub severity: Severity,
    pub status: AlertStatus,
    pub source_tool: String,
    pub category: AlertCategory,
    pub title: String,
    pub description: String,
    pub device_ip: Option<String>,
    pub fingerprint: String,
    pub correlation_id: Option<Uuid>,
    pub count: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A normalized alert from the pipeline input stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedAlert {
    pub source_tool: String,
    pub severity: Severity,
    pub category: AlertCategory,
    pub title: String,
    pub description: String,
    pub device_ip: Option<String>,
    pub fingerprint: String,
    pub raw_data: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}
