//! Alert model types.

use chrono::Utc;
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

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "info" => Self::Info,
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            "critical" => Self::Critical,
            _ => Self::Info,
        }
    }
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

impl AlertStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Acknowledged => "acknowledged",
            Self::Resolved => "resolved",
            Self::FalsePositive => "false_positive",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "new" => Self::New,
            "acknowledged" => Self::Acknowledged,
            "resolved" => Self::Resolved,
            "false_positive" => Self::FalsePositive,
            _ => Self::New,
        }
    }
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

impl AlertCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Intrusion => "intrusion",
            Self::Malware => "malware",
            Self::Vulnerability => "vulnerability",
            Self::PolicyViolation => "policy_violation",
            Self::Anomaly => "anomaly",
            Self::NetworkThreat => "network_threat",
            Self::Other => "other",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "intrusion" => Self::Intrusion,
            "malware" => Self::Malware,
            "vulnerability" => Self::Vulnerability,
            "policy_violation" => Self::PolicyViolation,
            "anomaly" => Self::Anomaly,
            "network_threat" => Self::NetworkThreat,
            _ => Self::Other,
        }
    }
}

/// A security alert (database row).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct Alert {
    pub id: String,
    pub severity: String,
    pub status: String,
    pub source_tool: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub device_ip: Option<String>,
    pub fingerprint: String,
    pub correlation_id: Option<String>,
    pub count: i64,
    pub created_at: String,
    pub updated_at: String,
    pub notes: Option<String>,
    pub source_event_id: Option<String>,
    pub device_id: Option<String>,
    pub raw_data: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
}

impl Alert {
    pub fn new(title: String, source_tool: String, fingerprint: String) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            id: Uuid::new_v4().to_string(),
            severity: Severity::Info.as_str().to_string(),
            status: AlertStatus::New.as_str().to_string(),
            source_tool,
            category: AlertCategory::Other.as_str().to_string(),
            title,
            description: String::new(),
            device_ip: None,
            fingerprint,
            correlation_id: None,
            count: 1,
            created_at: now.clone(),
            updated_at: now.clone(),
            notes: None,
            source_event_id: None,
            device_id: None,
            raw_data: None,
            first_seen: now.clone(),
            last_seen: now,
        }
    }

    pub fn severity_enum(&self) -> Severity {
        Severity::from_str_lossy(&self.severity)
    }

    pub fn status_enum(&self) -> AlertStatus {
        AlertStatus::from_str_lossy(&self.status)
    }

    pub fn category_enum(&self) -> AlertCategory {
        AlertCategory::from_str_lossy(&self.category)
    }
}

/// A normalized alert from the pipeline input stage (not stored directly).
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
    pub timestamp: chrono::DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_serde_roundtrip() {
        let alert = Alert::new("Test alert".into(), "nmap".into(), "fp-1".into());
        let json = serde_json::to_string(&alert).unwrap();
        let back: Alert = serde_json::from_str(&json).unwrap();
        assert_eq!(back.title, "Test alert");
        assert_eq!(back.source_tool, "nmap");
        assert_eq!(back.severity, "info");
        assert_eq!(back.status, "new");
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_severity_roundtrip() {
        for s in [Severity::Info, Severity::Low, Severity::Medium, Severity::High, Severity::Critical] {
            assert_eq!(Severity::from_str_lossy(s.as_str()), s);
        }
    }

    #[test]
    fn test_normalized_alert_serde() {
        let na = NormalizedAlert {
            source_tool: "suricata".into(),
            severity: Severity::High,
            category: AlertCategory::Intrusion,
            title: "ET SCAN".into(),
            description: "Scan detected".into(),
            device_ip: Some("10.0.0.1".into()),
            fingerprint: "fp-2".into(),
            raw_data: serde_json::json!({"sig_id": 2000001}),
            timestamp: Utc::now(),
        };
        let json = serde_json::to_string(&na).unwrap();
        let back: NormalizedAlert = serde_json::from_str(&json).unwrap();
        assert_eq!(back.severity, Severity::High);
        assert_eq!(back.category, AlertCategory::Intrusion);
    }

    // A1: AlertStatus enum roundtrip
    #[test]
    fn test_alert_status_roundtrip() {
        for s in [
            AlertStatus::New,
            AlertStatus::Acknowledged,
            AlertStatus::Resolved,
            AlertStatus::FalsePositive,
        ] {
            assert_eq!(AlertStatus::from_str_lossy(s.as_str()), s);
        }
    }

    // A1: AlertCategory enum roundtrip
    #[test]
    fn test_alert_category_roundtrip() {
        for c in [
            AlertCategory::Intrusion,
            AlertCategory::Malware,
            AlertCategory::Vulnerability,
            AlertCategory::PolicyViolation,
            AlertCategory::Anomaly,
            AlertCategory::NetworkThreat,
            AlertCategory::Other,
        ] {
            assert_eq!(AlertCategory::from_str_lossy(c.as_str()), c);
        }
    }

    // A5: from_str_lossy fallback tests
    #[test]
    fn test_severity_from_str_lossy_fallback() {
        assert_eq!(Severity::from_str_lossy("garbage"), Severity::Info);
        assert_eq!(Severity::from_str_lossy(""), Severity::Info);
        assert_eq!(Severity::from_str_lossy("HIGH"), Severity::Info); // case-sensitive
    }

    #[test]
    fn test_alert_status_from_str_lossy_fallback() {
        assert_eq!(AlertStatus::from_str_lossy("garbage"), AlertStatus::New);
        assert_eq!(AlertStatus::from_str_lossy(""), AlertStatus::New);
    }

    #[test]
    fn test_alert_category_from_str_lossy_fallback() {
        assert_eq!(AlertCategory::from_str_lossy("garbage"), AlertCategory::Other);
        assert_eq!(AlertCategory::from_str_lossy(""), AlertCategory::Other);
    }

    // A6: Accessor method tests
    #[test]
    fn test_alert_severity_enum_accessor() {
        let mut alert = Alert::new("test".into(), "nmap".into(), "fp".into());
        assert_eq!(alert.severity_enum(), Severity::Info);
        alert.severity = "critical".to_string();
        assert_eq!(alert.severity_enum(), Severity::Critical);
    }

    #[test]
    fn test_alert_status_enum_accessor() {
        let mut alert = Alert::new("test".into(), "nmap".into(), "fp".into());
        assert_eq!(alert.status_enum(), AlertStatus::New);
        alert.status = "resolved".to_string();
        assert_eq!(alert.status_enum(), AlertStatus::Resolved);
    }

    #[test]
    fn test_alert_category_enum_accessor() {
        let mut alert = Alert::new("test".into(), "nmap".into(), "fp".into());
        assert_eq!(alert.category_enum(), AlertCategory::Other);
        alert.category = "malware".to_string();
        assert_eq!(alert.category_enum(), AlertCategory::Malware);
    }

    // A7: Constructor defaults
    #[test]
    fn test_alert_constructor_defaults() {
        let alert = Alert::new("Test alert".into(), "suricata".into(), "fp-test".into());
        assert_eq!(alert.severity, "info");
        assert_eq!(alert.status, "new");
        assert_eq!(alert.category, "other");
        assert_eq!(alert.count, 1);
        assert_eq!(alert.description, "");
        assert!(alert.device_ip.is_none());
        assert!(alert.correlation_id.is_none());
        assert!(alert.notes.is_none());
        assert!(alert.source_event_id.is_none());
        assert!(alert.device_id.is_none());
        assert!(alert.raw_data.is_none());
        assert!(!alert.first_seen.is_empty());
        assert!(!alert.last_seen.is_empty());
        // ID is a valid UUID
        uuid::Uuid::parse_str(&alert.id).expect("id should be valid UUID");
        // Timestamps are present
        assert!(!alert.created_at.is_empty());
        assert!(!alert.updated_at.is_empty());
    }
}
