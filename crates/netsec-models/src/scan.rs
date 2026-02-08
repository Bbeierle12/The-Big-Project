//! Scan model types.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Scan status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl ScanStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "pending" => Self::Pending,
            "running" => Self::Running,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            _ => Self::Pending,
        }
    }
}

/// Scan type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanType {
    Discovery,
    Port,
    Vulnerability,
    Full,
    Custom,
}

impl ScanType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Discovery => "discovery",
            Self::Port => "port",
            Self::Vulnerability => "vulnerability",
            Self::Full => "full",
            Self::Custom => "custom",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "discovery" => Self::Discovery,
            "port" => Self::Port,
            "vulnerability" => Self::Vulnerability,
            "full" => Self::Full,
            _ => Self::Custom,
        }
    }
}

/// A scan execution record (database row).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct Scan {
    pub id: String,
    pub scan_type: String,
    pub tool: String,
    pub target: String,
    pub status: String,
    /// Scan progress as a percentage, range 0.0 to 100.0.
    pub progress: f64,
    pub parameters: String,
    pub results: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub created_at: String,
}

impl Scan {
    pub fn new(tool: String, target: String, scan_type: ScanType) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            scan_type: scan_type.as_str().to_string(),
            tool,
            target,
            status: ScanStatus::Pending.as_str().to_string(),
            progress: 0.0,
            parameters: "{}".to_string(),
            results: "{}".to_string(),
            started_at: None,
            completed_at: None,
            created_at: Utc::now().to_rfc3339(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_serde_roundtrip() {
        let scan = Scan::new("nmap".into(), "192.168.1.0/24".into(), ScanType::Discovery);
        let json = serde_json::to_string(&scan).unwrap();
        let back: Scan = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tool, "nmap");
        assert_eq!(back.scan_type, "discovery");
        assert_eq!(back.status, "pending");
    }

    #[test]
    fn test_scan_status_roundtrip() {
        for s in [ScanStatus::Pending, ScanStatus::Running, ScanStatus::Completed, ScanStatus::Failed, ScanStatus::Cancelled] {
            assert_eq!(ScanStatus::from_str_lossy(s.as_str()), s);
        }
    }

    // A2: ScanType enum roundtrip
    #[test]
    fn test_scan_type_roundtrip() {
        for t in [
            ScanType::Discovery,
            ScanType::Port,
            ScanType::Vulnerability,
            ScanType::Full,
            ScanType::Custom,
        ] {
            assert_eq!(ScanType::from_str_lossy(t.as_str()), t);
        }
    }

    // A5: from_str_lossy fallback tests
    #[test]
    fn test_scan_status_from_str_lossy_fallback() {
        assert_eq!(ScanStatus::from_str_lossy("garbage"), ScanStatus::Pending);
        assert_eq!(ScanStatus::from_str_lossy(""), ScanStatus::Pending);
    }

    #[test]
    fn test_scan_type_from_str_lossy_fallback() {
        assert_eq!(ScanType::from_str_lossy("garbage"), ScanType::Custom);
        assert_eq!(ScanType::from_str_lossy(""), ScanType::Custom);
    }

    // A7: Constructor defaults
    #[test]
    fn test_scan_constructor_defaults() {
        let scan = Scan::new("nmap".into(), "10.0.0.0/24".into(), ScanType::Full);
        assert_eq!(scan.tool, "nmap");
        assert_eq!(scan.target, "10.0.0.0/24");
        assert_eq!(scan.scan_type, "full");
        assert_eq!(scan.status, "pending");
        assert_eq!(scan.progress, 0.0);
        assert_eq!(scan.parameters, "{}");
        assert_eq!(scan.results, "{}");
        assert!(scan.started_at.is_none());
        assert!(scan.completed_at.is_none());
        uuid::Uuid::parse_str(&scan.id).expect("id should be valid UUID");
        assert!(!scan.created_at.is_empty());
    }
}
