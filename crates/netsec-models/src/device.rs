//! Device model types.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Network device status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    Online,
    Offline,
    Warning,
    Compromised,
    Unknown,
}

impl DeviceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Offline => "offline",
            Self::Warning => "warning",
            Self::Compromised => "compromised",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "online" => Self::Online,
            "offline" => Self::Offline,
            "warning" => Self::Warning,
            "compromised" => Self::Compromised,
            _ => Self::Unknown,
        }
    }
}

/// Classification of a network device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceType {
    Workstation,
    Server,
    Router,
    Switch,
    AccessPoint,
    Printer,
    IoT,
    Mobile,
    Unknown,
}

impl DeviceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Workstation => "workstation",
            Self::Server => "server",
            Self::Router => "router",
            Self::Switch => "switch",
            Self::AccessPoint => "access_point",
            Self::Printer => "printer",
            Self::IoT => "iot",
            Self::Mobile => "mobile",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "workstation" => Self::Workstation,
            "server" => Self::Server,
            "router" => Self::Router,
            "switch" => Self::Switch,
            "access_point" => Self::AccessPoint,
            "printer" => Self::Printer,
            "iot" => Self::IoT,
            "mobile" => Self::Mobile,
            _ => Self::Unknown,
        }
    }
}

/// A discovered network device.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct Device {
    pub id: String,
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub os_family: Option<String>,
    pub device_type: String,
    pub classification_confidence: f64,
    pub status: String,
    pub first_seen: String,
    pub last_seen: String,
    // Added in migration 011
    pub os_version: Option<String>,
    pub notes: Option<String>,
}

impl Device {
    /// Create a new device with generated ID and timestamps.
    pub fn new(ip: String) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            id: Uuid::new_v4().to_string(),
            ip,
            mac: None,
            hostname: None,
            vendor: None,
            os_family: None,
            device_type: DeviceType::Unknown.as_str().to_string(),
            classification_confidence: 0.0,
            status: DeviceStatus::Unknown.as_str().to_string(),
            first_seen: now.clone(),
            last_seen: now,
            os_version: None,
            notes: None,
        }
    }

    pub fn device_type_enum(&self) -> DeviceType {
        DeviceType::from_str_lossy(&self.device_type)
    }

    pub fn status_enum(&self) -> DeviceStatus {
        DeviceStatus::from_str_lossy(&self.status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_serde_roundtrip() {
        let device = Device::new("192.168.1.1".into());
        let json = serde_json::to_string(&device).unwrap();
        let back: Device = serde_json::from_str(&json).unwrap();
        assert_eq!(back.ip, "192.168.1.1");
        assert_eq!(back.device_type, "unknown");
        assert_eq!(back.status, "unknown");
    }

    #[test]
    fn test_device_type_roundtrip() {
        for dt in [
            DeviceType::Workstation,
            DeviceType::Server,
            DeviceType::Router,
            DeviceType::IoT,
            DeviceType::Unknown,
        ] {
            assert_eq!(DeviceType::from_str_lossy(dt.as_str()), dt);
        }
    }

    #[test]
    fn test_device_status_roundtrip() {
        for s in [
            DeviceStatus::Online,
            DeviceStatus::Offline,
            DeviceStatus::Warning,
            DeviceStatus::Compromised,
            DeviceStatus::Unknown,
        ] {
            assert_eq!(DeviceStatus::from_str_lossy(s.as_str()), s);
        }
    }

    // A5: from_str_lossy fallback tests
    #[test]
    fn test_device_status_from_str_lossy_fallback() {
        assert_eq!(DeviceStatus::from_str_lossy("garbage"), DeviceStatus::Unknown);
        assert_eq!(DeviceStatus::from_str_lossy(""), DeviceStatus::Unknown);
    }

    #[test]
    fn test_device_type_from_str_lossy_fallback() {
        assert_eq!(DeviceType::from_str_lossy("garbage"), DeviceType::Unknown);
        assert_eq!(DeviceType::from_str_lossy(""), DeviceType::Unknown);
    }

    // Complete DeviceType roundtrip (existing test misses some variants)
    #[test]
    fn test_device_type_all_variants_roundtrip() {
        for dt in [
            DeviceType::Workstation,
            DeviceType::Server,
            DeviceType::Router,
            DeviceType::Switch,
            DeviceType::AccessPoint,
            DeviceType::Printer,
            DeviceType::IoT,
            DeviceType::Mobile,
            DeviceType::Unknown,
        ] {
            assert_eq!(DeviceType::from_str_lossy(dt.as_str()), dt);
        }
    }

    // A6: Accessor method tests
    #[test]
    fn test_device_type_enum_accessor() {
        let mut device = Device::new("10.0.0.1".into());
        assert_eq!(device.device_type_enum(), DeviceType::Unknown);
        device.device_type = "server".to_string();
        assert_eq!(device.device_type_enum(), DeviceType::Server);
    }

    #[test]
    fn test_device_status_enum_accessor() {
        let mut device = Device::new("10.0.0.1".into());
        assert_eq!(device.status_enum(), DeviceStatus::Unknown);
        device.status = "online".to_string();
        assert_eq!(device.status_enum(), DeviceStatus::Online);
    }

    // A7: Constructor defaults
    #[test]
    fn test_device_constructor_defaults() {
        let device = Device::new("1.2.3.4".into());
        assert_eq!(device.ip, "1.2.3.4");
        assert_eq!(device.device_type, "unknown");
        assert_eq!(device.status, "unknown");
        assert_eq!(device.classification_confidence, 0.0);
        assert!(device.mac.is_none());
        assert!(device.hostname.is_none());
        assert!(device.vendor.is_none());
        assert!(device.os_family.is_none());
        assert!(device.os_version.is_none());
        assert!(device.notes.is_none());
        // ID is a valid UUID
        uuid::Uuid::parse_str(&device.id).expect("id should be valid UUID");
        // Timestamps present
        assert!(!device.first_seen.is_empty());
        assert!(!device.last_seen.is_empty());
    }
}
