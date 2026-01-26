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
    Unknown,
}

impl DeviceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Offline => "offline",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "online" => Self::Online,
            "offline" => Self::Offline,
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
        for s in [DeviceStatus::Online, DeviceStatus::Offline, DeviceStatus::Unknown] {
            assert_eq!(DeviceStatus::from_str_lossy(s.as_str()), s);
        }
    }
}
