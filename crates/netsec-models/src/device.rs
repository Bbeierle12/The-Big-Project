//! Device model types.

use chrono::{DateTime, Utc};
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

/// A discovered network device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: Uuid,
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub os_family: Option<String>,
    pub device_type: DeviceType,
    pub classification_confidence: f64,
    pub status: DeviceStatus,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}
