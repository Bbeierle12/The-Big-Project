//! Event bus model types.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Types of events emitted by the system.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    DeviceDiscovered,
    DeviceUpdated,
    DeviceLost,
    AlertCreated,
    AlertUpdated,
    AlertResolved,
    ScanStarted,
    ScanCompleted,
    ScanFailed,
    ThreatDetected,
    SystemHealth,
}

/// An event emitted on the event bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetsecEvent {
    pub id: String,
    pub event_type: EventType,
    pub payload: serde_json::Value,
    pub timestamp: String,
}

impl NetsecEvent {
    pub fn new(event_type: EventType, payload: serde_json::Value) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            event_type,
            payload,
            timestamp: Utc::now().to_rfc3339(),
        }
    }
}

/// Device event types (for the device_events table).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceEventType {
    Joined,
    Left,
    Updated,
    Classified,
}

impl DeviceEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Joined => "joined",
            Self::Left => "left",
            Self::Updated => "updated",
            Self::Classified => "classified",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "joined" => Self::Joined,
            "left" => Self::Left,
            "updated" => Self::Updated,
            "classified" => Self::Classified,
            _ => Self::Updated,
        }
    }
}

/// A device-specific event record (database row).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct DeviceEvent {
    pub id: String,
    pub device_id: String,
    pub event_type: String,
    pub details: String,
    pub created_at: String,
}

impl DeviceEvent {
    pub fn new(device_id: String, event_type: DeviceEventType, details: serde_json::Value) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            device_id,
            event_type: event_type.as_str().to_string(),
            details: details.to_string(),
            created_at: Utc::now().to_rfc3339(),
        }
    }
}

/// A passive observation record (database row).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct Observation {
    pub id: String,
    pub device_id: String,
    pub protocol: String,
    pub source_data: String,
    pub created_at: String,
}

impl Observation {
    pub fn new(device_id: String, protocol: String, source_data: serde_json::Value) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            device_id,
            protocol,
            source_data: source_data.to_string(),
            created_at: Utc::now().to_rfc3339(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_serde_roundtrip() {
        let event = NetsecEvent::new(
            EventType::DeviceDiscovered,
            serde_json::json!({"ip": "192.168.1.1"}),
        );
        let json = serde_json::to_string(&event).unwrap();
        let back: NetsecEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.event_type, EventType::DeviceDiscovered);
    }

    #[test]
    fn test_device_event_serde() {
        let de = DeviceEvent::new(
            "dev-1".into(),
            DeviceEventType::Joined,
            serde_json::json!({"ip": "10.0.0.5"}),
        );
        let json = serde_json::to_string(&de).unwrap();
        let back: DeviceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.event_type, "joined");
    }

    #[test]
    fn test_observation_serde() {
        let obs = Observation::new(
            "dev-1".into(),
            "mdns".into(),
            serde_json::json!({"name": "_http._tcp.local"}),
        );
        let json = serde_json::to_string(&obs).unwrap();
        let back: Observation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.protocol, "mdns");
    }
}
