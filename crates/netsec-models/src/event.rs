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

    // A3: DeviceEventType enum roundtrip
    #[test]
    fn test_device_event_type_roundtrip() {
        for t in [
            DeviceEventType::Joined,
            DeviceEventType::Left,
            DeviceEventType::Updated,
            DeviceEventType::Classified,
        ] {
            assert_eq!(DeviceEventType::from_str_lossy(t.as_str()), t);
        }
    }

    // A5: from_str_lossy fallback test
    #[test]
    fn test_device_event_type_from_str_lossy_fallback() {
        assert_eq!(DeviceEventType::from_str_lossy("garbage"), DeviceEventType::Updated);
        assert_eq!(DeviceEventType::from_str_lossy(""), DeviceEventType::Updated);
    }

    // A7: Constructor defaults
    #[test]
    fn test_netsec_event_constructor_defaults() {
        let event = NetsecEvent::new(
            EventType::AlertCreated,
            serde_json::json!({"test": true}),
        );
        uuid::Uuid::parse_str(&event.id).expect("id should be valid UUID");
        assert!(!event.timestamp.is_empty());
        assert_eq!(event.event_type, EventType::AlertCreated);
    }

    #[test]
    fn test_device_event_constructor_defaults() {
        let de = DeviceEvent::new(
            "dev-1".into(),
            DeviceEventType::Left,
            serde_json::json!({"reason": "timeout"}),
        );
        uuid::Uuid::parse_str(&de.id).expect("id should be valid UUID");
        assert_eq!(de.device_id, "dev-1");
        assert_eq!(de.event_type, "left");
        assert!(!de.created_at.is_empty());
    }

    #[test]
    fn test_observation_constructor_defaults() {
        let obs = Observation::new(
            "dev-2".into(),
            "ssdp".into(),
            serde_json::json!({}),
        );
        uuid::Uuid::parse_str(&obs.id).expect("id should be valid UUID");
        assert_eq!(obs.device_id, "dev-2");
        assert_eq!(obs.protocol, "ssdp");
        assert!(!obs.created_at.is_empty());
    }
}
