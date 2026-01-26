//! Event bus model types.

use chrono::{DateTime, Utc};
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
    pub id: Uuid,
    pub event_type: EventType,
    pub payload: serde_json::Value,
    pub timestamp: DateTime<Utc>,
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

/// A device-specific event record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEvent {
    pub id: Uuid,
    pub device_id: Uuid,
    pub event_type: DeviceEventType,
    pub details: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// A passive observation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub id: Uuid,
    pub device_id: Uuid,
    pub protocol: String,
    pub source_data: serde_json::Value,
    pub created_at: DateTime<Utc>,
}
