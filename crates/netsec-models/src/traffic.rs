//! Traffic flow model types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A network traffic flow record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficFlow {
    pub id: Uuid,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}
