//! Traffic flow model types.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A network traffic flow record (database row).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct TrafficFlow {
    pub id: String,
    pub src_ip: String,
    pub src_port: i64,
    pub dst_ip: String,
    pub dst_port: i64,
    pub protocol: String,
    pub bytes_sent: i64,
    pub bytes_received: i64,
    pub packets_sent: i64,
    pub packets_received: i64,
    pub first_seen: String,
    pub last_seen: String,
}

impl TrafficFlow {
    pub fn new(src_ip: String, src_port: u16, dst_ip: String, dst_port: u16, protocol: String) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            id: Uuid::new_v4().to_string(),
            src_ip,
            src_port: src_port as i64,
            dst_ip,
            dst_port: dst_port as i64,
            protocol,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            first_seen: now.clone(),
            last_seen: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traffic_serde_roundtrip() {
        let flow = TrafficFlow::new("10.0.0.1".into(), 12345, "10.0.0.2".into(), 80, "tcp".into());
        let json = serde_json::to_string(&flow).unwrap();
        let back: TrafficFlow = serde_json::from_str(&json).unwrap();
        assert_eq!(back.src_ip, "10.0.0.1");
        assert_eq!(back.dst_port, 80);
    }
}
