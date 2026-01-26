//! Port model types.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A port discovered on a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct Port {
    pub id: String,
    pub device_id: String,
    pub port_number: i64,
    pub protocol: String,
    pub state: String,
    pub service_name: Option<String>,
    pub service_version: Option<String>,
    pub banner: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
}

impl Port {
    pub fn new(device_id: String, port_number: u16, protocol: String) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            id: Uuid::new_v4().to_string(),
            device_id,
            port_number: port_number as i64,
            protocol,
            state: "unknown".to_string(),
            service_name: None,
            service_version: None,
            banner: None,
            first_seen: now.clone(),
            last_seen: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_serde_roundtrip() {
        let port = Port::new("dev-1".into(), 443, "tcp".into());
        let json = serde_json::to_string(&port).unwrap();
        let back: Port = serde_json::from_str(&json).unwrap();
        assert_eq!(back.port_number, 443);
        assert_eq!(back.protocol, "tcp");
        assert_eq!(back.device_id, "dev-1");
    }
}
