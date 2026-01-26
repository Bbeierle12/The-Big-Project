//! Suricata EVE JSON log parser.
//!
//! Ported from the original netsec-stream crate's suri_parser module.

use serde::{Deserialize, Serialize};

/// A parsed Suricata EVE event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EveEvent {
    pub timestamp: Option<String>,
    pub event_type: Option<String>,
    pub src_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dest_ip: Option<String>,
    pub dest_port: Option<u16>,
    pub proto: Option<String>,
    pub alert: Option<EveAlert>,
}

/// Alert details within an EVE event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EveAlert {
    pub action: Option<String>,
    pub signature: Option<String>,
    pub signature_id: Option<u64>,
    pub severity: Option<u8>,
    pub category: Option<String>,
}

/// Parse a batch of newline-delimited EVE JSON lines.
///
/// If `alerts_only` is true, only events with `event_type == "alert"` are returned.
pub fn parse_eve_batch(data: &str, alerts_only: bool) -> Vec<EveEvent> {
    let mut results = Vec::new();

    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let event: EveEvent = match serde_json::from_str(line) {
            Ok(e) => e,
            Err(_) => continue,
        };

        if alerts_only && event.event_type.as_deref() != Some("alert") {
            continue;
        }

        results.push(event);
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_alert_event() {
        let data = r#"{"timestamp":"2024-01-15T10:00:00","event_type":"alert","src_ip":"10.0.0.1","src_port":12345,"dest_ip":"10.0.0.2","dest_port":80,"proto":"TCP","alert":{"action":"allowed","signature":"ET SCAN","signature_id":2000001,"severity":3,"category":"Attempted Information Leak"}}"#;
        let events = parse_eve_batch(data, true);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].src_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(events[0].alert.as_ref().unwrap().severity, Some(3));
    }

    #[test]
    fn test_filter_non_alerts() {
        let data = r#"{"timestamp":"2024-01-15T10:00:00","event_type":"flow","src_ip":"10.0.0.1"}
{"timestamp":"2024-01-15T10:00:01","event_type":"alert","src_ip":"10.0.0.2","alert":{"action":"allowed","signature":"test","signature_id":1,"severity":1,"category":"test"}}"#;
        let alerts = parse_eve_batch(data, true);
        assert_eq!(alerts.len(), 1);
        let all = parse_eve_batch(data, false);
        assert_eq!(all.len(), 2);
    }
}
