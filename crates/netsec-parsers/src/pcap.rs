//! Lightweight flow extraction from packet data.
//!
//! Ported from the original netsec-stream crate's pcap_parser module.
//! Aggregates pre-parsed packet records into network flows.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A network flow aggregated from packet records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct FlowKey {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: String,
}

struct FlowStats {
    bytes_sent: u64,
    packets_sent: u64,
    first_seen: String,
    last_seen: String,
}

/// Aggregate packet records (as a JSON array string) into network flows.
pub fn extract_flows(packets_json: &str) -> Vec<Flow> {
    let packets: Vec<serde_json::Value> = match serde_json::from_str(packets_json) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };

    let mut flows: HashMap<FlowKey, FlowStats> = HashMap::new();

    for pkt in &packets {
        let src_ip = pkt
            .get("src_ip")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let dst_ip = pkt
            .get("dst_ip")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let src_port = pkt
            .get("src_port")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16;
        let dst_port = pkt
            .get("dst_port")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16;
        let protocol = pkt
            .get("protocol")
            .and_then(|v| v.as_str())
            .unwrap_or("tcp")
            .to_string();
        let bytes = pkt.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
        let timestamp = pkt
            .get("timestamp")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let key = FlowKey {
            src_ip: src_ip.clone(),
            dst_ip: dst_ip.clone(),
            src_port,
            dst_port,
            protocol: protocol.clone(),
        };

        let entry = flows.entry(key).or_insert(FlowStats {
            bytes_sent: 0,
            packets_sent: 0,
            first_seen: timestamp.clone(),
            last_seen: timestamp.clone(),
        });

        entry.bytes_sent += bytes;
        entry.packets_sent += 1;
        entry.last_seen = timestamp;
    }

    flows
        .into_iter()
        .map(|(key, stats)| Flow {
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            src_port: key.src_port,
            dst_port: key.dst_port,
            protocol: key.protocol,
            bytes_sent: stats.bytes_sent,
            bytes_received: 0,
            packets_sent: stats.packets_sent,
            packets_received: 0,
            first_seen: stats.first_seen,
            last_seen: stats.last_seen,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_flows_empty() {
        let flows = extract_flows("[]");
        assert!(flows.is_empty());
    }

    #[test]
    fn test_extract_flows_aggregation() {
        let json = r#"[
            {"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":12345,"dst_port":80,"protocol":"tcp","bytes":100,"timestamp":"t1"},
            {"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":12345,"dst_port":80,"protocol":"tcp","bytes":200,"timestamp":"t2"}
        ]"#;
        let flows = extract_flows(json);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].bytes_sent, 300);
        assert_eq!(flows[0].packets_sent, 2);
    }

    // C1: Malformed input
    #[test]
    fn test_pcap_malformed_json() {
        let flows = extract_flows("this is not json");
        assert!(flows.is_empty());
    }

    // C2: Single packet
    #[test]
    fn test_pcap_single_packet() {
        let json = r#"[
            {"src_ip":"10.0.0.5","dst_ip":"10.0.0.6","src_port":54321,"dst_port":443,"protocol":"tcp","bytes":64,"timestamp":"2024-01-15T10:00:00Z"}
        ]"#;
        let flows = extract_flows(json);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].packets_sent, 1);
        assert_eq!(flows[0].bytes_sent, 64);
        assert_eq!(flows[0].src_ip, "10.0.0.5");
        assert_eq!(flows[0].dst_ip, "10.0.0.6");
        assert_eq!(flows[0].src_port, 54321);
        assert_eq!(flows[0].dst_port, 443);
    }
}
