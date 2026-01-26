//! Lightweight flow extraction from packet data.
//! Note: For actual PCAP parsing, a full library like pcap-parser would be used.
//! This provides a simplified flow aggregation from pre-parsed packet data.

use pyo3::prelude::*;
use pyo3::types::PyList;
use std::collections::HashMap;

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
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
    first_seen: String,
    last_seen: String,
}

/// Aggregate packet records into network flows.
///
/// Args:
///     packets_json: JSON string containing array of packet records.
///         Each record should have: src_ip, dst_ip, src_port, dst_port, protocol, bytes, timestamp
///
/// Returns:
///     List of flow dicts with aggregated statistics
#[pyfunction]
fn extract_flows(py: Python<'_>, packets_json: &str) -> PyResult<Py<PyList>> {
    let list = PyList::empty(py);

    let packets: Vec<serde_json::Value> = match serde_json::from_str(packets_json) {
        Ok(p) => p,
        Err(_) => return Ok(list.into()),
    };

    let mut flows: HashMap<FlowKey, FlowStats> = HashMap::new();

    for pkt in &packets {
        let src_ip = pkt.get("src_ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let dst_ip = pkt.get("dst_ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let src_port = pkt.get("src_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
        let dst_port = pkt.get("dst_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
        let protocol = pkt.get("protocol").and_then(|v| v.as_str()).unwrap_or("tcp").to_string();
        let bytes = pkt.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
        let timestamp = pkt.get("timestamp").and_then(|v| v.as_str()).unwrap_or("").to_string();

        let key = FlowKey {
            src_ip: src_ip.clone(),
            dst_ip: dst_ip.clone(),
            src_port,
            dst_port,
            protocol: protocol.clone(),
        };

        let entry = flows.entry(key).or_insert(FlowStats {
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            first_seen: timestamp.clone(),
            last_seen: timestamp.clone(),
        });

        entry.bytes_sent += bytes;
        entry.packets_sent += 1;
        entry.last_seen = timestamp;
    }

    for (key, stats) in &flows {
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("src_ip", &key.src_ip)?;
        dict.set_item("dst_ip", &key.dst_ip)?;
        dict.set_item("src_port", key.src_port)?;
        dict.set_item("dst_port", key.dst_port)?;
        dict.set_item("protocol", &key.protocol)?;
        dict.set_item("bytes_sent", stats.bytes_sent)?;
        dict.set_item("bytes_received", stats.bytes_received)?;
        dict.set_item("packets_sent", stats.packets_sent)?;
        dict.set_item("packets_received", stats.packets_received)?;
        dict.set_item("first_seen", &stats.first_seen)?;
        dict.set_item("last_seen", &stats.last_seen)?;
        list.append(dict)?;
    }

    Ok(list.into())
}
