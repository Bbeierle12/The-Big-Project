//! Alert normalization stage.
//!
//! Converts raw parser output (Nmap, Suricata, Zeek, PCAP) into [`NormalizedAlert`]s.

use chrono::Utc;
use netsec_models::alert::{AlertCategory, NormalizedAlert, Severity};
use netsec_parsers::nmap::NmapHost;
use netsec_parsers::pcap::Flow;
use netsec_parsers::suricata::EveEvent;
use netsec_parsers::zeek::ZeekRecord;

use crate::PipelineError;

/// Wrapper enum for all parser output types.
pub enum ParserOutput {
    Nmap(NmapHost),
    Suricata(EveEvent),
    Zeek(ZeekRecord),
    Pcap(Flow),
}

/// Normalize parser output into a list of [`NormalizedAlert`]s.
pub fn normalize(input: ParserOutput) -> Result<Vec<NormalizedAlert>, PipelineError> {
    match input {
        ParserOutput::Nmap(host) => normalize_nmap(host),
        ParserOutput::Suricata(event) => normalize_suricata(event),
        ParserOutput::Zeek(record) => normalize_zeek(record),
        ParserOutput::Pcap(flow) => normalize_pcap(flow),
    }
}

fn normalize_nmap(host: NmapHost) -> Result<Vec<NormalizedAlert>, PipelineError> {
    let mut alerts = Vec::new();
    let ip = host
        .addresses
        .get("ipv4")
        .or_else(|| host.addresses.get("ipv6"))
        .cloned()
        .unwrap_or_default();

    // One alert per open port
    for port in &host.ports {
        if port.state != "open" {
            continue;
        }
        let service_name = port
            .service
            .get("name")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let fingerprint = format!(
            "nmap:open_port:{}:{}:{}",
            ip, port.port, port.protocol
        );

        alerts.push(NormalizedAlert {
            source_tool: "nmap".to_string(),
            severity: Severity::Info,
            category: AlertCategory::Vulnerability,
            title: format!("Open port {}/{} ({})", port.port, port.protocol, service_name),
            description: format!(
                "Nmap discovered open port {}/{} running {} on {}",
                port.port, port.protocol, service_name, ip
            ),
            device_ip: Some(ip.clone()),
            fingerprint,
            raw_data: serde_json::json!({
                "port": port.port,
                "protocol": port.protocol,
                "state": port.state,
                "service": port.service,
            }),
            timestamp: Utc::now(),
        });
    }

    // One alert for OS detection if present
    if let Some(os_name) = host.os.get("name") {
        let fingerprint = format!("nmap:os_detect:{}:{}", ip, os_name);
        alerts.push(NormalizedAlert {
            source_tool: "nmap".to_string(),
            severity: Severity::Info,
            category: AlertCategory::Other,
            title: format!("OS detected: {}", os_name),
            description: format!(
                "Nmap OS detection identified {} on {}",
                os_name, ip
            ),
            device_ip: Some(ip.clone()),
            fingerprint,
            raw_data: serde_json::json!({ "os": host.os }),
            timestamp: Utc::now(),
        });
    }

    Ok(alerts)
}

fn normalize_suricata(event: EveEvent) -> Result<Vec<NormalizedAlert>, PipelineError> {
    let alert_data = match &event.alert {
        Some(a) => a,
        None => return Ok(Vec::new()),
    };

    let severity = match alert_data.severity {
        Some(1) => Severity::Critical,
        Some(2) => Severity::High,
        Some(3) => Severity::Medium,
        _ => Severity::Low,
    };

    let sig_id = alert_data.signature_id.unwrap_or(0);
    let src_ip = event.src_ip.clone().unwrap_or_default();
    let dest_ip = event.dest_ip.clone().unwrap_or_default();

    let fingerprint = format!("suricata:{}:{}:{}", sig_id, src_ip, dest_ip);

    let category = categorize_suricata(
        alert_data
            .category
            .as_deref()
            .unwrap_or(""),
    );

    let title = alert_data
        .signature
        .clone()
        .unwrap_or_else(|| format!("Suricata alert SID {}", sig_id));

    let normalized = NormalizedAlert {
        source_tool: "suricata".to_string(),
        severity,
        category,
        title,
        description: format!(
            "Suricata alert: {} (SID {}) from {} to {}",
            alert_data.signature.as_deref().unwrap_or("unknown"),
            sig_id,
            src_ip,
            dest_ip,
        ),
        device_ip: event.src_ip.clone(),
        fingerprint,
        raw_data: serde_json::json!({
            "sig_id": sig_id,
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "src_port": event.src_port,
            "dest_port": event.dest_port,
            "proto": event.proto,
            "action": alert_data.action,
            "category": alert_data.category,
        }),
        timestamp: Utc::now(),
    };

    Ok(vec![normalized])
}

fn normalize_zeek(record: ZeekRecord) -> Result<Vec<NormalizedAlert>, PipelineError> {
    let conn_state = match record.get("conn_state") {
        Some(s) => s.as_str(),
        None => return Ok(Vec::new()),
    };

    // Only anomalous connection states
    if !matches!(conn_state, "S0" | "REJ" | "RSTO" | "RSTR") {
        return Ok(Vec::new());
    }

    let orig_h = record.get("id.orig_h").cloned().unwrap_or_default();
    let resp_h = record.get("id.resp_h").cloned().unwrap_or_default();
    let resp_p = record.get("id.resp_p").cloned().unwrap_or_default();
    let proto = record.get("proto").cloned().unwrap_or_else(|| "tcp".to_string());

    let fingerprint = format!(
        "zeek:{}:{}:{}:{}:{}",
        conn_state, orig_h, resp_h, resp_p, proto
    );

    let title = format!("Zeek anomalous connection state: {}", conn_state);
    let description = format!(
        "Connection from {} to {}:{} ({}) ended with state {}",
        orig_h, resp_h, resp_p, proto, conn_state
    );

    let raw_data = serde_json::to_value(&record).unwrap_or_default();

    let normalized = NormalizedAlert {
        source_tool: "zeek".to_string(),
        severity: Severity::Low,
        category: AlertCategory::Anomaly,
        title,
        description,
        device_ip: Some(orig_h),
        fingerprint,
        raw_data,
        timestamp: Utc::now(),
    };

    Ok(vec![normalized])
}

fn normalize_pcap(flow: Flow) -> Result<Vec<NormalizedAlert>, PipelineError> {
    const BYTES_THRESHOLD: u64 = 1_000_000; // 1 MB
    const PACKETS_THRESHOLD: u64 = 1_000;

    if flow.bytes_sent < BYTES_THRESHOLD && flow.packets_sent < PACKETS_THRESHOLD {
        return Ok(Vec::new());
    }

    let fingerprint = format!(
        "pcap:volume:{}:{}:{}:{}",
        flow.src_ip, flow.dst_ip, flow.dst_port, flow.protocol
    );

    let title = format!(
        "High volume traffic: {} -> {}:{}",
        flow.src_ip, flow.dst_ip, flow.dst_port
    );
    let description = format!(
        "Flow from {}:{} to {}:{} ({}) sent {} bytes in {} packets",
        flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.protocol,
        flow.bytes_sent, flow.packets_sent,
    );

    let normalized = NormalizedAlert {
        source_tool: "pcap".to_string(),
        severity: Severity::Medium,
        category: AlertCategory::Anomaly,
        title,
        description,
        device_ip: Some(flow.src_ip.clone()),
        fingerprint,
        raw_data: serde_json::json!({
            "src": flow.src_ip,
            "dst": flow.dst_ip,
            "src_port": flow.src_port,
            "port": flow.dst_port,
            "proto": flow.protocol,
            "bytes_sent": flow.bytes_sent,
            "packets_sent": flow.packets_sent,
        }),
        timestamp: Utc::now(),
    };

    Ok(vec![normalized])
}

/// Map a Suricata alert category string to an [`AlertCategory`].
pub fn categorize_suricata(category: &str) -> AlertCategory {
    let lower = category.to_lowercase();
    if lower.contains("trojan") || lower.contains("malware") || lower.contains("virus") {
        AlertCategory::Malware
    } else if lower.contains("intrusion")
        || lower.contains("exploit")
        || lower.contains("shellcode")
    {
        AlertCategory::Intrusion
    } else if lower.contains("policy") || lower.contains("compliance") {
        AlertCategory::PolicyViolation
    } else if lower.contains("scan") || lower.contains("recon") || lower.contains("information leak") {
        AlertCategory::NetworkThreat
    } else if lower.contains("anomal") {
        AlertCategory::Anomaly
    } else if lower.contains("vuln") {
        AlertCategory::Vulnerability
    } else {
        AlertCategory::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netsec_parsers::nmap::NmapPort;
    use std::collections::HashMap;

    fn make_nmap_host(ports: Vec<NmapPort>, os: HashMap<String, String>) -> NmapHost {
        let mut addresses = HashMap::new();
        addresses.insert("ipv4".to_string(), "10.0.0.1".to_string());
        NmapHost {
            status: "up".to_string(),
            addresses,
            hostnames: vec![],
            ports,
            os,
        }
    }

    #[test]
    fn test_nmap_open_ports() {
        let ports = vec![
            NmapPort {
                port: 22,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                service: {
                    let mut m = HashMap::new();
                    m.insert("name".to_string(), "ssh".to_string());
                    m
                },
            },
            NmapPort {
                port: 80,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                service: {
                    let mut m = HashMap::new();
                    m.insert("name".to_string(), "http".to_string());
                    m
                },
            },
        ];
        let host = make_nmap_host(ports, HashMap::new());
        let alerts = normalize(ParserOutput::Nmap(host)).unwrap();
        assert_eq!(alerts.len(), 2);
        assert!(alerts[0].title.contains("22"));
        assert!(alerts[1].title.contains("80"));
        assert_eq!(alerts[0].severity, Severity::Info);
    }

    #[test]
    fn test_nmap_os_detection() {
        let mut os = HashMap::new();
        os.insert("name".to_string(), "Linux 5.4".to_string());
        let host = make_nmap_host(vec![], os);
        let alerts = normalize(ParserOutput::Nmap(host)).unwrap();
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].title.contains("Linux 5.4"));
    }

    #[test]
    fn test_nmap_no_open_ports() {
        let ports = vec![NmapPort {
            port: 22,
            protocol: "tcp".to_string(),
            state: "filtered".to_string(),
            service: HashMap::new(),
        }];
        let host = make_nmap_host(ports, HashMap::new());
        let alerts = normalize(ParserOutput::Nmap(host)).unwrap();
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_nmap_fingerprint_determinism() {
        let ports = vec![NmapPort {
            port: 443,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service: HashMap::new(),
        }];
        let host1 = make_nmap_host(ports.clone(), HashMap::new());
        let host2 = make_nmap_host(ports, HashMap::new());
        let a1 = normalize(ParserOutput::Nmap(host1)).unwrap();
        let a2 = normalize(ParserOutput::Nmap(host2)).unwrap();
        assert_eq!(a1[0].fingerprint, a2[0].fingerprint);
        assert_eq!(a1[0].fingerprint, "nmap:open_port:10.0.0.1:443:tcp");
    }

    #[test]
    fn test_suricata_with_alert() {
        let event = EveEvent {
            timestamp: Some("2024-01-15T10:00:00".to_string()),
            event_type: Some("alert".to_string()),
            src_ip: Some("10.0.0.1".to_string()),
            src_port: Some(12345),
            dest_ip: Some("10.0.0.2".to_string()),
            dest_port: Some(80),
            proto: Some("TCP".to_string()),
            alert: Some(netsec_parsers::suricata::EveAlert {
                action: Some("allowed".to_string()),
                signature: Some("ET SCAN Nmap".to_string()),
                signature_id: Some(2000001),
                severity: Some(2),
                category: Some("Attempted Information Leak".to_string()),
            }),
        };
        let alerts = normalize(ParserOutput::Suricata(event)).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::High);
        assert!(alerts[0].fingerprint.contains("2000001"));
    }

    #[test]
    fn test_suricata_without_alert() {
        let event = EveEvent {
            timestamp: Some("2024-01-15T10:00:00".to_string()),
            event_type: Some("flow".to_string()),
            src_ip: Some("10.0.0.1".to_string()),
            src_port: None,
            dest_ip: None,
            dest_port: None,
            proto: None,
            alert: None,
        };
        let alerts = normalize(ParserOutput::Suricata(event)).unwrap();
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_suricata_severity_mapping() {
        let make_event = |sev: u8| EveEvent {
            timestamp: None,
            event_type: Some("alert".to_string()),
            src_ip: Some("1.2.3.4".to_string()),
            src_port: None,
            dest_ip: Some("5.6.7.8".to_string()),
            dest_port: None,
            proto: None,
            alert: Some(netsec_parsers::suricata::EveAlert {
                action: None,
                signature: Some("test".to_string()),
                signature_id: Some(1),
                severity: Some(sev),
                category: None,
            }),
        };

        let crit = normalize(ParserOutput::Suricata(make_event(1))).unwrap();
        assert_eq!(crit[0].severity, Severity::Critical);

        let high = normalize(ParserOutput::Suricata(make_event(2))).unwrap();
        assert_eq!(high[0].severity, Severity::High);

        let med = normalize(ParserOutput::Suricata(make_event(3))).unwrap();
        assert_eq!(med[0].severity, Severity::Medium);

        let low = normalize(ParserOutput::Suricata(make_event(4))).unwrap();
        assert_eq!(low[0].severity, Severity::Low);
    }

    #[test]
    fn test_zeek_anomalous_states() {
        for state in &["S0", "REJ", "RSTO", "RSTR"] {
            let mut record = HashMap::new();
            record.insert("conn_state".to_string(), state.to_string());
            record.insert("id.orig_h".to_string(), "10.0.0.1".to_string());
            record.insert("id.resp_h".to_string(), "10.0.0.2".to_string());
            record.insert("id.resp_p".to_string(), "80".to_string());
            record.insert("proto".to_string(), "tcp".to_string());

            let alerts = normalize(ParserOutput::Zeek(record)).unwrap();
            assert_eq!(alerts.len(), 1, "state {} should produce 1 alert", state);
            assert!(alerts[0].title.contains(state));
        }
    }

    #[test]
    fn test_zeek_normal_state() {
        let mut record = HashMap::new();
        record.insert("conn_state".to_string(), "SF".to_string());
        record.insert("id.orig_h".to_string(), "10.0.0.1".to_string());
        record.insert("id.resp_h".to_string(), "10.0.0.2".to_string());

        let alerts = normalize(ParserOutput::Zeek(record)).unwrap();
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_pcap_high_volume() {
        let flow = Flow {
            src_ip: "10.0.0.1".to_string(),
            dst_ip: "10.0.0.2".to_string(),
            src_port: 12345,
            dst_port: 443,
            protocol: "tcp".to_string(),
            bytes_sent: 2_000_000,
            bytes_received: 0,
            packets_sent: 500,
            packets_received: 0,
            first_seen: "t1".to_string(),
            last_seen: "t2".to_string(),
        };
        let alerts = normalize(ParserOutput::Pcap(flow)).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::Medium);
    }

    #[test]
    fn test_pcap_normal_volume() {
        let flow = Flow {
            src_ip: "10.0.0.1".to_string(),
            dst_ip: "10.0.0.2".to_string(),
            src_port: 12345,
            dst_port: 80,
            protocol: "tcp".to_string(),
            bytes_sent: 500,
            bytes_received: 0,
            packets_sent: 10,
            packets_received: 0,
            first_seen: "t1".to_string(),
            last_seen: "t2".to_string(),
        };
        let alerts = normalize(ParserOutput::Pcap(flow)).unwrap();
        assert!(alerts.is_empty());
    }
}
