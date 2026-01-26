//! Nmap XML output parser.
//!
//! Ported from the original netsec-nmap crate. Parses Nmap's -oX XML output
//! into structured Rust types using quick-xml.

use quick_xml::events::Event;
use quick_xml::reader::Reader;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Result of parsing an Nmap XML scan.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NmapScanResult {
    pub scan_info: HashMap<String, String>,
    pub hosts: Vec<NmapHost>,
}

/// A single host discovered by Nmap.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NmapHost {
    pub status: String,
    pub addresses: HashMap<String, String>,
    pub hostnames: Vec<HashMap<String, String>>,
    pub ports: Vec<NmapPort>,
    pub os: HashMap<String, String>,
}

/// A port found on a host.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NmapPort {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: HashMap<String, String>,
}

/// Parse Nmap XML output into structured data.
pub fn parse_nmap_xml(xml_data: &str) -> Result<NmapScanResult, String> {
    let mut result = NmapScanResult::default();
    let mut reader = Reader::from_str(xml_data);
    reader.config_mut().trim_text(true);

    let mut current_host: Option<NmapHost> = None;
    let mut in_host = false;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();

                match name.as_str() {
                    "nmaprun" => {
                        for attr in e.attributes().flatten() {
                            let key =
                                String::from_utf8_lossy(attr.key.as_ref()).to_string();
                            let val =
                                String::from_utf8_lossy(&attr.value).to_string();
                            result.scan_info.insert(key, val);
                        }
                    }
                    "host" => {
                        in_host = true;
                        current_host = Some(NmapHost {
                            status: "unknown".to_string(),
                            ..Default::default()
                        });
                    }
                    "status" if in_host => {
                        if let Some(ref mut host) = current_host {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"state" {
                                    host.status = String::from_utf8_lossy(&attr.value)
                                        .to_string();
                                }
                            }
                        }
                    }
                    "address" if in_host => {
                        if let Some(ref mut host) = current_host {
                            let mut addr_type = String::new();
                            let mut addr_val = String::new();
                            let mut vendor = String::new();
                            for attr in e.attributes().flatten() {
                                match attr.key.as_ref() {
                                    b"addrtype" => {
                                        addr_type = String::from_utf8_lossy(&attr.value)
                                            .to_string()
                                    }
                                    b"addr" => {
                                        addr_val = String::from_utf8_lossy(&attr.value)
                                            .to_string()
                                    }
                                    b"vendor" => {
                                        vendor = String::from_utf8_lossy(&attr.value)
                                            .to_string()
                                    }
                                    _ => {}
                                }
                            }
                            host.addresses.insert(addr_type, addr_val);
                            if !vendor.is_empty() {
                                host.addresses
                                    .insert("vendor".to_string(), vendor);
                            }
                        }
                    }
                    "hostname" if in_host => {
                        if let Some(ref mut host) = current_host {
                            let mut hn = HashMap::new();
                            for attr in e.attributes().flatten() {
                                let key = String::from_utf8_lossy(attr.key.as_ref())
                                    .to_string();
                                let val =
                                    String::from_utf8_lossy(&attr.value).to_string();
                                hn.insert(key, val);
                            }
                            host.hostnames.push(hn);
                        }
                    }
                    "port" if in_host => {
                        if let Some(ref mut host) = current_host {
                            let mut port = NmapPort::default();
                            for attr in e.attributes().flatten() {
                                match attr.key.as_ref() {
                                    b"portid" => {
                                        let val = String::from_utf8_lossy(&attr.value)
                                            .to_string();
                                        port.port = val.parse().unwrap_or(0);
                                    }
                                    b"protocol" => {
                                        port.protocol =
                                            String::from_utf8_lossy(&attr.value)
                                                .to_string();
                                    }
                                    _ => {}
                                }
                            }
                            host.ports.push(port);
                        }
                    }
                    "state" if in_host => {
                        if let Some(ref mut host) = current_host {
                            if let Some(last) = host.ports.last_mut() {
                                for attr in e.attributes().flatten() {
                                    if attr.key.as_ref() == b"state" {
                                        last.state =
                                            String::from_utf8_lossy(&attr.value)
                                                .to_string();
                                    }
                                }
                            }
                        }
                    }
                    "service" if in_host => {
                        if let Some(ref mut host) = current_host {
                            if let Some(last) = host.ports.last_mut() {
                                for attr in e.attributes().flatten() {
                                    let key = String::from_utf8_lossy(
                                        attr.key.as_ref(),
                                    )
                                    .to_string();
                                    let val = String::from_utf8_lossy(&attr.value)
                                        .to_string();
                                    last.service.insert(key, val);
                                }
                            }
                        }
                    }
                    "osmatch" if in_host => {
                        if let Some(ref mut host) = current_host {
                            for attr in e.attributes().flatten() {
                                let key = String::from_utf8_lossy(attr.key.as_ref())
                                    .to_string();
                                let val =
                                    String::from_utf8_lossy(&attr.value).to_string();
                                host.os.insert(key, val);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if name == "host" {
                    if let Some(host) = current_host.take() {
                        result.hosts.push(host);
                    }
                    in_host = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {e}")),
            _ => {}
        }
        buf.clear();
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_xml() {
        let xml = r#"<?xml version="1.0"?><nmaprun scanner="nmap"></nmaprun>"#;
        let result = parse_nmap_xml(xml).unwrap();
        assert!(result.hosts.is_empty());
        assert_eq!(result.scan_info.get("scanner").unwrap(), "nmap");
    }

    #[test]
    fn test_parse_host_with_ports() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="TestVendor"/>
    <hostnames><hostname name="router.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>"#;
        let result = parse_nmap_xml(xml).unwrap();
        assert_eq!(result.hosts.len(), 1);
        let host = &result.hosts[0];
        assert_eq!(host.status, "up");
        assert_eq!(host.addresses.get("ipv4").unwrap(), "192.168.1.1");
        assert_eq!(host.addresses.get("vendor").unwrap(), "TestVendor");
        assert_eq!(host.ports.len(), 2);
        assert_eq!(host.ports[0].port, 80);
        assert_eq!(host.ports[0].state, "open");
        assert_eq!(host.ports[0].service.get("name").unwrap(), "http");
        assert_eq!(host.ports[1].port, 443);
    }

    // C1: Malformed input tests
    #[test]
    fn test_nmap_malformed_xml() {
        // Mismatched tags cause a parse error
        let result = parse_nmap_xml("<nmaprun><host></nmaprun>");
        assert!(result.is_err());
    }

    #[test]
    fn test_nmap_non_xml_returns_empty() {
        // Plain text is not an error but produces no hosts
        let result = parse_nmap_xml("this is not xml at all").unwrap();
        assert!(result.hosts.is_empty());
        assert!(result.scan_info.is_empty());
    }

    #[test]
    fn test_nmap_missing_nmaprun() {
        let xml = r#"<?xml version="1.0"?><other_root><item/></other_root>"#;
        let result = parse_nmap_xml(xml).unwrap();
        // Parses successfully but no hosts and no scan_info from nmaprun
        assert!(result.hosts.is_empty());
        assert!(result.scan_info.is_empty());
    }

    #[test]
    fn test_nmap_host_no_ports() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.168.1.5" addrtype="ipv4"/>
  </host>
</nmaprun>"#;
        let result = parse_nmap_xml(xml).unwrap();
        assert_eq!(result.hosts.len(), 1);
        assert_eq!(result.hosts[0].addresses.get("ipv4").unwrap(), "192.168.1.5");
        assert!(result.hosts[0].ports.is_empty());
    }

    // C2: Multiple hosts
    #[test]
    fn test_nmap_multiple_hosts() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/></port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/></port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.0.0.3" addrtype="ipv4"/>
  </host>
</nmaprun>"#;
        let result = parse_nmap_xml(xml).unwrap();
        assert_eq!(result.hosts.len(), 3);
        assert_eq!(result.hosts[0].addresses.get("ipv4").unwrap(), "10.0.0.1");
        assert_eq!(result.hosts[0].ports[0].port, 22);
        assert_eq!(result.hosts[1].addresses.get("ipv4").unwrap(), "10.0.0.2");
        assert_eq!(result.hosts[1].ports[0].port, 80);
        assert_eq!(result.hosts[2].status, "down");
        assert!(result.hosts[2].ports.is_empty());
    }
}
