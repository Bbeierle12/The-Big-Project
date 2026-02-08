//! Device fingerprinting: OUI lookup and device classification.

use netsec_models::device::DeviceType;
use netsec_models::port::Port;
use std::collections::HashMap;
use std::sync::LazyLock;

/// Static OUI table mapping normalized MAC prefixes (first 8 chars, "XX:XX:XX")
/// to vendor names. This is a curated subset for demo/testing purposes, not a
/// full IEEE OUI database. See `data/oui_reference.json` for the canonical list.
static OUI_TABLE: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert("00:00:0C", "Cisco");
    m.insert("00:1A:2B", "Ayecom");
    m.insert("00:1B:63", "Apple");
    m.insert("00:1E:C2", "Apple");
    m.insert("00:50:56", "VMware");
    m.insert("00:0C:29", "VMware");
    m.insert("00:15:5D", "Microsoft");
    m.insert("00:1A:A0", "Dell");
    m.insert("00:14:22", "Dell");
    m.insert("00:25:B5", "Intel");
    m.insert("00:1B:21", "Intel");
    m.insert("3C:D9:2B", "HP");
    m.insert("00:1A:4B", "HP");
    m.insert("B8:27:EB", "Raspberry Pi Foundation");
    m.insert("DC:A6:32", "Raspberry Pi Foundation");
    m.insert("AC:DE:48", "Samsung");
    m.insert("00:1A:8A", "Samsung");
    m.insert("F8:1A:67", "TP-Link");
    m.insert("00:1D:7E", "Cisco");
    m.insert("00:26:CB", "Cisco");
    m.insert("00:17:88", "Signify N.V.");
    m.insert("44:D9:E7", "Ubiquiti");
    m.insert("80:2A:A8", "Ubiquiti");
    m.insert("00:1B:44", "SanDisk");
    m.insert("2C:F0:5D", "Juniper");
    m
});

/// Look up the vendor name for a MAC address via the OUI table.
///
/// Normalizes the MAC to uppercase and extracts the first 8 characters (XX:XX:XX).
/// Returns `None` if the MAC is too short or the prefix is not in the table.
pub fn lookup_oui(mac: &str) -> Option<&'static str> {
    let normalized = mac.to_uppercase();
    if normalized.len() < 8 {
        return None;
    }
    let prefix = &normalized[..8];
    OUI_TABLE.get(prefix).copied()
}

/// Classify a device based on its open ports, OS hint, and vendor.
///
/// Returns a `(DeviceType, confidence)` tuple. Rules are checked in priority order:
/// 1. OS hint contains "iOS"/"Android" -> Mobile (0.8)
/// 2. Vendor contains "Cisco"/"Juniper"/"Ubiquiti" -> Router (0.7)
/// 3. Port 631 or 9100 present -> Printer (0.7)
/// 4. Port 1883 (MQTT) or 5353 (mDNS) + no HTTP ports -> IoT (0.6)
/// 5. Multiple server ports (22, 80, 443, 8080, 3306, 5432) -> Server (0.7)
/// 6. Port 3389 (RDP) -> Workstation (0.6)
/// 7. Default -> Unknown (0.0)
pub fn classify_device(
    ports: &[Port],
    os_hint: Option<&str>,
    vendor: Option<&str>,
) -> (DeviceType, f64) {
    // Rule 1: Mobile by OS hint
    if let Some(os) = os_hint {
        let os_lower = os.to_lowercase();
        if os_lower.contains("ios") || os_lower.contains("android") {
            return (DeviceType::Mobile, 0.8);
        }
    }

    // Rule 2: Router by vendor
    if let Some(v) = vendor {
        let v_lower = v.to_lowercase();
        if v_lower.contains("cisco") || v_lower.contains("juniper") || v_lower.contains("ubiquiti")
        {
            return (DeviceType::Router, 0.7);
        }
    }

    let port_numbers: Vec<i64> = ports.iter().map(|p| p.port_number).collect();

    // Rule 3: Printer
    if port_numbers.contains(&631) || port_numbers.contains(&9100) {
        return (DeviceType::Printer, 0.7);
    }

    // Rule 4: IoT — MQTT or mDNS without HTTP
    let has_http = port_numbers.contains(&80)
        || port_numbers.contains(&443)
        || port_numbers.contains(&8080);
    if (port_numbers.contains(&1883) || port_numbers.contains(&5353)) && !has_http {
        return (DeviceType::IoT, 0.6);
    }

    // Rule 5: Server — multiple server ports
    let server_ports: &[i64] = &[22, 80, 443, 8080, 3306, 5432];
    let server_count = port_numbers
        .iter()
        .filter(|p| server_ports.contains(p))
        .count();
    if server_count >= 2 {
        return (DeviceType::Server, 0.7);
    }

    // Rule 6: Workstation by RDP
    if port_numbers.contains(&3389) {
        return (DeviceType::Workstation, 0.6);
    }

    // Rule 7: Default
    (DeviceType::Unknown, 0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_oui_known() {
        assert_eq!(lookup_oui("00:00:0C:11:22:33"), Some("Cisco"));
        assert_eq!(lookup_oui("B8:27:EB:AA:BB:CC"), Some("Raspberry Pi Foundation"));
    }

    #[test]
    fn test_lookup_oui_unknown() {
        assert_eq!(lookup_oui("FF:FF:FF:00:00:00"), None);
    }

    #[test]
    fn test_lookup_oui_case_insensitive() {
        assert_eq!(lookup_oui("b8:27:eb:aa:bb:cc"), Some("Raspberry Pi Foundation"));
        assert_eq!(lookup_oui("00:00:0c:11:22:33"), Some("Cisco"));
    }

    #[test]
    fn test_lookup_oui_short_mac() {
        assert_eq!(lookup_oui("00:00"), None);
        assert_eq!(lookup_oui(""), None);
    }

    fn make_port(port_number: u16) -> Port {
        Port::new("dev-1".into(), port_number, "tcp".into())
    }

    #[test]
    fn test_classify_server() {
        let ports = vec![make_port(22), make_port(80), make_port(443)];
        let (dt, conf) = classify_device(&ports, None, None);
        assert_eq!(dt, DeviceType::Server);
        assert!((conf - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn test_classify_printer() {
        let ports = vec![make_port(9100)];
        let (dt, conf) = classify_device(&ports, None, None);
        assert_eq!(dt, DeviceType::Printer);
        assert!((conf - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn test_classify_iot() {
        let ports = vec![make_port(1883)];
        let (dt, conf) = classify_device(&ports, None, None);
        assert_eq!(dt, DeviceType::IoT);
        assert!((conf - 0.6).abs() < f64::EPSILON);
    }

    #[test]
    fn test_classify_mobile() {
        let ports = vec![];
        let (dt, conf) = classify_device(&ports, Some("Android 13"), None);
        assert_eq!(dt, DeviceType::Mobile);
        assert!((conf - 0.8).abs() < f64::EPSILON);

        let (dt2, _) = classify_device(&ports, Some("iOS 17"), None);
        assert_eq!(dt2, DeviceType::Mobile);
    }

    #[test]
    fn test_classify_router() {
        let ports = vec![];
        let (dt, conf) = classify_device(&ports, None, Some("Cisco Systems"));
        assert_eq!(dt, DeviceType::Router);
        assert!((conf - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn test_classify_unknown() {
        let ports = vec![];
        let (dt, conf) = classify_device(&ports, None, None);
        assert_eq!(dt, DeviceType::Unknown);
        assert!((conf - 0.0).abs() < f64::EPSILON);
    }
}
