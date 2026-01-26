//! Passive discovery: mDNS and SSDP response parsing, device upsert logic.

use chrono::Utc;
use netsec_models::device::{Device, DeviceStatus};
use netsec_models::event::Observation;
use sqlx::SqlitePool;

use crate::ScannerResult;

/// A parsed mDNS record.
#[derive(Debug, Clone)]
pub struct MdnsRecord {
    pub hostname: Option<String>,
    pub service_type: String,
    pub ip: Option<String>,
    pub port: Option<u16>,
}

/// A parsed SSDP device response.
#[derive(Debug, Clone)]
pub struct SsdpDevice {
    pub location: String,
    pub server: Option<String>,
    pub usn: Option<String>,
    pub st: Option<String>,
}

/// Parse an mDNS service name like `_http._tcp.local` into `("http", "tcp")`.
///
/// Returns `None` if the name does not match the expected `_<service>._<proto>` pattern.
pub fn parse_mdns_name(name: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    let service_part = parts[0];
    let proto_part = parts[1];

    if !service_part.starts_with('_') || !proto_part.starts_with('_') {
        return None;
    }

    let service = service_part.trim_start_matches('_');
    let proto = proto_part.trim_start_matches('_');

    if service.is_empty() || proto.is_empty() {
        return None;
    }

    Some((service.to_string(), proto.to_string()))
}

/// Parse an SSDP M-SEARCH response (HTTP-like headers) into an `SsdpDevice`.
///
/// Requires at minimum a `LOCATION` header. Returns `None` otherwise.
pub fn parse_ssdp_response(response: &str) -> Option<SsdpDevice> {
    if response.trim().is_empty() {
        return None;
    }

    let mut location = None;
    let mut server = None;
    let mut usn = None;
    let mut st = None;

    for line in response.lines() {
        let line = line.trim();
        if let Some((key, value)) = line.split_once(':') {
            let key_upper = key.trim().to_uppercase();
            let value = value.trim().to_string();
            match key_upper.as_str() {
                "LOCATION" => location = Some(value),
                "SERVER" => server = Some(value),
                "USN" => usn = Some(value),
                "ST" => st = Some(value),
                _ => {}
            }
        }
    }

    let location = location?;

    Some(SsdpDevice {
        location,
        server,
        usn,
        st,
    })
}

/// Upsert a device from mDNS discovery.
///
/// If a device with the given IP already exists, updates `last_seen`, `status`, and
/// optionally merges the hostname. Otherwise inserts a new device.
/// Records an `Observation` with protocol "mdns".
pub async fn process_mdns_discovery(
    pool: &SqlitePool,
    record: &MdnsRecord,
    source_ip: &str,
) -> ScannerResult<Device> {
    let now = Utc::now().to_rfc3339();
    let ip = record.ip.as_deref().unwrap_or(source_ip);

    let device = match netsec_db::repo::devices::get_by_ip(pool, ip).await? {
        Some(mut existing) => {
            existing.last_seen = now.clone();
            existing.status = DeviceStatus::Online.as_str().to_string();
            if existing.hostname.is_none() {
                existing.hostname = record.hostname.clone();
            }
            netsec_db::repo::devices::update(pool, &existing).await?;
            existing
        }
        None => {
            let mut device = Device::new(ip.to_string());
            device.hostname = record.hostname.clone();
            device.status = DeviceStatus::Online.as_str().to_string();
            device.last_seen = now.clone();
            device.first_seen = now.clone();
            netsec_db::repo::devices::insert(pool, &device).await?;
            device
        }
    };

    // Record observation
    let obs = Observation::new(
        device.id.clone(),
        "mdns".to_string(),
        serde_json::json!({
            "hostname": record.hostname,
            "service_type": record.service_type,
            "ip": record.ip,
            "port": record.port,
        }),
    );
    netsec_db::repo::observations::insert(pool, &obs).await?;

    Ok(device)
}

/// Upsert a device from SSDP discovery.
///
/// If a device with the given IP already exists, updates `last_seen`, `status`, and
/// optionally merges server info into hostname. Otherwise inserts a new device.
/// Records an `Observation` with protocol "ssdp".
pub async fn process_ssdp_discovery(
    pool: &SqlitePool,
    ssdp: &SsdpDevice,
    source_ip: &str,
) -> ScannerResult<Device> {
    let now = Utc::now().to_rfc3339();

    let device = match netsec_db::repo::devices::get_by_ip(pool, source_ip).await? {
        Some(mut existing) => {
            existing.last_seen = now.clone();
            existing.status = DeviceStatus::Online.as_str().to_string();
            if existing.hostname.is_none() {
                existing.hostname = ssdp.server.clone();
            }
            netsec_db::repo::devices::update(pool, &existing).await?;
            existing
        }
        None => {
            let mut device = Device::new(source_ip.to_string());
            device.hostname = ssdp.server.clone();
            device.status = DeviceStatus::Online.as_str().to_string();
            device.last_seen = now.clone();
            device.first_seen = now.clone();
            netsec_db::repo::devices::insert(pool, &device).await?;
            device
        }
    };

    // Record observation
    let obs = Observation::new(
        device.id.clone(),
        "ssdp".to_string(),
        serde_json::json!({
            "location": ssdp.location,
            "server": ssdp.server,
            "usn": ssdp.usn,
            "st": ssdp.st,
        }),
    );
    netsec_db::repo::observations::insert(pool, &obs).await?;

    Ok(device)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mdns_name_valid() {
        let result = parse_mdns_name("_http._tcp.local");
        assert_eq!(result, Some(("http".to_string(), "tcp".to_string())));
    }

    #[test]
    fn test_parse_mdns_name_invalid() {
        assert_eq!(parse_mdns_name("garbage"), None);
        assert_eq!(parse_mdns_name("no_dots"), None);
    }

    #[test]
    fn test_parse_mdns_name_no_underscores() {
        assert_eq!(parse_mdns_name("foo.local"), None);
        assert_eq!(parse_mdns_name("http.tcp.local"), None);
    }

    #[test]
    fn test_parse_ssdp_response_valid() {
        let response = "HTTP/1.1 200 OK\r\n\
                         LOCATION: http://192.168.1.1:80/desc.xml\r\n\
                         SERVER: Linux/3.0 UPnP/1.0\r\n\
                         USN: uuid:device-1234\r\n\
                         ST: upnp:rootdevice\r\n\r\n";
        let result = parse_ssdp_response(response).unwrap();
        assert_eq!(result.location, "http://192.168.1.1:80/desc.xml");
        assert_eq!(result.server.as_deref(), Some("Linux/3.0 UPnP/1.0"));
        assert_eq!(result.usn.as_deref(), Some("uuid:device-1234"));
        assert_eq!(result.st.as_deref(), Some("upnp:rootdevice"));
    }

    #[test]
    fn test_parse_ssdp_response_missing_location() {
        let response = "SERVER: Linux/3.0\r\nUSN: uuid:1234\r\n";
        assert!(parse_ssdp_response(response).is_none());
    }

    #[test]
    fn test_parse_ssdp_response_empty() {
        assert!(parse_ssdp_response("").is_none());
        assert!(parse_ssdp_response("  ").is_none());
    }

    #[tokio::test]
    async fn test_process_mdns_creates_device() {
        let pool = netsec_db::pool::create_test_pool().await.unwrap();
        netsec_db::run_migrations(&pool).await.unwrap();

        let record = MdnsRecord {
            hostname: Some("mydevice.local".to_string()),
            service_type: "_http._tcp.local".to_string(),
            ip: Some("192.168.1.50".to_string()),
            port: Some(80),
        };

        let device = process_mdns_discovery(&pool, &record, "192.168.1.50")
            .await
            .unwrap();
        assert_eq!(device.ip, "192.168.1.50");
        assert_eq!(device.hostname.as_deref(), Some("mydevice.local"));
        assert_eq!(device.status, "online");

        // Verify in DB
        let from_db = netsec_db::repo::devices::get_by_ip(&pool, "192.168.1.50")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(from_db.id, device.id);

        // Verify observation recorded
        let obs = netsec_db::repo::observations::list_by_device(&pool, &device.id, 10)
            .await
            .unwrap();
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].protocol, "mdns");
    }

    #[tokio::test]
    async fn test_process_mdns_updates_existing() {
        let pool = netsec_db::pool::create_test_pool().await.unwrap();
        netsec_db::run_migrations(&pool).await.unwrap();

        // Insert existing device
        let mut existing = Device::new("192.168.1.60".to_string());
        existing.status = "offline".to_string();
        existing.hostname = Some("old-name".to_string());
        let original_last_seen = existing.last_seen.clone();
        netsec_db::repo::devices::insert(&pool, &existing)
            .await
            .unwrap();

        let record = MdnsRecord {
            hostname: Some("new-name.local".to_string()),
            service_type: "_http._tcp.local".to_string(),
            ip: Some("192.168.1.60".to_string()),
            port: None,
        };

        let device = process_mdns_discovery(&pool, &record, "192.168.1.60")
            .await
            .unwrap();
        assert_eq!(device.id, existing.id);
        assert_eq!(device.status, "online");
        // Hostname should NOT be overwritten since it already exists
        assert_eq!(device.hostname.as_deref(), Some("old-name"));
        assert_ne!(device.last_seen, original_last_seen);
    }

    #[tokio::test]
    async fn test_process_ssdp_creates_device_and_observation() {
        let pool = netsec_db::pool::create_test_pool().await.unwrap();
        netsec_db::run_migrations(&pool).await.unwrap();

        let ssdp = SsdpDevice {
            location: "http://192.168.1.70:80/desc.xml".to_string(),
            server: Some("Linux UPnP/1.0".to_string()),
            usn: Some("uuid:device-abc".to_string()),
            st: Some("upnp:rootdevice".to_string()),
        };

        let device = process_ssdp_discovery(&pool, &ssdp, "192.168.1.70")
            .await
            .unwrap();
        assert_eq!(device.ip, "192.168.1.70");
        assert_eq!(device.hostname.as_deref(), Some("Linux UPnP/1.0"));
        assert_eq!(device.status, "online");

        // Verify observation
        let obs = netsec_db::repo::observations::list_by_device(&pool, &device.id, 10)
            .await
            .unwrap();
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].protocol, "ssdp");
    }
}
