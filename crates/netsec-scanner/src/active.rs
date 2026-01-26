//! Active scanning: nmap argument building, result processing, and device persistence.

use chrono::Utc;
use netsec_events::EventBus;
use netsec_models::device::{Device, DeviceStatus};
use netsec_models::event::{EventType, NetsecEvent};
use netsec_models::port::Port;
use netsec_models::scan::{Scan, ScanStatus, ScanType};
use netsec_parsers::nmap::NmapScanResult;
use sqlx::SqlitePool;

use crate::fingerprint;
use crate::ScannerResult;

/// Configuration for an active scan.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// CIDR or IP target (e.g. "192.168.1.0/24").
    pub target: String,
    /// The type of scan to perform.
    pub scan_type: ScanType,
    /// Nmap timing template (0-5, maps to -T flag).
    pub timing: u8,
    /// Optional port specification (e.g. "22,80,443" or "1-1024").
    pub ports: Option<String>,
}

/// A host discovered during an active scan (intermediate representation).
#[derive(Debug, Clone)]
pub struct DiscoveredHost {
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub os_info: Option<String>,
    pub ports: Vec<DiscoveredPort>,
}

/// A port discovered on a host (intermediate representation).
#[derive(Debug, Clone)]
pub struct DiscoveredPort {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service_name: Option<String>,
    pub service_version: Option<String>,
}

/// Build nmap command-line arguments from a scan configuration.
///
/// Scan types:
/// - Discovery: `-sn -T{timing} {target}`
/// - Port: `-sS -T{timing} [-p ports] -oX - {target}`
/// - Full: `-sS -sV -O -T{timing} -oX - {target}`
/// - Others: treated like Port scan
///
/// Always includes `-oX -` for XML output to stdout (except Discovery).
pub fn build_nmap_args(config: &ScanConfig) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();

    match config.scan_type {
        ScanType::Discovery => {
            args.push("-sn".to_string());
            args.push(format!("-T{}", config.timing.min(5)));
            args.push(config.target.clone());
        }
        ScanType::Full => {
            args.push("-sS".to_string());
            args.push("-sV".to_string());
            args.push("-O".to_string());
            args.push(format!("-T{}", config.timing.min(5)));
            args.push("-oX".to_string());
            args.push("-".to_string());
            args.push(config.target.clone());
        }
        _ => {
            // Port, Vulnerability, Custom — all use port-scan style
            args.push("-sS".to_string());
            args.push(format!("-T{}", config.timing.min(5)));
            if let Some(ref ports) = config.ports {
                args.push("-p".to_string());
                args.push(ports.clone());
            }
            args.push("-oX".to_string());
            args.push("-".to_string());
            args.push(config.target.clone());
        }
    }

    args
}

/// Convert a parsed `NmapScanResult` into `DiscoveredHost` structs.
///
/// Only includes hosts with status "up". Extracts IP from `addresses["ipv4"]`,
/// MAC from `addresses["mac"]`, vendor from `addresses["vendor"]`,
/// hostname from the first `hostnames` entry, and OS from `os["name"]`.
pub fn process_nmap_results(scan_result: &NmapScanResult) -> Vec<DiscoveredHost> {
    scan_result
        .hosts
        .iter()
        .filter(|h| h.status == "up")
        .filter_map(|host| {
            let ip = host.addresses.get("ipv4").or(host.addresses.get("ipv6"))?;

            let mac = host.addresses.get("mac").cloned();
            let vendor = host.addresses.get("vendor").cloned();
            let hostname = host
                .hostnames
                .first()
                .and_then(|hn| hn.get("name").cloned());
            let os_info = host.os.get("name").cloned();

            let ports = host
                .ports
                .iter()
                .map(|p| DiscoveredPort {
                    port: p.port,
                    protocol: p.protocol.clone(),
                    state: p.state.clone(),
                    service_name: p.service.get("name").cloned(),
                    service_version: p.service.get("version").cloned(),
                })
                .collect();

            Some(DiscoveredHost {
                ip: ip.clone(),
                mac,
                hostname,
                vendor,
                os_info,
                ports,
            })
        })
        .collect()
}

/// Active scanner with database persistence and event publishing.
pub struct ActiveScanner {
    pool: SqlitePool,
    event_bus: EventBus,
}

impl ActiveScanner {
    pub fn new(pool: SqlitePool, event_bus: EventBus) -> Self {
        Self { pool, event_bus }
    }

    /// Persist discovered hosts to the database.
    ///
    /// For each host:
    /// 1. Upsert device (by IP)
    /// 2. Upsert each port
    /// 3. Classify device based on ports, OS, and vendor
    /// 4. Publish `DeviceDiscovered` (new) or `DeviceUpdated` (existing) event
    pub async fn persist_hosts(
        &self,
        hosts: &[DiscoveredHost],
    ) -> ScannerResult<Vec<Device>> {
        let mut devices = Vec::new();
        let now = Utc::now().to_rfc3339();

        for host in hosts {
            let is_new;
            let mut device =
                match netsec_db::repo::devices::get_by_ip(&self.pool, &host.ip).await? {
                    Some(mut existing) => {
                        is_new = false;
                        existing.last_seen = now.clone();
                        existing.status = DeviceStatus::Online.as_str().to_string();
                        if let Some(ref mac) = host.mac {
                            existing.mac = Some(mac.clone());
                        }
                        if existing.hostname.is_none() {
                            existing.hostname = host.hostname.clone();
                        }
                        if let Some(ref vendor) = host.vendor {
                            existing.vendor = Some(vendor.clone());
                        }
                        if let Some(ref os) = host.os_info {
                            existing.os_family = Some(os.clone());
                        }
                        existing
                    }
                    None => {
                        is_new = true;
                        let mut d = Device::new(host.ip.clone());
                        d.mac = host.mac.clone();
                        d.hostname = host.hostname.clone();
                        d.vendor = host.vendor.clone();
                        d.os_family = host.os_info.clone();
                        d.status = DeviceStatus::Online.as_str().to_string();
                        d.last_seen = now.clone();
                        d.first_seen = now.clone();
                        d
                    }
                };

            // Persist device first (ports have FK to device)
            if is_new {
                netsec_db::repo::devices::insert(&self.pool, &device).await?;
            } else {
                netsec_db::repo::devices::update(&self.pool, &device).await?;
            }

            // Upsert ports (device must exist for FK)
            for dp in &host.ports {
                let mut port = Port::new(device.id.clone(), dp.port, dp.protocol.clone());
                port.state = dp.state.clone();
                port.service_name = dp.service_name.clone();
                port.service_version = dp.service_version.clone();
                netsec_db::repo::ports::upsert(&self.pool, &port).await?;
            }

            // Classify device based on current ports, then update
            let db_ports =
                netsec_db::repo::ports::list_by_device(&self.pool, &device.id).await?;
            let (device_type, confidence) = fingerprint::classify_device(
                &db_ports,
                device.os_family.as_deref(),
                device.vendor.as_deref(),
            );
            device.device_type = device_type.as_str().to_string();
            device.classification_confidence = confidence;
            netsec_db::repo::devices::update(&self.pool, &device).await?;

            // Publish event
            let event_type = if is_new {
                EventType::DeviceDiscovered
            } else {
                EventType::DeviceUpdated
            };
            let event = NetsecEvent::new(
                event_type,
                serde_json::json!({
                    "device_id": device.id,
                    "ip": device.ip,
                    "device_type": device.device_type,
                }),
            );
            // Ignore send errors (no subscribers is fine)
            let _ = self.event_bus.publish(event);

            devices.push(device);
        }

        Ok(devices)
    }

    /// Create a scan record in the database with status=running.
    pub async fn create_scan_record(
        &self,
        config: &ScanConfig,
    ) -> ScannerResult<Scan> {
        let mut scan = Scan::new(
            "nmap".to_string(),
            config.target.clone(),
            config.scan_type.clone(),
        );
        scan.status = ScanStatus::Running.as_str().to_string();
        scan.started_at = Some(Utc::now().to_rfc3339());
        scan.parameters = serde_json::json!({
            "timing": config.timing,
            "ports": config.ports,
            "scan_type": config.scan_type.as_str(),
        })
        .to_string();

        netsec_db::repo::scans::insert(&self.pool, &scan).await?;
        Ok(scan)
    }

    /// Run a full scan: create record, execute nmap, persist results.
    ///
    /// 1. Creates a scan record in the database (status=running).
    /// 2. Executes nmap via `crate::executor::execute_nmap`.
    /// 3. On success: processes results, persists hosts, marks scan complete.
    /// 4. On failure: marks scan as failed in the database.
    pub async fn run_scan(&self, config: &ScanConfig) -> ScannerResult<Vec<Device>> {
        let scan = self.create_scan_record(config).await?;
        match crate::executor::execute_nmap(config).await {
            Ok(result) => {
                let hosts = process_nmap_results(&result);
                let devices = self.persist_hosts(&hosts).await?;
                self.complete_scan(&scan.id, &hosts).await?;
                Ok(devices)
            }
            Err(e) => {
                let _ = netsec_db::repo::scans::update_status(
                    &self.pool,
                    &scan.id,
                    "failed",
                    0.0,
                )
                .await;
                Err(e)
            }
        }
    }

    /// Mark a scan as completed and store a results summary.
    pub async fn complete_scan(
        &self,
        scan_id: &str,
        hosts: &[DiscoveredHost],
    ) -> ScannerResult<()> {
        let results = serde_json::json!({
            "hosts_found": hosts.len(),
            "total_ports": hosts.iter().map(|h| h.ports.len()).sum::<usize>(),
        })
        .to_string();

        let completed_at = Utc::now().to_rfc3339();
        netsec_db::repo::scans::set_results(&self.pool, scan_id, &results, &completed_at).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netsec_parsers::nmap::{NmapHost, NmapPort, NmapScanResult};
    use std::collections::HashMap;

    #[test]
    fn test_build_args_discovery() {
        let config = ScanConfig {
            target: "192.168.1.0/24".to_string(),
            scan_type: ScanType::Discovery,
            timing: 4,
            ports: None,
        };
        let args = build_nmap_args(&config);
        assert_eq!(args, vec!["-sn", "-T4", "192.168.1.0/24"]);
    }

    #[test]
    fn test_build_args_port_scan() {
        let config = ScanConfig {
            target: "10.0.0.1".to_string(),
            scan_type: ScanType::Port,
            timing: 3,
            ports: Some("22,80,443".to_string()),
        };
        let args = build_nmap_args(&config);
        assert_eq!(
            args,
            vec!["-sS", "-T3", "-p", "22,80,443", "-oX", "-", "10.0.0.1"]
        );
    }

    #[test]
    fn test_build_args_full_scan() {
        let config = ScanConfig {
            target: "10.0.0.0/24".to_string(),
            scan_type: ScanType::Full,
            timing: 4,
            ports: None,
        };
        let args = build_nmap_args(&config);
        assert_eq!(
            args,
            vec!["-sS", "-sV", "-O", "-T4", "-oX", "-", "10.0.0.0/24"]
        );
    }

    #[test]
    fn test_build_args_timing() {
        for t in 0..=5u8 {
            let config = ScanConfig {
                target: "1.2.3.4".to_string(),
                scan_type: ScanType::Discovery,
                timing: t,
                ports: None,
            };
            let args = build_nmap_args(&config);
            assert_eq!(args[1], format!("-T{t}"));
        }
    }

    #[test]
    fn test_build_args_custom_ports() {
        let config = ScanConfig {
            target: "10.0.0.1".to_string(),
            scan_type: ScanType::Port,
            timing: 3,
            ports: Some("1-1024".to_string()),
        };
        let args = build_nmap_args(&config);
        assert!(args.contains(&"-p".to_string()));
        assert!(args.contains(&"1-1024".to_string()));
    }

    fn make_nmap_host(
        ip: &str,
        status: &str,
        mac: Option<&str>,
        vendor: Option<&str>,
        hostname: Option<&str>,
        os: Option<&str>,
        ports: Vec<NmapPort>,
    ) -> NmapHost {
        let mut addresses = HashMap::new();
        addresses.insert("ipv4".to_string(), ip.to_string());
        if let Some(m) = mac {
            addresses.insert("mac".to_string(), m.to_string());
        }
        if let Some(v) = vendor {
            addresses.insert("vendor".to_string(), v.to_string());
        }
        let hostnames = if let Some(hn) = hostname {
            let mut h = HashMap::new();
            h.insert("name".to_string(), hn.to_string());
            vec![h]
        } else {
            vec![]
        };
        let os_map = if let Some(o) = os {
            let mut m = HashMap::new();
            m.insert("name".to_string(), o.to_string());
            m
        } else {
            HashMap::new()
        };
        NmapHost {
            status: status.to_string(),
            addresses,
            hostnames,
            ports,
            os: os_map,
        }
    }

    fn make_nmap_port(port: u16, state: &str, service_name: Option<&str>) -> NmapPort {
        let mut service = HashMap::new();
        if let Some(name) = service_name {
            service.insert("name".to_string(), name.to_string());
        }
        NmapPort {
            port,
            protocol: "tcp".to_string(),
            state: state.to_string(),
            service,
        }
    }

    #[test]
    fn test_process_results_single_host() {
        let scan = NmapScanResult {
            scan_info: HashMap::new(),
            hosts: vec![make_nmap_host(
                "192.168.1.1",
                "up",
                Some("AA:BB:CC:DD:EE:FF"),
                Some("TestVendor"),
                Some("host1.local"),
                None,
                vec![make_nmap_port(80, "open", Some("http"))],
            )],
        };
        let hosts = process_nmap_results(&scan);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, "192.168.1.1");
        assert_eq!(hosts[0].mac.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(hosts[0].vendor.as_deref(), Some("TestVendor"));
        assert_eq!(hosts[0].hostname.as_deref(), Some("host1.local"));
        assert_eq!(hosts[0].ports.len(), 1);
        assert_eq!(hosts[0].ports[0].port, 80);
    }

    #[test]
    fn test_process_results_multiple_hosts() {
        let scan = NmapScanResult {
            scan_info: HashMap::new(),
            hosts: vec![
                make_nmap_host("10.0.0.1", "up", None, None, None, None, vec![]),
                make_nmap_host("10.0.0.2", "up", None, None, None, None, vec![]),
            ],
        };
        let hosts = process_nmap_results(&scan);
        assert_eq!(hosts.len(), 2);
    }

    #[test]
    fn test_process_results_with_os() {
        let scan = NmapScanResult {
            scan_info: HashMap::new(),
            hosts: vec![make_nmap_host(
                "10.0.0.1",
                "up",
                None,
                None,
                None,
                Some("Linux 5.x"),
                vec![],
            )],
        };
        let hosts = process_nmap_results(&scan);
        assert_eq!(hosts[0].os_info.as_deref(), Some("Linux 5.x"));
    }

    #[test]
    fn test_process_results_skips_down() {
        let scan = NmapScanResult {
            scan_info: HashMap::new(),
            hosts: vec![
                make_nmap_host("10.0.0.1", "up", None, None, None, None, vec![]),
                make_nmap_host("10.0.0.2", "down", None, None, None, None, vec![]),
                make_nmap_host("10.0.0.3", "up", None, None, None, None, vec![]),
            ],
        };
        let hosts = process_nmap_results(&scan);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].ip, "10.0.0.1");
        assert_eq!(hosts[1].ip, "10.0.0.3");
    }

    #[tokio::test]
    async fn test_persist_inserts_new_device() {
        let pool = netsec_db::pool::create_test_pool().await.unwrap();
        netsec_db::run_migrations(&pool).await.unwrap();
        let bus = EventBus::new();
        let scanner = ActiveScanner::new(pool.clone(), bus);

        let hosts = vec![DiscoveredHost {
            ip: "192.168.1.100".to_string(),
            mac: Some("AA:BB:CC:DD:EE:FF".to_string()),
            hostname: Some("server1.local".to_string()),
            vendor: None,
            os_info: None,
            ports: vec![
                DiscoveredPort {
                    port: 22,
                    protocol: "tcp".to_string(),
                    state: "open".to_string(),
                    service_name: Some("ssh".to_string()),
                    service_version: None,
                },
                DiscoveredPort {
                    port: 80,
                    protocol: "tcp".to_string(),
                    state: "open".to_string(),
                    service_name: Some("http".to_string()),
                    service_version: None,
                },
            ],
        }];

        let devices = scanner.persist_hosts(&hosts).await.unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].ip, "192.168.1.100");
        assert_eq!(devices[0].mac.as_deref(), Some("AA:BB:CC:DD:EE:FF"));

        // Verify device in DB
        let from_db = netsec_db::repo::devices::get_by_ip(&pool, "192.168.1.100")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(from_db.id, devices[0].id);

        // Verify ports in DB
        let ports = netsec_db::repo::ports::list_by_device(&pool, &from_db.id)
            .await
            .unwrap();
        assert_eq!(ports.len(), 2);
    }

    #[tokio::test]
    async fn test_persist_updates_existing() {
        let pool = netsec_db::pool::create_test_pool().await.unwrap();
        netsec_db::run_migrations(&pool).await.unwrap();
        let bus = EventBus::new();
        let scanner = ActiveScanner::new(pool.clone(), bus);

        // Insert existing device
        let mut existing = Device::new("192.168.1.200".to_string());
        existing.status = "offline".to_string();
        netsec_db::repo::devices::insert(&pool, &existing)
            .await
            .unwrap();

        let hosts = vec![DiscoveredHost {
            ip: "192.168.1.200".to_string(),
            mac: Some("11:22:33:44:55:66".to_string()),
            hostname: None,
            vendor: Some("Intel".to_string()),
            os_info: None,
            ports: vec![],
        }];

        let devices = scanner.persist_hosts(&hosts).await.unwrap();
        assert_eq!(devices[0].id, existing.id);
        assert_eq!(devices[0].status, "online");
        assert_eq!(devices[0].mac.as_deref(), Some("11:22:33:44:55:66"));
        assert_eq!(devices[0].vendor.as_deref(), Some("Intel"));
    }

    #[tokio::test]
    async fn test_persist_upserts_ports() {
        let pool = netsec_db::pool::create_test_pool().await.unwrap();
        netsec_db::run_migrations(&pool).await.unwrap();
        let bus = EventBus::new();
        let scanner = ActiveScanner::new(pool.clone(), bus);

        // First scan — port 80 with http
        let hosts1 = vec![DiscoveredHost {
            ip: "10.0.0.1".to_string(),
            mac: None,
            hostname: None,
            vendor: None,
            os_info: None,
            ports: vec![DiscoveredPort {
                port: 80,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                service_name: Some("http".to_string()),
                service_version: None,
            }],
        }];
        let devices1 = scanner.persist_hosts(&hosts1).await.unwrap();
        let device_id = devices1[0].id.clone();

        // Second scan — same port with updated service version
        let hosts2 = vec![DiscoveredHost {
            ip: "10.0.0.1".to_string(),
            mac: None,
            hostname: None,
            vendor: None,
            os_info: None,
            ports: vec![DiscoveredPort {
                port: 80,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                service_name: Some("http".to_string()),
                service_version: Some("nginx/1.24".to_string()),
            }],
        }];
        scanner.persist_hosts(&hosts2).await.unwrap();

        // Should still only have one port entry (upserted)
        let ports = netsec_db::repo::ports::list_by_device(&pool, &device_id)
            .await
            .unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].service_version.as_deref(), Some("nginx/1.24"));
    }

    #[tokio::test]
    async fn test_persist_classifies_device() {
        let pool = netsec_db::pool::create_test_pool().await.unwrap();
        netsec_db::run_migrations(&pool).await.unwrap();
        let bus = EventBus::new();
        let scanner = ActiveScanner::new(pool.clone(), bus);

        let hosts = vec![DiscoveredHost {
            ip: "10.0.0.50".to_string(),
            mac: None,
            hostname: None,
            vendor: None,
            os_info: None,
            ports: vec![
                DiscoveredPort {
                    port: 22,
                    protocol: "tcp".to_string(),
                    state: "open".to_string(),
                    service_name: Some("ssh".to_string()),
                    service_version: None,
                },
                DiscoveredPort {
                    port: 80,
                    protocol: "tcp".to_string(),
                    state: "open".to_string(),
                    service_name: Some("http".to_string()),
                    service_version: None,
                },
                DiscoveredPort {
                    port: 443,
                    protocol: "tcp".to_string(),
                    state: "open".to_string(),
                    service_name: Some("https".to_string()),
                    service_version: None,
                },
            ],
        }];

        let devices = scanner.persist_hosts(&hosts).await.unwrap();
        assert_eq!(devices[0].device_type, "server");
        assert!((devices[0].classification_confidence - 0.7).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_persist_publishes_events() {
        let pool = netsec_db::pool::create_test_pool().await.unwrap();
        netsec_db::run_migrations(&pool).await.unwrap();
        let bus = EventBus::new();
        let mut rx = bus.subscribe();
        let scanner = ActiveScanner::new(pool.clone(), bus);

        let hosts = vec![DiscoveredHost {
            ip: "10.0.0.99".to_string(),
            mac: None,
            hostname: None,
            vendor: None,
            os_info: None,
            ports: vec![],
        }];

        scanner.persist_hosts(&hosts).await.unwrap();

        let event = rx.try_recv().unwrap();
        assert_eq!(event.event_type, EventType::DeviceDiscovered);
    }
}
