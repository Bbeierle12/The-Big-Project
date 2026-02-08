//! Integration tests for the netsec-scanner crate.

use netsec_events::EventBus;
use netsec_models::scan::ScanType;
use netsec_scanner::active::{ActiveScanner, DiscoveredHost, DiscoveredPort, ScanConfig, build_nmap_args, process_nmap_results};
use netsec_scanner::passive::{MdnsRecord, process_mdns_discovery};

/// Full scan pipeline: build args -> parse XML fixture -> process -> persist -> verify DB.
#[tokio::test]
async fn test_full_scan_pipeline() {
    let pool = netsec_db::pool::create_test_pool().await.unwrap();
    netsec_db::run_migrations(&pool).await.unwrap();
    let bus = EventBus::new();
    let scanner = ActiveScanner::new(pool.clone(), bus);

    // Step 1: Build args
    let config = ScanConfig {
        target: "192.168.1.0/24".to_string(),
        scan_type: ScanType::Full,
        timing: 4,
        ports: None,
    };
    let args = build_nmap_args(&config);
    assert!(args.contains(&"-sV".to_string()));
    assert!(args.contains(&"-O".to_string()));

    // Step 2: Parse XML fixture (shared canonical fixture)
    let xml = include_str!("../../../tests/fixtures/nmap_single_host.xml");

    let scan_result = netsec_parsers::nmap::parse_nmap_xml(xml).unwrap();

    // Step 3: Process results (fixture has 192.168.1.1 with ports 22 and 80)
    let hosts = process_nmap_results(&scan_result);
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].ip, "192.168.1.1");
    assert_eq!(hosts[0].ports.len(), 2);

    // Step 4: Persist
    let devices = scanner.persist_hosts(&hosts).await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].ip, "192.168.1.1");
    assert_eq!(devices[0].device_type, "server"); // 2 server ports (22, 80)

    // Step 5: Verify DB
    let from_db = netsec_db::repo::devices::get_by_ip(&pool, "192.168.1.1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from_db.hostname.as_deref(), Some("router.local"));
    assert_eq!(from_db.device_type, "server");

    let ports = netsec_db::repo::ports::list_by_device(&pool, &from_db.id)
        .await
        .unwrap();
    assert_eq!(ports.len(), 2);
}

/// mDNS discovers device -> nmap scan enriches it -> single device in DB.
#[tokio::test]
async fn test_passive_then_active_merge() {
    let pool = netsec_db::pool::create_test_pool().await.unwrap();
    netsec_db::run_migrations(&pool).await.unwrap();
    let bus = EventBus::new();
    let scanner = ActiveScanner::new(pool.clone(), bus);

    // Step 1: mDNS discovers the device
    let record = MdnsRecord {
        hostname: Some("printer.local".to_string()),
        service_type: "_ipp._tcp.local".to_string(),
        ip: Some("192.168.1.42".to_string()),
        port: Some(631),
    };
    let mdns_device = process_mdns_discovery(&pool, &record, "192.168.1.42")
        .await
        .unwrap();
    assert_eq!(mdns_device.ip, "192.168.1.42");
    assert_eq!(mdns_device.hostname.as_deref(), Some("printer.local"));

    // Step 2: Active scan enriches with port data
    let hosts = vec![DiscoveredHost {
        ip: "192.168.1.42".to_string(),
        mac: Some("DE:AD:BE:EF:00:01".to_string()),
        hostname: Some("printer-updated.local".to_string()),
        vendor: Some("HP".to_string()),
        os_info: None,
        ports: vec![
            DiscoveredPort {
                port: 631,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                service_name: Some("ipp".to_string()),
                service_version: None,
            },
            DiscoveredPort {
                port: 9100,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                service_name: Some("jetdirect".to_string()),
                service_version: None,
            },
        ],
    }];
    let devices = scanner.persist_hosts(&hosts).await.unwrap();

    // Should be the SAME device (same ID), not a duplicate
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].id, mdns_device.id);
    // Hostname should be preserved from mDNS (since it was set first)
    assert_eq!(devices[0].hostname.as_deref(), Some("printer.local"));
    // MAC and vendor should be updated from active scan
    assert_eq!(devices[0].mac.as_deref(), Some("DE:AD:BE:EF:00:01"));
    assert_eq!(devices[0].vendor.as_deref(), Some("HP"));
    // Should be classified as printer
    assert_eq!(devices[0].device_type, "printer");

    // Verify only one device in DB
    let count = netsec_db::repo::devices::count(&pool).await.unwrap();
    assert_eq!(count, 1);

    // Verify ports
    let ports = netsec_db::repo::ports::list_by_device(&pool, &devices[0].id)
        .await
        .unwrap();
    assert_eq!(ports.len(), 2);
}

/// Scan host with server ports -> device classified as Server.
#[tokio::test]
async fn test_classification_after_scan() {
    let pool = netsec_db::pool::create_test_pool().await.unwrap();
    netsec_db::run_migrations(&pool).await.unwrap();
    let bus = EventBus::new();
    let scanner = ActiveScanner::new(pool.clone(), bus);

    let hosts = vec![DiscoveredHost {
        ip: "10.10.10.1".to_string(),
        mac: None,
        hostname: Some("db-server".to_string()),
        vendor: None,
        os_info: Some("Linux 6.x".to_string()),
        ports: vec![
            DiscoveredPort {
                port: 22,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                service_name: Some("ssh".to_string()),
                service_version: Some("OpenSSH 9.0".to_string()),
            },
            DiscoveredPort {
                port: 5432,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                service_name: Some("postgresql".to_string()),
                service_version: Some("15.4".to_string()),
            },
        ],
    }];

    let devices = scanner.persist_hosts(&hosts).await.unwrap();
    assert_eq!(devices[0].device_type, "server");
    assert!((devices[0].classification_confidence - 0.7).abs() < f64::EPSILON);
    assert_eq!(devices[0].os_family.as_deref(), Some("Linux 6.x"));

    // Verify from DB
    let from_db = netsec_db::repo::devices::get_by_ip(&pool, "10.10.10.1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from_db.device_type, "server");
    assert_eq!(from_db.os_family.as_deref(), Some("Linux 6.x"));
}
