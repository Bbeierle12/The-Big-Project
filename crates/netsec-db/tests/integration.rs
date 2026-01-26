//! Integration tests for netsec-db against in-memory SQLite.

use netsec_db::{create_pool, run_migrations};
use netsec_db::repo::{devices, ports, alerts, scans, vulnerabilities, traffic, device_events, observations, scheduled_jobs};
use netsec_models::alert::{Alert, Severity};
use netsec_models::device::Device;
use netsec_models::event::{DeviceEvent, DeviceEventType, Observation};
use netsec_models::plugin::{ScheduledJob, TriggerType};
use netsec_models::port::Port;
use netsec_models::scan::{Scan, ScanType};
use netsec_models::traffic::TrafficFlow;
use netsec_models::vulnerability::Vulnerability;

async fn setup() -> sqlx::SqlitePool {
    let pool = create_pool("sqlite::memory:").await.expect("pool creation failed");
    run_migrations(&pool).await.expect("migrations failed");
    pool
}

#[tokio::test]
async fn test_migrations_idempotent() {
    let pool = setup().await;
    // Running migrations again should succeed (IF NOT EXISTS)
    run_migrations(&pool).await.expect("second migration run failed");
}

#[tokio::test]
async fn test_device_crud() {
    let pool = setup().await;

    let mut device = Device::new("192.168.1.1".into());
    device.hostname = Some("router.local".into());
    device.mac = Some("AA:BB:CC:DD:EE:FF".into());

    // Insert
    devices::insert(&pool, &device).await.unwrap();

    // Get by ID
    let fetched = devices::get_by_id(&pool, &device.id).await.unwrap().unwrap();
    assert_eq!(fetched.ip, "192.168.1.1");
    assert_eq!(fetched.hostname.as_deref(), Some("router.local"));

    // Get by IP
    let by_ip = devices::get_by_ip(&pool, "192.168.1.1").await.unwrap().unwrap();
    assert_eq!(by_ip.id, device.id);

    // List
    let all = devices::list(&pool, 100, 0).await.unwrap();
    assert_eq!(all.len(), 1);

    // Count
    let c = devices::count(&pool).await.unwrap();
    assert_eq!(c, 1);

    // Update
    device.hostname = Some("gateway.local".into());
    devices::update(&pool, &device).await.unwrap();
    let updated = devices::get_by_id(&pool, &device.id).await.unwrap().unwrap();
    assert_eq!(updated.hostname.as_deref(), Some("gateway.local"));

    // Delete
    let deleted = devices::delete(&pool, &device.id).await.unwrap();
    assert!(deleted);
    let gone = devices::get_by_id(&pool, &device.id).await.unwrap();
    assert!(gone.is_none());
}

#[tokio::test]
async fn test_port_crud() {
    let pool = setup().await;

    let device = Device::new("10.0.0.1".into());
    devices::insert(&pool, &device).await.unwrap();

    let mut port = Port::new(device.id.clone(), 443, "tcp".into());
    port.state = "open".into();
    port.service_name = Some("https".into());

    ports::insert(&pool, &port).await.unwrap();

    let fetched = ports::get_by_id(&pool, &port.id).await.unwrap().unwrap();
    assert_eq!(fetched.port_number, 443);
    assert_eq!(fetched.service_name.as_deref(), Some("https"));

    let by_device = ports::list_by_device(&pool, &device.id).await.unwrap();
    assert_eq!(by_device.len(), 1);
}

#[tokio::test]
async fn test_alert_crud() {
    let pool = setup().await;

    let alert = Alert::new("Port scan detected".into(), "suricata".into(), "fp-scan-1".into());
    alerts::insert(&pool, &alert).await.unwrap();

    let fetched = alerts::get_by_id(&pool, &alert.id).await.unwrap().unwrap();
    assert_eq!(fetched.title, "Port scan detected");
    assert_eq!(fetched.count, 1);

    // Increment count
    alerts::increment_count(&pool, &alert.id, &alert.updated_at).await.unwrap();
    let updated = alerts::get_by_id(&pool, &alert.id).await.unwrap().unwrap();
    assert_eq!(updated.count, 2);

    // Find by fingerprint
    let by_fp = alerts::get_by_fingerprint(&pool, "fp-scan-1").await.unwrap().unwrap();
    assert_eq!(by_fp.id, alert.id);

    // Count
    assert_eq!(alerts::count(&pool).await.unwrap(), 1);
}

#[tokio::test]
async fn test_scan_crud() {
    let pool = setup().await;

    let scan = Scan::new("nmap".into(), "192.168.1.0/24".into(), ScanType::Discovery);
    scans::insert(&pool, &scan).await.unwrap();

    let fetched = scans::get_by_id(&pool, &scan.id).await.unwrap().unwrap();
    assert_eq!(fetched.tool, "nmap");
    assert_eq!(fetched.status, "pending");

    // Update status
    scans::update_status(&pool, &scan.id, "running", 0.5).await.unwrap();
    let running = scans::get_by_id(&pool, &scan.id).await.unwrap().unwrap();
    assert_eq!(running.status, "running");
    assert!((running.progress - 0.5).abs() < f64::EPSILON);

    // Set results
    scans::set_results(&pool, &scan.id, r#"{"hosts":3}"#, "2024-01-15T10:00:00Z").await.unwrap();
    let done = scans::get_by_id(&pool, &scan.id).await.unwrap().unwrap();
    assert_eq!(done.status, "completed");
    assert!((done.progress - 1.0).abs() < f64::EPSILON);
}

#[tokio::test]
async fn test_vulnerability_crud() {
    let pool = setup().await;

    let vuln = Vulnerability::new("CVE-2024-1234".into(), "openvas".into(), Severity::High);
    vulnerabilities::insert(&pool, &vuln).await.unwrap();

    let fetched = vulnerabilities::get_by_id(&pool, &vuln.id).await.unwrap().unwrap();
    assert_eq!(fetched.title, "CVE-2024-1234");
    assert_eq!(fetched.severity, "high");
}

#[tokio::test]
async fn test_traffic_crud() {
    let pool = setup().await;

    let flow = TrafficFlow::new("10.0.0.1".into(), 12345, "10.0.0.2".into(), 80, "tcp".into());
    traffic::insert(&pool, &flow).await.unwrap();

    let fetched = traffic::get_by_id(&pool, &flow.id).await.unwrap().unwrap();
    assert_eq!(fetched.src_ip, "10.0.0.1");
    assert_eq!(fetched.dst_port, 80);

    let all = traffic::list(&pool, 100, 0).await.unwrap();
    assert_eq!(all.len(), 1);
}

#[tokio::test]
async fn test_device_events_crud() {
    let pool = setup().await;

    let device = Device::new("10.0.0.5".into());
    devices::insert(&pool, &device).await.unwrap();

    let event = DeviceEvent::new(
        device.id.clone(),
        DeviceEventType::Joined,
        serde_json::json!({"source": "arp"}),
    );
    device_events::insert(&pool, &event).await.unwrap();

    let events = device_events::list_by_device(&pool, &device.id, 10).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "joined");
}

#[tokio::test]
async fn test_observations_crud() {
    let pool = setup().await;

    let device = Device::new("10.0.0.6".into());
    devices::insert(&pool, &device).await.unwrap();

    let obs = Observation::new(
        device.id.clone(),
        "mdns".into(),
        serde_json::json!({"name": "_http._tcp.local"}),
    );
    observations::insert(&pool, &obs).await.unwrap();

    let list = observations::list_by_device(&pool, &device.id, 10).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].protocol, "mdns");
}

#[tokio::test]
async fn test_scheduled_jobs_crud() {
    let pool = setup().await;

    let job = ScheduledJob::new(TriggerType::Cron, "full_scan".into());
    scheduled_jobs::insert(&pool, &job).await.unwrap();

    let fetched = scheduled_jobs::get_by_id(&pool, &job.id).await.unwrap().unwrap();
    assert_eq!(fetched.task_type, "full_scan");
    assert!(fetched.enabled);

    // List enabled
    let enabled = scheduled_jobs::list_enabled(&pool).await.unwrap();
    assert_eq!(enabled.len(), 1);

    // Disable
    scheduled_jobs::set_enabled(&pool, &job.id, false, "2024-01-15T10:00:00Z").await.unwrap();
    let disabled = scheduled_jobs::get_by_id(&pool, &job.id).await.unwrap().unwrap();
    assert!(!disabled.enabled);

    let enabled_after = scheduled_jobs::list_enabled(&pool).await.unwrap();
    assert_eq!(enabled_after.len(), 0);
}

#[tokio::test]
async fn test_cascade_delete_device() {
    let pool = setup().await;

    let device = Device::new("10.0.0.10".into());
    devices::insert(&pool, &device).await.unwrap();

    // Add related records
    let port = Port::new(device.id.clone(), 80, "tcp".into());
    ports::insert(&pool, &port).await.unwrap();

    let event = DeviceEvent::new(device.id.clone(), DeviceEventType::Joined, serde_json::json!({}));
    device_events::insert(&pool, &event).await.unwrap();

    let obs = Observation::new(device.id.clone(), "ssdp".into(), serde_json::json!({}));
    observations::insert(&pool, &obs).await.unwrap();

    // Delete device should cascade
    devices::delete(&pool, &device.id).await.unwrap();

    // All related records should be gone
    let p = ports::get_by_id(&pool, &port.id).await.unwrap();
    assert!(p.is_none());

    let e = device_events::list_by_device(&pool, &device.id, 10).await.unwrap();
    assert!(e.is_empty());

    let o = observations::list_by_device(&pool, &device.id, 10).await.unwrap();
    assert!(o.is_empty());
}

// ============================================================
// B1: Untested CRUD operations
// ============================================================

#[tokio::test]
async fn test_port_delete() {
    let pool = setup().await;
    let device = Device::new("10.0.0.20".into());
    devices::insert(&pool, &device).await.unwrap();

    let port = Port::new(device.id.clone(), 22, "tcp".into());
    ports::insert(&pool, &port).await.unwrap();
    assert!(ports::get_by_id(&pool, &port.id).await.unwrap().is_some());

    let deleted = ports::delete(&pool, &port.id).await.unwrap();
    assert!(deleted);
    assert!(ports::get_by_id(&pool, &port.id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_alert_list_and_pagination() {
    let pool = setup().await;

    let a1 = Alert::new("Alert 1".into(), "nmap".into(), "fp-1".into());
    let a2 = Alert::new("Alert 2".into(), "nmap".into(), "fp-2".into());
    let a3 = Alert::new("Alert 3".into(), "nmap".into(), "fp-3".into());
    alerts::insert(&pool, &a1).await.unwrap();
    alerts::insert(&pool, &a2).await.unwrap();
    alerts::insert(&pool, &a3).await.unwrap();

    let page1 = alerts::list(&pool, 2, 0).await.unwrap();
    assert_eq!(page1.len(), 2);

    let page2 = alerts::list(&pool, 2, 2).await.unwrap();
    assert_eq!(page2.len(), 1);
}

#[tokio::test]
async fn test_alert_update_status() {
    let pool = setup().await;
    let alert = Alert::new("Status test".into(), "suricata".into(), "fp-status".into());
    alerts::insert(&pool, &alert).await.unwrap();

    let updated = alerts::update_status(&pool, &alert.id, "acknowledged", "2025-01-01T00:00:00Z").await.unwrap();
    assert!(updated);

    let fetched = alerts::get_by_id(&pool, &alert.id).await.unwrap().unwrap();
    assert_eq!(fetched.status, "acknowledged");
}

#[tokio::test]
async fn test_alert_delete() {
    let pool = setup().await;
    let alert = Alert::new("Delete me".into(), "nmap".into(), "fp-del".into());
    alerts::insert(&pool, &alert).await.unwrap();

    let deleted = alerts::delete(&pool, &alert.id).await.unwrap();
    assert!(deleted);
    assert!(alerts::get_by_id(&pool, &alert.id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_scan_list_pagination() {
    let pool = setup().await;
    let s1 = Scan::new("nmap".into(), "10.0.0.0/24".into(), ScanType::Discovery);
    let s2 = Scan::new("nmap".into(), "10.0.1.0/24".into(), ScanType::Port);
    scans::insert(&pool, &s1).await.unwrap();
    scans::insert(&pool, &s2).await.unwrap();

    let page = scans::list(&pool, 1, 0).await.unwrap();
    assert_eq!(page.len(), 1);

    let all = scans::list(&pool, 100, 0).await.unwrap();
    assert_eq!(all.len(), 2);
}

#[tokio::test]
async fn test_scan_delete() {
    let pool = setup().await;
    let scan = Scan::new("nmap".into(), "10.0.0.0/24".into(), ScanType::Full);
    scans::insert(&pool, &scan).await.unwrap();

    let deleted = scans::delete(&pool, &scan.id).await.unwrap();
    assert!(deleted);
    assert!(scans::get_by_id(&pool, &scan.id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_vulnerability_list() {
    let pool = setup().await;
    let v1 = Vulnerability::new("Vuln 1".into(), "openvas".into(), Severity::High);
    let v2 = Vulnerability::new("Vuln 2".into(), "openvas".into(), Severity::Low);
    vulnerabilities::insert(&pool, &v1).await.unwrap();
    vulnerabilities::insert(&pool, &v2).await.unwrap();

    let page = vulnerabilities::list(&pool, 1, 0).await.unwrap();
    assert_eq!(page.len(), 1);

    let all = vulnerabilities::list(&pool, 100, 0).await.unwrap();
    assert_eq!(all.len(), 2);
}

#[tokio::test]
async fn test_vulnerability_list_by_device() {
    let pool = setup().await;
    let d1 = Device::new("10.0.0.30".into());
    let d2 = Device::new("10.0.0.31".into());
    devices::insert(&pool, &d1).await.unwrap();
    devices::insert(&pool, &d2).await.unwrap();

    let mut v1 = Vulnerability::new("Vuln A".into(), "openvas".into(), Severity::High);
    v1.device_id = Some(d1.id.clone());
    let mut v2 = Vulnerability::new("Vuln B".into(), "openvas".into(), Severity::Medium);
    v2.device_id = Some(d2.id.clone());
    let mut v3 = Vulnerability::new("Vuln C".into(), "openvas".into(), Severity::Low);
    v3.device_id = Some(d1.id.clone());

    vulnerabilities::insert(&pool, &v1).await.unwrap();
    vulnerabilities::insert(&pool, &v2).await.unwrap();
    vulnerabilities::insert(&pool, &v3).await.unwrap();

    let d1_vulns = vulnerabilities::list_by_device(&pool, &d1.id).await.unwrap();
    assert_eq!(d1_vulns.len(), 2);

    let d2_vulns = vulnerabilities::list_by_device(&pool, &d2.id).await.unwrap();
    assert_eq!(d2_vulns.len(), 1);
}

#[tokio::test]
async fn test_vulnerability_delete() {
    let pool = setup().await;
    let vuln = Vulnerability::new("Delete me".into(), "nmap".into(), Severity::Info);
    vulnerabilities::insert(&pool, &vuln).await.unwrap();

    let deleted = vulnerabilities::delete(&pool, &vuln.id).await.unwrap();
    assert!(deleted);
    assert!(vulnerabilities::get_by_id(&pool, &vuln.id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_traffic_delete() {
    let pool = setup().await;
    let flow = TrafficFlow::new("10.0.0.1".into(), 1111, "10.0.0.2".into(), 80, "tcp".into());
    traffic::insert(&pool, &flow).await.unwrap();

    let deleted = traffic::delete(&pool, &flow.id).await.unwrap();
    assert!(deleted);
    assert!(traffic::get_by_id(&pool, &flow.id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_scheduled_jobs_list_pagination() {
    let pool = setup().await;
    let j1 = ScheduledJob::new(TriggerType::Cron, "scan_1".into());
    let j2 = ScheduledJob::new(TriggerType::Interval, "scan_2".into());
    scheduled_jobs::insert(&pool, &j1).await.unwrap();
    scheduled_jobs::insert(&pool, &j2).await.unwrap();

    let page = scheduled_jobs::list(&pool, 1, 0).await.unwrap();
    assert_eq!(page.len(), 1);

    let all = scheduled_jobs::list(&pool, 100, 0).await.unwrap();
    assert_eq!(all.len(), 2);
}

#[tokio::test]
async fn test_scheduled_jobs_delete() {
    let pool = setup().await;
    let job = ScheduledJob::new(TriggerType::Cron, "delete_me".into());
    scheduled_jobs::insert(&pool, &job).await.unwrap();

    let deleted = scheduled_jobs::delete(&pool, &job.id).await.unwrap();
    assert!(deleted);
    assert!(scheduled_jobs::get_by_id(&pool, &job.id).await.unwrap().is_none());
}

// ============================================================
// B2: Edge case tests
// ============================================================

#[tokio::test]
async fn test_get_nonexistent_returns_none() {
    let pool = setup().await;
    let fake_id = uuid::Uuid::new_v4().to_string();

    assert!(devices::get_by_id(&pool, &fake_id).await.unwrap().is_none());
    assert!(ports::get_by_id(&pool, &fake_id).await.unwrap().is_none());
    assert!(alerts::get_by_id(&pool, &fake_id).await.unwrap().is_none());
    assert!(scans::get_by_id(&pool, &fake_id).await.unwrap().is_none());
    assert!(vulnerabilities::get_by_id(&pool, &fake_id).await.unwrap().is_none());
    assert!(traffic::get_by_id(&pool, &fake_id).await.unwrap().is_none());
    assert!(scheduled_jobs::get_by_id(&pool, &fake_id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_delete_nonexistent_returns_false() {
    let pool = setup().await;
    let fake_id = uuid::Uuid::new_v4().to_string();

    assert!(!devices::delete(&pool, &fake_id).await.unwrap());
    assert!(!ports::delete(&pool, &fake_id).await.unwrap());
    assert!(!alerts::delete(&pool, &fake_id).await.unwrap());
    assert!(!scans::delete(&pool, &fake_id).await.unwrap());
    assert!(!vulnerabilities::delete(&pool, &fake_id).await.unwrap());
    assert!(!traffic::delete(&pool, &fake_id).await.unwrap());
    assert!(!scheduled_jobs::delete(&pool, &fake_id).await.unwrap());
}

#[tokio::test]
async fn test_update_nonexistent_returns_false() {
    let pool = setup().await;
    let fake_id = uuid::Uuid::new_v4().to_string();

    // devices::update with non-existent ID
    let mut fake_device = Device::new("1.1.1.1".into());
    fake_device.id = fake_id.clone();
    assert!(!devices::update(&pool, &fake_device).await.unwrap());

    // alerts::update_status with non-existent ID
    assert!(!alerts::update_status(&pool, &fake_id, "resolved", "2025-01-01T00:00:00Z").await.unwrap());

    // scans::update_status with non-existent ID
    assert!(!scans::update_status(&pool, &fake_id, "running", 0.5).await.unwrap());

    // scheduled_jobs::set_enabled with non-existent ID
    assert!(!scheduled_jobs::set_enabled(&pool, &fake_id, false, "2025-01-01T00:00:00Z").await.unwrap());
}

#[tokio::test]
async fn test_empty_list() {
    let pool = setup().await;

    assert!(devices::list(&pool, 100, 0).await.unwrap().is_empty());
    assert!(alerts::list(&pool, 100, 0).await.unwrap().is_empty());
    assert!(scans::list(&pool, 100, 0).await.unwrap().is_empty());
    assert!(vulnerabilities::list(&pool, 100, 0).await.unwrap().is_empty());
    assert!(traffic::list(&pool, 100, 0).await.unwrap().is_empty());
    assert!(scheduled_jobs::list(&pool, 100, 0).await.unwrap().is_empty());
    assert!(scheduled_jobs::list_enabled(&pool).await.unwrap().is_empty());
}

#[tokio::test]
async fn test_pagination_past_end() {
    let pool = setup().await;

    let device = Device::new("10.0.0.50".into());
    devices::insert(&pool, &device).await.unwrap();

    // Offset past count should return empty
    let result = devices::list(&pool, 100, 100).await.unwrap();
    assert!(result.is_empty());
}

// ============================================================
// B3: Constraint violation tests
// ============================================================

#[tokio::test]
async fn test_duplicate_id_insert() {
    let pool = setup().await;
    let device = Device::new("10.0.0.60".into());
    devices::insert(&pool, &device).await.unwrap();

    // Inserting same ID again should error
    let result = devices::insert(&pool, &device).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_fk_violation_port() {
    let pool = setup().await;

    // Insert port with non-existent device_id (foreign key violation)
    let port = Port::new("nonexistent-device-id".into(), 80, "tcp".into());
    let result = ports::insert(&pool, &port).await;
    assert!(result.is_err());
}

// ============================================================
// B4: Cascade behavior - vulnerability FK SET NULL
// ============================================================

#[tokio::test]
async fn test_vulnerability_device_set_null() {
    let pool = setup().await;

    let device = Device::new("10.0.0.70".into());
    devices::insert(&pool, &device).await.unwrap();

    let mut vuln = Vulnerability::new("FK test".into(), "openvas".into(), Severity::Medium);
    vuln.device_id = Some(device.id.clone());
    vulnerabilities::insert(&pool, &vuln).await.unwrap();

    // Delete the device - vulnerability should remain with device_id=NULL
    devices::delete(&pool, &device.id).await.unwrap();

    let fetched = vulnerabilities::get_by_id(&pool, &vuln.id).await.unwrap().unwrap();
    assert!(fetched.device_id.is_none(), "device_id should be NULL after device deletion (ON DELETE SET NULL)");
    assert_eq!(fetched.title, "FK test");
}
