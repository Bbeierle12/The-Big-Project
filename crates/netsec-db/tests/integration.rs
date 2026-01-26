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
