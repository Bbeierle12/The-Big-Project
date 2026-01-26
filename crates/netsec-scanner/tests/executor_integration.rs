//! Integration tests for the nmap executor module.

use netsec_events::EventBus;
use netsec_models::scan::ScanType;
use netsec_scanner::active::{ActiveScanner, ScanConfig};

/// run_scan should fail gracefully when nmap is not installed.
#[tokio::test]
async fn test_run_scan_end_to_end_no_nmap() {
    let pool = netsec_db::pool::create_test_pool().await.unwrap();
    netsec_db::run_migrations(&pool).await.unwrap();
    let bus = EventBus::new();
    let scanner = ActiveScanner::new(pool.clone(), bus);

    let config = ScanConfig {
        target: "192.168.99.0/24".to_string(),
        scan_type: ScanType::Discovery,
        timing: 4,
        ports: None,
    };

    let result = scanner.run_scan(&config).await;

    if netsec_scanner::executor::find_nmap_binary().is_none() {
        // Should fail with a clear error
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("nmap"),
            "Error should mention nmap: {err}"
        );
    }
    // If nmap is installed, result depends on whether the target is reachable
}

/// Scan record lifecycle: create -> complete -> verify DB status.
#[tokio::test]
async fn test_scan_record_lifecycle() {
    let pool = netsec_db::pool::create_test_pool().await.unwrap();
    netsec_db::run_migrations(&pool).await.unwrap();
    let bus = EventBus::new();
    let scanner = ActiveScanner::new(pool.clone(), bus);

    let config = ScanConfig {
        target: "10.0.0.0/24".to_string(),
        scan_type: ScanType::Full,
        timing: 3,
        ports: None,
    };

    // Create scan record
    let scan = scanner.create_scan_record(&config).await.unwrap();
    assert_eq!(scan.status, "running");
    assert!(scan.started_at.is_some());

    // Verify in DB
    let from_db = netsec_db::repo::scans::get_by_id(&pool, &scan.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from_db.status, "running");

    // Complete the scan
    let hosts = vec![]; // No hosts found
    scanner.complete_scan(&scan.id, &hosts).await.unwrap();

    // Verify completed status
    let completed = netsec_db::repo::scans::get_by_id(&pool, &scan.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(completed.status, "completed");
    assert_eq!(completed.progress, 1.0);
    assert!(completed.completed_at.is_some());
}
