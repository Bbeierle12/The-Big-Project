//! End-to-end integration tests for the alert processing pipeline.

use chrono::Utc;
use netsec_db::{pool::create_test_pool, run_migrations};
use netsec_db::repo::alerts as alert_repo;
use netsec_events::EventBus;
use netsec_models::alert::{AlertCategory, NormalizedAlert, Severity};
use netsec_parsers::nmap::{NmapHost, NmapPort};
use netsec_parsers::suricata::{EveAlert, EveEvent};
use netsec_pipeline::normalization::{normalize, ParserOutput};
use netsec_pipeline::Pipeline;
use std::collections::HashMap;

#[tokio::test]
async fn test_pipeline_nmap_end_to_end() {
    let pool = create_test_pool().await.unwrap();
    run_migrations(&pool).await.unwrap();
    let bus = EventBus::new();

    // Build an NmapHost with one open port
    let mut addresses = HashMap::new();
    addresses.insert("ipv4".to_string(), "192.168.1.10".to_string());
    let host = NmapHost {
        status: "up".to_string(),
        addresses,
        hostnames: vec![],
        ports: vec![NmapPort {
            port: 80,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service: {
                let mut m = HashMap::new();
                m.insert("name".to_string(), "http".to_string());
                m
            },
        }],
        os: HashMap::new(),
    };

    // Normalize
    let alerts = normalize(ParserOutput::Nmap(host)).unwrap();
    assert_eq!(alerts.len(), 1);

    // Process through pipeline
    let pipeline = Pipeline::new(pool.clone(), bus);
    let result = pipeline.process(alerts.into_iter().next().unwrap()).await.unwrap();

    // Verify alert is in DB
    let from_db = alert_repo::get_by_id(&pool, &result.id).await.unwrap();
    assert!(from_db.is_some());
    let from_db = from_db.unwrap();
    assert_eq!(from_db.source_tool, "nmap");
    assert!(from_db.title.contains("80"));
}

#[tokio::test]
async fn test_pipeline_suricata_end_to_end() {
    let pool = create_test_pool().await.unwrap();
    run_migrations(&pool).await.unwrap();
    let bus = EventBus::new();

    let event = EveEvent {
        timestamp: Some("2024-01-15T10:00:00".to_string()),
        event_type: Some("alert".to_string()),
        src_ip: Some("10.0.0.1".to_string()),
        src_port: Some(54321),
        dest_ip: Some("10.0.0.2".to_string()),
        dest_port: Some(80),
        proto: Some("TCP".to_string()),
        alert: Some(EveAlert {
            action: Some("allowed".to_string()),
            signature: Some("ET SCAN SYN".to_string()),
            signature_id: Some(2000100),
            severity: Some(2),
            category: Some("Attempted Information Leak".to_string()),
        }),
    };

    let alerts = normalize(ParserOutput::Suricata(event)).unwrap();
    assert_eq!(alerts.len(), 1);

    let pipeline = Pipeline::new(pool.clone(), bus);
    let result = pipeline.process(alerts.into_iter().next().unwrap()).await.unwrap();

    let from_db = alert_repo::get_by_id(&pool, &result.id).await.unwrap().unwrap();
    assert_eq!(from_db.source_tool, "suricata");
    assert_eq!(from_db.severity, "high");
}

#[tokio::test]
async fn test_pipeline_dedup_integration() {
    let pool = create_test_pool().await.unwrap();
    run_migrations(&pool).await.unwrap();
    let bus = EventBus::new();
    let pipeline = Pipeline::new(pool.clone(), bus);

    // Create a normalized alert
    let normalized = NormalizedAlert {
        source_tool: "test".to_string(),
        severity: Severity::Low,
        category: AlertCategory::Other,
        title: "Dedup integration".to_string(),
        description: "Test".to_string(),
        device_ip: Some("10.0.0.50".to_string()),
        fingerprint: "integration-dedup-fp".to_string(),
        raw_data: serde_json::json!({}),
        timestamp: Utc::now(),
    };

    // First processing -> new alert inserted
    let first = pipeline.process(normalized.clone()).await.unwrap();
    assert_eq!(first.count, 1);

    // Second processing -> duplicate found, count incremented
    let second = pipeline.process(normalized.clone()).await.unwrap();
    assert_eq!(second.count, 2);
    assert_eq!(second.fingerprint, first.fingerprint);
}

#[tokio::test]
async fn test_pipeline_correlation_groups_same_device() {
    let pool = create_test_pool().await.unwrap();
    run_migrations(&pool).await.unwrap();
    let bus = EventBus::new();
    let pipeline = Pipeline::new(pool.clone(), bus);

    // Two different alerts from the same device IP
    let alert1 = NormalizedAlert {
        source_tool: "test".to_string(),
        severity: Severity::Low,
        category: AlertCategory::Anomaly,
        title: "Alert A".to_string(),
        description: "First".to_string(),
        device_ip: Some("10.0.0.99".to_string()),
        fingerprint: "corr-integration-fp-1".to_string(),
        raw_data: serde_json::json!({}),
        timestamp: Utc::now(),
    };

    let alert2 = NormalizedAlert {
        source_tool: "test".to_string(),
        severity: Severity::Low,
        category: AlertCategory::Anomaly,
        title: "Alert B".to_string(),
        description: "Second".to_string(),
        device_ip: Some("10.0.0.99".to_string()),
        fingerprint: "corr-integration-fp-2".to_string(),
        raw_data: serde_json::json!({}),
        timestamp: Utc::now(),
    };

    let result1 = pipeline.process(alert1).await.unwrap();
    let result2 = pipeline.process(alert2).await.unwrap();

    // Both should have correlation_ids
    assert!(result1.correlation_id.is_some());
    assert!(result2.correlation_id.is_some());

    // And they should share the same correlation_id
    assert_eq!(result1.correlation_id, result2.correlation_id);
}

#[tokio::test]
async fn test_pipeline_scoring_critical_port() {
    let pool = create_test_pool().await.unwrap();
    run_migrations(&pool).await.unwrap();
    let bus = EventBus::new();
    let pipeline = Pipeline::new(pool.clone(), bus);

    let alert = NormalizedAlert {
        source_tool: "nmap".to_string(),
        severity: Severity::Info,
        category: AlertCategory::Vulnerability,
        title: "Open port 22".to_string(),
        description: "SSH on port 22".to_string(),
        device_ip: Some("10.0.0.1".to_string()),
        fingerprint: "score-integration-fp-22".to_string(),
        raw_data: serde_json::json!({"port": 22}),
        timestamp: Utc::now(),
    };

    let result = pipeline.process(alert).await.unwrap();
    // Info (0) + critical port boost (1) = Low (1)
    assert_eq!(result.severity, "low");
}

/// Verify all Suricata severity values (1-4) map to the correct output
/// through the full normalization -> pipeline path.
#[tokio::test]
async fn test_pipeline_suricata_full_severity_range() {
    let pool = create_test_pool().await.unwrap();
    run_migrations(&pool).await.unwrap();
    let bus = EventBus::new();

    // Suricata severity 1 = Critical, 2 = High, 3 = Medium, 4 = Low
    let cases: &[(u8, &str)] = &[
        (1, "critical"),
        (2, "high"),
        (3, "medium"),
        (4, "low"),
    ];

    for (sev, expected) in cases {
        let event = EveEvent {
            timestamp: Some("2024-01-15T10:00:00".to_string()),
            event_type: Some("alert".to_string()),
            src_ip: Some("10.0.0.1".to_string()),
            src_port: Some(54321),
            dest_ip: Some("10.0.0.2".to_string()),
            dest_port: Some(80),
            proto: Some("TCP".to_string()),
            alert: Some(EveAlert {
                action: Some("allowed".to_string()),
                signature: Some(format!("ET TEST severity {sev}")),
                signature_id: Some(3000000 + *sev as u64),
                severity: Some(*sev),
                category: Some("Test".to_string()),
            }),
        };

        let alerts = normalize(ParserOutput::Suricata(event)).unwrap();
        assert_eq!(alerts.len(), 1, "severity {sev}: expected 1 alert");

        let pipeline = Pipeline::new(pool.clone(), bus.clone());
        let result = pipeline.process(alerts.into_iter().next().unwrap()).await.unwrap();
        assert_eq!(
            result.severity, *expected,
            "Suricata severity {sev} should map to {expected}, got {}",
            result.severity
        );
    }
}
