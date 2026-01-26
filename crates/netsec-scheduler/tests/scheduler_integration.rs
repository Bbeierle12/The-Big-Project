//! Integration tests for the scheduler.

use std::time::Duration;

use netsec_events::EventBus;
use netsec_models::event::EventType;
use netsec_models::plugin::{ScheduledJob, TriggerType};

/// Insert an enabled interval job with 0s interval -> start scheduler -> receive event.
#[tokio::test]
async fn test_scheduler_dispatches_due_job() {
    let pool = netsec_db::pool::create_test_pool().await.unwrap();
    netsec_db::run_migrations(&pool).await.unwrap();

    // Insert an enabled job with 0-second interval (always due)
    let mut job = ScheduledJob::new(TriggerType::Interval, "discovery_scan".to_string());
    job.trigger_args = r#"{"interval_secs": 0}"#.to_string();
    job.task_params = r#"{"target": "192.168.1.0/24"}"#.to_string();
    netsec_db::repo::scheduled_jobs::insert(&pool, &job)
        .await
        .unwrap();

    let bus = EventBus::new();
    let mut rx = bus.subscribe();

    let scheduler = netsec_scheduler::Scheduler::new(
        pool.clone(),
        bus.clone(),
        Duration::from_millis(50),
    );

    let handle = scheduler.start();

    // Wait for the scheduler to tick and dispatch
    let event = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timeout waiting for scheduler event")
        .expect("recv error");

    assert_eq!(event.event_type, EventType::ScanStarted);
    let payload = &event.payload;
    assert_eq!(payload["job_id"].as_str().unwrap(), job.id);
    assert_eq!(payload["task_type"].as_str().unwrap(), "discovery_scan");

    scheduler.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}

/// Insert a disabled job -> tick -> no event should be dispatched.
#[tokio::test]
async fn test_scheduler_skips_disabled_job() {
    let pool = netsec_db::pool::create_test_pool().await.unwrap();
    netsec_db::run_migrations(&pool).await.unwrap();

    // Insert a disabled job
    let mut job = ScheduledJob::new(TriggerType::Interval, "full_scan".to_string());
    job.trigger_args = r#"{"interval_secs": 0}"#.to_string();
    job.enabled = false;
    netsec_db::repo::scheduled_jobs::insert(&pool, &job)
        .await
        .unwrap();

    let bus = EventBus::new();
    let mut rx = bus.subscribe();

    let scheduler = netsec_scheduler::Scheduler::new(
        pool.clone(),
        bus.clone(),
        Duration::from_millis(50),
    );

    let handle = scheduler.start();

    // Wait a few ticks — no event should come
    let result = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
    assert!(
        result.is_err(),
        "Should timeout because disabled job should not dispatch"
    );

    scheduler.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}
