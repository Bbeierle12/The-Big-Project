//! Alert dispatch stage.
//!
//! Builds the final [`Alert`] from a [`NormalizedAlert`] and sends it to
//! one or more dispatch targets (database, event bus, log).

use std::future::Future;
use std::pin::Pin;

use chrono::Utc;
use netsec_db::repo::alerts as alert_repo;
use netsec_events::EventBus;
use netsec_models::alert::{Alert, AlertStatus, NormalizedAlert, Severity};
use netsec_models::event::{EventType, NetsecEvent};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::{PipelineError, PipelineResult};

/// A target that receives dispatched alerts.
pub trait DispatchTarget: Send + Sync {
    fn send<'a>(
        &'a self,
        alert: &'a Alert,
    ) -> Pin<Box<dyn Future<Output = Result<(), PipelineError>> + Send + 'a>>;

    fn name(&self) -> &str;
}

/// Inserts the alert into the SQLite database.
pub struct DatabaseTarget {
    pool: SqlitePool,
}

impl DatabaseTarget {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

impl DispatchTarget for DatabaseTarget {
    fn send<'a>(
        &'a self,
        alert: &'a Alert,
    ) -> Pin<Box<dyn Future<Output = Result<(), PipelineError>> + Send + 'a>> {
        Box::pin(async move {
            alert_repo::insert(&self.pool, alert)
                .await
                .map_err(PipelineError::Database)
        })
    }

    fn name(&self) -> &str {
        "database"
    }
}

/// Publishes an [`NetsecEvent`] with `AlertCreated` type onto the event bus.
pub struct EventBusTarget {
    bus: EventBus,
}

impl EventBusTarget {
    pub fn new(bus: EventBus) -> Self {
        Self { bus }
    }
}

impl DispatchTarget for EventBusTarget {
    fn send<'a>(
        &'a self,
        alert: &'a Alert,
    ) -> Pin<Box<dyn Future<Output = Result<(), PipelineError>> + Send + 'a>> {
        Box::pin(async move {
            let payload = serde_json::to_value(alert)
                .map_err(|e| PipelineError::EventBus(e.to_string()))?;
            let event = NetsecEvent::new(EventType::AlertCreated, payload);
            // Ignore SendError when no subscribers are listening
            let _ = self.bus.publish(event);
            Ok(())
        })
    }

    fn name(&self) -> &str {
        "event_bus"
    }
}

/// Logs High and Critical severity alerts via `tracing::warn!`.
pub struct LogTarget;

impl DispatchTarget for LogTarget {
    fn send<'a>(
        &'a self,
        alert: &'a Alert,
    ) -> Pin<Box<dyn Future<Output = Result<(), PipelineError>> + Send + 'a>> {
        Box::pin(async move {
            let sev = alert.severity_enum();
            if sev >= Severity::High {
                tracing::warn!(
                    severity = alert.severity.as_str(),
                    title = alert.title.as_str(),
                    fingerprint = alert.fingerprint.as_str(),
                    "High-severity alert dispatched"
                );
            }
            Ok(())
        })
    }

    fn name(&self) -> &str {
        "log"
    }
}

/// Build an [`Alert`] from a normalized alert + scoring/correlation results,
/// then send it to all dispatch targets.
pub async fn dispatch(
    normalized: &NormalizedAlert,
    final_severity: Severity,
    correlation_id: Option<String>,
    targets: &[Box<dyn DispatchTarget>],
) -> PipelineResult<Alert> {
    let now = Utc::now().to_rfc3339();

    let alert = Alert {
        id: Uuid::new_v4().to_string(),
        severity: final_severity.as_str().to_string(),
        status: AlertStatus::New.as_str().to_string(),
        source_tool: normalized.source_tool.clone(),
        category: normalized.category.as_str().to_string(),
        title: normalized.title.clone(),
        description: normalized.description.clone(),
        device_ip: normalized.device_ip.clone(),
        fingerprint: normalized.fingerprint.clone(),
        correlation_id,
        count: 1,
        created_at: now.clone(),
        updated_at: now,
    };

    for target in targets {
        target
            .send(&alert)
            .await
            .map_err(|e| PipelineError::Dispatch(format!("{}: {}", target.name(), e)))?;
    }

    Ok(alert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use netsec_db::{pool::create_test_pool, run_migrations};
    use netsec_models::alert::{AlertCategory, Severity};

    fn make_normalized() -> NormalizedAlert {
        NormalizedAlert {
            source_tool: "suricata".to_string(),
            severity: Severity::High,
            category: AlertCategory::Intrusion,
            title: "ET SCAN Test".to_string(),
            description: "Test alert dispatch".to_string(),
            device_ip: Some("10.0.0.1".to_string()),
            fingerprint: "dispatch-fp-1".to_string(),
            raw_data: serde_json::json!({"sig_id": 123}),
            timestamp: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_correct_field_mapping() {
        let normalized = make_normalized();
        let targets: Vec<Box<dyn DispatchTarget>> = vec![];

        let alert = dispatch(&normalized, Severity::Critical, Some("cid-1".into()), &targets)
            .await
            .unwrap();

        assert_eq!(alert.severity, "critical");
        assert_eq!(alert.status, "new");
        assert_eq!(alert.source_tool, "suricata");
        assert_eq!(alert.category, "intrusion");
        assert_eq!(alert.title, "ET SCAN Test");
        assert_eq!(alert.description, "Test alert dispatch");
        assert_eq!(alert.device_ip, Some("10.0.0.1".to_string()));
        assert_eq!(alert.fingerprint, "dispatch-fp-1");
        assert_eq!(alert.correlation_id, Some("cid-1".to_string()));
        assert_eq!(alert.count, 1);
    }

    #[tokio::test]
    async fn test_db_insertion_verified() {
        let pool = create_test_pool().await.unwrap();
        run_migrations(&pool).await.unwrap();

        let normalized = make_normalized();
        let db_target = DatabaseTarget::new(pool.clone());
        let targets: Vec<Box<dyn DispatchTarget>> = vec![Box::new(db_target)];

        let alert = dispatch(&normalized, Severity::High, None, &targets)
            .await
            .unwrap();

        // Verify the alert was inserted
        let from_db = alert_repo::get_by_id(&pool, &alert.id).await.unwrap();
        assert!(from_db.is_some());
        let from_db = from_db.unwrap();
        assert_eq!(from_db.title, "ET SCAN Test");
        assert_eq!(from_db.severity, "high");
    }

    #[tokio::test]
    async fn test_event_bus_publication_verified() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        let normalized = make_normalized();
        let bus_target = EventBusTarget::new(bus.clone());
        let targets: Vec<Box<dyn DispatchTarget>> = vec![Box::new(bus_target)];

        let alert = dispatch(&normalized, Severity::High, None, &targets)
            .await
            .unwrap();

        let event = rx.recv().await.unwrap();
        assert_eq!(event.event_type, EventType::AlertCreated);
        let payload_id = event.payload.get("id").and_then(|v| v.as_str());
        assert_eq!(payload_id, Some(alert.id.as_str()));
    }

    #[tokio::test]
    async fn test_multiple_targets_fire() {
        let pool = create_test_pool().await.unwrap();
        run_migrations(&pool).await.unwrap();

        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        let normalized = make_normalized();
        let targets: Vec<Box<dyn DispatchTarget>> = vec![
            Box::new(DatabaseTarget::new(pool.clone())),
            Box::new(EventBusTarget::new(bus.clone())),
            Box::new(LogTarget),
        ];

        let alert = dispatch(&normalized, Severity::High, None, &targets)
            .await
            .unwrap();

        // DB target worked
        let from_db = alert_repo::get_by_id(&pool, &alert.id).await.unwrap();
        assert!(from_db.is_some());

        // EventBus target worked
        let event = rx.recv().await.unwrap();
        assert_eq!(event.event_type, EventType::AlertCreated);
    }

    #[tokio::test]
    async fn test_log_target_for_high_severity() {
        // LogTarget should not error for any severity
        let normalized = make_normalized();
        let targets: Vec<Box<dyn DispatchTarget>> = vec![Box::new(LogTarget)];

        // High severity — should log (we just verify no error)
        let alert = dispatch(&normalized, Severity::High, None, &targets)
            .await
            .unwrap();
        assert_eq!(alert.severity, "high");

        // Critical severity — should also log
        let alert2 = dispatch(&normalized, Severity::Critical, None, &targets)
            .await
            .unwrap();
        assert_eq!(alert2.severity, "critical");
    }
}
