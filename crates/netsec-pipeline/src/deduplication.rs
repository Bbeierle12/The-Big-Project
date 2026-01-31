//! Alert deduplication stage.
//!
//! Checks whether a normalized alert already exists in the database by fingerprint.
//! If it does, increments the existing alert's count and returns it as a duplicate.

use chrono::Utc;
use netsec_db::repo::alerts;
use netsec_models::alert::{Alert, NormalizedAlert};
use sqlx::SqlitePool;

use crate::PipelineResult;

/// Result of the deduplication check.
pub enum DeduplicationResult {
    /// An existing alert was found; its count has been incremented.
    Duplicate(Box<Alert>),
    /// No existing alert matches this fingerprint.
    New,
}

/// Check the database for an existing alert with the same fingerprint.
///
/// If found, increment its count and return `Duplicate`. Otherwise return `New`.
pub async fn deduplicate(
    pool: &SqlitePool,
    alert: &NormalizedAlert,
) -> PipelineResult<DeduplicationResult> {
    let existing = alerts::get_by_fingerprint(pool, &alert.fingerprint).await?;

    match existing {
        Some(mut found) => {
            let now = Utc::now().to_rfc3339();
            alerts::increment_count(pool, &found.id, &now).await?;
            found.count += 1;
            found.updated_at = now;
            Ok(DeduplicationResult::Duplicate(Box::new(found)))
        }
        None => Ok(DeduplicationResult::New),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netsec_db::{pool::create_test_pool, run_migrations};
    use netsec_models::alert::{AlertCategory, Severity};

    fn make_normalized(fingerprint: &str) -> NormalizedAlert {
        NormalizedAlert {
            source_tool: "test".to_string(),
            severity: Severity::Medium,
            category: AlertCategory::Other,
            title: "Test alert".to_string(),
            description: "Test".to_string(),
            device_ip: Some("10.0.0.1".to_string()),
            fingerprint: fingerprint.to_string(),
            raw_data: serde_json::json!({}),
            timestamp: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_new_alert() {
        let pool = create_test_pool().await.unwrap();
        run_migrations(&pool).await.unwrap();

        let normalized = make_normalized("fp-unique-1");
        let result = deduplicate(&pool, &normalized).await.unwrap();
        assert!(matches!(result, DeduplicationResult::New));
    }

    #[tokio::test]
    async fn test_duplicate_detection_count_2() {
        let pool = create_test_pool().await.unwrap();
        run_migrations(&pool).await.unwrap();

        // Insert first alert
        let mut alert = Alert::new("Test".into(), "test".into(), "fp-dup-1".into());
        alert.device_ip = Some("10.0.0.1".to_string());
        alerts::insert(&pool, &alert).await.unwrap();

        // Deduplicate should find it
        let normalized = make_normalized("fp-dup-1");
        let result = deduplicate(&pool, &normalized).await.unwrap();
        match result {
            DeduplicationResult::Duplicate(a) => assert_eq!(a.count, 2),
            _ => panic!("Expected duplicate"),
        }
    }

    #[tokio::test]
    async fn test_different_fingerprints_both_new() {
        let pool = create_test_pool().await.unwrap();
        run_migrations(&pool).await.unwrap();

        let n1 = make_normalized("fp-a");
        let n2 = make_normalized("fp-b");
        let r1 = deduplicate(&pool, &n1).await.unwrap();
        let r2 = deduplicate(&pool, &n2).await.unwrap();
        assert!(matches!(r1, DeduplicationResult::New));
        assert!(matches!(r2, DeduplicationResult::New));
    }

    #[tokio::test]
    async fn test_triple_dedup_count_4() {
        let pool = create_test_pool().await.unwrap();
        run_migrations(&pool).await.unwrap();

        // Insert with count=1
        let alert = Alert::new("Test".into(), "test".into(), "fp-triple".into());
        alerts::insert(&pool, &alert).await.unwrap();

        let normalized = make_normalized("fp-triple");

        // First dedup -> count 2
        let r1 = deduplicate(&pool, &normalized).await.unwrap();
        match &r1 {
            DeduplicationResult::Duplicate(a) => assert_eq!(a.count, 2),
            _ => panic!("Expected duplicate"),
        }

        // Second dedup -> count 3
        let r2 = deduplicate(&pool, &normalized).await.unwrap();
        match &r2 {
            DeduplicationResult::Duplicate(a) => assert_eq!(a.count, 3),
            _ => panic!("Expected duplicate"),
        }

        // Third dedup -> count 4
        let r3 = deduplicate(&pool, &normalized).await.unwrap();
        match r3 {
            DeduplicationResult::Duplicate(a) => assert_eq!(a.count, 4),
            _ => panic!("Expected duplicate"),
        }
    }
}
