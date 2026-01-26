//! Alert correlation stage.
//!
//! Groups related alerts from the same device within a time window
//! by assigning them a shared `correlation_id`.

use chrono::{Duration, Utc};
use netsec_db::repo::alerts;
use netsec_models::alert::NormalizedAlert;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::PipelineResult;

/// Determine a correlation_id for the given alert.
///
/// - If the alert has no `device_ip`, returns `None`.
/// - Queries recent alerts for the same device within `window_secs`.
/// - If a recent alert already has a `correlation_id`, reuses it.
/// - Otherwise, generates a new UUID and backfills existing correlated alerts.
pub async fn correlate(
    pool: &SqlitePool,
    alert: &NormalizedAlert,
    window_secs: i64,
) -> PipelineResult<Option<String>> {
    let device_ip = match &alert.device_ip {
        Some(ip) => ip,
        None => return Ok(None),
    };

    let since = (Utc::now() - Duration::seconds(window_secs)).to_rfc3339();
    let recent = alerts::list_by_device_ip_since(pool, device_ip, &since).await?;

    if recent.is_empty() {
        // First alert for this device in the window — new correlation group
        let cid = Uuid::new_v4().to_string();
        return Ok(Some(cid));
    }

    // Check if any recent alert already has a correlation_id
    for r in &recent {
        if let Some(ref cid) = r.correlation_id {
            return Ok(Some(cid.clone()));
        }
    }

    // No existing correlation_id — generate one and backfill
    let cid = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    for r in &recent {
        sqlx::query("UPDATE alerts SET correlation_id = ?, updated_at = ? WHERE id = ?")
            .bind(&cid)
            .bind(&now)
            .bind(&r.id)
            .execute(pool)
            .await
            .map_err(crate::PipelineError::Database)?;
    }

    Ok(Some(cid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use netsec_db::{pool::create_test_pool, run_migrations};
    use netsec_db::repo::alerts as alert_repo;
    use netsec_models::alert::{Alert, AlertCategory, Severity};

    fn make_normalized(device_ip: Option<&str>, fingerprint: &str) -> NormalizedAlert {
        NormalizedAlert {
            source_tool: "test".to_string(),
            severity: Severity::Low,
            category: AlertCategory::Other,
            title: "Corr test".to_string(),
            description: "".to_string(),
            device_ip: device_ip.map(|s| s.to_string()),
            fingerprint: fingerprint.to_string(),
            raw_data: serde_json::json!({}),
            timestamp: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_no_device_ip() {
        let pool = create_test_pool().await.unwrap();
        run_migrations(&pool).await.unwrap();

        let na = make_normalized(None, "fp-no-ip");
        let cid = correlate(&pool, &na, 300).await.unwrap();
        assert!(cid.is_none());
    }

    #[tokio::test]
    async fn test_first_alert_for_device() {
        let pool = create_test_pool().await.unwrap();
        run_migrations(&pool).await.unwrap();

        let na = make_normalized(Some("10.0.0.1"), "fp-first");
        let cid = correlate(&pool, &na, 300).await.unwrap();
        assert!(cid.is_some());
        // Should be a valid UUID
        Uuid::parse_str(cid.as_ref().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn test_second_alert_same_device_within_window() {
        let pool = create_test_pool().await.unwrap();
        run_migrations(&pool).await.unwrap();

        // Insert a first alert for the device
        let mut a1 = Alert::new("First".into(), "test".into(), "fp-corr-1".into());
        a1.device_ip = Some("10.0.0.5".to_string());
        a1.correlation_id = Some("existing-cid".to_string());
        alert_repo::insert(&pool, &a1).await.unwrap();

        // Correlate a second alert for the same device
        let na = make_normalized(Some("10.0.0.5"), "fp-corr-2");
        let cid = correlate(&pool, &na, 300).await.unwrap();
        assert_eq!(cid, Some("existing-cid".to_string()));
    }

    #[tokio::test]
    async fn test_backfill_sets_correlation_id() {
        let pool = create_test_pool().await.unwrap();
        run_migrations(&pool).await.unwrap();

        // Insert an alert WITHOUT a correlation_id
        let mut a1 = Alert::new("Backfill".into(), "test".into(), "fp-backfill-1".into());
        a1.device_ip = Some("10.0.0.9".to_string());
        a1.correlation_id = None;
        alert_repo::insert(&pool, &a1).await.unwrap();

        // Correlate a new alert for the same device
        let na = make_normalized(Some("10.0.0.9"), "fp-backfill-2");
        let cid = correlate(&pool, &na, 300).await.unwrap();
        assert!(cid.is_some());

        // The original alert should now have the correlation_id
        let updated = alert_repo::get_by_id(&pool, &a1.id).await.unwrap().unwrap();
        assert_eq!(updated.correlation_id, cid);
    }

    #[tokio::test]
    async fn test_outside_window_gets_new_id() {
        let pool = create_test_pool().await.unwrap();
        run_migrations(&pool).await.unwrap();

        // Insert an alert with an old timestamp (outside the window)
        let mut a1 = Alert::new("Old".into(), "test".into(), "fp-old-1".into());
        a1.device_ip = Some("10.0.0.20".to_string());
        a1.correlation_id = Some("old-cid".to_string());
        // Set created_at to 10 minutes ago (outside 5-min window)
        let old_time = (Utc::now() - Duration::seconds(600)).to_rfc3339();
        a1.created_at = old_time.clone();
        a1.updated_at = old_time;
        alert_repo::insert(&pool, &a1).await.unwrap();

        let na = make_normalized(Some("10.0.0.20"), "fp-old-2");
        let cid = correlate(&pool, &na, 300).await.unwrap();
        // Should be a new correlation_id, not the old one
        assert!(cid.is_some());
        assert_ne!(cid, Some("old-cid".to_string()));
    }
}
