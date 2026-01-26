//! Device event repository.

use netsec_models::event::DeviceEvent;
use sqlx::SqlitePool;

pub async fn insert(pool: &SqlitePool, event: &DeviceEvent) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO device_events (id, device_id, event_type, details, created_at)
         VALUES (?, ?, ?, ?, ?)"
    )
    .bind(&event.id)
    .bind(&event.device_id)
    .bind(&event.event_type)
    .bind(&event.details)
    .bind(&event.created_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_by_device(pool: &SqlitePool, device_id: &str, limit: i64) -> Result<Vec<DeviceEvent>, sqlx::Error> {
    sqlx::query_as::<_, DeviceEvent>("SELECT * FROM device_events WHERE device_id = ? ORDER BY created_at DESC LIMIT ?")
        .bind(device_id)
        .bind(limit)
        .fetch_all(pool)
        .await
}
