//! Observation repository.

use netsec_models::event::Observation;
use sqlx::SqlitePool;

pub async fn insert(pool: &SqlitePool, obs: &Observation) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO observations (id, device_id, protocol, source_data, created_at)
         VALUES (?, ?, ?, ?, ?)"
    )
    .bind(&obs.id)
    .bind(&obs.device_id)
    .bind(&obs.protocol)
    .bind(&obs.source_data)
    .bind(&obs.created_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_by_device(pool: &SqlitePool, device_id: &str, limit: i64) -> Result<Vec<Observation>, sqlx::Error> {
    sqlx::query_as::<_, Observation>("SELECT * FROM observations WHERE device_id = ? ORDER BY created_at DESC LIMIT ?")
        .bind(device_id)
        .bind(limit)
        .fetch_all(pool)
        .await
}
