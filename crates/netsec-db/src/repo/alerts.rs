//! Alert repository.

use netsec_models::alert::Alert;
use sqlx::SqlitePool;

pub async fn insert(pool: &SqlitePool, alert: &Alert) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO alerts (id, severity, status, source_tool, category, title, description, device_ip, fingerprint, correlation_id, count, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&alert.id)
    .bind(&alert.severity)
    .bind(&alert.status)
    .bind(&alert.source_tool)
    .bind(&alert.category)
    .bind(&alert.title)
    .bind(&alert.description)
    .bind(&alert.device_ip)
    .bind(&alert.fingerprint)
    .bind(&alert.correlation_id)
    .bind(alert.count)
    .bind(&alert.created_at)
    .bind(&alert.updated_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_by_id(pool: &SqlitePool, id: &str) -> Result<Option<Alert>, sqlx::Error> {
    sqlx::query_as::<_, Alert>("SELECT * FROM alerts WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn get_by_fingerprint(pool: &SqlitePool, fingerprint: &str) -> Result<Option<Alert>, sqlx::Error> {
    sqlx::query_as::<_, Alert>("SELECT * FROM alerts WHERE fingerprint = ? ORDER BY created_at DESC LIMIT 1")
        .bind(fingerprint)
        .fetch_optional(pool)
        .await
}

pub async fn list(pool: &SqlitePool, limit: i64, offset: i64) -> Result<Vec<Alert>, sqlx::Error> {
    sqlx::query_as::<_, Alert>("SELECT * FROM alerts ORDER BY created_at DESC LIMIT ? OFFSET ?")
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
}

pub async fn update_status(pool: &SqlitePool, id: &str, status: &str, updated_at: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("UPDATE alerts SET status=?, updated_at=? WHERE id=?")
        .bind(status)
        .bind(updated_at)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn increment_count(pool: &SqlitePool, id: &str, updated_at: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("UPDATE alerts SET count = count + 1, updated_at=? WHERE id=?")
        .bind(updated_at)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn delete(pool: &SqlitePool, id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM alerts WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn count(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM alerts")
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}
