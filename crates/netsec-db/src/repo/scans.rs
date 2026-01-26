//! Scan repository.

use netsec_models::scan::Scan;
use sqlx::SqlitePool;

pub async fn insert(pool: &SqlitePool, scan: &Scan) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO scans (id, scan_type, tool, target, status, progress, parameters, results, started_at, completed_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&scan.id)
    .bind(&scan.scan_type)
    .bind(&scan.tool)
    .bind(&scan.target)
    .bind(&scan.status)
    .bind(scan.progress)
    .bind(&scan.parameters)
    .bind(&scan.results)
    .bind(&scan.started_at)
    .bind(&scan.completed_at)
    .bind(&scan.created_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_by_id(pool: &SqlitePool, id: &str) -> Result<Option<Scan>, sqlx::Error> {
    sqlx::query_as::<_, Scan>("SELECT * FROM scans WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn list(pool: &SqlitePool, limit: i64, offset: i64) -> Result<Vec<Scan>, sqlx::Error> {
    sqlx::query_as::<_, Scan>("SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?")
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
}

pub async fn update_status(pool: &SqlitePool, id: &str, status: &str, progress: f64) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("UPDATE scans SET status=?, progress=? WHERE id=?")
        .bind(status)
        .bind(progress)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn set_results(pool: &SqlitePool, id: &str, results: &str, completed_at: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("UPDATE scans SET results=?, status='completed', progress=1.0, completed_at=? WHERE id=?")
        .bind(results)
        .bind(completed_at)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn delete(pool: &SqlitePool, id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM scans WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
