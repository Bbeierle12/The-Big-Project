//! Scheduled job repository.

use netsec_models::plugin::ScheduledJob;
use sqlx::SqlitePool;

pub async fn insert(pool: &SqlitePool, job: &ScheduledJob) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO scheduled_jobs (id, trigger_type, trigger_args, task_type, task_params, enabled, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&job.id)
    .bind(&job.trigger_type)
    .bind(&job.trigger_args)
    .bind(&job.task_type)
    .bind(&job.task_params)
    .bind(job.enabled)
    .bind(&job.created_at)
    .bind(&job.updated_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_by_id(pool: &SqlitePool, id: &str) -> Result<Option<ScheduledJob>, sqlx::Error> {
    sqlx::query_as::<_, ScheduledJob>("SELECT * FROM scheduled_jobs WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn list_enabled(pool: &SqlitePool) -> Result<Vec<ScheduledJob>, sqlx::Error> {
    sqlx::query_as::<_, ScheduledJob>("SELECT * FROM scheduled_jobs WHERE enabled = 1")
        .fetch_all(pool)
        .await
}

pub async fn list(pool: &SqlitePool, limit: i64, offset: i64) -> Result<Vec<ScheduledJob>, sqlx::Error> {
    sqlx::query_as::<_, ScheduledJob>("SELECT * FROM scheduled_jobs ORDER BY created_at DESC LIMIT ? OFFSET ?")
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
}

pub async fn set_enabled(pool: &SqlitePool, id: &str, enabled: bool, updated_at: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("UPDATE scheduled_jobs SET enabled=?, updated_at=? WHERE id=?")
        .bind(enabled)
        .bind(updated_at)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn delete(pool: &SqlitePool, id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM scheduled_jobs WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
