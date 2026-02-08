//! Vulnerability repository.

use netsec_models::vulnerability::Vulnerability;
use sqlx::SqlitePool;

pub async fn insert(pool: &SqlitePool, vuln: &Vulnerability) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO vulnerabilities (id, cve_id, cvss_score, severity, title, description, device_id, port, source_tool, solution, created_at, updated_at, service, device_ip, status, references_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&vuln.id)
    .bind(&vuln.cve_id)
    .bind(vuln.cvss_score)
    .bind(&vuln.severity)
    .bind(&vuln.title)
    .bind(&vuln.description)
    .bind(&vuln.device_id)
    .bind(vuln.port)
    .bind(&vuln.source_tool)
    .bind(&vuln.solution)
    .bind(&vuln.created_at)
    .bind(&vuln.updated_at)
    .bind(&vuln.service)
    .bind(&vuln.device_ip)
    .bind(&vuln.status)
    .bind(&vuln.references_json)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_by_id(pool: &SqlitePool, id: &str) -> Result<Option<Vulnerability>, sqlx::Error> {
    sqlx::query_as::<_, Vulnerability>("SELECT * FROM vulnerabilities WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn list(pool: &SqlitePool, limit: i64, offset: i64) -> Result<Vec<Vulnerability>, sqlx::Error> {
    sqlx::query_as::<_, Vulnerability>("SELECT * FROM vulnerabilities ORDER BY created_at DESC LIMIT ? OFFSET ?")
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
}

pub async fn list_by_device(pool: &SqlitePool, device_id: &str) -> Result<Vec<Vulnerability>, sqlx::Error> {
    sqlx::query_as::<_, Vulnerability>("SELECT * FROM vulnerabilities WHERE device_id = ? ORDER BY cvss_score DESC")
        .bind(device_id)
        .fetch_all(pool)
        .await
}

pub async fn delete(pool: &SqlitePool, id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM vulnerabilities WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
