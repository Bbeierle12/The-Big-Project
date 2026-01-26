//! Traffic flow repository.

use netsec_models::traffic::TrafficFlow;
use sqlx::SqlitePool;

pub async fn insert(pool: &SqlitePool, flow: &TrafficFlow) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO traffic_flows (id, src_ip, src_port, dst_ip, dst_port, protocol, bytes_sent, bytes_received, packets_sent, packets_received, first_seen, last_seen)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&flow.id)
    .bind(&flow.src_ip)
    .bind(flow.src_port)
    .bind(&flow.dst_ip)
    .bind(flow.dst_port)
    .bind(&flow.protocol)
    .bind(flow.bytes_sent)
    .bind(flow.bytes_received)
    .bind(flow.packets_sent)
    .bind(flow.packets_received)
    .bind(&flow.first_seen)
    .bind(&flow.last_seen)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_by_id(pool: &SqlitePool, id: &str) -> Result<Option<TrafficFlow>, sqlx::Error> {
    sqlx::query_as::<_, TrafficFlow>("SELECT * FROM traffic_flows WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn list(pool: &SqlitePool, limit: i64, offset: i64) -> Result<Vec<TrafficFlow>, sqlx::Error> {
    sqlx::query_as::<_, TrafficFlow>("SELECT * FROM traffic_flows ORDER BY last_seen DESC LIMIT ? OFFSET ?")
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
}

pub async fn delete(pool: &SqlitePool, id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM traffic_flows WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
