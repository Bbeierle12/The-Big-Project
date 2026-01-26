//! Port repository.

use netsec_models::port::Port;
use sqlx::SqlitePool;

pub async fn insert(pool: &SqlitePool, port: &Port) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO ports (id, device_id, port_number, protocol, state, service_name, service_version, banner, first_seen, last_seen)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&port.id)
    .bind(&port.device_id)
    .bind(port.port_number)
    .bind(&port.protocol)
    .bind(&port.state)
    .bind(&port.service_name)
    .bind(&port.service_version)
    .bind(&port.banner)
    .bind(&port.first_seen)
    .bind(&port.last_seen)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_by_id(pool: &SqlitePool, id: &str) -> Result<Option<Port>, sqlx::Error> {
    sqlx::query_as::<_, Port>("SELECT * FROM ports WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn list_by_device(pool: &SqlitePool, device_id: &str) -> Result<Vec<Port>, sqlx::Error> {
    sqlx::query_as::<_, Port>("SELECT * FROM ports WHERE device_id = ? ORDER BY port_number")
        .bind(device_id)
        .fetch_all(pool)
        .await
}

pub async fn upsert(pool: &SqlitePool, port: &Port) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO ports (id, device_id, port_number, protocol, state, service_name, service_version, banner, first_seen, last_seen)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(device_id, port_number, protocol) DO UPDATE SET
           state = excluded.state,
           service_name = excluded.service_name,
           service_version = excluded.service_version,
           banner = excluded.banner,
           last_seen = excluded.last_seen"
    )
    .bind(&port.id)
    .bind(&port.device_id)
    .bind(port.port_number)
    .bind(&port.protocol)
    .bind(&port.state)
    .bind(&port.service_name)
    .bind(&port.service_version)
    .bind(&port.banner)
    .bind(&port.first_seen)
    .bind(&port.last_seen)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_by_device_port_proto(
    pool: &SqlitePool,
    device_id: &str,
    port_number: i64,
    protocol: &str,
) -> Result<Option<Port>, sqlx::Error> {
    sqlx::query_as::<_, Port>(
        "SELECT * FROM ports WHERE device_id = ? AND port_number = ? AND protocol = ?",
    )
    .bind(device_id)
    .bind(port_number)
    .bind(protocol)
    .fetch_optional(pool)
    .await
}

pub async fn delete(pool: &SqlitePool, id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM ports WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
