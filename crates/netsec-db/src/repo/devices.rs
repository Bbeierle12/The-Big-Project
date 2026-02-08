//! Device repository.

use netsec_models::device::Device;
use sqlx::SqlitePool;

pub async fn insert(pool: &SqlitePool, device: &Device) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO devices (id, ip, mac, hostname, vendor, os_family, os_version, device_type, classification_confidence, status, notes, first_seen, last_seen)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&device.id)
    .bind(&device.ip)
    .bind(&device.mac)
    .bind(&device.hostname)
    .bind(&device.vendor)
    .bind(&device.os_family)
    .bind(&device.os_version)
    .bind(&device.device_type)
    .bind(device.classification_confidence)
    .bind(&device.status)
    .bind(&device.notes)
    .bind(&device.first_seen)
    .bind(&device.last_seen)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_by_id(pool: &SqlitePool, id: &str) -> Result<Option<Device>, sqlx::Error> {
    sqlx::query_as::<_, Device>("SELECT * FROM devices WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn get_by_ip(pool: &SqlitePool, ip: &str) -> Result<Option<Device>, sqlx::Error> {
    sqlx::query_as::<_, Device>("SELECT * FROM devices WHERE ip = ?")
        .bind(ip)
        .fetch_optional(pool)
        .await
}

pub async fn list(pool: &SqlitePool, limit: i64, offset: i64) -> Result<Vec<Device>, sqlx::Error> {
    sqlx::query_as::<_, Device>("SELECT * FROM devices ORDER BY last_seen DESC LIMIT ? OFFSET ?")
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
}

pub async fn update(pool: &SqlitePool, device: &Device) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE devices SET ip=?, mac=?, hostname=?, vendor=?, os_family=?, os_version=?, device_type=?, classification_confidence=?, status=?, notes=?, last_seen=?
         WHERE id=?"
    )
    .bind(&device.ip)
    .bind(&device.mac)
    .bind(&device.hostname)
    .bind(&device.vendor)
    .bind(&device.os_family)
    .bind(&device.os_version)
    .bind(&device.device_type)
    .bind(device.classification_confidence)
    .bind(&device.status)
    .bind(&device.notes)
    .bind(&device.last_seen)
    .bind(&device.id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn delete(pool: &SqlitePool, id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM devices WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn get_by_mac(pool: &SqlitePool, mac: &str) -> Result<Option<Device>, sqlx::Error> {
    sqlx::query_as::<_, Device>("SELECT * FROM devices WHERE mac = ?")
        .bind(mac)
        .fetch_optional(pool)
        .await
}

pub async fn count(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM devices")
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}
