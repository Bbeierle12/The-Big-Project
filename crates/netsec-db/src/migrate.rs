//! Schema migration from SQL files.

use sqlx::SqlitePool;

/// SQL statements for all 9 tables, in order.
const MIGRATIONS: &[(&str, &str)] = &[
    ("001_create_devices", include_str!("../../../migrations/sql/001_create_devices.sql")),
    ("002_create_ports", include_str!("../../../migrations/sql/002_create_ports.sql")),
    ("003_create_alerts", include_str!("../../../migrations/sql/003_create_alerts.sql")),
    ("004_create_scans", include_str!("../../../migrations/sql/004_create_scans.sql")),
    ("005_create_vulnerabilities", include_str!("../../../migrations/sql/005_create_vulnerabilities.sql")),
    ("006_create_traffic_flows", include_str!("../../../migrations/sql/006_create_traffic_flows.sql")),
    ("007_create_device_events", include_str!("../../../migrations/sql/007_create_device_events.sql")),
    ("008_create_observations", include_str!("../../../migrations/sql/008_create_observations.sql")),
    ("009_create_scheduled_jobs", include_str!("../../../migrations/sql/009_create_scheduled_jobs.sql")),
];

/// Run all migrations against the database.
///
/// Uses `CREATE TABLE IF NOT EXISTS` so migrations are idempotent.
pub async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    for (name, sql) in MIGRATIONS {
        tracing::debug!("Running migration: {name}");
        sqlx::raw_sql(sql).execute(pool).await?;
    }
    tracing::info!("All {} migrations applied", MIGRATIONS.len());
    Ok(())
}
