//! Schema migration from SQL files.

use sqlx::SqlitePool;

/// SQL statements for all tables and schema migrations, in order.
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
    ("010_add_alert_notes", include_str!("../../../migrations/sql/010_add_alert_notes.sql")),
    ("011_add_device_fields", include_str!("../../../migrations/sql/011_add_device_fields.sql")),
    ("012_add_alert_fields", include_str!("../../../migrations/sql/012_add_alert_fields.sql")),
    ("013_add_vuln_fields", include_str!("../../../migrations/sql/013_add_vuln_fields.sql")),
];

/// Run all migrations against the database.
///
/// Uses `CREATE TABLE IF NOT EXISTS` for table creation and gracefully handles
/// `ALTER TABLE ADD COLUMN` for columns that already exist (idempotent).
pub async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    for (name, sql) in MIGRATIONS {
        tracing::debug!("Running migration: {name}");
        // Split multi-statement migrations and execute each statement separately
        // so we can handle "duplicate column" errors from ALTER TABLE.
        for stmt in sql.split(';') {
            let stmt = stmt.trim();
            if stmt.is_empty() {
                continue;
            }
            match sqlx::raw_sql(&format!("{stmt};")).execute(pool).await {
                Ok(_) => {}
                Err(sqlx::Error::Database(ref e))
                    if e.message().contains("duplicate column name") =>
                {
                    tracing::debug!("Column already exists, skipping: {}", stmt.lines().next().unwrap_or(stmt));
                }
                Err(e) => return Err(e),
            }
        }
    }
    tracing::info!("All {} migrations applied", MIGRATIONS.len());
    Ok(())
}
