//! Database connection pool management.

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;

/// Create a SQLite connection pool.
///
/// `url` should be a SQLite path like `sqlite:netsec.db` or `:memory:` for testing.
pub async fn create_pool(url: &str) -> Result<SqlitePool, sqlx::Error> {
    let opts = SqliteConnectOptions::from_str(url)?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .foreign_keys(true);

    SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await
}

/// Create an in-memory pool for testing.
pub async fn create_test_pool() -> Result<SqlitePool, sqlx::Error> {
    create_pool("sqlite::memory:").await
}
