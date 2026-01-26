//! SQLite database layer via sqlx with async support.
//!
//! Provides:
//! - Connection pool initialization
//! - Schema migration from SQL files
//! - Repository implementations for all 9 unified schema tables

pub mod pool;
pub mod migrate;
pub mod repo;

pub use pool::create_pool;
pub use migrate::run_migrations;
