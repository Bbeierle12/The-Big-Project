//! Shared error types for the netsec platform.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetsecError {
    #[error("database error: {0}")]
    Database(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("scan error: {0}")]
    Scan(String),

    #[error("plugin error: {0}")]
    Plugin(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("platform error: {0}")]
    Platform(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, NetsecError>;
