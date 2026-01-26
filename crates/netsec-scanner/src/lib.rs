//! Network scanning engine: active discovery, passive listeners, OUI lookup,
//! device classification and fingerprinting.

pub mod active;
pub mod fingerprint;
pub mod passive;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScannerError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("nmap execution error: {0}")]
    NmapExecution(String),
    #[error("nmap parse error: {0}")]
    NmapParse(String),
    #[error("passive parse error: {0}")]
    PassiveParse(String),
    #[error("event bus error: {0}")]
    EventBus(String),
}

pub type ScannerResult<T> = Result<T, ScannerError>;
