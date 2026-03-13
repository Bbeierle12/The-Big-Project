//! File metadata extraction engine with security analysis.
//!
//! This crate ports the MetaExtract engine into the netsec workspace,
//! adding security-focused analysis (GPS leak detection, software fingerprinting,
//! timestamp anomaly detection) and a bridge to `NormalizedAlert`.
//!
//! # Architecture
//!
//! - **types** -- Core data structures (FileIdentity, ExtractedMetadata, ExifData, etc.)
//! - **handler** -- Handler trait and HandlerRegistry for pluggable format support
//! - **engine** -- MetadataEngine orchestrator (extract + analyze)
//! - **config** -- Serde-friendly configuration
//! - **security** -- SecurityFlags computation, risk scoring, NormalizedAlert bridge
//! - **utils** -- File identity (hashing) and MIME detection
//! - **handlers** -- Built-in handlers (image)

pub mod config;
pub mod engine;
pub mod handler;
pub mod handlers;
pub mod security;
pub mod types;
pub mod utils;

use thiserror::Error;

/// Errors produced by the metadata extraction engine.
#[derive(Debug, Error)]
pub enum MetadataError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("no handler for mime={mime}, extension={extension}")]
    NoHandler { mime: String, extension: String },

    #[error("file too large: {size} bytes (max {max})")]
    FileTooLarge { size: u64, max: u64 },

    #[error("invalid format: {0}")]
    InvalidFormat(String),

    #[error("validation failed: {0}")]
    ValidationFailed(String),

    #[error("exif error: {0}")]
    Exif(String),

    #[error("image error: {0}")]
    Image(#[from] image::ImageError),

    #[error("extraction error: {0}")]
    Extraction(String),
}

/// Convenience result alias.
pub type MetadataResult<T> = Result<T, MetadataError>;

// Re-exports for convenience.
pub use config::MetadataConfig;
pub use engine::MetadataEngine;
pub use handler::{Handler, HandlerRegistry};
pub use security::{MetadataAnalysis, SecurityFlags};
pub use types::ExtractedMetadata;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        let e = MetadataError::NoHandler {
            mime: "image/jpeg".into(),
            extension: ".jpg".into(),
        };
        assert!(e.to_string().contains("image/jpeg"));

        let e2 = MetadataError::FileTooLarge {
            size: 1000,
            max: 500,
        };
        assert!(e2.to_string().contains("1000"));
    }

    #[test]
    fn error_from_io() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let e: MetadataError = io.into();
        assert!(matches!(e, MetadataError::Io(_)));
    }
}
