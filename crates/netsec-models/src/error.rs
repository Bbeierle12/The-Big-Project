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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netsec_error_display() {
        let err = NetsecError::Database("connection refused".into());
        assert_eq!(format!("{err}"), "database error: connection refused");

        let err = NetsecError::Parse("invalid JSON".into());
        assert_eq!(format!("{err}"), "parse error: invalid JSON");

        let err = NetsecError::Scan("timeout".into());
        assert_eq!(format!("{err}"), "scan error: timeout");

        let err = NetsecError::Plugin("not found".into());
        assert_eq!(format!("{err}"), "plugin error: not found");

        let err = NetsecError::Config("missing key".into());
        assert_eq!(format!("{err}"), "configuration error: missing key");

        let err = NetsecError::Platform("unsupported".into());
        assert_eq!(format!("{err}"), "platform error: unsupported");

        let err = NetsecError::NotFound("device xyz".into());
        assert_eq!(format!("{err}"), "not found: device xyz");

        let err = NetsecError::Other("something".into());
        assert_eq!(format!("{err}"), "something");
    }

    #[test]
    fn test_netsec_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err: NetsecError = io_err.into();
        let msg = format!("{err}");
        assert!(msg.contains("file missing"));
    }
}
