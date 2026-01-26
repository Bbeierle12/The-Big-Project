//! Operating system detection.

use serde::{Deserialize, Serialize};

/// Supported operating system families.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OsType {
    Linux,
    MacOs,
    Windows,
    Unknown,
}

/// Detect the current operating system.
pub fn detect_platform() -> OsType {
    if cfg!(target_os = "linux") {
        OsType::Linux
    } else if cfg!(target_os = "macos") {
        OsType::MacOs
    } else if cfg!(target_os = "windows") {
        OsType::Windows
    } else {
        OsType::Unknown
    }
}
