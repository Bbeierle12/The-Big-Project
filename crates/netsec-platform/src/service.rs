//! Cross-platform service management.
//!
//! Stub — full implementation in Phase 4.

use serde::{Deserialize, Serialize};

/// Service operational state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Running,
    Stopped,
    Unknown,
}

/// Status of a system service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub name: String,
    pub state: ServiceState,
    pub pid: Option<u32>,
}

/// Query the status of a system service by name.
pub async fn get_service_status(_name: &str) -> ServiceStatus {
    // Stub: full cross-platform implementation in Phase 4
    ServiceStatus {
        name: _name.to_string(),
        state: ServiceState::Unknown,
        pid: None,
    }
}
