//! Cross-platform service management.
//!
//! Provides pure parsing functions for systemctl and sc query output,
//! plus a real `get_service_status` function that invokes the appropriate command.

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

/// Parse `systemctl show --property=ActiveState,MainPID,Id` output into a `ServiceStatus`.
///
/// Expected format:
/// ```text
/// Id=nginx.service
/// ActiveState=active
/// MainPID=1234
/// ```
pub fn parse_systemctl_output(output: &str) -> ServiceStatus {
    let mut name = String::new();
    let mut state = ServiceState::Unknown;
    let mut pid: Option<u32> = None;

    for line in output.lines() {
        let line = line.trim();
        if let Some((key, value)) = line.split_once('=') {
            match key.trim() {
                "ActiveState" => {
                    state = match value.trim() {
                        "active" => ServiceState::Running,
                        "inactive" | "failed" | "dead" => ServiceState::Stopped,
                        _ => ServiceState::Unknown,
                    };
                }
                "MainPID" => {
                    if let Ok(p) = value.trim().parse::<u32>() {
                        if p > 0 {
                            pid = Some(p);
                        }
                    }
                }
                "Id" => {
                    name = value.trim().to_string();
                }
                _ => {}
            }
        }
    }

    ServiceStatus { name, state, pid }
}

/// Parse Windows `sc query` output into a `ServiceStatus`.
///
/// Looks for `STATE` line containing `RUNNING` or `STOPPED`,
/// and optionally extracts `PID` from output.
pub fn parse_sc_output(service_name: &str, output: &str) -> ServiceStatus {
    let mut state = ServiceState::Unknown;
    let mut pid: Option<u32> = None;

    for line in output.lines() {
        let line_upper = line.trim().to_uppercase();

        if line_upper.contains("STATE") {
            if line_upper.contains("RUNNING") {
                state = ServiceState::Running;
            } else if line_upper.contains("STOPPED") {
                state = ServiceState::Stopped;
            }
        }

        // Try to extract PID from lines like "PID : 1234"
        if line_upper.contains("PID") {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 2 {
                if let Ok(p) = parts[1].trim().parse::<u32>() {
                    if p > 0 {
                        pid = Some(p);
                    }
                }
            }
        }
    }

    ServiceStatus {
        name: service_name.to_string(),
        state,
        pid,
    }
}

/// Query the status of a system service by name.
///
/// - **Unix**: runs `systemctl show --property=ActiveState,MainPID,Id {name}`.
/// - **Windows**: runs `sc query {name}`.
/// - On command failure: returns `ServiceState::Unknown`.
pub async fn get_service_status(name: &str) -> ServiceStatus {
    #[cfg(unix)]
    {
        match tokio::process::Command::new("systemctl")
            .args(["show", "--property=ActiveState,MainPID,Id", name])
            .output()
            .await
        {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut status = parse_systemctl_output(&stdout);
                if status.name.is_empty() {
                    status.name = name.to_string();
                }
                status
            }
            Err(_) => ServiceStatus {
                name: name.to_string(),
                state: ServiceState::Unknown,
                pid: None,
            },
        }
    }

    #[cfg(windows)]
    {
        match tokio::process::Command::new("sc")
            .args(["query", name])
            .output()
            .await
        {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                parse_sc_output(name, &stdout)
            }
            Err(_) => ServiceStatus {
                name: name.to_string(),
                state: ServiceState::Unknown,
                pid: None,
            },
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        ServiceStatus {
            name: name.to_string(),
            state: ServiceState::Unknown,
            pid: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_systemctl_active() {
        let output = "Id=nginx.service\nActiveState=active\nMainPID=1234\n";
        let status = parse_systemctl_output(output);
        assert_eq!(status.state, ServiceState::Running);
        assert_eq!(status.pid, Some(1234));
        assert_eq!(status.name, "nginx.service");
    }

    #[test]
    fn test_parse_systemctl_inactive() {
        let output = "Id=nginx.service\nActiveState=inactive\nMainPID=0\n";
        let status = parse_systemctl_output(output);
        assert_eq!(status.state, ServiceState::Stopped);
        assert_eq!(status.pid, None);
    }

    #[test]
    fn test_parse_systemctl_failed() {
        let output = "Id=myapp.service\nActiveState=failed\nMainPID=0\n";
        let status = parse_systemctl_output(output);
        assert_eq!(status.state, ServiceState::Stopped);
    }

    #[test]
    fn test_parse_systemctl_missing_pid() {
        let output = "Id=sshd.service\nActiveState=active\nMainPID=0\n";
        let status = parse_systemctl_output(output);
        assert_eq!(status.state, ServiceState::Running);
        assert_eq!(status.pid, None);
    }

    #[test]
    fn test_parse_systemctl_empty() {
        let status = parse_systemctl_output("");
        assert_eq!(status.state, ServiceState::Unknown);
        assert_eq!(status.pid, None);
        assert!(status.name.is_empty());
    }

    #[test]
    fn test_parse_sc_running() {
        let output = "SERVICE_NAME: w32time\n\
                       TYPE               : 30  WIN32\n\
                       STATE              : 4  RUNNING\n\
                       WIN32_EXIT_CODE    : 0\n\
                       PID                : 1048\n";
        let status = parse_sc_output("w32time", output);
        assert_eq!(status.state, ServiceState::Running);
        assert_eq!(status.pid, Some(1048));
        assert_eq!(status.name, "w32time");
    }

    #[test]
    fn test_parse_sc_stopped() {
        let output = "SERVICE_NAME: spooler\n\
                       TYPE               : 110  WIN32_OWN_PROCESS\n\
                       STATE              : 1  STOPPED\n\
                       WIN32_EXIT_CODE    : 0\n";
        let status = parse_sc_output("spooler", output);
        assert_eq!(status.state, ServiceState::Stopped);
    }

    #[test]
    fn test_parse_sc_empty() {
        let status = parse_sc_output("unknown", "");
        assert_eq!(status.state, ServiceState::Unknown);
        assert_eq!(status.pid, None);
        assert_eq!(status.name, "unknown");
    }
}
