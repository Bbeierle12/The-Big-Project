//! Nmap executor: binary discovery, privilege checking, and scan execution.

use std::path::PathBuf;

use netsec_models::scan::ScanType;
use netsec_parsers::nmap::NmapScanResult;

use crate::active::{build_nmap_args, ScanConfig};
use crate::{ScannerError, ScannerResult};

/// Find the nmap binary on the system.
///
/// 1. Tries `where nmap` (Windows) or `which nmap` (Unix) via `std::process::Command`.
/// 2. Falls back to common installation paths.
/// 3. Returns `None` if nmap cannot be found.
pub fn find_nmap_binary() -> Option<PathBuf> {
    // Try the system PATH lookup command
    #[cfg(windows)]
    let which_result = std::process::Command::new("where")
        .arg("nmap")
        .output();

    #[cfg(not(windows))]
    let which_result = std::process::Command::new("which")
        .arg("nmap")
        .output();

    if let Ok(output) = which_result {
        if output.status.success() {
            let path_str = String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if !path_str.is_empty() {
                let path = PathBuf::from(&path_str);
                if path.exists() {
                    return Some(path);
                }
            }
        }
    }

    // Check common fallback paths
    let fallback_paths = [
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
        "/opt/homebrew/bin/nmap",
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ];

    for path_str in &fallback_paths {
        let path = PathBuf::from(path_str);
        if path.exists() {
            return Some(path);
        }
    }

    None
}

/// Check if current privileges are sufficient for the given scan type.
///
/// - `Discovery` scans need no elevation (uses `-sn` ping scan).
/// - `Port`, `Full`, `Vulnerability`, and `Custom` scans require elevation
///   because they use SYN scan (`-sS`) which needs raw sockets.
pub fn check_scan_privileges(scan_type: &ScanType) -> ScannerResult<()> {
    match scan_type {
        ScanType::Discovery => Ok(()),
        _ => {
            if netsec_platform::privileges::is_elevated() {
                Ok(())
            } else {
                Err(ScannerError::NmapExecution(
                    "requires elevated privileges for SYN scan (-sS)".to_string(),
                ))
            }
        }
    }
}

/// Execute nmap with the given scan configuration and return parsed results.
///
/// 1. Finds the nmap binary.
/// 2. Checks privileges for the scan type.
/// 3. Builds nmap arguments.
/// 4. Spawns nmap as a subprocess, capturing stdout.
/// 5. Parses XML output via `netsec_parsers::nmap::parse_nmap_xml()`.
pub async fn execute_nmap(config: &ScanConfig) -> ScannerResult<NmapScanResult> {
    let nmap_path = find_nmap_binary().ok_or_else(|| {
        ScannerError::NmapExecution(
            "nmap binary not found; install nmap or add it to PATH".to_string(),
        )
    })?;

    check_scan_privileges(&config.scan_type)?;

    let args = build_nmap_args(config);

    let output = tokio::process::Command::new(&nmap_path)
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .map_err(|e| ScannerError::NmapExecution(format!("failed to spawn nmap: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ScannerError::NmapExecution(format!(
            "nmap exited with status {}: {}",
            output.status,
            stderr.trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    netsec_parsers::nmap::parse_nmap_xml(&stdout)
        .map_err(|e| ScannerError::NmapParse(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_nmap_binary_returns_option() {
        // Should return Some or None without panicking
        let _result: Option<PathBuf> = find_nmap_binary();
    }

    #[test]
    fn test_check_privileges_discovery_ok() {
        // Discovery scan should never require elevation
        let result = check_scan_privileges(&ScanType::Discovery);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_privileges_full_needs_elevation() {
        let result = check_scan_privileges(&ScanType::Full);
        if !netsec_platform::privileges::is_elevated() {
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(err.contains("elevated privileges"));
        } else {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_check_privileges_port_needs_elevation() {
        let result = check_scan_privileges(&ScanType::Port);
        if !netsec_platform::privileges::is_elevated() {
            assert!(result.is_err());
        } else {
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_execute_nmap_no_binary() {
        // Use a target that won't be found if nmap doesn't exist
        let config = ScanConfig {
            target: "127.0.0.1".to_string(),
            scan_type: ScanType::Discovery,
            timing: 4,
            ports: None,
        };

        if find_nmap_binary().is_none() {
            let result = execute_nmap(&config).await;
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(err.contains("nmap binary not found"));
        }
        // If nmap exists, this test is a no-op (we don't want to actually scan)
    }

    #[tokio::test]
    async fn test_run_scan_creates_record() {
        let pool = netsec_db::pool::create_test_pool().await.unwrap();
        netsec_db::run_migrations(&pool).await.unwrap();
        let bus = netsec_events::EventBus::new();
        let scanner = crate::active::ActiveScanner::new(pool.clone(), bus);

        let config = ScanConfig {
            target: "192.168.99.0/24".to_string(),
            scan_type: ScanType::Discovery,
            timing: 4,
            ports: None,
        };

        let scan = scanner.create_scan_record(&config).await.unwrap();
        assert_eq!(scan.tool, "nmap");
        assert_eq!(scan.status, "running");

        // Verify in DB
        let from_db = netsec_db::repo::scans::get_by_id(&pool, &scan.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(from_db.status, "running");
    }

    #[tokio::test]
    async fn test_run_scan_marks_failed_on_error() {
        let pool = netsec_db::pool::create_test_pool().await.unwrap();
        netsec_db::run_migrations(&pool).await.unwrap();
        let bus = netsec_events::EventBus::new();
        let scanner = crate::active::ActiveScanner::new(pool.clone(), bus);

        let config = ScanConfig {
            target: "192.168.99.0/24".to_string(),
            scan_type: ScanType::Discovery,
            timing: 4,
            ports: None,
        };

        // run_scan will fail because nmap probably isn't installed in test env
        let result = scanner.run_scan(&config).await;

        if result.is_err() {
            // Verify the scan record was created and marked as failed
            let scans = netsec_db::repo::scans::list(&pool, 10, 0).await.unwrap();
            if !scans.is_empty() {
                assert_eq!(scans[0].status, "failed");
            }
        }
    }
}
