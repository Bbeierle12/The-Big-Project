//! Privilege and elevation checking.
//!
//! Cross-platform implementation using `std::process::Command`.

/// Check if the current process has elevated/admin privileges.
///
/// - **Unix**: runs `id -u` and checks if output is `"0"` (root).
/// - **Windows**: runs `net session` and checks for success exit status.
/// - **Other**: returns `false`.
pub fn is_elevated() -> bool {
    #[cfg(unix)]
    {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .map(|output| {
                String::from_utf8_lossy(&output.stdout).trim() == "0"
            })
            .unwrap_or(false)
    }

    #[cfg(windows)]
    {
        std::process::Command::new("net")
            .arg("session")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::detect_platform;
    use crate::detect::OsType;

    #[test]
    fn test_is_elevated_returns_bool() {
        // Should return a bool without panicking
        let _result: bool = is_elevated();
    }

    #[test]
    fn test_is_elevated_deterministic() {
        let first = is_elevated();
        let second = is_elevated();
        assert_eq!(first, second);
    }

    #[test]
    fn test_platform_detection_consistent() {
        let platform = detect_platform();
        if cfg!(target_os = "linux") {
            assert_eq!(platform, OsType::Linux);
        } else if cfg!(target_os = "macos") {
            assert_eq!(platform, OsType::MacOs);
        } else if cfg!(target_os = "windows") {
            assert_eq!(platform, OsType::Windows);
        } else {
            assert_eq!(platform, OsType::Unknown);
        }
    }
}
