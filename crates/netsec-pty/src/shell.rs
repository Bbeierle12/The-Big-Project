//! Shell detection and information.

use std::path::PathBuf;

/// Information about an available shell.
#[derive(Debug, Clone)]
pub struct ShellInfo {
    /// Unique identifier (e.g., "pwsh", "cmd", "bash")
    pub id: String,
    /// Display name (e.g., "PowerShell 7", "Command Prompt")
    pub name: String,
    /// Full path to the shell executable
    pub path: PathBuf,
}

impl ShellInfo {
    /// Create a new ShellInfo.
    pub fn new(id: impl Into<String>, name: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            path: path.into(),
        }
    }
}

/// Detect available shells on the current platform.
pub fn detect_available_shells() -> Vec<ShellInfo> {
    let mut shells = Vec::new();

    #[cfg(windows)]
    {
        // PowerShell 7 (pwsh)
        let pwsh7_path = PathBuf::from(r"C:\Program Files\PowerShell\7\pwsh.exe");
        if pwsh7_path.exists() {
            shells.push(ShellInfo::new("pwsh", "PowerShell 7", pwsh7_path));
        }

        // Windows PowerShell 5.1
        let pwsh5_path = PathBuf::from(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
        if pwsh5_path.exists() {
            shells.push(ShellInfo::new("powershell", "Windows PowerShell", pwsh5_path));
        }

        // Command Prompt
        let cmd_path = std::env::var("COMSPEC")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(r"C:\Windows\System32\cmd.exe"));
        if cmd_path.exists() {
            shells.push(ShellInfo::new("cmd", "Command Prompt", cmd_path));
        }

        // Git Bash
        let git_bash_paths = [
            PathBuf::from(r"C:\Program Files\Git\bin\bash.exe"),
            PathBuf::from(r"C:\Program Files (x86)\Git\bin\bash.exe"),
        ];
        for path in git_bash_paths {
            if path.exists() {
                shells.push(ShellInfo::new("git-bash", "Git Bash", path));
                break;
            }
        }

        // WSL
        let wsl_path = PathBuf::from(r"C:\Windows\System32\wsl.exe");
        if wsl_path.exists() {
            shells.push(ShellInfo::new("wsl", "WSL", wsl_path));
        }
    }

    #[cfg(unix)]
    {
        let unix_shells = [
            ("bash", "Bash", "/bin/bash"),
            ("zsh", "Zsh", "/bin/zsh"),
            ("fish", "Fish", "/usr/bin/fish"),
            ("sh", "Shell", "/bin/sh"),
        ];

        for (id, name, path) in unix_shells {
            let path = PathBuf::from(path);
            if path.exists() {
                shells.push(ShellInfo::new(id, name, path));
            }
        }

        // Homebrew shells (macOS)
        let homebrew_shells = [
            ("bash-homebrew", "Bash (Homebrew)", "/usr/local/bin/bash"),
            ("zsh-homebrew", "Zsh (Homebrew)", "/usr/local/bin/zsh"),
            ("fish-homebrew", "Fish (Homebrew)", "/usr/local/bin/fish"),
        ];

        for (id, name, path) in homebrew_shells {
            let path = PathBuf::from(path);
            if path.exists() && !shells.iter().any(|s| s.path == path) {
                shells.push(ShellInfo::new(id, name, path));
            }
        }
    }

    shells
}

/// Get the default shell for the current platform.
pub fn default_shell() -> Option<ShellInfo> {
    detect_available_shells().into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_shells() {
        let shells = detect_available_shells();
        // Should find at least one shell on any system
        assert!(!shells.is_empty(), "Should detect at least one shell");

        for shell in &shells {
            assert!(!shell.id.is_empty());
            assert!(!shell.name.is_empty());
            assert!(shell.path.exists(), "Shell path should exist: {:?}", shell.path);
        }
    }
}
