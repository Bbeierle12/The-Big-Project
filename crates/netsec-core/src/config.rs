//! Layered TOML configuration loading via the `config` crate.
//!
//! Load order: `default.toml` (required) -> `local.toml` (optional) -> `NETSEC_` env vars.

use serde::Deserialize;
use std::path::Path;

/// Top-level configuration for the netsec platform.
#[derive(Debug, Clone, Deserialize)]
pub struct NetsecConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub logging: LoggingConfig,
    pub scheduler: SchedulerConfig,
    pub auth: AuthConfig,
    pub alerts: AlertsConfig,
    pub tools: ToolsConfig,
}

/// Server configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub reload: bool,
    pub workers: u32,
}

/// Database configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub echo: bool,
}

/// Logging configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
}

/// Scheduler configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct SchedulerConfig {
    pub enabled: bool,
    pub timezone: String,
}

/// Authentication configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    pub enabled: bool,
    pub api_key: String,
}

/// Alerts configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AlertsConfig {
    pub dedup_window_seconds: u64,
    pub max_alerts_per_minute: u64,
    pub dispatch: DispatchConfig,
}

/// Alert dispatch configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct DispatchConfig {
    pub webhook_url: String,
    pub email_enabled: bool,
    pub email_smtp_host: String,
    pub email_smtp_port: u16,
    pub email_from: String,
    pub email_to: String,
}

/// Tools configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolsConfig {
    pub scan_timeout: u64,
    pub max_concurrent_scans: u32,
}

/// Load configuration from TOML files and environment variables.
///
/// Load order:
/// 1. `{config_dir}/default.toml` (required)
/// 2. `{config_dir}/local.toml` (optional)
/// 3. Environment variables with prefix `NETSEC` and separator `__`
///
/// If `config_dir` is `None`, defaults to `"config"` relative to the current directory.
pub fn load_config(config_dir: Option<&Path>) -> Result<NetsecConfig, config::ConfigError> {
    let dir = config_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("config"));

    let default_path = dir.join("default.toml");
    let local_path = dir.join("local.toml");

    let builder = config::Config::builder()
        .add_source(config::File::from(default_path).required(true))
        .add_source(config::File::from(local_path).required(false))
        .add_source(
            config::Environment::with_prefix("NETSEC")
                .separator("__")
                .try_parsing(true),
        );

    let config = builder.build()?;
    config.try_deserialize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn config_dir() -> PathBuf {
        // Navigate from crate root to workspace root config/
        let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        dir.pop(); // crates/
        dir.pop(); // workspace root
        dir.join("config")
    }

    #[test]
    fn test_load_default_config() {
        let cfg = load_config(Some(&config_dir())).unwrap();
        assert!(!cfg.server.host.is_empty());
    }

    #[test]
    fn test_config_server_values() {
        let cfg = load_config(Some(&config_dir())).unwrap();
        assert_eq!(cfg.server.host, "127.0.0.1");
        assert_eq!(cfg.server.port, 8420);
        assert!(!cfg.server.reload);
        assert_eq!(cfg.server.workers, 1);
    }

    #[test]
    fn test_config_database_values() {
        let cfg = load_config(Some(&config_dir())).unwrap();
        assert!(cfg.database.url.contains("sqlite"));
        assert!(!cfg.database.echo);
    }

    #[test]
    fn test_config_scheduler_values() {
        let cfg = load_config(Some(&config_dir())).unwrap();
        assert!(cfg.scheduler.enabled);
        assert_eq!(cfg.scheduler.timezone, "UTC");
    }

    #[test]
    fn test_config_alerts_values() {
        let cfg = load_config(Some(&config_dir())).unwrap();
        assert_eq!(cfg.alerts.dedup_window_seconds, 300);
        assert_eq!(cfg.alerts.max_alerts_per_minute, 100);
    }

    #[test]
    fn test_config_tools_values() {
        let cfg = load_config(Some(&config_dir())).unwrap();
        assert_eq!(cfg.tools.scan_timeout, 300);
        assert_eq!(cfg.tools.max_concurrent_scans, 3);
    }

    #[test]
    fn test_load_config_missing_dir() {
        let result = load_config(Some(Path::new("/nonexistent/path/to/config")));
        assert!(result.is_err());
    }
}
