//! Settings persistence to disk.

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::views::settings::Settings;

/// Serializable settings format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedSettings {
    pub api_url: String,
    pub ws_url: String,
    pub dark_mode: bool,
    pub notifications_enabled: bool,
    pub auto_refresh: bool,
    pub refresh_interval_secs: u32,
}

impl From<&Settings> for PersistedSettings {
    fn from(s: &Settings) -> Self {
        Self {
            api_url: s.api_url.clone(),
            ws_url: s.ws_url.clone(),
            dark_mode: s.dark_mode,
            notifications_enabled: s.notifications_enabled,
            auto_refresh: s.auto_refresh,
            refresh_interval_secs: s.refresh_interval_secs,
        }
    }
}

impl From<PersistedSettings> for Settings {
    fn from(p: PersistedSettings) -> Self {
        Self {
            api_url: p.api_url,
            ws_url: p.ws_url,
            dark_mode: p.dark_mode,
            notifications_enabled: p.notifications_enabled,
            auto_refresh: p.auto_refresh,
            refresh_interval_secs: p.refresh_interval_secs,
        }
    }
}

/// Get the settings file path.
fn settings_path() -> Option<PathBuf> {
    ProjectDirs::from("com", "netwatch", "NetWatch").map(|dirs| {
        dirs.config_dir().join("settings.toml")
    })
}

/// Load settings from disk.
pub fn load_settings() -> Option<Settings> {
    let path = settings_path()?;

    if !path.exists() {
        tracing::debug!("Settings file not found at {:?}", path);
        return None;
    }

    match fs::read_to_string(&path) {
        Ok(content) => match toml::from_str::<PersistedSettings>(&content) {
            Ok(persisted) => {
                tracing::info!("Loaded settings from {:?}", path);
                Some(persisted.into())
            }
            Err(e) => {
                tracing::error!("Failed to parse settings: {}", e);
                None
            }
        },
        Err(e) => {
            tracing::error!("Failed to read settings file: {}", e);
            None
        }
    }
}

/// Save settings to disk.
pub fn save_settings(settings: &Settings) -> Result<(), String> {
    let path = settings_path()
        .ok_or_else(|| "Could not determine settings path".to_string())?;

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {}", e))?;
    }

    let persisted = PersistedSettings::from(settings);
    let content = toml::to_string_pretty(&persisted)
        .map_err(|e| format!("Failed to serialize settings: {}", e))?;

    fs::write(&path, content)
        .map_err(|e| format!("Failed to write settings file: {}", e))?;

    tracing::info!("Saved settings to {:?}", path);
    Ok(())
}

/// Get the config directory path (for display to user).
pub fn config_dir() -> Option<PathBuf> {
    ProjectDirs::from("com", "netwatch", "NetWatch").map(|dirs| {
        dirs.config_dir().to_path_buf()
    })
}
