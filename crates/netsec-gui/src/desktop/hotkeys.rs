//! Global hotkey support.
//!
//! Note: Global hotkeys must be managed on the main thread due to Windows API requirements.
//! The manager is passed back to the caller to keep it alive.

use global_hotkey::{
    hotkey::{Code, HotKey, Modifiers},
    GlobalHotKeyEvent, GlobalHotKeyManager,
};

/// Hotkey action identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HotkeyAction {
    /// Toggle window visibility (Ctrl+Shift+N)
    ToggleWindow,
    /// Quick scan (Ctrl+Shift+S)
    QuickScan,
    /// Refresh data (Ctrl+Shift+R)
    RefreshData,
    /// Open alerts (Ctrl+Shift+A)
    OpenAlerts,
}

/// Registered hotkey with its action.
pub struct RegisteredHotkey {
    pub hotkey: HotKey,
    pub action: HotkeyAction,
}

/// Hotkey manager wrapper that keeps the manager alive.
pub struct HotkeyManager {
    _manager: GlobalHotKeyManager,
    registered: Vec<RegisteredHotkey>,
}

impl HotkeyManager {
    /// Initialize the global hotkey manager and register default hotkeys.
    pub fn new() -> Result<Self, String> {
        let manager = GlobalHotKeyManager::new()
            .map_err(|e| format!("Failed to create hotkey manager: {}", e))?;

        let mut registered = Vec::new();

        // Define hotkeys
        let hotkeys = [
            (
                HotKey::new(Some(Modifiers::CONTROL | Modifiers::SHIFT), Code::KeyN),
                HotkeyAction::ToggleWindow,
            ),
            (
                HotKey::new(Some(Modifiers::CONTROL | Modifiers::SHIFT), Code::KeyS),
                HotkeyAction::QuickScan,
            ),
            (
                HotKey::new(Some(Modifiers::CONTROL | Modifiers::SHIFT), Code::KeyR),
                HotkeyAction::RefreshData,
            ),
            (
                HotKey::new(Some(Modifiers::CONTROL | Modifiers::SHIFT), Code::KeyA),
                HotkeyAction::OpenAlerts,
            ),
        ];

        for (hotkey, action) in hotkeys {
            match manager.register(hotkey) {
                Ok(()) => {
                    tracing::info!("Registered hotkey: {:?} -> {:?}", hotkey, action);
                    registered.push(RegisteredHotkey { hotkey, action });
                }
                Err(e) => {
                    tracing::warn!("Failed to register hotkey {:?}: {}", action, e);
                }
            }
        }

        Ok(Self {
            _manager: manager,
            registered,
        })
    }

    /// Get the registered hotkeys.
    pub fn registered(&self) -> &[RegisteredHotkey] {
        &self.registered
    }
}

/// Check for hotkey events (non-blocking).
pub fn poll_hotkey_event() -> Option<HotkeyAction> {
    if let Ok(event) = GlobalHotKeyEvent::receiver().try_recv() {
        // Map hotkey ID to action
        match event.id {
            id if id == HotKey::new(Some(Modifiers::CONTROL | Modifiers::SHIFT), Code::KeyN).id() => {
                Some(HotkeyAction::ToggleWindow)
            }
            id if id == HotKey::new(Some(Modifiers::CONTROL | Modifiers::SHIFT), Code::KeyS).id() => {
                Some(HotkeyAction::QuickScan)
            }
            id if id == HotKey::new(Some(Modifiers::CONTROL | Modifiers::SHIFT), Code::KeyR).id() => {
                Some(HotkeyAction::RefreshData)
            }
            id if id == HotKey::new(Some(Modifiers::CONTROL | Modifiers::SHIFT), Code::KeyA).id() => {
                Some(HotkeyAction::OpenAlerts)
            }
            _ => None,
        }
    } else {
        None
    }
}

/// Get a human-readable description of the hotkeys.
pub fn hotkey_descriptions() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Ctrl+Shift+N", "Toggle window visibility"),
        ("Ctrl+Shift+S", "Quick network scan"),
        ("Ctrl+Shift+R", "Refresh all data"),
        ("Ctrl+Shift+A", "Open alerts dashboard"),
    ]
}
