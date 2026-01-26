//! Facade crate: NetsecEngine wiring all sub-crates together,
//! plus the unified plugin registry and configuration loading.

pub use netsec_models as models;
pub use netsec_db as db;
pub use netsec_events as events;
pub use netsec_parsers as parsers;
pub use netsec_pipeline as pipeline;
pub use netsec_scanner as scanner;
pub use netsec_scheduler as scheduler;
pub use netsec_platform as platform;
pub use netsec_threat as threat;

pub mod engine;
pub mod config;
pub mod plugin_registry;

// Re-export key types for convenience.
pub use engine::{EngineError, EngineResult, NetsecEngine};
pub use plugin_registry::{Plugin, PluginInfo, PluginKey, PluginRegistry};
pub use config::{load_config, NetsecConfig};
