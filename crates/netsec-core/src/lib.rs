//! Facade crate: NetsecEngine wiring all sub-crates together,
//! plus the unified plugin registry and configuration loading.
//!
//! Stub — full implementation in Phase 5.

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
