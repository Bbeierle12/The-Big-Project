//! Shared types, enums, and error definitions for the netsec platform.
//!
//! This crate contains no I/O — only pure data structures used by all other crates.
//!
//! Enable the `sqlx` feature to derive `sqlx::FromRow` on row types.

pub mod alert;
pub mod device;
pub mod error;
pub mod event;
pub mod plugin;
pub mod port;
pub mod scan;
pub mod traffic;
pub mod vulnerability;
