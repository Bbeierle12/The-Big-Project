//! Shared types, enums, and error definitions for the netsec platform.
//!
//! This crate contains no I/O — only pure data structures used by all other crates.

pub mod device;
pub mod alert;
pub mod scan;
pub mod vulnerability;
pub mod traffic;
pub mod event;
pub mod plugin;
pub mod error;
