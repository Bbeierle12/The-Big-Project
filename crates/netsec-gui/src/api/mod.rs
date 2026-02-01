//! API client module for communicating with the NetSec backend.
//!
//! This module provides:
//! - HTTP client for REST API endpoints
//! - WebSocket client for real-time event streaming
//! - Typed request/response models matching the Python backend schemas

pub mod client;
pub mod models;
pub mod websocket;

pub use client::{ApiClient, ApiConfig};
pub use models::*;
pub use websocket::{WsConfig, WsEvent, WsEventType, WsState};
