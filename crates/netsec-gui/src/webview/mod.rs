//! Webview module for embedding React NetworkCanvas.
//!
//! This module provides a Wry-based webview that renders the React
//! NetworkCanvas component within the Iced desktop application.

mod ipc;
mod canvas_webview;

pub use ipc::*;

// Re-export canvas_webview types but allow them to be unused during development
#[allow(unused_imports)]
pub use canvas_webview::{CanvasWebview, WebviewError, assets_dir};
