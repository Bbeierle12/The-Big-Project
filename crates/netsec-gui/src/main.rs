//! NetWatch Desktop Application
//!
//! A native Rust GUI for network security monitoring.

mod api;
mod app;
mod desktop;
mod message;
mod state;
mod theme;
mod views;
mod webview;

use iced::Size;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

fn main() -> iced::Result {
    // Initialize logging
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env().add_directive("netsec_gui=debug".parse().unwrap()))
        .init();

    tracing::info!("Starting NetWatch Desktop Application");

    // Run the application using iced 0.13 functional API
    iced::application("NetWatch - Network Security Monitor", app::NetWatch::update, app::NetWatch::view)
        .subscription(app::NetWatch::subscription)
        .theme(app::NetWatch::theme)
        .window_size(Size::new(1400.0, 900.0))
        .antialiasing(true)
        .run_with(app::NetWatch::new)
}
