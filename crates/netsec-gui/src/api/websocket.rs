//! WebSocket client for real-time event streaming.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use futures_util::{SinkExt, StreamExt};
use iced::Subscription;
use serde::Deserialize;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};

/// Event types matching Python backend EventType enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WsEventType {
    // Scan events
    #[serde(rename = "scan.started")]
    ScanStarted,
    #[serde(rename = "scan.progress")]
    ScanProgress,
    #[serde(rename = "scan.completed")]
    ScanCompleted,
    #[serde(rename = "scan.failed")]
    ScanFailed,
    // Device events
    #[serde(rename = "device.discovered")]
    DeviceDiscovered,
    #[serde(rename = "device.updated")]
    DeviceUpdated,
    #[serde(rename = "device.offline")]
    DeviceOffline,
    // Alert events
    #[serde(rename = "alert.created")]
    AlertCreated,
    #[serde(rename = "alert.updated")]
    AlertUpdated,
    #[serde(rename = "alert.resolved")]
    AlertResolved,
    // Tool events
    #[serde(rename = "tool.online")]
    ToolOnline,
    #[serde(rename = "tool.offline")]
    ToolOffline,
    // System events
    #[serde(rename = "system.startup")]
    SystemStartup,
    #[serde(rename = "system.shutdown")]
    SystemShutdown,
}

impl WsEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            WsEventType::ScanStarted => "scan.started",
            WsEventType::ScanProgress => "scan.progress",
            WsEventType::ScanCompleted => "scan.completed",
            WsEventType::ScanFailed => "scan.failed",
            WsEventType::DeviceDiscovered => "device.discovered",
            WsEventType::DeviceUpdated => "device.updated",
            WsEventType::DeviceOffline => "device.offline",
            WsEventType::AlertCreated => "alert.created",
            WsEventType::AlertUpdated => "alert.updated",
            WsEventType::AlertResolved => "alert.resolved",
            WsEventType::ToolOnline => "tool.online",
            WsEventType::ToolOffline => "tool.offline",
            WsEventType::SystemStartup => "system.startup",
            WsEventType::SystemShutdown => "system.shutdown",
        }
    }
}

/// WebSocket event from the backend.
#[derive(Debug, Clone, Deserialize)]
pub struct WsEvent {
    #[serde(rename = "type")]
    pub event_type: WsEventType,
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub data: HashMap<String, serde_json::Value>,
}

impl WsEvent {
    /// Get a string value from the event data.
    pub fn get_string(&self, key: &str) -> Option<String> {
        self.data.get(key)?.as_str().map(String::from)
    }

    /// Get an integer value from the event data.
    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.data.get(key)?.as_i64()
    }

    /// Get a float value from the event data.
    pub fn get_f64(&self, key: &str) -> Option<f64> {
        self.data.get(key)?.as_f64()
    }
}

/// WebSocket connection state.
#[derive(Debug, Clone)]
pub enum WsState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting(u32), // reconnect attempt number
    Error(String),
}

/// Messages from the WebSocket connection.
#[derive(Debug, Clone)]
pub enum WsMessage2 {
    /// Connection state changed.
    StateChanged(WsState),
    /// Received an event from the backend.
    Event(WsEvent),
    /// Failed to parse a message.
    ParseError(String),
}

/// Configuration for WebSocket connection.
#[derive(Debug, Clone)]
pub struct WsConfig {
    pub url: String,
    pub reconnect_delay_ms: u64,
    pub max_reconnect_attempts: u32,
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            url: "ws://127.0.0.1:8420/ws".to_string(),
            reconnect_delay_ms: 2000,
            max_reconnect_attempts: 10,
        }
    }
}

/// Create a subscription for WebSocket events.
///
/// This returns an iced Subscription that:
/// 1. Connects to the WebSocket endpoint
/// 2. Streams events as they arrive
/// 3. Automatically reconnects on disconnect
pub fn connect(config: WsConfig) -> Subscription<WsMessage2> {
    struct WsConnection;

    Subscription::run_with_id(
        std::any::TypeId::of::<WsConnection>(),
        ws_stream(config),
    )
}

fn ws_stream(config: WsConfig) -> impl futures_util::Stream<Item = WsMessage2> {
    iced::stream::channel(100, move |mut output| {
        let config = config.clone();
        async move {
            let mut reconnect_attempts = 0u32;

            loop {
                // Report connecting state
                let _ = output.send(WsMessage2::StateChanged(
                    if reconnect_attempts > 0 {
                        WsState::Reconnecting(reconnect_attempts)
                    } else {
                        WsState::Connecting
                    }
                )).await;

                // Try to connect (pass URL as string - tokio-tungstenite accepts &str)
                match connect_async(&config.url).await {
                    Ok((ws_stream, _)) => {
                        reconnect_attempts = 0;
                        let _ = output.send(WsMessage2::StateChanged(WsState::Connected)).await;

                        let (mut write, mut read) = ws_stream.split();

                        // Read messages until disconnected
                        while let Some(msg_result) = read.next().await {
                            match msg_result {
                                Ok(WsMessage::Text(text)) => {
                                    match serde_json::from_str::<WsEvent>(&text) {
                                        Ok(event) => {
                                            let _ = output.send(WsMessage2::Event(event)).await;
                                        }
                                        Err(e) => {
                                            let _ = output.send(WsMessage2::ParseError(
                                                format!("Failed to parse event: {}", e)
                                            )).await;
                                        }
                                    }
                                }
                                Ok(WsMessage::Ping(data)) => {
                                    // Respond to ping with pong
                                    let _ = write.send(WsMessage::Pong(data)).await;
                                }
                                Ok(WsMessage::Close(_)) => {
                                    tracing::info!("WebSocket closed by server");
                                    break;
                                }
                                Ok(_) => {
                                    // Ignore other message types
                                }
                                Err(e) => {
                                    tracing::warn!("WebSocket error: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("WebSocket connection failed: {}", e);
                    }
                }

                // Connection lost - report and maybe reconnect
                let _ = output.send(WsMessage2::StateChanged(WsState::Disconnected)).await;

                reconnect_attempts += 1;
                if reconnect_attempts > config.max_reconnect_attempts {
                    let _ = output.send(WsMessage2::StateChanged(
                        WsState::Error("Max reconnect attempts exceeded".to_string())
                    )).await;
                    return;
                }

                // Wait before reconnecting
                tokio::time::sleep(std::time::Duration::from_millis(
                    config.reconnect_delay_ms * reconnect_attempts as u64
                )).await;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_as_str() {
        assert_eq!(WsEventType::ScanStarted.as_str(), "scan.started");
        assert_eq!(WsEventType::DeviceDiscovered.as_str(), "device.discovered");
        assert_eq!(WsEventType::AlertCreated.as_str(), "alert.created");
    }

    #[test]
    fn test_ws_config_default() {
        let config = WsConfig::default();
        assert_eq!(config.url, "ws://127.0.0.1:8420/ws");
        assert_eq!(config.reconnect_delay_ms, 2000);
        assert_eq!(config.max_reconnect_attempts, 10);
    }

    #[test]
    fn test_event_deserialize() {
        let json = r#"{
            "type": "scan.started",
            "id": "abc123",
            "timestamp": "2024-01-15T10:30:00Z",
            "source": "scanner",
            "data": {
                "scan_id": "scan-1",
                "target": "192.168.1.0/24"
            }
        }"#;

        let event: WsEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.event_type, WsEventType::ScanStarted);
        assert_eq!(event.id, "abc123");
        assert_eq!(event.source, "scanner");
        assert_eq!(event.get_string("scan_id"), Some("scan-1".to_string()));
        assert_eq!(event.get_string("target"), Some("192.168.1.0/24".to_string()));
    }
}
