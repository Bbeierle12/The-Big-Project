//! Event bus built on tokio::broadcast for inter-component communication.
//!
//! Supports typed events, wildcard subscriptions, and async consumption.
//!
//! Stub — full implementation in Phase 2.

use netsec_models::event::NetsecEvent;
use tokio::sync::broadcast;

/// Capacity of the broadcast channel.
const DEFAULT_CAPACITY: usize = 1024;

/// The central event bus for the netsec platform.
#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<NetsecEvent>,
}

impl EventBus {
    /// Create a new event bus with default capacity.
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(DEFAULT_CAPACITY);
        Self { sender }
    }

    /// Publish an event to all subscribers.
    pub fn publish(&self, event: NetsecEvent) -> Result<usize, broadcast::error::SendError<NetsecEvent>> {
        self.sender.send(event)
    }

    /// Subscribe to all events.
    pub fn subscribe(&self) -> broadcast::Receiver<NetsecEvent> {
        self.sender.subscribe()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}
