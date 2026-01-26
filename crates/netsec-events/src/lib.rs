//! Event bus built on tokio::broadcast for inter-component communication.
//!
//! Supports typed events, filtered subscriptions, and async consumption.

use netsec_models::event::{EventType, NetsecEvent};
use std::collections::HashSet;
use tokio::sync::broadcast;

/// Default capacity of the broadcast channel.
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

    /// Create a new event bus with a custom channel capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Publish an event to all subscribers.
    pub fn publish(
        &self,
        event: NetsecEvent,
    ) -> Result<usize, broadcast::error::SendError<NetsecEvent>> {
        self.sender.send(event)
    }

    /// Subscribe to all events.
    pub fn subscribe(&self) -> broadcast::Receiver<NetsecEvent> {
        self.sender.subscribe()
    }

    /// Subscribe to only specific event types.
    pub fn subscribe_filtered(&self, types: Vec<EventType>) -> FilteredSubscriber {
        FilteredSubscriber {
            receiver: self.sender.subscribe(),
            filter: types.into_iter().collect(),
        }
    }

    /// Return the number of active subscribers (receivers) on the channel.
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// A subscriber that only yields events matching a set of [`EventType`]s.
pub struct FilteredSubscriber {
    receiver: broadcast::Receiver<NetsecEvent>,
    filter: HashSet<EventType>,
}

impl FilteredSubscriber {
    /// Receive the next event that matches the filter.
    ///
    /// Events that do not match are silently skipped.
    pub async fn recv(&mut self) -> Result<NetsecEvent, broadcast::error::RecvError> {
        loop {
            let event = self.receiver.recv().await?;
            if self.filter.contains(&event.event_type) {
                return Ok(event);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netsec_models::event::{EventType, NetsecEvent};

    #[tokio::test]
    async fn test_publish_receive_roundtrip() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        let event = NetsecEvent::new(
            EventType::AlertCreated,
            serde_json::json!({"alert_id": "a1"}),
        );
        bus.publish(event.clone()).unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.event_type, EventType::AlertCreated);
        assert_eq!(received.id, event.id);
    }

    #[tokio::test]
    async fn test_filtered_subscriber_receives_matching() {
        let bus = EventBus::new();
        let mut filtered = bus.subscribe_filtered(vec![EventType::AlertCreated]);

        // Publish a matching event
        let event = NetsecEvent::new(
            EventType::AlertCreated,
            serde_json::json!({"id": "match"}),
        );
        bus.publish(event.clone()).unwrap();

        let received = filtered.recv().await.unwrap();
        assert_eq!(received.event_type, EventType::AlertCreated);
    }

    #[tokio::test]
    async fn test_filtered_subscriber_skips_non_matching() {
        let bus = EventBus::new();
        let mut filtered = bus.subscribe_filtered(vec![EventType::AlertCreated]);

        // Publish non-matching then matching
        let _non_match = bus
            .publish(NetsecEvent::new(
                EventType::DeviceDiscovered,
                serde_json::json!({}),
            ))
            .unwrap();
        let match_event = NetsecEvent::new(
            EventType::AlertCreated,
            serde_json::json!({"id": "target"}),
        );
        bus.publish(match_event.clone()).unwrap();

        let received = filtered.recv().await.unwrap();
        assert_eq!(received.event_type, EventType::AlertCreated);
        assert_eq!(received.id, match_event.id);
    }

    #[test]
    fn test_subscriber_count() {
        let bus = EventBus::new();
        assert_eq!(bus.subscriber_count(), 0);

        let _rx1 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 1);

        let _rx2 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);

        drop(_rx1);
        assert_eq!(bus.subscriber_count(), 1);
    }

    #[tokio::test]
    async fn test_custom_capacity() {
        let bus = EventBus::with_capacity(2);
        let mut rx = bus.subscribe();

        bus.publish(NetsecEvent::new(
            EventType::ScanStarted,
            serde_json::json!({}),
        ))
        .unwrap();
        bus.publish(NetsecEvent::new(
            EventType::ScanCompleted,
            serde_json::json!({}),
        ))
        .unwrap();

        let e1 = rx.recv().await.unwrap();
        assert_eq!(e1.event_type, EventType::ScanStarted);
        let e2 = rx.recv().await.unwrap();
        assert_eq!(e2.event_type, EventType::ScanCompleted);
    }
}
