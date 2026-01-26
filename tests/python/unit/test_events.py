"""Test async EventBus."""
import asyncio
import pytest
from netsec.core.events import Event, EventBus, EventType


@pytest.mark.asyncio
async def test_event_publish_subscribe():
    """Events should be delivered to subscribers."""
    bus = EventBus()
    received = []

    async def handler(event: Event):
        received.append(event)

    bus.subscribe(EventType.SCAN_COMPLETED, handler)
    await bus.start()

    event = Event(type=EventType.SCAN_COMPLETED, data={"scan_id": "abc"})
    await bus.publish(event)
    await asyncio.sleep(0.1)  # Let event process

    await bus.stop()
    assert len(received) == 1
    assert received[0].data["scan_id"] == "abc"


@pytest.mark.asyncio
async def test_wildcard_subscriber():
    """Wildcard subscribers should receive all events."""
    bus = EventBus()
    received = []

    async def handler(event: Event):
        received.append(event)

    bus.subscribe_all(handler)
    await bus.start()

    await bus.publish(Event(type=EventType.SCAN_STARTED))
    await bus.publish(Event(type=EventType.DEVICE_DISCOVERED))
    await asyncio.sleep(0.1)

    await bus.stop()
    assert len(received) == 2
