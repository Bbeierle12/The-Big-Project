---
created: 2026-01-31T07:05:47Z
last_updated: 2026-01-31T07:05:47Z
version: 1.0
author: Claude Code PM System
---

# System Patterns

## Architectural Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Frontend (React/TS)                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ NetworkCanvas│  │   Terminal   │  │  Dashboard   │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│           │               │               │                     │
│           └───────────────┴───────────────┘                     │
│                          │                                      │
│                   NetWatchApi (REST + WS)                       │
└─────────────────────────────┬───────────────────────────────────┘
                              │ HTTP/WebSocket
┌─────────────────────────────┴───────────────────────────────────┐
│                     FastAPI Backend                             │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐            │
│  │ Routers │──│Services │──│ EventBus│──│Scheduler│            │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘            │
│       │            │                          │                 │
│  ┌─────────┐  ┌─────────┐                ┌─────────┐           │
│  │ Schemas │  │ Models  │────────────────│Adapters │           │
│  └─────────┘  └─────────┘                └─────────┘           │
│                    │                          │                 │
│              ┌─────────┐              ┌───────────────┐        │
│              │ SQLite  │              │ External Tools│        │
│              └─────────┘              │ nmap,tshark.. │        │
│                                       └───────────────┘        │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────┴───────────────────────────────────┐
│                     Rust Core (netsec-core)                     │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐            │
│  │ Engine  │  │ Parsers │  │ Scanner │  │ Pipeline│            │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

## Design Patterns

### 1. Adapter Pattern (Tool Integration)

All external tools are wrapped in adapters that implement `BaseAdapter`:

```python
class BaseAdapter(ABC):
    @abstractmethod
    def tool_info(self) -> ToolInfo: ...

    @abstractmethod
    async def health_check(self) -> ToolStatus: ...

    @abstractmethod
    async def execute(self, task: str, params: dict) -> dict: ...
```

Benefits:
- Consistent interface for all tools
- Easy to add new tools
- Tools can be mocked for testing

### 2. Event-Driven Architecture

Components communicate via the `EventBus`:

```python
# Publishing
await event_bus.publish(Event(
    type=EventType.DEVICE_DISCOVERED,
    source="device_service",
    data={"device_id": "...", "ip": "..."}
))

# Subscribing
@event_bus.subscribe(EventType.DEVICE_DISCOVERED)
async def handle_device(event: Event):
    # Process event
```

Event types defined in `EventType` enum:
- `scan.*` - Scan lifecycle events
- `device.*` - Device state changes
- `alert.*` - Alert pipeline events
- `tool.*` - Tool availability changes
- `system.*` - System lifecycle events

### 3. Pipeline Pattern (Alert Processing)

Alerts flow through a multi-stage pipeline:

```
Raw Alert → Normalize → Deduplicate → Correlate → Classify → Dispatch
                ↓           ↓           ↓           ↓
            AlertNormalizer  AlertDedup  Correlator  Classifier
```

Each stage is a separate class with single responsibility.

### 4. Repository Pattern (Data Access)

Services encapsulate data access:

```python
class DeviceService:
    def __init__(self, session: AsyncSession, event_bus: EventBus):
        self.session = session
        self.event_bus = event_bus

    async def get_device(self, device_id: str) -> Device | None: ...
    async def upsert_from_scan(self, host_data: dict) -> Device: ...
```

### 5. Registry Pattern (Tool Discovery)

Tools are discovered and registered at startup:

```python
class AdapterRegistry:
    async def discover(self): ...  # Find all adapter classes
    async def init_all(self): ...  # Initialize adapters
    def get(self, name: str) -> BaseAdapter | None: ...
    def list_tools(self) -> list[ToolInfo]: ...
```

### 6. Plugin Architecture (Rust Core)

Rust core supports runtime plugin registration:

```rust
pub trait Plugin: Send + Sync {
    fn info(&self) -> PluginInfo;
    fn start(&self, config: PluginConfig) -> Result<()>;
    fn stop(&self) -> Result<()>;
    fn health_check(&self) -> HealthStatus;
}

pub struct PluginRegistry {
    plugins: HashMap<String, Box<dyn Plugin>>,
}
```

## Data Flow Patterns

### Scan Execution Flow

```
1. POST /api/scans {scan_type, tool, target}
2. ScanService.create_scan()
   → Validates tool availability
   → Creates Scan record (pending)
   → Publishes scan.started event
3. Adapter.execute(task, params)
   → Runs external tool
   → Parses output
4. ScanService processes results
   → Updates Scan record (completed/failed)
   → Publishes scan.completed event
5. DeviceService.upsert_from_scan()
   → Creates/updates devices
   → Publishes device.discovered/updated events
```

### WebSocket Event Flow

```
1. Event published to EventBus
2. WS forwarder receives event
3. Event serialized to JSON
4. Broadcast to all connected WS clients
5. Frontend handles event by type
6. UI updates reactively
```

### Alert Processing Flow

```
1. Tool adapter detects issue
2. AlertService.process_raw_alert()
   → Normalize (extract common fields)
   → Deduplicate (fingerprint matching)
   → Correlate (group related alerts)
   → Classify (assign severity)
   → Dispatch (email, webhook, etc.)
3. Alert stored in database
4. alert.created event published
5. Frontend receives via WS
```

## Error Handling Patterns

### API Errors
- Use `HTTPException` with appropriate status codes
- Return `{detail: "error message"}` format
- 404 for not found, 400 for bad request, 503 for unavailable

### Service Errors
- Raise `ValueError` for validation errors
- Raise `RuntimeError` for availability issues
- Log exceptions with structured context

### Async Safety
- Use `async with` for database sessions
- Proper cleanup in lifespan context manager
- Background tasks don't block request handling
