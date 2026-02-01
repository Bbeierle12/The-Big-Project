---
created: 2026-01-31T07:05:47Z
last_updated: 2026-02-01T02:21:43Z
version: 1.1
author: Claude Code PM System
---

# Project Structure

## Root Directory Layout

```
The Big Project/
├── .claude/              # Claude Code configuration and context
├── config/               # Configuration files (default.toml, etc.)
├── crates/               # Rust workspace crates (11 crates)
├── deploy/               # Deployment configurations (Docker, etc.)
├── dotnet/               # .NET components (scaffolded)
├── frontend/             # React/TypeScript web UI (ArchAngel)
├── migrations/           # Database migrations (SQL)
├── python/               # Python package (netsec)
├── scripts/              # Utility scripts
├── tests/                # Test suites
├── Cargo.toml            # Rust workspace root
├── pyproject.toml        # Python project configuration
├── alembic.ini           # Database migration config
├── justfile              # Task runner commands
└── netsec.db             # SQLite database (runtime)
```

## Python Package Structure (`python/netsec/`)

```
netsec/
├── adapters/             # Tool adapters (nmap, clamav, suricata, etc.)
│   ├── base.py           # BaseAdapter abstract class
│   ├── registry.py       # AdapterRegistry for tool discovery
│   ├── nmap.py           # Nmap tool adapter
│   ├── tshark.py         # Wireshark/tshark adapter
│   └── ...               # Other tool adapters
├── api/                  # FastAPI application
│   ├── app.py            # Application factory
│   ├── middleware.py     # API key authentication
│   ├── websocket.py      # WebSocket event forwarding
│   └── routers/          # API endpoints
│       ├── alerts.py     # /api/alerts
│       ├── devices.py    # /api/devices
│       ├── scans.py      # /api/scans
│       ├── tools.py      # /api/tools
│       ├── scheduler.py  # /api/scheduler
│       ├── system.py     # /api/system
│       └── ws.py         # /ws WebSocket endpoint
├── core/                 # Core infrastructure
│   ├── config.py         # Settings management
│   ├── events.py         # EventBus and EventType
│   ├── logging.py        # Structured logging
│   └── scheduler.py      # APScheduler integration
├── db/                   # Database layer
│   └── session.py        # Async SQLAlchemy session management
├── models/               # SQLAlchemy ORM models
│   ├── base.py           # Base model class
│   ├── alert.py          # Alert model
│   ├── device.py         # Device and Port models
│   └── scan.py           # Scan model
├── schemas/              # Pydantic schemas (API DTOs)
│   ├── alert.py          # AlertOut, AlertUpdate
│   ├── device.py         # DeviceOut, DeviceUpdate
│   └── scan.py           # ScanCreate, ScanOut
├── services/             # Business logic
│   ├── alert_service.py  # Alert pipeline orchestration
│   ├── device_service.py # Device management
│   ├── scan_service.py   # Scan orchestration
│   └── monitoring_service.py # Health monitoring
├── pipeline/             # Alert processing pipeline
│   ├── normalization.py  # Raw alert normalization
│   ├── deduplication.py  # Fingerprint-based dedup
│   ├── correlation.py    # Alert correlation
│   ├── severity.py       # Severity classification
│   └── dispatch.py       # Alert dispatch (email, etc.)
└── platform/             # Platform-specific utilities
```

## Rust Crates Structure (`crates/`)

```
crates/
├── netsec-core/          # Main facade (NetsecEngine, PluginRegistry)
├── netsec-db/            # Database operations (SQLx)
├── netsec-events/        # Event types and bus
├── netsec-models/        # Shared domain models
├── netsec-parsers/       # Tool output parsers (nmap XML, etc.)
├── netsec-pipeline/      # Rust alert pipeline
├── netsec-platform/      # Platform detection and tool resolution
├── netsec-scanner/       # Active/passive scanning
├── netsec-scheduler/     # Cron job scheduling
├── netsec-threat/        # Threat intelligence
├── netsec-python/        # PyO3 bindings for Python
├── netsec-ffi/           # C FFI for .NET/other consumers
├── netsec-pty/           # PTY/terminal emulation (NEW)
└── netsec-gui/           # Iced desktop application (NEW)
```

## Desktop Application Structure (`crates/netsec-gui/`)

```
netsec-gui/
├── src/
│   ├── main.rs           # Application entry point
│   ├── app.rs            # Main application state and logic (1850+ lines)
│   ├── message.rs        # Elm-style message types
│   ├── theme.rs          # Color palette and styling
│   ├── api/              # Backend API client
│   │   ├── mod.rs
│   │   ├── client.rs     # REST API client (reqwest)
│   │   ├── models.rs     # API data models
│   │   └── websocket.rs  # WebSocket client (tokio-tungstenite)
│   ├── desktop/          # Desktop integration
│   │   ├── mod.rs
│   │   ├── hotkeys.rs    # Global hotkey support
│   │   ├── notifications.rs # Native OS notifications
│   │   └── persistence.rs # Settings save/load (TOML)
│   ├── state/            # Application state
│   │   ├── mod.rs
│   │   ├── network.rs    # Network canvas state
│   │   └── terminal.rs   # Terminal emulation state
│   └── views/            # UI views (Iced widgets)
│       ├── mod.rs
│       ├── alerts.rs     # Alerts dashboard
│       ├── canvas.rs     # Network topology canvas
│       ├── header.rs     # Application header bar
│       ├── inspector.rs  # Device detail panel
│       ├── scans.rs      # Scans dashboard
│       ├── scheduler.rs  # Scheduled jobs view
│       ├── settings.rs   # Settings panel
│       ├── terminal.rs   # Embedded terminal view
│       ├── toolbar.rs    # Left toolbar
│       ├── tools.rs      # Tools dashboard
│       ├── traffic.rs    # Traffic flows view
│       ├── ui_components.rs # Toasts, dialogs, badges
│       └── vuln_dashboard.rs # Vulnerability dashboard
└── Cargo.toml
```

## PTY Library Structure (`crates/netsec-pty/`)

```
netsec-pty/
├── src/
│   ├── lib.rs            # Library exports
│   ├── session.rs        # PTY session management
│   └── shell.rs          # Shell detection and launching
└── Cargo.toml
```

## Frontend Structure (`frontend/`)

```
frontend/
├── components/           # React components
│   ├── Header.tsx        # App header
│   ├── NetworkCanvas.tsx # Main canvas for network visualization
│   ├── NetworkNode.tsx   # Individual node rendering
│   ├── Terminal.tsx      # Command terminal UI
│   ├── Toolbar.tsx       # Tool buttons
│   └── VulnerabilityDashboard.tsx
├── hooks/                # React hooks
│   ├── useNetwork.ts     # Network state and WS handling
│   ├── useScanner.ts     # Scan operations
│   ├── usePentest.ts     # Tool execution
│   └── useInteraction.ts # Canvas interactions
├── services/             # API client
│   └── api.ts            # NetWatchApi class
├── utils/                # Utilities
│   └── networkUtils.ts   # OUI lookup, IP generation
├── types.ts              # TypeScript type definitions
├── App.tsx               # Main application component
└── index.tsx             # Entry point
```

## Key File Naming Conventions

- **Python**: `snake_case.py` for modules
- **Rust**: `snake_case.rs` for modules
- **TypeScript/React**: `PascalCase.tsx` for components, `camelCase.ts` for utilities/hooks
- **Adapters**: Named after the tool they wrap (e.g., `nmap.py`, `suricata.py`)
- **Routers**: Named after the resource (e.g., `alerts.py`, `devices.py`)
