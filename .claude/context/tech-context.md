---
created: 2026-01-31T07:05:47Z
last_updated: 2026-02-02T17:49:58Z
version: 1.3
author: Claude Code PM System
---

# Technology Context

## Language Versions

| Language | Version | Notes |
|----------|---------|-------|
| Python | 3.11+ | Required for modern typing features |
| Rust | 2021 Edition | Stable toolchain |
| TypeScript | ~5.8 | Strict mode enabled |
| Node.js | 18+ | For frontend build tooling |

## Python Dependencies

### Core Runtime
| Package | Version | Purpose |
|---------|---------|---------|
| fastapi | >=0.115 | REST API framework |
| uvicorn | >=0.32 | ASGI server |
| sqlalchemy | >=2.0 | ORM with async support |
| aiosqlite | >=0.20 | Async SQLite driver |
| pydantic | >=2.0 | Data validation |
| pydantic-settings | >=2.0 | Settings management |
| apscheduler | >=3.10 | Job scheduling |
| websockets | >=13.0 | WebSocket support |
| httpx | >=0.27 | Async HTTP client |
| structlog | >=24.0 | Structured logging |

### Optional
| Package | Version | Purpose |
|---------|---------|---------|
| asyncpg | >=0.30 | PostgreSQL async driver |
| maturin | >=1.7 | Rust-Python binding build |

### Development
| Package | Version | Purpose |
|---------|---------|---------|
| pytest | >=8.0 | Test framework |
| pytest-asyncio | >=0.24 | Async test support |
| pytest-cov | >=6.0 | Coverage reporting |
| ruff | >=0.8 | Linting and formatting |
| mypy | >=1.13 | Static type checking |

## Rust Dependencies

### Workspace-Wide
| Crate | Version | Purpose |
|-------|---------|---------|
| tokio | 1 (full) | Async runtime |
| serde | 1 | Serialization |
| serde_json | 1 | JSON handling |
| sqlx | 0.8 | Database (SQLite) |
| chrono | 0.4 | Date/time handling |
| uuid | 1 | UUID generation |
| thiserror | 2 | Error handling |
| anyhow | 1 | Error context |
| tracing | 0.1 | Structured logging |
| pyo3 | 0.22 | Python bindings |
| quick-xml | 0.36 | XML parsing (nmap output) |

### Desktop Application (netsec-gui)
| Crate | Version | Purpose |
|-------|---------|---------|
| iced | 0.13 | Native GUI framework (Elm architecture) |
| reqwest | 0.12 | Async HTTP client |
| tokio-tungstenite | 0.24 | WebSocket client |
| futures-util | 0.3 | Async utilities |
| notify-rust | 4 | Native OS notifications |
| directories | 5 | Cross-platform config paths |
| toml | 0.8 | Settings file format |
| global-hotkey | 0.6 | System-wide keyboard shortcuts |
| vt100 | 0.15 | Terminal emulation |
| wry | 0.46 | Cross-platform webview for React widgets |
| raw-window-handle | 0.6 | Window handle abstraction for wry |
| rand | 0.8 | Random number generation (layout) |

## Frontend Dependencies

### Runtime
| Package | Version | Purpose |
|---------|---------|---------|
| react | ^19.2 | UI framework |
| react-dom | ^19.2 | DOM rendering |
| lucide-react | ^0.563 | Icon library |
| recharts | 2.12 | Charting library |
| @xterm/xterm | ^6.0.0 | Terminal emulator |
| @xterm/addon-fit | ^0.11.0 | Terminal resize support |
| @xterm/addon-web-links | ^0.12.0 | Clickable links in terminal |

### Development
| Package | Version | Purpose |
|---------|---------|---------|
| vite | ^6.2 | Build tool |
| @vitejs/plugin-react | ^5.0 | React plugin for Vite |
| typescript | ~5.8 | Type checking |

## Build Tools

| Tool | Purpose |
|------|---------|
| maturin | Build Python extension from Rust |
| cargo | Rust build system |
| just | Task runner (justfile) |
| vite | Frontend bundler |
| alembic | Database migrations |

## Runtime Requirements

### Required External Tools
The platform wraps these security tools via adapters:
- **nmap** - Network scanning
- **tshark** - Packet capture
- **clamav** - Malware scanning
- **suricata** - IDS/IPS
- **openvas** - Vulnerability scanning
- **fail2ban** - Intrusion prevention
- **zeek** - Network analysis
- **ntopng** - Traffic monitoring
- **ossec** - HIDS
- **pialert** - Network presence monitoring

### Database
- **SQLite** (default) - Local development
- **PostgreSQL** (optional) - Production deployment

## Configuration

Configuration is managed via TOML files in `config/`:
- `config/default.toml` - Default settings
- Environment variables override config values
- Settings loaded via `pydantic-settings`

### Key Config Sections
- `database.url` - Database connection string
- `auth.enabled` - API key authentication toggle
- `auth.api_keys` - List of valid API keys
- `scheduler.enabled` - Job scheduler toggle
- `logging.level` - Log verbosity
