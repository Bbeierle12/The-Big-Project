---
created: 2026-01-31T07:05:47Z
last_updated: 2026-01-31T07:05:47Z
version: 1.0
author: Claude Code PM System
---

# Project Overview

## What is NetSec Orchestrator?

NetSec Orchestrator is a unified network security platform that integrates multiple security tools under a single orchestration layer. It combines:

- **Python FastAPI backend** for REST API and tool orchestration
- **Rust core** for performance-critical operations
- **React frontend** (ArchAngel) for visual network monitoring
- **SQLite/PostgreSQL** for data persistence

## Feature Summary

### REST API Endpoints

| Endpoint | Methods | Purpose |
|----------|---------|---------|
| `/api/system/health` | GET | Health check (public) |
| `/api/system/info` | GET | System information |
| `/api/devices` | GET, POST | Device listing |
| `/api/devices/{id}` | GET, PATCH, DELETE | Device management |
| `/api/scans` | GET, POST | Scan listing and creation |
| `/api/scans/{id}` | GET | Scan details |
| `/api/scans/{id}/cancel` | POST | Cancel running scan |
| `/api/alerts` | GET | Alert listing with filters |
| `/api/alerts/stats` | GET | Alert statistics |
| `/api/alerts/{id}` | GET, PATCH | Alert management |
| `/api/tools` | GET | List available tools |
| `/api/tools/health` | GET | Health check all tools |
| `/api/tools/{name}` | GET | Tool details |
| `/api/tools/{name}/execute` | POST | Execute tool task |
| `/api/scheduler/jobs` | GET, POST, DELETE | Job management |
| `/api/vulnerabilities` | GET | Vulnerability listing |
| `/api/traffic` | GET | Traffic flow listing |
| `/ws` | WebSocket | Real-time event streaming |

### WebSocket Events

| Event Type | When Emitted |
|------------|--------------|
| `system.startup` | Application starts |
| `system.shutdown` | Application stops |
| `scan.started` | Scan begins |
| `scan.progress` | Scan status update |
| `scan.completed` | Scan finishes successfully |
| `scan.failed` | Scan encounters error |
| `device.discovered` | New device found |
| `device.updated` | Device info changed |
| `device.offline` | Device marked offline |
| `alert.created` | New alert generated |
| `alert.updated` | Alert status changed |
| `alert.resolved` | Alert resolved |
| `tool.online` | Tool becomes available |
| `tool.offline` | Tool becomes unavailable |

### Integrated Security Tools

| Tool | Adapter | Purpose |
|------|---------|---------|
| nmap | `nmap.py` | Network scanning |
| tshark | `tshark.py` | Packet capture |
| ClamAV | `clamav.py` | Malware scanning |
| Suricata | `suricata.py` | IDS/IPS |
| OpenVAS | `openvas.py` | Vulnerability scanning |
| fail2ban | `fail2ban.py` | Intrusion prevention |
| Zeek | `zeek.py` | Network analysis |
| ntopng | `ntopng.py` | Traffic monitoring |
| OSSEC | `ossec.py` | Host-based IDS |
| Pi.Alert | `pialert.py` | Network presence |

### Frontend Components

| Component | Purpose |
|-----------|---------|
| NetworkCanvas | Interactive network topology visualization |
| NetworkNode | Individual device rendering with status |
| Terminal | Command-line style interface |
| Toolbar | Quick access to tools |
| InspectorPanel | Device detail view |
| VulnerabilityDashboard | Vulnerability summary |
| ScanningOverlay | Scan progress indicator |

## Integration Points

### API → Frontend
- Frontend fetches data via REST API
- Uses `X-API-Key` header for authentication
- WebSocket connection for real-time updates
- Hydrates minimal WS events with full API calls

### Backend → Tools
- Adapters wrap external tool binaries
- Execute via subprocess with proper escaping
- Parse tool-specific output formats (XML, JSON, text)
- Report status via EventBus

### Backend → Database
- SQLAlchemy async ORM
- Models: Device, Port, Alert, Scan, Vulnerability, TrafficFlow
- Migrations via raw SQL in `migrations/sql/`

### Python → Rust
- PyO3 bindings via `netsec-python` crate
- `netsec_core` module exposed to Python
- Performance-critical parsing in Rust

## Current Capabilities

✅ **Working**
- Full REST API with all endpoints
- WebSocket event streaming
- Device discovery and tracking
- Nmap scan execution and parsing
- Alert pipeline (normalize, dedup, correlate, classify)
- Frontend network visualization
- Scheduled monitoring jobs

⚠️ **Partial**
- Other tool adapters (framework exists, not all tested)
- Traffic analysis (endpoint exists, limited functionality)
- Vulnerability aggregation

❌ **Not Yet Implemented**
- User authentication (API key only)
- Email/webhook notifications (framework exists)
- Report generation
- Cloud infrastructure support
