---
created: 2026-01-31T07:05:47Z
last_updated: 2026-01-31T07:05:47Z
version: 1.0
author: Claude Code PM System
---

# Project Brief: NetSec Orchestrator

## What It Is

NetSec Orchestrator is a unified network security platform that integrates multiple security tools (nmap, OpenVAS, Suricata, ClamAV, etc.) under a single orchestration layer with real-time monitoring, alerting, and visualization capabilities.

## Why It Exists

Network security typically requires running and managing multiple disconnected tools. This project provides:
- **Unified control plane** for all security tools via a single API
- **Real-time event streaming** via WebSocket for live monitoring
- **Automated alerting pipeline** with deduplication, correlation, and severity classification
- **Visual network mapping** through the ArchAngel frontend
- **Scheduled scanning** for continuous security monitoring

## Core Goals

1. **Tool Integration** - Wrap existing security tools (nmap, tshark, ClamAV, Suricata, etc.) with consistent adapters
2. **Event-Driven Architecture** - All components communicate via an event bus for loose coupling
3. **Performance** - Rust core for compute-intensive operations, Python for orchestration flexibility
4. **Extensibility** - Plugin architecture for adding new tools without modifying core code

## Success Criteria

- All supported tools accessible via unified REST API
- Real-time device discovery and status updates via WebSocket
- Alert pipeline processes and deduplicates security events
- Frontend visualizes network topology with live updates
- Scheduled scans run reliably without manual intervention

## Target Users

- **Security analysts** monitoring network health
- **System administrators** managing infrastructure security
- **Penetration testers** conducting authorized assessments
- **DevSecOps teams** integrating security into CI/CD pipelines

## Technology Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 19, TypeScript, Vite |
| API | FastAPI (Python 3.11+) |
| Core Engine | Rust (performance-critical paths) |
| Database | SQLite (default), PostgreSQL (optional) |
| Event Bus | In-process async (WebSocket forwarding) |
| Tools | nmap, tshark, ClamAV, Suricata, OpenVAS, etc. |
