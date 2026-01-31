---
created: 2026-01-31T07:05:47Z
last_updated: 2026-01-31T07:05:47Z
version: 1.0
author: Claude Code PM System
---

# Product Context

## Product Vision

NetSec Orchestrator provides a unified "single pane of glass" for network security operations, allowing security professionals to monitor, scan, and respond to threats across their infrastructure using familiar tools through a modern web interface.

## User Personas

### 1. Security Analyst (Primary)
**Goals:**
- Monitor network for threats in real-time
- Investigate alerts and correlate events
- Run on-demand scans when suspicious activity detected

**Pain Points:**
- Too many disconnected tools
- Alert fatigue from duplicate notifications
- Context switching between tool UIs

**How We Help:**
- Unified dashboard with all alerts
- Automatic deduplication and correlation
- Real-time WebSocket updates

### 2. System Administrator
**Goals:**
- Maintain inventory of network devices
- Ensure security tools are running
- Schedule regular security scans

**Pain Points:**
- Manual device tracking is error-prone
- Tools fail silently
- Remembering to run scans

**How We Help:**
- Automatic device discovery and tracking
- Tool health monitoring with alerts
- Scheduled scan jobs

### 3. Penetration Tester
**Goals:**
- Quickly enumerate network targets
- Identify vulnerabilities for assessment
- Document findings

**Pain Points:**
- Running multiple tools manually
- Correlating results across tools
- Keeping track of discovered assets

**How We Help:**
- One-click network scans
- Vulnerability aggregation
- Visual network map

## Core Features

### Device Management
- **Auto-discovery**: Devices found during scans are automatically tracked
- **Status tracking**: Online/offline/warning/compromised states
- **Port inventory**: Open ports and services per device
- **Vendor identification**: OUI-based manufacturer lookup

### Scanning
- **Network scans**: Discover hosts and services (nmap)
- **Vulnerability scans**: Find known CVEs (OpenVAS)
- **Traffic analysis**: Capture and analyze packets (tshark)
- **Malware scans**: Check for malicious files (ClamAV)

### Alerting
- **Multi-source**: Alerts from all integrated tools
- **Deduplication**: Same alert doesn't trigger multiple times
- **Correlation**: Group related alerts by device/timeframe
- **Severity classification**: Automatic priority assignment
- **Status workflow**: Open → Acknowledged → Resolved

### Scheduling
- **Recurring scans**: Daily/weekly/monthly schedules
- **Health monitoring**: Periodic tool health checks
- **Device staleness**: Automatic offline detection

### Visualization (ArchAngel Frontend)
- **Network canvas**: Interactive topology view
- **Live updates**: WebSocket-driven real-time changes
- **Node details**: Click for device info, ports, vulns
- **Terminal**: Command-line style tool execution

## Use Cases

### UC-1: Continuous Network Monitoring
1. Scheduled scan runs every 4 hours
2. New devices appear on network map
3. Device goes offline → marked as offline
4. Alert generated for unexpected device

### UC-2: Incident Investigation
1. IDS alert triggers notification
2. Analyst opens dashboard, sees correlated alerts
3. Clicks affected device on network map
4. Views open ports, recent scans, vulnerabilities
5. Initiates targeted vulnerability scan
6. Marks alerts as resolved after remediation

### UC-3: Vulnerability Assessment
1. Tester initiates full network scan
2. Reviews discovered devices and services
3. Runs vulnerability scan on critical systems
4. Exports findings for report

## Feature Priorities

### P0 - Core (Implemented)
- Device discovery and tracking
- Nmap integration
- Alert pipeline
- REST API
- WebSocket events
- Basic frontend visualization

### P1 - Important (Partial)
- Full vulnerability scanning (OpenVAS)
- Traffic analysis (tshark)
- Scheduled scans
- Tool health monitoring

### P2 - Nice to Have
- Email/webhook notifications
- Custom alert rules
- Role-based access control
- Multi-user support
- Report generation

### P3 - Future
- Threat intelligence feeds
- Automated response playbooks
- Cloud infrastructure support
- Mobile app
