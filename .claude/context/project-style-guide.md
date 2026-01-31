---
created: 2026-01-31T07:05:47Z
last_updated: 2026-01-31T07:05:47Z
version: 1.0
author: Claude Code PM System
---

# Project Style Guide

## Python Code Style

### General
- **Python version**: 3.11+
- **Line length**: 99 characters (configured in ruff)
- **Formatter**: Ruff
- **Type checker**: Mypy (strict mode)

### Naming Conventions
| Type | Convention | Example |
|------|------------|---------|
| Modules | `snake_case` | `device_service.py` |
| Classes | `PascalCase` | `DeviceService` |
| Functions | `snake_case` | `get_device()` |
| Variables | `snake_case` | `device_id` |
| Constants | `SCREAMING_SNAKE` | `MAX_RETRY_COUNT` |
| Private | `_leading_underscore` | `_find_device()` |

### Imports
```python
# Standard library
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

# Third-party
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

# Local
from netsec.core.events import Event, EventBus, EventType
from netsec.models.device import Device
```

Order: future → stdlib → third-party → local (enforced by ruff isort)

### Type Hints
```python
# Always use type hints
async def get_device(self, device_id: str) -> Device | None:
    ...

# Use Optional only when None is meaningful
from typing import Optional
notes: Optional[str] = None  # Can be None or missing

# Prefer | for unions (Python 3.10+)
status: str | None = None
```

### Async Patterns
```python
# Always use async with for sessions
async with get_session_context() as session:
    result = await session.execute(stmt)

# Use asyncio for concurrent operations
results = await asyncio.gather(
    self.check_devices(),
    self.check_tools(),
)
```

### Error Handling
```python
# Raise specific exceptions
raise ValueError(f"Unknown tool: {tool}")
raise RuntimeError(f"Tool not available: {tool}")

# In routers, convert to HTTPException
try:
    result = await service.create_scan(...)
except ValueError as e:
    raise HTTPException(status_code=400, detail=str(e))
except RuntimeError as e:
    raise HTTPException(status_code=503, detail=str(e))
```

## Rust Code Style

### General
- **Edition**: 2021
- **Formatter**: rustfmt (default settings)
- **Linter**: Clippy

### Naming Conventions
| Type | Convention | Example |
|------|------------|---------|
| Modules | `snake_case` | `device_service` |
| Types | `PascalCase` | `DeviceInfo` |
| Functions | `snake_case` | `parse_nmap_xml()` |
| Constants | `SCREAMING_SNAKE` | `MAX_BUFFER_SIZE` |
| Lifetimes | `'lowercase` | `'a`, `'input` |

### Error Handling
```rust
// Use thiserror for library errors
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("Invalid target: {0}")]
    InvalidTarget(String),
    #[error("Tool not found: {0}")]
    ToolNotFound(String),
}

// Use anyhow for application code
use anyhow::{Context, Result};

fn load_config() -> Result<Config> {
    let content = fs::read_to_string("config.toml")
        .context("Failed to read config file")?;
    Ok(toml::from_str(&content)?)
}
```

### Async Patterns
```rust
// Use tokio for async runtime
#[tokio::main]
async fn main() -> Result<()> {
    let engine = NetsecEngine::new().await?;
    engine.run().await
}

// Prefer async methods
pub async fn health_check(&self) -> HealthStatus {
    // ...
}
```

## TypeScript/React Style

### General
- **TypeScript version**: ~5.8
- **React version**: 19
- **Bundler**: Vite

### File Naming
| Type | Convention | Example |
|------|------------|---------|
| Components | `PascalCase.tsx` | `NetworkNode.tsx` |
| Hooks | `camelCase.ts` | `useNetwork.ts` |
| Utilities | `camelCase.ts` | `networkUtils.ts` |
| Types | `camelCase.ts` | `types.ts` |
| Services | `camelCase.ts` | `api.ts` |

### Component Structure
```tsx
// Imports
import { useState, useEffect } from 'react';
import { SomeIcon } from 'lucide-react';
import { SomeType } from '../types';

// Types
interface Props {
  device: ApiDevice;
  onSelect: (id: string) => void;
}

// Component
export const DeviceCard: React.FC<Props> = ({ device, onSelect }) => {
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    // Side effects
  }, [device.id]);

  return (
    <div className="device-card">
      {/* JSX */}
    </div>
  );
};
```

### Hooks Pattern
```typescript
export const useNetwork = () => {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    // Initialization
  }, []);

  const addNode = useCallback((type: NodeType) => {
    // Implementation
  }, []);

  return { nodes, isLoading, addNode };
};
```

### API Calls
```typescript
// Use static class methods
static async getDevice(deviceId: string): Promise<ApiDevice> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}`, {
    headers: this.getHeaders()
  });
  if (!res.ok) throw new Error(`Failed to fetch device ${deviceId}`);
  return res.json();
}
```

## Git Conventions

### Commit Messages
```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation
- `style` - Formatting
- `refactor` - Code restructuring
- `test` - Test additions
- `chore` - Maintenance

Examples:
```
feat(scanner): implement full scan functionality with nmap execution
fix(alerts): prevent duplicate notifications for same event
docs: update API documentation for device endpoints
```

### Branch Naming
- `main` - Production branch
- `feat/feature-name` - Feature branches
- `fix/issue-description` - Bug fixes
- `epic/epic-name` - Large feature sets

## Documentation

### Python Docstrings
```python
async def upsert_from_scan(self, host_data: dict[str, Any]) -> Device:
    """Create or update a device from scan results.

    Merges data if device already exists (matched by IP or MAC).

    Args:
        host_data: Dictionary containing host information from scan

    Returns:
        The created or updated Device instance

    Raises:
        ValueError: If host_data is missing required fields
    """
```

### Rust Documentation
```rust
/// Parse nmap XML output into structured scan results.
///
/// # Arguments
///
/// * `xml_content` - Raw XML string from nmap output
///
/// # Returns
///
/// Parsed `ScanResult` or error if parsing fails
///
/// # Example
///
/// ```
/// let result = parse_nmap_xml(xml_string)?;
/// println!("Found {} hosts", result.hosts.len());
/// ```
pub fn parse_nmap_xml(xml_content: &str) -> Result<ScanResult> {
```

### API Documentation
FastAPI auto-generates OpenAPI docs. Add descriptions:
```python
@router.get("/", response_model=list[DeviceOut])
async def list_devices(
    offset: int = 0,
    limit: int = 100,
    status: str | None = None,
) -> list[DeviceOut]:
    """List all discovered devices.

    Supports pagination and filtering by status.
    """
```
