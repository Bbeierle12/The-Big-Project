"""Cross-platform service management."""
from __future__ import annotations

import logging
import sys
from dataclasses import dataclass
from enum import StrEnum

from netsec.adapters.process import run_command
from netsec.platform.detect import OSType, detect_platform

logger = logging.getLogger(__name__)


class ServiceState(StrEnum):
    RUNNING = "running"
    STOPPED = "stopped"
    UNKNOWN = "unknown"


@dataclass
class ServiceStatus:
    name: str
    state: ServiceState
    enabled: bool = False
    pid: int | None = None


async def get_service_status(service_name: str) -> ServiceStatus:
    """Get the status of a system service."""
    platform_info = detect_platform()

    if platform_info.os_type == OSType.LINUX:
        return await _systemd_status(service_name)
    elif platform_info.os_type == OSType.MACOS:
        return await _launchctl_status(service_name)
    elif platform_info.os_type == OSType.WINDOWS:
        return await _sc_status(service_name)
    else:
        return ServiceStatus(name=service_name, state=ServiceState.UNKNOWN)


async def _systemd_status(name: str) -> ServiceStatus:
    result = await run_command(f"systemctl is-active {name}", timeout=10)
    state = ServiceState.RUNNING if result.stdout.strip() == "active" else ServiceState.STOPPED

    enabled_result = await run_command(f"systemctl is-enabled {name}", timeout=10)
    enabled = enabled_result.stdout.strip() == "enabled"

    pid = None
    if state == ServiceState.RUNNING:
        pid_result = await run_command(f"systemctl show {name} --property=MainPID --value", timeout=10)
        try:
            pid = int(pid_result.stdout.strip())
        except ValueError:
            pass

    return ServiceStatus(name=name, state=state, enabled=enabled, pid=pid)


async def _launchctl_status(name: str) -> ServiceStatus:
    result = await run_command(f"launchctl list {name}", timeout=10)
    state = ServiceState.RUNNING if result.success else ServiceState.STOPPED
    return ServiceStatus(name=name, state=state)


async def _sc_status(name: str) -> ServiceStatus:
    result = await run_command(f"sc query {name}", timeout=10)
    state = ServiceState.RUNNING if "RUNNING" in result.stdout else ServiceState.STOPPED
    return ServiceStatus(name=name, state=state)
