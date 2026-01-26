"""Base adapter interface for security tools."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ToolCategory(StrEnum):
    NETWORK_SCANNER = "network_scanner"
    IDS_IPS = "ids_ips"
    VULNERABILITY_SCANNER = "vulnerability_scanner"
    TRAFFIC_ANALYZER = "traffic_analyzer"
    MALWARE_SCANNER = "malware_scanner"
    LOG_ANALYZER = "log_analyzer"
    HOST_MONITOR = "host_monitor"
    ACCESS_CONTROL = "access_control"


class ToolStatus(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    RUNNING = "running"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass
class ToolInfo:
    """Metadata about a security tool."""
    name: str
    display_name: str
    category: ToolCategory
    description: str
    version: str | None = None
    binary_path: str | None = None
    status: ToolStatus = ToolStatus.UNKNOWN
    supported_tasks: list[str] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)


class BaseAdapter(ABC):
    """Abstract base class for all tool adapters.

    Each adapter wraps a single security tool and provides:
    - Detection: Is the tool installed and available?
    - Execution: Run the tool with parameters
    - Parsing: Convert tool output to structured data
    - Health: Check tool status
    """

    @abstractmethod
    def tool_info(self) -> ToolInfo:
        """Return static metadata about this tool."""
        ...

    @abstractmethod
    async def detect(self) -> bool:
        """Detect if the tool is installed and accessible.

        Should check for binary existence, version, permissions, etc.
        Returns True if the tool is ready to use.
        """
        ...

    @abstractmethod
    async def health_check(self) -> ToolStatus:
        """Check the current health/status of the tool.

        More detailed than detect() — checks if daemon is running,
        signatures are up to date, etc.
        """
        ...

    @abstractmethod
    async def execute(self, task: str, params: dict[str, Any]) -> dict[str, Any]:
        """Execute a task with the given parameters.

        Args:
            task: The task to execute (e.g., 'scan', 'update', 'status')
            params: Task-specific parameters

        Returns:
            Raw or parsed results dict
        """
        ...

    @abstractmethod
    async def parse_output(self, raw_output: str | bytes, output_format: str = "text") -> dict[str, Any]:
        """Parse raw tool output into structured data.

        Args:
            raw_output: The raw output from the tool
            output_format: Format hint (text, xml, json, etc.)

        Returns:
            Structured result dict
        """
        ...

    async def start(self) -> None:
        """Called when the adapter is initialized. Override for setup logic."""
        pass

    async def stop(self) -> None:
        """Called during shutdown. Override for cleanup logic."""
        pass
