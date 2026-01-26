"""Adapter registry with auto-discovery."""
from __future__ import annotations

import importlib
import logging
import pkgutil
from pathlib import Path
from typing import Any

from netsec.adapters.base import BaseAdapter, ToolInfo, ToolStatus

logger = logging.getLogger(__name__)


class AdapterRegistry:
    """Registry for tool adapters with auto-discovery."""

    def __init__(self) -> None:
        self._adapters: dict[str, BaseAdapter] = {}
        self._initialized = False

    @property
    def adapters(self) -> dict[str, BaseAdapter]:
        return dict(self._adapters)

    def register(self, adapter: BaseAdapter) -> None:
        """Manually register an adapter."""
        info = adapter.tool_info()
        self._adapters[info.name] = adapter
        logger.info("Registered adapter: %s", info.name)

    def get(self, name: str) -> BaseAdapter | None:
        """Get an adapter by tool name."""
        return self._adapters.get(name)

    def list_tools(self) -> list[ToolInfo]:
        """List all registered tools with their info."""
        return [a.tool_info() for a in self._adapters.values()]

    async def discover(self) -> None:
        """Auto-discover adapters from the adapters package.

        Scans for Python modules in the adapters directory that contain
        an 'Adapter' class inheriting from BaseAdapter.
        """
        adapters_dir = Path(__file__).parent
        package_name = "netsec.adapters"

        for module_info in pkgutil.iter_modules([str(adapters_dir)]):
            if module_info.name in ("base", "registry", "process", "__init__"):
                continue

            try:
                module = importlib.import_module(f"{package_name}.{module_info.name}")
                adapter_cls = getattr(module, "Adapter", None)

                if adapter_cls is None:
                    continue

                if not (isinstance(adapter_cls, type) and issubclass(adapter_cls, BaseAdapter)):
                    continue

                adapter = adapter_cls()
                self.register(adapter)

            except Exception:
                logger.exception("Failed to load adapter from %s", module_info.name)

    async def init_all(self) -> dict[str, bool]:
        """Initialize all adapters: detect + start available ones.

        Returns a dict of {tool_name: is_available}.
        """
        if self._initialized:
            return {name: a.tool_info().status == ToolStatus.AVAILABLE for name, a in self._adapters.items()}

        results: dict[str, bool] = {}
        for name, adapter in self._adapters.items():
            try:
                available = await adapter.detect()
                if available:
                    await adapter.start()
                    info = adapter.tool_info()
                    info.status = ToolStatus.AVAILABLE
                    logger.info("Tool available: %s", name)
                else:
                    info = adapter.tool_info()
                    info.status = ToolStatus.UNAVAILABLE
                    logger.info("Tool not found: %s", name)
                results[name] = available
            except Exception:
                logger.exception("Error initializing adapter: %s", name)
                info = adapter.tool_info()
                info.status = ToolStatus.ERROR
                results[name] = False

        self._initialized = True
        return results

    async def shutdown_all(self) -> None:
        """Stop all adapters."""
        for name, adapter in self._adapters.items():
            try:
                await adapter.stop()
            except Exception:
                logger.exception("Error stopping adapter: %s", name)

    async def health_check_all(self) -> dict[str, ToolStatus]:
        """Run health checks on all adapters."""
        results: dict[str, ToolStatus] = {}
        for name, adapter in self._adapters.items():
            try:
                results[name] = await adapter.health_check()
            except Exception:
                logger.exception("Health check failed for: %s", name)
                results[name] = ToolStatus.ERROR
        return results
