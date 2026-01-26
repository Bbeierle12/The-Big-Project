"""ntopng network traffic monitoring adapter."""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from netsec.adapters.base import BaseAdapter, ToolCategory, ToolInfo, ToolStatus
from netsec.adapters.process import check_binary

logger = logging.getLogger(__name__)

DEFAULT_API_URL = "http://127.0.0.1:3000"


class Adapter(BaseAdapter):
    def __init__(self) -> None:
        self._status = ToolStatus.UNKNOWN
        self._api_url = DEFAULT_API_URL
        user = os.environ.get("NETSEC__NTOPNG__API_USER")
        password = os.environ.get("NETSEC__NTOPNG__API_PASS")
        self._auth = (user, password) if user and password else None
        self._client: httpx.AsyncClient | None = None

    def tool_info(self) -> ToolInfo:
        return ToolInfo(
            name="ntopng",
            display_name="ntopng",
            category=ToolCategory.TRAFFIC_ANALYZER,
            description="Network traffic monitoring and analysis",
            status=self._status,
            supported_tasks=["flows", "hosts", "interfaces", "alerts", "stats"],
        )

    async def detect(self) -> bool:
        binary = await check_binary("ntopng")
        if binary:
            self._status = ToolStatus.AVAILABLE
            return True
        # Also check if API is reachable
        try:
            client = await self._get_client()
            resp = await client.get(f"{self._api_url}/lua/rest/v2/get/ntopng/interfaces.lua")
            if resp.status_code == 200:
                self._status = ToolStatus.AVAILABLE
                return True
        except Exception:
            pass
        self._status = ToolStatus.UNAVAILABLE
        return False

    async def health_check(self) -> ToolStatus:
        try:
            client = await self._get_client()
            resp = await client.get(f"{self._api_url}/lua/rest/v2/get/ntopng/interfaces.lua")
            self._status = ToolStatus.RUNNING if resp.status_code == 200 else ToolStatus.ERROR
        except Exception:
            self._status = ToolStatus.ERROR if self._status != ToolStatus.UNAVAILABLE else ToolStatus.UNAVAILABLE
        return self._status

    async def execute(self, task: str, params: dict[str, Any]) -> dict[str, Any]:
        client = await self._get_client()
        ifid = params.get("interface_id", 0)

        match task:
            case "flows":
                return await self._api_get(client, "/lua/rest/v2/get/flow/active.lua", {"ifid": ifid})
            case "hosts":
                return await self._api_get(client, "/lua/rest/v2/get/host/active.lua", {"ifid": ifid})
            case "interfaces":
                return await self._api_get(client, "/lua/rest/v2/get/ntopng/interfaces.lua")
            case "alerts":
                return await self._api_get(client, "/lua/rest/v2/get/flow/alert/list.lua", {"ifid": ifid})
            case "stats":
                return await self._api_get(client, "/lua/rest/v2/get/interface/data.lua", {"ifid": ifid})
            case _:
                raise ValueError(f"Unknown task: {task}")

    async def _api_get(self, client: httpx.AsyncClient, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            resp = await client.get(f"{self._api_url}{path}", params=params)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            return {"error": str(e)}

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(auth=self._auth, timeout=30.0)
        return self._client

    async def parse_output(self, raw_output: str | bytes, output_format: str = "text") -> dict[str, Any]:
        import json
        text = raw_output if isinstance(raw_output, str) else raw_output.decode(errors="replace")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"raw": text}

    async def stop(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
