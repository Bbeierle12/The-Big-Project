"""Certificate transparency monitoring helpers."""
from __future__ import annotations

from typing import Any

import httpx


async def query_crtsh(domain: str) -> list[dict[str, Any]]:
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
        response.raise_for_status()
        payload = response.json()
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []
