"""Integration tests for API endpoints."""
from uuid import uuid4

import pytest


@pytest.mark.asyncio
async def test_health_endpoint(client):
    response = await client.get("/api/system/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data


@pytest.mark.asyncio
async def test_system_info(client):
    response = await client.get("/api/system/info")
    assert response.status_code == 200
    data = response.json()
    assert "python_version" in data


@pytest.mark.asyncio
async def test_list_tools(client):
    response = await client.get("/api/tools/")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


@pytest.mark.asyncio
async def test_list_devices(client):
    response = await client.get("/api/devices/")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_list_scans(client):
    response = await client.get("/api/scans/")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_list_alerts(client):
    response = await client.get("/api/alerts/")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_sentinel_status_endpoint(client):
    response = await client.get("/api/sentinel/status")
    assert response.status_code == 200
    data = response.json()
    assert "feeds" in data
    assert "snapshots" in data


@pytest.mark.asyncio
async def test_sentinel_feed_status_endpoint(client):
    response = await client.get("/api/sentinel/osint/feeds")
    assert response.status_code == 200
    data = response.json()
    assert "ioc_counts" in data


@pytest.mark.asyncio
async def test_sentinel_collect_endpoint(client):
    response = await client.post("/api/sentinel/collect")
    assert response.status_code == 200
    data = response.json()
    assert "counts" in data
    assert "warnings" in data


@pytest.mark.asyncio
async def test_sentinel_correlate_ingests_alerts(client, app, monkeypatch):
    adapter = app.state.adapter_registry.get("sentinel")
    unique_title = f"Sentinel test alert {uuid4().hex}"

    async def fake_execute(task: str, params: dict) -> dict:
        assert task == "correlate"
        return {
            "count": 1,
            "warnings": [],
            "alerts": [
                {
                    "title": unique_title,
                    "description": "Synthetic Sentinel alert for integration test",
                    "severity": "high",
                    "category": "anomaly",
                    "device_ip": "198.51.100.42",
                    "fingerprint": uuid4().hex,
                    "raw_data": {"test": True},
                }
            ],
        }

    monkeypatch.setattr(adapter, "execute", fake_execute)

    response = await client.post(
        "/api/sentinel/correlate",
        json={"refresh_feeds": False, "scan_vulns": False, "ingest_alerts": True},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 1
    assert data["ingestion"]["created"] == 1

    alerts_response = await client.get("/api/alerts/?source_tool=sentinel")
    assert alerts_response.status_code == 200
    alerts = alerts_response.json()
    assert any(alert["title"] == unique_title for alert in alerts)
