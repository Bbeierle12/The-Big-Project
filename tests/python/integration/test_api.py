"""Integration tests for API endpoints."""
import pytest
import pytest_asyncio


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
