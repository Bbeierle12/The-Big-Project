"""Shared test fixtures."""
import asyncio
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from netsec.api.app import create_app
from netsec.db.session import init_db, close_db


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def app():
    """Create test application."""
    application = create_app()
    async with application.router.lifespan_context(application):
        yield application


@pytest_asyncio.fixture
async def client(app):
    """Async test client."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
