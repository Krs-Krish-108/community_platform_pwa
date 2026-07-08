"""
Integration test for the health check routes.
Requires a reachable MongoDB instance (set MONGODB_URI env var, or run via docker-compose).
"""
import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app


@pytest.mark.asyncio
async def test_liveness_returns_ok():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-XSS-Protection") == "1; mode=block"
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"



@pytest.mark.asyncio
async def test_readiness_reports_database_status():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert "status" in body
    assert "database" in body


@pytest.mark.asyncio
async def test_unauthenticated_request_to_protected_route_pattern_returns_error_shape():
    """
    AT-001 pattern check (full member routes come in Phase 3, this validates
    the error envelope contract now while only health routes exist).
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/does-not-exist")
    assert response.status_code == 404
    body = response.json()
    assert "error" in body
    assert "code" in body["error"]
    assert "request_id" in body["error"]
