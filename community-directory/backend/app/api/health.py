"""
Health check endpoints — public, no authentication required.
Used by deployment platforms (Render/Cloud Run) for liveness/readiness probes.
"""
from fastapi import APIRouter, Request

from app.core.database import ping_database

router = APIRouter(prefix="/api/health", tags=["health"])


@router.get("/live")
async def liveness():
    """Liveness probe — process is up and responding."""
    return {"status": "ok"}


@router.get("/ready")
async def readiness(request: Request):
    """Readiness probe — confirms the database is reachable."""
    db_ok = await ping_database()
    status = "ok" if db_ok else "degraded"
    return {
        "status": status,
        "database": "connected" if db_ok else "unreachable",
    }
