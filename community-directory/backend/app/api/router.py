"""
Central router composition. As each phase adds new route modules
(auth, webauthn, members, posts, media, admin), register them here.
"""
from fastapi import APIRouter

from app.api import health, admin_auth, admin, members, auth, webauthn, devices, posts, media

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(admin_auth.router)
api_router.include_router(admin.router)
api_router.include_router(members.router)
api_router.include_router(auth.router)
api_router.include_router(webauthn.router)
api_router.include_router(devices.router)
api_router.include_router(posts.router)
api_router.include_router(media.router)

# ── Phase 6+ routers will be added here as they are built ──────────────────


