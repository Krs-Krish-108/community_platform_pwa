"""
Application factory. Wires together config, database, middleware, routes,
error handlers, and startup/shutdown lifecycle (including admin bootstrap).
"""
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.router import api_router
from app.core.config import get_settings
from app.core.database import (
    close_mongo_connection,
    connect_to_mongo,
    create_indexes,
)
from app.core.errors import (
    AppError,
    app_error_handler,
    http_exception_handler,
    unhandled_error_handler,
)
from app.core.logging import configure_logging, get_logger, new_request_id
from app.domain.bootstrap_service import run_admin_bootstrap

settings = get_settings()
configure_logging(settings.log_level)
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: connect DB, create indexes, run admin bootstrap. Shutdown: close DB."""
    logger.info("Starting Verified Community Directory backend (mode=%s)", settings.app_mode)

    db = await connect_to_mongo()
    app.state.db = db

    await create_indexes(db)
    await run_admin_bootstrap(db)

    logger.info("Startup complete. Ready to accept requests.")
    yield

    logger.info("Shutting down...")
    await close_mongo_connection()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Verified Community Directory API",
        version=settings.app_version,
        lifespan=lifespan,
        docs_url="/api/docs" if settings.is_development else None,
        redoc_url="/api/redoc" if settings.is_development else None,
        openapi_url="/api/openapi.json" if settings.is_development else None,
    )

    # ── CORS ─────────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,  # required for HttpOnly cookies
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-Request-ID"],
    )

    # ── Request ID middleware ────────────────────────────────────────────
    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        incoming = request.headers.get("X-Request-ID")
        rid = incoming if incoming else str(uuid.uuid4())
        new_request_id()
        from app.core.logging import set_request_id
        set_request_id(rid)

        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        return response

    # ── Security Headers middleware ──────────────────────────────────────
    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if settings.is_production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        return response


    # ── Error handlers ───────────────────────────────────────────────────
    app.add_exception_handler(AppError, app_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(Exception, unhandled_error_handler)

    # ── Routes ───────────────────────────────────────────────────────────
    app.include_router(api_router)

    return app


app = create_app()
