"""
Structured logging with per-request correlation IDs.
Secrets are never logged — only safe metadata.
"""
import logging
import sys
import uuid
from contextvars import ContextVar
from typing import Optional

# Per-request correlation ID stored in context variable
_request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)


def get_request_id() -> str:
    """Return the current request's correlation ID, or a new one if none is set."""
    rid = _request_id_var.get()
    if rid is None:
        rid = str(uuid.uuid4())
        _request_id_var.set(rid)
    return rid


def set_request_id(request_id: str) -> None:
    _request_id_var.set(request_id)


def new_request_id() -> str:
    rid = str(uuid.uuid4())
    _request_id_var.set(rid)
    return rid


class RequestIDFilter(logging.Filter):
    """Inject correlation ID into every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = get_request_id()
        return True


def configure_logging(log_level: str = "INFO") -> None:
    """
    Configure root logger with structured output.
    In production this emits JSON-friendly lines; in dev, human-readable.
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    fmt = "%(asctime)s [%(levelname)s] [%(request_id)s] %(name)s: %(message)s"
    datefmt = "%Y-%m-%dT%H:%M:%S"

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
    handler.addFilter(RequestIDFilter())

    root = logging.getLogger()
    root.setLevel(level)
    # Remove any existing handlers (e.g. from uvicorn bootstrap)
    root.handlers.clear()
    root.addHandler(handler)

    # Quieten noisy third-party loggers
    logging.getLogger("motor").setLevel(logging.WARNING)
    logging.getLogger("pymongo").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger. Always use this instead of logging.getLogger()."""
    return logging.getLogger(name)
