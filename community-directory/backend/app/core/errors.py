"""
Standardised API error model and application exceptions.

All API errors return:
    {"error": {"code": "...", "message": "...", "request_id": "..."}}

Error messages shown to clients are deliberately vague where security requires it.
Detailed information is logged server-side only.
"""
from typing import Optional
from fastapi import Request
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.core.logging import get_request_id


# ── Response schema ───────────────────────────────────────────────────────────

class ErrorDetail(BaseModel):
    code: str
    message: str
    request_id: str


class ErrorResponse(BaseModel):
    error: ErrorDetail


# ── Application exception hierarchy ──────────────────────────────────────────

class AppError(Exception):
    """Base application error. Subclass to add specific status codes and codes."""
    status_code: int = 500
    error_code: str = "INTERNAL_ERROR"
    client_message: str = "An unexpected error occurred. Please try again."

    def __init__(self, detail: Optional[str] = None):
        self.detail = detail or self.client_message
        super().__init__(self.detail)


class AuthenticationRequired(AppError):
    status_code = 401
    error_code = "AUTHENTICATION_REQUIRED"
    client_message = "Please sign in to continue."


class SessionExpired(AppError):
    status_code = 401
    error_code = "SESSION_EXPIRED"
    client_message = "Your session has ended. Please sign in again."


class DeviceNotApproved(AppError):
    status_code = 403
    error_code = "DEVICE_NOT_APPROVED"
    client_message = "This device needs administrator approval before access can be granted."


class DeviceRevoked(AppError):
    status_code = 403
    error_code = "DEVICE_REVOKED"
    client_message = "Your session has ended. Please sign in again or contact an administrator."


class AccountSuspended(AppError):
    status_code = 403
    error_code = "ACCOUNT_SUSPENDED"
    client_message = "Your account has been suspended. Please contact an administrator."


class AccountNotActive(AppError):
    status_code = 403
    error_code = "ACCOUNT_NOT_ACTIVE"
    client_message = "Your account is not yet active. Please complete enrolment."


class PermissionDenied(AppError):
    status_code = 403
    error_code = "PERMISSION_DENIED"
    client_message = "You do not have permission to perform this action."


class NotFound(AppError):
    status_code = 404
    error_code = "NOT_FOUND"
    client_message = "The requested resource was not found."


class ValidationError(AppError):
    status_code = 422
    error_code = "VALIDATION_ERROR"
    client_message = "The submitted data is invalid."


class RateLimitExceeded(AppError):
    status_code = 429
    error_code = "RATE_LIMIT_EXCEEDED"
    client_message = "Too many requests. Please wait before trying again."


class OTPError(AppError):
    """Generic OTP failure — deliberately vague to prevent oracle attacks."""
    status_code = 400
    error_code = "OTP_INVALID"
    client_message = "The code could not be verified. Please request a new code if needed."


class OTPExpired(OTPError):
    error_code = "OTP_EXPIRED"
    client_message = "The code has expired. Please request a new verification code."


class OTPMaxAttempts(OTPError):
    error_code = "OTP_MAX_ATTEMPTS"
    client_message = "Too many incorrect attempts. Please request a new verification code."


class WebAuthnError(AppError):
    status_code = 400
    error_code = "WEBAUTHN_ERROR"
    client_message = "Passkey verification failed. Please try again."


class MediaError(AppError):
    status_code = 400
    error_code = "MEDIA_ERROR"
    client_message = "The file could not be processed. Check the type and size and try again."


class ConflictError(AppError):
    status_code = 409
    error_code = "CONFLICT"
    client_message = "This record already exists."


# ── FastAPI exception handlers ────────────────────────────────────────────────

def _error_response(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "request_id": get_request_id(),
            }
        },
    )


async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    return _error_response(exc.status_code, exc.error_code, exc.detail)


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    code_map = {
        400: "BAD_REQUEST",
        401: "AUTHENTICATION_REQUIRED",
        403: "PERMISSION_DENIED",
        404: "NOT_FOUND",
        405: "METHOD_NOT_ALLOWED",
        422: "VALIDATION_ERROR",
        429: "RATE_LIMIT_EXCEEDED",
        500: "INTERNAL_ERROR",
    }
    code = code_map.get(exc.status_code, "ERROR")
    return _error_response(exc.status_code, code, str(exc.detail))


async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    import logging
    logging.getLogger("app.errors").exception(
        "Unhandled exception on %s %s", request.method, request.url.path
    )
    return _error_response(500, "INTERNAL_ERROR", "An unexpected error occurred. Please try again.")
