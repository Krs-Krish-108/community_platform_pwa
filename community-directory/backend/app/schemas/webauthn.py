"""
Pydantic schemas for WebAuthn registration and login routes.

`credential` fields carry the raw JSON produced by the browser's
navigator.credentials.create() / .get() calls, passed through untouched
to the webauthn library for verification.
"""
from typing import Any, Dict
from pydantic import BaseModel, Field


class RegisterOptionsRequest(BaseModel):
    enrollment_ticket: str = Field(min_length=10)


class RegisterVerifyRequest(BaseModel):
    enrollment_ticket: str = Field(min_length=10)
    credential: Dict[str, Any]


class LoginVerifyRequest(BaseModel):
    credential: Dict[str, Any]


class WebAuthnResultResponse(BaseModel):
    member_id: str
    status: str
