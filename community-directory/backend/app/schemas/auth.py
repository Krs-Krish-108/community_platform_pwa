"""
Pydantic schemas for identity/OTP routes.
"""
from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class IdentifyRequest(BaseModel):
    member_id: str = Field(min_length=1, max_length=20)
    email: EmailStr


class GenericMessageResponse(BaseModel):
    message: str


class OTPVerifyRequest(BaseModel):
    member_id: str = Field(min_length=1, max_length=20)
    otp: str = Field(min_length=4, max_length=8)


class OTPVerifyResponse(BaseModel):
    next_step: str  # "PASSKEY_REGISTRATION" | "PENDING_ADMIN_APPROVAL"
    enrollment_ticket: Optional[str] = None
