"""Pydantic schemas for validation and API responses."""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, field_validator
import re


# ─── User Schemas ─────────────────────────────────────────────────────────────

class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    role: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Token Schemas ────────────────────────────────────────────────────────────

class TokenPayload(BaseModel):
    sub: str
    role: str
    exp: int
    iat: int


# ─── Document Schemas ─────────────────────────────────────────────────────────

class DocumentResponse(BaseModel):
    id: str
    filename: str
    mime_type: str
    size_bytes: int
    description: Optional[str]
    created_at: datetime
    owner_id: str

    model_config = {"from_attributes": True}


# ─── Permission Schemas ───────────────────────────────────────────────────────

class PermissionResponse(BaseModel):
    id: str
    document_id: str
    granted_to_id: str
    level: str
    is_active: bool
    expires_at: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Audit Schemas ────────────────────────────────────────────────────────────

class AuditLogResponse(BaseModel):
    id: str
    user_id: Optional[str]
    document_id: Optional[str]
    action: str
    ip_address: Optional[str]
    timestamp: datetime
    detail: Optional[dict]

    model_config = {"from_attributes": True}


# ─── Validation helpers ───────────────────────────────────────────────────────

def validate_password_strength(password: str) -> list[str]:
    """Return list of validation errors; empty list = valid."""
    errors = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")
    if not re.search(r"[0-9]", password):
        errors.append("Password must contain at least one digit.")
    return errors


def validate_email_format(email: str) -> bool:
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return bool(re.match(pattern, email))
