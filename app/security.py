"""Security utilities: password hashing (bcrypt), JWT creation/decoding, session revocation."""
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
from jose import JWTError, jwt
from fastapi import Request, Depends
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from . import models


def hash_password(password: str) -> str:
    """Hash a plaintext password with bcrypt (truncated to 72 bytes per standard)."""
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        pwd_bytes = plain_password.encode("utf-8")[:72]
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception:
        return False


def create_access_token(user: models.User, expires_delta: Optional[timedelta] = None) -> str:
    """Sign and return a short-lived JWT access token including user token_version."""
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload = {
        "sub": user.id,
        "role": user.role.value if hasattr(user.role, "value") else str(user.role),
        "v": user.token_version,  # Token version for instant revocation (Rule #4)
        "exp": expire,
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    """Decode and verify a JWT. Returns payload dict or None on failure."""
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        return None


class NotAuthenticatedException(Exception):
    """Raised when a protected route is accessed without a valid session."""
    pass


def revoke_user_sessions(user: models.User, db: Session):
    """Revoke all issued JWTs for this user immediately by incrementing token_version."""
    user.token_version += 1
    db.commit()


def get_current_user_optional(
    request: Request,
    db: Session = Depends(get_db),
) -> Optional[models.User]:
    """
    Return the authenticated User or None.
    Validates token signature and matches token_version against current DB state (Rule #4).
    """
    token = request.cookies.get("access_token")
    if not token:
        # Also check Authorization: Bearer <token> header for API calls
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()

    if not token:
        return None

    payload = decode_token(token)
    if not payload:
        return None

    user_id: str = payload.get("sub", "")
    token_version: int = payload.get("v", 0)

    if not user_id:
        return None

    user = (
        db.query(models.User)
        .filter(models.User.id == user_id, models.User.is_active.is_(True))
        .first()
    )
    if not user:
        return None

    # Immediate session revocation check (Rule #4)
    if user.token_version != token_version:
        return None

    return user


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> models.User:
    """Return the authenticated User, or raise NotAuthenticatedException."""
    user = get_current_user_optional(request, db)
    if not user:
        raise NotAuthenticatedException()
    return user


def require_admin(
    current_user: models.User = Depends(get_current_user),
) -> models.User:
    """Dependency that enforces admin role for administrative views."""
    role_val = current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role)
    if role_val != "admin":
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Admin role required")
    return current_user


def require_owner_or_admin(
    current_user: models.User = Depends(get_current_user),
) -> models.User:
    """Dependency for routes requiring document owner or admin privileges."""
    role_val = current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role)
    if role_val not in ("owner", "admin"):
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Owner privileges required to upload documents")
    return current_user
