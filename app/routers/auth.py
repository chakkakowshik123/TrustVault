"""Auth router: register, login (with rate limiting and demo cards), logout."""
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from fastapi import APIRouter, Depends, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import AuditAction, User, UserRole
from ..audit_chain import add_audit_log
from ..schemas import validate_email_format, validate_password_strength
from ..security import (
    create_access_token,
    get_current_user_optional,
    hash_password,
    verify_password,
    revoke_user_sessions,
)

router = APIRouter(prefix="/auth", tags=["auth"])
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

# Simple in-memory sliding window rate limiter for login attempts (5 per 60s per IP)
LOGIN_ATTEMPTS: Dict[str, List[float]] = {}
MAX_LOGIN_ATTEMPTS = 5
WINDOW_SECONDS = 60


def check_rate_limit(ip: str) -> bool:
    """Returns True if within rate limit, False if exceeded."""
    now = time.time()
    attempts = LOGIN_ATTEMPTS.get(ip, [])
    # Filter attempts within window
    attempts = [t for t in attempts if now - t < WINDOW_SECONDS]
    LOGIN_ATTEMPTS[ip] = attempts
    if len(attempts) >= MAX_LOGIN_ATTEMPTS:
        return False
    LOGIN_ATTEMPTS[ip].append(now)
    return True


# ─── Register ─────────────────────────────────────────────────────────────────

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, db: Session = Depends(get_db)):
    if get_current_user_optional(request, db):
        return RedirectResponse("/documents", status_code=302)
    return templates.TemplateResponse("register.html", {"request": request, "current_user": None})


@router.post("/register", response_class=HTMLResponse)
async def register(
    request: Request,
    email: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    role: str = Form("viewer"),
    db: Session = Depends(get_db),
):
    errors: list[str] = []
    form_data = {"email": email, "username": username, "role": role}

    # Field-level validation
    if not validate_email_format(email):
        errors.append("Please enter a valid email address.")
    if len(username) < 3 or len(username) > 50:
        errors.append("Username must be 3–50 characters.")
    if not username.replace("_", "").replace("-", "").isalnum():
        errors.append("Username may only contain letters, digits, underscores, and hyphens.")
    errors.extend(validate_password_strength(password))
    if password != confirm_password:
        errors.append("Passwords do not match.")

    # Validate role selection
    try:
        user_role = UserRole(role.lower())
    except ValueError:
        user_role = UserRole.viewer

    # Uniqueness checks
    if not errors:
        if db.query(User).filter(User.email == email.lower()).first():
            errors.append("That email address is already registered.")
        if db.query(User).filter(User.username == username).first():
            errors.append("That username is already taken.")

    if errors:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "errors": errors, "form": form_data, "current_user": None},
            status_code=422,
        )

    # First registered user becomes Admin if no users exist
    user_count = db.query(func.count(User.id)).scalar()
    if user_count == 0:
        user_role = UserRole.admin

    user = User(
        email=email.lower(),
        username=username,
        hashed_password=hash_password(password),
        role=user_role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    add_audit_log(
        db=db,
        action=AuditAction.REGISTER,
        request=request,
        user_id=user.id,
        detail={"email": email, "username": username, "role": user_role.value},
    )

    return RedirectResponse("/auth/login?registered=1", status_code=303)


# ─── Login ────────────────────────────────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
    registered: str = None,
    db: Session = Depends(get_db),
):
    if get_current_user_optional(request, db):
        return RedirectResponse("/documents", status_code=302)
    success = "Account created successfully! Please log in." if registered else None
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "success": success, "current_user": None},
    )


@router.post("/login")
async def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    ip = request.client.host if request.client else "unknown"

    # Rate Limiting Check
    if not check_rate_limit(ip):
        add_audit_log(
            db=db,
            action=AuditAction.LOGIN_FAILED,
            request=request,
            detail={"email": email, "reason": "rate_limit_exceeded"},
        )
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "errors": ["Too many login attempts. Please wait 60 seconds before trying again."],
                "current_user": None,
            },
            status_code=429,
        )

    user = db.query(User).filter(User.email == email.lower()).first()

    if not user or not verify_password(password, user.hashed_password):
        add_audit_log(
            db=db,
            action=AuditAction.LOGIN_FAILED,
            request=request,
            user_id=user.id if user else None,
            detail={"email": email, "reason": "invalid_credentials"},
        )
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "errors": ["Invalid email or password."],
                "current_user": None,
            },
            status_code=401,
        )

    if not user.is_active:
        add_audit_log(
            db=db,
            action=AuditAction.LOGIN_FAILED,
            request=request,
            user_id=user.id,
            detail={"email": email, "reason": "account_deactivated"},
        )
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "errors": ["Your account has been deactivated. Please contact an administrator."],
                "current_user": None,
            },
            status_code=403,
        )

    # Issue short-lived JWT token tied to user.token_version
    token = create_access_token(user)

    add_audit_log(
        db=db,
        action=AuditAction.LOGIN,
        request=request,
        user_id=user.id,
        detail={"email": email, "role": user.role.value if hasattr(user.role, "value") else str(user.role)},
    )

    response = RedirectResponse("/documents", status_code=303)
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=False,
    )
    return response


# ─── Logout ───────────────────────────────────────────────────────────────────

@router.post("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    user = get_current_user_optional(request, db)
    if user:
        # Invalidate all existing tokens by incrementing token_version (Rule #4)
        revoke_user_sessions(user, db)
        add_audit_log(db=db, action=AuditAction.LOGOUT, request=request, user_id=user.id)

    response = RedirectResponse("/auth/login", status_code=303)
    response.delete_cookie("access_token")
    return response
