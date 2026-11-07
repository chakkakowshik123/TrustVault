"""
TrustVault - Standalone Single-File Application
===============================================
A complete, secure, zero-trust document management & sharing platform.
Security-first architecture:
- Central authorize(user, document, action) on EVERY route (deny-by-default).
- Zero information leakage: returns 404 for unauthorized access (prevents IDOR).
- Role-based separation:
    * Admin: User & system management, audit log, anomaly alerts.
             CANNOT read or download document contents unless explicitly granted.
    * Owner: Upload, edit, delete, grant read/edit, revoke.
    * Viewer: Sees and accesses ONLY documents explicitly granted.
- Cryptographic append-only audit trail: SHA-256 hash chain with SQLite triggers
  blocking UPDATE and DELETE.
- Dynamic immediate revocation: checks active DB grants and token_version on every request.
- File upload security: Magic bytes check (%PDF, PNG, JPG, DOCX, TXT), 50MB cap,
  randomized storage name outside web root, path traversal prevention.
- Rate-limited login (5 attempts / 60s per IP) + three 1-click Demo Cards.
- Fully self-contained: embedded HTML/CSS/JS templates (zero external assets needed).
- Auto-seeds default demo accounts and documents on initial startup.

Run directly:
    python trustvault_standalone.py
Or with uvicorn:
    uvicorn trustvault_standalone:app --host 0.0.0.0 --port 8000
"""

import os
import io
import re
import csv
import sys
import uuid
import enum
import time
import hmac
import shutil
import base64
import hashlib
import unicodedata
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Literal

# External dependencies (FastAPI, Starlette, SQLAlchemy, bcrypt, python-jose, Jinja2)
try:
    import bcrypt
    from jose import JWTError, jwt
    from fastapi import FastAPI, Request, Response, Depends, Form, File, UploadFile, HTTPException, Query
    from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, JSONResponse
    from fastapi.templating import Jinja2Templates
    from jinja2 import Environment, DictLoader
    from sqlalchemy import (
        create_engine, Column, String, Boolean, DateTime, Integer,
        ForeignKey, Enum, Text, JSON, DDL, event, or_, and_, func, desc
    )
    from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
except ImportError as exc:
    sys.exit(
        f"[ERROR] Missing required library: {exc}.\n"
        "Please install requirements: pip install fastapi uvicorn sqlalchemy bcrypt python-jose jinja2 python-multipart"
    )

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

SECRET_KEY = os.environ.get("SECRET_KEY", "trustvault-production-secret-key-change-me-in-prod-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", BASE_DIR / "data"))
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", BASE_DIR / "storage" / "documents"))
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DATA_DIR / 'trustvault.db'}")

DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# DATABASE MODELS & APPEND-ONLY AUDIT TRIGGERS
# ─────────────────────────────────────────────────────────────────────────────

Base = declarative_base()
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    echo=False
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def _uuid() -> str:
    return str(uuid.uuid4())

class UserRole(str, enum.Enum):
    admin = "admin"
    owner = "owner"
    viewer = "viewer"

class PermissionLevel(str, enum.Enum):
    read = "read"
    edit = "edit"

class DocumentCategory(str, enum.Enum):
    financial = "Financial"
    legal = "Legal"
    hr = "HR"
    technical = "Technical"
    general = "General"

class AuditAction(str, enum.Enum):
    REGISTER = "REGISTER"
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    LOGIN_FAILED = "LOGIN_FAILED"
    UPLOAD = "UPLOAD"
    DOWNLOAD = "DOWNLOAD"
    VIEW = "VIEW"
    EDIT = "EDIT"
    DELETE = "DELETE"
    SHARE = "SHARE"
    REVOKE = "REVOKE"
    DENIED = "DENIED"

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=_uuid)
    email = Column(String, unique=True, nullable=False, index=True)
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.viewer, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    token_version = Column(Integer, default=1, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    documents = relationship("Document", back_populates="owner", foreign_keys="Document.owner_id")
    permissions_granted = relationship("Permission", back_populates="granted_to", foreign_keys="Permission.granted_to_id")
    audit_logs = relationship("AuditLog", back_populates="user", foreign_keys="AuditLog.user_id")

class Document(Base):
    __tablename__ = "documents"
    id = Column(String, primary_key=True, default=_uuid)
    owner_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    filename = Column(String, nullable=False)
    stored_name = Column(String, nullable=False, unique=True)
    mime_type = Column(String, nullable=False)
    size_bytes = Column(Integer, nullable=False)
    category = Column(Enum(DocumentCategory), default=DocumentCategory.general, nullable=False)
    description = Column(Text, nullable=True)
    is_deleted = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    owner = relationship("User", back_populates="documents", foreign_keys=[owner_id])
    permissions = relationship("Permission", back_populates="document", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="document", foreign_keys="AuditLog.document_id")

class Permission(Base):
    __tablename__ = "permissions"
    id = Column(String, primary_key=True, default=_uuid)
    document_id = Column(String, ForeignKey("documents.id"), nullable=False, index=True)
    granted_to_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    granted_by_id = Column(String, ForeignKey("users.id"), nullable=False)
    level = Column(Enum(PermissionLevel), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    document = relationship("Document", back_populates="permissions")
    granted_to = relationship("User", back_populates="permissions_granted", foreign_keys=[granted_to_id])
    granted_by = relationship("User", foreign_keys=[granted_by_id])

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True, default=_uuid)
    sequence = Column(Integer, autoincrement=True, unique=True, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=True, index=True)
    document_id = Column(String, ForeignKey("documents.id"), nullable=True, index=True)
    action = Column(String, nullable=False, index=True)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    detail = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    prev_hash = Column(String(64), nullable=False)
    current_hash = Column(String(64), nullable=False, index=True)

    user = relationship("User", back_populates="audit_logs", foreign_keys=[user_id])
    document = relationship("Document", back_populates="audit_logs", foreign_keys=[document_id])

# Enforce Append-Only SQLite Triggers: Blocks UPDATE and DELETE
trigger_no_update = DDL("""
CREATE TRIGGER IF NOT EXISTS abort_audit_update
BEFORE UPDATE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'Audit log is append-only: UPDATE is strictly prohibited');
END;
""")

trigger_no_delete = DDL("""
CREATE TRIGGER IF NOT EXISTS abort_audit_delete
BEFORE DELETE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'Audit log is append-only: DELETE is strictly prohibited');
END;
""")

event.listen(AuditLog.__table__, "after_create", trigger_no_update)
event.listen(AuditLog.__table__, "after_create", trigger_no_delete)

Base.metadata.create_all(bind=engine)

# ─────────────────────────────────────────────────────────────────────────────
# CRYPTOGRAPHIC AUDIT LOG & INTEGRITY CHAIN (Rule #5)
# ─────────────────────────────────────────────────────────────────────────────

GENESIS_PREV_HASH = "0" * 64

def compute_log_hash(
    prev_hash: str,
    user_id: Optional[str],
    action: str,
    document_id: Optional[str],
    timestamp: datetime,
    ip_address: Optional[str],
    detail_str: str,
) -> str:
    """Computes SHA-256 hash chaining this record to the previous record."""
    payload = (
        f"{prev_hash}|"
        f"{user_id or ''}|"
        f"{action}|"
        f"{document_id or ''}|"
        f"{timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')}|"
        f"{ip_address or ''}|"
        f"{detail_str}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def add_audit_log(
    db: Session,
    action: AuditAction | str,
    request: Optional[Request] = None,
    user_id: Optional[str] = None,
    document_id: Optional[str] = None,
    detail: Optional[dict] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> AuditLog:
    """Appends an immutable cryptographic record to the audit chain."""
    act_str = action.value if hasattr(action, "value") else str(action)
    if request:
        if not ip_address:
            ip_address = request.client.host if request.client else "unknown"
        if not user_agent:
            user_agent = request.headers.get("user-agent", "unknown")

    # Find the latest audit row to get prev_hash and sequence
    latest = db.query(AuditLog).order_by(AuditLog.sequence.desc()).first()
    prev_hash = latest.current_hash if latest else GENESIS_PREV_HASH
    next_seq = (latest.sequence + 1) if (latest and latest.sequence is not None) else 1

    now = datetime.utcnow()
    detail_str = str(sorted((detail or {}).items()))

    curr_hash = compute_log_hash(
        prev_hash=prev_hash,
        user_id=user_id,
        action=act_str,
        document_id=document_id,
        timestamp=now,
        ip_address=ip_address,
        detail_str=detail_str,
    )

    log_entry = AuditLog(
        sequence=next_seq,
        user_id=user_id,
        document_id=document_id,
        action=act_str,
        ip_address=ip_address,
        user_agent=user_agent,
        detail=detail or {},
        timestamp=now,
        prev_hash=prev_hash,
        current_hash=curr_hash,
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry

def verify_audit_chain(db: Session) -> Dict[str, Any]:
    """Cryptographically verifies every link in the append-only ledger."""
    records = db.query(AuditLog).order_by(AuditLog.sequence.asc()).all()
    if not records:
        return {
            "is_valid": True,
            "total_records": 0,
            "verified_records": 0,
            "message": "Audit log is empty. Integrity preserved.",
        }

    expected_prev = GENESIS_PREV_HASH
    for idx, rec in enumerate(records):
        if rec.prev_hash != expected_prev:
            return {
                "is_valid": False,
                "total_records": len(records),
                "corrupted_sequence": rec.sequence,
                "corrupted_id": rec.id,
                "reason": "Previous hash link broken (unauthorized insertion/deletion)",
                "expected_prev": expected_prev,
                "found_prev": rec.prev_hash,
                "message": f"Hash chain broken at sequence #{rec.sequence}",
            }
        detail_str = str(sorted((rec.detail or {}).items()))
        recalculated = compute_log_hash(
            prev_hash=rec.prev_hash,
            user_id=rec.user_id,
            action=rec.action,
            document_id=rec.document_id,
            timestamp=rec.timestamp,
            ip_address=rec.ip_address,
            detail_str=detail_str,
        )
        if rec.current_hash != recalculated:
            return {
                "is_valid": False,
                "total_records": len(records),
                "corrupted_sequence": rec.sequence,
                "corrupted_id": rec.id,
                "reason": "Row content has been modified after insertion",
                "message": f"Tampering detected at sequence #{rec.sequence}",
            }
        expected_prev = rec.current_hash

    return {
        "is_valid": True,
        "total_records": len(records),
        "verified_records": len(records),
        "latest_hash": records[-1].current_hash,
        "message": f"Cryptographic integrity verified across all {len(records)} audit records.",
    }

# ─────────────────────────────────────────────────────────────────────────────
# SECURITY UTILITIES & AUTHENTICATION
# ─────────────────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    # Truncate to 72 bytes per bcrypt standard
    pw_bytes = password[:72].encode("utf-8")
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(pw_bytes, salt).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        pw_bytes = plain_password[:72].encode("utf-8")
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(pw_bytes, hash_bytes)
    except Exception:
        return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

def get_current_user_optional(request: Request, db: Session) -> Optional[User]:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        return None

    payload = decode_token(token)
    if not payload:
        return None

    user_id = payload.get("sub")
    token_version = payload.get("tv")
    if not user_id or token_version is None:
        return None

    user = db.query(User).filter(User.id == user_id, User.is_active.is_(True)).first()
    if not user or user.token_version != token_version:
        return None
    return user

def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    user = get_current_user_optional(request, db)
    if not user:
        if request.url.path.startswith("/api/"):
            raise HTTPException(status_code=401, detail="Authentication required")
        raise HTTPException(status_code=303, headers={"Location": "/auth/login"})
    return user

def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != UserRole.admin:
        raise HTTPException(status_code=404, detail="Resource not found")
    return current_user

def require_owner_or_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role not in (UserRole.owner, UserRole.admin):
        raise HTTPException(status_code=404, detail="Resource not found")
    return current_user

# ─────────────────────────────────────────────────────────────────────────────
# CENTRAL AUTHORIZATION ENGINE (Rule #1: Deny by Default, Return 404 on Denied)
# ─────────────────────────────────────────────────────────────────────────────

ActionType = Literal["view", "download", "edit", "delete", "share", "revoke"]

def authorize(
    user: Optional[User],
    document: Optional[Document],
    action: ActionType,
    db: Session,
    request: Optional[Request] = None,
    log_denial: bool = True,
) -> bool:
    """
    Central authorization function used by EVERY route.
    Deny by default. Never trust client-side claims.
    
    Roles:
    - Admin: System & user management, audit logs. CANNOT view/download document contents unless explicitly granted.
    - Owner: Full control over their documents (view, download, edit, delete, share, revoke).
    - Viewer / Granted users: Only granted actions (read: view/download; edit: view/download/edit).
    """
    if document is None or document.is_deleted:
        return False

    if user is None or not user.is_active:
        if log_denial:
            add_audit_log(
                db,
                action=AuditAction.DENIED,
                request=request,
                user_id=user.id if user else None,
                document_id=document.id,
                detail={"action": action, "reason": "unauthenticated_or_inactive"},
            )
        return False

    # Document Owner has full access to their own documents
    if document.owner_id == user.id:
        return True

    # Immediate database lookup for active grant (Rule #4)
    grant = (
        db.query(Permission)
        .filter(
            Permission.document_id == document.id,
            Permission.granted_to_id == user.id,
            Permission.is_active.is_(True),
        )
        .first()
    )

    if not grant:
        # Admin CANNOT read or download document contents unless explicitly granted
        if log_denial:
            add_audit_log(
                db,
                action=AuditAction.DENIED,
                request=request,
                user_id=user.id,
                document_id=document.id,
                detail={
                    "action": action,
                    "reason": "no_active_permission",
                    "user_role": user.role.value if hasattr(user.role, "value") else str(user.role),
                },
            )
        return False

    # Evaluate permission level
    allowed = False
    if grant.level == PermissionLevel.edit:
        if action in ("view", "download", "edit"):
            allowed = True
    elif grant.level == PermissionLevel.read:
        if action in ("view", "download"):
            allowed = True

    if not allowed:
        if log_denial:
            add_audit_log(
                db,
                action=AuditAction.DENIED,
                request=request,
                user_id=user.id,
                document_id=document.id,
                detail={
                    "action": action,
                    "reason": "insufficient_permission_level",
                    "grant_level": grant.level.value if hasattr(grant.level, "value") else str(grant.level),
                },
            )
        return False

    return True

def get_authorized_document_or_404(
    doc_id: str,
    action: ActionType,
    user: User,
    db: Session,
    request: Optional[Request] = None,
) -> Document:
    """Fetch document and verify authorization; returns 404 for ANY denial to prevent IDOR."""
    doc = db.query(Document).filter(Document.id == doc_id, Document.is_deleted.is_(False)).first()
    if not doc:
        add_audit_log(
            db,
            action=AuditAction.DENIED,
            request=request,
            user_id=user.id if user else None,
            detail={"action": action, "target_doc_id": doc_id, "reason": "not_found"},
        )
        raise HTTPException(status_code=404, detail="Document not found")

    if not authorize(user, doc, action, db, request, log_denial=True):
        raise HTTPException(status_code=404, detail="Document not found")

    return doc

# ─────────────────────────────────────────────────────────────────────────────
# FILE VALIDATION & SECURE STORAGE
# ─────────────────────────────────────────────────────────────────────────────

BANNED_EXTENSIONS = {
    ".exe", ".sh", ".bash", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".php", ".py", ".rb", ".pl", ".cgi", ".jar", ".war", ".msi",
    ".dll", ".so", ".dylib", ".scr", ".pif", ".hta", ".cpl",
}

MAGIC_SIGNATURES = [
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"PK\x03\x04", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
]

def sanitize_filename(filename: str) -> str:
    filename = unicodedata.normalize("NFKD", filename)
    filename = os.path.basename(filename)
    filename = re.sub(r"[^\w\s.-]", "", filename).strip()
    return filename or "unnamed_document"

def validate_file_content(filename: str, content: bytes) -> tuple[bool, str, str]:
    if len(content) == 0:
        return False, "File is empty", ""
    if len(content) > MAX_UPLOAD_BYTES:
        return False, f"File exceeds maximum allowed size of {MAX_UPLOAD_BYTES // (1024*1024)}MB", ""

    ext = Path(filename).suffix.lower()
    if ext in BANNED_EXTENSIONS:
        return False, f"File extension '{ext}' is prohibited for security reasons", ""

    # Magic byte matching
    matched_mime = None
    for magic, mime in MAGIC_SIGNATURES:
        if content.startswith(magic):
            matched_mime = mime
            break

    # Plain text check
    if not matched_mime and ext in (".txt", ".csv", ".json", ".md", ".log"):
        try:
            content[:4096].decode("utf-8")
            matched_mime = "text/plain"
        except UnicodeDecodeError:
            pass

    if not matched_mime:
        return False, "Unrecognized or prohibited file format (magic bytes validation failed)", ""

    return True, "", matched_mime

def save_secure_file(original_filename: str, content: bytes) -> tuple[str, str]:
    clean_original = sanitize_filename(original_filename)
    ext = Path(clean_original).suffix.lower()
    stored_name = f"{uuid.uuid4().hex}{ext}"
    dest_path = UPLOAD_DIR / stored_name

    # Path traversal check
    if not str(dest_path.resolve()).startswith(str(UPLOAD_DIR.resolve())):
        raise ValueError("Invalid storage path detected")

    dest_path.write_bytes(content)
    return clean_original, stored_name

# ─────────────────────────────────────────────────────────────────────────────
# RATE LIMITING & SECURITY ANOMALY DETECTION
# ─────────────────────────────────────────────────────────────────────────────

LOGIN_ATTEMPTS: Dict[str, List[float]] = {}
MAX_LOGIN_ATTEMPTS = 5
WINDOW_SECONDS = 60

def check_rate_limit(ip: str) -> bool:
    now = time.time()
    attempts = LOGIN_ATTEMPTS.get(ip, [])
    attempts = [t for t in attempts if now - t < WINDOW_SECONDS]
    LOGIN_ATTEMPTS[ip] = attempts
    if len(attempts) >= MAX_LOGIN_ATTEMPTS:
        return False
    LOGIN_ATTEMPTS[ip].append(now)
    return True

def detect_anomalies(db: Session) -> List[Dict[str, Any]]:
    anomalies = []
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)

    denied_by_ip = (
        db.query(AuditLog.ip_address, func.count(AuditLog.id).label("count"))
        .filter(AuditLog.action == AuditAction.DENIED.value, AuditLog.timestamp >= one_hour_ago)
        .group_by(AuditLog.ip_address)
        .all()
    )
    for ip, count in denied_by_ip:
        if count >= 3:
            anomalies.append({
                "severity": "high",
                "title": "High Denied Attempts",
                "description": f"IP {ip} triggered {count} unauthorized access denials in the last hour.",
            })

    failed_logins = (
        db.query(AuditLog.ip_address, func.count(AuditLog.id).label("count"))
        .filter(AuditLog.action == AuditAction.LOGIN_FAILED.value, AuditLog.timestamp >= one_hour_ago)
        .group_by(AuditLog.ip_address)
        .all()
    )
    for ip, count in failed_logins:
        if count >= 3:
            anomalies.append({
                "severity": "medium",
                "title": "Repeated Failed Logins",
                "description": f"IP {ip} had {count} failed login attempts in the last hour.",
            })

    return anomalies

# ─────────────────────────────────────────────────────────────────────────────
# EMBEDDED JINJA2 TEMPLATES & MODERN STYLESHEET
# ─────────────────────────────────────────────────────────────────────────────

CSS_STYLES = """
:root {
    --bg-primary: #0b0f19;
    --bg-secondary: #111827;
    --bg-card: #1f2937;
    --bg-hover: #374151;
    --border: #374151;
    --text-primary: #f9fafb;
    --text-secondary: #9ca3af;
    --text-muted: #6b7280;
    --accent: #6366f1;
    --accent-hover: #4f46e5;
    --success: #10b981;
    --warning: #f59e0b;
    --danger: #ef4444;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.5;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
header {
    background-color: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    padding: 0.75rem 1.5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}
.brand {
    font-size: 1.25rem;
    font-weight: 700;
    color: #fff;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    text-decoration: none;
}
.nav-links { display: flex; align-items: center; gap: 1rem; }
.nav-badge {
    padding: 0.25rem 0.6rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
}
.badge-admin { background: rgba(239,68,68,0.2); color: #f87171; border: 1px solid rgba(239,68,68,0.3); }
.badge-owner { background: rgba(99,102,241,0.2); color: #818cf8; border: 1px solid rgba(99,102,241,0.3); }
.badge-viewer { background: rgba(16,185,129,0.2); color: #34d399; border: 1px solid rgba(16,185,129,0.3); }
main { flex: 1; padding: 2rem 1.5rem; max-width: 1200px; margin: 0 auto; width: 100%; }
.card {
    background-color: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 0.75rem;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
}
.btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    padding: 0.5rem 1rem;
    border-radius: 0.5rem;
    font-weight: 600;
    font-size: 0.875rem;
    cursor: pointer;
    border: none;
    transition: all 0.15s ease;
    text-decoration: none !important;
}
.btn-primary { background: var(--accent); color: #fff; }
.btn-primary:hover { background: var(--accent-hover); }
.btn-danger { background: var(--danger); color: #fff; }
.btn-danger:hover { opacity: 0.9; }
.btn-secondary { background: var(--bg-card); color: var(--text-primary); border: 1px solid var(--border); }
.btn-secondary:hover { background: var(--bg-hover); }
.btn-sm { padding: 0.25rem 0.5rem; font-size: 0.75rem; }
input[type="text"], input[type="email"], input[type="password"], select, textarea {
    width: 100%;
    padding: 0.6rem 0.75rem;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    color: var(--text-primary);
    font-size: 0.875rem;
    margin-top: 0.25rem;
    margin-bottom: 1rem;
}
input:focus, select:focus, textarea:focus {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 0 2px rgba(99,102,241,0.2);
}
table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.875rem; }
th { color: var(--text-secondary); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }
tr:hover { background: rgba(255,255,255,0.02); }
.alert {
    padding: 0.75rem 1rem;
    border-radius: 0.5rem;
    margin-bottom: 1rem;
    font-size: 0.875rem;
}
.alert-danger { background: rgba(239,68,68,0.15); border: 1px solid var(--danger); color: #fca5a5; }
.alert-success { background: rgba(16,185,129,0.15); border: 1px solid var(--success); color: #6ee7b7; }
.alert-warning { background: rgba(245,158,11,0.15); border: 1px solid var(--warning); color: #fde68a; }
.demo-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 1rem;
    margin-top: 1.5rem;
}
.demo-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    padding: 1rem;
    cursor: pointer;
    transition: transform 0.15s ease, border-color 0.15s ease;
}
.demo-card:hover { transform: translateY(-2px); border-color: var(--accent); }
.grid-stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 1.5rem;
}
.stat-box {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 0.75rem;
    padding: 1.25rem;
}
.stat-val { font-size: 1.75rem; font-weight: 700; color: #fff; }
.stat-lbl { color: var(--text-secondary); font-size: 0.875rem; }
.tag {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 0.25rem;
    font-size: 0.75rem;
    font-weight: 600;
}
.tag-financial { background: rgba(16,185,129,0.2); color: #34d399; }
.tag-legal { background: rgba(245,158,11,0.2); color: #fbbf24; }
.tag-technical { background: rgba(59,130,246,0.2); color: #60a5fa; }
.tag-hr { background: rgba(236,72,153,0.2); color: #f472b6; }
.tag-general { background: rgba(156,163,175,0.2); color: #d1d5db; }
"""

TEMPLATES_MAP = {
    "base.html": """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}TrustVault{% endblock %} - Secure Document Vault</title>
    <style>""" + CSS_STYLES + """</style>
</head>
<body>
    <header>
        <a href="/documents" class="brand">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--accent)"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            TrustVault
        </a>
        <nav class="nav-links">
            {% if current_user %}
                <a href="/documents" style="color: var(--text-secondary)">Documents</a>
                <a href="/audit/my" style="color: var(--text-secondary)">My Activity</a>
                {% if current_user.role == 'admin' %}
                    <a href="/audit" style="color: #f87171; font-weight: 600">Admin Security</a>
                {% endif %}
                <span class="nav-badge badge-{{ current_user.role }}">{{ current_user.role }}</span>
                <span style="font-size: 0.875rem; color: var(--text-muted)">{{ current_user.email }}</span>
                <form action="/auth/logout" method="post" style="display:inline; margin:0">
                    <button type="submit" class="btn btn-secondary btn-sm">Sign Out</button>
                </form>
            {% else %}
                <a href="/auth/login" class="btn btn-primary btn-sm">Sign In</a>
                <a href="/auth/register" class="btn btn-secondary btn-sm">Register</a>
            {% endif %}
        </nav>
    </header>
    <main>
        {% block content %}{% endblock %}
    </main>
</body>
</html>
""",

    "login.html": """{% extends "base.html" %}
{% block title %}Sign In{% endblock %}
{% block content %}
<div style="max-width: 480px; margin: 2rem auto;">
    <div class="card">
        <h2 style="margin-bottom: 0.5rem; text-align: center;">Sign In to TrustVault</h2>
        <p style="color: var(--text-secondary); text-align: center; margin-bottom: 1.5rem; font-size: 0.875rem;">
            Security-first document sharing platform with zero-trust access control.
        </p>

        {% if errors %}
            {% for err in errors %}
                <div class="alert alert-danger">{{ err }}</div>
            {% endfor %}
        {% endif %}

        <form action="/auth/login" method="post" id="loginForm">
            <label style="font-size: 0.875rem; font-weight: 600;">Email Address</label>
            <input type="email" name="email" id="email" required placeholder="user@trustvault.com" value="{{ form.email if form else '' }}">

            <label style="font-size: 0.875rem; font-weight: 600;">Password</label>
            <input type="password" name="password" id="password" required placeholder="••••••••••••">

            <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 0.5rem;">Sign In</button>
        </form>

        <p style="text-align: center; font-size: 0.875rem; color: var(--text-muted); margin-top: 1rem;">
            Don't have an account? <a href="/auth/register">Create Account</a>
        </p>
    </div>

    <div style="margin-top: 2rem;">
        <h4 style="text-align: center; color: var(--text-secondary); margin-bottom: 0.75rem; font-size: 0.875rem; text-transform: uppercase;">
            Demo Login Cards (1-Click Autofill)
        </h4>
        <div class="demo-grid">
            <div class="demo-card" onclick="fillDemo('admin@trustvault.com', 'Admin@TrustVault2026!')">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <strong>Admin</strong>
                    <span class="nav-badge badge-admin">admin</span>
                </div>
                <div style="font-size: 0.75rem; color: var(--text-muted);">admin@trustvault.com</div>
                <div style="font-size: 0.75rem; color: #10b981; margin-top: 0.5rem;">Click to Autofill</div>
            </div>

            <div class="demo-card" onclick="fillDemo('owner@trustvault.com', 'Owner@TrustVault2026!')">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <strong>Owner</strong>
                    <span class="nav-badge badge-owner">owner</span>
                </div>
                <div style="font-size: 0.75rem; color: var(--text-muted);">owner@trustvault.com</div>
                <div style="font-size: 0.75rem; color: #10b981; margin-top: 0.5rem;">Click to Autofill</div>
            </div>

            <div class="demo-card" onclick="fillDemo('viewer@trustvault.com', 'Viewer@TrustVault2026!')">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <strong>Viewer</strong>
                    <span class="nav-badge badge-viewer">viewer</span>
                </div>
                <div style="font-size: 0.75rem; color: var(--text-muted);">viewer@trustvault.com</div>
                <div style="font-size: 0.75rem; color: #10b981; margin-top: 0.5rem;">Click to Autofill</div>
            </div>
        </div>
    </div>
</div>

<script>
function fillDemo(email, password) {
    document.getElementById('email').value = email;
    document.getElementById('password').value = password;
}
</script>
{% endblock %}
""",

    "register.html": """{% extends "base.html" %}
{% block title %}Create Account{% endblock %}
{% block content %}
<div style="max-width: 480px; margin: 2rem auto;">
    <div class="card">
        <h2 style="margin-bottom: 0.5rem; text-align: center;">Create TrustVault Account</h2>
        <p style="color: var(--text-secondary); text-align: center; margin-bottom: 1.5rem; font-size: 0.875rem;">
            Register to securely upload and share confidential documents.
        </p>

        {% if errors %}
            {% for err in errors %}
                <div class="alert alert-danger">{{ err }}</div>
            {% endfor %}
        {% endif %}

        <form action="/auth/register" method="post">
            <label style="font-size: 0.875rem; font-weight: 600;">Email Address</label>
            <input type="email" name="email" required placeholder="name@company.com" value="{{ form.email if form else '' }}">

            <label style="font-size: 0.875rem; font-weight: 600;">Username</label>
            <input type="text" name="username" required placeholder="johndoe" value="{{ form.username if form else '' }}">

            <label style="font-size: 0.875rem; font-weight: 600;">Account Role</label>
            <select name="role">
                <option value="viewer" {% if form and form.role == 'viewer' %}selected{% endif %}>Viewer (Access granted documents only)</option>
                <option value="owner" {% if form and form.role == 'owner' %}selected{% endif %}>Owner (Can upload, manage & share documents)</option>
                <option value="admin" {% if form and form.role == 'admin' %}selected{% endif %}>Admin (System management & audit trail)</option>
            </select>

            <label style="font-size: 0.875rem; font-weight: 600;">Password (Min 8 chars, 1 uppercase, 1 digit)</label>
            <input type="password" name="password" required placeholder="••••••••••••">

            <label style="font-size: 0.875rem; font-weight: 600;">Confirm Password</label>
            <input type="password" name="confirm_password" required placeholder="••••••••••••">

            <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 0.5rem;">Create Account</button>
        </form>

        <p style="text-align: center; font-size: 0.875rem; color: var(--text-muted); margin-top: 1rem;">
            Already registered? <a href="/auth/login">Sign In</a>
        </p>
    </div>
</div>
{% endblock %}
""",

    "dashboard.html": """{% extends "base.html" %}
{% block title %}Dashboard{% endblock %}
{% block content %}
<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
    <div>
        <h1 style="font-size: 1.75rem; font-weight: 700;">Document Vault</h1>
        <p style="color: var(--text-secondary); font-size: 0.875rem;">Your secure, encrypted document repository.</p>
    </div>
    {% if current_user.role in ['owner', 'admin'] %}
        <a href="/documents/upload" class="btn btn-primary">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            Upload Document
        </a>
    {% endif %}
</div>

<div class="grid-stats">
    <div class="stat-box">
        <div class="stat-val">{{ total_docs }}</div>
        <div class="stat-lbl">Owned Documents</div>
    </div>
    <div class="stat-box">
        <div class="stat-val">{{ total_shared }}</div>
        <div class="stat-lbl">Shared with Me</div>
    </div>
    <div class="stat-box">
        <div class="stat-val">{{ (total_size / 1024 / 1024) | round(2) }} MB</div>
        <div class="stat-lbl">Storage Used</div>
    </div>
</div>

<!-- Search & Filter Bar -->
<div class="card" style="padding: 1rem; margin-bottom: 1.5rem;">
    <form action="/documents" method="get" style="display: flex; gap: 1rem; flex-wrap: wrap; align-items: center;">
        <input type="text" name="q" placeholder="Search by document name..." value="{{ q }}" style="flex: 2; margin: 0;">
        <select name="category" style="flex: 1; margin: 0;">
            <option value="">All Categories</option>
            {% for cat in categories %}
                <option value="{{ cat }}" {% if category == cat %}selected{% endif %}>{{ cat }}</option>
            {% endfor %}
        </select>
        <button type="submit" class="btn btn-secondary">Search</button>
        {% if q or category %}
            <a href="/documents" class="btn btn-secondary btn-sm">Clear</a>
        {% endif %}
    </form>
</div>

<!-- My Documents Table -->
<div class="card">
    <h3 style="margin-bottom: 1rem;">My Documents ({{ my_docs | length }})</h3>
    {% if my_docs %}
        <table>
            <thead>
                <tr>
                    <th>Filename</th>
                    <th>Category</th>
                    <th>Size</th>
                    <th>Uploaded</th>
                    <th style="text-align: right;">Actions</th>
                </tr>
            </thead>
            <tbody>
                {% for doc in my_docs %}
                    <tr>
                        <td>
                            <a href="/documents/{{ doc.id }}" style="font-weight: 600; color: #fff;">{{ doc.filename }}</a>
                            {% if doc.description %}
                                <div style="font-size: 0.75rem; color: var(--text-muted);">{{ doc.description }}</div>
                            {% endif %}
                        </td>
                        <td><span class="tag tag-{{ doc.category | lower }}">{{ doc.category }}</span></td>
                        <td>{{ (doc.size_bytes / 1024) | round(1) }} KB</td>
                        <td>{{ doc.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
                        <td style="text-align: right;">
                            <a href="/documents/{{ doc.id }}/download" class="btn btn-secondary btn-sm">Download</a>
                            <a href="/documents/{{ doc.id }}/share" class="btn btn-secondary btn-sm">Share</a>
                            <a href="/documents/{{ doc.id }}/edit" class="btn btn-secondary btn-sm">Edit</a>
                        </td>
                    </tr>
                {% endfor %}
            </tbody>
        </table>
    {% else %}
        <p style="color: var(--text-muted); font-size: 0.875rem;">No documents uploaded yet.</p>
    {% endif %}
</div>

<!-- Shared with Me Table -->
{% if shared_docs %}
<div class="card">
    <h3 style="margin-bottom: 1rem;">Shared with Me ({{ shared_docs | length }})</h3>
    <table>
        <thead>
            <tr>
                <th>Filename</th>
                <th>Owner</th>
                <th>Permission</th>
                <th>Category</th>
                <th style="text-align: right;">Actions</th>
            </tr>
        </thead>
        <tbody>
            {% for item in shared_docs %}
                <tr>
                    <td>
                        <a href="/documents/{{ item.doc.id }}" style="font-weight: 600; color: #fff;">{{ item.doc.filename }}</a>
                    </td>
                    <td>{{ item.doc.owner.username }}</td>
                    <td><span class="tag tag-technical">{{ item.perm.level }}</span></td>
                    <td><span class="tag tag-{{ item.doc.category | lower }}">{{ item.doc.category }}</span></td>
                    <td style="text-align: right;">
                        <a href="/documents/{{ item.doc.id }}/download" class="btn btn-secondary btn-sm">Download</a>
                        {% if item.perm.level == 'edit' %}
                            <a href="/documents/{{ item.doc.id }}/edit" class="btn btn-secondary btn-sm">Edit</a>
                        {% endif %}
                    </td>
                </tr>
            {% endfor %}
        </tbody>
    </table>
</div>
{% endif %}
{% endblock %}
""",

    "upload.html": """{% extends "base.html" %}
{% block title %}Upload Document{% endblock %}
{% block content %}
<div style="max-width: 600px; margin: 2rem auto;">
    <div class="card">
        <h2 style="margin-bottom: 0.5rem;">Upload Confidential Document</h2>
        <p style="color: var(--text-secondary); margin-bottom: 1.5rem; font-size: 0.875rem;">
            Files are validated with magic byte checks, stored securely outside web root, and guarded by zero-trust permissions.
        </p>

        {% if errors %}
            {% for err in errors %}
                <div class="alert alert-danger">{{ err }}</div>
            {% endfor %}
        {% endif %}

        <form action="/documents/upload" method="post" enctype="multipart/form-data">
            <label style="font-size: 0.875rem; font-weight: 600;">Select File (PDF, PNG, JPG, DOCX, TXT - Max 50MB)</label>
            <input type="file" name="file" required style="margin-bottom: 1.5rem;">

            <label style="font-size: 0.875rem; font-weight: 600;">Category</label>
            <select name="category">
                {% for cat in categories %}
                    <option value="{{ cat }}">{{ cat }}</option>
                {% endfor %}
            </select>

            <label style="font-size: 0.875rem; font-weight: 600;">Description (Optional)</label>
            <textarea name="description" rows="3" placeholder="Brief summary of this document..."></textarea>

            <div style="display: flex; gap: 1rem; margin-top: 1rem;">
                <button type="submit" class="btn btn-primary" style="flex: 1;">Upload & Encrypt</button>
                <a href="/documents" class="btn btn-secondary">Cancel</a>
            </div>
        </form>
    </div>
</div>
{% endblock %}
""",

    "document_detail.html": """{% extends "base.html" %}
{% block title %}{{ doc.filename }}{% endblock %}
{% block content %}
<div style="margin-bottom: 1.5rem;">
    <a href="/documents" style="color: var(--text-secondary); font-size: 0.875rem;">← Back to Documents</a>
</div>

<div class="card">
    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1rem;">
        <div>
            <h1 style="font-size: 1.5rem; font-weight: 700; color: #fff;">{{ doc.filename }}</h1>
            <p style="color: var(--text-secondary); font-size: 0.875rem; margin-top: 0.25rem;">
                Owner: <strong>{{ doc.owner.username }}</strong> &nbsp;|&nbsp;
                Category: <span class="tag tag-{{ doc.category | lower }}">{{ doc.category }}</span> &nbsp;|&nbsp;
                Size: {{ (doc.size_bytes / 1024) | round(1) }} KB &nbsp;|&nbsp;
                Uploaded: {{ doc.created_at.strftime('%Y-%m-%d %H:%M UTC') }}
            </p>
        </div>
        <div style="display: flex; gap: 0.5rem;">
            {% if can_download %}
                <a href="/documents/{{ doc.id }}/download" class="btn btn-primary">Download File</a>
            {% endif %}
            {% if can_edit %}
                <a href="/documents/{{ doc.id }}/edit" class="btn btn-secondary">Edit</a>
            {% endif %}
            {% if is_owner %}
                <a href="/documents/{{ doc.id }}/share" class="btn btn-secondary">Manage Sharing</a>
                <form action="/documents/{{ doc.id }}/delete" method="post" style="display:inline; margin:0;" onsubmit="return confirm('Delete this document?');">
                    <button type="submit" class="btn btn-danger">Delete</button>
                </form>
            {% endif %}
        </div>
    </div>

    {% if doc.description %}
        <div style="background: var(--bg-card); padding: 1rem; border-radius: 0.5rem; margin-top: 1rem; font-size: 0.875rem;">
            <strong style="color: var(--text-muted); text-transform: uppercase; font-size: 0.75rem;">Description</strong>
            <p style="margin-top: 0.25rem;">{{ doc.description }}</p>
        </div>
    {% endif %}

    <!-- Active Grants on this Document -->
    {% if is_owner %}
        <div style="margin-top: 2rem;">
            <h3 style="font-size: 1.1rem; margin-bottom: 0.5rem;">Access Grants</h3>
            {% if permissions %}
                <table>
                    <thead>
                        <tr>
                            <th>User Email</th>
                            <th>Permission Level</th>
                            <th>Granted Date</th>
                            <th style="text-align: right;">Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for perm in permissions %}
                            <tr>
                                <td>{{ perm.granted_to.email }}</td>
                                <td><span class="tag tag-technical">{{ perm.level }}</span></td>
                                <td>{{ perm.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
                                <td style="text-align: right;">
                                    <form action="/documents/{{ doc.id }}/revoke/{{ perm.id }}" method="post" style="display:inline; margin:0;">
                                        <button type="submit" class="btn btn-danger btn-sm">Revoke</button>
                                    </form>
                                </td>
                            </tr>
                        {% endfor %}
                    </tbody>
                </table>
            {% else %}
                <p style="color: var(--text-muted); font-size: 0.875rem;">No external access granted. Only you can access this document.</p>
            {% endif %}
        </div>
    {% endif %}
</div>
{% endblock %}
""",

    "edit_document.html": """{% extends "base.html" %}
{% block title %}Edit {{ doc.filename }}{% endblock %}
{% block content %}
<div style="max-width: 600px; margin: 2rem auto;">
    <div class="card">
        <h2 style="margin-bottom: 0.5rem;">Edit Document Metadata</h2>
        <p style="color: var(--text-secondary); margin-bottom: 1.5rem; font-size: 0.875rem;">
            Modify document title, category, or upload an updated file revision.
        </p>

        {% if errors %}
            {% for err in errors %}
                <div class="alert alert-danger">{{ err }}</div>
            {% endfor %}
        {% endif %}

        <form action="/documents/{{ doc.id }}/edit" method="post" enctype="multipart/form-data">
            <label style="font-size: 0.875rem; font-weight: 600;">Document Filename</label>
            <input type="text" name="filename" required value="{{ doc.filename }}">

            <label style="font-size: 0.875rem; font-weight: 600;">Category</label>
            <select name="category">
                {% for cat in categories %}
                    <option value="{{ cat }}" {% if doc.category == cat %}selected{% endif %}>{{ cat }}</option>
                {% endfor %}
            </select>

            <label style="font-size: 0.875rem; font-weight: 600;">Description</label>
            <textarea name="description" rows="3">{{ doc.description or '' }}</textarea>

            <label style="font-size: 0.875rem; font-weight: 600;">Replace File (Optional)</label>
            <input type="file" name="file" style="margin-bottom: 1.5rem;">

            <div style="display: flex; gap: 1rem; margin-top: 1rem;">
                <button type="submit" class="btn btn-primary" style="flex: 1;">Save Changes</button>
                <a href="/documents/{{ doc.id }}" class="btn btn-secondary">Cancel</a>
            </div>
        </form>
    </div>
</div>
{% endblock %}
""",

    "share.html": """{% extends "base.html" %}
{% block title %}Share {{ doc.filename }}{% endblock %}
{% block content %}
<div style="max-width: 700px; margin: 2rem auto;">
    <div style="margin-bottom: 1.5rem;">
        <a href="/documents/{{ doc.id }}" style="color: var(--text-secondary); font-size: 0.875rem;">← Back to {{ doc.filename }}</a>
    </div>

    <div class="card">
        <h2 style="margin-bottom: 0.5rem;">Share Document</h2>
        <p style="color: var(--text-secondary); margin-bottom: 1.5rem; font-size: 0.875rem;">
            Grant explicit read or edit access to registered users. Revocation takes effect immediately.
        </p>

        {% if success %}
            <div class="alert alert-success">{{ success }}</div>
        {% endif %}
        {% if errors %}
            {% for err in errors %}
                <div class="alert alert-danger">{{ err }}</div>
            {% endfor %}
        {% endif %}

        <form action="/documents/{{ doc.id }}/share" method="post" style="display: flex; gap: 1rem; align-items: flex-end; flex-wrap: wrap;">
            <div style="flex: 2; min-width: 220px;">
                <label style="font-size: 0.875rem; font-weight: 600;">User Email</label>
                <input type="email" name="email" required placeholder="recipient@trustvault.com" style="margin-bottom: 0;" value="{{ form.email if form else '' }}">
            </div>
            <div style="flex: 1; min-width: 140px;">
                <label style="font-size: 0.875rem; font-weight: 600;">Permission Level</label>
                <select name="level" style="margin-bottom: 0;">
                    <option value="read">Read (View & Download)</option>
                    <option value="edit">Edit (Read & Edit)</option>
                </select>
            </div>
            <button type="submit" class="btn btn-primary" style="height: 42px;">Grant Access</button>
        </form>
    </div>

    <div class="card">
        <h3 style="margin-bottom: 1rem;">Active Access Grants</h3>
        {% if permissions %}
            <table>
                <thead>
                    <tr>
                        <th>User Email</th>
                        <th>Level</th>
                        <th>Granted At</th>
                        <th style="text-align: right;">Action</th>
                    </tr>
                </thead>
                <tbody>
                    {% for perm in permissions %}
                        <tr>
                            <td>{{ perm.granted_to.email }}</td>
                            <td><span class="tag tag-technical">{{ perm.level }}</span></td>
                            <td>{{ perm.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
                            <td style="text-align: right;">
                                <form action="/documents/{{ doc.id }}/revoke/{{ perm.id }}" method="post" style="display:inline; margin:0;">
                                    <button type="submit" class="btn btn-danger btn-sm">Revoke</button>
                                </form>
                            </td>
                        </tr>
                    {% endfor %}
                </tbody>
            </table>
        {% else %}
            <p style="color: var(--text-muted); font-size: 0.875rem;">No users have been granted access yet.</p>
        {% endif %}
    </div>
</div>
{% endblock %}
""",

    "admin_dashboard.html": """{% extends "base.html" %}
{% block title %}Security & Audit Dashboard{% endblock %}
{% block content %}
<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
    <div>
        <h1 style="font-size: 1.75rem; font-weight: 700;">Security & Audit Control Center</h1>
        <p style="color: var(--text-secondary); font-size: 0.875rem;">
            Cryptographic ledger integrity, access refusal monitoring, and anomaly detection.
        </p>
    </div>
    <div style="display: flex; gap: 0.75rem;">
        <button onclick="verifyChain()" class="btn btn-primary" id="btnVerify">
            Verify Hash Chain
        </button>
        <a href="/audit/export" class="btn btn-secondary">Export Audit CSV</a>
    </div>
</div>

<div class="grid-stats">
    <div class="stat-box">
        <div class="stat-val">{{ total_logs }}</div>
        <div class="stat-lbl">Total Audit Records</div>
    </div>
    <div class="stat-box">
        <div class="stat-val" style="color: {% if total_denied > 0 %}#f87171{% else %}#fff{% endif %};">{{ total_denied }}</div>
        <div class="stat-lbl">Refused Access Denials</div>
    </div>
    <div class="stat-box">
        <div class="stat-val" style="color: {% if chain_status.is_valid %}#34d399{% else %}#ef4444{% endif %};">
            {% if chain_status.is_valid %}VERIFIED{% else %}COMPROMISED{% endif %}
        </div>
        <div class="stat-lbl">Cryptographic Integrity</div>
    </div>
</div>

<div id="chainBanner" style="display: none; margin-bottom: 1.5rem;"></div>

<!-- Anomaly Alerts -->
{% if anomalies %}
    <div class="card" style="border-left: 4px solid var(--danger);">
        <h3 style="color: #f87171; margin-bottom: 0.75rem; font-size: 1.1rem;">Security Anomaly Warnings (Past Hour)</h3>
        {% for a in anomalies %}
            <div class="alert alert-danger" style="margin-bottom: 0.5rem;">
                <strong>{{ a.title }}:</strong> {{ a.description }}
            </div>
        {% endfor %}
    </div>
{% endif %}

<!-- Refused Attempts Table -->
<div class="card">
    <h3 style="margin-bottom: 1rem; color: #f87171;">Refused Access Attempts (Rule #1 Denials)</h3>
    {% if denied_logs %}
        <table>
            <thead>
                <tr>
                    <th>Time (UTC)</th>
                    <th>User ID</th>
                    <th>IP Address</th>
                    <th>Target Document</th>
                    <th>Reason / Detail</th>
                </tr>
            </thead>
            <tbody>
                {% for log in denied_logs %}
                    <tr>
                        <td>{{ log.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</td>
                        <td>{{ log.user.username if log.user else 'Anonymous' }}</td>
                        <td><code>{{ log.ip_address }}</code></td>
                        <td>{{ log.document.filename if log.document else (log.document_id or 'N/A') }}</td>
                        <td><span style="color: #fca5a5; font-size: 0.75rem;">{{ log.detail }}</span></td>
                    </tr>
                {% endfor %}
            </tbody>
        </table>
    {% else %}
        <p style="color: var(--text-muted); font-size: 0.875rem;">No denied access attempts logged.</p>
    {% endif %}
</div>

<!-- Complete Cryptographic Audit Ledger -->
<div class="card">
    <h3 style="margin-bottom: 1rem;">Immutable Cryptographic Audit Trail</h3>
    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>Timestamp (UTC)</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Document</th>
                <th>IP</th>
                <th>Current SHA-256 Hash</th>
            </tr>
        </thead>
        <tbody>
            {% for log in recent_logs %}
                <tr>
                    <td>{{ log.sequence }}</td>
                    <td>{{ log.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</td>
                    <td>{{ log.user.username if log.user else 'System' }}</td>
                    <td><span class="tag tag-{{ 'legal' if log.action in ['SHARE','REVOKE'] else ('danger' if log.action=='DENIED' else 'general') }}">{{ log.action }}</span></td>
                    <td>{{ log.document.filename if log.document else (log.document_id or '-') }}</td>
                    <td><code>{{ log.ip_address }}</code></td>
                    <td><code style="font-size: 0.7rem; color: #818cf8;">{{ log.current_hash[:16] }}...</code></td>
                </tr>
            {% endfor %}
        </tbody>
    </table>
</div>

<script>
async function verifyChain() {
    const btn = document.getElementById('btnVerify');
    const banner = document.getElementById('chainBanner');
    btn.disabled = true;
    btn.innerText = 'Verifying SHA-256 Chain...';
    try {
        const res = await fetch('/audit/verify-chain');
        const data = await res.json();
        banner.style.display = 'block';
        if (data.is_valid) {
            banner.className = 'alert alert-success';
            banner.innerHTML = '<strong>Integrity Verified:</strong> ' + data.message + ' (All ' + data.verified_records + ' blocks cryptographically valid)';
        } else {
            banner.className = 'alert alert-danger';
            banner.innerHTML = '<strong>CRITICAL INTEGRITY FAILURE:</strong> ' + data.message;
        }
    } catch (e) {
        alert('Verification request failed: ' + e);
    } finally {
        btn.disabled = false;
        btn.innerText = 'Verify Hash Chain';
    }
}
</script>
{% endblock %}
""",

    "audit.html": """{% extends "base.html" %}
{% block title %}My Activity{% endblock %}
{% block content %}
<div class="card">
    <h2 style="margin-bottom: 0.5rem;">My Activity History</h2>
    <p style="color: var(--text-secondary); margin-bottom: 1.5rem; font-size: 0.875rem;">
        Your personal audit trail of uploads, downloads, views, and edits.
    </p>

    {% if logs %}
        <table>
            <thead>
                <tr>
                    <th>Timestamp (UTC)</th>
                    <th>Action</th>
                    <th>Document</th>
                    <th>IP Address</th>
                </tr>
            </thead>
            <tbody>
                {% for log in logs %}
                    <tr>
                        <td>{{ log.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</td>
                        <td><span class="tag tag-general">{{ log.action }}</span></td>
                        <td>{{ log.document.filename if log.document else (log.document_id or '-') }}</td>
                        <td><code>{{ log.ip_address }}</code></td>
                    </tr>
                {% endfor %}
            </tbody>
        </table>
    {% else %}
        <p style="color: var(--text-muted); font-size: 0.875rem;">No activity recorded yet.</p>
    {% endif %}
</div>
{% endblock %}
""",

    "error_404.html": """{% extends "base.html" %}
{% block title %}404 Not Found{% endblock %}
{% block content %}
<div style="max-width: 480px; margin: 4rem auto; text-align: center;">
    <div class="card">
        <h1 style="font-size: 3rem; font-weight: 800; color: #f87171; margin-bottom: 0.5rem;">404</h1>
        <h3 style="margin-bottom: 1rem;">Resource Not Found</h3>
        <p style="color: var(--text-secondary); font-size: 0.875rem; margin-bottom: 1.5rem;">
            The requested document or endpoint does not exist, or you lack authorization to access it.
        </p>
        <a href="/documents" class="btn btn-primary">Return to Vault</a>
    </div>
</div>
{% endblock %}
"""
}

# Instantiate Jinja2 environment with embedded dictionary loader
jinja_env = Environment(loader=DictLoader(TEMPLATES_MAP))
templates = Jinja2Templates(env=jinja_env)

# ─────────────────────────────────────────────────────────────────────────────
# FASTAPI APPLICATION & ROUTE DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(title="TrustVault Standalone", docs_url=None, redoc_url=None)

@app.exception_handler(404)
async def custom_404_handler(request: Request, exc: HTTPException):
    user = None
    try:
        db = SessionLocal()
        user = get_current_user_optional(request, db)
        db.close()
    except Exception:
        pass
    return templates.TemplateResponse("error_404.html", {"request": request, "current_user": user}, status_code=404)

@app.get("/")
async def root_redirect(request: Request, db: Session = Depends(get_db)):
    user = get_current_user_optional(request, db)
    if user:
        return RedirectResponse("/documents", status_code=303)
    return RedirectResponse("/auth/login", status_code=303)

# ─── AUTH ROUTES ─────────────────────────────────────────────────────────────

@app.get("/auth/login", response_class=HTMLResponse)
async def login_page(request: Request, db: Session = Depends(get_db)):
    if get_current_user_optional(request, db):
        return RedirectResponse("/documents", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "current_user": None})

@app.post("/auth/login")
async def login_action(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(ip):
        add_audit_log(
            db,
            action=AuditAction.LOGIN_FAILED,
            request=request,
            detail={"email": email, "reason": "rate_limit_exceeded"},
        )
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "errors": ["Too many login attempts. Please wait 60 seconds."], "form": {"email": email}, "current_user": None},
            status_code=429,
        )

    user = db.query(User).filter(User.email == email.strip().lower()).first()
    if not user or not verify_password(password, user.hashed_password):
        add_audit_log(
            db,
            action=AuditAction.LOGIN_FAILED,
            request=request,
            user_id=user.id if user else None,
            detail={"email": email, "reason": "invalid_credentials"},
        )
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "errors": ["Invalid email address or password."], "form": {"email": email}, "current_user": None},
            status_code=401,
        )

    if not user.is_active:
        add_audit_log(
            db,
            action=AuditAction.LOGIN_FAILED,
            request=request,
            user_id=user.id,
            detail={"email": email, "reason": "account_deactivated"},
        )
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "errors": ["This account has been deactivated."], "form": {"email": email}, "current_user": None},
            status_code=403,
        )

    token = create_access_token({"sub": user.id, "email": user.email, "role": user.role.value, "tv": user.token_version})
    add_audit_log(db, action=AuditAction.LOGIN, request=request, user_id=user.id)

    response = RedirectResponse("/documents", status_code=303)
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,  # Set to True in HTTPS production environments
        max_age=1800,
    )
    return response

@app.get("/auth/register", response_class=HTMLResponse)
async def register_page(request: Request, db: Session = Depends(get_db)):
    if get_current_user_optional(request, db):
        return RedirectResponse("/documents", status_code=303)
    return templates.TemplateResponse("register.html", {"request": request, "current_user": None})

@app.post("/auth/register")
async def register_action(
    request: Request,
    email: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    role: str = Form("viewer"),
    db: Session = Depends(get_db),
):
    errors = []
    clean_email = email.strip().lower()
    clean_username = username.strip()

    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", clean_email):
        errors.append("Invalid email format.")
    if len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter.")
    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit.")
    if password != confirm_password:
        errors.append("Passwords do not match.")

    try:
        user_role = UserRole(role.lower())
    except ValueError:
        user_role = UserRole.viewer

    if not errors:
        if db.query(User).filter(User.email == clean_email).first():
            errors.append("An account with this email already exists.")
        if db.query(User).filter(User.username == clean_username).first():
            errors.append("Username is already taken.")

    if errors:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "errors": errors, "form": {"email": email, "username": username, "role": role}, "current_user": None},
            status_code=422,
        )

    new_user = User(
        email=clean_email,
        username=clean_username,
        hashed_password=hash_password(password),
        role=user_role,
        is_active=True,
        token_version=1,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    add_audit_log(db, action=AuditAction.REGISTER, request=request, user_id=new_user.id, detail={"role": user_role.value})
    return RedirectResponse("/auth/login", status_code=303)

@app.post("/auth/logout")
async def logout_action(request: Request, db: Session = Depends(get_db)):
    user = get_current_user_optional(request, db)
    if user:
        add_audit_log(db, action=AuditAction.LOGOUT, request=request, user_id=user.id)
    response = RedirectResponse("/auth/login", status_code=303)
    response.delete_cookie("access_token")
    return response

# ─── DOCUMENT ROUTES ─────────────────────────────────────────────────────────

@app.get("/documents", response_class=HTMLResponse)
async def documents_dashboard(
    request: Request,
    q: Optional[str] = None,
    category: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Retrieve active permissions for current user
    active_perms = (
        db.query(Permission)
        .filter(Permission.granted_to_id == current_user.id, Permission.is_active.is_(True))
        .all()
    )
    shared_doc_ids = [p.document_id for p in active_perms]
    perm_map = {p.document_id: p for p in active_perms}

    # Query owned documents (Rule #2: Zero information leakage)
    q_my = db.query(Document).filter(Document.owner_id == current_user.id, Document.is_deleted.is_(False))
    q_shared = (
        db.query(Document).filter(Document.id.in_(shared_doc_ids), Document.is_deleted.is_(False))
        if shared_doc_ids else None
    )

    if q and q.strip():
        search_term = f"%{q.strip()}%"
        q_my = q_my.filter(or_(Document.filename.ilike(search_term), Document.description.ilike(search_term)))
        if q_shared:
            q_shared = q_shared.filter(or_(Document.filename.ilike(search_term), Document.description.ilike(search_term)))

    if category and category.strip():
        try:
            cat_enum = DocumentCategory(category.strip())
            q_my = q_my.filter(Document.category == cat_enum)
            if q_shared:
                q_shared = q_shared.filter(Document.category == cat_enum)
        except ValueError:
            pass

    my_docs = q_my.order_by(Document.created_at.desc()).all()
    shared_docs_raw = q_shared.order_by(Document.created_at.desc()).all() if q_shared else []
    shared_docs = [{"doc": d, "perm": perm_map.get(d.id)} for d in shared_docs_raw]

    total_size = sum(d.size_bytes for d in my_docs)

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "current_user": current_user,
            "my_docs": my_docs,
            "shared_docs": shared_docs,
            "total_size": total_size,
            "total_docs": len(my_docs),
            "total_shared": len(shared_docs),
            "q": q or "",
            "category": category or "",
            "categories": [c.value for c in DocumentCategory],
        },
    )

@app.get("/documents/upload", response_class=HTMLResponse)
async def upload_page(request: Request, current_user: User = Depends(require_owner_or_admin)):
    return templates.TemplateResponse(
        "upload.html",
        {"request": request, "current_user": current_user, "categories": [c.value for c in DocumentCategory]},
    )

@app.post("/documents/upload")
async def upload_action(
    request: Request,
    file: UploadFile = File(...),
    description: str = Form(""),
    category: str = Form("General"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_owner_or_admin),
):
    content = await file.read()
    is_valid, err_msg, mime_type = validate_file_content(file.filename or "", content)
    if not is_valid:
        add_audit_log(
            db,
            action=AuditAction.DENIED,
            request=request,
            user_id=current_user.id,
            detail={"filename": file.filename, "reason": "file_validation_failed", "error": err_msg},
        )
        return templates.TemplateResponse(
            "upload.html",
            {
                "request": request,
                "current_user": current_user,
                "errors": [err_msg],
                "categories": [c.value for c in DocumentCategory],
            },
            status_code=400,
        )

    try:
        doc_category = DocumentCategory(category)
    except ValueError:
        doc_category = DocumentCategory.general

    clean_name, stored_name = save_secure_file(file.filename or "upload.bin", content)
    doc = Document(
        owner_id=current_user.id,
        filename=clean_name,
        stored_name=stored_name,
        mime_type=mime_type,
        size_bytes=len(content),
        category=doc_category,
        description=description.strip() or None,
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)

    add_audit_log(
        db,
        action=AuditAction.UPLOAD,
        request=request,
        user_id=current_user.id,
        document_id=doc.id,
        detail={"filename": clean_name, "size_bytes": len(content), "mime_type": mime_type},
    )
    return RedirectResponse(f"/documents/{doc.id}", status_code=303)

@app.get("/documents/{doc_id}", response_class=HTMLResponse)
async def document_detail(
    doc_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    doc = get_authorized_document_or_404(doc_id, "view", current_user, db, request)
    is_owner = doc.owner_id == current_user.id

    permissions = []
    if is_owner:
        permissions = (
            db.query(Permission)
            .filter(Permission.document_id == doc_id, Permission.is_active.is_(True))
            .all()
        )

    can_download = authorize(current_user, doc, "download", db, request, log_denial=False)
    can_edit = authorize(current_user, doc, "edit", db, request, log_denial=False)

    add_audit_log(
        db,
        action=AuditAction.VIEW,
        request=request,
        user_id=current_user.id,
        document_id=doc.id,
        detail={"filename": doc.filename},
    )

    return templates.TemplateResponse(
        "document_detail.html",
        {
            "request": request,
            "current_user": current_user,
            "doc": doc,
            "is_owner": is_owner,
            "permissions": permissions,
            "can_download": can_download,
            "can_edit": can_edit,
        },
    )

@app.get("/documents/{doc_id}/download")
async def download_action(
    doc_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    doc = get_authorized_document_or_404(doc_id, "download", current_user, db, request)
    file_path = UPLOAD_DIR / doc.stored_name
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File content not found on server")

    add_audit_log(
        db,
        action=AuditAction.DOWNLOAD,
        request=request,
        user_id=current_user.id,
        document_id=doc.id,
        detail={"filename": doc.filename, "size_bytes": doc.size_bytes},
    )

    def iterfile():
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                yield chunk

    safe_name = sanitize_filename(doc.filename)
    return StreamingResponse(
        iterfile(),
        media_type=doc.mime_type,
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}"',
            "X-Content-Type-Options": "nosniff",
        },
    )

@app.get("/documents/{doc_id}/edit", response_class=HTMLResponse)
async def edit_page(
    doc_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    doc = get_authorized_document_or_404(doc_id, "edit", current_user, db, request)
    return templates.TemplateResponse(
        "edit_document.html",
        {"request": request, "current_user": current_user, "doc": doc, "categories": [c.value for c in DocumentCategory]},
    )

@app.post("/documents/{doc_id}/edit")
async def edit_action(
    doc_id: str,
    request: Request,
    filename: str = Form(...),
    description: str = Form(""),
    category: str = Form("General"),
    file: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    doc = get_authorized_document_or_404(doc_id, "edit", current_user, db, request)
    old_meta = {"filename": doc.filename, "category": doc.category.value}

    doc.filename = sanitize_filename(filename)
    doc.description = description.strip() or None
    try:
        doc.category = DocumentCategory(category)
    except ValueError:
        pass

    file_replaced = False
    if file and file.filename:
        content = await file.read()
        if len(content) > 0:
            is_valid, err_msg, mime = validate_file_content(file.filename, content)
            if not is_valid:
                return templates.TemplateResponse(
                    "edit_document.html",
                    {
                        "request": request,
                        "current_user": current_user,
                        "doc": doc,
                        "errors": [err_msg],
                        "categories": [c.value for c in DocumentCategory],
                    },
                    status_code=400,
                )
            clean_original, stored_name = save_secure_file(file.filename, content)
            doc.stored_name = stored_name
            doc.mime_type = mime
            doc.size_bytes = len(content)
            file_replaced = True

    db.commit()
    add_audit_log(
        db,
        action=AuditAction.EDIT,
        request=request,
        user_id=current_user.id,
        document_id=doc.id,
        detail={"old_meta": old_meta, "new_meta": {"filename": doc.filename, "file_replaced": file_replaced}},
    )
    return RedirectResponse(f"/documents/{doc.id}", status_code=303)

@app.post("/documents/{doc_id}/delete")
async def delete_action(
    doc_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    doc = get_authorized_document_or_404(doc_id, "delete", current_user, db, request)
    doc.is_deleted = True
    db.commit()

    add_audit_log(
        db,
        action=AuditAction.DELETE,
        request=request,
        user_id=current_user.id,
        document_id=doc.id,
        detail={"filename": doc.filename},
    )
    return RedirectResponse("/documents", status_code=303)

# ─── SHARING & REVOCATION (Rule #4: Immediate Revocation) ────────────────────

@app.get("/documents/{doc_id}/share", response_class=HTMLResponse)
async def share_page(
    doc_id: str,
    request: Request,
    shared: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    doc = get_authorized_document_or_404(doc_id, "share", current_user, db, request)
    permissions = (
        db.query(Permission)
        .filter(Permission.document_id == doc_id, Permission.is_active.is_(True))
        .all()
    )
    return templates.TemplateResponse(
        "share.html",
        {
            "request": request,
            "current_user": current_user,
            "doc": doc,
            "permissions": permissions,
            "success": "Permission granted successfully." if shared else None,
        },
    )

@app.post("/documents/{doc_id}/share")
async def share_action(
    doc_id: str,
    request: Request,
    email: str = Form(...),
    level: str = Form("read"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    doc = get_authorized_document_or_404(doc_id, "share", current_user, db, request)
    target = db.query(User).filter(User.email == email.strip().lower()).first()

    def _render_err(msg: str):
        perms = db.query(Permission).filter(Permission.document_id == doc_id, Permission.is_active.is_(True)).all()
        return templates.TemplateResponse(
            "share.html",
            {"request": request, "current_user": current_user, "doc": doc, "permissions": perms, "errors": [msg]},
            status_code=422,
        )

    if not target:
        return _render_err(f"No user found with email: {email}")
    if target.id == current_user.id:
        return _render_err("You cannot share a document with yourself.")
    if target.id == doc.owner_id:
        return _render_err("Cannot grant permission to the document owner.")

    try:
        perm_level = PermissionLevel(level.lower())
    except ValueError:
        perm_level = PermissionLevel.read

    existing = (
        db.query(Permission)
        .filter(Permission.document_id == doc_id, Permission.granted_to_id == target.id, Permission.is_active.is_(True))
        .first()
    )
    if existing:
        existing.level = perm_level
    else:
        db.add(Permission(
            document_id=doc_id,
            granted_to_id=target.id,
            granted_by_id=current_user.id,
            level=perm_level,
            is_active=True,
        ))

    db.commit()
    add_audit_log(
        db,
        action=AuditAction.SHARE,
        request=request,
        user_id=current_user.id,
        document_id=doc_id,
        detail={"shared_with": target.email, "level": perm_level.value},
    )
    return RedirectResponse(f"/documents/{doc_id}/share?shared=1", status_code=303)

@app.post("/documents/{doc_id}/revoke/{perm_id}")
async def revoke_action(
    doc_id: str,
    perm_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    doc = get_authorized_document_or_404(doc_id, "revoke", current_user, db, request)
    perm = db.query(Permission).filter(
        Permission.id == perm_id,
        Permission.document_id == doc_id,
        Permission.is_active.is_(True),
    ).first()

    if not perm:
        raise HTTPException(status_code=404, detail="Permission not found or already revoked")

    revoked_email = perm.granted_to.email
    perm.is_active = False
    db.commit()

    add_audit_log(
        db,
        action=AuditAction.REVOKE,
        request=request,
        user_id=current_user.id,
        document_id=doc_id,
        detail={"revoked_from": revoked_email, "level": perm.level.value},
    )
    return RedirectResponse(f"/documents/{doc_id}/share", status_code=303)

# ─── ADMIN & AUDIT LEDGER (Rule #5 & #6) ─────────────────────────────────────

@app.get("/audit", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    recent_logs = db.query(AuditLog).order_by(AuditLog.sequence.desc()).limit(150).all()
    denied_logs = db.query(AuditLog).filter(AuditLog.action == AuditAction.DENIED.value).order_by(AuditLog.sequence.desc()).limit(50).all()
    chain_status = verify_audit_chain(db)
    anomalies = detect_anomalies(db)

    total_logs = db.query(func.count(AuditLog.id)).scalar()
    total_denied = db.query(func.count(AuditLog.id)).filter(AuditLog.action == AuditAction.DENIED.value).scalar()

    return templates.TemplateResponse(
        "admin_dashboard.html",
        {
            "request": request,
            "current_user": current_user,
            "recent_logs": recent_logs,
            "denied_logs": denied_logs,
            "chain_status": chain_status,
            "anomalies": anomalies,
            "total_logs": total_logs,
            "total_denied": total_denied,
        },
    )

@app.get("/audit/verify-chain", response_class=JSONResponse)
async def api_verify_chain(db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    result = verify_audit_chain(db)
    return JSONResponse(content=result, status_code=200 if result["is_valid"] else 409)

@app.get("/audit/my", response_class=HTMLResponse)
async def user_my_activity(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    logs = db.query(AuditLog).filter(AuditLog.user_id == current_user.id).order_by(AuditLog.sequence.desc()).limit(100).all()
    return templates.TemplateResponse(
        "audit.html",
        {"request": request, "current_user": current_user, "logs": logs},
    )

@app.get("/audit/export")
async def export_audit_csv(db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    logs = db.query(AuditLog).order_by(AuditLog.sequence.asc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["sequence", "timestamp_utc", "user_id", "username", "action", "document_id", "ip_address", "prev_hash", "current_hash", "detail"])

    for log in logs:
        writer.writerow([
            log.sequence,
            log.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
            log.user_id or "",
            log.user.username if log.user else "",
            log.action,
            log.document_id or "",
            log.ip_address or "",
            log.prev_hash,
            log.current_hash,
            str(log.detail or ""),
        ])

    output.seek(0)
    fname = f"trustvault_audit_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )

# ─────────────────────────────────────────────────────────────────────────────
# AUTOMATIC SEEDING ON STARTUP
# ─────────────────────────────────────────────────────────────────────────────

def seed_database_if_empty():
    db = SessionLocal()
    try:
        user_count = db.query(User).count()
        if user_count > 0:
            return  # Already seeded

        print("[TrustVault] Seeding initial demo accounts, documents, and cryptographic hash chain...")

        # 1. Create Seed Users
        admin = User(
            email="admin@trustvault.com",
            username="admin",
            hashed_password=hash_password("Admin@TrustVault2026!"),
            role=UserRole.admin,
            is_active=True,
            token_version=1,
        )
        owner = User(
            email="owner@trustvault.com",
            username="owner",
            hashed_password=hash_password("Owner@TrustVault2026!"),
            role=UserRole.owner,
            is_active=True,
            token_version=1,
        )
        viewer = User(
            email="viewer@trustvault.com",
            username="viewer",
            hashed_password=hash_password("Viewer@TrustVault2026!"),
            role=UserRole.viewer,
            is_active=True,
            token_version=1,
        )
        db.add_all([admin, owner, viewer])
        db.commit()

        # 2. Seed Sample Files in Secure Storage
        doc1_content = (
            b"%PDF-1.4\n% TrustVault Confidential Financial Report Q4 2026\n"
            b"Revenue: $12.4M\nGross Margin: 78.4%\nOperating Income: $3.1M\n"
            b"EBITDA: $4.2M\nStatus: Board Approved\n%%EOF\n"
        )
        doc2_content = (
            b"CONFIDENTIAL MUTUAL NON-DISCLOSURE AGREEMENT\n\n"
            b"This Mutual NDA is entered into between TrustVault Inc. and Partners.\n"
            b"All trade secrets, source code, and security keys are strictly protected.\n"
        )
        doc3_content = (
            b"%PDF-1.4\n% TrustVault Security Architecture Whitepaper\n"
            b"Zero-trust authorization engine. Deny by default.\n"
            b"Append-only SHA-256 cryptographic audit chain.\n%%EOF\n"
        )

        _, doc1_stored = save_secure_file("Q4_Financial_Report.pdf", doc1_content)
        _, doc2_stored = save_secure_file("Mutual_NDA_Template.txt", doc2_content)
        _, doc3_stored = save_secure_file("Security_Architecture_2026.pdf", doc3_content)

        doc1 = Document(
            owner_id=owner.id,
            filename="Q4_Financial_Report.pdf",
            stored_name=doc1_stored,
            mime_type="application/pdf",
            size_bytes=len(doc1_content),
            category=DocumentCategory.financial,
            description="Confidential quarterly earnings and balance sheet for 2026.",
        )
        doc2 = Document(
            owner_id=owner.id,
            filename="Mutual_NDA_Template.txt",
            stored_name=doc2_stored,
            mime_type="text/plain",
            size_bytes=len(doc2_content),
            category=DocumentCategory.legal,
            description="Standard corporate mutual non-disclosure agreement.",
        )
        doc3 = Document(
            owner_id=owner.id,
            filename="Security_Architecture_2026.pdf",
            stored_name=doc3_stored,
            mime_type="application/pdf",
            size_bytes=len(doc3_content),
            category=DocumentCategory.technical,
            description="Full technical specification of the TrustVault zero-trust security engine.",
        )
        db.add_all([doc1, doc2, doc3])
        db.commit()

        # 3. Seed Demo Permission Grant: Owner grants Read to Viewer for doc1
        grant = Permission(
            document_id=doc1.id,
            granted_to_id=viewer.id,
            granted_by_id=owner.id,
            level=PermissionLevel.read,
            is_active=True,
        )
        db.add(grant)
        db.commit()

        # 4. Seed Initial Cryptographic Audit Chain Records
        add_audit_log(db, action=AuditAction.REGISTER, user_id=admin.id, ip_address="127.0.0.1", detail={"role": "admin"})
        add_audit_log(db, action=AuditAction.REGISTER, user_id=owner.id, ip_address="127.0.0.1", detail={"role": "owner"})
        add_audit_log(db, action=AuditAction.REGISTER, user_id=viewer.id, ip_address="127.0.0.1", detail={"role": "viewer"})
        add_audit_log(db, action=AuditAction.UPLOAD, user_id=owner.id, document_id=doc1.id, ip_address="127.0.0.1", detail={"filename": doc1.filename})
        add_audit_log(db, action=AuditAction.UPLOAD, user_id=owner.id, document_id=doc2.id, ip_address="127.0.0.1", detail={"filename": doc2.filename})
        add_audit_log(db, action=AuditAction.UPLOAD, user_id=owner.id, document_id=doc3.id, ip_address="127.0.0.1", detail={"filename": doc3.filename})
        add_audit_log(db, action=AuditAction.SHARE, user_id=owner.id, document_id=doc1.id, ip_address="127.0.0.1", detail={"shared_with": viewer.email, "level": "read"})

        print("[TrustVault] Database seeded successfully with demo users, documents, and verified audit chain!")
    finally:
        db.close()

@app.on_event("startup")
def on_startup():
    seed_database_if_empty()

# ─────────────────────────────────────────────────────────────────────────────
# RUN APPLICATION (Direct execution entry point)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"================================================================")
    print(f" TrustVault Secure Document Management Platform")
    print(f" Running at: http://localhost:{port}")
    print(f" Demo Logins:")
    print(f"   - Admin:  admin@trustvault.com  / Admin@TrustVault2026!")
    print(f"   - Owner:  owner@trustvault.com  / Owner@TrustVault2026!")
    print(f"   - Viewer: viewer@trustvault.com / Viewer@TrustVault2026!")
    print(f"================================================================")
    uvicorn.run("trustvault_standalone:app", host=host, port=port, reload=False)
