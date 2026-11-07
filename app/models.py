"""SQLAlchemy ORM models for TrustVault."""
import uuid
import enum
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Column, String, Boolean, DateTime, Integer,
    ForeignKey, Enum, Text, JSON, DDL, event
)
from sqlalchemy.orm import relationship

from .database import Base


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

    documents = relationship(
        "Document", back_populates="owner", foreign_keys="Document.owner_id"
    )
    permissions_granted = relationship(
        "Permission", back_populates="granted_to", foreign_keys="Permission.granted_to_id"
    )
    audit_logs = relationship("AuditLog", back_populates="user", foreign_keys="AuditLog.user_id")

    def __repr__(self) -> str:
        return f"<User {self.username} ({self.role})>"


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
    permissions = relationship(
        "Permission", back_populates="document", cascade="all, delete-orphan"
    )
    audit_logs = relationship("AuditLog", back_populates="document", foreign_keys="AuditLog.document_id")

    def __repr__(self) -> str:
        return f"<Document {self.filename}>"


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

    def __repr__(self) -> str:
        return f"<Permission {self.level} on {self.document_id} to {self.granted_to_id}>"


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

    def __repr__(self) -> str:
        return f"<AuditLog #{self.sequence} {self.action} by {self.user_id}>"


# Database-level triggers to enforce append-only audit log (reject UPDATE and DELETE)
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
