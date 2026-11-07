"""Central Authorization Engine for TrustVault (Rule #1: Deny-by-default)."""
from typing import Optional, Literal
from fastapi import Request, HTTPException
from sqlalchemy.orm import Session

from .models import User, Document, Permission, PermissionLevel, UserRole, AuditAction
from .audit_chain import add_audit_log


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
        # Edit level allows reading/downloading and editing metadata/content
        if action in ("view", "download", "edit"):
            allowed = True
    elif grant.level == PermissionLevel.read:
        # Read level allows viewing metadata and downloading file
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
    user: Optional[User],
    db: Session,
    request: Optional[Request] = None,
) -> Document:
    """
    Retrieve document and authorize requested action.
    Returns 404 on NOT FOUND or UNAUTHORIZED to avoid leaking existence (Rule #3).
    """
    doc = db.query(Document).filter(Document.id == doc_id, Document.is_deleted.is_(False)).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    if not authorize(user=user, document=doc, action=action, db=db, request=request, log_denial=True):
        # Return 404 instead of 403 to prevent enumeration / IDOR existence leak
        raise HTTPException(status_code=404, detail="Document not found")

    return doc
