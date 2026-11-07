"""Sharing router: grant and revoke document permissions."""
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditAction, Document, Permission, PermissionLevel, User
from ..security import get_current_user
from ..authz import authorize, get_authorized_document_or_404
from ..audit_chain import add_audit_log

router = APIRouter(prefix="/documents", tags=["sharing"])
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


# ─── Share Management Page ───────────────────────────────────────────────────

@router.get("/{doc_id}/share", response_class=HTMLResponse)
async def share_page(
    doc_id: str,
    request: Request,
    shared: str = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Rule #1 & #3: Central authorize call, returns 404 if unauthorized
    doc = get_authorized_document_or_404(doc_id, "share", current_user, db, request)

    permissions = (
        db.query(Permission)
        .filter(Permission.document_id == doc_id, Permission.is_active.is_(True))
        .all()
    )
    success = "Permission granted successfully." if shared else None

    return templates.TemplateResponse(
        "share.html",
        {
            "request": request,
            "current_user": current_user,
            "doc": doc,
            "permissions": permissions,
            "success": success,
        },
    )


# ─── Grant Permission ─────────────────────────────────────────────────────────

@router.post("/{doc_id}/share")
async def share_document(
    doc_id: str,
    request: Request,
    email: str = Form(...),
    level: str = Form("read"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    doc = get_authorized_document_or_404(doc_id, "share", current_user, db, request)

    # Validate permission level
    try:
        perm_level = PermissionLevel(level.lower())
    except ValueError:
        perm_level = PermissionLevel.read

    def _render_error(error_msg: str):
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
                "errors": [error_msg],
                "form": {"email": email},
            },
            status_code=422,
        )

    # Lookup target recipient
    target = db.query(User).filter(User.email == email.strip().lower()).first()
    if not target:
        return _render_error(f"No registered user found with email: {email}")
    if target.id == current_user.id:
        return _render_error("You cannot share a document with yourself.")
    if target.id == doc.owner_id:
        return _render_error("Cannot grant permission to the document owner — they already own the file.")

    # Upsert permission
    existing = (
        db.query(Permission)
        .filter(
            Permission.document_id == doc_id,
            Permission.granted_to_id == target.id,
            Permission.is_active.is_(True),
        )
        .first()
    )
    if existing:
        old_level = existing.level.value
        existing.level = perm_level
        action_detail = {
            "shared_with": email,
            "level": perm_level.value,
            "previous_level": old_level,
            "updated": True,
        }
    else:
        db.add(Permission(
            document_id=doc_id,
            granted_to_id=target.id,
            granted_by_id=current_user.id,
            level=perm_level,
        ))
        action_detail = {"shared_with": email, "level": perm_level.value, "new": True}

    db.commit()

    add_audit_log(
        db,
        action=AuditAction.SHARE,
        request=request,
        user_id=current_user.id,
        document_id=doc_id,
        detail=action_detail,
    )

    return RedirectResponse(f"/documents/{doc_id}/share?shared=1", status_code=303)


# ─── Revoke Permission (Rule #4: Immediate Revocation) ────────────────────────

@router.post("/{doc_id}/revoke/{perm_id}")
async def revoke_permission(
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
        raise HTTPException(status_code=404, detail="Permission record not found or already revoked")

    revoked_user_email = perm.granted_to.email
    revoked_level = perm.level.value
    perm.is_active = False
    db.commit()

    add_audit_log(
        db,
        action=AuditAction.REVOKE,
        request=request,
        user_id=current_user.id,
        document_id=doc_id,
        detail={"revoked_from": revoked_user_email, "level": revoked_level},
    )

    return RedirectResponse(f"/documents/{doc_id}/share", status_code=303)
