"""Documents router: upload, search, detail, download, edit, and delete."""
import os
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import or_, and_, desc
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import AuditAction, Document, DocumentCategory, Permission, PermissionLevel, User, UserRole
from ..security import get_current_user, require_owner_or_admin
from ..authz import authorize, get_authorized_document_or_404
from ..audit_chain import add_audit_log
from ..file_utils import validate_file_content, save_secure_file, sanitize_filename

router = APIRouter(prefix="/documents", tags=["documents"])
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


# ─── Dashboard & Search (Rule #2: Zero Information Leakage) ───────────────────

@router.get("", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    q: Optional[str] = None,
    category: Optional[str] = None,
    owner: Optional[str] = None,
    sort: Optional[str] = "date_desc",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Dashboard view.
    Searches and lists only documents the current user is authorized to view.
    Never leaks metadata or titles of documents belonging to other users.
    """
    # Active permissions granted to the current user
    active_perms = (
        db.query(Permission)
        .filter(Permission.granted_to_id == current_user.id, Permission.is_active.is_(True))
        .all()
    )
    shared_doc_ids = [p.document_id for p in active_perms]
    perm_map = {p.document_id: p for p in active_perms}

    # Base query: owned documents OR explicitly granted documents
    query_my = db.query(Document).filter(
        Document.owner_id == current_user.id,
        Document.is_deleted.is_(False),
    )
    query_shared = db.query(Document).filter(
        Document.id.in_(shared_doc_ids),
        Document.is_deleted.is_(False),
    ) if shared_doc_ids else None

    # Apply search filter by filename / description
    if q and q.strip():
        search_pattern = f"%{q.strip()}%"
        query_my = query_my.filter(
            or_(
                Document.filename.ilike(search_pattern),
                Document.description.ilike(search_pattern),
            )
        )
        if query_shared:
            query_shared = query_shared.filter(
                or_(
                    Document.filename.ilike(search_pattern),
                    Document.description.ilike(search_pattern),
                )
            )

    # Filter by category
    if category and category.strip():
        try:
            cat_enum = DocumentCategory(category.strip())
            query_my = query_my.filter(Document.category == cat_enum)
            if query_shared:
                query_shared = query_shared.filter(Document.category == cat_enum)
        except ValueError:
            pass

    # Filter by owner username
    if owner and owner.strip():
        owner_pattern = f"%{owner.strip()}%"
        query_my = query_my.join(Document.owner).filter(User.username.ilike(owner_pattern))
        if query_shared:
            query_shared = query_shared.join(Document.owner).filter(User.username.ilike(owner_pattern))

    # Sorting
    if sort == "name_asc":
        query_my = query_my.order_by(Document.filename.asc())
    elif sort == "size_desc":
        query_my = query_my.order_by(Document.size_bytes.desc())
    else:  # date_desc default
        query_my = query_my.order_by(Document.created_at.desc())

    my_docs = query_my.all()
    shared_docs_raw = query_shared.all() if query_shared else []
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
            "owner": owner or "",
            "sort": sort or "date_desc",
            "categories": [c.value for c in DocumentCategory],
        },
    )


# ─── Upload (Owner & Admin only, Magic Bytes Validated) ───────────────────────

@router.get("/upload", response_class=HTMLResponse)
async def upload_page(
    request: Request,
    current_user: User = Depends(require_owner_or_admin),
):
    return templates.TemplateResponse(
        "upload.html",
        {
            "request": request,
            "current_user": current_user,
            "categories": [c.value for c in DocumentCategory],
        },
    )


@router.post("/upload")
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    description: str = Form(""),
    category: str = Form("General"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_owner_or_admin),
):
    content = await file.read()

    # Deep content & magic byte validation
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

    # Validate category enum
    try:
        doc_category = DocumentCategory(category)
    except ValueError:
        doc_category = DocumentCategory.general

    # Store with randomized UUID name outside web root
    clean_original, stored_name = save_secure_file(file.filename or "upload.bin", content)

    doc = Document(
        owner_id=current_user.id,
        filename=clean_original,
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
        detail={
            "filename": clean_original,
            "size_bytes": len(content),
            "mime_type": mime_type,
            "category": doc_category.value,
        },
    )

    return RedirectResponse(f"/documents/{doc.id}", status_code=303)


# ─── Detail ───────────────────────────────────────────────────────────────────

@router.get("/{doc_id}", response_class=HTMLResponse)
async def document_detail(
    doc_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Rule #1 & #3: Central authorize call, returns 404 if unauthorized
    doc = get_authorized_document_or_404(doc_id, "view", current_user, db, request)

    is_owner = doc.owner_id == current_user.id
    perm = (
        db.query(Permission)
        .filter(
            Permission.document_id == doc_id,
            Permission.granted_to_id == current_user.id,
            Permission.is_active.is_(True),
        )
        .first()
    )

    permissions = []
    if is_owner:
        permissions = (
            db.query(Permission)
            .filter(Permission.document_id == doc_id, Permission.is_active.is_(True))
            .all()
        )

    can_download = authorize(current_user, doc, "download", db, request, log_denial=False)
    can_edit = authorize(current_user, doc, "edit", db, request, log_denial=False)
    can_share = is_owner

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
            "user_perm": perm,
            "permissions": permissions,
            "can_download": can_download,
            "can_edit": can_edit,
            "can_share": can_share,
        },
    )


# ─── Download ─────────────────────────────────────────────────────────────────

@router.get("/{doc_id}/download")
async def download_document(
    doc_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Rule #1 & #3: Central authorize call, returns 404 if unauthorized
    doc = get_authorized_document_or_404(doc_id, "download", current_user, db, request)

    file_path = settings.UPLOAD_DIR / doc.stored_name
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


# ─── Edit (Owner or Edit Permission) ──────────────────────────────────────────

@router.get("/{doc_id}/edit", response_class=HTMLResponse)
async def edit_page(
    doc_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    doc = get_authorized_document_or_404(doc_id, "edit", current_user, db, request)
    return templates.TemplateResponse(
        "edit_document.html",
        {
            "request": request,
            "current_user": current_user,
            "doc": doc,
            "categories": [c.value for c in DocumentCategory],
        },
    )


@router.post("/{doc_id}/edit")
async def edit_document(
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

    old_meta = {
        "filename": doc.filename,
        "description": doc.description,
        "category": doc.category.value if hasattr(doc.category, "value") else str(doc.category),
    }

    clean_name = sanitize_filename(filename)
    doc.filename = clean_name
    doc.description = description.strip() or None
    try:
        doc.category = DocumentCategory(category)
    except ValueError:
        pass

    # Optional file replacement with magic byte check
    file_replaced = False
    if file and file.filename:
        content = await file.read()
        if len(content) > 0:
            is_valid, err_msg, mime_type = validate_file_content(file.filename, content)
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
            doc.mime_type = mime_type
            doc.size_bytes = len(content)
            file_replaced = True

    db.commit()

    add_audit_log(
        db,
        action=AuditAction.EDIT,
        request=request,
        user_id=current_user.id,
        document_id=doc.id,
        detail={
            "old_meta": old_meta,
            "new_meta": {
                "filename": doc.filename,
                "category": doc.category.value,
                "file_replaced": file_replaced,
            },
        },
    )

    return RedirectResponse(f"/documents/{doc.id}", status_code=303)


# ─── Delete (Owner only) ──────────────────────────────────────────────────────

@router.post("/{doc_id}/delete")
async def delete_document(
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
