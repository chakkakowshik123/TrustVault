"""Audit router: admin activity dashboard, hash chain verification, CSV export."""
import csv
import io
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditLog, User, AuditAction
from ..security import get_current_user, require_admin
from ..audit_chain import verify_audit_chain

router = APIRouter(prefix="/audit", tags=["audit"])
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


def detect_anomalies(db: Session) -> List[Dict[str, Any]]:
    """Scan recent audit logs for security anomalies (Rule #6)."""
    anomalies = []
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)

    # 1. Check for brute-force or high denied attempts per user / IP
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

    # 2. Check for multiple failed logins
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


@router.get("", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Admin Activity & Security Dashboard (Rule #6)."""
    # Recent activity logs (all types)
    recent_logs = (
        db.query(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .limit(200)
        .all()
    )

    # Refused attempts (DENIED)
    denied_logs = (
        db.query(AuditLog)
        .filter(AuditLog.action == AuditAction.DENIED.value)
        .order_by(AuditLog.timestamp.desc())
        .limit(50)
        .all()
    )

    # Permission changes (SHARE / REVOKE)
    permission_changes = (
        db.query(AuditLog)
        .filter(AuditLog.action.in_([AuditAction.SHARE.value, AuditAction.REVOKE.value]))
        .order_by(AuditLog.timestamp.desc())
        .limit(50)
        .all()
    )

    # Cryptographic Hash Chain Verification (Rule #5)
    chain_status = verify_audit_chain(db)

    # Anomaly flags
    anomalies = detect_anomalies(db)
    if not chain_status["is_valid"]:
        anomalies.insert(0, {
            "severity": "critical",
            "title": "CRYPTOGRAPHIC CHAIN CORRUPTION",
            "description": chain_status["message"],
        })

    total_logs = db.query(func.count(AuditLog.id)).scalar()
    total_denied = db.query(func.count(AuditLog.id)).filter(AuditLog.action == AuditAction.DENIED.value).scalar()

    return templates.TemplateResponse(
        "admin_dashboard.html",
        {
            "request": request,
            "current_user": current_user,
            "recent_logs": recent_logs,
            "denied_logs": denied_logs,
            "permission_changes": permission_changes,
            "chain_status": chain_status,
            "anomalies": anomalies,
            "total_logs": total_logs,
            "total_denied": total_denied,
        },
    )


@router.get("/verify-chain", response_class=JSONResponse)
async def api_verify_chain(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """API endpoint to verify the audit log cryptographic hash chain."""
    result = verify_audit_chain(db)
    return JSONResponse(content=result, status_code=200 if result["is_valid"] else 409)


@router.get("/my", response_class=HTMLResponse)
async def audit_my(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Personal activity history for authenticated user."""
    logs = (
        db.query(AuditLog)
        .filter(AuditLog.user_id == current_user.id)
        .order_by(AuditLog.timestamp.desc())
        .limit(200)
        .all()
    )
    return templates.TemplateResponse(
        "audit.html",
        {
            "request": request,
            "current_user": current_user,
            "logs": logs,
            "is_admin_view": False,
        },
    )


@router.get("/export")
async def export_csv(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Export the complete audit trail and cryptographic hashes as CSV."""
    logs = db.query(AuditLog).order_by(AuditLog.sequence.asc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "sequence",
        "timestamp_utc",
        "user_id",
        "username",
        "action",
        "document_id",
        "ip_address",
        "prev_hash",
        "current_hash",
        "detail",
    ])

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
    fname = f"trustvault_audit_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )
