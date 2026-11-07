"""Append-only cryptographic hash chain for TrustVault audit logs."""
import hashlib
import json
from datetime import datetime
from typing import Optional, Any, Dict
from fastapi import Request
from sqlalchemy.orm import Session

from .models import AuditLog, AuditAction


GENESIS_HASH = "0" * 64


def serialize_detail(detail: Optional[Dict[str, Any]]) -> str:
    """Deterministically serialize detail dictionary."""
    if not detail:
        return ""
    try:
        return json.dumps(detail, sort_keys=True, separators=(",", ":"), default=str)
    except Exception:
        return str(detail)


def compute_audit_hash(
    prev_hash: str,
    user_id: Optional[str],
    document_id: Optional[str],
    action: str,
    timestamp: datetime,
    ip_address: Optional[str],
    detail_str: str,
) -> str:
    """Compute SHA-256 hash for an audit record linked to prev_hash."""
    iso_time = timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")
    payload = f"{prev_hash}|{user_id or ''}|{document_id or ''}|{action}|{iso_time}|{ip_address or ''}|{detail_str}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def get_latest_audit_hash(db: Session) -> str:
    """Return the hash of the latest audit log entry or GENESIS_HASH."""
    last_log = db.query(AuditLog).order_by(AuditLog.sequence.desc()).first()
    if last_log and last_log.current_hash:
        return last_log.current_hash
    return GENESIS_HASH


def add_audit_log(
    db: Session,
    action: str | AuditAction,
    request: Optional[Request] = None,
    user_id: Optional[str] = None,
    document_id: Optional[str] = None,
    detail: Optional[Dict[str, Any]] = None,
    ip_override: Optional[str] = None,
) -> AuditLog:
    """Append a new record to the audit log with hash chain integrity."""
    action_str = action.value if isinstance(action, AuditAction) else str(action)
    
    ip_address = ip_override
    user_agent = ""
    if request:
        if not ip_address:
            ip_address = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "")
    elif not ip_address:
        ip_address = "system"

    now = datetime.utcnow()
    detail_str = serialize_detail(detail)

    # Get hash of preceding record
    prev_hash = get_latest_audit_hash(db)
    current_hash = compute_audit_hash(
        prev_hash=prev_hash,
        user_id=user_id,
        document_id=document_id,
        action=action_str,
        timestamp=now,
        ip_address=ip_address,
        detail_str=detail_str,
    )

    log_entry = AuditLog(
        user_id=user_id,
        document_id=document_id,
        action=action_str,
        ip_address=ip_address,
        user_agent=user_agent,
        detail=detail or {},
        timestamp=now,
        prev_hash=prev_hash,
        current_hash=current_hash,
    )

    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry


def verify_audit_chain(db: Session) -> Dict[str, Any]:
    """
    Verify the cryptographic hash chain of the entire audit log.
    Returns status dict indicating validity and any tampered record.
    """
    logs = db.query(AuditLog).order_by(AuditLog.sequence.asc()).all()
    if not logs:
        return {
            "is_valid": True,
            "total_records": 0,
            "broken_at_sequence": None,
            "message": "Audit log is empty. Chain is intact (genesis state).",
        }

    expected_prev = GENESIS_HASH
    for i, log in enumerate(logs):
        # 1. Verify prev_hash matches the previous record's current_hash
        if log.prev_hash != expected_prev:
            return {
                "is_valid": False,
                "total_records": len(logs),
                "broken_at_sequence": log.sequence,
                "broken_at_id": log.id,
                "reason": "Previous hash pointer mismatch",
                "message": f"Hash chain broken at record #{log.sequence}. Stored prev_hash {log.prev_hash[:16]}... does not match expected {expected_prev[:16]}...",
            }

        # 2. Re-compute hash of this record and verify
        detail_str = serialize_detail(log.detail)
        recalculated_hash = compute_audit_hash(
            prev_hash=log.prev_hash,
            user_id=log.user_id,
            document_id=log.document_id,
            action=log.action,
            timestamp=log.timestamp,
            ip_address=log.ip_address,
            detail_str=detail_str,
        )

        if recalculated_hash != log.current_hash:
            return {
                "is_valid": False,
                "total_records": len(logs),
                "broken_at_sequence": log.sequence,
                "broken_at_id": log.id,
                "reason": "Data integrity violation / record tampering",
                "message": f"Tampering detected at record #{log.sequence}. Record content was modified or corrupted.",
            }

        expected_prev = log.current_hash

    return {
        "is_valid": True,
        "total_records": len(logs),
        "broken_at_sequence": None,
        "message": f"Audit hash chain verified successfully. {len(logs)} records validated.",
        "latest_hash": expected_prev,
    }
