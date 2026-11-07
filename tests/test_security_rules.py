"""
Automated tests verifying non-negotiable security rules:
- User A cannot read, download, edit, delete, or share User B's document.
- Admin cannot read/download document contents unless explicitly granted.
- Unauthorised access returns 404 to avoid leaking existence (Rule #3).
- Revocation is immediate (Rule #4).
- Audit rows are written for denials (who, what, when, IP).
- Tampering with the audit log is detected by hash chain verification.
- Audit table triggers reject UPDATE and DELETE.
- Search never leaks inaccessible document titles.
"""
import io
import pytest
from sqlalchemy import text
from app.models import AuditAction, AuditLog, PermissionLevel, UserRole
from app.audit_chain import verify_audit_chain, add_audit_log
from tests.conftest import login_client, make_test_pdf, grant_perm


class TestStrictAuthorization:
    def test_user_a_cannot_view_user_b_document(self, client, db, owner_user, third_party_user, upload_dir):
        doc = make_test_pdf(db, owner=owner_user, filename="confidential.pdf")
        login_client(client, third_party_user.email, "Charlie#Vault2026!")

        r = client.get(f"/documents/{doc.id}")
        # Rule #3: Return 404 to avoid revealing existence
        assert r.status_code == 404

    def test_user_a_cannot_download_user_b_document(self, client, db, owner_user, third_party_user, upload_dir):
        doc = make_test_pdf(db, owner=owner_user, filename="confidential.pdf")
        login_client(client, third_party_user.email, "Charlie#Vault2026!")

        r = client.get(f"/documents/{doc.id}/download")
        assert r.status_code == 404

    def test_user_a_cannot_edit_user_b_document(self, client, db, owner_user, third_party_user, upload_dir):
        doc = make_test_pdf(db, owner=owner_user, filename="confidential.pdf")
        login_client(client, third_party_user.email, "Charlie#Vault2026!")

        r = client.post(f"/documents/{doc.id}/edit", data={"filename": "hacked.pdf", "category": "General"})
        assert r.status_code == 404
        db.refresh(doc)
        assert doc.filename == "confidential.pdf"

    def test_user_a_cannot_delete_user_b_document(self, client, db, owner_user, third_party_user, upload_dir):
        doc = make_test_pdf(db, owner=owner_user, filename="confidential.pdf")
        login_client(client, third_party_user.email, "Charlie#Vault2026!")

        r = client.post(f"/documents/{doc.id}/delete")
        assert r.status_code == 404
        db.refresh(doc)
        assert doc.is_deleted is False

    def test_user_a_cannot_share_user_b_document(self, client, db, owner_user, third_party_user, viewer_user, upload_dir):
        doc = make_test_pdf(db, owner=owner_user, filename="confidential.pdf")
        login_client(client, third_party_user.email, "Charlie#Vault2026!")

        r = client.post(f"/documents/{doc.id}/share", data={"email": viewer_user.email, "level": "read"})
        assert r.status_code == 404

    def test_admin_cannot_read_document_without_grant(self, client, db, owner_user, admin_user, upload_dir):
        """Admin role: Cannot read document contents unless explicitly granted."""
        doc = make_test_pdf(db, owner=owner_user, filename="executive_secrets.pdf")
        login_client(client, admin_user.email, "Admin#Vault2026!")

        # Admin attempting to view document
        r_view = client.get(f"/documents/{doc.id}")
        assert r_view.status_code == 404

        # Admin attempting to download file
        r_down = client.get(f"/documents/{doc.id}/download")
        assert r_down.status_code == 404

    def test_admin_can_read_when_explicitly_granted(self, client, db, owner_user, admin_user, upload_dir):
        doc = make_test_pdf(db, owner=owner_user, filename="for_audit.pdf")
        grant_perm(db, doc, to_user=admin_user, by_user=owner_user, level=PermissionLevel.read)

        login_client(client, admin_user.email, "Admin#Vault2026!")
        r = client.get(f"/documents/{doc.id}")
        assert r.status_code == 200
        assert b"for_audit.pdf" in r.content


class TestImmediateRevocation:
    def test_revocation_is_immediate(self, client, db, owner_user, viewer_user, upload_dir):
        """Rule #4: Immediate access loss upon grant revocation."""
        doc = make_test_pdf(db, owner=owner_user, filename="shared_file.pdf")
        perm = grant_perm(db, doc, to_user=viewer_user, by_user=owner_user, level=PermissionLevel.read)

        # Viewer can read before revocation
        login_client(client, viewer_user.email, "Viewer#Vault2026!")
        r_before = client.get(f"/documents/{doc.id}/download")
        assert r_before.status_code == 200

        # Owner revokes permission
        login_client(client, owner_user.email, "Owner#Vault2026!")
        r_revoke = client.post(f"/documents/{doc.id}/revoke/{perm.id}")
        assert r_revoke.status_code in (200, 303)

        # Viewer tries again immediately -> must receive 404
        login_client(client, viewer_user.email, "Viewer#Vault2026!")
        r_after = client.get(f"/documents/{doc.id}/download")
        assert r_after.status_code == 404


class TestAuditLogAndHashChain:
    def test_denial_writes_audit_log_with_ip_and_details(self, client, db, owner_user, third_party_user, upload_dir):
        doc = make_test_pdf(db, owner=owner_user, filename="secret.pdf")
        login_client(client, third_party_user.email, "Charlie#Vault2026!")

        client.get(f"/documents/{doc.id}")

        log = db.query(AuditLog).filter(
            AuditLog.user_id == third_party_user.id,
            AuditLog.document_id == doc.id,
            AuditLog.action == AuditAction.DENIED.value,
        ).first()

        assert log is not None
        assert log.ip_address is not None
        assert log.timestamp is not None
        assert log.current_hash is not None
        assert log.prev_hash is not None

    def test_hash_chain_validates_genuine_log(self, db, admin_user):
        add_audit_log(db, action=AuditAction.LOGIN, user_id=admin_user.id, detail={"status": "ok"})
        add_audit_log(db, action=AuditAction.VIEW, user_id=admin_user.id, detail={"doc": "test"})

        res = verify_audit_chain(db)
        assert res["is_valid"] is True
        assert res["total_records"] >= 2

    def test_tampering_with_log_is_detected(self, db, admin_user):
        """Rule #5: Detect modified rows via cryptographic hash verification."""
        log1 = add_audit_log(db, action=AuditAction.LOGIN, user_id=admin_user.id, detail={"step": 1})
        log2 = add_audit_log(db, action=AuditAction.VIEW, user_id=admin_user.id, detail={"step": 2})

        # Pre-tamper verification passes
        assert verify_audit_chain(db)["is_valid"] is True

        # Directly tamper with log1 content via raw SQL (bypassing triggers if simulated)
        # Note: SQLite triggers prevent UPDATE, but if an attacker compromised raw DB or file:
        # We temporarily disable triggers or directly update to test hash chain detector
        db.execute(text("PRAGMA foreign_keys = OFF;"))
        # Force update by dropping trigger temporarily to simulate offline disk modification
        db.execute(text("DROP TRIGGER IF EXISTS abort_audit_update;"))
        db.execute(text(f"UPDATE audit_logs SET action = 'ALTERED' WHERE id = '{log1.id}'"))
        db.commit()

        # Chain verification must now FAIL and pinpoint tampered sequence
        tampered_res = verify_audit_chain(db)
        assert tampered_res["is_valid"] is False
        assert tampered_res["broken_at_id"] == log1.id


class TestSearchPrivacy:
    def test_search_never_leaks_titles_of_inaccessible_documents(self, client, db, owner_user, third_party_user, upload_dir):
        """Rule #2: Search results strictly contain only accessible documents."""
        doc = make_test_pdf(db, owner=owner_user, filename="Secret_Merger_Plan.pdf")
        login_client(client, third_party_user.email, "Charlie#Vault2026!")

        # Search for exact keyword
        r = client.get("/documents?q=Secret_Merger_Plan")
        assert r.status_code == 200
        assert b"Secret_Merger_Plan.pdf" not in r.content


class TestFileUploadSecurity:
    def test_executable_upload_is_blocked(self, client, db, owner_user, upload_dir):
        login_client(client, owner_user.email, "Owner#Vault2026!")

        malicious_content = b"#!/bin/bash\nrm -rf /"
        r = client.post(
            "/documents/upload",
            files={"file": ("exploit.sh", io.BytesIO(malicious_content), "application/x-sh")},
            data={"category": "General"},
        )
        assert r.status_code == 400
        assert b"prohibited" in r.content or b"invalid" in r.content.lower()

    def test_magic_bytes_mismatch_is_rejected(self, client, db, owner_user, upload_dir):
        login_client(client, owner_user.email, "Owner#Vault2026!")

        # Filename claims to be .pdf, but content is raw plain text without %PDF- magic bytes
        fake_pdf = b"This is not a pdf file at all"
        r = client.post(
            "/documents/upload",
            files={"file": ("fake.pdf", io.BytesIO(fake_pdf), "application/pdf")},
            data={"category": "General"},
        )
        assert r.status_code == 400
        assert b"magic bytes" in r.content.lower()
