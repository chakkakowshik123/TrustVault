"""Tests for sharing: granting and revoking permissions."""
import pytest
from tests.conftest import login_client, make_test_pdf, grant_perm
from app.models import Permission, PermissionLevel, AuditAction, AuditLog


class TestGrantSharing:
    def test_owner_can_grant_read_permission(self, client, db, owner_user, viewer_user, upload_dir):
        doc = make_test_pdf(db, owner=owner_user)
        login_client(client, owner_user.email, "Owner#Vault2026!")

        r = client.post(
            f"/documents/{doc.id}/share",
            data={"email": viewer_user.email, "level": "read"},
        )
        assert r.status_code in (200, 303)

        perm = db.query(Permission).filter(
            Permission.document_id == doc.id,
            Permission.granted_to_id == viewer_user.id,
            Permission.is_active.is_(True),
        ).first()
        assert perm is not None
        assert perm.level == PermissionLevel.read

    def test_owner_cannot_share_with_self(self, client, db, owner_user, upload_dir):
        doc = make_test_pdf(db, owner=owner_user)
        login_client(client, owner_user.email, "Owner#Vault2026!")

        r = client.post(
            f"/documents/{doc.id}/share",
            data={"email": owner_user.email, "level": "read"},
        )
        assert r.status_code == 422
        assert b"yourself" in r.content

    def test_share_nonexistent_email_returns_error(self, client, db, owner_user, upload_dir):
        doc = make_test_pdf(db, owner=owner_user)
        login_client(client, owner_user.email, "Owner#Vault2026!")

        r = client.post(
            f"/documents/{doc.id}/share",
            data={"email": "nobody@nowhere.com", "level": "read"},
        )
        assert r.status_code == 422
        assert b"No registered user found" in r.content


class TestRevokeSharing:
    def test_owner_can_revoke_permission(self, client, db, owner_user, viewer_user, upload_dir):
        doc = make_test_pdf(db, owner=owner_user)
        perm = grant_perm(db, doc, to_user=viewer_user, by_user=owner_user, level=PermissionLevel.read)

        login_client(client, owner_user.email, "Owner#Vault2026!")
        r = client.post(f"/documents/{doc.id}/revoke/{perm.id}")
        assert r.status_code in (200, 303)

        db.refresh(perm)
        assert perm.is_active is False
