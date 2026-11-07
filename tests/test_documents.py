"""Tests for document upload, view, edit, download, and delete."""
import io
import pytest
from tests.conftest import login_client, make_test_pdf, grant_perm
from app.models import Document, AuditLog, AuditAction, PermissionLevel


class TestDocumentUpload:
    def test_owner_can_upload_valid_pdf(self, client, db, owner_user, upload_dir):
        login_client(client, owner_user.email, "Owner#Vault2026!")

        valid_pdf = b"%PDF-1.5\nTest Document Content %%EOF"
        r = client.post(
            "/documents/upload",
            files={"file": ("report.pdf", io.BytesIO(valid_pdf), "application/pdf")},
            data={"category": "Financial", "description": "Q3 Report"},
        )
        assert r.status_code in (200, 303)

        doc = db.query(Document).filter(Document.owner_id == owner_user.id).first()
        assert doc is not None
        assert doc.filename == "report.pdf"
        assert doc.category.value == "Financial"

        # Stored with randomized UUID name
        assert doc.stored_name != doc.filename
        assert (upload_dir / doc.stored_name).exists()

    def test_viewer_role_cannot_upload_documents(self, client, viewer_user):
        """Viewer role sees only documents granted to them — cannot upload."""
        login_client(client, viewer_user.email, "Viewer#Vault2026!")

        valid_pdf = b"%PDF-1.5\nViewer Document %%EOF"
        r = client.post(
            "/documents/upload",
            files={"file": ("viewer_file.pdf", io.BytesIO(valid_pdf), "application/pdf")},
            data={"category": "General"},
        )
        assert r.status_code == 403


class TestDocumentViewAndDownload:
    def test_owner_can_view_and_download(self, client, db, owner_user, upload_dir):
        doc = make_test_pdf(db, owner=owner_user, content=b"%PDF-1.5 Owner Content %%EOF")
        login_client(client, owner_user.email, "Owner#Vault2026!")

        r_view = client.get(f"/documents/{doc.id}")
        assert r_view.status_code == 200

        r_down = client.get(f"/documents/{doc.id}/download")
        assert r_down.status_code == 200
        assert b"%PDF-1.5 Owner Content" in r_down.content
        assert "content-disposition" in r_down.headers

    def test_granted_read_user_can_view_and_download(self, client, db, owner_user, viewer_user, upload_dir):
        doc = make_test_pdf(db, owner=owner_user, content=b"%PDF-1.5 Shared Content %%EOF")
        grant_perm(db, doc, to_user=viewer_user, by_user=owner_user, level=PermissionLevel.read)

        login_client(client, viewer_user.email, "Viewer#Vault2026!")

        r_view = client.get(f"/documents/{doc.id}")
        assert r_view.status_code == 200

        r_down = client.get(f"/documents/{doc.id}/download")
        assert r_down.status_code == 200
        assert b"%PDF-1.5 Shared Content" in r_down.content


class TestDocumentEdit:
    def test_owner_can_edit_metadata(self, client, db, owner_user, upload_dir):
        doc = make_test_pdf(db, owner=owner_user, filename="original.pdf")
        login_client(client, owner_user.email, "Owner#Vault2026!")

        r = client.post(
            f"/documents/{doc.id}/edit",
            data={"filename": "updated.pdf", "category": "Legal", "description": "Updated description"},
        )
        assert r.status_code in (200, 303)
        db.refresh(doc)
        assert doc.filename == "updated.pdf"
        assert doc.category.value == "Legal"

    def test_read_permission_cannot_edit_document(self, client, db, owner_user, viewer_user, upload_dir):
        doc = make_test_pdf(db, owner=owner_user, filename="original.pdf")
        grant_perm(db, doc, to_user=viewer_user, by_user=owner_user, level=PermissionLevel.read)

        login_client(client, viewer_user.email, "Viewer#Vault2026!")
        r = client.post(
            f"/documents/{doc.id}/edit",
            data={"filename": "malicious.pdf", "category": "Legal"},
        )
        # Rule #3: Unauthorized access returns 404
        assert r.status_code == 404
        db.refresh(doc)
        assert doc.filename == "original.pdf"


class TestDocumentDelete:
    def test_owner_can_soft_delete(self, client, db, owner_user, upload_dir):
        doc = make_test_pdf(db, owner=owner_user)
        login_client(client, owner_user.email, "Owner#Vault2026!")

        r = client.post(f"/documents/{doc.id}/delete")
        assert r.status_code in (200, 303)
        db.refresh(doc)
        assert doc.is_deleted is True
