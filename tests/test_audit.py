"""Tests for admin dashboard, hash chain verification, and audit export."""
import pytest
from tests.conftest import login_client, make_test_pdf
from app.models import AuditLog, AuditAction


class TestAdminDashboard:
    def test_admin_can_access_dashboard(self, client, admin_user):
        login_client(client, admin_user.email, "Admin#Vault2026!")
        r = client.get("/audit")
        assert r.status_code == 200
        assert b"Security &amp; Audit Dashboard" in r.content or b"Dashboard" in r.content

    def test_non_admin_cannot_access_admin_dashboard(self, client, viewer_user):
        login_client(client, viewer_user.email, "Viewer#Vault2026!")
        r = client.get("/audit")
        assert r.status_code == 403

    def test_verify_chain_api(self, client, admin_user):
        login_client(client, admin_user.email, "Admin#Vault2026!")
        r = client.get("/audit/verify-chain")
        assert r.status_code == 200
        data = r.json()
        assert "is_valid" in data
        assert data["is_valid"] is True


class TestAuditExport:
    def test_admin_can_export_csv_with_hash_chain(self, client, admin_user):
        login_client(client, admin_user.email, "Admin#Vault2026!")
        r = client.get("/audit/export")
        assert r.status_code == 200
        assert "text/csv" in r.headers.get("content-type", "")
        content = r.content.decode("utf-8")
        assert "prev_hash" in content
        assert "current_hash" in content
        assert "sequence" in content
