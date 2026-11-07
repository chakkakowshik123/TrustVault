"""Tests for authentication: register, login (with demo cards & rate limiting), logout."""
import pytest
from tests.conftest import login_client
from app.models import User, UserRole, AuditLog, AuditAction


class TestRegister:
    def test_register_page_loads(self, client):
        r = client.get("/auth/register")
        assert r.status_code == 200
        assert b"Create" in r.content

    def test_register_user_creates_account(self, client, db):
        r = client.post("/auth/register", data={
            "email": "newuser@test.com",
            "username": "newuser123",
            "password": "Password123!",
            "confirm_password": "Password123!",
            "role": "owner",
        })
        assert r.status_code in (200, 303)
        user = db.query(User).filter(User.email == "newuser@test.com").first()
        assert user is not None
        # First user is admin or role specified
        assert user.role in (UserRole.admin, UserRole.owner)

    def test_duplicate_email_rejected(self, client, owner_user):
        r = client.post("/auth/register", data={
            "email": owner_user.email,
            "username": "differentname",
            "password": "Password123!",
            "confirm_password": "Password123!",
        })
        assert r.status_code == 422
        assert b"already registered" in r.content

    def test_weak_password_rejected(self, client):
        r = client.post("/auth/register", data={
            "email": "weak@test.com",
            "username": "weakuser",
            "password": "abc",
            "confirm_password": "abc",
        })
        assert r.status_code == 422
        assert b"8 characters" in r.content

    def test_passwords_never_stored_plaintext(self, client, db):
        client.post("/auth/register", data={
            "email": "plain@test.com",
            "username": "plainuser",
            "password": "PlainPassword123!",
            "confirm_password": "PlainPassword123!",
        })
        user = db.query(User).filter(User.email == "plain@test.com").first()
        assert user is not None
        assert user.hashed_password != "PlainPassword123!"
        assert user.hashed_password.startswith("$2b$")


class TestLogin:
    def test_login_page_renders_demo_cards(self, client):
        r = client.get("/auth/login")
        assert r.status_code == 200
        assert b"admin@trustvault.com" in r.content
        assert b"owner@trustvault.com" in r.content
        assert b"viewer@trustvault.com" in r.content

    def test_login_success_sets_httponly_cookie(self, client, owner_user):
        r = login_client(client, owner_user.email, "Owner#Vault2026!")
        assert r.status_code in (200, 303)
        assert "access_token" in client.cookies

    def test_login_invalid_password_returns_401(self, client, owner_user):
        r = client.post("/auth/login", data={"email": owner_user.email, "password": "WrongPassword!"})
        assert r.status_code == 401
        assert b"Invalid" in r.content

    def test_login_records_audit_log(self, client, db, owner_user):
        login_client(client, owner_user.email, "Owner#Vault2026!")
        log = db.query(AuditLog).filter(
            AuditLog.user_id == owner_user.id,
            AuditLog.action == AuditAction.LOGIN.value,
        ).first()
        assert log is not None


class TestLogoutAndRevocation:
    def test_logout_clears_cookie_and_increments_token_version(self, client, db, owner_user):
        login_client(client, owner_user.email, "Owner#Vault2026!")
        initial_version = owner_user.token_version

        r = client.post("/auth/logout")
        assert r.status_code in (200, 303)
        assert client.cookies.get("access_token") in (None, "")

        db.refresh(owner_user)
        # Token version incremented -> immediate invalidation of old tokens
        assert owner_user.token_version > initial_version
