"""pytest fixtures for TrustVault test suite."""
import io
import os
import shutil
import tempfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.main import app
from app.models import User, UserRole, Document, DocumentCategory, Permission, PermissionLevel
from app.security import hash_password
from app.config import settings
from app.routers.auth import LOGIN_ATTEMPTS

TEST_DB_URL = "sqlite:///./test_trustvault.db"


@pytest.fixture(scope="session")
def engine():
    _engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=_engine)
    yield _engine
    Base.metadata.drop_all(bind=_engine)
    _engine.dispose()
    if os.path.exists("test_trustvault.db"):
        try:
            os.remove("test_trustvault.db")
        except Exception:
            pass


@pytest.fixture(scope="function")
def db(engine):
    """Fresh session per test; safely clears tables by lifting append-only triggers."""
    LOGIN_ATTEMPTS.clear()  # Reset rate limiter between tests

    with engine.connect() as conn:
        conn.execute(text("DROP TRIGGER IF EXISTS abort_audit_delete;"))
        conn.execute(text("DROP TRIGGER IF EXISTS abort_audit_update;"))
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(table.delete())
        conn.commit()
        # Re-attach triggers for test
        conn.execute(text("""
            CREATE TRIGGER IF NOT EXISTS abort_audit_update
            BEFORE UPDATE ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'Audit log is append-only: UPDATE is strictly prohibited');
            END;
        """))
        conn.execute(text("""
            CREATE TRIGGER IF NOT EXISTS abort_audit_delete
            BEFORE DELETE ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'Audit log is append-only: DELETE is strictly prohibited');
            END;
        """))
        conn.commit()

    TestSession = sessionmaker(bind=engine)
    session = TestSession()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="function")
def upload_dir(tmp_path):
    """Temporary upload directory scoped to each test."""
    udir = tmp_path / "uploads"
    udir.mkdir()
    old = settings.UPLOAD_DIR
    settings.UPLOAD_DIR = udir
    yield udir
    settings.UPLOAD_DIR = old


@pytest.fixture(scope="function")
def client(db, upload_dir):
    """TestClient wired to test DB and temp upload dir."""
    def override_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


# ─── User Fixtures ────────────────────────────────────────────────────────────

@pytest.fixture
def admin_user(db):
    user = User(
        email="admin@trustvault.com",
        username="admin_sec",
        hashed_password=hash_password("Admin#Vault2026!"),
        role=UserRole.admin,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def owner_user(db):
    user = User(
        email="owner@trustvault.com",
        username="owner_sarah",
        hashed_password=hash_password("Owner#Vault2026!"),
        role=UserRole.owner,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def viewer_user(db):
    user = User(
        email="viewer@trustvault.com",
        username="viewer_dave",
        hashed_password=hash_password("Viewer#Vault2026!"),
        role=UserRole.viewer,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def third_party_user(db):
    user = User(
        email="charlie@external.test",
        username="charlie",
        hashed_password=hash_password("Charlie#Vault2026!"),
        role=UserRole.viewer,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# ─── Helpers ─────────────────────────────────────────────────────────────────

def login_client(client, email, password):
    """Log in and verify cookie is set."""
    r = client.post("/auth/login", data={"email": email, "password": password})
    assert "access_token" in client.cookies, f"Login failed for {email}: status={r.status_code}"
    return r


def make_test_pdf(db, owner, filename="test_doc.pdf", content=b"%PDF-1.5\nTest PDF content %%EOF"):
    """Create a valid Document record in DB with physical file on disk."""
    import uuid
    stored = f"{uuid.uuid4().hex}.pdf"
    path = settings.UPLOAD_DIR / stored
    path.write_bytes(content)
    doc = Document(
        owner_id=owner.id,
        filename=filename,
        stored_name=stored,
        mime_type="application/pdf",
        size_bytes=len(content),
        category=DocumentCategory.financial,
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)
    return doc


def grant_perm(db, doc, to_user, by_user, level=PermissionLevel.read):
    perm = Permission(
        document_id=doc.id,
        granted_to_id=to_user.id,
        granted_by_id=by_user.id,
        level=level,
        is_active=True,
    )
    db.add(perm)
    db.commit()
    db.refresh(perm)
    return perm
