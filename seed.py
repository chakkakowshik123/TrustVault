"""
Database seed script for TrustVault.
Seeds demo users (Admin, Owner, Viewer), sample documents, and initial cryptographic audit chain.
"""
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from app.config import settings
from app.database import Base, engine, SessionLocal
from app.models import User, UserRole, Document, DocumentCategory, Permission, PermissionLevel, AuditAction
from app.security import hash_password
from app.audit_chain import add_audit_log, verify_audit_chain
from app.file_utils import save_secure_file

DEMO_USERS = [
    {
        "email": "admin@trustvault.com",
        "username": "admin_sec",
        "password": "Admin#Vault2026!",
        "role": UserRole.admin,
    },
    {
        "email": "owner@trustvault.com",
        "username": "owner_sarah",
        "password": "Owner#Vault2026!",
        "role": UserRole.owner,
    },
    {
        "email": "viewer@trustvault.com",
        "username": "viewer_dave",
        "password": "Viewer#Vault2026!",
        "role": UserRole.viewer,
    },
]

SAMPLE_DOCS = [
    {
        "filename": "Q3_Financial_Audit_Report.pdf",
        "category": DocumentCategory.financial,
        "description": "Quarterly financial statements, balance sheet audit, and executive compliance report.",
        # Valid PDF magic bytes (%PDF-1.5)
        "content": b"%PDF-1.5\n%TrustVault Sample Financial Report\n1 0 obj\n<< /Title (Q3 Financial Report) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n",
    },
    {
        "filename": "Enterprise_Master_Service_Agreement.docx",
        "category": DocumentCategory.legal,
        "description": "Standard mutual NDA and vendor master service terms for FY2026.",
        # Valid DOCX / PK magic bytes
        "content": b"PK\x03\x04\x14\x00\x00\x00\x08\x00TrustVault Sample Legal Agreement Document Content PK\x05\x06",
    },
    {
        "filename": "Zero_Trust_Security_Architecture.pdf",
        "category": DocumentCategory.technical,
        "description": "Internal technical specifications for access control, cryptographic hash chains, and IAM policies.",
        # Valid PDF magic bytes (%PDF-1.5)
        "content": b"%PDF-1.5\n%TrustVault Architecture Specification\n1 0 obj\n<< /Title (Security Architecture) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n",
    },
]


def seed():
    print("======================================================================")
    print("TrustVault Database Seeding")
    print("======================================================================")

    # 1. Initialize DB tables
    print("-> Creating database schema & immutability triggers...")
    Base.metadata.create_all(bind=engine)
    settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    db = SessionLocal()
    try:
        # Check if already seeded
        existing_admin = db.query(User).filter(User.email == "admin@trustvault.com").first()
        if existing_admin:
            print("(!) Database is already seeded. Skipping initial user creation.")
            return

        # 2. Seed Users
        user_objs = {}
        for u in DEMO_USERS:
            user = User(
                email=u["email"],
                username=u["username"],
                hashed_password=hash_password(u["password"]),
                role=u["role"],
                is_active=True,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            user_objs[u["role"]] = user

            # Log registration in cryptographic audit log
            add_audit_log(
                db=db,
                action=AuditAction.REGISTER,
                user_id=user.id,
                detail={"email": user.email, "role": user.role.value, "seeded": True},
                ip_override="127.0.0.1",
            )
            print(f" [+] Created {u['role'].value.upper():<7} user: {u['email']} (username: {u['username']})")

        owner = user_objs[UserRole.owner]
        viewer = user_objs[UserRole.viewer]

        # 3. Seed Sample Documents (Uploaded by Owner)
        doc_objs = []
        for d in SAMPLE_DOCS:
            clean_name, stored_name = save_secure_file(d["filename"], d["content"])
            doc = Document(
                owner_id=owner.id,
                filename=clean_name,
                stored_name=stored_name,
                mime_type="application/pdf" if clean_name.endswith(".pdf") else "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                size_bytes=len(d["content"]),
                category=d["category"],
                description=d["description"],
            )
            db.add(doc)
            db.commit()
            db.refresh(doc)
            doc_objs.append(doc)

            add_audit_log(
                db=db,
                action=AuditAction.UPLOAD,
                user_id=owner.id,
                document_id=doc.id,
                detail={"filename": doc.filename, "category": doc.category.value, "size_bytes": doc.size_bytes},
                ip_override="127.0.0.1",
            )
            print(f" [+] Uploaded Document: '{doc.filename}' ({doc.category.value})")

        # 4. Seed Grant: Owner grants 'read' access on Q3 Financial to Viewer
        shared_doc = doc_objs[0]  # Q3 Financial Report
        perm = Permission(
            document_id=shared_doc.id,
            granted_to_id=viewer.id,
            granted_by_id=owner.id,
            level=PermissionLevel.read,
            is_active=True,
        )
        db.add(perm)
        db.commit()
        db.refresh(perm)

        add_audit_log(
            db=db,
            action=AuditAction.SHARE,
            user_id=owner.id,
            document_id=shared_doc.id,
            detail={
                "shared_with": viewer.email,
                "level": PermissionLevel.read.value,
                "seeded": True,
            },
            ip_override="127.0.0.1",
        )
        print(f" [+] Granted READ access on '{shared_doc.filename}' to '{viewer.email}'")

        # 5. Verify Hash Chain
        verification = verify_audit_chain(db)
        print("-" * 70)
        status_label = "VALID [OK]" if verification["is_valid"] else "BROKEN [FAILED]"
        print(f" Cryptographic Hash Chain Status: {status_label}")
        print(f" Total Log Records: {verification['total_records']}")
        print(f" Verification Message: {verification['message']}")
        print("-" * 70)
        print("\nSEEDED DEMO CREDENTIALS:")
        print("  +---------+--------------------------+-------------------+")
        print("  | Role    | Email                    | Password          |")
        print("  +---------+--------------------------+-------------------+")
        print("  | Admin   | admin@trustvault.com     | Admin#Vault2026!  |")
        print("  | Owner   | owner@trustvault.com     | Owner#Vault2026!  |")
        print("  | Viewer  | viewer@trustvault.com    | Viewer#Vault2026! |")
        print("  +---------+--------------------------+-------------------+")
        print("=" * 70)

    finally:
        db.close()


if __name__ == "__main__":
    seed()
