# 🔐 TrustVault — Secure Document Management & Sharing Platform

> **"Build a document platform where the wrong person can never read the file, and you can mathematically prove who read it."**

TrustVault is a zero-trust, security-first document management and sharing application engineered with **FastAPI**, **SQLAlchemy**, and a **cryptographic append-only audit trail**.

---

## 📋 Table of Contents

1. [Key Architecture & Security Invariants](#-key-architecture--security-invariants)
2. [User Roles](#-user-roles)
3. [Quick Start & Setup](#-quick-start--setup)
4. [Demo Accounts & Seeding](#-demo-accounts--seeding)
5. [API Documentation & Access Matrix](#-api-documentation--access-matrix)
6. [Security Rules Implemented](#-security-rules-implemented)
7. [Running Automated Tests](#-running-automated-tests)
8. [Docker & Deployment Guide](#-docker--deployment-guide)
9. [Pushing to GitHub](#-pushing-to-github)

---

## 🛡️ Key Architecture & Security Invariants

- **Single Central Authorize Function (`authorize`)**: Every request passes through a centralized, deny-by-default function in `app/authz.py`.
- **Zero Information Leakage (404 on Unauthorized)**: Unauthorized requests receive HTTP `404 Not Found` rather than `403` to prevent IDOR existence leaks and object enumeration.
- **Admin Content Isolation**: System Administrators can manage users, view system metrics, and audit logs, but **cannot view or download document contents** unless explicitly granted by the document owner.
- **Immediate Revocation**: Database checks occur on every request. Revoking a grant takes effect instantaneously.
- **Cryptographic Audit Hash Chain**: Every event is appended to an immutable audit log where each row stores the SHA-256 hash of the previous row. Database triggers strictly reject SQL `UPDATE` and `DELETE` operations.
- **Deep File Validation**: File size caps (50 MB), banned extensions (`.exe`, `.sh`, `.php`, `.py`, `.js`), and magic byte verification (`%PDF-`, `\x89PNG`, `\xff\xd8\xff`, `PK\x03\x04`). Files are stored with randomized UUID4 names in a private directory outside the web root.

---

## 👥 User Roles

| Role | Permissions & Capabilities | Document Content Access |
|---|---|---|
| **Admin** | View system security dashboard, inspect audit logs, export CSV audit trail, verify cryptographic hash chain integrity, manage system users. | ❌ **No inherent access** to read or download documents unless explicitly granted by the owner. |
| **Owner** | Upload documents, categorize files, edit metadata, grant read/edit access to named users, revoke access, soft-delete documents. | ✅ Full access to own documents. |
| **Viewer** | View metadata and download documents that have been explicitly shared with them. | 🔒 Only documents explicitly granted. Cannot upload or delete. |

---

## 🚀 Quick Start & Setup

### Prerequisites
- Python 3.12+
- `pip` or `venv`

### Installation

```bash
# 1. Clone repository and navigate into project directory
cd trustvault

# 2. Create virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy environment configuration
cp .env.example .env

# 5. Seed the database with demo users and sample files
python seed.py

# 6. Start the development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Open your browser to: **`http://localhost:8000`**

---

## 🔑 Demo Accounts & Seeding

The login page features **1-click demo autofill cards** for immediate testing:

| Role | Email | Password | Pre-seeded Permissions |
|---|---|---|---|
| **Admin** | `admin@trustvault.com` | `Admin#Vault2026!` | Access to Security Dashboard (`/audit`), Hash Chain Verifier, CSV Export. |
| **Owner** | `owner@trustvault.com` | `Owner#Vault2026!` | Uploaded sample Financial, Legal, and Technical documents. Can share/revoke. |
| **Viewer** | `viewer@trustvault.com` | `Viewer#Vault2026!` | Granted `read` access to `Q3_Financial_Audit_Report.pdf`. |

To re-seed or reset the database:
```bash
python seed.py
```

---

## 📖 API Documentation & Access Matrix

Interactive OpenAPI documentation is available at **`/api/docs`** when running.

| Endpoint | Method | Role Allowed | Description |
|---|---|---|---|
| `/auth/login` | `GET`, `POST` | Public | Login with email & password. Rate-limited (5 attempts/min/IP). |
| `/auth/register` | `GET`, `POST` | Public | Register new account. First user registered becomes Admin. |
| `/auth/logout` | `POST` | Authenticated | Logs out and increments `token_version` to invalidate session immediately. |
| `/documents` | `GET` | Authenticated | Dashboard and search. Returns strictly authorized documents. |
| `/documents/upload` | `GET`, `POST` | **Owner, Admin** | Upload file with magic bytes check and randomized storage name. |
| `/documents/{id}` | `GET` | **Owner, Granted** | Document detail view. Returns 404 if unauthorized. |
| `/documents/{id}/download` | `GET` | **Owner, Granted** | Stream document content securely with safe disposition headers. |
| `/documents/{id}/edit` | `GET`, `POST` | **Owner, Edit Grant** | Update document metadata or replace file content. |
| `/documents/{id}/share` | `GET`, `POST` | **Owner** | Grant `read` or `edit` access to a named user by email. |
| `/documents/{id}/revoke/{pid}` | `POST` | **Owner** | Revoke an active permission grant immediately. |
| `/documents/{id}/delete` | `POST` | **Owner** | Soft-delete document. |
| `/audit` | `GET` | **Admin** | Security dashboard with anomalies, refusal feed, and chain status. |
| `/audit/verify-chain` | `GET` | **Admin** | Verify cryptographic SHA-256 hash chain of the entire audit log. |
| `/audit/my` | `GET` | Authenticated | Personal user activity history. |
| `/audit/export` | `GET` | **Admin** | Download full audit log with cryptographic hashes as CSV. |

---

## 🔒 Security Rules Implemented

1. **Deny-by-Default Central Authorization (`app/authz.py`)**:
   Every route routes access checks through `authorize(user, document, action)`.
2. **Private File Storage**:
   Uploaded files are stored outside the web root (`uploads/`) with names derived from `uuid.uuid4().hex`. Files are served solely through authenticated streaming endpoints.
3. **Information Concealment**:
   Unauthorized requests return `404 Not Found` rather than `403` to prevent object existence enumeration and IDOR guessing.
4. **Immediate Revocation**:
   Revoked permissions are written directly to the database. User sessions are backed by `token_version` on the `User` model; incrementing this version revokes all existing JWTs immediately.
5. **Cryptographic Append-Only Audit Trail**:
   Each log entry records:
   $$\text{current\_hash} = \text{SHA-256}(\text{prev\_hash} \parallel \text{user\_id} \parallel \text{doc\_id} \parallel \text{action} \parallel \text{timestamp} \parallel \text{ip} \parallel \text{detail})$$
   SQLite database triggers reject `UPDATE` and `DELETE` on `audit_logs`.
6. **Admin Security Dashboard & Anomaly Detection**:
   Monitors unauthorized access spikes ($\ge 3$ denials/hour from single IP), brute-force login attempts, and cryptographic chain tampering.

---

## 🧪 Running Automated Tests

The comprehensive test suite covers all security invariants, access control rules, cryptographic chain verification, and file validation.

```bash
python -m pytest tests/ -v
```

Expected output: **`39 passed` (100% pass rate)**.

---

## 🐳 Docker & Deployment Guide

### Using Docker Compose

```bash
# Build and run container
docker-compose up --build -d

# Check logs
docker-compose logs -f

# Seed within container
docker-compose exec trustvault python seed.py
```

### Google Cloud Run Deployment

```bash
gcloud run deploy trustvault \
  --source . \
  --region asia-southeast1 \
  --platform managed \
  --allow-unauthenticated \
  --port 8000 \
  --memory 512Mi \
  --cpu 1 \
  --set-env-vars "SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')" \
  --set-env-vars "DATABASE_URL=sqlite:////app/data/trustvault.db" \
  --set-env-vars "UPLOAD_DIR=/app/data/uploads"
```

---

## 📦 Pushing to GitHub

```bash
# 1. Initialize git repository
git init

# 2. Add files
git add .

# 3. Commit
git commit -m "feat: complete TrustVault zero-trust secure document platform"

# 4. Set main branch and remote
git branch -M main
git remote add origin https://github.com/<YOUR-USERNAME>/trustvault.git

# 5. Push to GitHub
git push -u origin main
```

---

## 📄 License

MIT License. Built for security-first document management.
