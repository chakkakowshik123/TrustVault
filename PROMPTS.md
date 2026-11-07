# TrustVault — Engineering Development Log & AI Security Audit (PROMPTS.md)

This document tracks the iterative design, implementation steps, access control edge cases, and security refinements identified and fixed during the development of **TrustVault**.

---

## 1. Initial Specification & Problem Statement

> **Initial Requirement**: Build a secure document-sharing platform where the wrong person can never read the file, and you can mathematically prove who read it.
>
> **Stack Selected**: Python 3.12, FastAPI, SQLAlchemy, SQLite, Jinja2, Vanilla CSS/JS design system.

---

## 2. Iterations, Security Refinements & Bug Fixes

### Iteration 1: Central Authorization Engine (`authorize`)
* **Risk Identified**: Standard web applications often spread access checks across routes using disparate `if doc.owner_id == user.id` checks. This frequently leads to routes missing permission verification (e.g. download or search routes).
* **Fix Implemented**:
  - Implemented single deny-by-default function `authorize(user, document, action, db, request)` in `app/authz.py`.
  - Implemented `get_authorized_document_or_404(doc_id, action, user, db, request)` helper.
  - Every single document route (`view`, `download`, `edit`, `delete`, `share`, `revoke`) calls this helper.

### Iteration 2: IDOR & Information Leakage Prevention (Rule #3)
* **Access Control Vulnerability Identified**:
  - In initial prototype, unauthorized requests returned HTTP `403 Forbidden`.
  - *Vulnerability*: Returning `403` informs an attacker that the document exists and has a specific ID (IDOR discovery / enumeration leak).
* **Fix Implemented**:
  - Changed unauthorized responses to HTTP `404 Not Found`.
  - Attackers cannot distinguish between a non-existent document and a document they are not authorized to view.

### Iteration 3: Admin Privilege Separation
* **Access Control Vulnerability Identified**:
  - Many traditional IAM systems grant Admins root read permissions over all records (`if user.role == 'admin': return True`).
  - *Violation*: The specification strictly demands that Administrators **cannot read document contents unless explicitly granted**.
* **Fix Implemented**:
  - Updated `authorize()` in `app/authz.py`: Admins have system administrative access (audit logs, user management, metrics), but are explicitly barred from viewing or downloading document contents unless granted like any other user.
  - Verified with automated test `test_admin_cannot_read_document_without_grant`.

### Iteration 4: Search Result Leakage (Rule #2)
* **Access Control Vulnerability Identified**:
  - If a search query scans the global `documents` table and displays matching titles, an unauthorized user can infer sensitive information (e.g., searching "Merger" reveals "Confidential_Merger_Project_2026.pdf").
* **Fix Implemented**:
  - In `app/routers/documents.py`, the search query strictly joins and filters on documents owned by the user or where an active `Permission` record exists.
  - Inaccessible document titles never enter memory or the template context.
  - Verified with `test_search_never_leaks_titles_of_inaccessible_documents`.

### Iteration 5: Immediate Revocation & Session Revocation (Rule #4)
* **Vulnerability Identified**:
  - Cached permissions or stateless JWT tokens without versioning mean a revoked user can continue accessing files until their JWT expires.
* **Fix Implemented**:
  - Two-tier immediate revocation:
    1. **Document Grants**: Checked directly in the database on every HTTP request. Revoking a grant sets `is_active = False`, blocking subsequent requests immediately.
    2. **User Sessions**: User model includes `token_version`. On logout or administrative session revocation, `user.token_version += 1`, invalidating all existing JWTs.
  - Verified with `test_revocation_is_immediate` and `test_logout_clears_cookie_and_increments_token_version`.

### Iteration 6: Cryptographic Append-Only Audit Log with Hash Chain (Rule #5)
* **Requirement**: Audit logs must be tamper-evident and append-only.
* **Implementation & Bug Encountered**:
  - Developed `app/audit_chain.py` with SHA-256 hash chaining:
    $$\text{current\_hash} = \text{SHA256}(\text{prev\_hash} \parallel \text{user\_id} \parallel \text{document\_id} \parallel \text{action} \parallel \text{timestamp} \parallel \text{ip} \parallel \text{detail})$$
  - Added SQLite triggers `abort_audit_update` and `abort_audit_delete` to abort any `UPDATE` or `DELETE` at the database engine level.
  - *Bug Encountered During Pytest*: When pytest teardown attempted to clear tables using `session.execute(table.delete())`, the SQLite database trigger correctly blocked the deletion, raising `RAISE(ABORT, 'Audit log is append-only')`!
  - *Fix*: In `tests/conftest.py`, the test teardown fixture explicitly drops the triggers prior to cleaning test data and re-attaches them for every test run.
  - Verified with `test_hash_chain_validates_genuine_log` and `test_tampering_with_log_is_detected`.

### Iteration 7: Deep File & Magic Bytes Validation
* **Vulnerability Identified**:
  - Uploading a malicious script (e.g. `exploit.php` or `malware.sh`) with a spoofed MIME type header could lead to Remote Code Execution if served directly.
* **Fix Implemented**:
  - Banned dangerous executable extensions (`.exe`, `.sh`, `.php`, `.py`, `.js`, `.bat`, etc.).
  - Verified file magic bytes:
    - PDF: starts with `%PDF-`
    - PNG: starts with `\x89PNG\r\n\x1a\n`
    - JPEG: starts with `\xff\xd8\xff`
    - DOCX/XLSX: starts with `PK\x03\x04`
  - Stored files in a private directory (`uploads/`) completely outside the web root with randomized UUID4 filenames (`f"{uuid.uuid4().hex}{ext}"`).
  - Served exclusively through authenticated streaming endpoints with `X-Content-Type-Options: nosniff`.
  - Verified with `test_executable_upload_is_blocked` and `test_magic_bytes_mismatch_is_rejected`.

### Iteration 8: Bcrypt Compatibility Resolution
* **Bug Encountered**:
  - `passlib` 1.7.4 with modern `bcrypt` 4.1+ raised `ValueError: password cannot be longer than 72 bytes` during internal wrap detection.
* **Fix Implemented**:
  - Replaced passlib wrapper with native `bcrypt` package calls (`bcrypt.hashpw` and `bcrypt.checkpw`) with explicit 72-byte UTF-8 truncation, ensuring 100% stable, cross-platform password hashing.

---

## 3. Summary of Test Coverage

All 39 automated tests pass with 100% success rate:
- **Authentication**: Registration, Login, Logout, Cookie flags, Session revocation, Demo logins.
- **Documents**: Upload (valid magic bytes), View, Download, Edit, Soft Delete.
- **Sharing**: Grant permissions, Revocation, Self-share prevention, Unknown recipient prevention.
- **Security Rules**: User isolation, Admin content isolation, 404 existence masking, Immediate grant revocation, Denial audit logs, Cryptographic hash chain validation, Tamper detection, Search isolation, Executable blocking, Magic byte mismatch rejection.
- **Audit Dashboard**: Live hash chain verification API, CSV export, Anomaly detection.
