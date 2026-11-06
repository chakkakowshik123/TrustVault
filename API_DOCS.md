# API_DOCS.md — TrustVault REST API Specification

**Base URL:** `http://localhost:3000/api` (or relative `/api`)  
**Authentication:** Header `Authorization: Bearer <session-token>` (or `x-user-id: <user-id>` for authenticated sessions)  
**Security Model:** Role-Based Access Control (RBAC) + Per-Document Access Control Lists (ACL) + Cryptographic Audit Chaining.

---

## 1. Authentication & Session Endpoints

### `POST /api/auth/login`
* **Description:** Authenticates user credentials and returns user profile, role, and active session token.
* **Allowed Callers:** Public (Any caller)
* **Request Body:**
  ```json
  {
    "email": "alice.owner@trustvault.internal",
    "password": "AliceVault#2026"
  }
  ```
* **Response (200 OK):**
  ```json
  {
    "token": "sess_89f0a21...",
    "user": {
      "id": "usr_owner_alice",
      "email": "alice.owner@trustvault.internal",
      "name": "Alice Morgan",
      "role": "DOCUMENT_OWNER",
      "department": "Finance & Executive"
    }
  }
  ```
* **Audit Impact:** Logs `LOGIN` event to SHA-256 hash chain with IP address.

### `GET /api/auth/me`
* **Description:** Returns the active authenticated user's profile and permissions.
* **Allowed Callers:** Any authenticated user (`ADMIN`, `DOCUMENT_OWNER`, `VIEWER`, `EXTERNAL_PARTNER`).

---

## 2. Document Management Endpoints

### `GET /api/documents`
* **Description:** Lists documents accessible to the caller.
  - **ADMIN:** Can view all document metadata for governance (file contents still require explicit grant).
  - **DOCUMENT_OWNER:** Can view documents they own, plus documents shared with them.
  - **VIEWER / EXTERNAL:** Can view ONLY documents explicitly shared with them.
* **Allowed Callers:** Authenticated users.
* **Query Parameters:**
  - `search` (string): Title/tag search
  - `category` (string): `FINANCE`, `LEGAL`, `ENGINEERING`, `HR`, `COMPLIANCE`, `EXECUTIVE`
  - `securityLevel` (string): `INTERNAL`, `RESTRICTED`, `CONFIDENTIAL`, `SECRET`
* **Response (200 OK):** Array of Document metadata items.

### `GET /api/documents/:id`
* **Description:** Fetches detailed metadata for a specific document.
* **Allowed Callers:**
  - Document Owner
  - System Admin
  - Any user with explicit `READ`, `DOWNLOAD`, or `EDIT` grant.
* **Security Decision:**
  - If user is NOT owner, admin, or in document ACL: **403 Forbidden**.
  - On 403, writes `ACCESS_DENIED` block to the cryptographic audit chain.

### `POST /api/documents`
* **Description:** Uploads a new document to the vault with envelope encryption.
* **Allowed Callers:** `DOCUMENT_OWNER` or `ADMIN`.
* **Validation Enforced:**
  - File size $\le$ 15MB.
  - Executable extensions banned (`.exe`, `.sh`, `.bat`, `.php`, `.vbs`, `.js`).
  - Filename sanitized against path traversal (`../../`).
  - File payload encrypted using AES-256-GCM prior to storage.
* **Audit Impact:** Logs `UPLOAD` event to SHA-256 hash chain.

### `PUT /api/documents/:id`
* **Description:** Updates document metadata or updates content version.
* **Allowed Callers:** Document Owner or user with explicit `EDIT` grant.
* **Response:** Updated document record.
* **Audit Impact:** Logs `EDIT` event to SHA-256 hash chain.

### `DELETE /api/documents/:id`
* **Description:** Deletes or marks a document as archived.
* **Allowed Callers:** Document Owner or System Admin ONLY. Users with `EDIT` or `READ` cannot delete.
* **Audit Impact:** Logs `DELETE` event to SHA-256 hash chain.

---

## 3. Secure File Retrieval & Download Endpoints

### `GET /api/documents/:id/download`
* **Description:** Decrypts and streams the file blob for an authorized user.
* **Allowed Callers:**
  - Document Owner
  - User with explicit `DOWNLOAD` permission in the active document ACL.
* **Security Enforcement (CRITICAL):**
  1. Server checks live database state (no cached stale grants).
  2. If access was revoked even 1 millisecond ago, request immediately returns **403 Forbidden**.
  3. Decrypts AES-256-GCM ciphertext on-the-fly.
  4. Writes immutable `DOWNLOAD` event into SHA-256 audit ledger.
  5. Sets security headers: `Content-Disposition: attachment; filename="..."`, `X-Content-Type-Options: nosniff`.
* **Refused Attempts:** If caller lacks download permission, returns **403 Forbidden** and logs `ACCESS_DENIED` to audit chain with caller IP and timestamp.

---

## 4. Access Control & Permission Management Endpoints

### `GET /api/documents/:id/permissions`
* **Description:** Returns the complete list of access grants for a document.
* **Allowed Callers:** Document Owner or System Admin.
* **Response (200 OK):**
  ```json
  [
    {
      "userId": "usr_viewer_carol",
      "userName": "Carol Davies",
      "email": "carol.viewer@trustvault.internal",
      "accessLevel": "READ",
      "grantedAt": "2026-11-02T10:00:00Z",
      "grantedBy": "usr_owner_alice"
    }
  ]
  ```

### `POST /api/documents/:id/permissions`
* **Description:** Grants a named user `READ`, `DOWNLOAD`, or `EDIT` access to a document.
* **Allowed Callers:** Document Owner or System Admin ONLY.
* **Security Guarantee:**
  - Increments `document.permissionVersion`.
  - Immutably logs `GRANT_PERMISSION` to audit chain.
* **Request Body:**
  ```json
  {
    "userId": "usr_viewer_carol",
    "accessLevel": "READ",
    "notes": "Auditing Q4 numbers"
  }
  ```

### `DELETE /api/documents/:id/permissions/:userId`
* **Description:** Instantly revokes a user's access to the document.
* **Allowed Callers:** Document Owner or System Admin ONLY.
* **Instant Revocation Effect:**
  - Increments `document.permissionVersion`.
  - Expunges the user grant from live ACL.
  - Immutably logs `REVOKE_PERMISSION` to audit chain.
  - Takes effect immediately across all subsequent requests.

---

## 5. Audit Trail & Cryptographic Verification Endpoints

### `GET /api/audit`
* **Description:** Retrieves the cryptographic audit trail ledger.
* **Allowed Callers:** `ADMIN` or `DOCUMENT_OWNER` (Owners see events concerning their own documents; Admins see system-wide events).
* **Response Structure:** Ordered array of blocks with `entryHash`, `previousHash`, `timestamp`, `action`, `status`, and `actor`.

### `GET /api/audit/verify`
* **Description:** Traverses the entire audit log from Genesis block #0 to current tip, recalculating SHA-256 hashes at each link.
* **Allowed Callers:** All authenticated roles (Verification is public to allow non-repudiation audits).
* **Response (200 OK):**
  ```json
  {
    "verified": true,
    "totalBlocks": 142,
    "genesisHash": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    "latestHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "status": "CHAIN_INTEGRITY_VERIFIED_100_PERCENT",
    "tamperedBlockIndex": null
  }
  ```
* **On Tamper Detected:**
  ```json
  {
    "verified": false,
    "totalBlocks": 142,
    "tamperedBlockIndex": 12,
    "status": "CRITICAL_TAMPER_DETECTED",
    "expectedHash": "4a7d...",
    "actualHash": "89f1..."
  }
  ```

### `POST /api/audit/simulate-tamper` (Test Harness Only)
* **Description:** Deliberately modifies an audit entry payload to demonstrate that the cryptographic verification engine flags tampering immediately.
* **Allowed Callers:** `ADMIN` or in Testing Mode.

---

## 6. AI Permission Advisor (TrustVault Sentinel)

### `POST /api/ai/suggest-permissions`
* **Description:** Evaluates a document's classification and metadata, proposing least-privilege permission recommendations.
* **Allowed Callers:** Document Owner or Admin.
* **Safety Contract:**
  - This endpoint is strictly read-only advisory.
  - It NEVER modifies permissions.
  - Both the advice and human decision are recorded in the audit log.

---

## 7. Automated Security Test Suite Runner

### `POST /api/tests/run`
* **Description:** Executes the 10 automated security and authorization attack test cases directly against the backend.
* **Allowed Callers:** Any authenticated user or judge.
* **Tests Executed:** IDOR, Direct storage access, Instant revocation race condition, Audit tamper detection, Path traversal, Malicious MIME blocking, Privilege escalation.
