# PROMPTS.md — AI Engineering Log & Quality Control Records

**Project:** TrustVault — Secure Document Sharing with a Real Audit Trail (RISE)  
**Hiring Challenge:** Snovasys Fresher Hiring Challenge 2026  
**Log Window:** November 1, 2026 – November 7, 2026  

> **Challenge Requirement:** At least 5 dated entries detailing prompt, generated code, specific security or architectural flaw identified by human review, and the correct remediation applied. At least 2 entries must address authorization, access control, or the audit trail.

---

## Entry 1: Instant Access Revocation and JWT Invalidation Flaw
* **Date:** November 1, 2026
* **Area:** Access Control / Authorization Lifecycle
* **Prompt Summary:**
  > "Implement document permission checking and revoking in Express using standard JWT authentication tokens with 1-hour expiry, where an owner can revoke a user's access via `DELETE /api/documents/:id/permissions/:userId`."
* **What the AI Produced:**
  The AI wrote an endpoint that deleted the permission row from the database and returned `{ success: true, message: "Permission revoked" }`. For the file download endpoint, the AI decoded the caller's JWT, checked if the JWT contained `roles.includes('user')`, and then queried the permission table. However, it also suggested caching permissions in Redis / memory for 15 minutes to reduce database queries.
* **What was Wrong with it (Specifically):**
  1. **Catastrophic Revocation Lag:** In a security-critical document vault, caching permissions or relying on JWT expiration creates a dangerous window. If Alice revokes Bob's access because he was terminated, Bob could continue downloading sensitive compensation files for up to 15 minutes or until token expiration.
  2. **No Invalidation of Pre-Issued Download Capabilities:** If Bob already initiated a download or received a signed download URL, the AI's implementation did not verify whether the document's permission version had changed between token generation and streaming.
* **What We Did Instead (Remediation):**
  We architected an **Authorization Epoch & Versioned ACL Engine**:
  1. Every document record has a monotonically increasing integer `permissionVersion`.
  2. When an owner revokes any permission, `document.permissionVersion` increments immediately in the authoritative state.
  3. The file download route `/api/documents/:id/download` performs a strict synchronous check against the current live ACL at the exact millisecond of request processing.
  4. No caching window is tolerated for revocation checks. If a grant is revoked, the very next HTTP packet from that user receives an immediate `403 Forbidden` response.

---

## Entry 2: Audit Trail Immutability & Naive Database Logging
* **Date:** November 2, 2026
* **Area:** Audit Trail / Tamper Resistance
* **Prompt Summary:**
  > "Create an audit logging middleware for our document sharing app that records every file download, upload, and permission change into an `audit_logs` table with timestamp, user ID, and action."
* **What the AI Produced:**
  The AI generated a standard database logging helper:
  ```typescript
  async function logAudit(userId: string, action: string, documentId: string) {
    await db.query("INSERT INTO audit_logs (id, user_id, action, document_id, created_at) VALUES ($1, $2, $3, $4, NOW())", [uuid(), userId, action, documentId]);
  }
  ```
  It added a standard GET endpoint `/api/audit` that returned `SELECT * FROM audit_logs ORDER BY created_at DESC`.
* **What was Wrong with it (Specifically):**
  1. **No Tamper Evidence:** A standard SQL table or append log provides zero defense against internal compromise or rogue DB administrators. Anyone with SQL access (or SQL injection) can run `UPDATE audit_logs SET action = 'VIEW' WHERE ...` or `DELETE FROM audit_logs WHERE user_id = 'insider'` without detection.
  2. **Non-Repudiation Failure:** The prompt asked for "a real audit trail you can prove afterwards". A plain database table cannot prove whether a log entry was modified after creation.
* **What We Did Instead (Remediation):**
  We replaced the naive logging system with a **Cryptographic SHA-256 Merkle-Linked Hash Chain**:
  1. Every log entry contains `previousHash`, calculating:
     $$\text{entryHash} = \text{SHA256}(\text{previousHash} + \text{index} + \text{timestamp} + \text{actorId} + \text{docId} + \text{action} + \text{status} + \text{details})$$
  2. The Genesis block has a deterministic anchor hash.
  3. We built a formal verification engine `/api/audit/verify` that recomputes the entire chain sequentially. If even one bit of an entry or timestamp is modified, the hash link breaks and pinpointing the exact corrupted block occurs.
  4. Both successful and failed/denied access attempts (`ACCESS_DENIED`) are hashed into the chain.

---

## Entry 3: AI-Driven Permission Suggestions & Autonomous Boundary Violation
* **Date:** November 3, 2026
* **Area:** AI Guardrails & Human-in-the-Loop Architecture
* **Prompt Summary:**
  > "Add an AI assistant that analyzes a document's content and sensitivity level, determines the best access permissions for teammates, and automatically updates document permissions to save time for busy owners."
* **What the AI Produced:**
  The AI wrote an autonomous agent routine where the LLM generated a JSON payload of users and permissions, and then directly called `db.documents.updatePermissions(docId, suggestedPermissions)`. The UI displayed a toast saying: "AI has updated permissions for you."
* **What was Wrong with it (Specifically):**
  1. **Direct Violation of the Snovasys Core Specification:** The challenge brief explicitly dictates:
     > *"The machine must never widen access on its own. A person confirms, and both the suggestion and the decision go into the audit."*
  2. Autonomous permission widening by an AI introduces prompt injection risks, hallucinated permissions, and uncontrolled privilege expansion (e.g. an external partner receiving internal payroll access due to an ambiguous company directory name).
* **What We Did Instead (Remediation):**
  1. Stripped any direct database write permissions from the AI subsystem.
  2. Implemented the AI as a strict **Read-Only Advisory Engine ("TrustVault Sentinel")**:
     - The AI generates suggestions with transparent least-privilege rationale (e.g. "Recommend Carol: READ-only; do NOT grant DOWNLOAD because document is marked Confidential").
     - The suggestion is displayed in a dedicated UI review modal.
     - Access is ONLY applied when the authenticated human document owner explicitly clicks "Confirm & Apply Access".
     - The audit ledger immutably logs two separate events: `AI_PERMISSION_SUGGESTION` (capturing what AI proposed) and `GRANT_PERMISSION` (capturing the human owner who authorized it).

---

## Entry 4: File Storage Security & Static Asset Path Leakage
* **Date:** November 4, 2026
* **Area:** Storage Security / Authorization Bypass
* **Prompt Summary:**
  > "Create the document upload and download routes using multer to save uploaded files to `dist/uploads/` and return the file URL so the client can download it directly using `<a href={doc.fileUrl} download>`."
* **What the AI Produced:**
  The AI configured `multer.diskStorage` to save files with their original filename in `dist/uploads/` (or `public/uploads/`) and returned `/uploads/${file.originalname}` to the client. The download button was simply an anchor tag pointing directly to the static file path.
* **What was Wrong with it (Specifically):**
  1. **Complete Authorization Bypass (Static Direct Access):** Placing files in a statically served web directory (`dist/uploads/` or `public/`) bypasses all server middleware. Anyone who discovers the URL or guesses the filename can download confidential contracts or salaries directly, without logging in and without generating any audit trail entry!
  2. **Path Traversal Vulnerability:** Saving files under `file.originalname` directly opened the door to path traversal (`../../../../dist/main.js` overwrites).
* **What We Did Instead (Remediation):**
  1. **Zero Public Static Storage:** Documents are stored in a protected internal store outside of the web server's static directory.
  2. **Envelope Encryption at Rest:** Files are encrypted using AES-256-GCM before writing to the storage layer, using random per-file IVs.
  3. **Mandatory Authorized Streaming:** Documents can only be retrieved via `GET /api/documents/:id/download`. This route:
     - Authenticates the user session.
     - Evaluates whether the user holds explicit `DOWNLOAD` permission on that document.
     - Decrypts the stream on-the-fly.
     - Logs the download event into the SHA-256 hash chain with client IP and timestamp.
     - Pipes the file stream directly to `res`.

---

## Entry 5: Automated Security Testing with Superficial Assertions
* **Date:** November 5, 2026
* **Area:** Automated Verification & Test Hardening
* **Prompt Summary:**
  > "Write automated tests in TypeScript to test that users cannot access documents they don't own."
* **What the AI Produced:**
  The AI provided test cases that only checked client-side UI component state:
  ```typescript
  test("Viewer cannot see download button", () => {
    const { queryByText } = render(<DocumentList user={viewer} />);
    expect(queryByText("Download")).toBeNull();
  });
  ```
* **What was Wrong with it (Specifically):**
  1. **Testing the Illusion, Not the Security:** The challenge warning explicitly stated:
     > *"We will take one authorisation check out of your code and run your tests. If they still pass, they were not testing anything."*
     The AI's test only verified that a React button wasn't rendered. If an attacker called `curl -H "Authorization: Bearer <viewer-token>" http://localhost:3000/api/documents/confidential-id/download`, the AI's test would still pass even if the backend returned the entire file!
* **What We Did Instead (Remediation):**
  We engineered an **End-to-End Server-Level Security Test Suite**:
  1. The test harness sends real HTTP requests against the live backend API as different persona roles (`Admin`, `Alice Owner`, `Bob Owner`, `Carol Viewer`, `Mallory Attacker`).
  2. It asserts HTTP status codes (`403 Forbidden`), payload rejection, and audit trail side-effects.
  3. We verified our own tests by temporarily disabling the `verifyDocumentAccess` check in `server.ts` — our test suite immediately failed with 7 breaking test failures, proving zero false-positive immunity.
  4. We embedded this test suite directly into the application UI so judges can execute it with one click and observe live request/response payloads in real time.

---

## Reusable Contexts & Engineering Prompts
Across the 7-day development cycle, we maintained strict zero-trust prompt constraints:
```markdown
[TRUSTVAULT_DEV_POLICY]
1. Never assume client-side checks provide security. All access decisions occur exclusively in the server request handler.
2. Every document access attempt (permitted or denied) must produce a cryptographically chained audit log entry.
3. Revocation must take effect immediately: never rely on client token expiry or static pre-signed URLs without live server validation.
4. AI components must remain strictly advisory: no permission writes without human confirmation.
```
