# THREATS.md — TrustVault Threat Model & Security Posture

**Application:** TrustVault — Secure Document Sharing with a Real Audit Trail  
**Challenge:** Snovasys Fresher Hiring Challenge 2026 — RISE  
**Date:** November 1 – 7, 2026  
**Security Standard:** Strict Zero-Trust, Server-Authoritative Access Control, Tamper-Evident Cryptographic Audit Trails, and Immediate Access Revocation.

---

## 1. Threat Modeling Methodology

TrustVault is analyzed using the **STRIDE** methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) combined with an assumed adversary model:

### Attacker Profiles
1. **Curious Insider (Viewer):** Authenticated user attempting to view or download documents outside their explicit grant (Insecure Direct Object Reference / IDOR).
2. **Disgruntled Former Employee (Revoked User):** User whose access was just revoked attempting to reuse cached tokens, unclosed browser tabs, pre-signed download URLs, or replay requests.
3. **Privilege Escalator:** Viewer or External Partner attempting to grant themselves `EDIT` or `MANAGE` rights, or modify documents they only have `READ` access to.
4. **Malicious Administrator or Compromised DB Operator:** Admin attempting to covertly read sensitive files without authorization, or alter the audit trail to hide illicit actions.
5. **External Hostile Actor (Mallory):** Unauthenticated attacker probing API routes, injecting malicious payloads (`.exe`, `.sh`, polyglot files), directory traversal (`../../`), or tampered cryptographic signatures.

---

## 2. Threat Catalog, Mitigations & Verification Tests

### T-01: Insecure Direct Object Reference (IDOR) on Document Retrieval
* **STRIDE:** Information Disclosure
* **Attack Vector:** An attacker discovers or guesses a valid document UUID (`/api/documents/doc-finance-001`) belonging to another department or owner, and issues direct GET or download requests.
* **Why Client-Side Hiding Fails:** In naive systems, the UI hides the button, but the REST endpoint `/api/documents/:id` responds with the payload if the user has any valid JWT.
* **TrustVault Defense:** Server-authoritative permission validation. On *every* document read, download, or metadata request, `verifyDocumentAccess(user, docId, requiredPermission)` checks the live Access Control List (ACL). If `user.id` is not the owner, not an admin with explicit audit clearance, and not explicitly granted the required permission, the server halts with `403 Forbidden` and writes an `ACCESS_DENIED` event to the cryptographic audit trail.
* **Automated Test:** `TEST_01_IDOR_PREVENTION` (Carol Viewer attempts to fetch Bob's confidential "Q4 Executive Bonus Ledger" -> 403 Forbidden).

---

### T-02: Stale Authorization & Race Conditions during Access Revocation
* **STRIDE:** Elevation of Privilege / Information Disclosure
* **Attack Vector:** An owner revokes a user's access at 14:00:00. The user had already received a download link or kept a session token valid until 14:15:00, or a distributed cache holds permissions for 5 minutes.
* **Why JWT Expiry Alone Fails:** Stateless JWTs cannot be revoked without state tracking or short expiries; even 60-second windows allow automated mass downloads of proprietary documents.
* **TrustVault Defense:** Instant Revocation Engine with Authorization Epochs.
  1. Revoking access increments the document's `permissionVersion` and expunges the grant from the live ledger.
  2. The server *never* trusts client-side authorization state or pre-signed static URLs for document downloads.
  3. Every file download route passes through live server verification against the current database state at the microsecond of request handling.
  4. Any download token is bound to `(userId, docId, permissionVersion, epoch)`. If `permissionVersion` has incremented, the token is instantly invalid.
* **Automated Test:** `TEST_03_INSTANT_REVOCATION` (Bob revokes Carol; Carol's next request in the same second receives 403 Forbidden).

---

### T-03: Tampering with the Audit Trail (Post-Breach Evidence Destruction)
* **STRIDE:** Tampering / Repudiation
* **Attack Vector:** A rogue administrator or attacker who gained database write access modifies past audit records to erase proof of unauthorized downloads, or deletes entries indicating access denial.
* **Why Traditional DB Logs Fail:** SQL `UPDATE audit_logs SET action='READ' WHERE ...` or `DELETE` leaves no trace if the attacker has DB credentials.
* **TrustVault Defense:** Cryptographic SHA-256 Hash Chaining (Merkle/Blockchain Architecture).
  1. Every audit record includes:
     $$\text{Hash}_n = \text{SHA-256}(\text{Hash}_{n-1} + \text{Index}_n + \text{Timestamp}_n + \text{ActorID}_n + \text{DocID}_n + \text{Action}_n + \text{Status}_n + \text{Details}_n)$$
  2. Modifying even a single character in block $k$ breaks the hash linkage for all subsequent blocks $k+1 \dots N$.
  3. Continuous background & on-demand cryptographic verification (`/api/audit/verify`) traverses the chain from Genesis block #0 to tip. If any hash fails to match, the system generates a critical tamper alert and pinpoints the exact corrupted block.
* **Automated Test:** `TEST_04_AUDIT_TAMPER_DETECTION` (Simulated tampering of an audit payload causes the cryptographic verifier to flag block tampering).

---

### T-04: Direct Storage Blob Access (Static File Bypassing)
* **STRIDE:** Information Disclosure
* **Attack Vector:** Attacker discovers the physical or cloud storage path of the file (e.g., `/storage/documents/payroll_2026.pdf` or an S3 bucket URL) and fetches it directly without traversing the application layer.
* **TrustVault Defense:**
  1. Zero Direct Static Serving: Files are *never* stored in public folders (e.g. `public/` or Vite root) or served statically.
  2. Envelope Encryption at Rest: Document payloads are AES-256-GCM encrypted prior to disk storage with random 128-bit Initialization Vectors (IV) and 128-bit authentication tags.
  3. Streaming via Authorizing Proxy: Files can ONLY be fetched through the authenticated streaming endpoint `/api/documents/:id/download`, which validates permissions, decrypts on-the-fly, logs the audit trail, and pipes to the response stream.
* **Automated Test:** `TEST_02_STORAGE_BYPASS_PROTECTION` (Direct file path probing returns 404 or 403).

---

### T-05: Path Traversal & Arbitrary File Overwrite
* **STRIDE:** Tampering / Elevation of Privilege
* **Attack Vector:** Malicious user uploads a file with a crafted filename like `../../../../etc/passwd` or `../../../dist/index.html` to overwrite system files or executable binaries.
* **TrustVault Defense:**
  1. Filename Sanitization: Raw user filenames are sanitized using strict alphanumeric + dot regex (`/[^a-zA-Z0-9._-]/g`) and stripped of all path separators (`/`, `\`, null bytes `%00`).
  2. Storage Isolation: On disk, files are stored using random UUID keys (`doc_blob_<uuid>.enc`), completely decoupled from the original filename. The original display name is preserved strictly in sanitized metadata.
* **Automated Test:** `TEST_07_PATH_TRAVERSAL_PREVENTION` (Uploading `../../../../etc/passwd` stores safely under UUID without path escaping).

---

### T-06: Malicious File Upload & Polyglot Executable Execution
* **STRIDE:** Elevation of Privilege / Denial of Service
* **Attack Vector:** An attacker uploads a shell script (`shell.php`, `exploit.exe`, `malware.sh`, `payload.vbs`) or a polyglot file disguised as a PDF/JPEG to execute arbitrary code on the server or client machines.
* **TrustVault Defense:**
  1. Strict MIME and Extension Allow-list: Disallows all executable formats (`.exe`, `.sh`, `.bat`, `.cmd`, `.js`, `.php`, `.vbs`, `.dll`, `.wasm`, `.scr`, `.jar`).
  2. Magic Byte Signature Verification: Server inspects the leading file header bytes (e.g., `%PDF-` for PDFs, `\xFF\xD8\xFF` for JPEGs, `\x89PNG` for PNGs, `PK\x03\x04` for Office ZIP formats) rather than trusting client-supplied `Content-Type`.
  3. Maximum Size Quotas: Hard cap of 15MB enforced at the middleware layer prevents denial-of-service via disk exhaustion.
* **Automated Test:** `TEST_06_MALICIOUS_UPLOAD_REJECTION` (Uploading an `.exe` disguised as a PDF is rejected with 400 Bad Request).

---

### T-07: Privilege Escalation on Permission Assignment
* **STRIDE:** Elevation of Privilege
* **Attack Vector:** A user with `READ` permission calls `POST /api/documents/:id/permissions` to grant themselves `EDIT` or `MANAGE` rights, or modify other users' access levels.
* **TrustVault Defense:**
  1. Only the document `owner` or a system `ADMIN` holds the capability to invoke permission modification endpoints.
  2. Permission mutation checks verify the caller's identity against the document's `ownerId` or system role.
  3. Every permission grant and revocation is immutably logged with the author's identity and timestamp.
* **Automated Test:** `TEST_05_PRIVILEGE_ESCALATION_PREVENTION` (Carol Viewer attempting to grant herself `EDIT` permission receives 403 Forbidden).

---

### T-08: AI-Assisted Permission Over-Granting (Autonomous Drift)
* **STRIDE:** Information Disclosure / Elevation of Privilege
* **Attack Vector:** An AI assistant, tasked with suggesting access permissions, autonomously modifies permissions or misinterprets user intent, inadvertently widening access to sensitive documents.
* **TrustVault Defense:**
  1. Architectural Constraint: The AI module is strictly advisory (`READ-ONLY` context).
  2. The server rejects any permission update that lacks an explicit cryptographic human approval signature.
  3. Both the AI's recommendation and the human owner's final decision are recorded in the audit trail, guaranteeing accountability.
* **Automated Test:** `TEST_10_AI_AUTONOMOUS_WIDENING_REJECTION` (Server rejects automated AI grant requests lacking human owner confirmation).

---

### T-09: Unlogged Failed / Probing Attacks (Silent Reconnaissance)
* **STRIDE:** Repudiation / Information Disclosure
* **Attack Vector:** An attacker scans document IDs or tests passwords. If only successful actions are logged, security teams cannot detect automated brute-force or reconnaissance attacks.
* **TrustVault Defense:**
  1. All failed authorization checks, 401 Unauthenticated, and 403 Forbidden outcomes generate high-priority `ACCESS_DENIED` blocks in the cryptographic hash chain.
  2. Real-time threat detection calculates failed access velocity: $\ge 3$ denied attempts within 60 seconds triggers a high-severity security alert on the Admin Dashboard.
* **Automated Test:** `TEST_08_FAILED_ATTEMPT_FORENSICS` (Failed access attempts appear in audit ledger with IP, timestamp, and attempted document ID).

---

## 3. Knowingly Accepted Risks & Justifications

| Risk ID | Accepted Threat | Justification & Mitigations in Place |
|---|---|---|
| **R-01** | **Client-side screen capture / physical camera photography of opened documents** | Once a document is legibly decrypted on a client screen, preventing physical photography or OS-level screenshots is impossible in standard web standards. Mitigated via: visible dynamic forensic watermarking displaying viewer email, IP, and timestamp on document previews. |
| **R-02** | **Full server host compromise (Root OS breach)** | If an adversary obtains root execution on the host server containing the encryption master key in RAM, they can decrypt files in memory. Mitigated in enterprise deployments via Hardware Security Modules (HSM) / AWS KMS / Cloud KMS with envelope encryption, where the root key never enters application memory. |
| **R-03** | **Network-level Denial of Service (Volumetric DDoS)** | Application-level rate limiting is implemented, but volumetric L3/L4 network floods require upstream cloud CDN/DDoS scrubbing (Cloudflare, Google Cloud Armor) outside the application container boundary. |

---

## 4. Summary Matrix: Threats vs Automated Tests

| Threat | STRIDE | Severity | Server Defense | Automated Test |
|---|---|---|---|---|
| IDOR Document Access | Information Disclosure | Critical | Strict ACL on all routes | `TEST_01_IDOR` |
| Direct Storage Path Access | Information Disclosure | Critical | AES-256 encrypted blobs, no static routes | `TEST_02_STORAGE` |
| Revoked User Replay | Elevation of Privilege | Critical | Versioned authorization epochs | `TEST_03_REVOCATION` |
| Audit Trail Tampering | Tampering / Repudiation | Critical | Cryptographic SHA-256 Hash Chain | `TEST_04_AUDIT_INTEGRITY` |
| Unauthorized Permission Edit | Elevation of Privilege | High | Owner/Admin check on ACL mutations | `TEST_05_ESCALATION` |
| Malicious File Upload | Tampering / DoS | High | Magic-byte & extension verification | `TEST_06_FILE_VALIDATION` |
| Path Traversal (`../../`) | Tampering / Elevation | High | Path sanitization & UUID storage | `TEST_07_PATH_TRAVERSAL` |
| Unlogged Probing Attacks | Repudiation | Medium | Every 403 logged to hash chain | `TEST_08_DENIAL_LOGGING` |
| AI Autonomous Granting | Information Disclosure | Medium | Human-confirmation barrier | `TEST_10_AI_GUARDRAIL` |
