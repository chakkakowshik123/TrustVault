# TrustVault — Secure Document Sharing with a Real Audit Trail

> **Snovasys Fresher Hiring Challenge 2026 — RISE**  
> **Challenge Window:** November 1 – 7, 2026  
> **Problem Statement:** Build a document platform where the wrong person can never read the file, and you can prove who read it.

---

## 1. Quick Start & Evaluator Credentials

### Live Deployment
- **Live Application URL:** Available in the AI Studio preview window.
- **Local Dev Server:** `npm install && npm run dev` (Runs on `http://localhost:3000`)

### Seed Accounts for Evaluators
Use the **Persona Switcher** in the top-right corner of the app, or log in with these credentials:

| Role | Name | Email | Password | What This Account Can Do |
|---|---|---|---|---|
| **ADMIN** | Sarah Connor | `admin@trustvault.internal` | `AdminSecure#2026` | Audit ledger inspection, threat alerts, tamper verifications, global overview. |
| **OWNER** | Alice Morgan | `alice.owner@trustvault.internal` | `AliceVault#2026` | Owns Acme Master Agreement & Quantum RFC. Grants/revokes named permissions. |
| **OWNER** | Bob Henderson | `bob.owner@trustvault.internal` | `BobVault#2026` | Owns Q4 Executive Bonus Ledger (`SECRET`). Private, unshared. |
| **VIEWER** | Carol Davies | `carol.viewer@trustvault.internal` | `CarolView#2026` | Has `READ` on Acme Contract. Blocked from Bob's secret document (403). |
| **EXTERNAL** | Dave Wilson | `dave.external@partner.org` | `DavePartner#2026` | External auditor scoped to SOX 404 audit document only. |
| **ATTACKER** | Mallory Vance | `mallory.attacker@hostile.com` | `MalloryPwn#2026` | Pre-configured persona to test IDOR, traversal, and tampering blocks. |

---

## 2. The Three Non-Negotiable Standards & Where to Inspect in Code

### Standard 1: A document is reachable only by someone who was granted it.
* **The Guarantee:** Not "the button is hidden" or "the page checks". The server decides, on every route.
* **Where it happens in code:** `server.ts` $\rightarrow$ `verifyDocumentAccess(user, doc, requiredLevel)` (Line ~295).
* **The Download Enforcement:** `server.ts` $\rightarrow$ `GET /api/documents/:id/download` (Line ~448).
* **Interview Question:** *"Where is the authorization decision made when someone downloads a file, and what would happen if that line were removed?"*
  - **Answer:** The decision is made in `server.ts` inside `GET /api/documents/:id/download` via `verifyDocumentAccess(user, doc, 'DOWNLOAD')`. If that line were removed, any authenticated user who discovers or guesses a document UUID could download confidential compensation spreadsheets or legal agreements directly—causing an immediate IDOR vulnerability. Our automated test `TEST-01-IDOR-READ` and `TEST-02-STORAGE-BYPASS` specifically assert that removing this line causes immediate test failure.

### Standard 2: You can prove who reached it (Cryptographic Audit Trail).
* **The Guarantee:** An audit trail that can be quietly altered is not evidence.
* **Where it happens in code:** `server.ts` $\rightarrow$ `computeBlockHash()` and `appendAuditEntry()` (Lines ~112–158).
* **How it works:** Every single event (including failed `ACCESS_DENIED` attempts) is chained using SHA-256:
  $$\text{Hash}_n = \text{SHA256}(\text{Hash}_{n-1} + \text{Index}_n + \text{Timestamp}_n + \text{Actor}_n + \text{DocID}_n + \text{Action}_n + \text{Status}_n + \text{Details}_n)$$
* **Verification & Tamper Detection:** Open the **"Audit Ledger"** tab and click **"Verify Cryptographic Integrity"** (calls `GET /api/audit/verify`). To test tamper evidence, click **"Simulate Tampering"**; the verifier immediately flags the altered block index and severed hash link.

### Standard 3: Taking access away works immediately (0ms Lag).
* **The Guarantee:** Whatever was issued before that moment stops working instantly.
* **Where it happens in code:** `server.ts` $\rightarrow$ `DELETE /api/documents/:id/permissions/:targetUserId` (Line ~635).
* **How it works:** Revoking access synchronously expunges the user from the document's ACL and increments `doc.permissionVersion`. We deliberately avoid caching permissions or relying on unrevokable pre-signed URLs. The download stream handler evaluates live state on each incoming packet.

---

## 3. The 10 Core Challenge Requirements Checklist

- [x] **1. Authentication with $\ge 3$ roles:** Administrator, Document Owner, Viewer, plus External Partner and Attacker personas.
- [x] **2. Upload, organise, search and manage documents:** Search by title, owner, category, classification, and date.
- [x] **3. Permissions per document:** `READ`, `DOWNLOAD`, `EDIT`, `MANAGE` granted to named individuals.
- [x] **4. Owners can grant access and take it back immediately:** Instant revocation engine with versioned authorization epochs.
- [x] **5. Unpermitted people cannot read, download, change or delete:** Enforced server-side with 403 Forbidden on all routes.
- [x] **6. Audit trail of uploads, downloads, changes, deletions, and permission changes:** SHA-256 Merkle hash chain.
- [x] **7. Search by name, owner, category, and date:** Instant debounce filtering across all metadata.
- [x] **8. Validation of what is uploaded:** Banned executable formats (`.exe`, `.sh`, `.php`), path traversal sanitization, 15MB quota.
- [x] **9. Administrative view:** Real-time threat telemetry, denied attempt velocities, sensitivity distribution, and incident alerts.
- [x] **10. Automated security tests:** 11 end-to-end tests executable directly in the UI ("Attack Tests" tab) and via `POST /api/tests/run`.
- [x] **11. Time-Bound Temporal Access Governance:** Expirable grants (5m demo, 1h contractor, 24h pass) with zero-delay synchronous revocation upon expiry.
- [x] **12. Interactive Exploit Sandbox:** Live evaluator penetration console with custom payload injection and real-time defense interception.
- [x] **13. Forensic Dynamic Watermarking:** Tamper-evident screen watermark with user identity, timestamp, and enclave ID.

---

## 4. Database Schema & Setup Scripts (Clean Clone)

The database architecture is defined in standard relational SQL with 5 core tables, foreign keys, cascading deletions, and cryptographic hash columns:

* **SQL DDL Schema:** [`schema.sql`](./schema.sql) (Defines `users`, `encrypted_blobs`, `documents`, `document_permissions`, `audit_ledger`).
* **Relational Seeds:** [`seeds.sql`](./seeds.sql) (Seed users, encrypted blobs, documents, and Genesis block).
* **Setup & Verification Script:** [`scripts/setup-db.ts`](./scripts/setup-db.ts) (Automates schema validation, disk initialization, and SHA-256 integrity verification).

### To Setup Database from a Clean Clone:
```bash
# 1. Install dependencies
npm install

# 2. Bootstrap & verify database and seeds
npm run db:setup

# 3. Start development server
npm run dev
```

---

## 5. How to Run the Security Attack Tests & Exploit Sandbox

### Option A: In the Web UI:
1. Click the **"Attack Tests (11)"** tab in the top navigation bar.
2. Under **"Automated Threat Suite (11 Tests)"**, click **"Run Full Attack Suite (11 Tests)"**.
3. Under **"Interactive Exploit Sandbox"**, pick an exploit template (IDOR, Role Forgery, Path Traversal, Expiry Replay, Tamper Block) or type arbitrary payloads to see live server interception and SHA-256 audit ledger signing.

### Option B: Via CLI / Terminal:
```bash
# Run full 11-test security suite
curl -s -X POST -H "x-user-id: usr_admin" http://localhost:3000/api/tests/run

# Fire custom exploit simulation
curl -s -X POST -H "Content-Type: application/json" -H "x-user-id: usr_admin" \
  -d '{"attackVector":"IDOR_PROBE","simulatedUserId":"usr_viewer_carol","targetDocId":"doc-exec-003","action":"READ"}' \
  http://localhost:3000/api/tests/custom-attack
```

---

## 6. Required Deliverable Documents
- [`THREATS.md`](./THREATS.md): Comprehensive STRIDE threat model, attacker profiles, defenses, test mappings, and accepted risks.
- [`PROMPTS.md`](./PROMPTS.md): 5 dated entries (Nov 1–7, 2026) documenting prompt, AI mistake caught, and technical remediation.
- [`API_DOCS.md`](./API_DOCS.md): REST API specification, role authorization matrix, and time-bound grant specifications.

---

## 7. Architecture & Technology Stack
- **Backend:** Node.js + Express with TypeScript.
- **Cryptography:** AES-256-GCM symmetric envelope encryption with random IVs + SHA-256 Merkle hash chaining.
- **Frontend:** React 19 + TypeScript + Tailwind CSS + Lucide Icons.
- **Penetration Testing:** Interactive Evaluator Exploit Sandbox + 11 Automated STRIDE-grounded test suites.
- **AI Integration:** Context-aware least-privilege advisor ("TrustVault Sentinel") with strict human-confirmation barriers.
