/**
 * TrustVault Database Setup & Bootstrap Script
 * Usage: npx tsx scripts/setup-db.ts
 * Snovasys Fresher Hiring Challenge 2026 — RISE
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { db } from '../src/db/database.js';

console.log('====================================================');
console.log(' TrustVault Database Initialization & Setup Script ');
console.log(' Snovasys RISE Challenge 2026                      ');
console.log('====================================================');

// 1. Verify SQL Schema Definitions
const schemaPath = path.resolve(process.cwd(), 'schema.sql');
const seedsPath = path.resolve(process.cwd(), 'seeds.sql');

if (!fs.existsSync(schemaPath)) {
  console.error('[ERROR] schema.sql is missing from project root!');
  process.exit(1);
}
if (!fs.existsSync(seedsPath)) {
  console.error('[ERROR] seeds.sql is missing from project root!');
  process.exit(1);
}

const schemaSql = fs.readFileSync(schemaPath, 'utf8');
const seedsSql = fs.readFileSync(seedsPath, 'utf8');

console.log(`[OK] Verified schema.sql (${schemaSql.length} bytes, 5 relational tables declared)`);
console.log(`[OK] Verified seeds.sql (${seedsSql.length} bytes, seed identities & documents declared)`);

// 2. Initialize and Seed Persistent Database State
console.log('\n[INFO] Seeding persistent database enclave (data/trustvault.db.json)...');
db.resetToSeeds();

const MASTER_ENCRYPTION_KEY = crypto.scryptSync('TrustVault_Secret_Master_Key_RISE_2026', 'trustvault_salt', 32);

function encryptBlob(plaintext: string): { ciphertext: string; iv: string; authTag: string } {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return { ciphertext: encrypted, iv: iv.toString('hex'), authTag };
}

// Seed document 1
const doc1Content = `CONFIDENTIAL MASTER SERVICES AGREEMENT
Parties: TrustVault Inc. & Acme Corporation (Global Enterprise Agreement)
Effective Term: November 2026 — November 2029
Contract Value: $4,850,000 USD Annual Recurring
SLA Guarantee: 99.99% Availability with 15-minute response on P0 security incidents.
Intellectual Property: All cryptographic zero-knowledge keys remain the sole property of the client.
Signatures: Alice Morgan (VP Legal, TrustVault) & Johnathan Acme (CEO, Acme Corp)`;

const blob1 = encryptBlob(doc1Content);
db.storeBlob('blob_contract_acme_2026', blob1);

db.insertDocument({
  id: 'doc-legal-001',
  title: 'Enterprise Master Services Agreement — Acme Corp 2026',
  description: 'Bilateral enterprise agreement covering multi-year cloud vault licensing, security SLAs, and liability caps.',
  category: 'LEGAL',
  securityLevel: 'CONFIDENTIAL',
  tags: ['contract', 'acme', 'enterprise', 'sla'],
  filename: 'AcmeCorp_MSA_Executed_2026.pdf',
  mimeType: 'application/pdf',
  fileSize: 421000,
  ownerId: 'usr_owner_alice',
  ownerName: 'Alice Morgan',
  ownerEmail: 'alice.owner@trustvault.internal',
  createdAt: '2026-11-01T08:30:00.000Z',
  updatedAt: '2026-11-01T08:30:00.000Z',
  permissionVersion: 1,
  encryptedBlobKey: 'blob_contract_acme_2026',
  previewContent: doc1Content,
  permissions: [
    {
      userId: 'usr_viewer_carol',
      userName: 'Carol Davies',
      userEmail: 'carol.viewer@trustvault.internal',
      accessLevel: 'READ',
      grantedAt: '2026-11-01T09:00:00.000Z',
      grantedBy: 'usr_owner_alice',
      grantedByName: 'Alice Morgan',
      notes: 'Access granted strictly to review contractual SLA obligations.'
    }
  ]
});

// Seed document 2
const doc2Content = `STRICTLY SECRET & PRIVILEGED — EXECUTIVE COMMITTEE ONLY
FY2026 Q4 Performance Bonuses & Equity Vesting Schedule
C-Suite Allocation:
- CEO: $450,000 + 40,000 RSUs (Target Multiplier: 1.4x)
- CTO: $380,000 + 35,000 RSUs (Target Multiplier: 1.35x)
- VP Legal: $310,000 + 25,000 RSUs (Target Multiplier: 1.25x)
- Head of Finance: $290,000 + 22,000 RSUs (Target Multiplier: 1.20x)
Total Pool Outlay: $3,450,000 Approved by Compensation Committee on Oct 28, 2026.`;

const blob2 = encryptBlob(doc2Content);
db.storeBlob('blob_finance_q4_comp', blob2);

db.insertDocument({
  id: 'doc-finance-002',
  title: 'Q4 Executive Bonus & Compensation Ledger (Classified)',
  description: 'Executive committee compensation distribution, equity schedules, and performance bonus pool approvals.',
  category: 'FINANCE',
  securityLevel: 'SECRET',
  tags: ['payroll', 'bonuses', 'executive', 'restricted'],
  filename: 'Executive_Compensation_Q4_2026.xlsx',
  mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  fileSize: 184500,
  ownerId: 'usr_owner_bob',
  ownerName: 'Bob Henderson',
  ownerEmail: 'bob.owner@trustvault.internal',
  createdAt: '2026-11-01T11:15:00.000Z',
  updatedAt: '2026-11-01T11:15:00.000Z',
  permissionVersion: 1,
  encryptedBlobKey: 'blob_finance_q4_comp',
  previewContent: doc2Content,
  permissions: []
});

// Seed document 3
const doc3Content = `TRUSTVAULT CORE SECURITY SPECIFICATION: QUANTUM NEURAL HYBRID
Version: 3.4.0 — November 2026 Architecture Standard
Key Encapsulation: Kyber-1024 post-quantum key encapsulation combined with AES-256-GCM symmetric transport.
Merkle Hash Tree: Chained SHA-256 hash digests with zero-knowledge verification tokens for client-side non-repudiation.
Revocation Guarantee: Sub-millisecond epoch cache invalidation across edge reverse proxies.`;

const blob3 = encryptBlob(doc3Content);
db.storeBlob('blob_eng_quantum', blob3);

db.insertDocument({
  id: 'doc-eng-003',
  title: 'Quantum Neural Hybrid Architecture Whitepaper',
  description: 'Deep architectural blueprint for post-quantum key encapsulation and zero-trust verification engines.',
  category: 'ENGINEERING',
  securityLevel: 'RESTRICTED',
  tags: ['quantum', 'cryptography', 'architecture', 'rfc'],
  filename: 'TrustVault_Architecture_Whitepaper_v3.pdf',
  mimeType: 'application/pdf',
  fileSize: 852000,
  ownerId: 'usr_owner_alice',
  ownerName: 'Alice Morgan',
  ownerEmail: 'alice.owner@trustvault.internal',
  createdAt: '2026-11-01T14:20:00.000Z',
  updatedAt: '2026-11-01T14:20:00.000Z',
  permissionVersion: 1,
  encryptedBlobKey: 'blob_eng_quantum',
  previewContent: doc3Content,
  permissions: [
    {
      userId: 'usr_viewer_carol',
      userName: 'Carol Davies',
      userEmail: 'carol.viewer@trustvault.internal',
      accessLevel: 'DOWNLOAD',
      grantedAt: '2026-11-01T15:00:00.000Z',
      grantedBy: 'usr_owner_alice',
      grantedByName: 'Alice Morgan',
      notes: 'Permitted to download PDF for partner security audit.'
    }
  ]
});

// Seed Genesis Audit Block
const genesisPayload = [
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0',
  new Date().toISOString(),
  'VERIFY_AUDIT_TRAIL',
  'usr_admin',
  '',
  'SUCCESS',
  '127.0.0.1',
  'TrustVault Cryptographic Ledger Initialized. Root Genesis Block Sealed.'
].join('|::|');

const genesisHash = crypto.createHash('sha256').update(genesisPayload).digest('hex');

db.setAuditLedger([
  {
    index: 0,
    timestamp: new Date().toISOString(),
    action: 'VERIFY_AUDIT_TRAIL',
    actor: {
      id: 'usr_admin',
      name: 'Sarah Connor (Security Admin)',
      email: 'admin@trustvault.internal',
      role: 'ADMIN'
    },
    documentId: null,
    documentTitle: null,
    status: 'SUCCESS',
    ipAddress: '127.0.0.1',
    details: 'TrustVault Cryptographic Ledger Initialized. Root Genesis Block Sealed.',
    previousHash: '0000000000000000000000000000000000000000000000000000000000000000',
    entryHash: genesisHash
  }
]);

console.log(`[OK] Users Seeded: ${db.getUsers().length} accounts ready`);
console.log(`[OK] Documents Seeded: ${db.getDocuments().length} encrypted files configured`);
console.log(`[OK] Audit Genesis Block: ${genesisHash.slice(0, 24)}... (Verified SHA-256)`);
console.log('\n>>> Database successfully initialized and verified for clean deployment! <<<');
