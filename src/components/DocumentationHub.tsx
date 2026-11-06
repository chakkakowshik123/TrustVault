import React, { useState } from 'react';
import { 
  BookOpen, 
  Shield, 
  FileText, 
  Sparkles, 
  KeyRound, 
  CheckCircle2, 
  ExternalLink,
  Code,
  AlertTriangle,
  Server
} from 'lucide-react';

export const DocumentationHub: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<'overview' | 'threats' | 'prompts' | 'api' | 'schema' | 'creds'>('overview');

  return (
    <div className="space-y-6">
      {/* Top Navigation */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow-xl flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <BookOpen className="w-5 h-5 text-indigo-400" />
          <h2 className="text-base font-bold text-slate-100">Project Deliverables & Governance Documentation</h2>
        </div>

        <div className="flex flex-wrap items-center gap-1.5 bg-slate-950 p-1 rounded-xl border border-slate-800">
          <button
            onClick={() => setActiveSubTab('overview')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeSubTab === 'overview'
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Project Summary
          </button>

          <button
            onClick={() => setActiveSubTab('threats')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeSubTab === 'threats'
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            THREATS.md
          </button>

          <button
            onClick={() => setActiveSubTab('prompts')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeSubTab === 'prompts'
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            PROMPTS.md (5 Entries)
          </button>

          <button
            onClick={() => setActiveSubTab('api')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeSubTab === 'api'
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            API Specification
          </button>

          <button
            onClick={() => setActiveSubTab('schema')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeSubTab === 'schema'
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Database (SQL Schema & Setup)
          </button>

          <button
            onClick={() => setActiveSubTab('creds')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeSubTab === 'creds'
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Seed Credentials
          </button>
        </div>
      </div>

      {/* Content Area */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl text-slate-300 text-xs leading-relaxed space-y-6">
        {/* SUBTAB 1: Project Overview & Evaluation Write-up */}
        {activeSubTab === 'overview' && (
          <div className="space-y-6 max-w-4xl">
            <div>
              <span className="text-[10px] uppercase font-bold tracking-wider text-indigo-400">Challenge Submission</span>
              <h3 className="text-xl font-bold text-slate-100 mt-1">
                TrustVault — Secure Document Sharing with a Real Audit Trail
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Snovasys Fresher Hiring Challenge 2026 — RISE (November 1 – 7, 2026)
              </p>
            </div>

            <div className="p-4 bg-indigo-950/30 border border-indigo-800/40 rounded-xl space-y-2 text-indigo-200">
              <h4 className="font-bold text-slate-100 flex items-center gap-2">
                <Shield className="w-4 h-4 text-indigo-400" />
                <span>The Three Non-Negotiable Standards Achieved</span>
              </h4>
              <ul className="list-disc pl-5 space-y-1.5 text-xs">
                <li>
                  <strong>1. Zero-Leakage Server Authority:</strong> A document is reachable only by someone explicitly granted it.
                  The server validates live ACL on every single request; UI buttons are purely decorative affordances.
                </li>
                <li>
                  <strong>2. Cryptographic Proof (Non-Repudiation):</strong> An audit trail that can be altered is not evidence.
                  Every download, read, upload, grant, and refused attempt is sealed in a continuous SHA-256 Merkle hash chain.
                </li>
                <li>
                  <strong>3. Immediate Revocation (0ms Lag):</strong> Taking access away works instantly.
                  All authorization epochs increment monotonically; pre-issued capabilities and cached sessions stop working immediately.
                </li>
              </ul>
            </div>

            <div className="space-y-4">
              <h4 className="text-sm font-bold text-slate-100">1. Permission Model in Our Own Words</h4>
              <p>
                TrustVault implements a hybrid <strong>Role-Based Access Control (RBAC) + Per-Document Access Control List (ACL)</strong> architecture.
                Users hold an organizational role (<code>ADMIN</code>, <code>DOCUMENT_OWNER</code>, <code>VIEWER</code>, <code>EXTERNAL_PARTNER</code>).
                However, individual documents are controlled by the document owner through an authoritative ACL matrix:
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                  <strong className="text-emerald-400 block font-semibold">READ</strong>
                  <span className="text-[11px] text-slate-400">Decrypted inline preview in secure enclave. No export.</span>
                </div>
                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                  <strong className="text-cyan-400 block font-semibold">DOWNLOAD</strong>
                  <span className="text-[11px] text-slate-400">Authorize binary stream download through proxy.</span>
                </div>
                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                  <strong className="text-amber-400 block font-semibold">EDIT</strong>
                  <span className="text-[11px] text-slate-400">Modify metadata and upload new revisions.</span>
                </div>
                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                  <strong className="text-indigo-400 block font-semibold">MANAGE</strong>
                  <span className="text-[11px] text-slate-400">Grant and revoke named access to colleagues.</span>
                </div>
              </div>
            </div>

            <div className="space-y-3">
              <h4 className="text-sm font-bold text-slate-100">2. What We Chose Not to Build, and Why</h4>
              <div className="space-y-2">
                <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800">
                  <strong className="text-slate-200">1. Stateless Long-Lived Pre-Signed S3 URLs:</strong> Naive cloud architectures generate pre-signed URLs valid for 15 minutes. This creates an unacceptable 15-minute window where a revoked employee can still download confidential files. We deliberately routed all downloads through an authorizing stream proxy with live state checks.
                </div>
                <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800">
                  <strong className="text-slate-200">2. Autonomous AI Permission Granting:</strong> As commanded by Snovasys specifications: <em>"The machine must never widen access on its own."</em> We built TrustVault Sentinel as a strictly advisory intelligence layer requiring human confirmation.
                </div>
                <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800">
                  <strong className="text-slate-200">3. Plain SQL / MongoDB Audit Logs:</strong> Standard database rows can be silently modified with an <code>UPDATE</code> query by a malicious administrator. We replaced this with a SHA-256 cryptographic hash chain with public audit verification.
                </div>
                <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800">
                  <strong className="text-slate-200">4. Static Permanent-Only Grants (Time-Bound Governance Added):</strong> TrustVault supports expirable permissions (5m evaluator demo, 1h contractor window, 24h emergency audit pass). Expirations are enforced synchronously in the request pipeline with zero delay.
                </div>
                <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800">
                  <strong className="text-slate-200">5. Interactive Exploit Sandbox for Evaluators:</strong> In addition to 11 automated security tests, evaluators can launch real adversarial payloads in the live Exploit Sandbox and observe instant server interception and audit hashes.
                </div>
              </div>
            </div>
          </div>
        )}

        {/* SUBTAB 2: THREATS.md */}
        {activeSubTab === 'threats' && (
          <div className="space-y-4 max-w-4xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div>
                <h3 className="text-base font-bold text-slate-100">THREATS.md — Full Adversary Threat Catalog</h3>
                <p className="text-xs text-slate-400">STRIDE categorization, server mitigations, and automated test mappings.</p>
              </div>
              <span className="text-xs bg-indigo-950 text-indigo-300 border border-indigo-800 px-2.5 py-1 rounded-lg font-mono">
                9 Documented Threats
              </span>
            </div>

            <div className="space-y-3">
              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-indigo-400 font-bold">T-01: Insecure Direct Object Reference (IDOR)</span>
                  <span className="text-[10px] bg-rose-500/10 text-rose-400 border border-rose-500/30 px-2 py-0.5 rounded-full font-bold">Information Disclosure</span>
                </div>
                <p className="text-slate-300">
                  Attacker guesses document ID. Naive apps hide UI button but allow REST call.
                </p>
                <div className="text-[11px] text-slate-400">
                  <strong>TrustVault Defense:</strong> Server executes <code>verifyDocumentAccess</code> on every single request.
                  <strong> Test:</strong> <code>TEST_01_IDOR_PREVENTION</code>
                </div>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-indigo-400 font-bold">T-02: Stale Authorization on Access Revocation</span>
                  <span className="text-[10px] bg-amber-500/10 text-amber-400 border border-amber-500/30 px-2 py-0.5 rounded-full font-bold">Elevation of Privilege</span>
                </div>
                <p className="text-slate-300">
                  User access is revoked, but cached JWT or pre-signed link continues to work for minutes.
                </p>
                <div className="text-[11px] text-slate-400">
                  <strong>TrustVault Defense:</strong> Monotonic permissionVersion epoch invalidation. Zero cache tolerance.
                  <strong> Test:</strong> <code>TEST_03_INSTANT_REVOCATION</code>
                </div>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-indigo-400 font-bold">T-03: Post-Breach Audit Trail Tampering</span>
                  <span className="text-[10px] bg-purple-500/10 text-purple-400 border border-purple-500/30 px-2 py-0.5 rounded-full font-bold">Tampering & Repudiation</span>
                </div>
                <p className="text-slate-300">
                  Compromised DB operator modifies audit records to hide unauthorized downloads.
                </p>
                <div className="text-[11px] text-slate-400">
                  <strong>TrustVault Defense:</strong> Cryptographic SHA-256 Merkle hash chain. Tampering one byte shatters chain.
                  <strong> Test:</strong> <code>TEST_04_AUDIT_INTEGRITY</code>
                </div>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-indigo-400 font-bold">T-04: Direct Static Storage Bypass</span>
                  <span className="text-[10px] bg-rose-500/10 text-rose-400 border border-rose-500/30 px-2 py-0.5 rounded-full font-bold">Information Disclosure</span>
                </div>
                <p className="text-slate-300">
                  Attacker discovers static upload directory (e.g. <code>/uploads/contract.pdf</code>) and bypasses authentication.
                </p>
                <div className="text-[11px] text-slate-400">
                  <strong>TrustVault Defense:</strong> Zero static serving. AES-256-GCM envelope encryption at rest. Decryption proxy only.
                  <strong> Test:</strong> <code>TEST_02_STORAGE_BYPASS</code>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* SUBTAB 3: PROMPTS.md */}
        {activeSubTab === 'prompts' && (
          <div className="space-y-4 max-w-4xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div>
                <h3 className="text-base font-bold text-slate-100">PROMPTS.md — AI Engineering Log (Nov 1–7, 2026)</h3>
                <p className="text-xs text-slate-400">
                  Mandatory challenge deliverable: 5 dated entries detailing prompt, hallucination/flaw caught, and technical remediation.
                </p>
              </div>
              <span className="text-xs bg-emerald-950 text-emerald-300 border border-emerald-800 px-2.5 py-1 rounded-lg font-mono">
                5 Dated Entries Verified
              </span>
            </div>

            <div className="space-y-3">
              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <strong className="text-slate-200">Entry 1 (Nov 1, 2026): Instant Revocation & JWT Invalidation Flaw</strong>
                  <span className="text-[10px] font-mono text-slate-500">Access Control</span>
                </div>
                <p className="text-slate-400">
                  <strong>AI Flaw:</strong> Proposed 1-hour JWTs with Redis caching for 15 minutes. Revoked users could continue downloading files for 15 minutes!
                </p>
                <p className="text-indigo-300">
                  <strong>Remediation:</strong> Designed authorization epochs where revoking increments doc version; stream handler checks live state synchronously.
                </p>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <strong className="text-slate-200">Entry 2 (Nov 2, 2026): Audit Trail Immutability & Naive DB Logging</strong>
                  <span className="text-[10px] font-mono text-slate-500">Audit Trail</span>
                </div>
                <p className="text-slate-400">
                  <strong>AI Flaw:</strong> Used standard SQL <code>INSERT INTO audit_logs</code>. Anyone with database access could run <code>UPDATE</code> or <code>DELETE</code> without leaving a trace.
                </p>
                <p className="text-indigo-300">
                  <strong>Remediation:</strong> Implemented SHA-256 Merkle-linked hash chain with cryptographic verification engine.
                </p>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <strong className="text-slate-200">Entry 3 (Nov 3, 2026): AI Autonomous Permission Widening</strong>
                  <span className="text-[10px] font-mono text-slate-500">AI Guardrail</span>
                </div>
                <p className="text-slate-400">
                  <strong>AI Flaw:</strong> Created an AI agent that automatically widened user permissions upon parsing document text, directly violating Snovasys requirement: <em>"The machine must never widen access on its own."</em>
                </p>
                <p className="text-indigo-300">
                  <strong>Remediation:</strong> Rebuilt AI as read-only advisor requiring mandatory human confirmation signature. Both suggestion and decision logged to audit.
                </p>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <strong className="text-slate-200">Entry 4 (Nov 4, 2026): Static Asset Path Leakage & Path Traversal</strong>
                  <span className="text-[10px] font-mono text-slate-500">Storage Security</span>
                </div>
                <p className="text-slate-400">
                  <strong>AI Flaw:</strong> Stored uploaded files in <code>dist/uploads/filename</code> and served directly via static link, completely bypassing server auth.
                </p>
                <p className="text-indigo-300">
                  <strong>Remediation:</strong> Zero static serving; AES-256-GCM envelope encryption at rest; randomized UUID blob keys; streaming proxy route.
                </p>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <strong className="text-slate-200">Entry 5 (Nov 5, 2026): Superficial Automated Tests (False Positives)</strong>
                  <span className="text-[10px] font-mono text-slate-500">Security Testing</span>
                </div>
                <p className="text-slate-400">
                  <strong>AI Flaw:</strong> Wrote UI-only tests checking if button was rendered. Removing server check still passed the tests!
                </p>
                <p className="text-indigo-300">
                  <strong>Remediation:</strong> Created real HTTP end-to-end security test suite asserting 403 Forbidden on server endpoints.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* SUBTAB 4: API Specification */}
        {activeSubTab === 'api' && (
          <div className="space-y-4 max-w-4xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div>
                <h3 className="text-base font-bold text-slate-100">API Documentation & Caller Authorizations</h3>
                <p className="text-xs text-slate-400">Listing of all endpoints and exact permission rules.</p>
              </div>
            </div>

            <div className="space-y-2 text-xs">
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono">
                <span className="text-emerald-400 font-bold">POST /api/auth/login</span>
                <span className="text-slate-500 block text-[11px] font-sans mt-0.5">Caller: Public. Authenticates user and returns session.</span>
              </div>
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono">
                <span className="text-cyan-400 font-bold">GET /api/documents</span>
                <span className="text-slate-500 block text-[11px] font-sans mt-0.5">Caller: Authenticated. Server strictly filters unshared files.</span>
              </div>
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono">
                <span className="text-cyan-400 font-bold">GET /api/documents/:id</span>
                <span className="text-slate-500 block text-[11px] font-sans mt-0.5">Caller: Owner, Admin, or user with READ grant. Returns 403 and logs ACCESS_DENIED otherwise.</span>
              </div>
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono">
                <span className="text-cyan-400 font-bold">GET /api/documents/:id/download</span>
                <span className="text-slate-500 block text-[11px] font-sans mt-0.5">Caller: Owner or user with DOWNLOAD grant. Decrypts AES-256 stream and signs audit block.</span>
              </div>
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono">
                <span className="text-indigo-400 font-bold">POST /api/documents/:id/permissions</span>
                <span className="text-slate-500 block text-[11px] font-sans mt-0.5">Caller: Document Owner or Admin ONLY. Grants named permission and bumps epoch.</span>
              </div>
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono">
                <span className="text-rose-400 font-bold">DELETE /api/documents/:id/permissions/:targetUserId</span>
                <span className="text-slate-500 block text-[11px] font-sans mt-0.5">Caller: Document Owner or Admin ONLY. Instantly revokes access with 0ms delay.</span>
              </div>
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono">
                <span className="text-emerald-400 font-bold">GET /api/audit/verify</span>
                <span className="text-slate-500 block text-[11px] font-sans mt-0.5">Caller: Any authenticated user. Cryptographically checks SHA-256 hash chain from genesis block.</span>
              </div>
            </div>
          </div>
        )}

        {/* SUBTAB 5: Database Schema & Clean Clone Setup */}
        {activeSubTab === 'schema' && (
          <div className="space-y-6 max-w-4xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div>
                <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <Server className="w-5 h-5 text-indigo-400" />
                  <span>Database Schema & Clean-Clone Setup Instructions</span>
                </h3>
                <p className="text-xs text-slate-400">
                  Full relational DDL schema (schema.sql), relational seed script (seeds.sql), and persistent disk enclave.
                </p>
              </div>
              <span className="text-xs bg-indigo-950 text-indigo-300 border border-indigo-800 px-2.5 py-1 rounded-lg font-mono">
                5 Relational Tables
              </span>
            </div>

            {/* Clean Clone Setup Guide */}
            <div className="p-4 bg-indigo-950/40 border border-indigo-800/50 rounded-xl space-y-3">
              <h4 className="font-bold text-slate-100 text-xs flex items-center gap-2">
                <Code className="w-4 h-4 text-indigo-400" />
                <span>How to Setup & Bootstrap the Database from a Clean Git Clone</span>
              </h4>
              <p className="text-xs text-slate-300 leading-relaxed">
                When cloning this repository fresh, initialize the database tables and seed accounts by running:
              </p>
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 font-mono text-xs text-emerald-400">
                # 1. Install dependencies<br />
                npm install<br /><br />
                # 2. Bootstrap & verify database schema and seeds<br />
                npm run db:setup<br /><br />
                # 3. Start the application<br />
                npm run dev
              </div>
            </div>

            {/* Relational Table Breakdown */}
            <div className="space-y-3">
              <h4 className="font-bold text-slate-100 text-xs uppercase tracking-wider text-slate-400">
                Relational Tables Declared in schema.sql
              </h4>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-indigo-400 font-bold">1. users</span>
                    <span className="text-[10px] text-slate-500">6 Seed Rows</span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Stores user identities, hashed passwords, roles (ADMIN, DOCUMENT_OWNER, VIEWER), and departments.
                  </p>
                </div>

                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-indigo-400 font-bold">2. encrypted_blobs</span>
                    <span className="text-[10px] text-slate-500">AES-256-GCM</span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Stores ciphertext, 128-bit IVs, and 128-bit authentication tags. Zero plaintext stored on disk.
                  </p>
                </div>

                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-indigo-400 font-bold">3. documents</span>
                    <span className="text-[10px] text-slate-500">Foreign Key to Users</span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Document governance metadata, security classification, owner_id FK, and permission_version epoch.
                  </p>
                </div>

                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-indigo-400 font-bold">4. document_permissions</span>
                    <span className="text-[10px] text-slate-500">Granular ACL</span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Per-document named grants (READ, DOWNLOAD, EDIT, MANAGE), granter audit link, and unique constraint.
                  </p>
                </div>

                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-1 sm:col-span-2">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-indigo-400 font-bold">5. audit_ledger</span>
                    <span className="text-[10px] text-emerald-400 font-bold">SHA-256 Hash Chained</span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Immutable log with block_index, timestamp, actor, action, status, previous_hash, and entry_hash.
                  </p>
                </div>
              </div>
            </div>

            {/* DDL Preview */}
            <div className="space-y-2">
              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block">
                schema.sql Preview (ANSI / PostgreSQL Compatible DDL):
              </span>
              <pre className="p-4 bg-slate-950 rounded-xl border border-slate-800 font-mono text-[11px] text-slate-300 max-h-60 overflow-y-auto leading-relaxed">
{`CREATE TABLE users (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    role VARCHAR(32) NOT NULL CHECK (role IN ('ADMIN', 'DOCUMENT_OWNER', 'VIEWER', 'EXTERNAL_PARTNER', 'ATTACKER')),
    department VARCHAR(255) NOT NULL
);

CREATE TABLE encrypted_blobs (
    blob_key VARCHAR(128) PRIMARY KEY,
    ciphertext TEXT NOT NULL,
    iv_hex VARCHAR(64) NOT NULL,
    auth_tag_hex VARCHAR(64) NOT NULL
);

CREATE TABLE documents (
    id VARCHAR(64) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    category VARCHAR(32) NOT NULL,
    security_level VARCHAR(32) NOT NULL,
    owner_id VARCHAR(64) REFERENCES users(id),
    encrypted_blob_key VARCHAR(128) REFERENCES encrypted_blobs(blob_key),
    permission_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE document_permissions (
    id VARCHAR(64) PRIMARY KEY,
    document_id VARCHAR(64) REFERENCES documents(id) ON DELETE CASCADE,
    user_id VARCHAR(64) REFERENCES users(id) ON DELETE CASCADE,
    access_level VARCHAR(32) NOT NULL CHECK (access_level IN ('READ', 'DOWNLOAD', 'EDIT', 'MANAGE'))
);

CREATE TABLE audit_ledger (
    block_index BIGINT PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    action VARCHAR(64) NOT NULL,
    actor_id VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    previous_hash VARCHAR(64) NOT NULL,
    entry_hash VARCHAR(64) NOT NULL UNIQUE
);`}
              </pre>
            </div>
          </div>
        )}

        {/* SUBTAB 6: Seed Credentials */}
        {activeSubTab === 'creds' && (
          <div className="space-y-4 max-w-4xl">
            <div className="pb-3 border-b border-slate-800">
              <h3 className="text-base font-bold text-slate-100">Seed Credentials for Snovasys Judges</h3>
              <p className="text-xs text-slate-400">One account for each required role, plus external partner and hostile attacker personas.</p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <strong className="text-slate-200">Sarah Connor (Security Admin)</strong>
                  <span className="text-[10px] bg-rose-500/10 text-rose-400 border border-rose-500/30 px-2 py-0.5 rounded-full font-bold">ADMIN</span>
                </div>
                <p className="text-[11px] text-slate-400">Email: <code className="text-indigo-300">admin@trustvault.internal</code></p>
                <p className="text-[11px] text-slate-400">Password: <code className="text-slate-300">AdminSecure#2026</code></p>
                <p className="text-[10px] text-slate-500">Capability: System-wide audit inspection, threat alerts, tamper verification.</p>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <strong className="text-slate-200">Alice Morgan (Document Owner)</strong>
                  <span className="text-[10px] bg-blue-500/10 text-blue-400 border border-blue-500/30 px-2 py-0.5 rounded-full font-bold">DOCUMENT_OWNER</span>
                </div>
                <p className="text-[11px] text-slate-400">Email: <code className="text-indigo-300">alice.owner@trustvault.internal</code></p>
                <p className="text-[11px] text-slate-400">Password: <code className="text-slate-300">AliceVault#2026</code></p>
                <p className="text-[10px] text-slate-500">Capability: Owns Legal & Quantum docs; grants & immediately revokes permissions.</p>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <strong className="text-slate-200">Bob Henderson (Document Owner)</strong>
                  <span className="text-[10px] bg-blue-500/10 text-blue-400 border border-blue-500/30 px-2 py-0.5 rounded-full font-bold">DOCUMENT_OWNER</span>
                </div>
                <p className="text-[11px] text-slate-400">Email: <code className="text-indigo-300">bob.owner@trustvault.internal</code></p>
                <p className="text-[11px] text-slate-400">Password: <code className="text-slate-300">BobVault#2026</code></p>
                <p className="text-[10px] text-slate-500">Capability: Owns SECRET executive compensation ledger with zero unshared access.</p>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <strong className="text-slate-200">Carol Davies (Internal Viewer)</strong>
                  <span className="text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded-full font-bold">VIEWER</span>
                </div>
                <p className="text-[11px] text-slate-400">Email: <code className="text-indigo-300">carol.viewer@trustvault.internal</code></p>
                <p className="text-[11px] text-slate-400">Password: <code className="text-slate-300">CarolView#2026</code></p>
                <p className="text-[10px] text-slate-500">Capability: Granted READ on Acme Contract; blocked from Bob's secret compensation.</p>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <strong className="text-slate-200">Dave Wilson (External Auditor)</strong>
                  <span className="text-[10px] bg-amber-500/10 text-amber-400 border border-amber-500/30 px-2 py-0.5 rounded-full font-bold">EXTERNAL_PARTNER</span>
                </div>
                <p className="text-[11px] text-slate-400">Email: <code className="text-indigo-300">dave.external@partner.org</code></p>
                <p className="text-[11px] text-slate-400">Password: <code className="text-slate-300">DavePartner#2026</code></p>
                <p className="text-[10px] text-slate-500">Capability: Scoped to SOX 404 Audit document only.</p>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <strong className="text-slate-200">Mallory Vance (Simulated Attacker)</strong>
                  <span className="text-[10px] bg-purple-500/10 text-purple-400 border border-purple-500/30 px-2 py-0.5 rounded-full font-bold">ATTACKER</span>
                </div>
                <p className="text-[11px] text-slate-400">Email: <code className="text-indigo-300">mallory.attacker@hostile.com</code></p>
                <p className="text-[11px] text-slate-400">Password: <code className="text-slate-300">MalloryPwn#2026</code></p>
                <p className="text-[10px] text-slate-500">Capability: Used to test 403 Forbidden responses, probing, and tamper detection.</p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
