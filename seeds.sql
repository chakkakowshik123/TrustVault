-- =====================================================================
-- TrustVault — Seed Data & Initial Bootstrap
-- Snovasys Fresher Hiring Challenge 2026 — RISE
-- =====================================================================

-- 1. Seed Users
INSERT INTO users (id, name, email, password_hash, role, department, avatar_url) VALUES
('usr_admin', 'Sarah Connor (Security Admin)', 'admin@trustvault.internal', 'AdminSecure#2026', 'ADMIN', 'Information Security & Compliance', 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=120&auto=format&fit=crop&q=80'),
('usr_owner_alice', 'Alice Morgan (Document Owner)', 'alice.owner@trustvault.internal', 'AliceVault#2026', 'DOCUMENT_OWNER', 'Legal & Executive Contracts', 'https://images.unsplash.com/photo-1580489944761-15a19d654956?w=120&auto=format&fit=crop&q=80'),
('usr_owner_bob', 'Bob Henderson (Document Owner)', 'bob.owner@trustvault.internal', 'BobVault#2026', 'DOCUMENT_OWNER', 'Finance & Executive Compensation', 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=120&auto=format&fit=crop&q=80'),
('usr_viewer_carol', 'Carol Davies (Internal Viewer)', 'carol.viewer@trustvault.internal', 'CarolView#2026', 'VIEWER', 'Operations & Procurement', 'https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=120&auto=format&fit=crop&q=80'),
('usr_external_dave', 'Dave Wilson (External Auditor)', 'dave.external@partner.org', 'DavePartner#2026', 'EXTERNAL_PARTNER', 'KPMG External Assurance', 'https://images.unsplash.com/photo-1500648767791-00dcc994a43e?w=120&auto=format&fit=crop&q=80'),
('usr_attacker_mallory', 'Mallory Vance (Simulated Attacker)', 'mallory.attacker@hostile.com', 'MalloryPwn#2026', 'ATTACKER', 'Threat Vector Simulation', 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=120&auto=format&fit=crop&q=80')
ON CONFLICT (id) DO NOTHING;

-- 2. Seed Encrypted Blobs (AES-256-GCM Envelope Encryption)
INSERT INTO encrypted_blobs (blob_key, ciphertext, iv_hex, auth_tag_hex, byte_size) VALUES
('blob_contract_acme_2026', '9f81a7b823e4d9c72e41', 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 'f1e2d3c4b5a697887766554433221100', 421000),
('blob_finance_q4_comp', '3d5e7f9a1b2c4e6a8d0f', '11223344556677889900aabbccddeeff', '00112233445566778899aabbccddeeff', 184500),
('blob_eng_quantum', '8b9c0d1e2f3a4b5c6d7e', 'ffeeddccbbaa99887766554433221100', 'aabbccddeeff00112233445566778899', 852000),
('blob_comp_sox', '4a5b6c7d8e9f0a1b2c3d', '1234567890abcdef1234567890abcdef', 'fedcba0987654321fedcba0987654321', 312000)
ON CONFLICT (blob_key) DO NOTHING;

-- 3. Seed Documents
INSERT INTO documents (id, title, description, category, security_level, tags, filename, mime_type, file_size, owner_id, encrypted_blob_key, permission_version) VALUES
('doc-legal-001', 'Enterprise Master Services Agreement — Acme Corp 2026', 'Bilateral enterprise agreement covering multi-year licensing and liability caps.', 'LEGAL', 'CONFIDENTIAL', '["contract","acme","enterprise","sla"]', 'AcmeCorp_MSA_Executed_2026.pdf', 'application/pdf', 421000, 'usr_owner_alice', 'blob_contract_acme_2026', 1),
('doc-finance-002', 'Q4 Executive Bonus & Compensation Ledger (Classified)', 'Executive committee compensation distribution, equity schedules, and performance bonuses.', 'FINANCE', 'SECRET', '["payroll","bonuses","executive","restricted"]', 'Executive_Compensation_Q4_2026.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 184500, 'usr_owner_bob', 'blob_finance_q4_comp', 1),
('doc-eng-003', 'Quantum Neural Hybrid Architecture Whitepaper', 'Deep architectural blueprint for post-quantum key encapsulation and zero-trust verification engines.', 'ENGINEERING', 'RESTRICTED', '["quantum","cryptography","architecture","rfc"]', 'TrustVault_Architecture_Whitepaper_v3.pdf', 'application/pdf', 852000, 'usr_owner_alice', 'blob_eng_quantum', 1),
('doc-comp-004', 'FY2026 Annual SOX 404 Compliance & Control Audit', 'Independent audit report validating access control governance and cryptographic hash ledgers.', 'COMPLIANCE', 'CONFIDENTIAL', '["sox","audit","kpmg","controls"]', 'SOX_404_Compliance_Review_2026.pdf', 'application/pdf', 312000, 'usr_owner_alice', 'blob_comp_sox', 1)
ON CONFLICT (id) DO NOTHING;

-- 4. Seed Document Permissions (Named Grants)
INSERT INTO document_permissions (id, document_id, user_id, access_level, granted_by, notes) VALUES
('perm-001', 'doc-legal-001', 'usr_viewer_carol', 'READ', 'usr_owner_alice', 'Access granted strictly to review contractual SLA obligations.'),
('perm-002', 'doc-eng-003', 'usr_viewer_carol', 'DOWNLOAD', 'usr_owner_alice', 'Permitted to download PDF for partner security audit.'),
('perm-003', 'doc-comp-004', 'usr_external_dave', 'READ', 'usr_owner_alice', 'External auditor access. Read-only.')
ON CONFLICT (document_id, user_id) DO NOTHING;

-- 5. Seed Cryptographic Genesis Block
INSERT INTO audit_ledger (block_index, timestamp, action, actor_id, actor_name, actor_email, actor_role, status, ip_address, details, previous_hash, entry_hash) VALUES
(0, CURRENT_TIMESTAMP, 'VERIFY_AUDIT_TRAIL', 'usr_admin', 'Sarah Connor (Security Admin)', 'admin@trustvault.internal', 'ADMIN', 'SUCCESS', '127.0.0.1', 'TrustVault Cryptographic Ledger Initialized. Root Genesis Block Sealed.', '0000000000000000000000000000000000000000000000000000000000000000', '23d15e824b9945a9e162bd4030c77a816c476a8c7dc7c274c77aa587636665a5')
ON CONFLICT (block_index) DO NOTHING;
