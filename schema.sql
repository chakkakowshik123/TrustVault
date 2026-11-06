-- =====================================================================
-- TrustVault — Secure Document Sharing & Cryptographic Audit Trail
-- Database Schema Definition (SQL DDL)
-- Snovasys Fresher Hiring Challenge 2026 — RISE
-- Target RDBMS: PostgreSQL 14+ / MySQL 8+ / SQLite 3.35+
-- =====================================================================

-- 1. Users & Identities Table
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL CHECK (role IN ('ADMIN', 'DOCUMENT_OWNER', 'VIEWER', 'EXTERNAL_PARTNER', 'ATTACKER')),
    department VARCHAR(255) NOT NULL,
    avatar_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- 2. Encrypted Document Blobs Enclave (Zero Plaintext at Rest)
CREATE TABLE IF NOT EXISTS encrypted_blobs (
    blob_key VARCHAR(128) PRIMARY KEY,
    ciphertext TEXT NOT NULL,
    iv_hex VARCHAR(64) NOT NULL,
    auth_tag_hex VARCHAR(64) NOT NULL,
    encryption_algorithm VARCHAR(32) DEFAULT 'AES-256-GCM',
    byte_size INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Documents Metadata & Governance Table
CREATE TABLE IF NOT EXISTS documents (
    id VARCHAR(64) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(32) NOT NULL CHECK (category IN ('FINANCE', 'LEGAL', 'ENGINEERING', 'HR', 'COMPLIANCE', 'EXECUTIVE')),
    security_level VARCHAR(32) NOT NULL CHECK (security_level IN ('INTERNAL', 'RESTRICTED', 'CONFIDENTIAL', 'SECRET')),
    tags JSON NOT NULL DEFAULT '[]',
    filename VARCHAR(255) NOT NULL,
    mime_type VARCHAR(128) NOT NULL DEFAULT 'application/octet-stream',
    file_size INTEGER NOT NULL,
    owner_id VARCHAR(64) NOT NULL,
    encrypted_blob_key VARCHAR(128) NOT NULL,
    permission_version INTEGER NOT NULL DEFAULT 1,
    preview_content TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_documents_owner FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE RESTRICT,
    CONSTRAINT fk_documents_blob FOREIGN KEY (encrypted_blob_key) REFERENCES encrypted_blobs(blob_key) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_documents_category ON documents(category);
CREATE INDEX IF NOT EXISTS idx_documents_security ON documents(security_level);

-- 4. Per-Document Access Control Lists (ACL Grants)
CREATE TABLE IF NOT EXISTS document_permissions (
    id VARCHAR(64) PRIMARY KEY,
    document_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    access_level VARCHAR(32) NOT NULL CHECK (access_level IN ('READ', 'DOWNLOAD', 'EDIT', 'MANAGE')),
    granted_by VARCHAR(64) NOT NULL,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,
    CONSTRAINT fk_perm_document FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    CONSTRAINT fk_perm_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_perm_granter FOREIGN KEY (granted_by) REFERENCES users(id) ON DELETE RESTRICT,
    CONSTRAINT uq_doc_user_grant UNIQUE (document_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_permissions_lookup ON document_permissions(document_id, user_id);

-- 5. Cryptographic Tamper-Evident Audit Trail (Merkle-Linked Hash Chain)
CREATE TABLE IF NOT EXISTS audit_ledger (
    block_index BIGINT PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    action VARCHAR(64) NOT NULL,
    actor_id VARCHAR(64) NOT NULL,
    actor_name VARCHAR(255) NOT NULL,
    actor_email VARCHAR(255) NOT NULL,
    actor_role VARCHAR(32) NOT NULL,
    document_id VARCHAR(64),
    document_title VARCHAR(255),
    status VARCHAR(32) NOT NULL CHECK (status IN ('SUCCESS', 'ACCESS_DENIED', 'TAMPER_DETECTED')),
    ip_address VARCHAR(45) NOT NULL,
    details TEXT NOT NULL,
    previous_hash VARCHAR(64) NOT NULL,
    entry_hash VARCHAR(64) NOT NULL,
    tampered BOOLEAN DEFAULT FALSE,
    CONSTRAINT uq_audit_entry_hash UNIQUE (entry_hash)
);

CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_ledger(action);
CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_ledger(status);
CREATE INDEX IF NOT EXISTS idx_audit_document ON audit_ledger(document_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_ledger(actor_id);
