export type Role = 'ADMIN' | 'DOCUMENT_OWNER' | 'VIEWER' | 'EXTERNAL_PARTNER' | 'ATTACKER';

export type AccessLevel = 'READ' | 'DOWNLOAD' | 'EDIT' | 'MANAGE';

export type SecurityLevel = 'INTERNAL' | 'RESTRICTED' | 'CONFIDENTIAL' | 'SECRET';

export type Category = 'FINANCE' | 'LEGAL' | 'ENGINEERING' | 'HR' | 'COMPLIANCE' | 'EXECUTIVE';

export interface User {
  id: string;
  name: string;
  email: string;
  role: Role;
  department: string;
  avatar?: string;
  password?: string;
}

export interface PermissionGrant {
  userId: string;
  userName: string;
  userEmail: string;
  accessLevel: AccessLevel;
  grantedAt: string;
  grantedBy: string;
  grantedByName?: string;
  notes?: string;
  expiresAt?: string | null;
}

export interface Document {
  id: string;
  title: string;
  description: string;
  category: Category;
  securityLevel: SecurityLevel;
  tags: string[];
  filename: string;
  mimeType: string;
  fileSize: number;
  ownerId: string;
  ownerName: string;
  ownerEmail: string;
  createdAt: string;
  updatedAt: string;
  permissionVersion: number;
  encryptedBlobKey: string;
  previewContent?: string;
  userAccessLevel?: string;
  permissions: PermissionGrant[];
}

export type AuditAction = 
  | 'UPLOAD'
  | 'READ'
  | 'DOWNLOAD'
  | 'EDIT'
  | 'DELETE'
  | 'GRANT_PERMISSION'
  | 'REVOKE_PERMISSION'
  | 'LOGIN'
  | 'ACCESS_DENIED'
  | 'TAMPER_ATTEMPT'
  | 'VERIFY_AUDIT_TRAIL'
  | 'AI_PERMISSION_SUGGESTION';

export type AuditStatus = 'SUCCESS' | 'ACCESS_DENIED' | 'TAMPER_DETECTED';

export interface AuditBlock {
  index: number;
  timestamp: string;
  action: AuditAction;
  actor: {
    id: string;
    name: string;
    email: string;
    role: Role;
  };
  documentId: string | null;
  documentTitle: string | null;
  status: AuditStatus;
  ipAddress: string;
  details: string;
  previousHash: string;
  entryHash: string;
  tampered?: boolean;
}

export interface SecurityTestResult {
  id: string;
  name: string;
  threatId: string;
  category: string;
  description: string;
  passed: boolean;
  httpStatus: number;
  expectedStatus: number;
  executionMs: number;
  evidence: string;
  logs: string[];
}

export interface AuditVerificationResult {
  verified: boolean;
  totalBlocks: number;
  genesisHash: string;
  latestHash: string;
  status: string;
  tamperedBlockIndex: number | null;
  tamperedDetails?: string;
}
