import type {
  User,
  Document as VaultDoc,
  PermissionGrant,
  AuditBlock,
  AuditVerificationResult,
  SecurityTestResult,
  AccessLevel,
  Category,
  SecurityLevel
} from '../types.js';

let activeToken = localStorage.getItem('trustvault_token') || 'token_usr_admin';
let activeUserId = localStorage.getItem('trustvault_user_id') || 'usr_admin';

export function setAuthSession(token: string, userId: string) {
  activeToken = token;
  activeUserId = userId;
  localStorage.setItem('trustvault_token', token);
  localStorage.setItem('trustvault_user_id', userId);
}

export function clearAuthSession() {
  activeToken = '';
  activeUserId = '';
  localStorage.removeItem('trustvault_token');
  localStorage.removeItem('trustvault_user_id');
}

export function getActiveSession() {
  return { token: activeToken, userId: activeUserId };
}

async function fetchWithAuth(url: string, options: RequestInit = {}) {
  const headers = new Headers(options.headers || {});
  if (activeToken) {
    headers.set('Authorization', `Bearer ${activeToken}`);
  }
  if (activeUserId) {
    headers.set('x-user-id', activeUserId);
  }
  if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(url, { ...options, headers });
  return response;
}

export const api = {
  // Authentication
  async login(email: string, password?: string): Promise<{ token: string; user: User }> {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Login failed' }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    const data = await res.json();
    setAuthSession(data.token, data.user.id);
    return data;
  },

  async getCurrentUser(): Promise<User> {
    const res = await fetchWithAuth('/api/auth/me');
    if (!res.ok) throw new Error('Not authenticated');
    const data = await res.json();
    return data.user;
  },

  async getUsers(): Promise<User[]> {
    const res = await fetchWithAuth('/api/auth/users');
    if (!res.ok) throw new Error('Failed to load users directory');
    const data = await res.json();
    return data.users;
  },

  // Documents
  async getDocuments(params?: { search?: string; category?: string; securityLevel?: string }): Promise<VaultDoc[]> {
    const q = new URLSearchParams();
    if (params?.search) q.set('search', params.search);
    if (params?.category) q.set('category', params.category);
    if (params?.securityLevel) q.set('securityLevel', params.securityLevel);

    const res = await fetchWithAuth(`/api/documents?${q.toString()}`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Failed to fetch documents' }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    const data = await res.json();
    return data.documents;
  },

  async getDocument(id: string): Promise<VaultDoc> {
    const res = await fetchWithAuth(`/api/documents/${id}`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Failed to fetch document' }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    const data = await res.json();
    return data.document;
  },

  async downloadDocument(id: string, filename: string): Promise<void> {
    const res = await fetchWithAuth(`/api/documents/${id}/download`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Download failed' }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  },

  async uploadDocument(payload: {
    title: string;
    description: string;
    category: Category;
    securityLevel: SecurityLevel;
    tags: string[];
    filename: string;
    content: string;
    mimeType?: string;
  }): Promise<VaultDoc> {
    const res = await fetchWithAuth('/api/documents', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Upload failed' }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    const data = await res.json();
    return data.document;
  },

  async deleteDocument(id: string): Promise<void> {
    const res = await fetchWithAuth(`/api/documents/${id}`, {
      method: 'DELETE'
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Delete failed' }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
  },

  // Permissions & Instant Revocation
  async getPermissions(id: string): Promise<{ permissions: PermissionGrant[]; permissionVersion: number }> {
    const res = await fetchWithAuth(`/api/documents/${id}/permissions`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Failed to load permissions' }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
  },

  async grantPermission(
    documentId: string,
    targetUserId: string,
    accessLevel: AccessLevel,
    notes?: string,
    expiresInMinutes?: number | null,
    expiresAt?: string | null
  ): Promise<{ permissions: PermissionGrant[]; permissionVersion: number }> {
    const res = await fetchWithAuth(`/api/documents/${documentId}/permissions`, {
      method: 'POST',
      body: JSON.stringify({ targetUserId, accessLevel, notes, expiresInMinutes, expiresAt })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Grant failed' }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
  },

  async revokePermission(
    documentId: string,
    targetUserId: string
  ): Promise<{ permissions: PermissionGrant[]; permissionVersion: number }> {
    const res = await fetchWithAuth(`/api/documents/${documentId}/permissions/${targetUserId}`, {
      method: 'DELETE'
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Revocation failed' }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
  },

  // Audit Ledger
  async getAuditLogs(params?: { action?: string; status?: string; documentId?: string }): Promise<{
    records: AuditBlock[];
    totalCount: number;
    chainLength: number;
  }> {
    const q = new URLSearchParams();
    if (params?.action) q.set('action', params.action);
    if (params?.status) q.set('status', params.status);
    if (params?.documentId) q.set('documentId', params.documentId);

    const res = await fetchWithAuth(`/api/audit?${q.toString()}`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Failed to fetch audit ledger' }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
  },

  async verifyAuditTrail(): Promise<AuditVerificationResult> {
    const res = await fetchWithAuth('/api/audit/verify');
    if (!res.ok) throw new Error('Verification failed');
    return res.json();
  },

  async simulateTamper(): Promise<{ message: string; tamperedBlockIndex: number }> {
    const res = await fetchWithAuth('/api/audit/simulate-tamper', { method: 'POST' });
    if (!res.ok) throw new Error('Simulate tamper failed');
    return res.json();
  },

  async restoreAuditChain(): Promise<{ message: string }> {
    const res = await fetchWithAuth('/api/audit/restore', { method: 'POST' });
    if (!res.ok) throw new Error('Restore failed');
    return res.json();
  },

  // AI Permission Advisor
  async suggestPermissions(documentId: string, targetUserId: string): Promise<{
    recommendedLevel: AccessLevel;
    riskScore: 'LOW' | 'MEDIUM' | 'HIGH';
    rationale: string;
    warnings: string[];
    policyNotice: string;
  }> {
    const res = await fetchWithAuth('/api/ai/suggest-permissions', {
      method: 'POST',
      body: JSON.stringify({ documentId, targetUserId })
    });
    if (!res.ok) throw new Error('AI suggestion failed');
    return res.json();
  },

  // Security Attack Test Suite
  async runSecurityTests(): Promise<{
    summary: { total: number; passed: number; failed: number; executedAt: string };
    results: SecurityTestResult[];
  }> {
    const res = await fetchWithAuth('/api/tests/run', { method: 'POST' });
    if (!res.ok) throw new Error('Security tests execution failed');
    return res.json();
  },

  // Interactive Adversarial Attack Simulator
  async runCustomAttack(params: {
    attackVector: string;
    simulatedUserId: string;
    targetDocId: string;
    action?: string;
    customPayload?: string;
  }): Promise<{
    attackId: string;
    timestamp: string;
    intercepted: boolean;
    httpStatus: number;
    defenseLayer: string;
    attackVector: string;
    actor: { id: string; name: string; email: string; role: string };
    targetDocument: { id: string; title: string; securityLevel: string; ownerName: string };
    defenseSummary: string;
    auditBlockIndex: number;
    auditEntryHash: string;
    executionTrace: string[];
  }> {
    const res = await fetchWithAuth('/api/tests/custom-attack', {
      method: 'POST',
      body: JSON.stringify(params)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Custom attack simulation failed' }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
  }
};
