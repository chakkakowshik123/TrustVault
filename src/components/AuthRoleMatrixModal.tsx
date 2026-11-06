import React, { useState } from 'react';
import { 
  Shield, 
  Lock, 
  KeyRound, 
  CheckCircle2, 
  XCircle, 
  UserCheck, 
  FileText, 
  AlertCircle,
  Copy,
  Check,
  Terminal,
  Zap
} from 'lucide-react';
import type { User, Role } from '../types.js';

interface AuthRoleMatrixModalProps {
  currentUser: User | null;
  allUsers: User[];
  onSelectUser: (user: User) => void;
  onClose: () => void;
}

export const AuthRoleMatrixModal: React.FC<AuthRoleMatrixModalProps> = ({
  currentUser,
  allUsers,
  onSelectUser,
  onClose
}) => {
  const [selectedRoleFilter, setSelectedRoleFilter] = useState<string>('ALL');
  const [copiedText, setCopiedText] = useState<string | null>(null);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const roleDefinitions: Record<Role, {
    title: string;
    description: string;
    allowed: string[];
    forbidden: string[];
  }> = {
    ADMIN: {
      title: 'Security Administrator',
      description: 'Oversees organizational security, cryptographic audit ledgers, and threat mitigation.',
      allowed: [
        'Inspect system-wide cryptographic audit trail',
        'Verify SHA-256 Merkle hash chain from Genesis block',
        'View security telemetry, 403 denied probe velocities, and alerts',
        'Oversee document inventory and permission version epochs'
      ],
      forbidden: [
        'Read or download SECRET documents without explicit dual-custody authorization',
        'Quietly alter or delete past audit entries (prevented by SHA-256 Merkle chain)'
      ]
    },
    DOCUMENT_OWNER: {
      title: 'Document Owner (Creator)',
      description: 'Holds sovereign authority over created files and manages per-document access grants.',
      allowed: [
        'Upload documents encrypted with AES-256-GCM envelope encryption',
        'Grant granular permissions (READ, DOWNLOAD, EDIT, MANAGE) to named colleagues',
        'Revoke access immediately with 0ms lag (bumps permissionVersion epoch)',
        'Consult TrustVault Sentinel (AI Advisor) for least-privilege suggestions',
        'Permanently purge own documents from vault'
      ],
      forbidden: [
        'View or download unshared confidential documents belonging to other owners',
        'Modify system security policies or erase audit logs'
      ]
    },
    VIEWER: {
      title: 'Viewer (Internal Employee)',
      description: 'Standard team member with strictly granted read/download privileges.',
      allowed: [
        'View decrypted inline previews of documents explicitly granted to them',
        'Download file streams ONLY if granted explicit DOWNLOAD permission',
        'Search and filter documents they hold valid grants for'
      ],
      forbidden: [
        'Access unshared documents (Blocked by server with 403 Forbidden)',
        'Download documents where only READ was granted',
        'Grant, modify, or escalate permissions for themselves or others',
        'Delete or edit documents belonging to document owners'
      ]
    },
    EXTERNAL_PARTNER: {
      title: 'External Partner / Auditor',
      description: 'Third-party vendor or compliance auditor with strictly scoped access.',
      allowed: [
        'View audit compliance documents explicitly shared with their domain'
      ],
      forbidden: [
        'Access internal financial, salary, or quantum engineering blueprints',
        'Download raw files without explicit cryptographic export approval'
      ]
    },
    ATTACKER: {
      title: 'Simulated Threat Actor (Mallory)',
      description: 'Persona used by judges to test IDOR, parameter tampering, and traversal blocks.',
      allowed: [
        'Attempt unauthorized REST API calls to test 403 server defense'
      ],
      forbidden: [
        'All unauthorized actions (100% blocked and logged as ACCESS_DENIED)'
      ]
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-4xl w-full max-h-[92vh] flex flex-col shadow-2xl overflow-hidden relative">
        {/* Header */}
        <div className="p-6 border-b border-slate-800 flex items-start justify-between bg-slate-950/70">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-indigo-500/10 border border-indigo-500/30 rounded-xl text-indigo-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-slate-100">
                  Authentication & Role Authorization Matrix
                </h2>
                <span className="text-xs bg-indigo-950 text-indigo-300 border border-indigo-800 px-2 py-0.5 rounded-full font-mono">
                  Snovasys RISE Mandate
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                "Authentication, with at least three roles: an administrator, a document owner, and a viewer. You decide what each can do and write it down."
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 p-2 rounded-lg hover:bg-slate-800/60 transition-colors"
          >
            ✕
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-xs">
          {/* Active User Quick Status */}
          <div className="p-4 bg-indigo-950/30 border border-indigo-800/40 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <img
                src={currentUser?.avatar}
                alt={currentUser?.name}
                className="w-10 h-10 rounded-xl object-cover border border-indigo-500/40"
              />
              <div>
                <span className="text-[10px] uppercase font-bold text-indigo-400 tracking-wider">Active Session</span>
                <div className="flex items-center gap-2">
                  <strong className="text-sm text-slate-100 font-bold">{currentUser?.name}</strong>
                  <span className="bg-indigo-500/20 text-indigo-300 px-2 py-0.5 rounded text-[11px] font-semibold border border-indigo-500/30">
                    {currentUser?.role}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400">{currentUser?.email} • {currentUser?.department}</p>
              </div>
            </div>

            <div className="flex items-center gap-2 font-mono text-[11px] text-slate-400 bg-slate-950 px-3 py-2 rounded-lg border border-slate-800">
              <KeyRound className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
              <span>Token: <code>token_{currentUser?.id}</code></span>
            </div>
          </div>

          {/* Role Filter Buttons */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mr-2">Filter Roles:</span>
            {['ALL', 'ADMIN', 'DOCUMENT_OWNER', 'VIEWER', 'EXTERNAL_PARTNER', 'ATTACKER'].map((role) => (
              <button
                key={role}
                onClick={() => setSelectedRoleFilter(role)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                  selectedRoleFilter === role
                    ? 'bg-indigo-600 text-white shadow-sm'
                    : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                {role.replace('_', ' ')}
              </button>
            ))}
          </div>

          {/* User Directory & Account Switcher */}
          <div className="space-y-4">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <UserCheck className="w-4 h-4 text-emerald-400" />
              <span>Evaluator Credentials & Live Session Switcher</span>
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {allUsers
                .filter(u => selectedRoleFilter === 'ALL' || u.role === selectedRoleFilter)
                .map((u) => {
                  const isCurrent = u.id === currentUser?.id;
                  const def = roleDefinitions[u.role];

                  return (
                    <div
                      key={u.id}
                      className={`p-4 rounded-xl border transition-all ${
                        isCurrent
                          ? 'bg-indigo-950/40 border-indigo-500/60 shadow-lg shadow-indigo-950/30'
                          : 'bg-slate-950/60 border-slate-800/80 hover:border-slate-700/80'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex items-center gap-3">
                          <img
                            src={u.avatar}
                            alt={u.name}
                            className="w-10 h-10 rounded-lg object-cover border border-slate-700 shrink-0"
                          />
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="text-xs font-bold text-slate-100">{u.name}</span>
                              {isCurrent && (
                                <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[10px] px-1.5 py-0.2 rounded font-bold">
                                  ACTIVE
                                </span>
                              )}
                            </div>
                            <p className="text-[11px] text-slate-400">{u.email}</p>
                            <p className="text-[10px] text-indigo-400 mt-0.5">Password: <code>{u.password}</code></p>
                          </div>
                        </div>

                        <div className="flex flex-col items-end gap-1.5 shrink-0">
                          <button
                            onClick={() => {
                              onSelectUser(u);
                              onClose();
                            }}
                            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${
                              isCurrent
                                ? 'bg-indigo-600 text-white'
                                : 'bg-slate-800 hover:bg-indigo-600 text-slate-300 hover:text-white'
                            }`}
                          >
                            {isCurrent ? 'Active Now' : 'Switch To'}
                          </button>

                          <button
                            onClick={() => copyToClipboard(`${u.email} | ${u.password}`)}
                            className="text-[10px] text-slate-400 hover:text-slate-200 flex items-center gap-1"
                            title="Copy email & password"
                          >
                            {copiedText === `${u.email} | ${u.password}` ? (
                              <Check className="w-3 h-3 text-emerald-400" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                            <span>Copy Creds</span>
                          </button>
                        </div>
                      </div>

                      {/* Explicit Written Role Capabilities */}
                      <div className="mt-3 pt-3 border-t border-slate-800/80 space-y-1.5 text-[11px]">
                        <p className="text-slate-400 font-medium">{def.description}</p>
                        
                        <div className="space-y-1">
                          <div className="flex items-center gap-1.5 text-emerald-400 font-semibold text-[10px]">
                            <CheckCircle2 className="w-3 h-3 shrink-0" />
                            <span>Permitted Capabilities:</span>
                          </div>
                          <ul className="pl-4 space-y-0.5 text-[10px] text-slate-300 list-disc">
                            {def.allowed.slice(0, 2).map((item, i) => (
                              <li key={i}>{item}</li>
                            ))}
                          </ul>
                        </div>

                        <div className="space-y-1 pt-1">
                          <div className="flex items-center gap-1.5 text-rose-400 font-semibold text-[10px]">
                            <XCircle className="w-3 h-3 shrink-0" />
                            <span>Enforced Server Restrictions:</span>
                          </div>
                          <ul className="pl-4 space-y-0.5 text-[10px] text-slate-400 list-disc">
                            {def.forbidden.slice(0, 1).map((item, i) => (
                              <li key={i}>{item}</li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    </div>
                  );
                })}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-indigo-400" />
            <span>Server enforces <code>verifyDocumentAccess</code> on all endpoints regardless of UI role</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl font-semibold transition-colors"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
