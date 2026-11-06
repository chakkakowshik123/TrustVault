import React, { useState, useEffect } from 'react';
import { 
  Activity, 
  ShieldAlert, 
  ShieldCheck, 
  Lock, 
  Users, 
  FileText, 
  AlertTriangle, 
  Clock, 
  Zap, 
  Key, 
  Fingerprint, 
  TrendingUp,
  RefreshCw,
  FolderLock
} from 'lucide-react';
import type { Document as VaultDoc, AuditBlock, User } from '../types.js';
import { api } from '../services/api.js';

interface AdminSecurityDashboardProps {
  documents: VaultDoc[];
  currentUser: User;
  allUsers: User[];
  onNavigateToAudit: () => void;
  onNavigateToAttacks: () => void;
}

export const AdminSecurityDashboard: React.FC<AdminSecurityDashboardProps> = ({
  documents,
  currentUser,
  allUsers,
  onNavigateToAudit,
  onNavigateToAttacks
}) => {
  const [auditLogs, setAuditLogs] = useState<AuditBlock[]>([]);
  const [loading, setLoading] = useState(false);

  const loadData = async () => {
    setLoading(true);
    try {
      const res = await api.getAuditLogs();
      setAuditLogs(res.records);
    } catch (err: any) {
      console.error('Failed to load admin audit data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const deniedAttempts = auditLogs.filter(l => l.status === 'ACCESS_DENIED');
  const downloads = auditLogs.filter(l => l.action === 'DOWNLOAD');
  const permissionChanges = auditLogs.filter(l => l.action === 'GRANT_PERMISSION' || l.action === 'REVOKE_PERMISSION');

  const totalBytes = documents.reduce((acc, d) => acc + d.fileSize, 0);

  // Group by sensitivity
  const secretDocs = documents.filter(d => d.securityLevel === 'SECRET');
  const confidentialDocs = documents.filter(d => d.securityLevel === 'CONFIDENTIAL');
  const restrictedDocs = documents.filter(d => d.securityLevel === 'RESTRICTED');
  const internalDocs = documents.filter(d => d.securityLevel === 'INTERNAL');

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="p-2 bg-indigo-500/10 border border-indigo-500/30 rounded-xl text-indigo-400">
              <Activity className="w-5 h-5" />
            </span>
            <h2 className="text-lg font-bold text-slate-100">Security Governance & Threat Telemetry</h2>
          </div>
          <p className="text-xs text-slate-400">
            Real-time monitoring of document access control lists, refused unauthorized probes, and hash chain health.
          </p>
        </div>

        <button
          onClick={loadData}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-950 border border-slate-800 hover:bg-slate-800 text-slate-300 rounded-xl text-xs transition-colors self-start sm:self-auto"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Telemetry</span>
        </button>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900/70 border border-slate-800/80 rounded-2xl p-4 flex items-center justify-between">
          <div>
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Total Enclave Files</span>
            <p className="text-2xl font-bold text-slate-100 mt-1">{documents.length}</p>
            <span className="text-[11px] text-slate-500 font-mono">{(totalBytes / 1024).toFixed(0)} KB Encrypted</span>
          </div>
          <div className="p-3 bg-indigo-500/10 border border-indigo-500/20 rounded-xl text-indigo-400">
            <FileText className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-900/70 border border-slate-800/80 rounded-2xl p-4 flex items-center justify-between">
          <div>
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Refused Probes (403s)</span>
            <p className="text-2xl font-bold text-rose-400 mt-1">{deniedAttempts.length}</p>
            <span className="text-[11px] text-rose-400/80">Logged to Hash Chain</span>
          </div>
          <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-xl text-rose-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-900/70 border border-slate-800/80 rounded-2xl p-4 flex items-center justify-between">
          <div>
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Authorized Downloads</span>
            <p className="text-2xl font-bold text-emerald-400 mt-1">{downloads.length}</p>
            <span className="text-[11px] text-emerald-400/80">Zero Stale Token Leaks</span>
          </div>
          <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-xl text-emerald-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-900/70 border border-slate-800/80 rounded-2xl p-4 flex items-center justify-between">
          <div>
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">ACL Mutations</span>
            <p className="text-2xl font-bold text-cyan-400 mt-1">{permissionChanges.length}</p>
            <span className="text-[11px] text-cyan-400/80">Epoch Bump Events</span>
          </div>
          <div className="p-3 bg-cyan-500/10 border border-cyan-500/20 rounded-xl text-cyan-400">
            <Key className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Security Threat Alerts & Velocity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Classification Distribution & Threat Status */}
        <div className="space-y-6">
          <div className="bg-slate-900/70 border border-slate-800/80 rounded-2xl p-5 space-y-4">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <FolderLock className="w-4 h-4 text-indigo-400" />
              <span>Sensitivity Distribution</span>
            </h3>

            <div className="space-y-2.5 text-xs">
              <div className="flex items-center justify-between p-2 rounded-lg bg-rose-950/20 border border-rose-900/30">
                <span className="text-rose-300 font-semibold">SECRET</span>
                <span className="font-mono font-bold text-rose-400">{secretDocs.length}</span>
              </div>
              <div className="flex items-center justify-between p-2 rounded-lg bg-amber-950/20 border border-amber-900/30">
                <span className="text-amber-300 font-semibold">CONFIDENTIAL</span>
                <span className="font-mono font-bold text-amber-400">{confidentialDocs.length}</span>
              </div>
              <div className="flex items-center justify-between p-2 rounded-lg bg-indigo-950/20 border border-indigo-900/30">
                <span className="text-indigo-300 font-semibold">RESTRICTED</span>
                <span className="font-mono font-bold text-indigo-400">{restrictedDocs.length}</span>
              </div>
              <div className="flex items-center justify-between p-2 rounded-lg bg-emerald-950/20 border border-emerald-900/30">
                <span className="text-emerald-300 font-semibold">INTERNAL</span>
                <span className="font-mono font-bold text-emerald-400">{internalDocs.length}</span>
              </div>
            </div>
          </div>

          {/* Quick Threat Test Shortcut */}
          <div className="bg-gradient-to-br from-indigo-950/50 to-slate-900 border border-indigo-900/50 rounded-2xl p-5 space-y-3">
            <div className="flex items-center gap-2 text-indigo-300 text-xs font-bold">
              <Zap className="w-4 h-4 text-indigo-400" />
              <span>Snovasys Judge Attack Sandbox</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Launch the automated attack suite to test all 10 threat scenarios from THREATS.md against the live server.
            </p>
            <button
              onClick={onNavigateToAttacks}
              className="w-full py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-semibold shadow-md transition-colors"
            >
              Open Attack Arena
            </button>
          </div>
        </div>

        {/* Right Column: Security Incidents & Refused Access Events */}
        <div className="lg:col-span-2 bg-slate-900/70 border border-slate-800/80 rounded-2xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400" />
              <span>Recent Security Events & Refused Probes</span>
            </h3>

            <button
              onClick={onNavigateToAudit}
              className="text-xs text-indigo-400 hover:text-indigo-300 hover:underline"
            >
              View Full Audit Ledger →
            </button>
          </div>

          <div className="space-y-2 max-h-96 overflow-y-auto">
            {auditLogs.slice(0, 8).map((log) => {
              const isDenied = log.status === 'ACCESS_DENIED';

              return (
                <div
                  key={`${log.index}-${log.entryHash}`}
                  className={`p-3 rounded-xl border text-xs flex items-start gap-3 transition-colors ${
                    isDenied
                      ? 'bg-rose-950/30 border-rose-900/40 text-rose-200'
                      : 'bg-slate-950/40 border-slate-800/80 text-slate-300'
                  }`}
                >
                  <div
                    className={`p-1.5 rounded-lg shrink-0 mt-0.5 ${
                      isDenied ? 'bg-rose-500/20 text-rose-400' : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {isDenied ? <ShieldAlert className="w-3.5 h-3.5" /> : <Clock className="w-3.5 h-3.5" />}
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-semibold text-slate-200 truncate">
                        {log.action} — {log.actor.name}
                      </span>
                      <span className="font-mono text-[10px] text-slate-500 shrink-0">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </span>
                    </div>

                    <p className="text-[11px] text-slate-400 mt-0.5 line-clamp-1">{log.details}</p>

                    <div className="mt-1 flex items-center gap-3 text-[10px] font-mono text-slate-500">
                      <span>IP: {log.ipAddress}</span>
                      <span>Hash: {log.entryHash.slice(0, 14)}...</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
