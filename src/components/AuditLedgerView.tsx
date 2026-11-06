import React, { useState, useEffect } from 'react';
import { 
  History, 
  ShieldCheck, 
  ShieldAlert, 
  CheckCircle2, 
  AlertTriangle, 
  Fingerprint, 
  RefreshCw, 
  Terminal, 
  Hash, 
  ArrowDown, 
  Search,
  Filter,
  Sparkles,
  Zap,
  Lock,
  Unlock,
  RotateCcw
} from 'lucide-react';
import type { AuditBlock, AuditVerificationResult, User } from '../types.js';
import { api } from '../services/api.js';

interface AuditLedgerViewProps {
  currentUser: User;
}

export const AuditLedgerView: React.FC<AuditLedgerViewProps> = ({ currentUser }) => {
  const [logs, setLogs] = useState<AuditBlock[]>([]);
  const [chainLength, setChainLength] = useState(0);
  const [loading, setLoading] = useState(false);
  const [filterAction, setFilterAction] = useState<string>('ALL');
  const [filterStatus, setFilterStatus] = useState<string>('ALL');
  const [search, setSearch] = useState('');

  // Verification State
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<AuditVerificationResult | null>(null);
  const [tamperSimulationLoading, setTamperSimulationLoading] = useState(false);
  const [tamperNotice, setTamperNotice] = useState<string | null>(null);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const params: any = {};
      if (filterAction !== 'ALL') params.action = filterAction;
      if (filterStatus !== 'ALL') params.status = filterStatus;
      const res = await api.getAuditLogs(params);
      setLogs(res.records);
      setChainLength(res.chainLength);
    } catch (err: any) {
      console.error('Failed to load audit logs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [filterAction, filterStatus]);

  const handleVerifyChain = async () => {
    setVerifying(true);
    try {
      const res = await api.verifyAuditTrail();
      setVerificationResult(res);
      fetchLogs();
    } catch (err: any) {
      console.error('Verification failed:', err);
    } finally {
      setVerifying(false);
    }
  };

  const handleSimulateTamper = async () => {
    setTamperSimulationLoading(true);
    setTamperNotice(null);
    try {
      const res = await api.simulateTamper();
      setTamperNotice(res.message);
      await fetchLogs();
      // Auto-trigger verification to demonstrate detection
      const verifyRes = await api.verifyAuditTrail();
      setVerificationResult(verifyRes);
    } catch (err: any) {
      setTamperNotice(`Tamper simulation error: ${err.message}`);
    } finally {
      setTamperSimulationLoading(false);
    }
  };

  const handleRestoreChain = async () => {
    setTamperSimulationLoading(true);
    try {
      await api.restoreAuditChain();
      setTamperNotice(null);
      setVerificationResult(null);
      await fetchLogs();
      const verifyRes = await api.verifyAuditTrail();
      setVerificationResult(verifyRes);
    } catch (err: any) {
      console.error('Failed to restore chain:', err);
    } finally {
      setTamperSimulationLoading(false);
    }
  };

  const filteredLogs = logs.filter((log) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      log.action.toLowerCase().includes(q) ||
      log.actor.name.toLowerCase().includes(q) ||
      log.actor.email.toLowerCase().includes(q) ||
      log.details.toLowerCase().includes(q) ||
      (log.documentTitle && log.documentTitle.toLowerCase().includes(q)) ||
      log.entryHash.toLowerCase().includes(q)
    );
  });

  const getActionBadge = (action: string) => {
    switch (action) {
      case 'ACCESS_DENIED':
        return <span className="bg-rose-500/10 text-rose-400 border border-rose-500/30 text-[10px] font-bold px-2 py-0.5 rounded-full">ACCESS_DENIED</span>;
      case 'TAMPER_ATTEMPT':
        return <span className="bg-purple-500/10 text-purple-400 border border-purple-500/30 text-[10px] font-bold px-2 py-0.5 rounded-full">TAMPER_ATTEMPT</span>;
      case 'GRANT_PERMISSION':
        return <span className="bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 text-[10px] font-bold px-2 py-0.5 rounded-full">GRANT_PERMISSION</span>;
      case 'REVOKE_PERMISSION':
        return <span className="bg-amber-500/10 text-amber-400 border border-amber-500/30 text-[10px] font-bold px-2 py-0.5 rounded-full">REVOKE_PERMISSION</span>;
      case 'DOWNLOAD':
        return <span className="bg-blue-500/10 text-blue-400 border border-blue-500/30 text-[10px] font-bold px-2 py-0.5 rounded-full">DOWNLOAD</span>;
      case 'UPLOAD':
        return <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[10px] font-bold px-2 py-0.5 rounded-full">UPLOAD</span>;
      case 'AI_PERMISSION_SUGGESTION':
        return <span className="bg-teal-500/10 text-teal-300 border border-teal-500/30 text-[10px] font-bold px-2 py-0.5 rounded-full">AI_ADVISORY</span>;
      default:
        return <span className="bg-slate-800 text-slate-300 text-[10px] font-bold px-2 py-0.5 rounded-full">{action}</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner: Cryptographic Hash Chaining Defense Guarantee */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2 max-w-2xl">
            <div className="flex items-center gap-2">
              <span className="p-2 bg-indigo-500/10 border border-indigo-500/30 rounded-xl text-indigo-400">
                <Hash className="w-5 h-5" />
              </span>
              <div>
                <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                  <span>Cryptographic Merkle Hash Chain (SHA-256)</span>
                  <span className="text-xs bg-indigo-950 text-indigo-300 border border-indigo-800 px-2 py-0.5 rounded-full font-mono font-normal">
                    {chainLength} Blocks Sealed
                  </span>
                </h2>
                <p className="text-xs text-slate-400">
                  Every entry is immutably linked to the previous block: <code className="text-indigo-300">H_n = SHA256(H_prev + payload)</code>.
                  Modifying even one byte in past history shatters the cryptographic chain and triggers instant forensic detection.
                </p>
              </div>
            </div>
          </div>

          {/* Interactive Verification & Tamper Simulation Tools */}
          <div className="flex flex-wrap items-center gap-2.5">
            <button
              onClick={handleVerifyChain}
              disabled={verifying}
              className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-indigo-600/30 transition-all hover:scale-102"
              title="Traverse all blocks and re-evaluate SHA-256 mathematical proofs"
            >
              <ShieldCheck className="w-4 h-4 text-emerald-300" />
              <span>{verifying ? 'Traversing Chain...' : 'Verify Cryptographic Integrity'}</span>
            </button>

            <button
              onClick={handleSimulateTamper}
              disabled={tamperSimulationLoading}
              className="flex items-center gap-2 px-3.5 py-2 bg-rose-950/40 hover:bg-rose-900/40 border border-rose-800/60 text-rose-300 rounded-xl text-xs font-semibold transition-all hover:scale-102"
              title="Adversarially inject a modified string into block #1 to prove verifier detects it"
            >
              <Unlock className="w-3.5 h-3.5 text-rose-400" />
              <span>Simulate Tampering</span>
            </button>

            <button
              onClick={handleRestoreChain}
              disabled={tamperSimulationLoading}
              className="flex items-center gap-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-medium transition-all"
              title="Restore pristine genesis ledger"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Reset</span>
            </button>
          </div>
        </div>

        {/* Verification Result Notification Card */}
        {verificationResult && (
          <div
            className={`mt-4 p-4 rounded-xl border text-xs flex items-start gap-3 transition-all ${
              verificationResult.verified
                ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-200'
                : 'bg-rose-950/60 border-rose-800/80 text-rose-200 animate-pulse'
            }`}
          >
            {verificationResult.verified ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            )}
            <div className="flex-1">
              <div className="flex items-center justify-between">
                <strong className="text-sm font-bold">
                  {verificationResult.verified
                    ? '100% Cryptographic Ledger Integrity Verified'
                    : 'CRITICAL ALERT: Tampering Detected in Audit Ledger!'}
                </strong>
                <span className="font-mono text-[11px] opacity-80">
                  {verificationResult.totalBlocks} Blocks Evaluated
                </span>
              </div>
              <p className="mt-1 leading-relaxed">
                {verificationResult.verified
                  ? `All ${verificationResult.totalBlocks} consecutive blocks verified against SHA-256 Merkle chain. Root genesis hash matches anchor. Zero tampering detected.`
                  : verificationResult.tamperedDetails || 'A record in the historical log was altered. Hash continuity was severed.'}
              </p>
              <div className="mt-2 text-[10px] font-mono opacity-70 flex flex-wrap gap-4">
                <span>Genesis: {verificationResult.genesisHash.slice(0, 24)}...</span>
                <span>Tip: {verificationResult.latestHash.slice(0, 24)}...</span>
              </div>
            </div>
          </div>
        )}

        {tamperNotice && (
          <div className="mt-3 p-3 bg-purple-950/40 border border-purple-800/60 rounded-xl text-xs text-purple-300 flex items-center gap-2">
            <Zap className="w-4 h-4 text-purple-400 shrink-0" />
            <span>{tamperNotice}</span>
          </div>
        )}
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-slate-900/60 p-4 rounded-2xl border border-slate-800">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search audit trail by actor, action, hash, or details..."
            className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Quick Filter: Denied Attempts Only */}
          <button
            onClick={() => {
              setFilterStatus(filterStatus === 'ACCESS_DENIED' ? 'ALL' : 'ACCESS_DENIED');
              setFilterAction('ALL');
            }}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold border transition-all ${
              filterStatus === 'ACCESS_DENIED'
                ? 'bg-rose-600 text-white border-rose-500 shadow-md shadow-rose-950'
                : 'bg-rose-950/30 text-rose-400 border-rose-900/40 hover:bg-rose-900/40'
            }`}
          >
            Denied Probes (403s)
          </button>

          <select
            value={filterAction}
            onChange={(e) => {
              setFilterAction(e.target.value);
              setFilterStatus('ALL');
            }}
            className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-indigo-500"
          >
            <option value="ALL">All Actions</option>
            <option value="DOWNLOAD">Downloads</option>
            <option value="READ">Reads</option>
            <option value="UPLOAD">Uploads</option>
            <option value="GRANT_PERMISSION">Permission Grants</option>
            <option value="REVOKE_PERMISSION">Instant Revocations</option>
            <option value="AI_PERMISSION_SUGGESTION">AI Suggestions</option>
            <option value="ACCESS_DENIED">Access Denied (403)</option>
            <option value="VERIFY_AUDIT_TRAIL">Chain Verifications</option>
          </select>

          <button
            onClick={fetchLogs}
            className="p-1.5 text-slate-400 hover:text-slate-200 bg-slate-950 border border-slate-800 rounded-xl hover:bg-slate-800/60 transition-colors shrink-0"
            title="Refresh Ledger"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Visual Hash Chain Timeline */}
      <div className="space-y-3">
        {filteredLogs.length === 0 ? (
          <div className="p-12 text-center bg-slate-900/30 border border-dashed border-slate-800 rounded-2xl text-xs text-slate-500">
            No audit records matched your active filter criteria.
          </div>
        ) : (
          filteredLogs.map((block, idx) => {
            const isDenied = block.status === 'ACCESS_DENIED';
            const isTampered = block.tampered;
            const isAi = block.action === 'AI_PERMISSION_SUGGESTION';

            return (
              <div
                key={`${block.index}-${block.entryHash}`}
                className={`bg-slate-900/80 border rounded-2xl p-4 transition-all relative overflow-hidden ${
                  isTampered
                    ? 'border-rose-500 bg-rose-950/20 shadow-lg shadow-rose-950/40'
                    : isDenied
                    ? 'border-rose-900/60 bg-rose-950/10'
                    : isAi
                    ? 'border-teal-900/50 bg-teal-950/10'
                    : 'border-slate-800/80 hover:border-slate-700/80'
                }`}
              >
                {/* Block Index and Action Row */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2.5 border-b border-slate-800/60 text-xs">
                  <div className="flex items-center gap-2.5">
                    <span className="font-mono text-[11px] font-bold text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                      Block #{block.index}
                    </span>
                    {getActionBadge(block.action)}
                    {isTampered && (
                      <span className="bg-rose-600 text-white text-[10px] font-bold px-2 py-0.5 rounded-full animate-bounce">
                        TAMPERED PAYLOAD
                      </span>
                    )}
                    {block.documentTitle && (
                      <span className="text-slate-300 font-semibold truncate max-w-xs">
                        "{block.documentTitle}"
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-3 text-[11px] text-slate-400">
                    <span>IP: <code className="text-slate-300">{block.ipAddress}</code></span>
                    <span>•</span>
                    <span>{new Date(block.timestamp).toLocaleTimeString()} ({new Date(block.timestamp).toLocaleDateString()})</span>
                  </div>
                </div>

                {/* Actor & Details */}
                <div className="py-3 flex flex-col sm:flex-row sm:items-start justify-between gap-3 text-xs">
                  <div className="flex items-center gap-2.5 shrink-0">
                    <div className="w-7 h-7 rounded-lg bg-indigo-950/60 border border-indigo-800/40 flex items-center justify-center font-bold text-[10px] text-indigo-300">
                      {block.actor.name.slice(0, 2).toUpperCase()}
                    </div>
                    <div>
                      <p className="font-semibold text-slate-200 leading-tight">{block.actor.name}</p>
                      <p className="text-[10px] text-slate-400">{block.actor.email} ({block.actor.role})</p>
                    </div>
                  </div>

                  <div className="flex-1 bg-slate-950/60 p-2.5 rounded-xl border border-slate-800/60 font-mono text-[11px] text-slate-300 leading-relaxed">
                    {block.details}
                  </div>
                </div>

                {/* Cryptographic Link Hashes (Merkle Connection) */}
                <div className="pt-2.5 border-t border-slate-800/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[10px] font-mono text-slate-500">
                  <div className="flex items-center gap-1.5 truncate max-w-md">
                    <span className="text-slate-600">PREV_HASH:</span>
                    <span className="text-slate-400 truncate">{block.previousHash}</span>
                  </div>

                  <div className="flex items-center gap-1.5 truncate max-w-md">
                    <span className="text-indigo-400 font-bold">ENTRY_HASH:</span>
                    <span className="text-indigo-300 truncate">{block.entryHash}</span>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
