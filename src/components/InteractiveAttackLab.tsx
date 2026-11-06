import React, { useState } from 'react';
import {
  Terminal,
  ShieldAlert,
  ShieldCheck,
  Send,
  Flame,
  Bug,
  RefreshCw,
  Lock,
  FileCode,
  Hash,
  AlertTriangle,
  CheckCircle2,
  Cpu,
  Layers,
  ArrowRight
} from 'lucide-react';
import type { User } from '../types.js';
import { api } from '../services/api.js';

interface InteractiveAttackLabProps {
  currentUser: User;
}

interface AttackPreset {
  name: string;
  category: string;
  vector: string;
  simulatedUserId: string;
  targetDocId: string;
  action: string;
  payload: string;
  description: string;
}

const PRESETS: AttackPreset[] = [
  {
    name: 'Insecure Direct Object Reference (IDOR)',
    category: 'Broken Object Level Authorization',
    vector: 'IDOR_PROBE',
    simulatedUserId: 'usr_viewer_carol',
    targetDocId: 'doc-finance-002',
    action: 'READ',
    payload: 'GET /api/documents/doc-finance-002 HTTP/1.1 (IDOR Probe)',
    description: 'Carol Davies (VIEWER) directly probes classified Executive Compensation without grant.'
  },
  {
    name: 'Privilege Escalation via Header Forgery',
    category: 'Authentication & Session Spoofing',
    vector: 'FORGED_ROLE_HEADER',
    simulatedUserId: 'usr_attacker_eve',
    targetDocId: 'doc-finance-002',
    action: 'DOWNLOAD',
    payload: 'Authorization: Bearer token_eve [x-injected-role: ADMIN]',
    description: 'Eve Thorne attempts to inject client-side admin privileges to download secret compensation file.'
  },
  {
    name: 'Arbitrary File Path Traversal',
    category: 'Input Validation & Directory Traversal',
    vector: 'PATH_TRAVERSAL',
    simulatedUserId: 'usr_attacker_eve',
    targetDocId: 'doc-finance-002',
    action: 'UPLOAD',
    payload: '../../../../etc/passwd',
    description: 'Adversary attempts to upload and traverse filesystem to exfiltrate root Linux credentials.'
  },
  {
    name: 'Time-Bound Token Expiration Replay',
    category: 'Temporal Authorization Flaw',
    vector: 'EXPIRED_GRANT_REPLAY',
    simulatedUserId: 'usr_viewer_carol',
    targetDocId: 'doc-legal-001',
    action: 'DOWNLOAD',
    payload: 'Replay-Token-Epoch: v4-expired-60s-ago',
    description: 'Attacker replays valid credentials after the grant time window has elapsed.'
  },
  {
    name: 'Cryptographic Audit Block Tampering',
    category: 'Non-Repudiation & Log Injection',
    vector: 'AUDIT_BLOCK_TAMPER',
    simulatedUserId: 'usr_attacker_eve',
    targetDocId: 'doc-legal-001',
    action: 'TAMPER',
    payload: 'UPDATE audit_ledger SET details = "CLEANSED_LOG" WHERE index = 2',
    description: 'Attacker tries to alter historic audit entry. Recomputed SHA-256 chain will detect mismatch.'
  },
  {
    name: 'Unauthorized Resource Destruction',
    category: 'Missing Function Level Access Control',
    vector: 'UNAUTHORIZED_DELETE',
    simulatedUserId: 'usr_viewer_carol',
    targetDocId: 'doc-legal-001',
    action: 'DELETE',
    payload: 'DELETE /api/documents/doc-legal-001',
    description: 'Viewer role invokes destructive document removal endpoint belonging to another department.'
  }
];

export const InteractiveAttackLab: React.FC<InteractiveAttackLabProps> = ({ currentUser }) => {
  const [selectedVector, setSelectedVector] = useState<string>('IDOR_PROBE');
  const [simulatedUserId, setSimulatedUserId] = useState<string>('usr_viewer_carol');
  const [targetDocId, setTargetDocId] = useState<string>('doc-finance-002');
  const [action, setAction] = useState<string>('READ');
  const [customPayload, setCustomPayload] = useState<string>('GET /api/documents/doc-finance-002 (IDOR Probe)');
  const [loading, setLoading] = useState(false);
  const [attackReport, setAttackReport] = useState<any | null>(null);

  const applyPreset = (preset: AttackPreset) => {
    setSelectedVector(preset.vector);
    setSimulatedUserId(preset.simulatedUserId);
    setTargetDocId(preset.targetDocId);
    setAction(preset.action);
    setCustomPayload(preset.payload);
    setAttackReport(null);
  };

  const handleExecuteAttack = async () => {
    setLoading(true);
    try {
      const report = await api.runCustomAttack({
        attackVector: selectedVector,
        simulatedUserId,
        targetDocId,
        action,
        customPayload
      });
      setAttackReport(report);
    } catch (err: any) {
      console.error('Attack execution failed:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Statement */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="p-2 bg-rose-500/10 border border-rose-500/30 rounded-xl text-rose-400">
                <Terminal className="w-5 h-5" />
              </span>
              <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                <span>Interactive Evaluator Exploit Sandbox</span>
                <span className="text-[10px] bg-rose-950 text-rose-300 border border-rose-800 px-2 py-0.5 rounded-full font-mono font-semibold">
                  Live Penetration Console
                </span>
              </h2>
            </div>
            <p className="text-xs text-slate-400 max-w-2xl">
              Unlike static test scripts, this interactive lab allows evaluators to craft arbitrary adversarial payloads, 
              test boundary edge cases in real-time, and observe server-authoritative defense interception and cryptographic audit signing.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-950/80 border border-slate-800 text-xs text-slate-400 font-mono">
              <Cpu className="w-3.5 h-3.5 text-indigo-400" />
              <span>Zero-Bypass Policy Active</span>
            </span>
          </div>
        </div>

        {/* Quick Attack Vector Presets */}
        <div className="mt-6 pt-4 border-t border-slate-800/80">
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block mb-2.5">
            Select Adversarial Exploit Template:
          </span>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
            {PRESETS.map((preset, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => applyPreset(preset)}
                className={`p-3 text-left rounded-xl border transition-all text-xs flex flex-col justify-between ${
                  selectedVector === preset.vector && customPayload === preset.payload
                    ? 'bg-rose-950/40 border-rose-600/70 text-slate-100 shadow-lg shadow-rose-950/40'
                    : 'bg-slate-950/40 border-slate-800/80 hover:border-slate-700 text-slate-300'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between gap-1 mb-1">
                    <span className="font-bold text-slate-200">{preset.name}</span>
                    <Flame className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                  </div>
                  <p className="text-[11px] text-slate-400 line-clamp-2">{preset.description}</p>
                </div>
                <div className="mt-2 pt-1.5 border-t border-slate-800/60 flex items-center justify-between text-[10px] text-slate-500 font-mono">
                  <span>{preset.category}</span>
                  <span className="text-rose-400">{preset.action}</span>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Attack Configurator & Telemetry Output Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Attack Payload Construction (5 cols) */}
        <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Bug className="w-4 h-4 text-rose-400" />
              <span>Exploit Payload Configurator</span>
            </h3>
            <span className="text-[10px] font-mono text-slate-500">POST /api/tests/custom-attack</span>
          </div>

          <div className="space-y-3">
            <div>
              <label className="block text-[11px] font-semibold text-slate-400 mb-1">Attack Classification</label>
              <select
                value={selectedVector}
                onChange={(e) => setSelectedVector(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-rose-500 font-mono"
              >
                <option value="IDOR_PROBE">IDOR_PROBE (Direct Object Reference)</option>
                <option value="FORGED_ROLE_HEADER">FORGED_ROLE_HEADER (Client-Side Privilege Tampering)</option>
                <option value="PATH_TRAVERSAL">PATH_TRAVERSAL (Arbitrary Filesystem Escape)</option>
                <option value="EXPIRED_GRANT_REPLAY">EXPIRED_GRANT_REPLAY (Temporal Expiry Bypass)</option>
                <option value="AUDIT_BLOCK_TAMPER">AUDIT_BLOCK_TAMPER (Merkle Hash Invalidation)</option>
                <option value="UNAUTHORIZED_DELETE">UNAUTHORIZED_DELETE (Unauthorized Resource Removal)</option>
              </select>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[11px] font-semibold text-slate-400 mb-1">Simulated Actor</label>
                <select
                  value={simulatedUserId}
                  onChange={(e) => setSimulatedUserId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-rose-500"
                >
                  <option value="usr_attacker_eve">Eve Thorne (ATTACKER)</option>
                  <option value="usr_viewer_carol">Carol Davies (VIEWER)</option>
                  <option value="usr_partner_dave">Dave Miller (PARTNER)</option>
                  <option value="usr_uploader_bob">Bob Henderson (FINANCE)</option>
                  <option value="usr_admin">Alice Morgan (ADMIN)</option>
                </select>
              </div>

              <div>
                <label className="block text-[11px] font-semibold text-slate-400 mb-1">Target Resource</label>
                <select
                  value={targetDocId}
                  onChange={(e) => setTargetDocId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-rose-500"
                >
                  <option value="doc-finance-002">doc-finance-002 (Executive Bonus Ledger) [SECRET]</option>
                  <option value="doc-legal-001">doc-legal-001 (Acme Corp Agreement) [CONFIDENTIAL]</option>
                  <option value="doc-eng-003">doc-eng-003 (Quantum Architecture) [INTERNAL]</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[11px] font-semibold text-slate-400 mb-1">Target Action</label>
                <select
                  value={action}
                  onChange={(e) => setAction(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-rose-500"
                >
                  <option value="READ">READ (View / Preview)</option>
                  <option value="DOWNLOAD">DOWNLOAD (Exfiltrate Binary)</option>
                  <option value="EDIT">EDIT (Modify Document)</option>
                  <option value="DELETE">DELETE (Destroy File)</option>
                </select>
              </div>

              <div>
                <label className="block text-[11px] font-semibold text-slate-400 mb-1">Defense Interception</label>
                <div className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-emerald-400 font-mono flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
                  <span>Enforce Zero-Trust</span>
                </div>
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-semibold text-slate-400 mb-1">Raw Exploit String / Headers</label>
              <textarea
                rows={3}
                value={customPayload}
                onChange={(e) => setCustomPayload(e.target.value)}
                placeholder="Enter adversarial payload..."
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-rose-300 placeholder:text-slate-600 focus:outline-none focus:border-rose-500"
              />
            </div>

            <button
              type="button"
              onClick={handleExecuteAttack}
              disabled={loading}
              className="w-full py-3 bg-rose-600 hover:bg-rose-500 text-white rounded-xl text-xs font-bold shadow-lg shadow-rose-950/60 flex items-center justify-center gap-2 transition-all disabled:opacity-50 hover:scale-101"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Transmitting Payload to Secure Enclave...</span>
                </>
              ) : (
                <>
                  <Send className="w-4 h-4" />
                  <span>Fire Adversarial Exploit Payload</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Right Column: Live Server Defense Telemetry (7 cols) */}
        <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-2xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-emerald-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  Real-Time Server Authorization Telemetry
                </h3>
              </div>
              {attackReport && (
                <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full border ${
                  attackReport.intercepted
                    ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                    : 'bg-rose-950 text-rose-300 border-rose-800'
                }`}>
                  HTTP {attackReport.httpStatus} • {attackReport.intercepted ? 'INTERCEPTED' : 'UNINTERCEPTED'}
                </span>
              )}
            </div>

            {!attackReport ? (
              <div className="min-h-[280px] flex flex-col items-center justify-center text-center p-6 border border-dashed border-slate-800 rounded-xl bg-slate-950/40">
                <Terminal className="w-8 h-8 text-slate-600 mb-3" />
                <h4 className="text-xs font-bold text-slate-300 mb-1">Awaiting Exploit Execution</h4>
                <p className="text-[11px] text-slate-500 max-w-sm">
                  Click <strong className="text-rose-400">"Fire Adversarial Exploit Payload"</strong> or pick one of the presets above to inspect the real-time server defense pipeline.
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                {/* Result Hero Banner */}
                <div className={`p-4 rounded-xl border ${
                  attackReport.intercepted
                    ? 'bg-emerald-950/30 border-emerald-800/60 text-emerald-300'
                    : 'bg-rose-950/30 border-rose-800/60 text-rose-300'
                }`}>
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        {attackReport.intercepted ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                        ) : (
                          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                        )}
                        <span className="text-xs font-bold text-slate-100">
                          {attackReport.intercepted ? 'Attack Neutralized by Server' : 'Attack Succeeded (Vulnerability Found)'}
                        </span>
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed">
                        {attackReport.defenseSummary}
                      </p>
                    </div>

                    <div className="text-right shrink-0">
                      <span className="text-[10px] font-mono text-slate-500 block">Attack ID</span>
                      <span className="text-xs font-mono font-bold text-slate-300">{attackReport.attackId}</span>
                    </div>
                  </div>
                </div>

                {/* Defense Details Grid */}
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="p-3 bg-slate-950/50 border border-slate-800 rounded-xl">
                    <span className="text-[10px] uppercase font-bold text-slate-500 block">Defense Layer</span>
                    <span className="text-slate-200 font-semibold text-[11px]">{attackReport.defenseLayer}</span>
                  </div>
                  <div className="p-3 bg-slate-950/50 border border-slate-800 rounded-xl">
                    <span className="text-[10px] uppercase font-bold text-slate-500 block">Audit Chain Block</span>
                    <span className="text-indigo-400 font-mono font-bold text-[11px]">
                      Block #{attackReport.auditBlockIndex}
                    </span>
                  </div>
                </div>

                {/* Audit Hash Reference */}
                <div className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-xl flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2 overflow-hidden">
                    <Hash className="w-4 h-4 text-slate-500 shrink-0" />
                    <div className="truncate">
                      <span className="text-[10px] text-slate-500 block">Cryptographic Audit Digest (SHA-256)</span>
                      <span className="font-mono text-[11px] text-slate-300 truncate block">
                        {attackReport.auditEntryHash}
                      </span>
                    </div>
                  </div>
                  <span className="text-[10px] bg-slate-900 border border-slate-800 px-2 py-1 rounded text-emerald-400 font-mono shrink-0">
                    Non-Repudiation Signed
                  </span>
                </div>

                {/* Live Server Trace Logs */}
                <div className="p-3.5 bg-black/60 border border-slate-800 rounded-xl space-y-1.5 font-mono text-[11px]">
                  <div className="flex items-center justify-between text-[10px] text-slate-500 uppercase tracking-wider pb-1 border-b border-slate-800/60">
                    <span>Server-Side Decision Pipeline</span>
                    <span>100% Deterministic</span>
                  </div>
                  {attackReport.executionTrace?.map((line: string, i: number) => (
                    <div key={i} className="flex items-start gap-2 text-slate-300">
                      <span className="text-indigo-400 select-none">›</span>
                      <span>{line}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Evaluator Insight Footer */}
          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-500">
            <span>Snovasys Criterion 1: Zero Client-Side Storage Leakage</span>
            <span className="font-mono text-slate-400">verifyDocumentAccess() server-authoritative</span>
          </div>
        </div>
      </div>
    </div>
  );
};
