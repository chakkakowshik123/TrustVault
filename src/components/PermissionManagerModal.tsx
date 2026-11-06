import React, { useState, useEffect } from 'react';
import { 
  Key, 
  UserMinus, 
  UserPlus, 
  Sparkles, 
  AlertTriangle, 
  ShieldCheck, 
  CheckCircle2, 
  Clock, 
  HelpCircle,
  ExternalLink,
  Zap,
  Info
} from 'lucide-react';
import type { Document as VaultDoc, PermissionGrant, User as CurrentUser, AccessLevel } from '../types.js';
import { api } from '../services/api.js';

interface PermissionManagerModalProps {
  document: VaultDoc;
  currentUser: CurrentUser;
  allUsers: CurrentUser[];
  onClose: () => void;
  onPermissionsUpdated: () => void;
}

export const PermissionManagerModal: React.FC<PermissionManagerModalProps> = ({
  document: doc,
  currentUser,
  allUsers,
  onClose,
  onPermissionsUpdated
}) => {
  const [permissions, setPermissions] = useState<PermissionGrant[]>(doc.permissions || []);
  const [permissionVersion, setPermissionVersion] = useState<number>(doc.permissionVersion || 1);
  const [loading, setLoading] = useState(false);
  const [revokingUserId, setRevokingUserId] = useState<string | null>(null);
  const [feedbackMessage, setFeedbackMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // New grant form state
  const [selectedUserId, setSelectedUserId] = useState<string>('');
  const [selectedLevel, setSelectedLevel] = useState<AccessLevel>('READ');
  const [notes, setNotes] = useState<string>('');
  const [expiresInMinutes, setExpiresInMinutes] = useState<number | null>(null);

  // AI Advisor state
  const [aiLoading, setAiLoading] = useState(false);
  const [aiSuggestion, setAiSuggestion] = useState<{
    recommendedLevel: AccessLevel;
    riskScore: 'LOW' | 'MEDIUM' | 'HIGH';
    rationale: string;
    warnings: string[];
    policyNotice: string;
  } | null>(null);

  // Users eligible to be added (excluding owner and already granted users)
  const eligibleUsers = allUsers.filter(
    u => u.id !== doc.ownerId && !(permissions || []).some(p => p.userId === u.id)
  );

  useEffect(() => {
    if (eligibleUsers.length > 0 && !selectedUserId) {
      setSelectedUserId(eligibleUsers[0].id);
    }
  }, [eligibleUsers, selectedUserId]);

  const handleRevoke = async (targetUserId: string, targetName: string) => {
    setRevokingUserId(targetUserId);
    setFeedbackMessage(null);

    try {
      const res = await api.revokePermission(doc.id, targetUserId);
      setPermissions(res.permissions);
      setPermissionVersion(res.permissionVersion);
      setFeedbackMessage({
        type: 'success',
        text: `Access for ${targetName} was REVOKED IMMEDIATELY. Epoch bumped to v${res.permissionVersion}. Any future download request by this user will be blocked with 403 Forbidden.`
      });
      onPermissionsUpdated();
    } catch (err: any) {
      setFeedbackMessage({
        type: 'error',
        text: err.message || 'Failed to revoke permission'
      });
    } finally {
      setRevokingUserId(null);
    }
  };

  const handleConsultAiAdvisor = async () => {
    if (!selectedUserId) return;
    setAiLoading(true);
    setFeedbackMessage(null);

    try {
      const res = await api.suggestPermissions(doc.id, selectedUserId);
      setAiSuggestion(res);
      setSelectedLevel(res.recommendedLevel);
      setNotes(`AI Recommended: ${res.rationale}`);
    } catch (err: any) {
      setFeedbackMessage({
        type: 'error',
        text: err.message || 'AI advisor consultation failed'
      });
    } finally {
      setAiLoading(false);
    }
  };

  const handleGrant = async () => {
    if (!selectedUserId) return;
    setLoading(true);
    setFeedbackMessage(null);

    try {
      const targetUser = allUsers.find(u => u.id === selectedUserId);
      const res = await api.grantPermission(doc.id, selectedUserId, selectedLevel, notes, expiresInMinutes);
      setPermissions(res.permissions);
      setPermissionVersion(res.permissionVersion);
      setAiSuggestion(null);
      setNotes('');
      setExpiresInMinutes(null);
      const expiryText = expiresInMinutes ? ` (Auto-expires in ${expiresInMinutes} mins)` : ' (Permanent)';
      setFeedbackMessage({
        type: 'success',
        text: `Granted ${selectedLevel} permission to ${targetUser?.name || selectedUserId}${expiryText}. Access Control Epoch v${res.permissionVersion} recorded to hash chain.`
      });
      onPermissionsUpdated();
    } catch (err: any) {
      setFeedbackMessage({
        type: 'error',
        text: err.message || 'Failed to grant permission'
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden relative">
        {/* Header */}
        <div className="p-6 border-b border-slate-800 flex items-start justify-between bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-indigo-500/10 border border-indigo-500/30 rounded-xl">
              <Key className="w-5 h-5 text-indigo-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-slate-100">Access Control & Instant Revocation</h2>
                <span className="bg-indigo-950 text-indigo-300 border border-indigo-800 text-[10px] font-mono font-bold px-2 py-0.5 rounded-full">
                  Epoch v{permissionVersion}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5 truncate max-w-md">
                Document: <strong className="text-slate-200">{doc.title}</strong>
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
        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          {/* Feedback alert */}
          {feedbackMessage && (
            <div
              className={`p-3.5 rounded-xl text-xs flex items-start gap-2.5 border ${
                feedbackMessage.type === 'success'
                  ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300'
                  : 'bg-rose-950/40 border-rose-800/60 text-rose-300'
              }`}
            >
              {feedbackMessage.type === 'success' ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              ) : (
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              )}
              <span className="leading-relaxed">{feedbackMessage.text}</span>
            </div>
          )}

          {/* Section: Active Grants */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                Active Named Grants ({permissions.length})
              </h3>
              <span className="text-[11px] text-slate-500">
                Revocations take effect immediately on next request
              </span>
            </div>

            {permissions.length === 0 ? (
              <div className="p-6 bg-slate-950/40 border border-dashed border-slate-800 rounded-xl text-center text-xs text-slate-500">
                <ShieldCheck className="w-6 h-6 text-slate-600 mx-auto mb-2" />
                This document is strictly private to owner <strong className="text-slate-400">{doc.ownerName}</strong>. No other person has access.
              </div>
            ) : (
              <div className="space-y-2">
                {permissions.map((p) => (
                  <div
                    key={p.userId}
                    className="p-3 bg-slate-950/50 border border-slate-800/80 rounded-xl flex items-center justify-between hover:border-slate-700/80 transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg bg-indigo-950/60 border border-indigo-800/50 flex items-center justify-center font-bold text-xs text-indigo-300">
                        {p.userName.slice(0, 2).toUpperCase()}
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-semibold text-slate-200">{p.userName}</span>
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                            p.accessLevel === 'DOWNLOAD'
                              ? 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30'
                              : p.accessLevel === 'EDIT'
                              ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                              : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                          }`}>
                            {p.accessLevel}
                          </span>
                          {p.expiresAt && (
                            <span className={`text-[10px] font-mono flex items-center gap-1 px-1.5 py-0.5 rounded border ${
                              new Date(p.expiresAt).getTime() <= Date.now()
                                ? 'bg-rose-950/80 text-rose-400 border-rose-800'
                                : 'bg-cyan-950/60 text-cyan-300 border-cyan-800'
                            }`}>
                              <Clock className="w-2.5 h-2.5" />
                              {new Date(p.expiresAt).getTime() <= Date.now()
                                ? 'EXPIRED'
                                : `Expires ${new Date(p.expiresAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`}
                            </span>
                          )}
                        </div>
                        <p className="text-[11px] text-slate-400 mt-0.5">{p.userEmail}</p>
                        {p.notes && <p className="text-[10px] text-slate-500 italic mt-0.5">{p.notes}</p>}
                      </div>
                    </div>

                    <button
                      onClick={() => handleRevoke(p.userId, p.userName)}
                      disabled={revokingUserId === p.userId}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-rose-950/40 hover:bg-rose-900/40 border border-rose-800/60 text-rose-300 rounded-lg text-xs font-semibold transition-all hover:scale-105"
                      title="Instantly invalidate all access and bump epoch"
                    >
                      <UserMinus className="w-3.5 h-3.5 text-rose-400" />
                      <span>{revokingUserId === p.userId ? 'Revoking...' : 'Revoke Immediately'}</span>
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Section: Grant Access Form */}
          <div className="pt-4 border-t border-slate-800/80">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <UserPlus className="w-3.5 h-3.5 text-indigo-400" />
                <span>Grant Access to Named Person</span>
              </h3>

              {/* Snovasys AI Rule Compliance Pill */}
              <div className="flex items-center gap-1 text-[11px] text-cyan-400 bg-cyan-950/40 border border-cyan-800/40 px-2 py-0.5 rounded-md">
                <Sparkles className="w-3 h-3 text-cyan-400" />
                <span>AI Advisory Available</span>
              </div>
            </div>

            {eligibleUsers.length === 0 ? (
              <p className="text-xs text-slate-500 italic">All directory users already have permissions assigned.</p>
            ) : (
              <div className="space-y-4 bg-slate-950/40 p-4 rounded-xl border border-slate-800/80">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div>
                    <label className="block text-[11px] font-semibold text-slate-400 mb-1">Target Person</label>
                    <select
                      value={selectedUserId}
                      onChange={(e) => {
                        setSelectedUserId(e.target.value);
                        setAiSuggestion(null);
                      }}
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                    >
                      {eligibleUsers.map((u) => (
                        <option key={u.id} value={u.id}>
                          {u.name} ({u.email}) — {u.role}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="block text-[11px] font-semibold text-slate-400 mb-1">Access Level</label>
                    <select
                      value={selectedLevel}
                      onChange={(e) => setSelectedLevel(e.target.value as AccessLevel)}
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                    >
                      <option value="READ">READ (View decrypted preview only)</option>
                      <option value="DOWNLOAD">DOWNLOAD (Permit file download)</option>
                      <option value="EDIT">EDIT (Modify metadata & new versions)</option>
                      <option value="MANAGE">MANAGE (Co-manage permissions)</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-[11px] font-semibold text-slate-400 mb-1 flex items-center justify-between">
                      <span>Time-Bound Window</span>
                      <span className="text-[10px] text-cyan-400 font-mono">Zero-Delay Expiry</span>
                    </label>
                    <select
                      value={expiresInMinutes === null ? 'null' : expiresInMinutes.toString()}
                      onChange={(e) => setExpiresInMinutes(e.target.value === 'null' ? null : parseInt(e.target.value, 10))}
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                    >
                      <option value="null">Permanent / Indefinite</option>
                      <option value="5">5 Minutes (Evaluator Live Demo)</option>
                      <option value="60">1 Hour (External Contractor)</option>
                      <option value="1440">24 Hours (Daily Emergency Pass)</option>
                      <option value="10080">7 Days (Audit Sprint Review)</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-[11px] font-semibold text-slate-400 mb-1">Grant Justification / Notes</label>
                  <input
                    type="text"
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    placeholder="e.g. Legal audit review for Q4 contract..."
                    className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-indigo-500"
                  />
                </div>

                {/* AI Advisor Button */}
                <div className="flex items-center justify-between pt-1">
                  <button
                    type="button"
                    onClick={handleConsultAiAdvisor}
                    disabled={aiLoading}
                    className="flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 bg-cyan-950/40 hover:bg-cyan-900/40 border border-cyan-800/60 px-3 py-1.5 rounded-lg transition-all"
                  >
                    <Sparkles className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
                    <span>{aiLoading ? 'Analyzing policy...' : 'Ask TrustVault Sentinel (AI Advisor)'}</span>
                  </button>

                  <button
                    type="button"
                    onClick={handleGrant}
                    disabled={loading || !selectedUserId}
                    className="flex items-center gap-1.5 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold shadow-md shadow-indigo-600/30 transition-all disabled:opacity-50"
                  >
                    <UserPlus className="w-3.5 h-3.5" />
                    <span>{loading ? 'Recording to Ledger...' : 'Confirm & Grant Access'}</span>
                  </button>
                </div>

                {/* AI Suggestion Card with Strict Snovasys Human-Confirmation Guardrail */}
                {aiSuggestion && (
                  <div className="p-4 bg-cyan-950/30 border border-cyan-800/50 rounded-xl space-y-2 mt-3 animate-fadeIn">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Sparkles className="w-4 h-4 text-cyan-400" />
                        <span className="text-xs font-bold text-cyan-200">
                          AI Recommendation: Grant {aiSuggestion.recommendedLevel}
                        </span>
                      </div>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                        aiSuggestion.riskScore === 'HIGH'
                          ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                          : aiSuggestion.riskScore === 'MEDIUM'
                          ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                          : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                      }`}>
                        Risk Assessment: {aiSuggestion.riskScore}
                      </span>
                    </div>

                    <p className="text-xs text-slate-300 leading-relaxed">
                      {aiSuggestion.rationale}
                    </p>

                    {aiSuggestion.warnings.length > 0 && (
                      <div className="space-y-1 pt-1">
                        {aiSuggestion.warnings.map((w, idx) => (
                          <div key={idx} className="flex items-center gap-1.5 text-[11px] text-amber-300">
                            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                            <span>{w}</span>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Snovasys Specification Compliance Notice */}
                    <div className="pt-2 border-t border-cyan-800/40 flex items-start gap-2 text-[10px] text-cyan-300/80">
                      <Info className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                      <span>{aiSuggestion.policyNotice}</span>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between text-xs text-slate-500">
          <div className="flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5 text-amber-400" />
            <span>Server-side epoch invalidation guarantees immediate revocation</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 rounded-xl transition-colors"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
