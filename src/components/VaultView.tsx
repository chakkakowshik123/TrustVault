import React, { useState } from 'react';
import { 
  FileText, 
  Search, 
  Filter, 
  Plus, 
  Download, 
  Eye, 
  Key, 
  Trash2, 
  Lock, 
  ShieldCheck, 
  AlertTriangle,
  Fingerprint,
  RefreshCw,
  FolderOpen
} from 'lucide-react';
import type { Document as VaultDoc, User, Category, SecurityLevel } from '../types.js';
import { api } from '../services/api.js';

interface VaultViewProps {
  documents: VaultDoc[];
  currentUser: User;
  onOpenPreview: (doc: VaultDoc) => void;
  onOpenPermissions: (doc: VaultDoc) => void;
  onOpenUpload: () => void;
  onRefresh: () => void;
}

export const VaultView: React.FC<VaultViewProps> = ({
  documents,
  currentUser,
  onOpenPreview,
  onOpenPermissions,
  onOpenUpload,
  onRefresh
}) => {
  const [search, setSearch] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedLevel, setSelectedLevel] = useState<string>('ALL');
  const [actionFeedback, setActionFeedback] = useState<{ id: string; text: string; error?: boolean } | null>(null);

  const filteredDocs = documents.filter((doc) => {
    if (selectedCategory !== 'ALL' && doc.category !== selectedCategory) return false;
    if (selectedLevel !== 'ALL' && doc.securityLevel !== selectedLevel) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      const matchTitle = doc.title.toLowerCase().includes(q);
      const matchDesc = doc.description.toLowerCase().includes(q);
      const matchOwner = doc.ownerName.toLowerCase().includes(q);
      const matchTags = doc.tags.some(t => t.toLowerCase().includes(q));
      if (!matchTitle && !matchDesc && !matchOwner && !matchTags) return false;
    }
    return true;
  });

  const handleDirectDownload = async (doc: VaultDoc, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await api.downloadDocument(doc.id, doc.filename);
      setActionFeedback({ id: doc.id, text: 'Decrypted and downloaded successfully.' });
      setTimeout(() => setActionFeedback(null), 3000);
    } catch (err: any) {
      setActionFeedback({ 
        id: doc.id, 
        text: `403 Forbidden: ${err.message || 'Access Denied'}`, 
        error: true 
      });
      setTimeout(() => setActionFeedback(null), 4000);
    }
  };

  const handleDelete = async (doc: VaultDoc, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm(`Are you sure you want to permanently purge '${doc.title}'?`)) return;

    try {
      await api.deleteDocument(doc.id);
      setActionFeedback({ id: doc.id, text: 'Document purged from secure enclave.' });
      onRefresh();
    } catch (err: any) {
      setActionFeedback({ id: doc.id, text: `Delete blocked: ${err.message}`, error: true });
    }
  };

  const getSecurityLevelBadge = (level: SecurityLevel) => {
    switch (level) {
      case 'SECRET':
        return <span className="bg-rose-500/10 text-rose-400 border border-rose-500/30 text-[10px] font-bold px-2 py-0.5 rounded-full">SECRET</span>;
      case 'CONFIDENTIAL':
        return <span className="bg-amber-500/10 text-amber-400 border border-amber-500/30 text-[10px] font-bold px-2 py-0.5 rounded-full">CONFIDENTIAL</span>;
      case 'RESTRICTED':
        return <span className="bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 text-[10px] font-bold px-2 py-0.5 rounded-full">RESTRICTED</span>;
      default:
        return <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[10px] font-bold px-2 py-0.5 rounded-full">INTERNAL</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Controls Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4 bg-slate-900/60 p-4 rounded-2xl border border-slate-800">
        <div className="flex items-center gap-3 flex-1 max-w-lg">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by name, owner, tags, or description..."
              className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500 transition-colors"
            />
          </div>

          <button
            onClick={onRefresh}
            className="p-2 text-slate-400 hover:text-slate-200 bg-slate-950 border border-slate-800 rounded-xl hover:bg-slate-800/60 transition-colors shrink-0"
            title="Refresh Vault State"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>

        {/* Filters and Upload Button */}
        <div className="flex flex-wrap items-center gap-2.5">
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-indigo-500"
          >
            <option value="ALL">All Categories</option>
            <option value="FINANCE">Finance & Compensation</option>
            <option value="LEGAL">Legal & Contracts</option>
            <option value="ENGINEERING">Engineering & Architecture</option>
            <option value="HR">HR & Personnel</option>
            <option value="COMPLIANCE">Regulatory & Compliance</option>
            <option value="EXECUTIVE">Executive Board</option>
          </select>

          <select
            value={selectedLevel}
            onChange={(e) => setSelectedLevel(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-indigo-500"
          >
            <option value="ALL">All Classifications</option>
            <option value="INTERNAL">Internal</option>
            <option value="RESTRICTED">Restricted</option>
            <option value="CONFIDENTIAL">Confidential</option>
            <option value="SECRET">Secret</option>
          </select>

          {(currentUser.role === 'DOCUMENT_OWNER' || currentUser.role === 'ADMIN') && (
            <button
              onClick={onOpenUpload}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-semibold shadow-md shadow-indigo-600/30 transition-all hover:scale-102"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Upload Document</span>
            </button>
          )}
        </div>
      </div>

      {/* Role Context Notification */}
      <div className="p-3 bg-slate-900/40 border border-slate-800/80 rounded-xl flex items-center justify-between text-xs text-slate-400">
        <div className="flex items-center gap-2">
          <Fingerprint className="w-4 h-4 text-indigo-400" />
          <span>
            Viewing as <strong className="text-slate-200">{currentUser.name}</strong> ({currentUser.role}).
            Showing {filteredDocs.length} accessible document{filteredDocs.length === 1 ? '' : 's'}.
          </span>
        </div>
        <span className="text-[11px] text-slate-500 hidden sm:inline">
          Server filters unshared documents automatically (Zero Client-Side Leaks)
        </span>
      </div>

      {/* Document Grid */}
      {filteredDocs.length === 0 ? (
        <div className="p-12 text-center bg-slate-900/30 border border-dashed border-slate-800 rounded-2xl space-y-3">
          <FolderOpen className="w-10 h-10 text-slate-600 mx-auto" />
          <h3 className="text-sm font-semibold text-slate-300">No Documents Found</h3>
          <p className="text-xs text-slate-500 max-w-sm mx-auto">
            Either no documents match your active filter, or your active role does not possess permissions on unshared documents.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredDocs.map((doc) => {
            const isOwner = doc.ownerId === currentUser.id;
            const isAdmin = currentUser.role === 'ADMIN';
            const userGrant = (doc.permissions || []).find(p => p.userId === currentUser.id);
            const userLevel = doc.userAccessLevel || (isOwner ? 'OWNER' : (isAdmin ? 'ADMIN' : (userGrant ? userGrant.accessLevel : 'NONE')));
            const canManage = isOwner || isAdmin;
            const feedback = actionFeedback?.id === doc.id ? actionFeedback : null;

            return (
              <div
                key={doc.id}
                onClick={() => onOpenPreview(doc)}
                className="bg-slate-900/70 border border-slate-800/80 hover:border-slate-700/80 rounded-2xl p-5 flex flex-col justify-between transition-all hover:shadow-xl hover:shadow-indigo-950/20 cursor-pointer group relative overflow-hidden"
              >
                <div>
                  {/* Card Header: Category & Security Level */}
                  <div className="flex items-center justify-between gap-2 mb-3">
                    <span className="text-[11px] font-semibold text-slate-400 bg-slate-800/80 px-2 py-0.5 rounded-md">
                      {doc.category}
                    </span>
                    <div className="flex items-center gap-1.5">
                      {getSecurityLevelBadge(doc.securityLevel)}
                      <span className="text-[10px] font-mono text-slate-500" title="Permission Version Epoch">
                        v{doc.permissionVersion}
                      </span>
                    </div>
                  </div>

                  {/* Document Title & Description */}
                  <h3 className="text-sm font-bold text-slate-100 group-hover:text-indigo-300 transition-colors line-clamp-1">
                    {doc.title}
                  </h3>
                  <p className="text-xs text-slate-400 mt-1 line-clamp-2 leading-relaxed">
                    {doc.description}
                  </p>

                  {/* Tags */}
                  <div className="flex flex-wrap gap-1 mt-3">
                    {doc.tags.slice(0, 3).map((tag, idx) => (
                      <span
                        key={idx}
                        className="text-[10px] bg-slate-950 text-slate-400 px-2 py-0.5 rounded border border-slate-800"
                      >
                        #{tag}
                      </span>
                    ))}
                    {doc.tags.length > 3 && (
                      <span className="text-[10px] text-slate-500 py-0.5">+{doc.tags.length - 3}</span>
                    )}
                  </div>
                </div>

                {/* Card Footer: Metadata & Actions */}
                <div className="mt-5 pt-4 border-t border-slate-800/80 space-y-3">
                  <div className="flex items-center justify-between text-[11px] text-slate-400">
                    <span>Owner: <strong className="text-slate-300">{doc.ownerName}</strong></span>
                    <span className="font-mono text-slate-500">{(doc.fileSize / 1024).toFixed(0)} KB</span>
                  </div>

                  {/* Live Feedback Notification inside card */}
                  {feedback && (
                    <div className={`p-2 rounded-lg text-[11px] flex items-center gap-1.5 ${
                      feedback.error 
                        ? 'bg-rose-950/60 border border-rose-800/60 text-rose-300' 
                        : 'bg-emerald-950/60 border border-emerald-800/60 text-emerald-300'
                    }`}>
                      <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                      <span className="truncate">{feedback.text}</span>
                    </div>
                  )}

                  {/* Action Buttons & Server Authorization Status */}
                  <div className="flex items-center justify-between gap-2 pt-1">
                    <div className="flex items-center gap-1.5">
                      <span className="text-[10px] uppercase font-bold text-slate-500">Access:</span>
                      <span className={`text-[11px] font-bold ${
                        userLevel === 'OWNER'
                          ? 'text-indigo-400'
                          : userLevel === 'ADMIN'
                          ? 'text-red-400'
                          : userLevel === 'DOWNLOAD'
                          ? 'text-cyan-400'
                          : userLevel === 'EDIT'
                          ? 'text-amber-400'
                          : userLevel === 'READ'
                          ? 'text-emerald-400'
                          : 'text-slate-500'
                      }`}>
                        {userLevel}
                      </span>
                      <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-slate-950 text-slate-500 border border-slate-800" title="Server evaluates live ACL on every download/view request">
                        verifyDocumentAccess()
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5">
                      {canManage && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onOpenPermissions(doc);
                          }}
                          className="p-1.5 text-slate-400 hover:text-indigo-400 bg-slate-950 hover:bg-slate-800 rounded-lg border border-slate-800 transition-colors"
                          title="Manage Access Control List"
                        >
                          <Key className="w-3.5 h-3.5" />
                        </button>
                      )}

                      <button
                        onClick={(e) => handleDirectDownload(doc, e)}
                        className="p-1.5 text-slate-400 hover:text-slate-200 bg-slate-950 hover:bg-slate-800 rounded-lg border border-slate-800 transition-colors"
                        title="Download Document (Server checks authorization)"
                      >
                        <Download className="w-3.5 h-3.5" />
                      </button>

                      {canManage && (
                        <button
                          onClick={(e) => handleDelete(doc, e)}
                          className="p-1.5 text-slate-400 hover:text-rose-400 bg-slate-950 hover:bg-rose-950/40 rounded-lg border border-slate-800 transition-colors"
                          title="Delete Document"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
