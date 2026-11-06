import React, { useState } from 'react';
import { 
  Shield, 
  Lock, 
  Download, 
  FileText, 
  User, 
  Calendar, 
  Tag, 
  Key, 
  AlertCircle, 
  CheckCircle2, 
  ExternalLink,
  Fingerprint
} from 'lucide-react';
import type { Document as VaultDoc, User as CurrentUser } from '../types.js';
import { api } from '../services/api.js';

interface DocumentPreviewModalProps {
  document: VaultDoc;
  currentUser: CurrentUser;
  onClose: () => void;
  onOpenPermissions: (doc: VaultDoc) => void;
}

export const DocumentPreviewModal: React.FC<DocumentPreviewModalProps> = ({
  document: doc,
  currentUser,
  onClose,
  onOpenPermissions
}) => {
  const [downloading, setDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [downloadSuccess, setDownloadSuccess] = useState(false);

  const canDownload = 
    doc.ownerId === currentUser.id ||
    currentUser.role === 'ADMIN' ||
    doc.userAccessLevel === 'OWNER' ||
    doc.userAccessLevel === 'ADMIN' ||
    doc.userAccessLevel === 'DOWNLOAD' ||
    doc.userAccessLevel === 'EDIT' ||
    doc.userAccessLevel === 'MANAGE' ||
    (doc.permissions || []).some(p => p.userId === currentUser.id && (p.accessLevel === 'DOWNLOAD' || p.accessLevel === 'EDIT' || p.accessLevel === 'MANAGE'));

  const canManage = doc.ownerId === currentUser.id || currentUser.role === 'ADMIN';

  const handleDownload = async () => {
    setDownloading(true);
    setDownloadError(null);
    setDownloadSuccess(false);

    try {
      await api.downloadDocument(doc.id, doc.filename);
      setDownloadSuccess(true);
      setTimeout(() => setDownloadSuccess(false), 3000);
    } catch (err: any) {
      setDownloadError(err.message || 'Download forbidden: Insufficient authorization.');
    } finally {
      setDownloading(false);
    }
  };

  const getSecurityLevelColor = (level: string) => {
    switch (level) {
      case 'SECRET':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'CONFIDENTIAL':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'RESTRICTED':
        return 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30';
      default:
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-3xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden relative">
        {/* Header */}
        <div className="p-6 border-b border-slate-800 flex items-start justify-between bg-slate-950/60">
          <div className="flex-1 pr-4">
            <div className="flex items-center gap-2 mb-2">
              <span className={`text-[11px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border ${getSecurityLevelColor(doc.securityLevel)}`}>
                {doc.securityLevel}
              </span>
              <span className="text-xs bg-slate-800 text-slate-300 px-2 py-0.5 rounded-md font-medium">
                {doc.category}
              </span>
              <span className="text-xs text-slate-400 font-mono">
                ACL Epoch v{doc.permissionVersion}
              </span>
            </div>
            <h2 className="text-xl font-bold text-slate-100 leading-snug">{doc.title}</h2>
            <p className="text-xs text-slate-400 mt-1">{doc.description}</p>
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
          {/* Metadata Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-4 bg-slate-950/40 rounded-xl border border-slate-800/80 text-xs">
            <div>
              <span className="text-slate-500 block text-[10px] uppercase font-bold">Document Owner</span>
              <span className="text-slate-200 font-medium">{doc.ownerName}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase font-bold">Encrypted Size</span>
              <span className="text-slate-200 font-medium">{(doc.fileSize / 1024).toFixed(1)} KB</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase font-bold">Storage Cipher</span>
              <span className="text-indigo-400 font-mono font-medium">AES-256-GCM</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase font-bold">Your Permission</span>
              <span className="text-emerald-400 font-semibold">{doc.userAccessLevel || 'GRANTED'}</span>
            </div>
          </div>

          {/* Secure Document Preview Enclave with Forensic Dynamic Watermark */}
          <div className="relative border border-slate-800 rounded-xl bg-slate-950 p-5 overflow-hidden">
            {/* Dynamic Forensic Watermark overlay */}
            <div className="absolute inset-0 pointer-events-none select-none flex items-center justify-center rotate-[-15deg] opacity-[0.06] text-white text-base sm:text-lg font-mono font-bold leading-relaxed whitespace-pre-wrap text-center">
              {`CONFIDENTIAL // ${currentUser.email}\n${currentUser.id} // SECURE ENCLAVE\nTIMESTAMP: ${new Date().toISOString()}`}
            </div>

            <div className="flex items-center justify-between pb-3 border-b border-slate-800/60 mb-3 text-xs">
              <div className="flex items-center gap-2 text-slate-400">
                <FileText className="w-4 h-4 text-indigo-400" />
                <span className="font-mono text-slate-300">{doc.filename}</span>
              </div>
              <div className="flex items-center gap-1.5 text-emerald-400 text-[11px]">
                <Fingerprint className="w-3.5 h-3.5" />
                <span>Zero-Trust Decrypted Preview</span>
              </div>
            </div>

            <pre className="font-mono text-xs text-slate-300 whitespace-pre-wrap leading-relaxed max-h-64 overflow-y-auto p-2 bg-slate-900/50 rounded-lg border border-slate-800/40">
              {doc.previewContent || 'Secure document content decrypted on client request.'}
            </pre>
          </div>

          {/* Download Error Feedback */}
          {downloadError && (
            <div className="p-3 bg-rose-950/50 border border-rose-800/60 rounded-xl text-xs text-rose-300 flex items-start gap-2.5">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div>
                <strong className="block font-semibold">Server Security Authorization Block:</strong>
                <span>{downloadError}</span>
                <p className="mt-1 text-[11px] text-rose-400/80">
                  This attempt has been cryptographically recorded as <code>ACCESS_DENIED</code> in the SHA-256 audit ledger.
                </p>
              </div>
            </div>
          )}

          {downloadSuccess && (
            <div className="p-3 bg-emerald-950/50 border border-emerald-800/60 rounded-xl text-xs text-emerald-300 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>Decryption verified. File downloaded securely and audit entry signed.</span>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="p-4 sm:p-6 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between">
          <div>
            {canManage && (
              <button
                onClick={() => onOpenPermissions(doc)}
                className="flex items-center gap-2 text-xs font-medium text-indigo-400 hover:text-indigo-300 bg-indigo-950/40 hover:bg-indigo-900/40 border border-indigo-800/60 px-3 py-2 rounded-xl transition-all"
              >
                <Key className="w-3.5 h-3.5" />
                <span>Manage Access & ACL</span>
              </button>
            )}
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className="px-4 py-2 text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 rounded-xl transition-colors"
            >
              Close
            </button>

            <button
              onClick={handleDownload}
              disabled={downloading}
              className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-xl shadow-lg transition-all ${
                canDownload
                  ? 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-indigo-600/25'
                  : 'bg-slate-800 text-slate-400 hover:bg-slate-700/80'
              }`}
              title={canDownload ? 'Decrypt and download authorized file' : 'Click to test server 403 authorization defense'}
            >
              <Download className="w-3.5 h-3.5" />
              <span>{downloading ? 'Decrypting Stream...' : canDownload ? 'Secure Download' : 'Attempt Download (Test 403)'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
