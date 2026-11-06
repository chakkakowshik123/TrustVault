import React, { useState } from 'react';
import { 
  Upload, 
  ShieldAlert, 
  CheckCircle, 
  FileText, 
  Lock, 
  AlertTriangle,
  FileCode,
  Tag
} from 'lucide-react';
import type { Category, SecurityLevel, User } from '../types.js';
import { api } from '../services/api.js';

interface UploadModalProps {
  currentUser: User;
  onClose: () => void;
  onSuccess: () => void;
}

export const UploadModal: React.FC<UploadModalProps> = ({
  currentUser,
  onClose,
  onSuccess
}) => {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [category, setCategory] = useState<Category>('FINANCE');
  const [securityLevel, setSecurityLevel] = useState<SecurityLevel>('CONFIDENTIAL');
  const [tags, setTags] = useState('internal, audit, 2026');
  const [filename, setFilename] = useState('');
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Security validation checks (client feedback prior to server authoritative check)
  const isDangerousExtension = (name: string) => {
    const prohibited = ['.exe', '.sh', '.bat', '.cmd', '.js', '.php', '.vbs', '.dll', '.wasm', '.scr'];
    return prohibited.some(ext => name.toLowerCase().endsWith(ext));
  };

  const hasPathTraversal = (name: string) => {
    return name.includes('..') || name.includes('/') || name.includes('\\');
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setFilename(file.name);
    if (!title) {
      setTitle(file.name.replace(/\.[^/.]+$/, '').replace(/[-_]/g, ' '));
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      setContent(text || `Binary/Document File: ${file.name} (${file.size} bytes)`);
    };
    reader.readAsText(file);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title || !filename || !content) {
      setError('Please provide title, filename, and document content.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await api.uploadDocument({
        title,
        description,
        category,
        securityLevel,
        tags: tags.split(',').map(t => t.trim()).filter(Boolean),
        filename,
        content,
        mimeType: filename.endsWith('.pdf') ? 'application/pdf' : 'text/plain'
      });
      onSuccess();
      onClose();
    } catch (err: any) {
      setError(err.message || 'Upload failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full max-h-[92vh] flex flex-col shadow-2xl overflow-hidden relative">
        <div className="p-6 border-b border-slate-800 flex items-start justify-between bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-indigo-500/10 border border-indigo-500/30 rounded-xl">
              <Upload className="w-5 h-5 text-indigo-400" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-100">Upload to Secure Enclave</h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Client-side validation + Server-side AES-256-GCM Envelope Encryption
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

        <form onSubmit={handleSubmit} className="p-6 overflow-y-auto space-y-4 flex-1 text-xs">
          {error && (
            <div className="p-3.5 bg-rose-950/40 border border-rose-800/60 rounded-xl text-rose-300 flex items-start gap-2.5">
              <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div>
                <strong className="block font-semibold">Validation Rejected:</strong>
                <span>{error}</span>
              </div>
            </div>
          )}

          {/* Title and Category */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-[11px] font-semibold text-slate-400 mb-1">Document Title *</label>
              <input
                type="text"
                required
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="e.g. Q4 Financial Audit Report"
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div>
              <label className="block text-[11px] font-semibold text-slate-400 mb-1">Category *</label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value as Category)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-indigo-500"
              >
                <option value="FINANCE">Finance & Compensation</option>
                <option value="LEGAL">Legal & Contracts</option>
                <option value="ENGINEERING">Engineering & Architecture</option>
                <option value="HR">HR & Personnel</option>
                <option value="COMPLIANCE">Regulatory & Compliance</option>
                <option value="EXECUTIVE">Executive Board</option>
              </select>
            </div>
          </div>

          {/* Security Level and Tags */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-[11px] font-semibold text-slate-400 mb-1">Security Classification *</label>
              <select
                value={securityLevel}
                onChange={(e) => setSecurityLevel(e.target.value as SecurityLevel)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-indigo-500"
              >
                <option value="INTERNAL">INTERNAL (Standard organizational access)</option>
                <option value="RESTRICTED">RESTRICTED (Department-level access)</option>
                <option value="CONFIDENTIAL">CONFIDENTIAL (Named grants required)</option>
                <option value="SECRET">SECRET (Strict zero-trust, executive only)</option>
              </select>
            </div>

            <div>
              <label className="block text-[11px] font-semibold text-slate-400 mb-1">Tags (comma separated)</label>
              <input
                type="text"
                value={tags}
                onChange={(e) => setTags(e.target.value)}
                placeholder="e.g. audit, executive, 2026"
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-indigo-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-[11px] font-semibold text-slate-400 mb-1">Description</label>
            <textarea
              rows={2}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Provide context regarding purpose, retention period, or compliance scope..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-indigo-500"
            />
          </div>

          {/* File Picker & Name with Security Warnings */}
          <div className="p-4 bg-slate-950/60 border border-slate-800 rounded-xl space-y-3">
            <div className="flex items-center justify-between">
              <label className="block text-[11px] font-semibold text-slate-300">File Attachment</label>
              <span className="text-[10px] text-slate-500">Max size: 15MB. Prohibited: .exe, .sh, .bat</span>
            </div>

            <div className="flex items-center gap-3">
              <label className="cursor-pointer px-3 py-2 bg-indigo-950/60 hover:bg-indigo-900/60 border border-indigo-800/60 text-indigo-300 rounded-lg font-medium transition-colors">
                <span>Select File</span>
                <input type="file" onChange={handleFileUpload} className="hidden" />
              </label>

              <div className="flex-1">
                <input
                  type="text"
                  required
                  value={filename}
                  onChange={(e) => setFilename(e.target.value)}
                  placeholder="filename.pdf"
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 font-mono focus:outline-none focus:border-indigo-500"
                />
              </div>
            </div>

            {/* Live Security Lint on Filename */}
            {filename && (
              <div className="space-y-1">
                {isDangerousExtension(filename) && (
                  <div className="text-[11px] text-rose-400 flex items-center gap-1.5 bg-rose-950/30 p-2 rounded-lg border border-rose-900/40">
                    <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
                    <span>Malicious Extension Warning: Executable files are blocked by the server security filter.</span>
                  </div>
                )}
                {hasPathTraversal(filename) && (
                  <div className="text-[11px] text-amber-400 flex items-center gap-1.5 bg-amber-950/30 p-2 rounded-lg border border-amber-900/40">
                    <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                    <span>Path Traversal Detected: The server will automatically sanitize all path separators.</span>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Document Content / Enclave Payload */}
          <div>
            <label className="block text-[11px] font-semibold text-slate-400 mb-1">
              Document Content (Plaintext before AES-256-GCM encryption) *
            </label>
            <textarea
              required
              rows={4}
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="Paste or write confidential document body..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 font-mono focus:outline-none focus:border-indigo-500"
            />
          </div>

          <div className="p-3 bg-indigo-950/30 border border-indigo-800/40 rounded-xl flex items-center gap-2.5 text-indigo-300 text-[11px]">
            <Lock className="w-4 h-4 text-indigo-400 shrink-0" />
            <span>
              This file will be encrypted on the server using AES-256-GCM before writing to storage. An immutable UPLOAD entry will be signed into the SHA-256 hash ledger.
            </span>
          </div>

          <div className="pt-2 flex items-center justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-slate-400 hover:text-slate-200 rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading || !title || !filename || !content}
              className="px-5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-semibold shadow-md shadow-indigo-600/30 transition-all disabled:opacity-50"
            >
              {loading ? 'Encrypting & Storing...' : 'Upload & Encrypt Document'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
