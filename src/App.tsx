/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar.js';
import { VaultView } from './components/VaultView.js';
import { AuditLedgerView } from './components/AuditLedgerView.js';
import { AttackArenaView } from './components/AttackArenaView.js';
import { AdminSecurityDashboard } from './components/AdminSecurityDashboard.js';
import { DocumentationHub } from './components/DocumentationHub.js';
import { DocumentPreviewModal } from './components/DocumentPreviewModal.js';
import { PermissionManagerModal } from './components/PermissionManagerModal.js';
import { UploadModal } from './components/UploadModal.js';

import type { User, Document as VaultDoc } from './types.js';
import { api, setAuthSession, getActiveSession } from './services/api.js';

export default function App() {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [allUsers, setAllUsers] = useState<User[]>([]);
  const [documents, setDocuments] = useState<VaultDoc[]>([]);
  const [activeTab, setActiveTab] = useState<'vault' | 'audit' | 'admin' | 'attack' | 'docs'>('vault');
  const [loading, setLoading] = useState(true);

  // Modals state
  const [previewDoc, setPreviewDoc] = useState<VaultDoc | null>(null);
  const [permissionDoc, setPermissionDoc] = useState<VaultDoc | null>(null);
  const [isUploadOpen, setIsUploadOpen] = useState(false);

  // Initial data load
  const loadInitialData = async () => {
    setLoading(true);
    try {
      // 1. Load users
      const users = await api.getUsers();
      setAllUsers(users);

      // 2. Resolve current user
      const { userId } = getActiveSession();
      const current = users.find(u => u.id === userId) || users[0];
      setCurrentUser(current);
      setAuthSession(`token_${current.id}`, current.id);

      // 3. Load documents accessible to this user
      const docs = await api.getDocuments();
      setDocuments(docs);
    } catch (err) {
      console.error('Initialization error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadInitialData();
  }, []);

  const handleSwitchUser = async (user: User) => {
    setAuthSession(`token_${user.id}`, user.id);
    setCurrentUser(user);
    setLoading(true);
    try {
      const docs = await api.getDocuments();
      setDocuments(docs);
      // Close any active modal
      setPreviewDoc(null);
      setPermissionDoc(null);
    } catch (err) {
      console.error('Failed to reload documents for user:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleRefreshVault = async () => {
    try {
      const docs = await api.getDocuments();
      setDocuments(docs);
      if (previewDoc) {
        const updatedPreview = docs.find(d => d.id === previewDoc.id);
        if (updatedPreview) setPreviewDoc(updatedPreview);
      }
      if (permissionDoc) {
        const updatedPermDoc = docs.find(d => d.id === permissionDoc.id);
        if (updatedPermDoc) setPermissionDoc(updatedPermDoc);
      }
    } catch (err) {
      console.error('Failed to refresh documents:', err);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-indigo-500 selection:text-white">
      {/* Top Navigation */}
      <Navbar
        currentUser={currentUser}
        allUsers={allUsers}
        activeTab={activeTab}
        onTabChange={setActiveTab}
        onSwitchUser={handleSwitchUser}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {loading && !currentUser ? (
          <div className="min-h-[50vh] flex flex-col items-center justify-center space-y-3">
            <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
            <p className="text-xs text-slate-400">Loading TrustVault Secure Enclave...</p>
          </div>
        ) : (
          <>
            {activeTab === 'vault' && currentUser && (
              <VaultView
                documents={documents}
                currentUser={currentUser}
                onOpenPreview={(doc) => setPreviewDoc(doc)}
                onOpenPermissions={(doc) => setPermissionDoc(doc)}
                onOpenUpload={() => setIsUploadOpen(true)}
                onRefresh={handleRefreshVault}
              />
            )}

            {activeTab === 'audit' && currentUser && (
              <AuditLedgerView currentUser={currentUser} />
            )}

            {activeTab === 'admin' && currentUser && (
              <AdminSecurityDashboard
                documents={documents}
                currentUser={currentUser}
                allUsers={allUsers}
                onNavigateToAudit={() => setActiveTab('audit')}
                onNavigateToAttacks={() => setActiveTab('attack')}
              />
            )}

            {activeTab === 'attack' && currentUser && (
              <AttackArenaView currentUser={currentUser} />
            )}

            {activeTab === 'docs' && (
              <DocumentationHub />
            )}
          </>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>TrustVault — Snovasys Fresher Hiring Challenge 2026 (RISE)</span>
          <span className="font-mono text-[11px] text-slate-600">
            SHA-256 Merkle Chain • AES-256-GCM Envelope Encryption • Zero-Trust ACL
          </span>
        </div>
      </footer>

      {/* Modals */}
      {previewDoc && currentUser && (
        <DocumentPreviewModal
          document={previewDoc}
          currentUser={currentUser}
          onClose={() => setPreviewDoc(null)}
          onOpenPermissions={(doc) => {
            setPreviewDoc(null);
            setPermissionDoc(doc);
          }}
        />
      )}

      {permissionDoc && currentUser && (
        <PermissionManagerModal
          document={permissionDoc}
          currentUser={currentUser}
          allUsers={allUsers}
          onClose={() => setPermissionDoc(null)}
          onPermissionsUpdated={handleRefreshVault}
        />
      )}

      {isUploadOpen && currentUser && (
        <UploadModal
          currentUser={currentUser}
          onClose={() => setIsUploadOpen(false)}
          onSuccess={handleRefreshVault}
        />
      )}
    </div>
  );
}
