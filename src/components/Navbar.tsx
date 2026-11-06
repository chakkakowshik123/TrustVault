import React, { useState } from 'react';
import { 
  Shield, 
  Lock, 
  UserCheck, 
  FileText, 
  History, 
  Activity, 
  Swords, 
  BookOpen, 
  ChevronDown, 
  Copy, 
  Check, 
  KeyRound,
  AlertTriangle,
  Zap
} from 'lucide-react';
import type { User, Role } from '../types.js';
import { AuthRoleMatrixModal } from './AuthRoleMatrixModal.js';

interface NavbarProps {
  currentUser: User | null;
  allUsers: User[];
  activeTab: 'vault' | 'audit' | 'admin' | 'attack' | 'docs';
  onTabChange: (tab: 'vault' | 'audit' | 'admin' | 'attack' | 'docs') => void;
  onSwitchUser: (user: User) => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentUser,
  allUsers,
  activeTab,
  onTabChange,
  onSwitchUser
}) => {
  const [showUserDropdown, setShowUserDropdown] = useState(false);
  const [showCredsModal, setShowCredsModal] = useState(false);
  const [copiedEmail, setCopiedEmail] = useState<string | null>(null);

  const getRoleBadge = (role?: Role) => {
    switch (role) {
      case 'ADMIN':
        return <span className="bg-red-500/10 text-red-400 border border-red-500/30 text-xs px-2 py-0.5 rounded-full font-semibold">Security Admin</span>;
      case 'DOCUMENT_OWNER':
        return <span className="bg-blue-500/10 text-blue-400 border border-blue-500/30 text-xs px-2 py-0.5 rounded-full font-semibold">Document Owner</span>;
      case 'VIEWER':
        return <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-xs px-2 py-0.5 rounded-full font-semibold">Viewer (Internal)</span>;
      case 'EXTERNAL_PARTNER':
        return <span className="bg-amber-500/10 text-amber-400 border border-amber-500/30 text-xs px-2 py-0.5 rounded-full font-semibold">External Partner</span>;
      case 'ATTACKER':
        return <span className="bg-purple-500/10 text-purple-400 border border-purple-500/30 text-xs px-2 py-0.5 rounded-full font-semibold">Simulated Attacker</span>;
      default:
        return null;
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedEmail(text);
    setTimeout(() => setCopiedEmail(null), 2000);
  };

  return (
    <>
      <header className="sticky top-0 z-40 bg-slate-950/90 backdrop-blur-md border-b border-slate-800 text-slate-100">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Logo and Challenge Badge */}
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2.5 cursor-pointer" onClick={() => onTabChange('vault')}>
                <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 via-indigo-600 to-cyan-500 flex items-center justify-center shadow-lg shadow-indigo-500/20 border border-indigo-400/30">
                  <Shield className="w-5 h-5 text-white" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-lg tracking-tight bg-gradient-to-r from-white via-slate-100 to-slate-400 bg-clip-text text-transparent">
                      TrustVault
                    </span>
                    <span className="bg-indigo-950 text-indigo-300 border border-indigo-700/50 text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.5 rounded">
                      RISE 2026
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 hidden sm:block">
                    Zero-Leakage Document Sharing & Hash-Chained Audit
                  </p>
                </div>
              </div>

              {/* Snovasys Challenge Banner Indicator */}
              <div className="hidden lg:flex items-center gap-2 pl-4 border-l border-slate-800 text-xs text-slate-400">
                <span className="inline-block w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                <span>Snovasys Hiring Challenge: Nov 1–7, 2026</span>
              </div>
            </div>

            {/* Navigation Tabs */}
            <nav className="hidden md:flex items-center gap-1 bg-slate-900/80 p-1 rounded-xl border border-slate-800">
              <button
                onClick={() => onTabChange('vault')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  activeTab === 'vault'
                    ? 'bg-indigo-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Documents</span>
              </button>

              <button
                onClick={() => onTabChange('audit')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  activeTab === 'audit'
                    ? 'bg-indigo-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <History className="w-3.5 h-3.5" />
                <span>Audit Ledger (SHA-256)</span>
              </button>

              <button
                onClick={() => onTabChange('admin')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  activeTab === 'admin'
                    ? 'bg-indigo-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <Activity className="w-3.5 h-3.5" />
                <span>Security Dashboard</span>
              </button>

              <button
                onClick={() => onTabChange('attack')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  activeTab === 'attack'
                    ? 'bg-rose-600 text-white shadow-sm shadow-rose-900/30'
                    : 'text-rose-400 hover:text-rose-300 hover:bg-rose-950/40'
                }`}
              >
                <Swords className="w-3.5 h-3.5" />
                <span>Attack Arena (11)</span>
              </button>

              <button
                onClick={() => onTabChange('docs')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  activeTab === 'docs'
                    ? 'bg-indigo-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <BookOpen className="w-3.5 h-3.5" />
                <span>SQL Studio & Docs (PROMPTS.md)</span>
              </button>
            </nav>

            {/* Persona Switcher & Credentials */}
            <div className="flex items-center gap-3">
              <button
                onClick={() => setShowCredsModal(true)}
                className="hidden sm:flex items-center gap-1.5 text-xs text-indigo-300 hover:text-white bg-indigo-900/40 hover:bg-indigo-800/50 border border-indigo-700/60 px-3 py-1.5 rounded-lg transition-all font-semibold shadow-sm"
                title="View Authentication & Role Authorization Matrix (Snovasys Mandate)"
              >
                <Shield className="w-3.5 h-3.5 text-indigo-400" />
                <span>Auth & Role Matrix</span>
              </button>

              {/* Persona Selector Dropdown */}
              <div className="relative">
                <button
                  onClick={() => setShowUserDropdown(!showUserDropdown)}
                  className="flex items-center gap-2.5 p-1.5 pr-3 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition-all text-left"
                >
                  <img
                    src={currentUser?.avatar || 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=80&auto=format&fit=crop&q=80'}
                    alt={currentUser?.name}
                    className="w-8 h-8 rounded-lg object-cover border border-slate-700"
                  />
                  <div className="hidden sm:block">
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs font-medium text-slate-200 leading-tight">
                        {currentUser?.name.split(' ')[0]}
                      </span>
                      {getRoleBadge(currentUser?.role)}
                    </div>
                    <span className="text-[10px] text-slate-400 block leading-tight">
                      {currentUser?.department}
                    </span>
                  </div>
                  <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
                </button>

                {showUserDropdown && (
                  <div className="absolute right-0 mt-2 w-80 bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl py-2 z-50">
                    <div className="px-3 py-2 border-b border-slate-800">
                      <p className="text-xs font-semibold text-slate-200">Switch Persona (Live RBAC Testing)</p>
                      <p className="text-[11px] text-slate-400">
                        Test how permissions, downloads, and 403 blocks behave across roles.
                      </p>
                    </div>

                    <div className="py-1 max-h-96 overflow-y-auto">
                      {allUsers.map((user) => {
                        const isSelected = user.id === currentUser?.id;
                        return (
                          <button
                            key={user.id}
                            onClick={() => {
                              onSwitchUser(user);
                              setShowUserDropdown(false);
                            }}
                            className={`w-full px-3 py-2 text-left flex items-center gap-3 transition-colors ${
                              isSelected ? 'bg-indigo-950/60 border-l-2 border-indigo-500' : 'hover:bg-slate-800/50'
                            }`}
                          >
                            <img
                              src={user.avatar}
                              alt={user.name}
                              className="w-8 h-8 rounded-lg object-cover border border-slate-700 shrink-0"
                            />
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center justify-between">
                                <p className="text-xs font-medium text-slate-200 truncate">{user.name}</p>
                                {isSelected && <Check className="w-3.5 h-3.5 text-indigo-400 shrink-0" />}
                              </div>
                              <p className="text-[11px] text-slate-400 truncate">{user.email}</p>
                              <div className="mt-1">{getRoleBadge(user.role)}</div>
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Mobile Navigation Row */}
        <div className="md:hidden flex items-center justify-around border-t border-slate-800/80 px-2 py-2 bg-slate-950/95 overflow-x-auto">
          <button
            onClick={() => onTabChange('vault')}
            className={`flex flex-col items-center gap-1 text-[10px] px-2 py-1 rounded ${
              activeTab === 'vault' ? 'text-indigo-400 font-bold' : 'text-slate-400'
            }`}
          >
            <FileText className="w-4 h-4" />
            <span>Vault</span>
          </button>
          <button
            onClick={() => onTabChange('audit')}
            className={`flex flex-col items-center gap-1 text-[10px] px-2 py-1 rounded ${
              activeTab === 'audit' ? 'text-indigo-400 font-bold' : 'text-slate-400'
            }`}
          >
            <History className="w-4 h-4" />
            <span>Audit</span>
          </button>
          <button
            onClick={() => onTabChange('admin')}
            className={`flex flex-col items-center gap-1 text-[10px] px-2 py-1 rounded ${
              activeTab === 'admin' ? 'text-indigo-400 font-bold' : 'text-slate-400'
            }`}
          >
            <Activity className="w-4 h-4" />
            <span>Security</span>
          </button>
          <button
            onClick={() => onTabChange('attack')}
            className={`flex flex-col items-center gap-1 text-[10px] px-2 py-1 rounded ${
              activeTab === 'attack' ? 'text-rose-400 font-bold' : 'text-slate-400'
            }`}
          >
            <Swords className="w-4 h-4" />
            <span>Attacks</span>
          </button>
          <button
            onClick={() => onTabChange('docs')}
            className={`flex flex-col items-center gap-1 text-[10px] px-2 py-1 rounded ${
              activeTab === 'docs' ? 'text-indigo-400 font-bold' : 'text-slate-400'
            }`}
          >
            <BookOpen className="w-4 h-4" />
            <span>Docs</span>
          </button>
        </div>
      </header>

      {/* Authentication & Role Authorization Matrix Modal */}
      {showCredsModal && (
        <AuthRoleMatrixModal
          currentUser={currentUser}
          allUsers={allUsers}
          onSelectUser={(u) => {
            onSwitchUser(u);
            setShowCredsModal(false);
          }}
          onClose={() => setShowCredsModal(false)}
        />
      )}
    </>
  );
};
