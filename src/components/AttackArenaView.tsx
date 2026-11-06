import React, { useState } from 'react';
import { 
  Swords, 
  ShieldCheck, 
  ShieldAlert, 
  Play, 
  Terminal, 
  CheckCircle2, 
  AlertTriangle, 
  Clock, 
  ChevronDown, 
  ChevronUp, 
  RotateCcw,
  ExternalLink,
  Flame,
  Bug
} from 'lucide-react';
import type { SecurityTestResult, User } from '../types.js';
import { api } from '../services/api.js';
import { InteractiveAttackLab } from './InteractiveAttackLab.js';

interface AttackArenaViewProps {
  currentUser: User;
}

export const AttackArenaView: React.FC<AttackArenaViewProps> = ({ currentUser }) => {
  const [subTab, setSubTab] = useState<'automated' | 'interactive'>('automated');
  const [testing, setTesting] = useState(false);
  const [results, setResults] = useState<SecurityTestResult[]>([]);
  const [summary, setSummary] = useState<{ total: number; passed: number; failed: number; executedAt: string } | null>(null);
  const [expandedTestId, setExpandedTestId] = useState<string | null>(null);
  const [hasRun, setHasRun] = useState(false);

  const handleRunAllTests = async () => {
    setTesting(true);
    try {
      const res = await api.runSecurityTests();
      setResults(res.results);
      setSummary(res.summary);
      setHasRun(true);
      if (res.results.length > 0 && !expandedTestId) {
        setExpandedTestId(res.results[0].id);
      }
    } catch (err: any) {
      console.error('Failed to run attack tests:', err);
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner: Attack Arena & Judge Challenge Statement */}
      <div className="bg-gradient-to-r from-rose-950/40 via-slate-900 to-indigo-950/30 border border-rose-900/40 rounded-2xl p-6 shadow-xl relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2 max-w-2xl">
            <div className="flex items-center gap-2">
              <span className="p-2.5 bg-rose-500/10 border border-rose-500/30 rounded-xl text-rose-400">
                <Swords className="w-5 h-5" />
              </span>
              <div>
                <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                  <span>Adversarial Attack Simulation Arena</span>
                  <span className="text-xs bg-rose-950 text-rose-300 border border-rose-800 px-2 py-0.5 rounded-full font-mono font-normal">
                    THREATS.md Grounded
                  </span>
                </h2>
                <p className="text-xs text-slate-400">
                  Automated security test harness asserting server-authoritative defense on every pathway.
                  Tests will fail if any authorization check is removed or bypassed.
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleRunAllTests}
              disabled={testing}
              className="flex items-center gap-2 px-5 py-2.5 bg-rose-600 hover:bg-rose-500 text-white rounded-xl text-xs font-bold shadow-lg shadow-rose-950/50 transition-all hover:scale-102 disabled:opacity-50"
            >
              <Play className="w-4 h-4 fill-white" />
              <span>{testing ? 'Executing Attack Payloads...' : 'Run Full Attack Suite (11 Tests)'}</span>
            </button>
          </div>
        </div>

        {/* Navigation Sub-Tabs */}
        <div className="mt-6 pt-4 border-t border-slate-800/80 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setSubTab('automated')}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
                subTab === 'automated'
                  ? 'bg-rose-600 text-white shadow-md shadow-rose-950/60'
                  : 'bg-slate-950/60 text-slate-400 hover:text-slate-200 border border-slate-800/80'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Automated Threat Suite (11 Tests)</span>
            </button>

            <button
              type="button"
              onClick={() => setSubTab('interactive')}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
                subTab === 'interactive'
                  ? 'bg-rose-600 text-white shadow-md shadow-rose-950/60'
                  : 'bg-slate-950/60 text-slate-400 hover:text-slate-200 border border-slate-800/80'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Interactive Exploit Sandbox (Custom Payloads)</span>
              <span className="text-[10px] bg-rose-950 text-rose-300 border border-rose-800 px-1.5 py-0.2 rounded font-mono font-normal">
                Judge Lab
              </span>
            </button>
          </div>

          <span className="text-[11px] text-slate-500 hidden sm:inline font-mono">
            Zero-Trust Architectural Hardening
          </span>
        </div>

        {/* Results Summary Bar */}
        {summary && subTab === 'automated' && (
          <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-4 text-xs">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-1.5 text-emerald-400 font-bold">
                <CheckCircle2 className="w-4 h-4" />
                <span>{summary.passed} / {summary.total} Attacks Neutralized</span>
              </div>
              {summary.failed > 0 && (
                <div className="flex items-center gap-1.5 text-rose-400 font-bold animate-pulse">
                  <AlertTriangle className="w-4 h-4" />
                  <span>{summary.failed} Vulnerability Detected!</span>
                </div>
              )}
            </div>

            <div className="text-[11px] text-slate-400 font-mono">
              Executed at {new Date(summary.executedAt).toLocaleTimeString()}
            </div>
          </div>
        )}
      </div>

      {/* Render subTab content */}
      {subTab === 'interactive' ? (
        <InteractiveAttackLab currentUser={currentUser} />
      ) : (
        /* Test Execution List */
        <div className="space-y-3">
          {!hasRun ? (
            <div className="p-12 text-center bg-slate-900/30 border border-dashed border-slate-800 rounded-2xl space-y-3">
              <Swords className="w-10 h-10 text-rose-500/50 mx-auto" />
              <h3 className="text-sm font-semibold text-slate-200">Attack Arena Ready</h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                Click <strong>"Run Full Attack Suite"</strong> above to launch 11 real HTTP attack requests against the server: IDOR document fetching, instant revocation latency, raw blob probing, temporal expiry bypass, and audit tamper checks.
              </p>
            </div>
          ) : (
            results.map((test) => {
              const isExpanded = expandedTestId === test.id;

            return (
              <div
                key={test.id}
                className={`bg-slate-900/70 border rounded-2xl transition-all overflow-hidden ${
                  test.passed
                    ? 'border-slate-800/80 hover:border-slate-700/80'
                    : 'border-rose-500/80 bg-rose-950/20'
                }`}
              >
                {/* Test Header */}
                <div
                  onClick={() => setExpandedTestId(isExpanded ? null : test.id)}
                  className="p-4 flex items-center justify-between gap-4 cursor-pointer hover:bg-slate-850/50 transition-colors"
                >
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    <div
                      className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 border ${
                        test.passed
                          ? 'bg-emerald-950/50 border-emerald-800/60 text-emerald-400'
                          : 'bg-rose-950/50 border-rose-800/60 text-rose-400'
                      }`}
                    >
                      {test.passed ? <CheckCircle2 className="w-4 h-4" /> : <ShieldAlert className="w-4 h-4" />}
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-bold text-indigo-400 bg-indigo-950/60 border border-indigo-900/50 px-1.5 py-0.5 rounded">
                          {test.threatId}
                        </span>
                        <h4 className="text-xs font-bold text-slate-200 truncate">{test.name}</h4>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-0.5 truncate">{test.description}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1">
                      <Clock className="w-3 h-3 text-slate-500" />
                      {test.executionMs}ms
                    </span>

                    <span
                      className={`text-xs font-mono font-bold px-2 py-0.5 rounded-full border ${
                        test.passed
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                          : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                      }`}
                    >
                      HTTP {test.httpStatus}
                    </span>

                    <span
                      className={`text-xs font-bold px-2 py-0.5 rounded-lg ${
                        test.passed ? 'bg-emerald-600/20 text-emerald-300' : 'bg-rose-600/20 text-rose-300'
                      }`}
                    >
                      {test.passed ? 'PASSED' : 'FAILED'}
                    </span>

                    {isExpanded ? (
                      <ChevronUp className="w-4 h-4 text-slate-400" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-slate-400" />
                    )}
                  </div>
                </div>

                {/* Expanded Details: Terminal Logs & Evidence */}
                {isExpanded && (
                  <div className="p-4 pt-0 border-t border-slate-800/60 bg-slate-950/60 space-y-3">
                    <div className="p-3 bg-slate-950 rounded-xl border border-slate-800/80 font-mono text-xs text-slate-300 space-y-1">
                      <div className="text-[10px] uppercase font-bold text-slate-500 flex items-center gap-1 mb-1">
                        <Terminal className="w-3 h-3 text-indigo-400" />
                        <span>Execution Trace & Server Response:</span>
                      </div>
                      {test.logs.map((log, idx) => (
                        <div key={idx} className="text-slate-300 flex items-start gap-2">
                          <span className="text-slate-600 select-none">&gt;</span>
                          <span>{log}</span>
                        </div>
                      ))}
                    </div>

                    <div className="text-[11px] text-slate-400 flex items-center justify-between">
                      <span><strong>Forensic Verification:</strong> {test.evidence}</span>
                      <span className="font-mono text-indigo-400">Coverage: THREATS.md / {test.threatId}</span>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
      )}
    </div>
  );
};
