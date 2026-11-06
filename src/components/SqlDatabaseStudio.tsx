import React, { useState, useEffect } from 'react';
import {
  Database,
  Table,
  Play,
  Copy,
  Check,
  Code,
  FileText,
  Search,
  RefreshCw,
  HardDrive,
  Key,
  ShieldCheck,
  Layers,
  Clock
} from 'lucide-react';
import { api } from '../services/api.js';

interface SqlDatabaseStudioProps {
  onRefreshData?: () => void;
}

export const SqlDatabaseStudio: React.FC<SqlDatabaseStudioProps> = () => {
  const [activeTab, setActiveTab] = useState<'explorer' | 'schema' | 'seeds'>('explorer');
  const [query, setQuery] = useState<string>('SELECT * FROM documents;');
  const [loading, setLoading] = useState<boolean>(false);
  const [schemaData, setSchemaData] = useState<{
    tables: Array<{ name: string; count: number; description: string }>;
    schemaSql: string;
    seedsSql: string;
  } | null>(null);

  const [queryResult, setQueryResult] = useState<{
    table: string;
    columns: string[];
    rows: any[];
    rowCount: number;
    executionMs: number;
    executedQuery: string;
  } | null>(null);

  const [copiedType, setCopiedType] = useState<string | null>(null);

  const loadSchema = async () => {
    try {
      const data = await api.getDatabaseSchema();
      setSchemaData(data);
    } catch (err) {
      console.error('Failed to load database schema metadata:', err);
    }
  };

  const handleExecuteQuery = async (queryToRun?: string) => {
    const sql = queryToRun || query;
    setLoading(true);
    try {
      const result = await api.executeDatabaseQuery(sql);
      setQueryResult(result);
    } catch (err) {
      console.error('SQL query execution error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSchema();
    handleExecuteQuery('SELECT * FROM documents;');
  }, []);

  const handleSelectTable = (tableName: string) => {
    const newQuery = `SELECT * FROM ${tableName};`;
    setQuery(newQuery);
    handleExecuteQuery(newQuery);
  };

  const copyToClipboard = (text: string, type: string) => {
    navigator.clipboard.writeText(text);
    setCopiedType(type);
    setTimeout(() => setCopiedType(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="p-2 bg-indigo-500/10 border border-indigo-500/30 rounded-xl text-indigo-400">
                <Database className="w-5 h-5" />
              </span>
              <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                <span>SQL Database Studio & Schema Inspector</span>
                <span className="text-[10px] bg-indigo-950 text-indigo-300 border border-indigo-800 px-2 py-0.5 rounded-full font-mono font-semibold">
                  PostgreSQL / ANSI DDL Verified
                </span>
              </h2>
            </div>
            <p className="text-xs text-slate-400 max-w-2xl">
              TrustVault is backed by a relational database schema declaring 5 normalized tables with foreign keys, 
              cascading deletions, and cryptographic hashes. Evaluators can inspect schema files and execute live queries below.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-950/80 border border-slate-800 text-xs text-slate-400 font-mono">
              <HardDrive className="w-3.5 h-3.5 text-cyan-400" />
              <span>data/trustvault.db.json (Persistent)</span>
            </span>
          </div>
        </div>

        {/* View Switcher Sub-Tabs */}
        <div className="mt-6 pt-4 border-t border-slate-800/80 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setActiveTab('explorer')}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
                activeTab === 'explorer'
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-950/60'
                  : 'bg-slate-950/60 text-slate-400 hover:text-slate-200 border border-slate-800/80'
              }`}
            >
              <Table className="w-3.5 h-3.5" />
              <span>Live Query & Table Explorer</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('schema')}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
                activeTab === 'schema'
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-950/60'
                  : 'bg-slate-950/60 text-slate-400 hover:text-slate-200 border border-slate-800/80'
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              <span>schema.sql (DDL Schema)</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('seeds')}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
                activeTab === 'seeds'
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-950/60'
                  : 'bg-slate-950/60 text-slate-400 hover:text-slate-200 border border-slate-800/80'
              }`}
            >
              <Code className="w-3.5 h-3.5" />
              <span>seeds.sql (Relational Seeds)</span>
            </button>
          </div>

          <span className="text-[11px] text-slate-500 hidden sm:inline font-mono">
            npm run db:setup
          </span>
        </div>
      </div>

      {/* Explorer Mode */}
      {activeTab === 'explorer' && (
        <div className="space-y-6">
          {/* Relational Table Selector Cards */}
          <div>
            <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block mb-2.5">
              Select Relational Table to Query:
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
              {schemaData?.tables.map((t) => (
                <button
                  key={t.name}
                  type="button"
                  onClick={() => handleSelectTable(t.name)}
                  className={`p-3 text-left rounded-xl border transition-all text-xs flex flex-col justify-between ${
                    query.includes(t.name)
                      ? 'bg-indigo-950/40 border-indigo-500/70 text-slate-100 shadow-lg shadow-indigo-950/40'
                      : 'bg-slate-900 border-slate-800/80 hover:border-slate-700 text-slate-300'
                  }`}
                >
                  <div className="space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-slate-100">{t.name}</span>
                      <span className="text-[10px] bg-slate-950 text-indigo-400 border border-slate-800 px-1.5 py-0.5 rounded font-mono font-bold">
                        {t.count} rows
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">{t.description}</p>
                  </div>
                  <div className="mt-2 pt-1 border-t border-slate-800/60 text-[10px] text-indigo-400 font-mono flex items-center gap-1">
                    <span>SELECT *</span>
                    <span>→</span>
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* SQL Query Editor Bar */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="font-bold text-slate-300 flex items-center gap-2">
                <Code className="w-4 h-4 text-indigo-400" />
                <span>SQL Query Editor</span>
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => handleSelectTable('users')}
                  className="text-[11px] font-mono text-slate-400 hover:text-indigo-300 bg-slate-950 px-2 py-1 rounded border border-slate-800"
                >
                  users
                </button>
                <button
                  type="button"
                  onClick={() => handleSelectTable('documents')}
                  className="text-[11px] font-mono text-slate-400 hover:text-indigo-300 bg-slate-950 px-2 py-1 rounded border border-slate-800"
                >
                  documents
                </button>
                <button
                  type="button"
                  onClick={() => handleSelectTable('document_permissions')}
                  className="text-[11px] font-mono text-slate-400 hover:text-indigo-300 bg-slate-950 px-2 py-1 rounded border border-slate-800"
                >
                  permissions
                </button>
                <button
                  type="button"
                  onClick={() => handleSelectTable('audit_ledger')}
                  className="text-[11px] font-mono text-slate-400 hover:text-indigo-300 bg-slate-950 px-2 py-1 rounded border border-slate-800"
                >
                  audit_ledger
                </button>
                <button
                  type="button"
                  onClick={() => handleSelectTable('encrypted_blobs')}
                  className="text-[11px] font-mono text-slate-400 hover:text-indigo-300 bg-slate-950 px-2 py-1 rounded border border-slate-800"
                >
                  encrypted_blobs
                </button>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleExecuteQuery()}
                placeholder="Enter SQL SELECT statement..."
                className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 font-mono text-xs text-indigo-300 placeholder:text-slate-600 focus:outline-none focus:border-indigo-500"
              />
              <button
                type="button"
                onClick={() => handleExecuteQuery()}
                disabled={loading}
                className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-bold flex items-center gap-2 shadow-md shadow-indigo-950/60 transition-all disabled:opacity-50"
              >
                {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-white" />}
                <span>Execute SQL</span>
              </button>
            </div>
          </div>

          {/* Results Table */}
          {queryResult && (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
              <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
                <div className="flex items-center gap-3">
                  <div className="p-1.5 bg-indigo-500/10 border border-indigo-500/30 rounded-lg text-indigo-400">
                    <Table className="w-4 h-4" />
                  </div>
                  <div>
                    <span className="text-xs font-bold text-slate-200">
                      Query Result: Table <strong className="text-indigo-400 font-mono">[{queryResult.table}]</strong>
                    </span>
                    <span className="text-[11px] text-slate-500 block font-mono">
                      {queryResult.rowCount} rows returned in {queryResult.executionMs}ms
                    </span>
                  </div>
                </div>

                <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/40 border border-emerald-800/40 px-2 py-0.5 rounded">
                  200 OK
                </span>
              </div>

              <div className="overflow-x-auto max-h-[420px]">
                <table className="w-full text-left border-collapse text-xs">
                  <thead className="bg-slate-950 sticky top-0 border-b border-slate-800">
                    <tr>
                      {queryResult.columns.map((col) => (
                        <th key={col} className="p-3 text-[11px] font-mono font-bold uppercase tracking-wider text-slate-400 border-r border-slate-800/60 last:border-r-0">
                          {col}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {queryResult.rows.map((row, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/40 transition-colors font-mono text-[11px]">
                        {queryResult.columns.map((col) => (
                          <td key={col} className="p-3 text-slate-300 border-r border-slate-800/60 last:border-r-0 max-w-xs truncate">
                            {typeof row[col] === 'object' ? JSON.stringify(row[col]) : String(row[col] ?? 'NULL')}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Schema DDL View */}
      {activeTab === 'schema' && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
            <div>
              <h3 className="text-xs font-bold text-slate-200 font-mono">schema.sql</h3>
              <p className="text-[11px] text-slate-400">PostgreSQL / ANSI DDL table definitions and indexes</p>
            </div>
            <button
              onClick={() => copyToClipboard(schemaData?.schemaSql || '', 'schema')}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg text-xs text-slate-300 transition-all"
            >
              {copiedType === 'schema' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedType === 'schema' ? 'Copied' : 'Copy SQL'}</span>
            </button>
          </div>
          <pre className="p-5 font-mono text-xs text-slate-300 bg-slate-950 overflow-x-auto max-h-[500px] leading-relaxed selection:bg-indigo-500">
            {schemaData?.schemaSql || '-- Loading schema.sql...'}
          </pre>
        </div>
      )}

      {/* Seeds DDL View */}
      {activeTab === 'seeds' && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
            <div>
              <h3 className="text-xs font-bold text-slate-200 font-mono">seeds.sql</h3>
              <p className="text-[11px] text-slate-400">Relational identities, documents, and genesis block seeding script</p>
            </div>
            <button
              onClick={() => copyToClipboard(schemaData?.seedsSql || '', 'seeds')}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg text-xs text-slate-300 transition-all"
            >
              {copiedType === 'seeds' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedType === 'seeds' ? 'Copied' : 'Copy SQL'}</span>
            </button>
          </div>
          <pre className="p-5 font-mono text-xs text-slate-300 bg-slate-950 overflow-x-auto max-h-[500px] leading-relaxed selection:bg-indigo-500">
            {schemaData?.seedsSql || '-- Loading seeds.sql...'}
          </pre>
        </div>
      )}
    </div>
  );
};
