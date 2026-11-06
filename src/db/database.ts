import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import type { User, Document as VaultDoc, PermissionGrant, AuditBlock } from '../types.js';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'trustvault.db.json');

export interface DatabaseState {
  users: User[];
  documents: VaultDoc[];
  encryptedBlobs: Record<string, { ciphertext: string; iv: string; authTag: string }>;
  auditLedger: AuditBlock[];
  version: string;
  lastInitialized: string;
}

export class VaultDatabase {
  private state: DatabaseState;

  constructor() {
    this.ensureDataDirectory();
    this.state = this.loadFromDisk();
  }

  private ensureDataDirectory() {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
  }

  private loadFromDisk(): DatabaseState {
    if (fs.existsSync(DB_FILE)) {
      try {
        const raw = fs.readFileSync(DB_FILE, 'utf8');
        return JSON.parse(raw);
      } catch (err) {
        console.error('[Database] Failed to read database file, initializing fresh state:', err);
      }
    }
    return this.createDefaultState();
  }

  public saveToDisk() {
    try {
      this.ensureDataDirectory();
      fs.writeFileSync(DB_FILE, JSON.stringify(this.state, null, 2), 'utf8');
    } catch (err) {
      console.error('[Database] Error persisting database state to disk:', err);
    }
  }

  public resetToSeeds() {
    this.state = this.createDefaultState();
    this.saveToDisk();
  }

  private createDefaultState(): DatabaseState {
    const users: User[] = [
      {
        id: 'usr_admin',
        name: 'Sarah Connor (Security Admin)',
        email: 'admin@trustvault.internal',
        role: 'ADMIN',
        department: 'Information Security & Compliance',
        avatar: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=120&auto=format&fit=crop&q=80',
        password: 'AdminSecure#2026'
      },
      {
        id: 'usr_owner_alice',
        name: 'Alice Morgan (Document Owner)',
        email: 'alice.owner@trustvault.internal',
        role: 'DOCUMENT_OWNER',
        department: 'Legal & Executive Contracts',
        avatar: 'https://images.unsplash.com/photo-1580489944761-15a19d654956?w=120&auto=format&fit=crop&q=80',
        password: 'AliceVault#2026'
      },
      {
        id: 'usr_owner_bob',
        name: 'Bob Henderson (Document Owner)',
        email: 'bob.owner@trustvault.internal',
        role: 'DOCUMENT_OWNER',
        department: 'Finance & Executive Compensation',
        avatar: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=120&auto=format&fit=crop&q=80',
        password: 'BobVault#2026'
      },
      {
        id: 'usr_viewer_carol',
        name: 'Carol Davies (Internal Viewer)',
        email: 'carol.viewer@trustvault.internal',
        role: 'VIEWER',
        department: 'Operations & Procurement',
        avatar: 'https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=120&auto=format&fit=crop&q=80',
        password: 'CarolView#2026'
      },
      {
        id: 'usr_external_dave',
        name: 'Dave Wilson (External Auditor)',
        email: 'dave.external@partner.org',
        role: 'EXTERNAL_PARTNER',
        department: 'KPMG External Assurance',
        avatar: 'https://images.unsplash.com/photo-1500648767791-00dcc994a43e?w=120&auto=format&fit=crop&q=80',
        password: 'DavePartner#2026'
      },
      {
        id: 'usr_attacker_mallory',
        name: 'Mallory Vance (Simulated Attacker)',
        email: 'mallory.attacker@hostile.com',
        role: 'ATTACKER',
        department: 'Threat Vector Simulation',
        avatar: 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=120&auto=format&fit=crop&q=80',
        password: 'MalloryPwn#2026'
      }
    ];

    return {
      users,
      documents: [],
      encryptedBlobs: {},
      auditLedger: [],
      version: '1.0.0',
      lastInitialized: new Date().toISOString()
    };
  }

  // User queries
  public getUsers(): User[] {
    return this.state.users;
  }

  public getUserById(id: string): User | undefined {
    return this.state.users.find(u => u.id === id);
  }

  public getUserByEmail(email: string): User | undefined {
    return this.state.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  }

  // Document queries
  public getDocuments(): VaultDoc[] {
    return this.state.documents;
  }

  public getDocumentById(id: string): VaultDoc | undefined {
    return this.state.documents.find(d => d.id === id);
  }

  public insertDocument(doc: VaultDoc) {
    this.state.documents.unshift(doc);
    this.saveToDisk();
  }

  public updateDocument(id: string, updates: Partial<VaultDoc>) {
    const idx = this.state.documents.findIndex(d => d.id === id);
    if (idx >= 0) {
      this.state.documents[idx] = { ...this.state.documents[idx], ...updates };
      this.saveToDisk();
    }
  }

  public deleteDocument(id: string) {
    const idx = this.state.documents.findIndex(d => d.id === id);
    if (idx >= 0) {
      const doc = this.state.documents[idx];
      delete this.state.encryptedBlobs[doc.encryptedBlobKey];
      this.state.documents.splice(idx, 1);
      this.saveToDisk();
    }
  }

  // Blob storage
  public getBlob(key: string): { ciphertext: string; iv: string; authTag: string } | undefined {
    return this.state.encryptedBlobs[key];
  }

  public storeBlob(key: string, blob: { ciphertext: string; iv: string; authTag: string }) {
    this.state.encryptedBlobs[key] = blob;
    this.saveToDisk();
  }

  // Audit Ledger
  public getAuditLedger(): AuditBlock[] {
    return this.state.auditLedger;
  }

  public appendAuditBlock(block: AuditBlock) {
    this.state.auditLedger.push(block);
    this.saveToDisk();
  }

  public setAuditLedger(ledger: AuditBlock[]) {
    this.state.auditLedger = ledger;
    this.saveToDisk();
  }

  public getState(): DatabaseState {
    return this.state;
  }
}

export const db = new VaultDatabase();
