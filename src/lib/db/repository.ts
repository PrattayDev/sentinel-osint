import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import {
  AuditEventRecord,
  CaseNote,
  CaseRecord,
  CaseTimelineEvent,
  EntityRecord,
  EntityRelationshipRecord,
  EvidenceSourceRecord,
  FindingRecord,
  InvestigationRecord,
  ProviderExecutionRecord,
  ReportRecord,
  RetentionPolicyRecord,
  UsageEventRecord,
  UserProfile,
  Workspace
} from '@/types/osint';
import { sanitizeText } from '@/lib/security/sanitizer';

export interface DatabaseState {
  users: UserProfile[];
  sessions: Array<{
    tokenHash: string;
    userId: string;
    createdAt: string;
    expiresAt: string;
  }>;
  revokedTokenHashes?: string[];
  passwordResetTokens: Array<{
    tokenHash: string;
    userId: string;
    email: string;
    expiresAt: string;
    used: boolean;
  }>;
  workspaces: Workspace[];
  investigations: InvestigationRecord[];
  providerExecutions: ProviderExecutionRecord[];
  evidenceSources: EvidenceSourceRecord[];
  findings: FindingRecord[];
  entities: EntityRecord[];
  entityRelationships: EntityRelationshipRecord[];
  cases: CaseRecord[];
  reports: ReportRecord[];
  auditEvents: AuditEventRecord[];
  usageEvents: UsageEventRecord[];
  retentionPolicies: RetentionPolicyRecord[];
}

const DATA_DIR = process.env.VERCEL
  ? path.join(os.tmpdir(), 'sentinel-osint-data')
  : path.join(process.cwd(), '.data');
const DB_FILE =
  process.env.SENTINEL_TEST_DB_PATH || path.join(DATA_DIR, 'sentinel-db.json');

const SESSION_HMAC_SECRET =
  process.env.SESSION_SECRET ||
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  'sentinel-osint-v2-hmac-session-signing-key-2026';

interface SignedSessionPayload {
  uid: string;
  em: string;
  fn: string;
  rl: 'analyst' | 'senior_analyst' | 'admin';
  iat: number;
  exp: number;
  jti: string;
}

function createSignedSessionToken(user: UserProfile, expiresAtMs: number): string {
  const payload: SignedSessionPayload = {
    uid: user.id,
    em: user.email,
    fn: user.fullName,
    rl: user.role,
    iat: Date.now(),
    exp: expiresAtMs,
    jti: crypto.randomBytes(16).toString('hex')
  };
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = crypto
    .createHmac('sha256', SESSION_HMAC_SECRET)
    .update(encoded)
    .digest('base64url');
  return `st2.${encoded}.${sig}`;
}

function verifySignedSessionToken(rawToken: string): SignedSessionPayload | null {
  if (!rawToken.startsWith('st2.')) return null;
  const parts = rawToken.split('.');
  if (parts.length !== 3) return null;
  const [, encoded, sig] = parts;
  const expectedSig = crypto
    .createHmac('sha256', SESSION_HMAC_SECRET)
    .update(encoded)
    .digest('base64url');
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expectedSig);
  if (sigBuf.byteLength !== expBuf.byteLength) return null;
  if (!crypto.timingSafeEqual(sigBuf, expBuf)) return null;
  try {
    const parsed = JSON.parse(
      Buffer.from(encoded, 'base64url').toString('utf8')
    ) as SignedSessionPayload;
    if (!parsed.uid || !parsed.em || typeof parsed.exp !== 'number') return null;
    if (Date.now() >= parsed.exp) return null;
    return parsed;
  } catch {
    return null;
  }
}

let memoryDb: DatabaseState | null = null;

function createEmptyState(): DatabaseState {
  return {
    users: [],
    sessions: [],
    revokedTokenHashes: [],
    passwordResetTokens: [],
    workspaces: [],
    investigations: [],
    providerExecutions: [],
    evidenceSources: [],
    findings: [],
    entities: [],
    entityRelationships: [],
    cases: [],
    reports: [],
    auditEvents: [],
    usageEvents: [],
    retentionPolicies: []
  };
}

export function hashPassword(
  password: string,
  salt = crypto.randomBytes(16).toString('hex')
): { hash: string; salt: string } {
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return { hash: derived, salt };
}

export function verifyPassword(
  password: string,
  expectedHash: string,
  salt: string
): boolean {
  const derived = crypto.scryptSync(password, salt, 64);
  const expectedBuf = Buffer.from(expectedHash, 'hex');
  if (derived.byteLength !== expectedBuf.byteLength) return false;
  return crypto.timingSafeEqual(derived, expectedBuf);
}

function loadState(): DatabaseState {
  if (memoryDb) return memoryDb;

  try {
    if (fs.existsSync(DB_FILE)) {
      const raw = fs.readFileSync(DB_FILE, 'utf8');
      const parsed = JSON.parse(raw) as Partial<DatabaseState>;
      memoryDb = {
        ...createEmptyState(),
        ...parsed
      };
      return memoryDb;
    }
  } catch {
    // Fallback to clean state if corrupted
  }

  memoryDb = createEmptyState();
  saveState();
  return memoryDb;
}

function saveState(): void {
  if (!memoryDb) return;
  try {
    const dir = path.dirname(DB_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(DB_FILE, JSON.stringify(memoryDb, null, 2), 'utf8');
  } catch {
    // Ignore write failure in read-only edge runtimes; memoryDb remains authoritative
  }
}

export function resetDatabaseForTest(): void {
  memoryDb = createEmptyState();
  saveState();
}

export function getSupabaseAdminClient(): SupabaseClient | null {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key =
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  if (!url || !key) return null;
  return createClient(url, key, {
    auth: { persistSession: false }
  });
}

// ============================================================================
// USER & AUTHENTICATION REPOSITORY
// ============================================================================

export function createUserAccount(input: {
  email: string;
  password: string;
  fullName: string;
  acceptedEthicalTerms: boolean;
  role?: 'analyst' | 'senior_analyst' | 'admin';
}): UserProfile {
  const db = loadState();
  const normalizedEmail = input.email.trim().toLowerCase();

  if (!input.acceptedEthicalTerms) {
    throw new Error('Ethical-use terms and conditions must be accepted.');
  }

  if (input.password.length < 8) {
    throw new Error('Password must be at least 8 characters long.');
  }

  const existing = db.users.find((u) => u.email === normalizedEmail);
  if (existing) {
    throw new Error('An account with this email address already exists.');
  }

  const { hash, salt } = hashPassword(input.password);
  const now = new Date().toISOString();
  const userId = crypto.randomUUID();
  const workspaceId = crypto.randomUUID();

  const user: UserProfile = {
    id: userId,
    email: normalizedEmail,
    fullName: sanitizeText(input.fullName, 120),
    passwordHash: hash,
    passwordSalt: salt,
    role: input.role || 'analyst',
    mfaEnabled: false,
    acceptedEthicalTerms: true,
    acceptedTermsAt: now,
    createdAt: now,
    updatedAt: now
  };

  const workspace: Workspace = {
    id: workspaceId,
    name: `${user.fullName}'s Intelligence Workspace`,
    description: 'Isolated analyst investigation workspace',
    ownerId: userId,
    createdAt: now,
    updatedAt: now
  };

  const retention: RetentionPolicyRecord = {
    id: crypto.randomUUID(),
    workspaceId,
    ownerId: userId,
    investigationRetentionDays: 90,
    autoRedactSensitiveExif: true,
    updatedAt: now
  };

  db.users.push(user);
  db.workspaces.push(workspace);
  db.retentionPolicies.push(retention);
  recordAuditEvent({
    actorId: userId,
    action: 'auth.register',
    resourceType: 'user',
    resourceId: userId,
    metadata: { email: normalizedEmail, acceptedEthicalTerms: true }
  });
  saveState();
  return user;
}

export function authenticateUser(
  email: string,
  password: string
): { user: UserProfile; sessionToken: string } {
  const db = loadState();
  const normalizedEmail = email.trim().toLowerCase();
  const user = db.users.find((u) => u.email === normalizedEmail);

  if (!user || !verifyPassword(password, user.passwordHash, user.passwordSalt)) {
    recordAuditEvent({
      action: 'auth.login_failed',
      resourceType: 'user',
      metadata: { email: normalizedEmail }
    });
    throw new Error('Invalid email or password.');
  }

  const now = Date.now();
  const expiresAtMs = now + 7 * 24 * 60 * 60 * 1000;
  const expiresAt = new Date(expiresAtMs).toISOString();
  const rawToken = createSignedSessionToken(user, expiresAtMs);
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

  db.sessions.push({
    tokenHash,
    userId: user.id,
    createdAt: new Date(now).toISOString(),
    expiresAt
  });

  recordAuditEvent({
    actorId: user.id,
    action: 'auth.login_success',
    resourceType: 'session',
    resourceId: user.id,
    metadata: {}
  });
  saveState();
  return { user, sessionToken: rawToken };
}

export function getUserBySessionToken(rawToken?: string | null): UserProfile | null {
  if (!rawToken) return null;
  const db = loadState();
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  if (db.revokedTokenHashes?.includes(tokenHash)) {
    return null;
  }

  const nowIso = new Date().toISOString();
  const session = db.sessions.find(
    (s) => s.tokenHash === tokenHash && s.expiresAt > nowIso
  );
  if (session) {
    return db.users.find((u) => u.id === session.userId) || null;
  }

  // Stateless HMAC verification fallback for serverless cold starts (e.g. Vercel multi-instance)
  const verifiedPayload = verifySignedSessionToken(rawToken);
  if (!verifiedPayload) return null;

  let user = db.users.find((u) => u.id === verifiedPayload.uid);
  if (!user) {
    // If user was already known in this instance and deleted/reset, do not rehydrate
    const hadRevokedForUser = db.auditEvents.some(
      (ev) =>
        ev.actorId === verifiedPayload.uid &&
        (ev.action === 'auth.account_hard_deleted' ||
          ev.action === 'auth.password_reset_completed')
    );
    if (hadRevokedForUser) return null;

    const now = new Date().toISOString();
    user = {
      id: verifiedPayload.uid,
      email: verifiedPayload.em,
      fullName: verifiedPayload.fn,
      passwordHash: '',
      passwordSalt: '',
      role: verifiedPayload.rl,
      mfaEnabled: false,
      acceptedEthicalTerms: true,
      acceptedTermsAt: now,
      createdAt: now,
      updatedAt: now
    };
    db.users.push(user);
    getOrCreatePrimaryWorkspace(user.id);
  }

  db.sessions.push({
    tokenHash,
    userId: user.id,
    createdAt: nowIso,
    expiresAt: new Date(verifiedPayload.exp).toISOString()
  });
  saveState();
  return user;
}

export function invalidateSessionToken(rawToken?: string | null): void {
  if (!rawToken) return;
  const db = loadState();
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  if (!db.revokedTokenHashes) db.revokedTokenHashes = [];
  if (!db.revokedTokenHashes.includes(tokenHash)) {
    db.revokedTokenHashes.push(tokenHash);
  }
  const existing = db.sessions.find((s) => s.tokenHash === tokenHash);
  db.sessions = db.sessions.filter((s) => s.tokenHash !== tokenHash);
  if (existing) {
    recordAuditEvent({
      actorId: existing.userId,
      action: 'auth.logout',
      resourceType: 'session',
      resourceId: existing.userId,
      metadata: {}
    });
  }
  saveState();
}

export function createPasswordResetToken(email: string): {
  resetToken: string | null;
  expiresAt: string;
} {
  const db = loadState();
  const normalizedEmail = email.trim().toLowerCase();
  const user = db.users.find((u) => u.email === normalizedEmail);
  const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();

  if (!user) {
    // Do not leak user existence; return null token internally
    return { resetToken: null, expiresAt };
  }

  const rawToken = crypto.randomBytes(24).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

  db.passwordResetTokens.push({
    tokenHash,
    userId: user.id,
    email: user.email,
    expiresAt,
    used: false
  });

  recordAuditEvent({
    actorId: user.id,
    action: 'auth.password_reset_requested',
    resourceType: 'user',
    resourceId: user.id,
    metadata: {}
  });
  saveState();
  return { resetToken: rawToken, expiresAt };
}

export function completePasswordReset(
  rawToken: string,
  newPassword: string
): boolean {
  if (newPassword.length < 8) {
    throw new Error('New password must be at least 8 characters long.');
  }
  const db = loadState();
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const nowIso = new Date().toISOString();

  const entry = db.passwordResetTokens.find(
    (t) => t.tokenHash === tokenHash && !t.used && t.expiresAt > nowIso
  );
  if (!entry) {
    throw new Error('Invalid or expired password reset token.');
  }

  const user = db.users.find((u) => u.id === entry.userId);
  if (!user) {
    throw new Error('Associated account not found.');
  }

  const { hash, salt } = hashPassword(newPassword);
  user.passwordHash = hash;
  user.passwordSalt = salt;
  user.updatedAt = nowIso;
  entry.used = true;

  // Invalidate all active sessions for security and record their hashes as revoked
  if (!db.revokedTokenHashes) db.revokedTokenHashes = [];
  for (const s of db.sessions) {
    if (s.userId === user.id && !db.revokedTokenHashes.includes(s.tokenHash)) {
      db.revokedTokenHashes.push(s.tokenHash);
    }
  }
  db.sessions = db.sessions.filter((s) => s.userId !== user.id);

  recordAuditEvent({
    actorId: user.id,
    action: 'auth.password_reset_completed',
    resourceType: 'user',
    resourceId: user.id,
    metadata: {}
  });
  saveState();
  return true;
}

export function deleteUserAccountAndData(userId: string): void {
  const db = loadState();
  if (!db.revokedTokenHashes) db.revokedTokenHashes = [];
  for (const s of db.sessions) {
    if (s.userId === userId && !db.revokedTokenHashes.includes(s.tokenHash)) {
      db.revokedTokenHashes.push(s.tokenHash);
    }
  }
  db.sessions = db.sessions.filter((s) => s.userId !== userId);
  db.investigations = db.investigations.filter((i) => i.ownerId !== userId);
  db.providerExecutions = db.providerExecutions.filter((p) => p.ownerId !== userId);
  db.evidenceSources = db.evidenceSources.filter((e) => e.ownerId !== userId);
  db.findings = db.findings.filter((f) => f.ownerId !== userId);
  db.entities = db.entities.filter((e) => e.ownerId !== userId);
  db.entityRelationships = db.entityRelationships.filter((r) => r.ownerId !== userId);
  db.cases = db.cases.filter((c) => c.ownerId !== userId);
  db.reports = db.reports.filter((r) => r.ownerId !== userId);
  db.workspaces = db.workspaces.filter((w) => w.ownerId !== userId);
  db.retentionPolicies = db.retentionPolicies.filter((p) => p.ownerId !== userId);
  db.users = db.users.filter((u) => u.id !== userId);

  recordAuditEvent({
    actorId: userId,
    action: 'auth.account_hard_deleted',
    resourceType: 'user',
    resourceId: userId,
    metadata: {}
  });
  saveState();
}

export function getOrCreatePrimaryWorkspace(userId: string): Workspace {
  const db = loadState();
  const existing = db.workspaces.find((w) => w.ownerId === userId);
  if (existing) return existing;

  const now = new Date().toISOString();
  const ws: Workspace = {
    id: crypto.randomUUID(),
    name: 'Primary Intelligence Workspace',
    description: 'Default workspace',
    ownerId: userId,
    createdAt: now,
    updatedAt: now
  };
  db.workspaces.push(ws);
  saveState();
  return ws;
}

// ============================================================================
// INVESTIGATION, FINDING & GRAPH REPOSITORY (STRICT TENANT ISOLATION)
// ============================================================================

export function saveInvestigationBundle(bundle: {
  investigation: InvestigationRecord;
  providerExecutions: ProviderExecutionRecord[];
  evidenceSources: EvidenceSourceRecord[];
  findings: FindingRecord[];
  entities: EntityRecord[];
  relationships: EntityRelationshipRecord[];
  caseId?: string;
}): InvestigationRecord {
  const db = loadState();
  const ownerId = bundle.investigation.ownerId;

  // Replace if re-run of existing investigation ID owned by same user
  db.investigations = db.investigations.filter(
    (i) => !(i.id === bundle.investigation.id && i.ownerId === ownerId)
  );
  db.providerExecutions = db.providerExecutions.filter(
    (p) => !(p.investigationId === bundle.investigation.id && p.ownerId === ownerId)
  );
  db.evidenceSources = db.evidenceSources.filter(
    (e) => !(e.investigationId === bundle.investigation.id && e.ownerId === ownerId)
  );
  db.findings = db.findings.filter(
    (f) => !(f.investigationId === bundle.investigation.id && f.ownerId === ownerId)
  );
  db.entities = db.entities.filter(
    (e) => !(e.investigationId === bundle.investigation.id && e.ownerId === ownerId)
  );
  db.entityRelationships = db.entityRelationships.filter(
    (r) => !(r.investigationId === bundle.investigation.id && r.ownerId === ownerId)
  );

  db.investigations.unshift(bundle.investigation);
  db.providerExecutions.push(...bundle.providerExecutions);
  db.evidenceSources.push(...bundle.evidenceSources);
  db.findings.push(...bundle.findings);
  db.entities.push(...bundle.entities);
  db.entityRelationships.push(...bundle.relationships);

  for (const exec of bundle.providerExecutions) {
    if (exec.status === 'completed' || exec.status === 'partial') {
      db.usageEvents.push({
        id: crypto.randomUUID(),
        ownerId,
        providerId: exec.providerId,
        eventType: 'provider_lookup',
        quotaCost: 1,
        status: exec.status,
        createdAt: exec.queriedAt
      });
    }
  }

  if (bundle.caseId) {
    const targetCase = db.cases.find(
      (c) => c.id === bundle.caseId && c.ownerId === ownerId
    );
    if (targetCase) {
      if (!targetCase.investigationIds.includes(bundle.investigation.id)) {
        targetCase.investigationIds.push(bundle.investigation.id);
      }
      targetCase.timeline.unshift({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        title: `Investigation executed: ${bundle.investigation.normalizedTarget}`,
        description: `Target (${bundle.investigation.targetType}) produced ${bundle.findings.length} findings across ${bundle.providerExecutions.length} providers.`,
        category: 'investigation',
        sourceRef: bundle.investigation.id
      });
      targetCase.updatedAt = new Date().toISOString();
    }
  }

  recordAuditEvent({
    actorId: ownerId,
    action: 'investigation.completed',
    resourceType: 'investigation',
    resourceId: bundle.investigation.id,
    metadata: {
      targetType: bundle.investigation.targetType,
      normalizedTarget: bundle.investigation.normalizedTarget,
      findingsCount: bundle.findings.length
    }
  });

  saveState();
  return bundle.investigation;
}

export function listUserInvestigations(userId: string): InvestigationRecord[] {
  const db = loadState();
  return db.investigations
    .filter((i) => i.ownerId === userId)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export function getInvestigationDetailsForUser(
  investigationId: string,
  userId: string
): {
  investigation: InvestigationRecord;
  providerExecutions: ProviderExecutionRecord[];
  evidenceSources: EvidenceSourceRecord[];
  findings: FindingRecord[];
  entities: EntityRecord[];
  relationships: EntityRelationshipRecord[];
} | null {
  const db = loadState();
  const investigation = db.investigations.find(
    (i) => i.id === investigationId && i.ownerId === userId
  );
  if (!investigation) return null;

  return {
    investigation,
    providerExecutions: db.providerExecutions.filter(
      (p) => p.investigationId === investigationId && p.ownerId === userId
    ),
    evidenceSources: db.evidenceSources.filter(
      (e) => e.investigationId === investigationId && e.ownerId === userId
    ),
    findings: db.findings
      .filter((f) => f.investigationId === investigationId && f.ownerId === userId)
      .map(({ unredactedAttributes: _hidden, ...rest }) => rest),
    entities: db.entities.filter(
      (e) => e.investigationId === investigationId && e.ownerId === userId
    ),
    relationships: db.entityRelationships.filter(
      (r) => r.investigationId === investigationId && r.ownerId === userId
    )
  };
}

export function deleteInvestigationForUser(
  investigationId: string,
  userId: string
): boolean {
  const db = loadState();
  const existing = db.investigations.find((i) => i.id === investigationId);
  if (!existing) return false;
  if (existing.ownerId !== userId) {
    recordAuditEvent({
      actorId: userId,
      action: 'security.unauthorized_delete_attempt',
      resourceType: 'investigation',
      resourceId: investigationId,
      metadata: {}
    });
    throw new Error('FORBIDDEN: Cannot delete another user investigation.');
  }

  db.investigations = db.investigations.filter((i) => i.id !== investigationId);
  db.providerExecutions = db.providerExecutions.filter(
    (p) => p.investigationId !== investigationId
  );
  db.evidenceSources = db.evidenceSources.filter(
    (e) => e.investigationId !== investigationId
  );
  db.findings = db.findings.filter((f) => f.investigationId !== investigationId);
  db.entities = db.entities.filter((e) => e.investigationId !== investigationId);
  db.entityRelationships = db.entityRelationships.filter(
    (r) => r.investigationId !== investigationId
  );
  for (const c of db.cases) {
    if (c.ownerId === userId) {
      c.investigationIds = c.investigationIds.filter((id) => id !== investigationId);
    }
  }

  recordAuditEvent({
    actorId: userId,
    action: 'investigation.deleted',
    resourceType: 'investigation',
    resourceId: investigationId,
    metadata: {}
  });
  saveState();
  return true;
}

export function listUserFindings(userId: string): FindingRecord[] {
  const db = loadState();
  return db.findings
    .filter((f) => f.ownerId === userId)
    .map(({ unredactedAttributes: _hidden, ...rest }) => rest)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export function toggleFindingBookmarkOrTags(
  findingId: string,
  userId: string,
  updates: { bookmarked?: boolean; tags?: string[]; revealSensitive?: boolean }
): FindingRecord | null {
  const db = loadState();
  const finding = db.findings.find(
    (f) => f.id === findingId && f.ownerId === userId
  );
  if (!finding) return null;

  if (typeof updates.bookmarked === 'boolean') {
    finding.bookmarked = updates.bookmarked;
  }
  if (Array.isArray(updates.tags)) {
    finding.tags = updates.tags.map((t) => sanitizeText(t, 40)).filter(Boolean);
  }
  saveState();
  const { unredactedAttributes, ...safeCopy } = finding;
  if (updates.revealSensitive && unredactedAttributes) {
    return {
      ...safeCopy,
      attributes: unredactedAttributes
    };
  }
  return safeCopy;
}

export function listUserGraphData(
  userId: string,
  investigationId?: string
): {
  entities: EntityRecord[];
  relationships: EntityRelationshipRecord[];
} {
  const db = loadState();
  const entities = db.entities.filter(
    (e) =>
      e.ownerId === userId &&
      (!investigationId || e.investigationId === investigationId)
  );
  const relationships = db.entityRelationships.filter(
    (r) =>
      r.ownerId === userId &&
      (!investigationId || r.investigationId === investigationId)
  );
  return { entities, relationships };
}

// ============================================================================
// CASE MANAGEMENT REPOSITORY (STRICT TENANT ISOLATION)
// ============================================================================

export function createCaseForUser(
  userId: string,
  input: {
    title: string;
    description: string;
    scopeAndAuthorization: string;
    status?: 'draft' | 'active' | 'completed' | 'archived';
    priority?: 'low' | 'medium' | 'high' | 'critical';
    tags?: string[];
  }
): CaseRecord {
  const db = loadState();
  const ws = getOrCreatePrimaryWorkspace(userId);
  const now = new Date().toISOString();

  const newCase: CaseRecord = {
    id: crypto.randomUUID(),
    workspaceId: ws.id,
    ownerId: userId,
    title: sanitizeText(input.title, 160),
    description: sanitizeText(input.description, 2000),
    scopeAndAuthorization: sanitizeText(input.scopeAndAuthorization, 2000),
    status: input.status || 'active',
    priority: input.priority || 'medium',
    tags: (input.tags || []).map((t) => sanitizeText(t, 40)),
    investigationIds: [],
    notes: [],
    timeline: [
      {
        id: crypto.randomUUID(),
        timestamp: now,
        title: 'Case opened',
        description: `Case "${sanitizeText(input.title, 160)}" initialized with verified scope.`,
        category: 'case_lifecycle'
      }
    ],
    createdAt: now,
    updatedAt: now
  };

  db.cases.unshift(newCase);
  recordAuditEvent({
    actorId: userId,
    action: 'case.created',
    resourceType: 'case',
    resourceId: newCase.id,
    metadata: { title: newCase.title, status: newCase.status }
  });
  saveState();
  return newCase;
}

export function listUserCases(userId: string): CaseRecord[] {
  const db = loadState();
  return db.cases
    .filter((c) => c.ownerId === userId)
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

export function getCaseForUser(caseId: string, userId: string): CaseRecord | null {
  const db = loadState();
  const c = db.cases.find((item) => item.id === caseId);
  if (!c) return null;
  if (c.ownerId !== userId) {
    recordAuditEvent({
      actorId: userId,
      action: 'security.unauthorized_case_access_attempt',
      resourceType: 'case',
      resourceId: caseId,
      metadata: {}
    });
    return null;
  }
  return c;
}

export function updateCaseForUser(
  caseId: string,
  userId: string,
  updates: {
    title?: string;
    description?: string;
    scopeAndAuthorization?: string;
    status?: 'draft' | 'active' | 'completed' | 'archived';
    priority?: 'low' | 'medium' | 'high' | 'critical';
    tags?: string[];
    addNote?: { content: string; authorName: string };
    linkInvestigationId?: string;
  }
): CaseRecord | null {
  const db = loadState();
  const target = db.cases.find((c) => c.id === caseId);
  if (!target) return null;
  if (target.ownerId !== userId) {
    recordAuditEvent({
      actorId: userId,
      action: 'security.unauthorized_case_update_attempt',
      resourceType: 'case',
      resourceId: caseId,
      metadata: {}
    });
    throw new Error('FORBIDDEN: Cannot modify another user case.');
  }

  const now = new Date().toISOString();
  if (updates.title) target.title = sanitizeText(updates.title, 160);
  if (updates.description) target.description = sanitizeText(updates.description, 2000);
  if (updates.scopeAndAuthorization) {
    target.scopeAndAuthorization = sanitizeText(updates.scopeAndAuthorization, 2000);
  }
  if (updates.status && updates.status !== target.status) {
    target.timeline.unshift({
      id: crypto.randomUUID(),
      timestamp: now,
      title: `Case status changed: ${target.status} -> ${updates.status}`,
      description: `Analyst updated case lifecycle state to ${updates.status}.`,
      category: 'status_change'
    });
    target.status = updates.status;
  }
  if (updates.priority) target.priority = updates.priority;
  if (updates.tags) target.tags = updates.tags.map((t) => sanitizeText(t, 40));

  if (updates.addNote && updates.addNote.content.trim()) {
    const note: CaseNote = {
      id: crypto.randomUUID(),
      authorId: userId,
      authorName: sanitizeText(updates.addNote.authorName, 80),
      content: sanitizeText(updates.addNote.content, 4000),
      createdAt: now
    };
    target.notes.unshift(note);
    target.timeline.unshift({
      id: crypto.randomUUID(),
      timestamp: now,
      title: 'Analyst note added',
      description: note.content.slice(0, 140),
      category: 'note'
    });
  }

  if (updates.linkInvestigationId) {
    const inv = db.investigations.find(
      (i) => i.id === updates.linkInvestigationId && i.ownerId === userId
    );
    if (inv && !target.investigationIds.includes(inv.id)) {
      target.investigationIds.push(inv.id);
      target.timeline.unshift({
        id: crypto.randomUUID(),
        timestamp: now,
        title: `Linked investigation: ${inv.normalizedTarget}`,
        description: `Attached ${inv.targetType} investigation (${inv.summary.totalFindings} findings).`,
        category: 'investigation',
        sourceRef: inv.id
      });
    }
  }

  target.updatedAt = now;
  saveState();
  return target;
}

export function deleteCaseForUser(caseId: string, userId: string): boolean {
  const db = loadState();
  const target = db.cases.find((c) => c.id === caseId);
  if (!target) return false;
  if (target.ownerId !== userId) {
    throw new Error('FORBIDDEN: Cannot delete another user case.');
  }
  db.cases = db.cases.filter((c) => c.id !== caseId);
  recordAuditEvent({
    actorId: userId,
    action: 'case.deleted',
    resourceType: 'case',
    resourceId: caseId,
    metadata: {}
  });
  saveState();
  return true;
}

// ============================================================================
// REPORTS, AUDIT & DASHBOARD TELEMETRY
// ============================================================================

export function createReportRecordForUser(
  userId: string,
  input: {
    title: string;
    classification: 'TLP:CLEAR' | 'TLP:GREEN' | 'TLP:AMBER' | 'TLP:RED';
    executiveSummary: string;
    conclusions: string;
    caseId?: string;
    investigationId?: string;
  }
): ReportRecord {
  const db = loadState();
  const ws = getOrCreatePrimaryWorkspace(userId);
  const report: ReportRecord = {
    id: crypto.randomUUID(),
    workspaceId: ws.id,
    ownerId: userId,
    caseId: input.caseId,
    investigationId: input.investigationId,
    title: sanitizeText(input.title, 160),
    classification: input.classification,
    executiveSummary: sanitizeText(input.executiveSummary, 4000),
    conclusions: sanitizeText(input.conclusions, 4000),
    createdAt: new Date().toISOString()
  };
  db.reports.unshift(report);
  recordAuditEvent({
    actorId: userId,
    action: 'report.generated',
    resourceType: 'report',
    resourceId: report.id,
    metadata: { title: report.title, classification: report.classification }
  });
  saveState();
  return report;
}

export function listUserReports(userId: string): ReportRecord[] {
  const db = loadState();
  return db.reports.filter((r) => r.ownerId === userId);
}

export function recordAuditEvent(input: {
  actorId?: string;
  action: string;
  resourceType: string;
  resourceId?: string;
  ipAddress?: string;
  metadata: Record<string, unknown>;
}): AuditEventRecord {
  const db = loadState();
  const event: AuditEventRecord = {
    id: crypto.randomUUID(),
    actorId: input.actorId,
    action: input.action,
    resourceType: input.resourceType,
    resourceId: input.resourceId,
    ipAddress: input.ipAddress,
    metadata: input.metadata,
    createdAt: new Date().toISOString()
  };
  db.auditEvents.unshift(event);
  if (db.auditEvents.length > 1000) {
    db.auditEvents = db.auditEvents.slice(0, 1000);
  }
  saveState();
  return event;
}

export function listUserAuditEvents(userId: string, limit = 50): AuditEventRecord[] {
  const db = loadState();
  return db.auditEvents
    .filter((e) => e.actorId === userId)
    .slice(0, limit);
}

export function getUserRetentionPolicy(userId: string): RetentionPolicyRecord {
  const db = loadState();
  const existing = db.retentionPolicies.find((p) => p.ownerId === userId);
  if (existing) return existing;

  const ws = getOrCreatePrimaryWorkspace(userId);
  const policy: RetentionPolicyRecord = {
    id: crypto.randomUUID(),
    workspaceId: ws.id,
    ownerId: userId,
    investigationRetentionDays: 90,
    autoRedactSensitiveExif: true,
    updatedAt: new Date().toISOString()
  };
  db.retentionPolicies.push(policy);
  saveState();
  return policy;
}

export function updateUserRetentionPolicy(
  userId: string,
  updates: {
    investigationRetentionDays?: number;
    autoRedactSensitiveExif?: boolean;
  }
): RetentionPolicyRecord {
  const policy = getUserRetentionPolicy(userId);
  if (
    typeof updates.investigationRetentionDays === 'number' &&
    updates.investigationRetentionDays >= 1 &&
    updates.investigationRetentionDays <= 3650
  ) {
    policy.investigationRetentionDays = updates.investigationRetentionDays;
  }
  if (typeof updates.autoRedactSensitiveExif === 'boolean') {
    policy.autoRedactSensitiveExif = updates.autoRedactSensitiveExif;
  }
  policy.updatedAt = new Date().toISOString();
  recordAuditEvent({
    actorId: userId,
    action: 'settings.retention_updated',
    resourceType: 'retention_policy',
    resourceId: policy.id,
    metadata: updates
  });
  saveState();
  return policy;
}
