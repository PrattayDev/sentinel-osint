export type TargetType =
  | 'email'
  | 'domain'
  | 'ip'
  | 'url'
  | 'username'
  | 'phone'
  | 'file_hash'
  | 'organization'
  | 'file';

export type OsintCategory =
  | 'identity'
  | 'domain'
  | 'network'
  | 'web'
  | 'social'
  | 'threat'
  | 'media'
  | 'organization'
  | 'search';

export type ProviderStatus =
  | 'available'
  | 'not_configured'
  | 'running'
  | 'completed'
  | 'partial'
  | 'rate_limited'
  | 'failed'
  | 'unsupported';

export type ConfidenceLevel =
  | 'confirmed'
  | 'high'
  | 'medium'
  | 'low'
  | 'unverified_heuristic';

export type DataSensitivity = 'public' | 'internal' | 'sensitive' | 'restricted';

export type SeverityLevel = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type EntityType =
  | 'domain'
  | 'ip'
  | 'asn'
  | 'url'
  | 'profile'
  | 'organization'
  | 'email'
  | 'file_hash'
  | 'certificate'
  | 'phone'
  | 'evidence_source';

export interface InvestigationContext {
  investigationId: string;
  userId: string;
  workspaceId: string;
  scope: string;
  purpose: string;
  externalConsent: boolean;
  signal?: AbortSignal;
  fileBuffer?: Buffer;
  fileName?: string;
  mimeType?: string;
}

export interface NormalizedFindingInput {
  moduleCode: string; // e.g., 'DOM-02', 'ID-01', 'NET-03'
  category: OsintCategory;
  title: string;
  summary: string;
  severity: SeverityLevel;
  confidence: ConfidenceLevel;
  sensitivity?: DataSensitivity;
  redactedByDefault?: boolean;
  tags?: string[];
  attributes: Record<string, unknown>;
  sourceUrl?: string;
  observedAt?: string;
}

export interface DiscoveredEntityInput {
  key: string; // deterministic key within investigation, e.g. 'ip:93.184.216.34'
  entityType: EntityType;
  label: string;
  value: string;
  confidence: ConfidenceLevel;
  metadata?: Record<string, unknown>;
}

export interface DiscoveredRelationshipInput {
  sourceKey: string;
  targetKey: string;
  relationshipType: string; // e.g. 'resolves_to', 'belongs_to_asn', 'presents_certificate'
  confidence: ConfidenceLevel;
  verificationStatus?: 'verified' | 'corroborated' | 'unverified' | 'disputed';
}

export interface SourceReference {
  providerId: string;
  providerName: string;
  sourceUrl?: string;
  observedAt: string;
  queriedAt: string;
  confidence: ConfidenceLevel;
  sensitivity: DataSensitivity;
  verificationStatus: 'verified' | 'corroborated' | 'unverified' | 'disputed';
  citationNote?: string;
}

export interface ProviderResult<TResult = Record<string, unknown>> {
  providerId: string;
  providerName: string;
  status: ProviderStatus;
  findings: NormalizedFindingInput[];
  entities: DiscoveredEntityInput[];
  relationships: DiscoveredRelationshipInput[];
  sourceReferences: SourceReference[];
  rawResult?: TResult;
  observedTimestamp: string;
  queryTimestamp: string;
  durationMs: number;
  errors: string[];
  rateLimit?: {
    limit?: number;
    remaining?: number;
    resetAt?: string;
  };
  confidence: ConfidenceLevel;
  sensitivity: DataSensitivity;
}

export interface OsintProvider<TInput = string, TResult = Record<string, unknown>> {
  id: string;
  name: string;
  category: OsintCategory;
  supportedTypes: TargetType[];
  requiresApiKey: boolean;
  envVarNames: string[];
  isFreeTierAvailable: boolean;
  rateLimitPerMinute: number;
  disclosureNotice: string;
  featureIds: string[];

  isConfigured(): boolean;
  validateInput(input: unknown): TInput;
  execute(
    input: TInput,
    context: InvestigationContext
  ): Promise<ProviderResult<TResult>>;
}

// ============================================================================
// DATABASE & APPLICATION DOMAIN RECORDS
// ============================================================================

export interface UserProfile {
  id: string;
  email: string;
  fullName: string;
  passwordHash: string;
  passwordSalt: string;
  role: 'analyst' | 'senior_analyst' | 'admin';
  mfaEnabled: boolean;
  mfaSecret?: string;
  acceptedEthicalTerms: boolean;
  acceptedTermsAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface Workspace {
  id: string;
  name: string;
  description: string;
  ownerId: string;
  createdAt: string;
  updatedAt: string;
}

export interface ProviderExecutionRecord {
  id: string;
  investigationId: string;
  ownerId: string;
  providerId: string;
  providerName: string;
  status: ProviderStatus;
  durationMs: number;
  findingsCount: number;
  errorMessage?: string;
  rateLimitRemaining?: number;
  queriedAt: string;
  observedAt: string;
}

export interface EvidenceSourceRecord {
  id: string;
  investigationId: string;
  ownerId: string;
  providerId: string;
  providerName: string;
  sourceUrl?: string;
  observedAt: string;
  queriedAt: string;
  confidence: ConfidenceLevel;
  sensitivity: DataSensitivity;
  verificationStatus: 'verified' | 'corroborated' | 'unverified' | 'disputed';
  bookmarked: boolean;
  citationNote?: string;
  createdAt: string;
}

export interface FindingRecord {
  id: string;
  investigationId: string;
  ownerId: string;
  providerId: string;
  providerName: string;
  category: OsintCategory;
  moduleCode: string;
  title: string;
  summary: string;
  severity: SeverityLevel;
  confidence: ConfidenceLevel;
  sensitivity: DataSensitivity;
  redactedByDefault: boolean;
  bookmarked: boolean;
  tags: string[];
  attributes: Record<string, unknown>;
  unredactedAttributes?: Record<string, unknown>;
  sourceUrl?: string;
  evidenceSourceId?: string;
  observedAt: string;
  queriedAt: string;
  createdAt: string;
}

export interface EntityRecord {
  id: string;
  investigationId: string;
  ownerId: string;
  entityType: EntityType;
  label: string;
  value: string;
  confidence: ConfidenceLevel;
  providerId: string;
  metadata: Record<string, unknown>;
  positionX?: number;
  positionY?: number;
  observedAt: string;
  createdAt: string;
}

export interface EntityRelationshipRecord {
  id: string;
  investigationId: string;
  ownerId: string;
  sourceEntityId: string;
  targetEntityId: string;
  relationshipType: string;
  sourceProvider: string;
  evidenceId?: string;
  confidence: ConfidenceLevel;
  verificationStatus: 'verified' | 'corroborated' | 'unverified' | 'disputed';
  observedAt: string;
  createdAt: string;
}

export interface InvestigationRecord {
  id: string;
  workspaceId: string;
  ownerId: string;
  title: string;
  targetType: TargetType;
  targetValue: string;
  normalizedTarget: string;
  scope: string;
  purpose: string;
  externalProviderConsent: boolean;
  status: 'queued' | 'running' | 'completed' | 'partial' | 'failed' | 'cancelled';
  tags: string[];
  summary: {
    totalProviders: number;
    completedProviders: number;
    partialProviders: number;
    notConfiguredProviders: number;
    failedProviders: number;
    totalFindings: number;
    totalEntities: number;
    totalRelationships: number;
    highestSeverity: SeverityLevel;
  };
  createdAt: string;
  updatedAt: string;
  completedAt?: string;
}

export interface CaseNote {
  id: string;
  authorId: string;
  authorName: string;
  content: string;
  createdAt: string;
}

export interface CaseTimelineEvent {
  id: string;
  timestamp: string;
  title: string;
  description: string;
  category: string;
  sourceRef?: string;
}

export interface CaseRecord {
  id: string;
  workspaceId: string;
  ownerId: string;
  title: string;
  description: string;
  scopeAndAuthorization: string;
  status: 'draft' | 'active' | 'completed' | 'archived';
  priority: 'low' | 'medium' | 'high' | 'critical';
  tags: string[];
  investigationIds: string[];
  notes: CaseNote[];
  timeline: CaseTimelineEvent[];
  createdAt: string;
  updatedAt: string;
}

export interface ReportRecord {
  id: string;
  workspaceId: string;
  ownerId: string;
  caseId?: string;
  investigationId?: string;
  title: string;
  classification: 'TLP:CLEAR' | 'TLP:GREEN' | 'TLP:AMBER' | 'TLP:RED';
  executiveSummary: string;
  conclusions: string;
  createdAt: string;
}

export interface AuditEventRecord {
  id: string;
  actorId?: string;
  action: string;
  resourceType: string;
  resourceId?: string;
  ipAddress?: string;
  metadata: Record<string, unknown>;
  createdAt: string;
}

export interface UsageEventRecord {
  id: string;
  ownerId: string;
  providerId: string;
  eventType: string;
  quotaCost: number;
  status: string;
  createdAt: string;
}

export interface RetentionPolicyRecord {
  id: string;
  workspaceId: string;
  ownerId: string;
  investigationRetentionDays: number;
  autoRedactSensitiveExif: boolean;
  updatedAt: string;
}
