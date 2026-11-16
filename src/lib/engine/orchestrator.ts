import crypto from 'crypto';
import {
  EntityRecord,
  EntityRelationshipRecord,
  EvidenceSourceRecord,
  FindingRecord,
  InvestigationContext,
  InvestigationRecord,
  ProviderExecutionRecord,
  ProviderResult,
  SeverityLevel,
  TargetType
} from '@/types/osint';
import { classifyAndValidateTarget } from '@/lib/validation/schemas';
import { getProvidersForTargetType } from '@/lib/providers/registry';
import { checkRateLimit } from '@/lib/security/rate-limiter';
import {
  getOrCreatePrimaryWorkspace,
  saveInvestigationBundle
} from '@/lib/db/repository';
import { redactSensitiveAttributes, sanitizeRecord, sanitizeText } from '@/lib/security/sanitizer';

const MAX_CONCURRENCY = 4;

const SEVERITY_RANK: Record<SeverityLevel, number> = {
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5
};

const LOCAL_ONLY_PROVIDER_IDS = new Set(['phone-metadata', 'file-metadata']);

async function runWithConcurrency<T, R>(
  items: T[],
  limit: number,
  worker: (item: T) => Promise<R>
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let nextIndex = 0;

  async function next(): Promise<void> {
    while (nextIndex < items.length) {
      const idx = nextIndex++;
      results[idx] = await worker(items[idx]);
    }
  }

  const runners = Array.from(
    { length: Math.min(limit, items.length) },
    () => next()
  );
  await Promise.all(runners);
  return results;
}

export interface ExecuteInvestigationInput {
  userId: string;
  targetValue: string;
  targetType?: TargetType;
  title?: string;
  scope: string;
  purpose: string;
  externalProviderConsent?: boolean;
  caseId?: string;
  tags?: string[];
  existingInvestigationId?: string;
  fileBuffer?: Buffer;
  fileName?: string;
  mimeType?: string;
}

export interface ExecutedInvestigationBundle {
  investigation: InvestigationRecord;
  providerExecutions: ProviderExecutionRecord[];
  evidenceSources: EvidenceSourceRecord[];
  findings: FindingRecord[];
  entities: EntityRecord[];
  relationships: EntityRelationshipRecord[];
}

export async function executeUniversalInvestigation(
  input: ExecuteInvestigationInput
): Promise<ExecutedInvestigationBundle> {
  const validation = classifyAndValidateTarget(
    input.targetValue,
    input.targetType
  );
  if (!validation.valid) {
    throw new Error(validation.error || 'Target validation failed.');
  }

  const workspace = getOrCreatePrimaryWorkspace(input.userId);
  const investigationId = input.existingInvestigationId || crypto.randomUUID();
  const createdAt = new Date().toISOString();
  const externalConsent = input.externalProviderConsent !== false;

  const context: InvestigationContext = {
    investigationId,
    userId: input.userId,
    workspaceId: workspace.id,
    scope: sanitizeText(input.scope, 500),
    purpose: sanitizeText(input.purpose, 500),
    externalConsent,
    fileBuffer: input.fileBuffer,
    fileName: input.fileName,
    mimeType: input.mimeType
  };

  const providers = getProvidersForTargetType(validation.targetType);

  const rawResults: ProviderResult<Record<string, unknown>>[] =
    await runWithConcurrency(providers, MAX_CONCURRENCY, async (provider) => {
      const nowIso = new Date().toISOString();

      // Check external disclosure consent
      if (!externalConsent && !LOCAL_ONLY_PROVIDER_IDS.has(provider.id)) {
        return {
          providerId: provider.id,
          providerName: provider.name,
          status: 'unsupported',
          findings: [],
          entities: [],
          relationships: [],
          sourceReferences: [],
          observedTimestamp: nowIso,
          queryTimestamp: nowIso,
          durationMs: 0,
          errors: [
            'Skipped external network lookup because externalProviderConsent was set to false.'
          ],
          confidence: 'low',
          sensitivity: 'public'
        };
      }

      if (!provider.isConfigured()) {
        return {
          providerId: provider.id,
          providerName: provider.name,
          status: 'not_configured',
          findings: [],
          entities: [],
          relationships: [],
          sourceReferences: [],
          observedTimestamp: nowIso,
          queryTimestamp: nowIso,
          durationMs: 0,
          errors: [
            `Required credential(s) [${provider.envVarNames.join(', ')}] not configured.`
          ],
          confidence: 'low',
          sensitivity: 'public'
        };
      }

      const rateCheck = checkRateLimit(
        `provider:${provider.id}:user:${input.userId}`,
        provider.rateLimitPerMinute,
        60_000
      );

      if (!rateCheck.allowed) {
        return {
          providerId: provider.id,
          providerName: provider.name,
          status: 'rate_limited',
          findings: [],
          entities: [],
          relationships: [],
          sourceReferences: [],
          observedTimestamp: nowIso,
          queryTimestamp: nowIso,
          durationMs: 0,
          errors: [
            `Rate limit reached for ${provider.name}. Retry after ${rateCheck.retryAfterSeconds}s.`
          ],
          rateLimit: {
            limit: rateCheck.limit,
            remaining: rateCheck.remaining,
            resetAt: rateCheck.resetAt
          },
          confidence: 'low',
          sensitivity: 'public'
        };
      }

      try {
        const res = await provider.execute(validation.normalizedValue, context);
        res.rateLimit = {
          limit: rateCheck.limit,
          remaining: rateCheck.remaining,
          resetAt: rateCheck.resetAt
        };
        return res;
      } catch (err) {
        return {
          providerId: provider.id,
          providerName: provider.name,
          status: 'failed',
          findings: [],
          entities: [],
          relationships: [],
          sourceReferences: [],
          observedTimestamp: new Date().toISOString(),
          queryTimestamp: nowIso,
          durationMs: 0,
          errors: [(err as Error).message],
          confidence: 'low',
          sensitivity: 'public'
        };
      }
    });

  const providerExecutions: ProviderExecutionRecord[] = [];
  const evidenceSources: EvidenceSourceRecord[] = [];
  const findings: FindingRecord[] = [];
  const entityMap = new Map<string, EntityRecord>();
  const relationships: EntityRelationshipRecord[] = [];
  const findingDedupKeys = new Set<string>();
  const edgeDedupKeys = new Set<string>();

  // Create root entity node for target
  const rootEntityTypeMap: Record<TargetType, EntityRecord['entityType']> = {
    email: 'email',
    domain: 'domain',
    ip: 'ip',
    url: 'url',
    username: 'profile',
    phone: 'phone',
    file_hash: 'file_hash',
    organization: 'organization',
    file: 'file_hash'
  };

  const rootKeyPrefix: Record<TargetType, string> = {
    email: 'email',
    domain: 'domain',
    ip: 'ip',
    url: 'url',
    username: 'profile:handle',
    phone: 'phone',
    file_hash: 'hash',
    organization: 'org',
    file: 'hash'
  };

  const rootKey = `${rootKeyPrefix[validation.targetType]}:${validation.normalizedValue.toLowerCase()}`;
  entityMap.set(rootKey, {
    id: crypto.randomUUID(),
    investigationId,
    ownerId: input.userId,
    entityType: rootEntityTypeMap[validation.targetType],
    label: validation.normalizedValue,
    value: validation.normalizedValue,
    confidence: 'confirmed',
    providerId: 'target-input',
    metadata: validation.metadata,
    positionX: 400,
    positionY: 250,
    observedAt: createdAt,
    createdAt
  });

  let highestSeverity: SeverityLevel = 'info';

  for (const res of rawResults) {
    providerExecutions.push({
      id: crypto.randomUUID(),
      investigationId,
      ownerId: input.userId,
      providerId: res.providerId,
      providerName: res.providerName,
      status: res.status,
      durationMs: res.durationMs,
      findingsCount: res.findings.length,
      errorMessage: res.errors.length > 0 ? res.errors.join('; ') : undefined,
      rateLimitRemaining: res.rateLimit?.remaining,
      queriedAt: res.queryTimestamp,
      observedAt: res.observedTimestamp
    });

    let primaryEvidenceSourceId: string | undefined;
    for (const src of res.sourceReferences) {
      const evId = crypto.randomUUID();
      if (!primaryEvidenceSourceId) primaryEvidenceSourceId = evId;
      evidenceSources.push({
        id: evId,
        investigationId,
        ownerId: input.userId,
        providerId: src.providerId,
        providerName: src.providerName,
        sourceUrl: src.sourceUrl,
        observedAt: src.observedAt,
        queriedAt: src.queriedAt,
        confidence: src.confidence,
        sensitivity: src.sensitivity,
        verificationStatus: src.verificationStatus,
        bookmarked: false,
        citationNote: src.citationNote,
        createdAt
      });
    }

    for (const f of res.findings) {
      const dedupKey = `${f.moduleCode}:${f.title.toLowerCase()}`;
      if (findingDedupKeys.has(dedupKey)) continue;
      findingDedupKeys.add(dedupKey);

      if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[highestSeverity]) {
        highestSeverity = f.severity;
      }

      const safeAttrs = sanitizeRecord(f.attributes);
      const redactedAttrs = f.redactedByDefault
        ? redactSensitiveAttributes(safeAttrs, false)
        : safeAttrs;

      findings.push({
        id: crypto.randomUUID(),
        investigationId,
        ownerId: input.userId,
        providerId: res.providerId,
        providerName: res.providerName,
        category: f.category,
        moduleCode: f.moduleCode,
        title: sanitizeText(f.title, 200),
        summary: sanitizeText(f.summary, 1000),
        severity: f.severity,
        confidence: f.confidence,
        sensitivity: f.sensitivity || 'public',
        redactedByDefault: Boolean(f.redactedByDefault),
        bookmarked: false,
        tags: (f.tags || []).map((t) => sanitizeText(t, 40)),
        attributes: redactedAttrs,
        unredactedAttributes: f.redactedByDefault ? safeAttrs : undefined,
        sourceUrl: f.sourceUrl,
        evidenceSourceId: primaryEvidenceSourceId,
        observedAt: f.observedAt || res.observedTimestamp,
        queriedAt: res.queryTimestamp,
        createdAt
      });
    }

    for (const ent of res.entities) {
      const normKey = ent.key.toLowerCase();
      if (!entityMap.has(normKey)) {
        const idx = entityMap.size;
        const angle = (idx * 2 * Math.PI) / Math.max(8, idx + 4);
        const radius = 220 + Math.floor(idx / 8) * 120;
        entityMap.set(normKey, {
          id: crypto.randomUUID(),
          investigationId,
          ownerId: input.userId,
          entityType: ent.entityType,
          label: sanitizeText(ent.label, 120),
          value: sanitizeText(ent.value, 256),
          confidence: ent.confidence,
          providerId: res.providerId,
          metadata: sanitizeRecord(ent.metadata || {}),
          positionX: Math.round(400 + radius * Math.cos(angle)),
          positionY: Math.round(250 + radius * Math.sin(angle)),
          observedAt: res.observedTimestamp,
          createdAt
        });
      }
    }

    for (const rel of res.relationships) {
      const sNode =
        entityMap.get(rel.sourceKey.toLowerCase()) || entityMap.get(rootKey);
      const tNode = entityMap.get(rel.targetKey.toLowerCase());
      if (!sNode || !tNode || sNode.id === tNode.id) continue;

      const edgeKey = `${sNode.id}->${tNode.id}:${rel.relationshipType}`;
      if (edgeDedupKeys.has(edgeKey)) continue;
      edgeDedupKeys.add(edgeKey);

      relationships.push({
        id: crypto.randomUUID(),
        investigationId,
        ownerId: input.userId,
        sourceEntityId: sNode.id,
        targetEntityId: tNode.id,
        relationshipType: sanitizeText(rel.relationshipType, 80),
        sourceProvider: res.providerName,
        evidenceId: findings[findings.length - 1]?.id,
        confidence: rel.confidence,
        verificationStatus: rel.verificationStatus || 'verified',
        observedAt: res.observedTimestamp,
        createdAt
      });
    }
  }

  const completedProviders = providerExecutions.filter(
    (p) => p.status === 'completed'
  ).length;
  const partialProviders = providerExecutions.filter(
    (p) => p.status === 'partial'
  ).length;
  const notConfiguredProviders = providerExecutions.filter(
    (p) => p.status === 'not_configured'
  ).length;
  const failedProviders = providerExecutions.filter(
    (p) => p.status === 'failed' || p.status === 'rate_limited'
  ).length;

  let overallStatus: InvestigationRecord['status'] = 'completed';
  if (completedProviders === 0 && partialProviders === 0 && failedProviders > 0) {
    overallStatus = 'failed';
  } else if (failedProviders > 0 || partialProviders > 0) {
    overallStatus = 'partial';
  }

  const entities = Array.from(entityMap.values());
  const completedAt = new Date().toISOString();

  const investigation: InvestigationRecord = {
    id: investigationId,
    workspaceId: workspace.id,
    ownerId: input.userId,
    title: sanitizeText(
      input.title || `${validation.targetType.toUpperCase()}: ${validation.normalizedValue}`,
      160
    ),
    targetType: validation.targetType,
    targetValue: input.targetValue,
    normalizedTarget: validation.normalizedValue,
    scope: context.scope,
    purpose: context.purpose,
    externalProviderConsent: externalConsent,
    status: overallStatus,
    tags: (input.tags || [validation.targetType]).map((t) => sanitizeText(t, 40)),
    summary: {
      totalProviders: providerExecutions.length,
      completedProviders,
      partialProviders,
      notConfiguredProviders,
      failedProviders,
      totalFindings: findings.length,
      totalEntities: entities.length,
      totalRelationships: relationships.length,
      highestSeverity
    },
    createdAt,
    updatedAt: completedAt,
    completedAt
  };

  saveInvestigationBundle({
    investigation,
    providerExecutions,
    evidenceSources,
    findings,
    entities,
    relationships,
    caseId: input.caseId
  });

  return {
    investigation,
    providerExecutions,
    evidenceSources,
    findings: findings.map(({ unredactedAttributes: _hidden, ...rest }) => rest),
    entities,
    relationships
  };
}
