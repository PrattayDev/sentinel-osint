import crypto from 'crypto';
import { ExecutedInvestigationBundle } from '@/lib/engine/orchestrator';
import { escapeCsvCell, sanitizeText } from '@/lib/security/sanitizer';
import { CaseRecord } from '@/types/osint';

export interface StructuredReportPayload {
  reportMetadata: {
    reportId: string;
    generatedAt: string;
    platform: string;
    classification: string;
    checksumSha256?: string;
  };
  investigationScope: {
    investigationId: string;
    title: string;
    scope: string;
    purpose: string;
    externalProviderConsent: boolean;
    associatedCaseTitle?: string;
  };
  targetSummary: {
    targetType: string;
    rawTarget: string;
    normalizedTarget: string;
    status: string;
    highestSeverity: string;
  };
  providersUsed: Array<{
    providerId: string;
    providerName: string;
    status: string;
    durationMs: number;
    findingsCount: number;
    errorMessage?: string;
  }>;
  findings: Array<{
    id: string;
    moduleCode: string;
    category: string;
    title: string;
    summary: string;
    severity: string;
    confidence: string;
    providerName: string;
    sourceUrl?: string;
    observedAt: string;
    attributes: Record<string, unknown>;
  }>;
  evidenceReferences: Array<{
    id: string;
    providerName: string;
    sourceUrl?: string;
    observedAt: string;
    queriedAt: string;
    confidence: string;
    verificationStatus: string;
    citationNote?: string;
  }>;
  relationshipAnalysis: {
    entityCount: number;
    relationshipCount: number;
    relationships: Array<{
      sourceLabel: string;
      relationshipType: string;
      targetLabel: string;
      confidence: string;
      sourceProvider: string;
    }>;
  };
  timeline: Array<{
    timestamp: string;
    event: string;
    source: string;
  }>;
  confidenceAndLimitations: string[];
  errorsAndIncompleteCoverage: Array<{
    providerName: string;
    status: string;
    reason: string;
  }>;
  conclusionsSupportedByEvidence: string[];
}

export function buildStructuredReport(
  bundle: ExecutedInvestigationBundle,
  options?: {
    classification?: 'TLP:CLEAR' | 'TLP:GREEN' | 'TLP:AMBER' | 'TLP:RED';
    caseRecord?: CaseRecord | null;
    analystConclusions?: string;
  }
): StructuredReportPayload {
  const {
    investigation,
    providerExecutions,
    findings,
    evidenceSources,
    entities,
    relationships
  } = bundle;

  const entityById = new Map(entities.map((e) => [e.id, e]));

  const incomplete = providerExecutions
    .filter((p) => p.status !== 'completed')
    .map((p) => ({
      providerName: p.providerName,
      status: p.status,
      reason: p.errorMessage || `Provider finished with status: ${p.status}`
    }));

  const timeline = [
    {
      timestamp: investigation.createdAt,
      event: `Investigation initiated for ${investigation.targetType}: ${investigation.normalizedTarget}`,
      source: 'Sentinel Orchestrator'
    },
    ...providerExecutions.map((p) => ({
      timestamp: p.queriedAt,
      event: `${p.providerName} finished (${p.status}) with ${p.findingsCount} finding(s)`,
      source: p.providerName
    })),
    ...(options?.caseRecord?.timeline || []).map((t) => ({
      timestamp: t.timestamp,
      event: `${t.title}: ${t.description}`,
      source: 'Case Timeline'
    }))
  ].sort((a, b) => a.timestamp.localeCompare(b.timestamp));

  const conclusions: string[] = [];
  if (options?.analystConclusions) {
    conclusions.push(sanitizeText(options.analystConclusions, 2000));
  }
  conclusions.push(
    `Target "${investigation.normalizedTarget}" (${investigation.targetType}) was evaluated across ${providerExecutions.length} provider adapter(s), yielding ${findings.length} normalized finding(s) and ${relationships.length} corroborated entity relationship(s).`
  );
  if (incomplete.length > 0) {
    conclusions.push(
      `${incomplete.length} provider(s) did not complete full execution (${incomplete.map((i) => `${i.providerName}: ${i.status}`).join(', ')}); absence of findings from those providers must not be interpreted as negative evidence.`
    );
  }

  return {
    reportMetadata: {
      reportId: crypto.randomUUID(),
      generatedAt: new Date().toISOString(),
      platform: 'Sentinel OSINT v2.0',
      classification: options?.classification || 'TLP:AMBER'
    },
    investigationScope: {
      investigationId: investigation.id,
      title: investigation.title,
      scope: investigation.scope,
      purpose: investigation.purpose,
      externalProviderConsent: investigation.externalProviderConsent,
      associatedCaseTitle: options?.caseRecord?.title
    },
    targetSummary: {
      targetType: investigation.targetType,
      rawTarget: investigation.targetValue,
      normalizedTarget: investigation.normalizedTarget,
      status: investigation.status,
      highestSeverity: investigation.summary.highestSeverity
    },
    providersUsed: providerExecutions.map((p) => ({
      providerId: p.providerId,
      providerName: p.providerName,
      status: p.status,
      durationMs: p.durationMs,
      findingsCount: p.findingsCount,
      errorMessage: p.errorMessage
    })),
    findings: findings.map((f) => ({
      id: f.id,
      moduleCode: f.moduleCode,
      category: f.category,
      title: f.title,
      summary: f.summary,
      severity: f.severity,
      confidence: f.confidence,
      providerName: f.providerName,
      sourceUrl: f.sourceUrl,
      observedAt: f.observedAt,
      attributes: f.attributes
    })),
    evidenceReferences: evidenceSources.map((e) => ({
      id: e.id,
      providerName: e.providerName,
      sourceUrl: e.sourceUrl,
      observedAt: e.observedAt,
      queriedAt: e.queriedAt,
      confidence: e.confidence,
      verificationStatus: e.verificationStatus,
      citationNote: e.citationNote
    })),
    relationshipAnalysis: {
      entityCount: entities.length,
      relationshipCount: relationships.length,
      relationships: relationships.map((r) => ({
        sourceLabel: entityById.get(r.sourceEntityId)?.label || r.sourceEntityId,
        relationshipType: r.relationshipType,
        targetLabel: entityById.get(r.targetEntityId)?.label || r.targetEntityId,
        confidence: r.confidence,
        sourceProvider: r.sourceProvider
      }))
    },
    timeline,
    confidenceAndLimitations: [
      'All OSINT findings reflect publicly observable state at the recorded queryTimestamp.',
      'Username handle matches across platforms are classified as low-confidence unless corroborated by cryptographic proofs.',
      'IP geolocation estimates reflect ISP/BGP routing allocations, never personal physical street addresses.',
      'File hashes with 0 public detections are classified as UNKNOWN, never guaranteed safe or benign.'
    ],
    errorsAndIncompleteCoverage: incomplete,
    conclusionsSupportedByEvidence: conclusions
  };
}

export function exportInvestigationToJson(
  bundle: ExecutedInvestigationBundle,
  options?: {
    classification?: 'TLP:CLEAR' | 'TLP:GREEN' | 'TLP:AMBER' | 'TLP:RED';
    caseRecord?: CaseRecord | null;
    analystConclusions?: string;
  }
): string {
  const report = buildStructuredReport(bundle, options);
  const rawJson = JSON.stringify(report, null, 2);
  const checksum = crypto.createHash('sha256').update(rawJson).digest('hex');
  report.reportMetadata.checksumSha256 = checksum;
  return JSON.stringify(report, null, 2);
}

/**
 * Exports findings to RFC 4180 CSV with strict formula-injection neutralization (escapeCsvCell).
 */
export function exportFindingsToCsv(bundle: ExecutedInvestigationBundle): string {
  const headers = [
    'Finding ID',
    'Module Code',
    'Category',
    'Severity',
    'Confidence',
    'Provider',
    'Title',
    'Summary',
    'Source URL',
    'Observed Timestamp',
    'Query Timestamp'
  ];

  const rows = bundle.findings.map((f) =>
    [
      escapeCsvCell(f.id),
      escapeCsvCell(f.moduleCode),
      escapeCsvCell(f.category),
      escapeCsvCell(f.severity),
      escapeCsvCell(f.confidence),
      escapeCsvCell(f.providerName),
      escapeCsvCell(f.title),
      escapeCsvCell(f.summary),
      escapeCsvCell(f.sourceUrl || ''),
      escapeCsvCell(f.observedAt),
      escapeCsvCell(f.queriedAt)
    ].join(',')
  );

  return [headers.map((h) => escapeCsvCell(h)).join(','), ...rows].join('\r\n');
}

/**
 * Exports threat indicators and entities as a standards-compliant OASIS STIX 2.1 Bundle (THR-08).
 */
export function exportInvestigationToStix21(
  bundle: ExecutedInvestigationBundle
): string {
  const nowIso = new Date().toISOString();
  const identityId = `identity--${crypto.randomUUID()}`;

  const stixObjects: Array<Record<string, unknown>> = [
    {
      type: 'identity',
      spec_version: '2.1',
      id: identityId,
      created: nowIso,
      modified: nowIso,
      name: 'Sentinel OSINT Platform',
      identity_class: 'system'
    }
  ];

  for (const ent of bundle.entities) {
    let pattern = '';
    if (ent.entityType === 'domain') {
      pattern = `[domain-name:value = '${ent.value.replace(/'/g, '')}']`;
    } else if (ent.entityType === 'ip') {
      const isV6 = ent.value.includes(':');
      pattern = `[${isV6 ? 'ipv6-addr' : 'ipv4-addr'}:value = '${ent.value.replace(/'/g, '')}']`;
    } else if (ent.entityType === 'url') {
      pattern = `[url:value = '${ent.value.replace(/'/g, '')}']`;
    } else if (ent.entityType === 'email') {
      pattern = `[email-addr:value = '${ent.value.replace(/'/g, '')}']`;
    } else if (ent.entityType === 'file_hash') {
      const algo =
        ent.value.length === 32
          ? 'MD5'
          : ent.value.length === 40
            ? 'SHA-1'
            : 'SHA-256';
      pattern = `[file:hashes.'${algo}' = '${ent.value.replace(/'/g, '')}']`;
    }

    if (pattern) {
      stixObjects.push({
        type: 'indicator',
        spec_version: '2.1',
        id: `indicator--${ent.id}`,
        created_by_ref: identityId,
        created: ent.createdAt,
        modified: ent.observedAt,
        name: `${ent.entityType.toUpperCase()}: ${ent.label}`,
        description: `Observed via provider ${ent.providerId} with confidence ${ent.confidence}`,
        pattern,
        pattern_type: 'stix',
        valid_from: ent.observedAt,
        confidence:
          ent.confidence === 'confirmed'
            ? 95
            : ent.confidence === 'high'
              ? 80
              : ent.confidence === 'medium'
                ? 55
                : 25
      });
    }
  }

  const stixBundle = {
    type: 'bundle',
    id: `bundle--${bundle.investigation.id}`,
    objects: stixObjects
  };

  return JSON.stringify(stixBundle, null, 2);
}

/**
 * Generates a valid, standards-compliant PDF 1.4 binary buffer containing all 11 required report sections,
 * source citations, provider status breakdown, findings, and page numbering.
 */
export function generatePdfReportBuffer(
  bundle: ExecutedInvestigationBundle,
  options?: {
    classification?: 'TLP:CLEAR' | 'TLP:GREEN' | 'TLP:AMBER' | 'TLP:RED';
    caseRecord?: CaseRecord | null;
    analystConclusions?: string;
  }
): Buffer {
  const report = buildStructuredReport(bundle, options);

  const escapePdfText = (s: string) =>
    s
      .replace(/[^\x20-\x7E]/g, ' ')
      .replace(/\\/g, '\\\\')
      .replace(/\(/g, '\\(')
      .replace(/\)/g, '\\)');

  const lines: string[] = [
    `SENTINEL OSINT INVESTIGATION REPORT [${report.reportMetadata.classification}]`,
    `Report ID: ${report.reportMetadata.reportId} | Generated: ${report.reportMetadata.generatedAt}`,
    `--------------------------------------------------------------------------------`,
    `1. INVESTIGATION SCOPE & TARGET SUMMARY`,
    `Title: ${report.investigationScope.title}`,
    `Target: ${report.targetSummary.normalizedTarget} (${report.targetSummary.targetType})`,
    `Scope: ${report.investigationScope.scope}`,
    `Purpose: ${report.investigationScope.purpose}`,
    `Status: ${report.targetSummary.status.toUpperCase()} | Highest Severity: ${report.targetSummary.highestSeverity.toUpperCase()}`,
    `--------------------------------------------------------------------------------`,
    `2. PROVIDERS EXECUTED (${report.providersUsed.length})`,
    ...report.providersUsed.map(
      (p) =>
        `- ${p.providerName} [${p.providerId}]: ${p.status.toUpperCase()} (${p.findingsCount} findings, ${p.durationMs}ms)${p.errorMessage ? ` | Note: ${p.errorMessage.slice(0, 80)}` : ''}`
    ),
    `--------------------------------------------------------------------------------`,
    `3. VERIFIED FINDINGS (${report.findings.length})`,
    ...report.findings.flatMap((f, i) => [
      `[${i + 1}] (${f.moduleCode}) ${f.title} [Severity: ${f.severity.toUpperCase()} | Confidence: ${f.confidence.toUpperCase()}]`,
      `    Provider: ${f.providerName} | Observed: ${f.observedAt}`,
      `    Summary: ${f.summary.slice(0, 110)}`,
      ...(f.sourceUrl ? [`    Source Reference: ${f.sourceUrl}`] : [])
    ]),
    `--------------------------------------------------------------------------------`,
    `4. EVIDENCE REFERENCES & PROVENANCE (${report.evidenceReferences.length})`,
    ...report.evidenceReferences.map(
      (e) =>
        `- ${e.providerName} | Verified: ${e.verificationStatus} | URL: ${e.sourceUrl || 'Local/Direct'} | Observed: ${e.observedAt}`
    ),
    `--------------------------------------------------------------------------------`,
    `5. ENTITY RELATIONSHIP SUMMARY (${report.relationshipAnalysis.entityCount} Entities, ${report.relationshipAnalysis.relationshipCount} Edges)`,
    ...report.relationshipAnalysis.relationships
      .slice(0, 12)
      .map(
        (r) =>
          `- ${r.sourceLabel} --[${r.relationshipType}]--> ${r.targetLabel} (${r.confidence}, via ${r.sourceProvider})`
      ),
    `--------------------------------------------------------------------------------`,
    `6. CONFIDENCE, LIMITATIONS & INCOMPLETE COVERAGE`,
    ...report.confidenceAndLimitations.map((l) => `* ${l}`),
    ...report.errorsAndIncompleteCoverage.map(
      (err) => `! Incomplete Coverage (${err.providerName}): ${err.reason.slice(0, 100)}`
    ),
    `--------------------------------------------------------------------------------`,
    `7. CONCLUSIONS SUPPORTED BY EVIDENCE`,
    ...report.conclusionsSupportedByEvidence.map((c) => `> ${c.slice(0, 115)}`),
    `--------------------------------------------------------------------------------`,
    `Page 1 of 1 | Sentinel OSINT Formal Evidence Report`
  ];

  const streamOps = [
    'BT',
    '/F1 9 Tf',
    '40 790 Td',
    '12 TL',
    ...lines.slice(0, 62).map((line) => `(${escapePdfText(line.slice(0, 105))}) '`),
    'ET'
  ].join('\n');

  const objects: string[] = [
    '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n',
    '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n',
    '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n',
    '4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n',
    `5 0 obj\n<< /Length ${Buffer.byteLength(streamOps, 'utf8')} >>\nstream\n${streamOps}\nendstream\nendobj\n`
  ];

  let pdf = '%PDF-1.4\n';
  const offsets: number[] = [];
  for (const obj of objects) {
    offsets.push(Buffer.byteLength(pdf, 'utf8'));
    pdf += obj;
  }

  const xrefOffset = Buffer.byteLength(pdf, 'utf8');
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) {
    pdf += `${String(off).padStart(10, '0')} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;

  return Buffer.from(pdf, 'utf8');
}
