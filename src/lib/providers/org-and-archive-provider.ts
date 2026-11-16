import {
  DiscoveredEntityInput,
  DiscoveredRelationshipInput,
  InvestigationContext,
  NormalizedFindingInput,
  OsintProvider,
  ProviderResult
} from '@/types/osint';
import {
  validateAndNormalizeDomain,
  validateAndNormalizeOrganization,
  validateAndNormalizeUrl
} from '@/lib/validation/schemas';
import { sanitizeText } from '@/lib/security/sanitizer';
import { inspectUploadedFile } from '@/lib/security/file-validator';

export class WaybackArchiveProvider
  implements OsintProvider<string, Record<string, unknown>>
{
  id = 'wayback-archive';
  name = 'Internet Archive Wayback Machine & CDX Historical Index';
  category = 'search' as const;
  supportedTypes = ['url' as const, 'domain' as const];
  requiresApiKey = false;
  envVarNames: string[] = [];
  isFreeTierAvailable = true;
  rateLimitPerMinute = 20;
  disclosureNotice =
    'Queries the Internet Archive Wayback Availability and CDX APIs for historical captures.';
  featureIds = ['WEB-08', 'WEB-09', 'SRCH-04', 'SRCH-05'];

  isConfigured(): boolean {
    return true;
  }

  validateInput(input: unknown): string {
    const raw = String(input || '').trim();
    if (/^https?:\/\//i.test(raw)) {
      const u = validateAndNormalizeUrl(raw);
      if (!u.valid) throw new Error(u.error);
      return u.normalizedValue;
    }
    const d = validateAndNormalizeDomain(raw);
    if (!d.valid) throw new Error(d.error);
    return d.normalizedValue;
  }

  async execute(
    input: string,
    _context: InvestigationContext
  ): Promise<ProviderResult<Record<string, unknown>>> {
    const startMs = Date.now();
    const queryTimestamp = new Date().toISOString();
    const target = this.validateInput(input);

    const availUrl = `https://archive.org/wayback/available?url=${encodeURIComponent(target)}`;
    const cdxUrl = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(target)}&output=json&limit=12&fl=timestamp,original,mimetype,statuscode,digest`;

    try {
      const [availRes, cdxRes] = await Promise.allSettled([
        fetch(availUrl, { signal: AbortSignal.timeout(6500) }).then((r) =>
          r.ok ? r.json() : null
        ),
        fetch(cdxUrl, { signal: AbortSignal.timeout(6500) }).then((r) =>
          r.ok ? r.json() : null
        )
      ]);

      const closest =
        availRes.status === 'fulfilled' && availRes.value
          ? (
              availRes.value as {
                archived_snapshots?: {
                  closest?: {
                    available?: boolean;
                    url?: string;
                    timestamp?: string;
                    status?: string;
                  };
                };
              }
            ).archived_snapshots?.closest
          : undefined;

      const cdxRows =
        cdxRes.status === 'fulfilled' && Array.isArray(cdxRes.value)
          ? (cdxRes.value as string[][]).slice(1)
          : [];

      const captures = cdxRows.map((row) => ({
        timestamp: sanitizeText(row[0], 20),
        originalUrl: sanitizeText(row[1], 200),
        mimeType: sanitizeText(row[2], 64),
        statusCode: sanitizeText(row[3], 16),
        digest: sanitizeText(row[4], 64),
        archiveUrl: `https://web.archive.org/web/${sanitizeText(row[0], 20)}/${sanitizeText(row[1], 200)}`
      }));

      const findings: NormalizedFindingInput[] = [
        {
          moduleCode: 'WEB-09',
          category: 'search',
          title: `Wayback Machine Archive Availability (${closest?.available ? 'Archived' : `${captures.length} CDX Capture(s)`})`,
          summary: closest?.available
            ? `Latest snapshot captured at ${closest.timestamp} (HTTP ${closest.status}): ${closest.url}.`
            : captures.length > 0
              ? `Found ${captures.length} historical CDX capture records on web.archive.org.`
              : `No Wayback Machine snapshots currently indexed for ${target}.`,
          severity: 'info',
          confidence: 'confirmed',
          tags: ['wayback-machine', 'historical-archive', 'cdx'],
          attributes: {
            target,
            available: Boolean(closest?.available || captures.length > 0),
            closestSnapshotUrl: closest?.url || captures[0]?.archiveUrl || null,
            closestTimestamp: closest?.timestamp || captures[0]?.timestamp || null,
            historicalCaptures: captures
          },
          sourceUrl:
            closest?.url ||
            `https://web.archive.org/web/*/${encodeURIComponent(target)}`
        }
      ];

      const observedTimestamp = new Date().toISOString();
      return {
        providerId: this.id,
        providerName: this.name,
        status: 'completed',
        findings,
        entities: [],
        relationships: [],
        sourceReferences: [
          {
            providerId: this.id,
            providerName: this.name,
            sourceUrl: `https://web.archive.org/web/*/${encodeURIComponent(target)}`,
            observedAt: observedTimestamp,
            queriedAt: queryTimestamp,
            confidence: 'confirmed',
            sensitivity: 'public',
            verificationStatus: 'verified',
            citationNote: `Internet Archive Wayback & CDX index for ${target}`
          }
        ],
        rawResult: {
          closest,
          captures
        },
        observedTimestamp,
        queryTimestamp,
        durationMs: Date.now() - startMs,
        errors: [],
        confidence: 'confirmed',
        sensitivity: 'public'
      };
    } catch (err) {
      return {
        providerId: this.id,
        providerName: this.name,
        status: 'partial',
        findings: [],
        entities: [],
        relationships: [],
        sourceReferences: [],
        observedTimestamp: new Date().toISOString(),
        queryTimestamp,
        durationMs: Date.now() - startMs,
        errors: [`Wayback Archive note: ${(err as Error).message}`],
        confidence: 'medium',
        sensitivity: 'public'
      };
    }
  }
}

export class GleifOrganizationProvider
  implements OsintProvider<string, Record<string, unknown>>
{
  id = 'gleif-lei';
  name = 'GLEIF Global Legal Entity Identifier Registry & Corporate Hierarchy';
  category = 'organization' as const;
  supportedTypes = ['organization' as const];
  requiresApiKey = false;
  envVarNames: string[] = [];
  isFreeTierAvailable = true;
  rateLimitPerMinute = 30;
  disclosureNotice =
    'Queries the official GLEIF Global LEI Index API (api.gleif.org) and Wikipedia OpenSearch for public corporate registry records.';
  featureIds = ['ORG-01', 'ORG-03', 'ORG-04', 'ORG-06', 'ORG-08', 'SRCH-01', 'SRCH-02'];

  isConfigured(): boolean {
    return true;
  }

  validateInput(input: unknown): string {
    const val = validateAndNormalizeOrganization(String(input || ''));
    if (!val.valid) throw new Error(val.error);
    return val.normalizedValue;
  }

  async execute(
    input: string,
    _context: InvestigationContext
  ): Promise<ProviderResult<Record<string, unknown>>> {
    const startMs = Date.now();
    const queryTimestamp = new Date().toISOString();
    const orgName = this.validateInput(input);

    const gleifUrl = `https://api.gleif.org/api/v1/lei-records?filter[entity.legalName]=${encodeURIComponent(orgName)}&page[size]=5`;
    const wikiUrl = `https://en.wikipedia.org/w/api.php?action=opensearch&search=${encodeURIComponent(orgName)}&limit=5&namespace=0&format=json`;

    const [gleifRes, wikiRes] = await Promise.allSettled([
      fetch(gleifUrl, {
        headers: { Accept: 'application/vnd.api+json' },
        signal: AbortSignal.timeout(7000)
      }).then((r) => (r.ok ? r.json() : null)),
      fetch(wikiUrl, {
        headers: { 'User-Agent': 'Sentinel-OSINT/2.0' },
        signal: AbortSignal.timeout(5500)
      }).then((r) => (r.ok ? r.json() : null))
    ]);

    const findings: NormalizedFindingInput[] = [];
    const entities: DiscoveredEntityInput[] = [
      {
        key: `org:${orgName.toLowerCase()}`,
        entityType: 'organization',
        label: orgName,
        value: orgName,
        confidence: 'confirmed'
      }
    ];
    const relationships: DiscoveredRelationshipInput[] = [];

    const leiRecords =
      gleifRes.status === 'fulfilled' &&
      gleifRes.value &&
      Array.isArray((gleifRes.value as { data?: unknown[] }).data)
        ? ((gleifRes.value as { data: Array<Record<string, unknown>> }).data ?? [])
        : [];

    if (leiRecords.length > 0) {
      const formattedRecords = leiRecords.map((rec) => {
        const attr = (rec.attributes || {}) as Record<string, unknown>;
        const entity = (attr.entity || {}) as Record<string, unknown>;
        const legalName = sanitizeText(
          (entity.legalName as { name?: string } | undefined)?.name || orgName,
          160
        );
        const jurisdiction = sanitizeText(entity.jurisdiction || '', 32);
        const status = sanitizeText(entity.status || '', 32);
        const legalAddress = (entity.legalAddress || {}) as Record<string, unknown>;
        const city = sanitizeText(legalAddress.city || '', 80);
        const country = sanitizeText(legalAddress.country || '', 32);
        const lei = sanitizeText(attr.lei || rec.id || '', 40);

        return {
          lei,
          legalName,
          jurisdiction,
          status,
          headquarters: [city, country].filter(Boolean).join(', ')
        };
      });

      findings.push({
        moduleCode: 'ORG-03',
        category: 'organization',
        title: `GLEIF Global Legal Entity Registry (${formattedRecords.length} Verified LEI Record(s))`,
        summary: formattedRecords
          .map(
            (r) =>
              `${r.legalName} [LEI: ${r.lei}] (${r.jurisdiction || r.headquarters} — ${r.status})`
          )
          .join(' | '),
        severity: 'info',
        confidence: 'confirmed',
        tags: ['gleif', 'lei', 'business-registry', 'corporate'],
        attributes: {
          query: orgName,
          recordCount: formattedRecords.length,
          records: formattedRecords
        },
        sourceUrl: `https://search.gleif.org/#/search/simpleSearch=${encodeURIComponent(orgName)}`
      });

      for (const rec of formattedRecords) {
        const subKey = `org:lei:${rec.lei}`;
        entities.push({
          key: subKey,
          entityType: 'organization',
          label: `${rec.legalName} (${rec.jurisdiction})`,
          value: rec.lei,
          confidence: 'confirmed',
          metadata: rec
        });
        relationships.push({
          sourceKey: `org:${orgName.toLowerCase()}`,
          targetKey: subKey,
          relationshipType: 'registered_legal_entity',
          confidence: 'confirmed'
        });
      }
    }

    // Wikipedia OpenSearch public references (ORG-01, SRCH-01)
    if (wikiRes.status === 'fulfilled' && Array.isArray(wikiRes.value)) {
      const titles = Array.isArray(wikiRes.value[1])
        ? (wikiRes.value[1] as string[])
        : [];
      const links = Array.isArray(wikiRes.value[3])
        ? (wikiRes.value[3] as string[])
        : [];

      if (titles.length > 0) {
        const dedupedResults = titles.map((t, idx) => ({
          title: sanitizeText(t, 120),
          url: sanitizeText(links[idx] || '', 250)
        }));

        findings.push({
          moduleCode: 'ORG-01',
          category: 'organization',
          title: `Public Encyclopedia & Organization References (${dedupedResults.length} entry)`,
          summary: `Public reference entries matching "${orgName}": ${dedupedResults.map((d) => d.title).join(', ')}.`,
          severity: 'info',
          confidence: 'high',
          tags: ['organization', 'public-reference'],
          attributes: {
            results: dedupedResults
          },
          sourceUrl: dedupedResults[0]?.url
        });
      }
    }

    const observedTimestamp = new Date().toISOString();
    return {
      providerId: this.id,
      providerName: this.name,
      status: findings.length > 0 ? 'completed' : 'partial',
      findings,
      entities,
      relationships,
      sourceReferences: [
        {
          providerId: this.id,
          providerName: this.name,
          sourceUrl: `https://search.gleif.org/#/search/simpleSearch=${encodeURIComponent(orgName)}`,
          observedAt: observedTimestamp,
          queriedAt: queryTimestamp,
          confidence: 'confirmed',
          sensitivity: 'public',
          verificationStatus: 'verified',
          citationNote: `GLEIF Global LEI Registry lookup for "${orgName}"`
        }
      ],
      rawResult: {
        orgName,
        leiCount: leiRecords.length
      },
      observedTimestamp,
      queryTimestamp,
      durationMs: Date.now() - startMs,
      errors: [],
      confidence: 'confirmed',
      sensitivity: 'public'
    };
  }
}

export class BraveWebSearchProvider
  implements OsintProvider<string, Record<string, unknown>>
{
  id = 'brave-search';
  name = 'Brave Search Official Web Index API';
  category = 'search' as const;
  supportedTypes = [
    'domain' as const,
    'organization' as const,
    'username' as const,
    'email' as const
  ];
  requiresApiKey = true;
  envVarNames = ['BRAVE_SEARCH_API_KEY'];
  isFreeTierAvailable = true;
  rateLimitPerMinute = 15;
  disclosureNotice =
    'Queries the official Brave Web Search REST API when BRAVE_SEARCH_API_KEY is configured.';
  featureIds = ['SRCH-01', 'SRCH-02', 'SRCH-03', 'WEB-12'];

  isConfigured(): boolean {
    return Boolean(process.env.BRAVE_SEARCH_API_KEY?.trim());
  }

  validateInput(input: unknown): string {
    const clean = sanitizeText(input, 200);
    if (!clean) throw new Error('Search query cannot be empty.');
    return clean;
  }

  async execute(
    input: string,
    _context: InvestigationContext
  ): Promise<ProviderResult<Record<string, unknown>>> {
    const queryTimestamp = new Date().toISOString();
    const query = this.validateInput(input);

    if (!this.isConfigured()) {
      return {
        providerId: this.id,
        providerName: this.name,
        status: 'not_configured',
        findings: [],
        entities: [],
        relationships: [],
        sourceReferences: [],
        observedTimestamp: queryTimestamp,
        queryTimestamp,
        durationMs: 0,
        errors: ['BRAVE_SEARCH_API_KEY is not configured in environment.'],
        confidence: 'low',
        sensitivity: 'public'
      };
    }

    const startMs = Date.now();
    try {
      const res = await fetch(
        `https://api.search.brave.com/res/v1/web/search?q=${encodeURIComponent(query)}&count=10`,
        {
          headers: {
            'X-Subscription-Token': process.env.BRAVE_SEARCH_API_KEY!.trim(),
            Accept: 'application/json'
          },
          signal: AbortSignal.timeout(6500)
        }
      );
      if (res.status === 429) {
        return {
          providerId: this.id,
          providerName: this.name,
          status: 'rate_limited',
          findings: [],
          entities: [],
          relationships: [],
          sourceReferences: [],
          observedTimestamp: new Date().toISOString(),
          queryTimestamp,
          durationMs: Date.now() - startMs,
          errors: ['Brave Search API rate limit reached.'],
          confidence: 'low',
          sensitivity: 'public'
        };
      }
      if (!res.ok) throw new Error(`Brave Search returned HTTP ${res.status}`);
      const data = (await res.json()) as {
        web?: {
          results?: Array<{ title?: string; url?: string; description?: string }>;
        };
      };
      const rawResults = data.web?.results || [];
      const seenUrls = new Set<string>();
      const dedupedResults = rawResults
        .map((r) => ({
          title: sanitizeText(r.title, 160),
          url: sanitizeText(r.url, 300),
          description: sanitizeText(r.description, 300)
        }))
        .filter((r) => {
          if (!r.url || seenUrls.has(r.url)) return false;
          seenUrls.add(r.url);
          return true;
        });

      const observedTimestamp = new Date().toISOString();
      return {
        providerId: this.id,
        providerName: this.name,
        status: 'completed',
        findings: [
          {
            moduleCode: 'SRCH-01',
            category: 'search',
            title: `Public Search Engine Indexing (${dedupedResults.length} Deduplicated Results)`,
            summary: dedupedResults
              .slice(0, 4)
              .map((r) => r.title)
              .join(' | '),
            severity: 'info',
            confidence: 'confirmed',
            tags: ['brave-search', 'web-index'],
            attributes: {
              query,
              results: dedupedResults
            }
          }
        ],
        entities: [],
        relationships: [],
        sourceReferences: [],
        rawResult: { results: dedupedResults },
        observedTimestamp,
        queryTimestamp,
        durationMs: Date.now() - startMs,
        errors: [],
        confidence: 'confirmed',
        sensitivity: 'public'
      };
    } catch (err) {
      return {
        providerId: this.id,
        providerName: this.name,
        status: 'failed',
        findings: [],
        entities: [],
        relationships: [],
        sourceReferences: [],
        observedTimestamp: new Date().toISOString(),
        queryTimestamp,
        durationMs: Date.now() - startMs,
        errors: [(err as Error).message],
        confidence: 'low',
        sensitivity: 'public'
      };
    }
  }
}

export class LocalFileIntelligenceProvider
  implements OsintProvider<string, Record<string, unknown>>
{
  id = 'file-metadata';
  name = 'Sandboxed Binary File EXIF, PDF & Hash Inspector';
  category = 'media' as const;
  supportedTypes = ['file' as const];
  requiresApiKey = false;
  envVarNames: string[] = [];
  isFreeTierAvailable = true;
  rateLimitPerMinute = 30;
  disclosureNotice =
    'Processes uploaded images and PDFs 100% locally in memory. Zero external file uploads are performed. GPS EXIF coordinates are redacted by default.';
  featureIds = [
    'IMG-01',
    'IMG-02',
    'IMG-03',
    'IMG-04',
    'IMG-05',
    'IMG-06',
    'IMG-07',
    'IMG-09',
    'IMG-10'
  ];

  isConfigured(): boolean {
    return true;
  }

  validateInput(input: unknown): string {
    return sanitizeText(input || 'upload.bin', 128);
  }

  async execute(
    input: string,
    context: InvestigationContext
  ): Promise<ProviderResult<Record<string, unknown>>> {
    const startMs = Date.now();
    const queryTimestamp = new Date().toISOString();
    const fileName = this.validateInput(input);

    if (!context.fileBuffer) {
      throw new Error('No file buffer supplied to LocalFileIntelligenceProvider.');
    }

    const report = inspectUploadedFile(context.fileBuffer, fileName);

    const findings: NormalizedFindingInput[] = [
      {
        moduleCode: 'IMG-02',
        category: 'media',
        title: `Cryptographic & Perceptual File Hashes (${report.detectedMime})`,
        summary: `SHA-256: ${report.hashes.sha256} | MD5: ${report.hashes.md5} | Perceptual dHash: ${report.hashes.perceptualDHash}.`,
        severity: 'info',
        confidence: 'confirmed',
        tags: ['file-hash', 'sha256', 'dhash', report.detectedMime],
        attributes: {
          fileName: report.fileName,
          mimeType: report.detectedMime,
          sizeBytes: report.sizeBytes,
          ...report.hashes,
          dimensions: report.dimensions || null
        }
      }
    ];

    if (Object.keys(report.exifMetadata).length > 0) {
      findings.push({
        moduleCode: 'IMG-01',
        category: 'media',
        title: `Embedded File & EXIF Metadata (${Object.keys(report.exifMetadata).length} field(s))`,
        summary: Object.entries(report.exifMetadata)
          .map(([k, v]) => `${k}: ${v}`)
          .join(' | '),
        severity: 'info',
        confidence: 'confirmed',
        tags: ['exif', 'metadata'],
        attributes: report.exifMetadata
      });
    }

    if (report.gpsMetadata.hasGps) {
      findings.push({
        moduleCode: 'IMG-09',
        category: 'media',
        title: `Sensitive EXIF Geolocation Metadata (REDACTED BY DEFAULT)`,
        summary:
          'Embedded GPS coordinates were detected in this image and are hidden by default per Sentinel privacy policy. Explicit analyst reveal is required.',
        severity: 'medium',
        confidence: 'confirmed',
        sensitivity: 'restricted',
        redactedByDefault: true,
        tags: ['exif-gps', 'sensitive-location', 'redacted'],
        attributes: {
          hasGps: true,
          gpsLatitude: report.gpsMetadata.gpsLatitude,
          gpsLongitude: report.gpsMetadata.gpsLongitude,
          privacyNotice:
            'Hidden by default to protect private location metadata.'
        }
      });
    }

    if (report.pdfMetadata) {
      findings.push({
        moduleCode: 'IMG-05',
        category: 'media',
        title: `PDF Container & Dictionary Inspection (PDF v${report.pdfMetadata.pdfVersion} — ~${report.pdfMetadata.pageCountEstimate} page(s))`,
        summary: `Title: ${report.pdfMetadata.title || 'None'} | Author: ${report.pdfMetadata.author || 'None'} | Producer: ${report.pdfMetadata.producer || 'None'} | Active JS/Launch: ${report.pdfMetadata.containsJavaScriptOrLaunchAction ? 'DETECTED' : 'None'}.`,
        severity: report.pdfMetadata.containsJavaScriptOrLaunchAction
          ? 'high'
          : 'info',
        confidence: 'confirmed',
        tags: ['pdf-metadata', 'document-intel'],
        attributes: { ...report.pdfMetadata }
      });
    }

    if (report.reverseImageWorkflowLinks) {
      findings.push({
        moduleCode: 'IMG-07',
        category: 'media',
        title: `Reverse Image Search Investigator Portals (Manual Reference Links)`,
        summary:
          'External reverse-image portals provided as manual reference workflows. Sentinel never uploads evidence files automatically.',
        severity: 'info',
        confidence: 'confirmed',
        tags: ['reverse-image-links'],
        attributes: {
          portals: report.reverseImageWorkflowLinks
        }
      });
    }

    const entities: DiscoveredEntityInput[] = [
      {
        key: `hash:${report.hashes.sha256}`,
        entityType: 'file_hash',
        label: `${report.fileName} (${report.hashes.sha256.slice(0, 10)}…)`,
        value: report.hashes.sha256,
        confidence: 'confirmed',
        metadata: {
          md5: report.hashes.md5,
          perceptualDHash: report.hashes.perceptualDHash,
          mimeType: report.detectedMime
        }
      }
    ];

    const observedTimestamp = new Date().toISOString();
    return {
      providerId: this.id,
      providerName: this.name,
      status: 'completed',
      findings,
      entities,
      relationships: [],
      sourceReferences: [
        {
          providerId: this.id,
          providerName: this.name,
          observedAt: observedTimestamp,
          queriedAt: queryTimestamp,
          confidence: 'confirmed',
          sensitivity: report.gpsMetadata.hasGps ? 'restricted' : 'public',
          verificationStatus: 'verified',
          citationNote: `Local binary inspection of ${report.fileName} (SHA-256: ${report.hashes.sha256})`
        }
      ],
      rawResult: report as unknown as Record<string, unknown>,
      observedTimestamp,
      queryTimestamp,
      durationMs: Date.now() - startMs,
      errors: [],
      confidence: 'confirmed',
      sensitivity: report.gpsMetadata.hasGps ? 'restricted' : 'public'
    };
  }
}
