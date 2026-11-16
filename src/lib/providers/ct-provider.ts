import {
  DiscoveredEntityInput,
  DiscoveredRelationshipInput,
  InvestigationContext,
  NormalizedFindingInput,
  OsintProvider,
  ProviderResult
} from '@/types/osint';
import { validateAndNormalizeDomain } from '@/lib/validation/schemas';
import { sanitizeText } from '@/lib/security/sanitizer';

interface CtDiscoveryResult {
  domain: string;
  certificateCount: number;
  passiveSubdomains: string[];
  issuers: string[];
  sourceUsed: string;
}

export class CertificateTransparencyProvider
  implements OsintProvider<string, CtDiscoveryResult>
{
  id = 'ct-logs';
  name = 'Certificate Transparency & Passive Subdomain Discovery';
  category = 'domain' as const;
  supportedTypes = ['domain' as const];
  requiresApiKey = false;
  envVarNames: string[] = [];
  isFreeTierAvailable = true;
  rateLimitPerMinute = 15;
  disclosureNotice =
    'Queries public Certificate Transparency logs (crt.sh and CertSpotter) for historical certificates and passive subdomains.';
  featureIds = ['DOM-06', 'DOM-07'];

  isConfigured(): boolean {
    return true;
  }

  validateInput(input: unknown): string {
    const domVal = validateAndNormalizeDomain(String(input || ''));
    if (!domVal.valid) throw new Error(domVal.error);
    return domVal.normalizedValue;
  }

  async execute(
    input: string,
    _context: InvestigationContext
  ): Promise<ProviderResult<CtDiscoveryResult>> {
    const startMs = Date.now();
    const queryTimestamp = new Date().toISOString();
    const domain = this.validateInput(input);

    const subdomains = new Set<string>();
    const issuers = new Set<string>();
    let certificateCount = 0;
    let sourceUsed = 'crt.sh';
    let sourceUrl = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;

    try {
      const crtRes = await fetch(sourceUrl, {
        headers: {
          Accept: 'application/json',
          'User-Agent': 'Sentinel-OSINT/2.0'
        },
        signal: AbortSignal.timeout(7500)
      });

      if (crtRes.ok) {
        const rows = (await crtRes.json()) as Array<{
          name_value?: string;
          common_name?: string;
          issuer_name?: string;
        }>;
        certificateCount = rows.length;
        for (const row of rows.slice(0, 300)) {
          if (row.issuer_name) {
            issuers.add(sanitizeText(row.issuer_name, 120));
          }
          const names = (row.name_value || row.common_name || '').split('\n');
          for (const rawName of names) {
            const clean = rawName
              .trim()
              .toLowerCase()
              .replace(/^\*\./, '');
            if (
              clean &&
              (clean === domain || clean.endsWith(`.${domain}`)) &&
              /^[a-z0-9.-]+$/.test(clean)
            ) {
              subdomains.add(clean);
            }
          }
        }
      } else {
        throw new Error(`crt.sh returned HTTP ${crtRes.status}`);
      }
    } catch {
      // Fallback to CertSpotter public CT issuance API
      try {
        sourceUsed = 'certspotter';
        sourceUrl = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names&expand=issuer`;
        const csRes = await fetch(sourceUrl, {
          headers: { Accept: 'application/json' },
          signal: AbortSignal.timeout(6500)
        });
        if (csRes.ok) {
          const items = (await csRes.json()) as Array<{
            dns_names?: string[];
            issuer?: { name?: string };
          }>;
          certificateCount = items.length;
          for (const item of items) {
            if (item.issuer?.name) {
              issuers.add(sanitizeText(item.issuer.name, 120));
            }
            for (const dnsName of item.dns_names || []) {
              const clean = dnsName.trim().toLowerCase().replace(/^\*\./, '');
              if (
                clean &&
                (clean === domain || clean.endsWith(`.${domain}`)) &&
                /^[a-z0-9.-]+$/.test(clean)
              ) {
                subdomains.add(clean);
              }
            }
          }
        }
      } catch (fallbackErr) {
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
          errors: [
            `CT log lookup timed out or rate-limited: ${(fallbackErr as Error).message}`
          ],
          confidence: 'medium',
          sensitivity: 'public'
        };
      }
    }

    const passiveSubdomains = Array.from(subdomains).sort().slice(0, 60);
    const issuerList = Array.from(issuers).slice(0, 10);

    const findings: NormalizedFindingInput[] = [
      {
        moduleCode: 'DOM-06',
        category: 'domain',
        title: `Certificate Transparency Log Analysis (${certificateCount} issuances)`,
        summary: `Observed ${certificateCount} certificate log entries via ${sourceUsed} across ${issuerList.length} issuing CAs.`,
        severity: 'info',
        confidence: 'confirmed',
        tags: ['ct-logs', 'certificates', sourceUsed],
        attributes: {
          domain,
          certificateCount,
          issuers: issuerList,
          sourceUsed
        },
        sourceUrl
      },
      {
        moduleCode: 'DOM-07',
        category: 'domain',
        title: `Passive Subdomain Discovery (${passiveSubdomains.length} unique hosts)`,
        summary:
          passiveSubdomains.length > 0
            ? `Discovered ${passiveSubdomains.length} subdomains passively from CT logs: ${passiveSubdomains.slice(0, 12).join(', ')}.`
            : `No additional subdomains observed in public CT logs for ${domain}.`,
        severity: 'info',
        confidence: 'confirmed',
        tags: ['subdomains', 'passive-recon', 'ct-logs'],
        attributes: {
          domain,
          subdomainCount: passiveSubdomains.length,
          subdomains: passiveSubdomains
        },
        sourceUrl
      }
    ];

    const entities: DiscoveredEntityInput[] = [
      {
        key: `domain:${domain}`,
        entityType: 'domain',
        label: domain,
        value: domain,
        confidence: 'confirmed'
      }
    ];
    const relationships: DiscoveredRelationshipInput[] = [];

    for (const sub of passiveSubdomains
      .filter((s) => s !== domain)
      .slice(0, 12)) {
      entities.push({
        key: `domain:${sub}`,
        entityType: 'domain',
        label: sub,
        value: sub,
        confidence: 'confirmed',
        metadata: { parentDomain: domain, discoveredVia: 'ct-logs' }
      });
      relationships.push({
        sourceKey: `domain:${sub}`,
        targetKey: `domain:${domain}`,
        relationshipType: 'subdomain_of',
        confidence: 'confirmed'
      });
    }

    const observedTimestamp = new Date().toISOString();
    return {
      providerId: this.id,
      providerName: this.name,
      status: 'completed',
      findings,
      entities,
      relationships,
      sourceReferences: [
        {
          providerId: this.id,
          providerName: this.name,
          sourceUrl,
          observedAt: observedTimestamp,
          queriedAt: queryTimestamp,
          confidence: 'confirmed',
          sensitivity: 'public',
          verificationStatus: 'verified',
          citationNote: `Certificate Transparency issuance logs via ${sourceUsed}`
        }
      ],
      rawResult: {
        domain,
        certificateCount,
        passiveSubdomains,
        issuers: issuerList,
        sourceUsed
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
