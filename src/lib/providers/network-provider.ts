import dns from 'dns/promises';
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
  validateAndNormalizeIp
} from '@/lib/validation/schemas';
import { sanitizeText } from '@/lib/security/sanitizer';

export class RipeStatBgpProvider
  implements OsintProvider<string, Record<string, unknown>>
{
  id = 'ripestat-bgp';
  name = 'RIPEstat BGP, ASN, Reverse DNS & Coarse GeoIP';
  category = 'network' as const;
  supportedTypes = ['ip' as const];
  requiresApiKey = false;
  envVarNames: string[] = [];
  isFreeTierAvailable = true;
  rateLimitPerMinute = 40;
  disclosureNotice =
    'Queries RIPE NCC RIPEstat public BGP/ASN API and performs standard Reverse DNS (PTR) lookup.';
  featureIds = ['NET-01', 'NET-03', 'NET-04', 'NET-05', 'NET-06', 'NET-08', 'NET-11'];

  isConfigured(): boolean {
    return true;
  }

  validateInput(input: unknown): string {
    const val = validateAndNormalizeIp(String(input || ''));
    if (!val.valid) throw new Error(val.error);
    return val.normalizedValue;
  }

  async execute(
    input: string,
    _context: InvestigationContext
  ): Promise<ProviderResult<Record<string, unknown>>> {
    const startMs = Date.now();
    const queryTimestamp = new Date().toISOString();
    const ip = this.validateInput(input);

    const netInfoUrl = `https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(ip)}`;
    const geoUrl = `https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=${encodeURIComponent(ip)}`;

    const [ptrRes, netRes, geoRes] = await Promise.allSettled([
      dns.reverse(ip),
      fetch(netInfoUrl, { signal: AbortSignal.timeout(6500) }).then((r) =>
        r.ok ? r.json() : null
      ),
      fetch(geoUrl, { signal: AbortSignal.timeout(6500) }).then((r) =>
        r.ok ? r.json() : null
      )
    ]);

    const ptrHostnames =
      ptrRes.status === 'fulfilled'
        ? ptrRes.value.map((h) => sanitizeText(h, 128).toLowerCase())
        : [];

    const netData =
      netRes.status === 'fulfilled' && netRes.value
        ? ((netRes.value as { data?: { asns?: string[]; prefix?: string } }).data ?? {})
        : {};
    const asns = Array.isArray(netData.asns) ? netData.asns.map(String) : [];
    const bgpPrefix = sanitizeText(netData.prefix || '', 64);

    let asHolder = '';
    const primaryAsn = asns[0];
    if (primaryAsn) {
      try {
        const asRes = await fetch(
          `https://stat.ripe.net/data/as-overview/data.json?resource=AS${encodeURIComponent(primaryAsn)}`,
          { signal: AbortSignal.timeout(5000) }
        );
        if (asRes.ok) {
          const asJson = (await asRes.json()) as {
            data?: { holder?: string };
          };
          asHolder = sanitizeText(asJson.data?.holder || '', 120);
        }
      } catch {
        // Optional holder enrichment
      }
    }

    let country = '';
    let city = '';
    if (geoRes.status === 'fulfilled' && geoRes.value) {
      const located = (
        geoRes.value as {
          data?: {
            located_resources?: Array<{
              locations?: Array<{ country?: string; city?: string }>;
            }>;
          };
        }
      ).data?.located_resources?.[0]?.locations?.[0];
      if (located) {
        country = sanitizeText(located.country || '', 32);
        city = sanitizeText(located.city || '', 64);
      }
    }

    const findings: NormalizedFindingInput[] = [
      {
        moduleCode: 'NET-03',
        category: 'network',
        title: `BGP Routing & Autonomous System (${primaryAsn ? `AS${primaryAsn}` : 'Unannounced'} — ${bgpPrefix || ip})`,
        summary: `Announced BGP Prefix: ${bgpPrefix || 'N/A'} | Originating ASN: ${asns.map((a) => `AS${a}`).join(', ') || 'None'} | Holder: ${asHolder || 'Unknown'}.`,
        severity: 'info',
        confidence: 'confirmed',
        tags: ['bgp', 'asn', 'ripestat'],
        attributes: {
          ip,
          asns: asns.map((a) => `AS${a}`),
          asHolder: asHolder || null,
          bgpPrefix: bgpPrefix || null
        },
        sourceUrl: netInfoUrl
      },
      {
        moduleCode: 'NET-05',
        category: 'network',
        title: `Reverse DNS (PTR) Resolution (${ptrHostnames.length} record(s))`,
        summary:
          ptrHostnames.length > 0
            ? `IP ${ip} resolves via PTR to: ${ptrHostnames.join(', ')}.`
            : `No Reverse DNS (PTR) records configured for ${ip}.`,
        severity: 'info',
        confidence: 'confirmed',
        tags: ['ptr', 'reverse-dns'],
        attributes: {
          ip,
          ptrHostnames
        }
      }
    ];

    if (country || city) {
      findings.push({
        moduleCode: 'NET-06',
        category: 'network',
        title: `Network-Level Geolocation Estimate (${[city, country].filter(Boolean).join(', ')})`,
        summary: `Coarse network registration/PoP estimate: ${[city, country].filter(Boolean).join(', ')}. DISCLAIMER: GeoIP reflects ISP/network routing allocation, NOT precise personal or physical street location.`,
        severity: 'info',
        confidence: 'medium',
        tags: ['geoip', 'network-estimate'],
        attributes: {
          ip,
          country: country || null,
          city: city || null,
          precisionDisclaimer:
            'Network-level routing estimate only; never interpret as exact physical location of an individual.'
        },
        sourceUrl: geoUrl
      });
    }

    const entities: DiscoveredEntityInput[] = [
      {
        key: `ip:${ip}`,
        entityType: 'ip',
        label: ip,
        value: ip,
        confidence: 'confirmed',
        metadata: { bgpPrefix, country }
      }
    ];
    const relationships: DiscoveredRelationshipInput[] = [];

    if (primaryAsn) {
      const asnKey = `asn:AS${primaryAsn}`;
      entities.push({
        key: asnKey,
        entityType: 'asn',
        label: `AS${primaryAsn}${asHolder ? ` (${asHolder})` : ''}`,
        value: `AS${primaryAsn}`,
        confidence: 'confirmed',
        metadata: { holder: asHolder, prefix: bgpPrefix }
      });
      relationships.push({
        sourceKey: `ip:${ip}`,
        targetKey: asnKey,
        relationshipType: 'belongs_to_asn',
        confidence: 'confirmed'
      });
    }

    for (const ptr of ptrHostnames.slice(0, 5)) {
      entities.push({
        key: `domain:${ptr}`,
        entityType: 'domain',
        label: ptr,
        value: ptr,
        confidence: 'confirmed',
        metadata: { discoveredVia: 'ptr' }
      });
      relationships.push({
        sourceKey: `ip:${ip}`,
        targetKey: `domain:${ptr}`,
        relationshipType: 'reverse_resolves_to',
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
          sourceUrl: netInfoUrl,
          observedAt: observedTimestamp,
          queriedAt: queryTimestamp,
          confidence: 'confirmed',
          sensitivity: 'public',
          verificationStatus: 'verified',
          citationNote: `RIPEstat BGP/ASN & PTR intelligence for ${ip}`
        }
      ],
      rawResult: {
        ip,
        asns,
        asHolder,
        bgpPrefix,
        ptrHostnames,
        country,
        city
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

export class ShodanInternetDbProvider
  implements OsintProvider<string, Record<string, unknown>>
{
  id = 'shodan-internetdb';
  name = 'Shodan InternetDB Passive Service & CVE Observations';
  category = 'network' as const;
  supportedTypes = ['ip' as const];
  requiresApiKey = false;
  envVarNames: string[] = [];
  isFreeTierAvailable = true;
  rateLimitPerMinute = 30;
  disclosureNotice =
    'Queries Shodan InternetDB (internetdb.shodan.io) for passive port, CPE, hostname, and CVE observations. Zero active packets are sent to the target IP.';
  featureIds = ['NET-09', 'THR-04'];

  isConfigured(): boolean {
    return true;
  }

  validateInput(input: unknown): string {
    const val = validateAndNormalizeIp(String(input || ''));
    if (!val.valid) throw new Error(val.error);
    return val.normalizedValue;
  }

  async execute(
    input: string,
    _context: InvestigationContext
  ): Promise<ProviderResult<Record<string, unknown>>> {
    const startMs = Date.now();
    const queryTimestamp = new Date().toISOString();
    const ip = this.validateInput(input);
    const url = `https://internetdb.shodan.io/${encodeURIComponent(ip)}`;

    try {
      const res = await fetch(url, {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(6500)
      });

      if (res.status === 404) {
        const observedTimestamp = new Date().toISOString();
        return {
          providerId: this.id,
          providerName: this.name,
          status: 'completed',
          findings: [
            {
              moduleCode: 'NET-09',
              category: 'network',
              title: `Passive Service Observations (0 Open Ports Indexed)`,
              summary: `Shodan InternetDB has no indexed open ports or passive vulnerability observations for ${ip}.`,
              severity: 'info',
              confidence: 'high',
              tags: ['passive-recon', 'shodan-internetdb'],
              attributes: {
                ip,
                ports: [],
                cpes: [],
                hostnames: [],
                vulns: []
              },
              sourceUrl: url
            }
          ],
          entities: [],
          relationships: [],
          sourceReferences: [
            {
              providerId: this.id,
              providerName: this.name,
              sourceUrl: url,
              observedAt: observedTimestamp,
              queriedAt: queryTimestamp,
              confidence: 'high',
              sensitivity: 'public',
              verificationStatus: 'verified'
            }
          ],
          rawResult: { ip, ports: [], vulns: [] },
          observedTimestamp,
          queryTimestamp,
          durationMs: Date.now() - startMs,
          errors: [],
          confidence: 'high',
          sensitivity: 'public'
        };
      }

      if (!res.ok) {
        throw new Error(`Shodan InternetDB returned HTTP ${res.status}`);
      }

      const data = (await res.json()) as {
        ip?: string;
        ports?: number[];
        cpes?: string[];
        hostnames?: string[];
        tags?: string[];
        vulns?: string[];
      };

      const ports = Array.isArray(data.ports) ? data.ports : [];
      const cpes = Array.isArray(data.cpes) ? data.cpes : [];
      const hostnames = Array.isArray(data.hostnames) ? data.hostnames : [];
      const tags = Array.isArray(data.tags) ? data.tags : [];
      const vulns = Array.isArray(data.vulns) ? data.vulns : [];

      const findings: NormalizedFindingInput[] = [
        {
          moduleCode: 'NET-09',
          category: 'network',
          title: `Passive Service Observations (${ports.length} Open Ports, ${cpes.length} CPEs)`,
          summary: `Passively observed ports on ${ip}: [${ports.join(', ') || 'none'}]. CPEs: [${cpes.join(', ') || 'none'}]. Tags: [${tags.join(', ') || 'none'}].`,
          severity: vulns.length > 0 ? 'high' : ports.length > 5 ? 'medium' : 'info',
          confidence: 'confirmed',
          tags: ['passive-ports', 'shodan-internetdb', ...tags],
          attributes: {
            ip,
            ports,
            cpes,
            hostnames,
            tags,
            vulnsCount: vulns.length,
            vulns: vulns.slice(0, 30),
            collectionMethod: 'Strictly passive observation via Shodan InternetDB'
          },
          sourceUrl: url
        }
      ];

      const entities: DiscoveredEntityInput[] = [
        {
          key: `ip:${ip}`,
          entityType: 'ip',
          label: ip,
          value: ip,
          confidence: 'confirmed'
        }
      ];
      const relationships: DiscoveredRelationshipInput[] = [];

      for (const h of hostnames.slice(0, 6)) {
        const cleanHost = sanitizeText(h, 128).toLowerCase();
        entities.push({
          key: `domain:${cleanHost}`,
          entityType: 'domain',
          label: cleanHost,
          value: cleanHost,
          confidence: 'high',
          metadata: { discoveredVia: 'shodan-internetdb' }
        });
        relationships.push({
          sourceKey: `ip:${ip}`,
          targetKey: `domain:${cleanHost}`,
          relationshipType: 'associated_hostname',
          confidence: 'high'
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
            sourceUrl: url,
            observedAt: observedTimestamp,
            queriedAt: queryTimestamp,
            confidence: 'confirmed',
            sensitivity: 'public',
            verificationStatus: 'verified',
            citationNote: `Passive port/CPE index for ${ip} via Shodan InternetDB`
          }
        ],
        rawResult: data as Record<string, unknown>,
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

export class ShodanFullApiProvider
  implements OsintProvider<string, Record<string, unknown>>
{
  id = 'shodan-full';
  name = 'Shodan Enterprise Host History API';
  category = 'network' as const;
  supportedTypes = ['ip' as const];
  requiresApiKey = true;
  envVarNames = ['SHODAN_API_KEY'];
  isFreeTierAvailable = false;
  rateLimitPerMinute = 20;
  disclosureNotice = 'Queries api.shodan.io with SHODAN_API_KEY when configured.';
  featureIds = ['NET-09', 'NET-10'];

  isConfigured(): boolean {
    return Boolean(process.env.SHODAN_API_KEY?.trim());
  }

  validateInput(input: unknown): string {
    const val = validateAndNormalizeIp(String(input || ''));
    if (!val.valid) throw new Error(val.error);
    return val.normalizedValue;
  }

  async execute(
    input: string,
    _context: InvestigationContext
  ): Promise<ProviderResult<Record<string, unknown>>> {
    const startMs = Date.now();
    const queryTimestamp = new Date().toISOString();
    const ip = this.validateInput(input);

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
        errors: ['SHODAN_API_KEY is not configured in environment.'],
        confidence: 'low',
        sensitivity: 'public'
      };
    }

    const apiKey = process.env.SHODAN_API_KEY!.trim();
    const endpoint = `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(apiKey)}`;

    try {
      const res = await fetch(endpoint, { signal: AbortSignal.timeout(7000) });
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
          errors: ['Shodan API rate limit exceeded.'],
          confidence: 'low',
          sensitivity: 'public'
        };
      }
      if (!res.ok) {
        throw new Error(`Shodan API returned HTTP ${res.status}`);
      }
      const data = (await res.json()) as Record<string, unknown>;
      const observedTimestamp = new Date().toISOString();
      return {
        providerId: this.id,
        providerName: this.name,
        status: 'completed',
        findings: [
          {
            moduleCode: 'NET-10',
            category: 'network',
            title: `Shodan Host Banner & Historical Observation (${ip})`,
            summary: `Organization: ${sanitizeText(data.org, 100) || 'N/A'} | ISP: ${sanitizeText(data.isp, 100) || 'N/A'} | Last Update: ${sanitizeText(data.last_update, 64) || 'N/A'}.`,
            severity: 'info',
            confidence: 'confirmed',
            tags: ['shodan', 'passive-banners'],
            attributes: {
              ip,
              org: data.org,
              isp: data.isp,
              os: data.os,
              ports: data.ports,
              lastUpdate: data.last_update
            },
            sourceUrl: `https://www.shodan.io/host/${ip}`
          }
        ],
        entities: [],
        relationships: [],
        sourceReferences: [
          {
            providerId: this.id,
            providerName: this.name,
            sourceUrl: `https://www.shodan.io/host/${ip}`,
            observedAt: observedTimestamp,
            queriedAt: queryTimestamp,
            confidence: 'confirmed',
            sensitivity: 'public',
            verificationStatus: 'verified'
          }
        ],
        rawResult: data,
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

export class SecurityTrailsDnsHistoryProvider
  implements OsintProvider<string, Record<string, unknown>>
{
  id = 'securitytrails';
  name = 'SecurityTrails Historical DNS Intelligence';
  category = 'domain' as const;
  supportedTypes = ['domain' as const];
  requiresApiKey = true;
  envVarNames = ['SECURITYTRAILS_API_KEY'];
  isFreeTierAvailable = true;
  rateLimitPerMinute = 10;
  disclosureNotice =
    'Queries api.securitytrails.com for historical DNS A record changes when SECURITYTRAILS_API_KEY is configured.';
  featureIds = ['DOM-08'];

  isConfigured(): boolean {
    return Boolean(process.env.SECURITYTRAILS_API_KEY?.trim());
  }

  validateInput(input: unknown): string {
    const val = validateAndNormalizeDomain(String(input || ''));
    if (!val.valid) throw new Error(val.error);
    return val.normalizedValue;
  }

  async execute(
    input: string,
    _context: InvestigationContext
  ): Promise<ProviderResult<Record<string, unknown>>> {
    const queryTimestamp = new Date().toISOString();
    const domain = this.validateInput(input);

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
        errors: ['SECURITYTRAILS_API_KEY is not configured in environment.'],
        confidence: 'low',
        sensitivity: 'public'
      };
    }

    const startMs = Date.now();
    try {
      const res = await fetch(
        `https://api.securitytrails.com/v1/history/${encodeURIComponent(domain)}/dns/a`,
        {
          headers: {
            APIKEY: process.env.SECURITYTRAILS_API_KEY!.trim(),
            Accept: 'application/json'
          },
          signal: AbortSignal.timeout(7000)
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
          errors: ['SecurityTrails API rate limit reached.'],
          confidence: 'low',
          sensitivity: 'public'
        };
      }
      if (!res.ok) throw new Error(`SecurityTrails returned HTTP ${res.status}`);
      const data = (await res.json()) as { records?: unknown[] };
      const records = Array.isArray(data.records) ? data.records : [];
      const observedTimestamp = new Date().toISOString();

      return {
        providerId: this.id,
        providerName: this.name,
        status: 'completed',
        findings: [
          {
            moduleCode: 'DOM-08',
            category: 'domain',
            title: `Historical DNS A Records (${records.length} historical periods)`,
            summary: `Retrieved ${records.length} historical A-record intervals for ${domain} via SecurityTrails.`,
            severity: 'info',
            confidence: 'confirmed',
            tags: ['dns-history', 'securitytrails'],
            attributes: {
              domain,
              historicalRecordCount: records.length,
              records: records.slice(0, 20)
            }
          }
        ],
        entities: [],
        relationships: [],
        sourceReferences: [
          {
            providerId: this.id,
            providerName: this.name,
            sourceUrl: `https://securitytrails.com/domain/${domain}/history/a`,
            observedAt: observedTimestamp,
            queriedAt: queryTimestamp,
            confidence: 'confirmed',
            sensitivity: 'public',
            verificationStatus: 'verified'
          }
        ],
        rawResult: data as Record<string, unknown>,
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
