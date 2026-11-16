import net from 'net';
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

export class RdapRegistryProvider implements OsintProvider<string, Record<string, unknown>> {
  id = 'rdap-registry';
  name = 'IANA / RIR RDAP Registration Service';
  category = 'domain' as const;
  supportedTypes = ['domain' as const, 'ip' as const];
  requiresApiKey = false;
  envVarNames: string[] = [];
  isFreeTierAvailable = true;
  rateLimitPerMinute = 30;
  disclosureNotice =
    'Queries public Regional Internet Registry (RIR) and TLD RDAP servers via rdap.org.';
  featureIds = ['DOM-04', 'DOM-14', 'NET-02', 'NET-04', 'NET-08'];

  isConfigured(): boolean {
    return true;
  }

  validateInput(input: unknown): string {
    const raw = String(input || '').trim();
    if (net.isIP(raw) !== 0) {
      const ipVal = validateAndNormalizeIp(raw);
      if (!ipVal.valid) throw new Error(ipVal.error);
      return ipVal.normalizedValue;
    }
    const domVal = validateAndNormalizeDomain(raw);
    if (!domVal.valid) throw new Error(domVal.error);
    return domVal.normalizedValue;
  }

  async execute(
    input: string,
    _context: InvestigationContext
  ): Promise<ProviderResult<Record<string, unknown>>> {
    const startMs = Date.now();
    const queryTimestamp = new Date().toISOString();
    const normalized = this.validateInput(input);
    const isIp = net.isIP(normalized) !== 0;

    const rdapUrl = isIp
      ? `https://rdap.org/ip/${encodeURIComponent(normalized)}`
      : `https://rdap.org/domain/${encodeURIComponent(normalized)}`;

    try {
      const res = await fetch(rdapUrl, {
        headers: {
          Accept: 'application/rdap+json, application/json',
          'User-Agent': 'Sentinel-OSINT/2.0'
        },
        signal: AbortSignal.timeout(8000)
      });

      if (!res.ok) {
        return {
          providerId: this.id,
          providerName: this.name,
          status: res.status === 429 ? 'rate_limited' : 'partial',
          findings: [],
          entities: [],
          relationships: [],
          sourceReferences: [],
          observedTimestamp: new Date().toISOString(),
          queryTimestamp,
          durationMs: Date.now() - startMs,
          errors: [`RDAP query returned HTTP ${res.status} for ${normalized}`],
          confidence: 'medium',
          sensitivity: 'public'
        };
      }

      const data = (await res.json()) as Record<string, unknown>;
      const handle = sanitizeText(data.handle || data.ldhName || normalized, 128);
      const name = sanitizeText(data.name || data.ldhName || normalized, 128);
      const statusList = Array.isArray(data.status)
        ? data.status.map((s) => sanitizeText(s, 64))
        : [];

      const events = Array.isArray(data.events)
        ? (data.events as Array<{ eventAction?: string; eventDate?: string }>)
        : [];
      const registrationDate = events.find(
        (e) => e.eventAction === 'registration'
      )?.eventDate;
      const expirationDate = events.find(
        (e) => e.eventAction === 'expiration'
      )?.eventDate;
      const lastChangedDate = events.find(
        (e) => e.eventAction === 'last changed'
      )?.eventDate;

      // Extract entity names from vCardArray if present
      const orgNames: string[] = [];
      if (Array.isArray(data.entities)) {
        for (const ent of data.entities as Array<Record<string, unknown>>) {
          const vcard = ent.vcardArray;
          if (Array.isArray(vcard) && Array.isArray(vcard[1])) {
            for (const row of vcard[1] as unknown[][]) {
              if (
                Array.isArray(row) &&
                (row[0] === 'fn' || row[0] === 'org') &&
                typeof row[3] === 'string'
              ) {
                const fn = sanitizeText(row[3], 120);
                if (fn && !fn.toLowerCase().includes('redacted')) {
                  orgNames.push(fn);
                }
              }
            }
          }
        }
      }

      const uniqueOrgs = Array.from(new Set(orgNames));
      const findings: NormalizedFindingInput[] = [];
      const entities: DiscoveredEntityInput[] = [];
      const relationships: DiscoveredRelationshipInput[] = [];

      if (isIp) {
        const startAddress = sanitizeText(data.startAddress, 64);
        const endAddress = sanitizeText(data.endAddress, 64);
        const country = sanitizeText(data.country, 16);

        findings.push({
          moduleCode: 'NET-02',
          category: 'network',
          title: `RIR RDAP Network Allocation (${name || handle})`,
          summary: `IP ${normalized} is allocated within range ${startAddress} – ${endAddress} (${country || 'Global'}). Registered holder: ${uniqueOrgs.join(', ') || name || handle}.`,
          severity: 'info',
          confidence: 'confirmed',
          tags: ['rdap', 'ip-allocation', 'rir'],
          attributes: {
            ip: normalized,
            handle,
            networkName: name,
            startAddress,
            endAddress,
            country,
            organizations: uniqueOrgs,
            status: statusList,
            registrationDate,
            lastChangedDate
          },
          sourceUrl: rdapUrl
        });

        entities.push({
          key: `ip:${normalized}`,
          entityType: 'ip',
          label: normalized,
          value: normalized,
          confidence: 'confirmed'
        });

        for (const org of uniqueOrgs.slice(0, 3)) {
          entities.push({
            key: `org:${org.toLowerCase()}`,
            entityType: 'organization',
            label: org,
            value: org,
            confidence: 'confirmed',
            metadata: { role: 'network_registrant' }
          });
          relationships.push({
            sourceKey: `ip:${normalized}`,
            targetKey: `org:${org.toLowerCase()}`,
            relationshipType: 'allocated_to_org',
            confidence: 'confirmed'
          });
        }
      } else {
        const nameservers = Array.isArray(data.nameservers)
          ? (data.nameservers as Array<{ ldhName?: string }>)
              .map((n) => sanitizeText(n.ldhName, 120).toLowerCase())
              .filter(Boolean)
          : [];
        const secureDns = data.secureDNS as { delegationSigned?: boolean } | undefined;

        findings.push({
          moduleCode: 'DOM-04',
          category: 'domain',
          title: `RDAP Domain Registration (${normalized})`,
          summary: `Registered: ${registrationDate || 'Unknown'} | Expires: ${expirationDate || 'Unknown'} | Registrar/Entities: ${uniqueOrgs.join(', ') || 'Privacy Redacted'} | DNSSEC: ${secureDns?.delegationSigned ? 'Signed' : 'Unsigned'}.`,
          severity: 'info',
          confidence: 'confirmed',
          tags: ['rdap', 'whois', 'domain-registration'],
          attributes: {
            domain: normalized,
            handle,
            registrarAndEntities: uniqueOrgs,
            status: statusList,
            registrationDate,
            expirationDate,
            lastChangedDate,
            nameservers,
            dnssecSigned: Boolean(secureDns?.delegationSigned)
          },
          sourceUrl: rdapUrl
        });

        entities.push({
          key: `domain:${normalized}`,
          entityType: 'domain',
          label: normalized,
          value: normalized,
          confidence: 'confirmed'
        });

        for (const org of uniqueOrgs.slice(0, 2)) {
          entities.push({
            key: `org:${org.toLowerCase()}`,
            entityType: 'organization',
            label: org,
            value: org,
            confidence: 'high',
            metadata: { role: 'domain_registrar_or_registrant' }
          });
          relationships.push({
            sourceKey: `domain:${normalized}`,
            targetKey: `org:${org.toLowerCase()}`,
            relationshipType: 'registered_via',
            confidence: 'high'
          });
        }
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
            sourceUrl: rdapUrl,
            observedAt: observedTimestamp,
            queriedAt: queryTimestamp,
            confidence: 'confirmed',
            sensitivity: 'public',
            verificationStatus: 'verified',
            citationNote: `RDAP registration record for ${normalized}`
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
        errors: [`RDAP lookup error: ${(err as Error).message}`],
        confidence: 'low',
        sensitivity: 'public'
      };
    }
  }
}
