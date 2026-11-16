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
  validateAndNormalizeEmail
} from '@/lib/validation/schemas';

interface DnsQueryBundle {
  domain: string;
  aRecords: string[];
  aaaaRecords: string[];
  mxRecords: Array<{ exchange: string; priority: number }>;
  nsRecords: string[];
  txtRecords: string[];
  cnameRecords: string[];
  dmarcRecords: string[];
  spfRecords: string[];
  dkimSelectorsFound: string[];
  detectedSaasFootprint: string[];
}

async function queryDohFallback(domain: string, type: string): Promise<string[]> {
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}`,
      {
        headers: { Accept: 'application/dns-json' },
        signal: AbortSignal.timeout(4500)
      }
    );
    if (!res.ok) return [];
    const data = (await res.json()) as {
      Answer?: Array<{ data: string; type: number }>;
    };
    return (data.Answer || []).map((a) => a.data.replace(/^"|"$/g, ''));
  } catch {
    return [];
  }
}

export class AuthoritativeDnsProvider implements OsintProvider<string, DnsQueryBundle> {
  id = 'dns-core';
  name = 'Authoritative DNS & DoH Analyzer';
  category = 'domain' as const;
  supportedTypes = ['domain' as const, 'email' as const];
  requiresApiKey = false;
  envVarNames: string[] = [];
  isFreeTierAvailable = true;
  rateLimitPerMinute = 60;
  disclosureNotice =
    'Resolves public DNS records (A, AAAA, MX, NS, TXT, DMARC, SPF) via system DNS and Cloudflare DNS-over-HTTPS.';
  featureIds = ['ID-02', 'ID-10', 'DOM-01', 'DOM-02', 'DOM-03', 'DOM-12', 'ORG-05'];

  isConfigured(): boolean {
    return true;
  }

  validateInput(input: unknown): string {
    const raw = String(input || '').trim();
    if (raw.includes('@')) {
      const emailVal = validateAndNormalizeEmail(raw);
      if (!emailVal.valid) throw new Error(emailVal.error);
      return String(emailVal.metadata.domain);
    }
    const domVal = validateAndNormalizeDomain(raw);
    if (!domVal.valid) throw new Error(domVal.error);
    return domVal.normalizedValue;
  }

  async execute(
    input: string,
    _context: InvestigationContext
  ): Promise<ProviderResult<DnsQueryBundle>> {
    const startMs = Date.now();
    const queryTimestamp = new Date().toISOString();
    const domain = this.validateInput(input);

    const [aRes, aaaaRes, mxRes, nsRes, txtRes, cnameRes, dmarcRes] =
      await Promise.allSettled([
        dns.resolve4(domain),
        dns.resolve6(domain),
        dns.resolveMx(domain),
        dns.resolveNs(domain),
        dns.resolveTxt(domain),
        dns.resolveCname(domain),
        dns.resolveTxt(`_dmarc.${domain}`)
      ]);

    let aRecords = aRes.status === 'fulfilled' ? aRes.value : [];
    if (aRecords.length === 0) {
      aRecords = await queryDohFallback(domain, 'A');
    }

    let aaaaRecords = aaaaRes.status === 'fulfilled' ? aaaaRes.value : [];
    if (aaaaRecords.length === 0) {
      aaaaRecords = await queryDohFallback(domain, 'AAAA');
    }

    const mxRecords =
      mxRes.status === 'fulfilled'
        ? mxRes.value.sort((a, b) => a.priority - b.priority)
        : [];
    const nsRecords = nsRes.status === 'fulfilled' ? nsRes.value : [];
    const txtRecords =
      txtRes.status === 'fulfilled'
        ? txtRes.value.map((chunks) => chunks.join(''))
        : [];
    const cnameRecords = cnameRes.status === 'fulfilled' ? cnameRes.value : [];
    const dmarcRecords =
      dmarcRes.status === 'fulfilled'
        ? dmarcRes.value.map((chunks) => chunks.join(''))
        : [];

    // Probe standard passive DKIM selectors
    const commonSelectors = ['default', 'google', 'selector1', 'selector2', 'k1'];
    const dkimResults = await Promise.allSettled(
      commonSelectors.map(async (sel) => {
        const recs = await dns.resolveTxt(`${sel}._domainkey.${domain}`);
        return recs.length > 0 ? sel : null;
      })
    );
    const dkimSelectorsFound = dkimResults
      .map((r) => (r.status === 'fulfilled' ? r.value : null))
      .filter((v): v is string => Boolean(v));

    const spfRecords = txtRecords.filter((t) =>
      t.toLowerCase().startsWith('v=spf1')
    );

    // Passive SaaS technology footprint from TXT/MX records (ORG-05)
    const detectedSaasFootprint: string[] = [];
    for (const txt of txtRecords) {
      const lower = txt.toLowerCase();
      if (lower.includes('google-site-verification'))
        detectedSaasFootprint.push('Google Workspace / Search Console');
      if (lower.startsWith('ms='))
        detectedSaasFootprint.push('Microsoft 365 / Entra ID');
      if (lower.includes('atlassian-domain-verification'))
        detectedSaasFootprint.push('Atlassian Cloud');
      if (lower.includes('stripe-verification'))
        detectedSaasFootprint.push('Stripe');
      if (lower.includes('docusign')) detectedSaasFootprint.push('DocuSign');
      if (lower.includes('hubspot')) detectedSaasFootprint.push('HubSpot');
      if (lower.includes('amazonses') || lower.includes('aws'))
        detectedSaasFootprint.push('Amazon Web Services (SES)');
      if (lower.includes('spf.protection.outlook.com'))
        detectedSaasFootprint.push('Microsoft Exchange Online Protection');
      if (lower.includes('_spf.google.com'))
        detectedSaasFootprint.push('Google Workspace Mail');
    }

    const findings: NormalizedFindingInput[] = [];
    const entities: DiscoveredEntityInput[] = [
      {
        key: `domain:${domain}`,
        entityType: 'domain',
        label: domain,
        value: domain,
        confidence: 'confirmed',
        metadata: { source: 'dns-core' }
      }
    ];
    const relationships: DiscoveredRelationshipInput[] = [];

    if (aRecords.length > 0 || aaaaRecords.length > 0) {
      findings.push({
        moduleCode: 'DOM-02',
        category: 'domain',
        title: `DNS Address Records (${aRecords.length} IPv4, ${aaaaRecords.length} IPv6)`,
        summary: `Domain ${domain} resolves to IPv4 [${aRecords.join(', ') || 'none'}] and IPv6 [${aaaaRecords.join(', ') || 'none'}].`,
        severity: 'info',
        confidence: 'confirmed',
        tags: ['dns', 'a-record', 'aaaa-record'],
        attributes: {
          domain,
          ipv4: aRecords,
          ipv6: aaaaRecords,
          cname: cnameRecords
        },
        sourceUrl: `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}`
      });

      for (const ip of [...aRecords.slice(0, 8), ...aaaaRecords.slice(0, 4)]) {
        entities.push({
          key: `ip:${ip}`,
          entityType: 'ip',
          label: ip,
          value: ip,
          confidence: 'confirmed',
          metadata: { resolvedFrom: domain }
        });
        relationships.push({
          sourceKey: `domain:${domain}`,
          targetKey: `ip:${ip}`,
          relationshipType: 'resolves_to',
          confidence: 'confirmed'
        });
      }
    }

    if (nsRecords.length > 0 || txtRecords.length > 0 || mxRecords.length > 0) {
      findings.push({
        moduleCode: 'DOM-03',
        category: 'domain',
        title: `Nameservers, Mail Exchange & TXT Records`,
        summary: `Found ${nsRecords.length} NS records, ${mxRecords.length} MX records, and ${txtRecords.length} TXT records for ${domain}.`,
        severity: 'info',
        confidence: 'confirmed',
        tags: ['dns', 'ns', 'mx', 'txt'],
        attributes: {
          nameservers: nsRecords,
          mxRecords,
          txtRecords,
          detectedSaasFootprint: Array.from(new Set(detectedSaasFootprint))
        }
      });
    }

    // Email Security Posture Analysis (ID-02, ID-10, DOM-12)
    const hasSpf = spfRecords.length > 0;
    const spfStrict = spfRecords.some((s) => s.includes('-all') || s.includes('~all'));
    const hasDmarc = dmarcRecords.some((d) =>
      d.toLowerCase().startsWith('v=dmarc1')
    );
    const dmarcRejectOrQuarantine = dmarcRecords.some((d) =>
      /p=(reject|quarantine)/i.test(d)
    );

    let postureScore = 0;
    if (mxRecords.length > 0) postureScore += 20;
    if (hasSpf) postureScore += 25;
    if (spfStrict) postureScore += 15;
    if (hasDmarc) postureScore += 25;
    if (dmarcRejectOrQuarantine) postureScore += 15;

    findings.push({
      moduleCode: 'DOM-12',
      category: 'identity',
      title: `Email & Domain Anti-Spoofing Posture (${postureScore}/100)`,
      summary: `SPF: ${hasSpf ? 'Present' : 'Missing'} | DMARC: ${hasDmarc ? 'Present' : 'Missing'} | Passive DKIM Selectors: ${dkimSelectorsFound.join(', ') || 'None detected in common list'}.`,
      severity: !hasSpf || !hasDmarc ? 'medium' : 'info',
      confidence: 'confirmed',
      tags: ['spf', 'dmarc', 'dkim', 'email-security'],
      attributes: {
        postureScore,
        spfRecords,
        dmarcRecords,
        dkimSelectorsFound,
        mxCount: mxRecords.length,
        spoofingRisk:
          !hasSpf || !hasDmarc
            ? 'Elevated risk of domain spoofing due to missing SPF or DMARC policy'
            : dmarcRejectOrQuarantine
              ? 'Strong enforcement (quarantine/reject)'
              : 'Monitoring only (p=none)'
      }
    });

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
          sourceUrl: `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}`,
          observedAt: observedTimestamp,
          queriedAt: queryTimestamp,
          confidence: 'confirmed',
          sensitivity: 'public',
          verificationStatus: 'verified',
          citationNote: `Authoritative DNS resolution for ${domain}`
        }
      ],
      rawResult: {
        domain,
        aRecords,
        aaaaRecords,
        mxRecords,
        nsRecords,
        txtRecords,
        cnameRecords,
        dmarcRecords,
        spfRecords,
        dkimSelectorsFound,
        detectedSaasFootprint
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
