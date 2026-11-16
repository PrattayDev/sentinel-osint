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
  validateAndNormalizeUrl
} from '@/lib/validation/schemas';
import { safeFetchWithRedirectInspection } from '@/lib/security/ssrf-guard';
import { sanitizeText } from '@/lib/security/sanitizer';

export class SafeHttpSecurityProvider
  implements OsintProvider<string, Record<string, unknown>>
{
  id = 'http-security';
  name = 'Safe HTTP Response, Redirect-Chain & Security Header Inspector';
  category = 'web' as const;
  supportedTypes = ['domain' as const, 'url' as const];
  requiresApiKey = false;
  envVarNames: string[] = [];
  isFreeTierAvailable = true;
  rateLimitPerMinute = 30;
  disclosureNotice =
    'Performs an SSRF-guarded HTTP GET request (verifying every redirect hop) to inspect public headers, title, and security.txt.';
  featureIds = [
    'DOM-10',
    'DOM-11',
    'DOM-13',
    'WEB-01',
    'WEB-02',
    'WEB-03',
    'WEB-04',
    'WEB-10',
    'WEB-11',
    'ORG-07'
  ];

  isConfigured(): boolean {
    return true;
  }

  validateInput(input: unknown): string {
    const raw = String(input || '').trim();
    if (/^https?:\/\//i.test(raw)) {
      const urlVal = validateAndNormalizeUrl(raw);
      if (!urlVal.valid) throw new Error(urlVal.error);
      return urlVal.normalizedValue;
    }
    const domVal = validateAndNormalizeDomain(raw);
    if (!domVal.valid) throw new Error(domVal.error);
    return `https://${domVal.normalizedValue}`;
  }

  async execute(
    input: string,
    _context: InvestigationContext
  ): Promise<ProviderResult<Record<string, unknown>>> {
    const startMs = Date.now();
    const queryTimestamp = new Date().toISOString();
    const targetUrl = this.validateInput(input);
    const parsedInitial = new URL(targetUrl);

    try {
      const inspect = await safeFetchWithRedirectInspection(targetUrl, {
        maxRedirects: 5,
        timeoutMs: 7500,
        maxBytes: 256 * 1024
      });

      const headers = inspect.headers;
      const html = inspect.bodySnippet;

      // Safe extraction of <title>, meta description, generator, canonical
      const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
      const pageTitle = titleMatch ? sanitizeText(titleMatch[1], 200) : '';

      const descMatch =
        html.match(
          /<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["']/i
        ) ||
        html.match(
          /<meta[^>]+content=["']([^"']+)["'][^>]+name=["']description["']/i
        );
      const metaDescription = descMatch ? sanitizeText(descMatch[1], 300) : '';

      const genMatch = html.match(
        /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i
      );
      const metaGenerator = genMatch ? sanitizeText(genMatch[1], 100) : '';

      // Evaluate HTTP Security Headers (DOM-11, WEB-04)
      const secHeaders = {
        strictTransportSecurity: headers['strict-transport-security'] || null,
        contentSecurityPolicy: headers['content-security-policy'] || null,
        xFrameOptions: headers['x-frame-options'] || null,
        xContentTypeOptions: headers['x-content-type-options'] || null,
        referrerPolicy: headers['referrer-policy'] || null,
        permissionsPolicy: headers['permissions-policy'] || null,
        crossOriginOpenerPolicy: headers['cross-origin-opener-policy'] || null
      };

      const presentSecHeaders = Object.entries(secHeaders)
        .filter(([, val]) => Boolean(val))
        .map(([k]) => k);
      const missingSecHeaders = Object.entries(secHeaders)
        .filter(([, val]) => !val)
        .map(([k]) => k);

      // Passive Technology Identification (DOM-10, WEB-11)
      const technologies = new Set<string>();
      if (headers['server']) technologies.add(`Server: ${sanitizeText(headers['server'], 80)}`);
      if (headers['x-powered-by'])
        technologies.add(`Powered-By: ${sanitizeText(headers['x-powered-by'], 80)}`);
      if (headers['cf-ray'] || headers['server']?.toLowerCase().includes('cloudflare'))
        technologies.add('Cloudflare CDN/WAF');
      if (headers['x-vercel-id']) technologies.add('Vercel Edge Network');
      if (headers['x-amz-cf-id'] || headers['via']?.includes('CloudFront'))
        technologies.add('AWS CloudFront');
      if (headers['x-fastly-request-id']) technologies.add('Fastly CDN');
      if (metaGenerator) technologies.add(`Generator: ${metaGenerator}`);
      if (html.includes('/_next/static/')) technologies.add('Next.js');
      if (html.includes('wp-content/')) technologies.add('WordPress');

      const findings: NormalizedFindingInput[] = [
        {
          moduleCode: 'WEB-02',
          category: 'web',
          title: `HTTP Response & Redirect Chain (${inspect.statusCode} — ${inspect.redirectChain.length} hop(s))`,
          summary: `Initial target ${targetUrl} resolved to ${inspect.finalUrl} with HTTP ${inspect.statusCode}. Page title: "${pageTitle || 'N/A'}".`,
          severity: 'info',
          confidence: 'confirmed',
          tags: ['http', 'redirects', 'metadata'],
          attributes: {
            initialUrl: targetUrl,
            finalUrl: inspect.finalUrl,
            statusCode: inspect.statusCode,
            redirectChain: inspect.redirectChain,
            pageTitle,
            metaDescription,
            contentType: headers['content-type'] || 'unknown',
            server: headers['server'] || null
          },
          sourceUrl: inspect.finalUrl
        },
        {
          moduleCode: 'DOM-11',
          category: 'web',
          title: `HTTP Security Header Posture (${presentSecHeaders.length}/7 headers enforced)`,
          summary: `Present: [${presentSecHeaders.join(', ') || 'None'}]. Missing: [${missingSecHeaders.join(', ') || 'None'}].`,
          severity: missingSecHeaders.length >= 4 ? 'medium' : 'info',
          confidence: 'confirmed',
          tags: ['security-headers', 'hsts', 'csp'],
          attributes: {
            presentCount: presentSecHeaders.length,
            missingHeaders: missingSecHeaders,
            headers: secHeaders
          },
          sourceUrl: inspect.finalUrl
        }
      ];

      if (technologies.size > 0) {
        findings.push({
          moduleCode: 'DOM-10',
          category: 'web',
          title: `Passive Web Technology Fingerprint (${technologies.size} detected)`,
          summary: `Identified stack components: ${Array.from(technologies).join(' | ')}.`,
          severity: 'info',
          confidence: 'high',
          tags: ['tech-stack', 'fingerprinting'],
          attributes: {
            technologies: Array.from(technologies)
          },
          sourceUrl: inspect.finalUrl
        });
      }

      // Check RFC 9116 /.well-known/security.txt passively (ORG-07)
      try {
        const secTxtUrl = `${parsedInitial.origin}/.well-known/security.txt`;
        const secTxtRes = await safeFetchWithRedirectInspection(secTxtUrl, {
          maxRedirects: 2,
          timeoutMs: 4000,
          maxBytes: 16384
        });
        if (
          secTxtRes.statusCode === 200 &&
          secTxtRes.bodySnippet.toLowerCase().includes('contact:')
        ) {
          findings.push({
            moduleCode: 'ORG-07',
            category: 'organization',
            title: `Published Security Disclosure Policy (security.txt)`,
            summary: `Found valid RFC 9116 security.txt disclosure policy at ${secTxtUrl}.`,
            severity: 'info',
            confidence: 'confirmed',
            tags: ['security.txt', 'vulnerability-disclosure', 'rfc9116'],
            attributes: {
              url: secTxtUrl,
              snippet: sanitizeText(secTxtRes.bodySnippet, 600)
            },
            sourceUrl: secTxtUrl
          });
        }
      } catch {
        // Optional check; ignore if absent
      }

      const finalHost = new URL(inspect.finalUrl).hostname.toLowerCase();
      const entities: DiscoveredEntityInput[] = [
        {
          key: `url:${inspect.finalUrl}`,
          entityType: 'url',
          label: inspect.finalUrl,
          value: inspect.finalUrl,
          confidence: 'confirmed',
          metadata: { statusCode: inspect.statusCode, pageTitle }
        },
        {
          key: `domain:${finalHost}`,
          entityType: 'domain',
          label: finalHost,
          value: finalHost,
          confidence: 'confirmed'
        }
      ];

      const relationships: DiscoveredRelationshipInput[] = [
        {
          sourceKey: `url:${inspect.finalUrl}`,
          targetKey: `domain:${finalHost}`,
          relationshipType: 'hosted_on_domain',
          confidence: 'confirmed'
        }
      ];

      for (const ip of inspect.resolvedIps.slice(0, 4)) {
        entities.push({
          key: `ip:${ip}`,
          entityType: 'ip',
          label: ip,
          value: ip,
          confidence: 'confirmed'
        });
        relationships.push({
          sourceKey: `domain:${finalHost}`,
          targetKey: `ip:${ip}`,
          relationshipType: 'resolves_to',
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
            sourceUrl: inspect.finalUrl,
            observedAt: observedTimestamp,
            queriedAt: queryTimestamp,
            confidence: 'confirmed',
            sensitivity: 'public',
            verificationStatus: 'verified',
            citationNote: `SSRF-verified HTTP inspection of ${inspect.finalUrl}`
          }
        ],
        rawResult: {
          finalUrl: inspect.finalUrl,
          statusCode: inspect.statusCode,
          redirectChain: inspect.redirectChain,
          pageTitle,
          metaDescription,
          securityHeaders: secHeaders,
          technologies: Array.from(technologies)
        },
        observedTimestamp,
        queryTimestamp,
        durationMs: Date.now() - startMs,
        errors: [],
        confidence: 'confirmed',
        sensitivity: 'public'
      };
    } catch (err) {
      const msg = (err as Error).message;
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
        errors: [msg],
        confidence: 'low',
        sensitivity: 'public'
      };
    }
  }
}
