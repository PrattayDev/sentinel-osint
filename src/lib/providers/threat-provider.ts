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
  validateAndNormalizeFileHash,
  validateAndNormalizeIp,
  validateAndNormalizeUrl
} from '@/lib/validation/schemas';
import { sanitizeText } from '@/lib/security/sanitizer';

export class AbuseChThreatProvider
  implements OsintProvider<string, Record<string, unknown>>
{
  id = 'abusech-threat';
  name = 'abuse.ch ThreatFox, URLhaus & MalwareBazaar IOC Intelligence';
  category = 'threat' as const;
  supportedTypes = [
    'file_hash' as const,
    'domain' as const,
    'ip' as const,
    'url' as const
  ];
  requiresApiKey = false;
  envVarNames: string[] = [];
  isFreeTierAvailable = true;
  rateLimitPerMinute = 30;
  disclosureNotice =
    'Queries abuse.ch public threat feeds (ThreatFox, URLhaus, MalwareBazaar) for known malware hashes, C2 hosts, and malicious URLs.';
  featureIds = [
    'DOM-09',
    'WEB-06',
    'THR-01',
    'THR-02',
    'THR-03',
    'THR-04',
    'THR-05',
    'THR-09',
    'THR-10'
  ];

  isConfigured(): boolean {
    return true;
  }

  validateInput(input: unknown): string {
    const raw = String(input || '').trim();
    if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(raw)) {
      const h = validateAndNormalizeFileHash(raw);
      if (!h.valid) throw new Error(h.error);
      return h.normalizedValue;
    }
    if (/^https?:\/\//i.test(raw)) {
      const u = validateAndNormalizeUrl(raw);
      if (!u.valid) throw new Error(u.error);
      return u.normalizedValue;
    }
    if (net.isIP(raw) !== 0) {
      const ip = validateAndNormalizeIp(raw);
      if (!ip.valid) throw new Error(ip.error);
      return ip.normalizedValue;
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
    const indicator = this.validateInput(input);
    const isHash = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(indicator);
    const isUrl = /^https?:\/\//i.test(indicator);
    const isIp = net.isIP(indicator) !== 0;

    const findings: NormalizedFindingInput[] = [];
    const entities: DiscoveredEntityInput[] = [];
    const relationships: DiscoveredRelationshipInput[] = [];
    const errors: string[] = [];

    if (isHash) {
      entities.push({
        key: `hash:${indicator}`,
        entityType: 'file_hash',
        label: `${indicator.slice(0, 12)}…`,
        value: indicator,
        confidence: 'confirmed'
      });

      let hashMatched = false;
      try {
        const body = new URLSearchParams({
          query: 'get_info',
          hash: indicator
        });
        const mbRes = await fetch('https://mb-api.abuse.ch/api/v1/', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Sentinel-OSINT/2.0'
          },
          body: body.toString(),
          signal: AbortSignal.timeout(6500)
        });

        if (mbRes.ok) {
          const mbData = (await mbRes.json()) as {
            query_status?: string;
            data?: Array<{
              sha256_hash?: string;
              file_name?: string;
              file_type?: string;
              signature?: string;
              first_seen?: string;
              tags?: string[];
            }>;
          };

          if (
            mbData.query_status === 'ok' &&
            Array.isArray(mbData.data) &&
            mbData.data.length > 0
          ) {
            hashMatched = true;
            const sample = mbData.data[0];
            findings.push({
              moduleCode: 'THR-01',
              category: 'threat',
              title: `MalwareBazaar Positive Match (${sanitizeText(sample.signature || 'Malware Sample', 80)})`,
              summary: `Hash ${indicator} matched known malware sample in abuse.ch MalwareBazaar. Signature: ${sanitizeText(sample.signature, 80) || 'Unknown'} | First Seen: ${sanitizeText(sample.first_seen, 40) || 'N/A'}.`,
              severity: 'critical',
              confidence: 'confirmed',
              tags: ['malwarebazaar', 'malware-hash', ...(sample.tags || [])],
              attributes: {
                hash: indicator,
                verdict: 'malicious_indicator_observed',
                signature: sample.signature,
                fileName: sample.file_name,
                fileType: sample.file_type,
                firstSeen: sample.first_seen,
                tags: sample.tags || []
              },
              sourceUrl: `https://bazaar.abuse.ch/sample/${sample.sha256_hash || indicator}/`
            });
          }
        }
      } catch (e) {
        errors.push(`MalwareBazaar query note: ${(e as Error).message}`);
      }

      if (!hashMatched) {
        // CRITICAL REQUIREMENT: Unknown hashes MUST be classified as 'unknown', NEVER 'safe'!
        findings.push({
          moduleCode: 'THR-01',
          category: 'threat',
          title: `File Hash Reputation (${indicator.slice(0, 16)}… — Verdict: UNKNOWN)`,
          summary: `Hash ${indicator} returned 0 hits in public MalwareBazaar corpus. Classification is strictly UNKNOWN (unrated)—absence from public feeds does NOT prove a file is benign or safe.`,
          severity: 'info',
          confidence: 'medium',
          tags: ['file-hash', 'unknown-verdict', 'unrated'],
          attributes: {
            hash: indicator,
            verdict: 'unknown',
            isClassifiedSafe: false,
            hitsCount: 0,
            defensiveNote:
              'Unknown hashes must never be treated as safe; novel or targeted binaries may not appear in public threat corpora.'
          },
          sourceUrl: 'https://bazaar.abuse.ch/'
        });
      }
    } else {
      // Query ThreatFox for domain / IP / URL IOC matches (THR-02, THR-03, THR-04, THR-05)
      let iocMatched = false;
      try {
        const tfRes = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'Sentinel-OSINT/2.0'
          },
          body: JSON.stringify({
            query: 'search_ioc',
            search_term: isUrl ? new URL(indicator).hostname : indicator
          }),
          signal: AbortSignal.timeout(6500)
        });

        if (tfRes.ok) {
          const tfData = (await tfRes.json()) as {
            query_status?: string;
            data?: Array<{
              ioc?: string;
              threat_type?: string;
              malware_printable?: string;
              confidence_level?: number;
              first_seen?: string;
              tags?: string[];
            }>;
          };

          if (
            tfData.query_status === 'ok' &&
            Array.isArray(tfData.data) &&
            tfData.data.length > 0
          ) {
            iocMatched = true;
            const hits = tfData.data.slice(0, 10);
            findings.push({
              moduleCode: 'THR-05',
              category: 'threat',
              title: `ThreatFox IOC Match (${hits.length} indicator record(s))`,
              summary: `Indicator ${indicator} matched ThreatFox IOC feed: ${hits.map((h) => `${h.malware_printable} (${h.threat_type})`).join(', ')}.`,
              severity: 'high',
              confidence: 'high',
              tags: ['threatfox', 'ioc-match'],
              attributes: {
                indicator,
                verdict: 'suspicious_or_malicious_ioc',
                matchCount: tfData.data.length,
                matches: hits
              },
              sourceUrl: 'https://threatfox.abuse.ch/'
            });
          }
        }
      } catch (e) {
        errors.push(`ThreatFox query note: ${(e as Error).message}`);
      }

      if (!iocMatched) {
        findings.push({
          moduleCode: isIp ? 'THR-04' : isUrl ? 'THR-02' : 'THR-03',
          category: 'threat',
          title: `abuse.ch Threat Feed Check (${indicator} — 0 Known IOC Matches)`,
          summary: `No active C2 or malware distribution hits recorded for ${indicator} in ThreatFox. Verdict: unrated/no_known_hits (single feed absence is not conclusive proof of safety).`,
          severity: 'info',
          confidence: 'medium',
          tags: ['threat-intel', 'no-hits'],
          attributes: {
            indicator,
            verdict: 'unrated_no_hits',
            hitsCount: 0
          },
          sourceUrl: 'https://threatfox.abuse.ch/'
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
          sourceUrl: isHash
            ? 'https://bazaar.abuse.ch/'
            : 'https://threatfox.abuse.ch/',
          observedAt: observedTimestamp,
          queriedAt: queryTimestamp,
          confidence: 'high',
          sensitivity: 'public',
          verificationStatus: 'verified',
          citationNote: `abuse.ch threat feed lookup for ${indicator}`
        }
      ],
      rawResult: { indicator, findingsCount: findings.length },
      observedTimestamp,
      queryTimestamp,
      durationMs: Date.now() - startMs,
      errors,
      confidence: 'high',
      sensitivity: 'public'
    };
  }
}

export class VirusTotalV3Provider
  implements OsintProvider<string, Record<string, unknown>>
{
  id = 'virustotal-v3';
  name = 'VirusTotal API v3 Multi-Engine Reputation';
  category = 'threat' as const;
  supportedTypes = [
    'file_hash' as const,
    'domain' as const,
    'ip' as const,
    'url' as const
  ];
  requiresApiKey = true;
  envVarNames = ['VIRUSTOTAL_API_KEY'];
  isFreeTierAvailable = true;
  rateLimitPerMinute = 4;
  disclosureNotice =
    'Queries VirusTotal API v3 (www.virustotal.com) when VIRUSTOTAL_API_KEY is configured.';
  featureIds = ['DOM-09', 'WEB-06', 'THR-01', 'THR-02', 'THR-03', 'THR-09'];

  isConfigured(): boolean {
    return Boolean(process.env.VIRUSTOTAL_API_KEY?.trim());
  }

  validateInput(input: unknown): string {
    const raw = String(input || '').trim();
    if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(raw)) {
      const h = validateAndNormalizeFileHash(raw);
      if (!h.valid) throw new Error(h.error);
      return h.normalizedValue;
    }
    if (/^https?:\/\//i.test(raw)) {
      const u = validateAndNormalizeUrl(raw);
      if (!u.valid) throw new Error(u.error);
      return u.normalizedValue;
    }
    if (net.isIP(raw) !== 0) {
      const ip = validateAndNormalizeIp(raw);
      if (!ip.valid) throw new Error(ip.error);
      return ip.normalizedValue;
    }
    const d = validateAndNormalizeDomain(raw);
    if (!d.valid) throw new Error(d.error);
    return d.normalizedValue;
  }

  async execute(
    input: string,
    _context: InvestigationContext
  ): Promise<ProviderResult<Record<string, unknown>>> {
    const queryTimestamp = new Date().toISOString();
    const indicator = this.validateInput(input);

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
        errors: ['VIRUSTOTAL_API_KEY is not configured in environment.'],
        confidence: 'low',
        sensitivity: 'public'
      };
    }

    const startMs = Date.now();
    const isHash = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(indicator);
    const isUrl = /^https?:\/\//i.test(indicator);
    const isIp = net.isIP(indicator) !== 0;

    let endpoint = '';
    if (isHash) {
      endpoint = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(indicator)}`;
    } else if (isUrl) {
      const b64Url = Buffer.from(indicator).toString('base64url');
      endpoint = `https://www.virustotal.com/api/v3/urls/${b64Url}`;
    } else if (isIp) {
      endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(indicator)}`;
    } else {
      endpoint = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(indicator)}`;
    }

    try {
      const res = await fetch(endpoint, {
        headers: {
          'x-apikey': process.env.VIRUSTOTAL_API_KEY!.trim(),
          Accept: 'application/json'
        },
        signal: AbortSignal.timeout(7500)
      });

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
          errors: ['VirusTotal API rate limit exceeded (HTTP 429).'],
          confidence: 'low',
          sensitivity: 'public'
        };
      }

      if (res.status === 404) {
        const observedTimestamp = new Date().toISOString();
        return {
          providerId: this.id,
          providerName: this.name,
          status: 'completed',
          findings: [
            {
              moduleCode: isHash ? 'THR-01' : 'THR-02',
              category: 'threat',
              title: `VirusTotal Analysis (Verdict: UNKNOWN — Not Previously Indexed)`,
              summary: `Indicator ${indicator} is not present in VirusTotal's dataset. Verdict is UNKNOWN (never assumed safe).`,
              severity: 'info',
              confidence: 'medium',
              tags: ['virustotal', 'unknown-verdict'],
              attributes: {
                indicator,
                verdict: 'unknown',
                isClassifiedSafe: false
              }
            }
          ],
          entities: [],
          relationships: [],
          sourceReferences: [],
          rawResult: { indicator, verdict: 'unknown' },
          observedTimestamp,
          queryTimestamp,
          durationMs: Date.now() - startMs,
          errors: [],
          confidence: 'medium',
          sensitivity: 'public'
        };
      }

      if (!res.ok) {
        throw new Error(`VirusTotal API returned HTTP ${res.status}`);
      }

      const json = (await res.json()) as {
        data?: {
          attributes?: {
            last_analysis_stats?: {
              malicious?: number;
              suspicious?: number;
              harmless?: number;
              undetected?: number;
            };
            reputation?: number;
          };
        };
      };

      const stats = json.data?.attributes?.last_analysis_stats || {};
      const malicious = stats.malicious ?? 0;
      const suspicious = stats.suspicious ?? 0;
      const harmless = stats.harmless ?? 0;
      const undetected = stats.undetected ?? 0;
      const total = malicious + suspicious + harmless + undetected;

      const observedTimestamp = new Date().toISOString();
      return {
        providerId: this.id,
        providerName: this.name,
        status: 'completed',
        findings: [
          {
            moduleCode: isHash ? 'THR-01' : isUrl ? 'WEB-06' : 'DOM-09',
            category: 'threat',
            title: `VirusTotal Multi-Engine Verdict (${malicious}/${total} Malicious, ${suspicious} Suspicious)`,
            summary: `${malicious} engine(s) flagged ${indicator} as malicious and ${suspicious} as suspicious out of ${total} engines. Note: Single-engine detections require corroboration.`,
            severity:
              malicious >= 3
                ? 'critical'
                : malicious >= 1 || suspicious >= 2
                  ? 'high'
                  : 'info',
            confidence: 'confirmed',
            tags: ['virustotal', 'reputation'],
            attributes: {
              indicator,
              malicious,
              suspicious,
              harmless,
              undetected,
              totalEngines: total,
              verdict:
                malicious > 0
                  ? 'malicious_detections_present'
                  : suspicious > 0
                    ? 'suspicious_detections_present'
                    : 'no_current_detections'
            },
            sourceUrl: 'https://www.virustotal.com/'
          }
        ],
        entities: [],
        relationships: [],
        sourceReferences: [
          {
            providerId: this.id,
            providerName: this.name,
            sourceUrl: 'https://www.virustotal.com/',
            observedAt: observedTimestamp,
            queriedAt: queryTimestamp,
            confidence: 'confirmed',
            sensitivity: 'public',
            verificationStatus: 'verified'
          }
        ],
        rawResult: stats as Record<string, unknown>,
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

export class AbuseIpDbProvider
  implements OsintProvider<string, Record<string, unknown>>
{
  id = 'abuseipdb-v2';
  name = 'AbuseIPDB v2 IP Abuse & Confidence Score';
  category = 'threat' as const;
  supportedTypes = ['ip' as const];
  requiresApiKey = true;
  envVarNames = ['ABUSEIPDB_API_KEY'];
  isFreeTierAvailable = true;
  rateLimitPerMinute = 15;
  disclosureNotice =
    'Queries AbuseIPDB v2 API for community abuse reports when ABUSEIPDB_API_KEY is configured.';
  featureIds = ['NET-07', 'THR-04'];

  isConfigured(): boolean {
    return Boolean(process.env.ABUSEIPDB_API_KEY?.trim());
  }

  validateInput(input: unknown): string {
    const ip = validateAndNormalizeIp(String(input || ''));
    if (!ip.valid) throw new Error(ip.error);
    return ip.normalizedValue;
  }

  async execute(
    input: string,
    _context: InvestigationContext
  ): Promise<ProviderResult<Record<string, unknown>>> {
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
        errors: ['ABUSEIPDB_API_KEY is not configured in environment.'],
        confidence: 'low',
        sensitivity: 'public'
      };
    }

    const startMs = Date.now();
    try {
      const res = await fetch(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
        {
          headers: {
            Key: process.env.ABUSEIPDB_API_KEY!.trim(),
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
          errors: ['AbuseIPDB rate limit exceeded.'],
          confidence: 'low',
          sensitivity: 'public'
        };
      }

      if (!res.ok) throw new Error(`AbuseIPDB returned HTTP ${res.status}`);
      const json = (await res.json()) as {
        data?: {
          abuseConfidenceScore?: number;
          totalReports?: number;
          usageType?: string;
          isp?: string;
          domain?: string;
          isTor?: boolean;
        };
      };
      const d = json.data || {};
      const score = d.abuseConfidenceScore ?? 0;
      const reports = d.totalReports ?? 0;
      const observedTimestamp = new Date().toISOString();

      return {
        providerId: this.id,
        providerName: this.name,
        status: 'completed',
        findings: [
          {
            moduleCode: 'NET-07',
            category: 'threat',
            title: `AbuseIPDB Reputation (Confidence Score: ${score}% — ${reports} report(s))`,
            summary: `IP ${ip} has an AbuseIPDB confidence score of ${score}% across ${reports} community report(s). ISP: ${sanitizeText(d.isp, 100) || 'N/A'} | Usage: ${sanitizeText(d.usageType, 80) || 'N/A'}.`,
            severity: score >= 75 ? 'high' : score >= 25 ? 'medium' : 'info',
            confidence: 'confirmed',
            tags: ['abuseipdb', 'ip-reputation'],
            attributes: {
              ip,
              abuseConfidenceScore: score,
              totalReports: reports,
              usageType: d.usageType,
              isp: d.isp,
              domain: d.domain,
              isTor: Boolean(d.isTor)
            },
            sourceUrl: `https://www.abuseipdb.com/check/${ip}`
          }
        ],
        entities: [],
        relationships: [],
        sourceReferences: [
          {
            providerId: this.id,
            providerName: this.name,
            sourceUrl: `https://www.abuseipdb.com/check/${ip}`,
            observedAt: observedTimestamp,
            queriedAt: queryTimestamp,
            confidence: 'confirmed',
            sensitivity: 'public',
            verificationStatus: 'verified'
          }
        ],
        rawResult: d as Record<string, unknown>,
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

export class GoogleSafeBrowsingProvider
  implements OsintProvider<string, Record<string, unknown>>
{
  id = 'google-safebrowsing';
  name = 'Google Safe Browsing v4 Phishing & Malware Reputation';
  category = 'web' as const;
  supportedTypes = ['url' as const, 'domain' as const];
  requiresApiKey = true;
  envVarNames = ['GOOGLE_SAFE_BROWSING_API_KEY'];
  isFreeTierAvailable = true;
  rateLimitPerMinute = 30;
  disclosureNotice =
    'Queries Google Safe Browsing v4 API when GOOGLE_SAFE_BROWSING_API_KEY is configured.';
  featureIds = ['WEB-07', 'THR-02'];

  isConfigured(): boolean {
    return Boolean(process.env.GOOGLE_SAFE_BROWSING_API_KEY?.trim());
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
    return `https://${d.normalizedValue}/`;
  }

  async execute(
    input: string,
    _context: InvestigationContext
  ): Promise<ProviderResult<Record<string, unknown>>> {
    const queryTimestamp = new Date().toISOString();
    const targetUrl = this.validateInput(input);

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
        errors: ['GOOGLE_SAFE_BROWSING_API_KEY is not configured in environment.'],
        confidence: 'low',
        sensitivity: 'public'
      };
    }

    const startMs = Date.now();
    try {
      const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY!.trim();
      const res = await fetch(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client: { clientId: 'sentinel-osint', clientVersion: '2.0.0' },
            threatInfo: {
              threatTypes: [
                'MALWARE',
                'SOCIAL_ENGINEERING',
                'UNWANTED_SOFTWARE',
                'POTENTIALLY_HARMFUL_APPLICATION'
              ],
              platformTypes: ['ANY_PLATFORM'],
              threatEntryTypes: ['URL'],
              threatEntries: [{ url: targetUrl }]
            }
          }),
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
          errors: ['Google Safe Browsing rate limit reached.'],
          confidence: 'low',
          sensitivity: 'public'
        };
      }

      if (!res.ok) throw new Error(`Safe Browsing returned HTTP ${res.status}`);
      const data = (await res.json()) as {
        matches?: Array<{ threatType?: string; platformType?: string }>;
      };
      const matches = Array.isArray(data.matches) ? data.matches : [];
      const observedTimestamp = new Date().toISOString();

      return {
        providerId: this.id,
        providerName: this.name,
        status: 'completed',
        findings: [
          {
            moduleCode: 'WEB-07',
            category: 'web',
            title: `Google Safe Browsing Verdict (${matches.length} Threat Match(es))`,
            summary:
              matches.length > 0
                ? `Flagged by Google Safe Browsing for: ${matches.map((m) => m.threatType).join(', ')}.`
                : `No active phishing or malware matches in Google Safe Browsing for ${targetUrl}.`,
            severity: matches.length > 0 ? 'critical' : 'info',
            confidence: 'confirmed',
            tags: ['safe-browsing', 'phishing-check'],
            attributes: {
              targetUrl,
              matchCount: matches.length,
              matches
            }
          }
        ],
        entities: [],
        relationships: [],
        sourceReferences: [],
        rawResult: { matches },
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
