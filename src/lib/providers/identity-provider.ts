import crypto from 'crypto';
import { parsePhoneNumberFromString } from 'libphonenumber-js';
import {
  DiscoveredEntityInput,
  DiscoveredRelationshipInput,
  InvestigationContext,
  NormalizedFindingInput,
  OsintProvider,
  ProviderResult
} from '@/types/osint';
import {
  validateAndNormalizeEmail,
  validateAndNormalizePhone,
  validateAndNormalizeUsername
} from '@/lib/validation/schemas';
import { sanitizeText } from '@/lib/security/sanitizer';

const DISPOSABLE_EMAIL_DOMAINS = new Set([
  '10minutemail.com',
  '10minutemail.net',
  '20minutemail.com',
  'anonbox.net',
  'Boun.cr',
  'burnermail.io',
  'discard.email',
  'discardmail.com',
  'dispostable.com',
  'dropmail.me',
  'emailondeck.com',
  'fakeinbox.com',
  'fakemailgenerator.com',
  'getairmail.com',
  'getnada.com',
  'grr.la',
  'guerrillamail.biz',
  'guerrillamail.com',
  'guerrillamail.de',
  'guerrillamail.info',
  'guerrillamail.net',
  'guerrillamail.org',
  'guerrillamailblock.com',
  'harakirimail.com',
  'inboxkitten.com',
  'jetable.org',
  'koszmail.pl',
  'mailcatch.com',
  'maildrop.cc',
  'mailexpire.com',
  'mailforspam.com',
  'mailinator.com',
  'mailinator.net',
  'mailinator2.com',
  'mailnesia.com',
  'mailnull.com',
  'mailsac.com',
  'mailtemp.info',
  'mintemail.com',
  'mohmal.com',
  'mt2015.com',
  'mytemp.email',
  'mytrashmail.com',
  'nada.email',
  'OwlPic.com',
  'pokemail.net',
  'sharklasers.com',
  'spam4.me',
  'spambox.us',
  'spamgourmet.com',
  'spamhole.com',
  'temp-mail.io',
  'temp-mail.org',
  'tempail.com',
  'tempinbox.com',
  'tempmail.com',
  'tempmail.net',
  'tempmailaddress.com',
  'tempmailo.com',
  'throwawaymail.com',
  'tmail.ws',
  'trashmail.com',
  'trashmail.de',
  'trashmail.me',
  'trashmail.net',
  'yopmail.com',
  'yopmail.fr',
  'yopmail.net'
]);

const ROLE_ACCOUNT_PREFIXES = new Set([
  'admin',
  'administrator',
  'Root',
  'security',
  'secops',
  'soc',
  'abuse',
  'postmaster',
  'hostmaster',
  'webmaster',
  'support',
  'help',
  'info',
  'contact',
  'sales',
  'billing',
  'legal',
  'privacy',
  'hr',
  'noc',
  'noreply',
  'no-reply'
]);

export class EmailIntelligenceProvider
  implements OsintProvider<string, Record<string, unknown>>
{
  id = 'email-posture';
  name = 'Email Syntax, Disposable Detection & Public Gravatar Correlation';
  category = 'identity' as const;
  supportedTypes = ['email' as const];
  requiresApiKey = false;
  envVarNames: string[] = [];
  isFreeTierAvailable = true;
  rateLimitPerMinute = 60;
  disclosureNotice =
    'Validates email syntax and disposable provider status locally; queries Gravatar using a one-way cryptographic hash of the email.';
  featureIds = ['ID-01', 'ID-03', 'ID-09'];

  isConfigured(): boolean {
    return true;
  }

  validateInput(input: unknown): string {
    const val = validateAndNormalizeEmail(String(input || ''));
    if (!val.valid) throw new Error(val.error);
    return val.normalizedValue;
  }

  async execute(
    input: string,
    _context: InvestigationContext
  ): Promise<ProviderResult<Record<string, unknown>>> {
    const startMs = Date.now();
    const queryTimestamp = new Date().toISOString();
    const emailValidation = validateAndNormalizeEmail(String(input || ''));
    if (!emailValidation.valid) {
      throw new Error(emailValidation.error);
    }

    const email = emailValidation.normalizedValue;
    const localPart = String(emailValidation.metadata.localPart);
    const baseLocalPart = String(emailValidation.metadata.baseLocalPart);
    const subaddressTag = emailValidation.metadata.subaddressTag as string | null;
    const domain = String(emailValidation.metadata.domain);

    const isDisposable = DISPOSABLE_EMAIL_DOMAINS.has(domain);
    const isRoleAccount = ROLE_ACCOUNT_PREFIXES.has(baseLocalPart.toLowerCase());

    const md5Hash = crypto.createHash('md5').update(email).digest('hex');
    const sha256Hash = crypto.createHash('sha256').update(email).digest('hex');

    let gravatarProfile: {
      found: boolean;
      displayName?: string;
      preferredUsername?: string;
      profileUrl?: string;
      location?: string;
      verifiedAccounts?: string[];
    } = { found: false };

    try {
      const gravRes = await fetch(`https://en.gravatar.com/${md5Hash}.json`, {
        headers: {
          Accept: 'application/json',
          'User-Agent': 'Sentinel-OSINT/2.0'
        },
        signal: AbortSignal.timeout(4500)
      });
      if (gravRes.ok) {
        const gravData = (await gravRes.json()) as {
          entry?: Array<{
            displayName?: string;
            preferredUsername?: string;
            profileUrl?: string;
            currentLocation?: string;
            accounts?: Array<{ shortname?: string; url?: string }>;
          }>;
        };
        const entry = gravData.entry?.[0];
        if (entry) {
          gravatarProfile = {
            found: true,
            displayName: sanitizeText(entry.displayName, 100),
            preferredUsername: sanitizeText(entry.preferredUsername, 80),
            profileUrl: sanitizeText(entry.profileUrl, 200),
            location: sanitizeText(entry.currentLocation, 100),
            verifiedAccounts: (entry.accounts || [])
              .map((a) => `${sanitizeText(a.shortname, 40)}: ${sanitizeText(a.url, 160)}`)
              .slice(0, 10)
          };
        }
      }
    } catch {
      // Optional Gravatar check
    }

    const findings: NormalizedFindingInput[] = [
      {
        moduleCode: 'ID-01',
        category: 'identity',
        title: `Email Syntax, Normalization & Structure (${email})`,
        summary: `Valid RFC 5322 address. Domain: ${domain} | Role Account: ${isRoleAccount ? 'Yes' : 'No'} | Subaddressing (+tag): ${subaddressTag || 'None'}.`,
        severity: 'info',
        confidence: 'confirmed',
        tags: ['email', 'syntax', isRoleAccount ? 'role-account' : 'personal-format'],
        attributes: {
          email,
          localPart,
          baseLocalPart,
          subaddressTag,
          domain,
          isRoleAccount,
          sha256Hash
        }
      },
      {
        moduleCode: 'ID-03',
        category: 'identity',
        title: `Disposable & Throwaway Email Assessment (${isDisposable ? 'DISPOSABLE DETECTED' : 'Standard Domain'})`,
        summary: isDisposable
          ? `Domain ${domain} matches known disposable/temporary email provider dataset.`
          : `Domain ${domain} is not listed in the known disposable email provider dataset.`,
        severity: isDisposable ? 'high' : 'info',
        confidence: 'confirmed',
        tags: ['disposable-email', isDisposable ? 'throwaway' : 'standard-domain'],
        attributes: {
          domain,
          isDisposable,
          datasetSize: DISPOSABLE_EMAIL_DOMAINS.size
        }
      }
    ];

    const entities: DiscoveredEntityInput[] = [
      {
        key: `email:${email}`,
        entityType: 'email',
        label: email,
        value: email,
        confidence: 'confirmed',
        metadata: { isDisposable, isRoleAccount }
      },
      {
        key: `domain:${domain}`,
        entityType: 'domain',
        label: domain,
        value: domain,
        confidence: 'confirmed'
      }
    ];
    const relationships: DiscoveredRelationshipInput[] = [
      {
        sourceKey: `email:${email}`,
        targetKey: `domain:${domain}`,
        relationshipType: 'hosted_at_domain',
        confidence: 'confirmed'
      }
    ];

    if (gravatarProfile.found) {
      findings.push({
        moduleCode: 'ID-09',
        category: 'identity',
        title: `Public Gravatar Profile Match (${gravatarProfile.displayName || gravatarProfile.preferredUsername || email})`,
        summary: `Public Gravatar metadata associated with email hash: Display Name "${gravatarProfile.displayName || 'N/A'}", Username "${gravatarProfile.preferredUsername || 'N/A'}".`,
        severity: 'info',
        confidence: 'high',
        tags: ['gravatar', 'identity-correlation'],
        attributes: {
          ...gravatarProfile,
          safeguardNotice:
            'Self-reported public Gravatar profile fields; verify independently before attribution.'
        },
        sourceUrl: gravatarProfile.profileUrl || `https://en.gravatar.com/${md5Hash}`
      });

      if (gravatarProfile.preferredUsername) {
        const profKey = `profile:gravatar:${gravatarProfile.preferredUsername.toLowerCase()}`;
        entities.push({
          key: profKey,
          entityType: 'profile',
          label: `Gravatar: ${gravatarProfile.preferredUsername}`,
          value: gravatarProfile.preferredUsername,
          confidence: 'high',
          metadata: gravatarProfile
        });
        relationships.push({
          sourceKey: `email:${email}`,
          targetKey: profKey,
          relationshipType: 'matches_email_hash',
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
          sourceUrl: gravatarProfile.found
            ? `https://en.gravatar.com/${md5Hash}.json`
            : undefined,
          observedAt: observedTimestamp,
          queriedAt: queryTimestamp,
          confidence: 'confirmed',
          sensitivity: 'public',
          verificationStatus: 'verified',
          citationNote: `Local RFC 5322 + Disposable dataset + Gravatar hash check for ${email}`
        }
      ],
      rawResult: {
        email,
        domain,
        isDisposable,
        isRoleAccount,
        gravatarProfile
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

export class HibpBreachProvider
  implements OsintProvider<string, Record<string, unknown>>
{
  id = 'hibp-breach';
  name = 'Have I Been Pwned (HIBP v3) Breach Exposure Service';
  category = 'identity' as const;
  supportedTypes = ['email' as const];
  requiresApiKey = true;
  envVarNames = ['HIBP_API_KEY'];
  isFreeTierAvailable = false;
  rateLimitPerMinute = 10;
  disclosureNotice =
    'Queries Have I Been Pwned official v3 API for breach metadata only when HIBP_API_KEY is configured. Never retrieves plaintext passwords.';
  featureIds = ['ID-04'];

  isConfigured(): boolean {
    return Boolean(process.env.HIBP_API_KEY?.trim());
  }

  validateInput(input: unknown): string {
    const val = validateAndNormalizeEmail(String(input || ''));
    if (!val.valid) throw new Error(val.error);
    return val.normalizedValue;
  }

  async execute(
    input: string,
    _context: InvestigationContext
  ): Promise<ProviderResult<Record<string, unknown>>> {
    const queryTimestamp = new Date().toISOString();
    const email = this.validateInput(input);

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
        errors: [
          'HIBP_API_KEY is not configured. Have I Been Pwned v3 requires a paid API key.'
        ],
        confidence: 'low',
        sensitivity: 'sensitive'
      };
    }

    const startMs = Date.now();
    const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`;
    try {
      const res = await fetch(url, {
        headers: {
          'hibp-api-key': process.env.HIBP_API_KEY!.trim(),
          'user-agent': 'Sentinel-OSINT-Platform/2.0'
        },
        signal: AbortSignal.timeout(7000)
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
          errors: ['HIBP API rate limit exceeded.'],
          confidence: 'low',
          sensitivity: 'sensitive'
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
              moduleCode: 'ID-04',
              category: 'identity',
              title: `Authorized Breach Exposure Check (0 Public Breaches Indexed)`,
              summary: `No public breach incidents indexed for ${email} in Have I Been Pwned.`,
              severity: 'info',
              confidence: 'confirmed',
              sensitivity: 'sensitive',
              tags: ['hibp', 'breach-check'],
              attributes: { email, breachCount: 0, breaches: [] }
            }
          ],
          entities: [],
          relationships: [],
          sourceReferences: [
            {
              providerId: this.id,
              providerName: this.name,
              sourceUrl: 'https://haveibeenpwned.com/',
              observedAt: observedTimestamp,
              queriedAt: queryTimestamp,
              confidence: 'confirmed',
              sensitivity: 'sensitive',
              verificationStatus: 'verified'
            }
          ],
          rawResult: { email, breaches: [] },
          observedTimestamp,
          queryTimestamp,
          durationMs: Date.now() - startMs,
          errors: [],
          confidence: 'confirmed',
          sensitivity: 'sensitive'
        };
      }

      if (!res.ok) {
        throw new Error(`HIBP API returned HTTP ${res.status}`);
      }

      const breaches = (await res.json()) as Array<{
        Name?: string;
        Title?: string;
        Domain?: string;
        BreachDate?: string;
        DataClasses?: string[];
        IsVerified?: boolean;
      }>;

      const summaryList = breaches.slice(0, 25).map((b) => ({
        name: sanitizeText(b.Name, 80),
        title: sanitizeText(b.Title, 120),
        domain: sanitizeText(b.Domain, 100),
        breachDate: sanitizeText(b.BreachDate, 32),
        dataClasses: (b.DataClasses || []).map((c) => sanitizeText(c, 60)),
        isVerified: Boolean(b.IsVerified)
      }));

      const observedTimestamp = new Date().toISOString();
      return {
        providerId: this.id,
        providerName: this.name,
        status: 'completed',
        findings: [
          {
            moduleCode: 'ID-04',
            category: 'identity',
            title: `Authorized Breach Exposure (${breaches.length} Breach Incident(s))`,
            summary: `Email ${email} appears in ${breaches.length} documented breach dataset(s): ${summaryList.map((b) => `${b.title} (${b.breachDate})`).slice(0, 6).join(', ')}. Plaintext credentials are never retrieved.`,
            severity: breaches.length > 0 ? 'high' : 'info',
            confidence: 'confirmed',
            sensitivity: 'sensitive',
            tags: ['hibp', 'breach-exposure'],
            attributes: {
              email,
              breachCount: breaches.length,
              breaches: summaryList,
              privacySafeguard:
                'Metadata only (breach title, date, exposed data classes). No passwords or raw dumps are accessed.'
            },
            sourceUrl: 'https://haveibeenpwned.com/'
          }
        ],
        entities: [],
        relationships: [],
        sourceReferences: [
          {
            providerId: this.id,
            providerName: this.name,
            sourceUrl: 'https://haveibeenpwned.com/',
            observedAt: observedTimestamp,
            queriedAt: queryTimestamp,
            confidence: 'confirmed',
            sensitivity: 'sensitive',
            verificationStatus: 'verified'
          }
        ],
        rawResult: { email, breachCount: breaches.length, breaches: summaryList },
        observedTimestamp,
        queryTimestamp,
        durationMs: Date.now() - startMs,
        errors: [],
        confidence: 'confirmed',
        sensitivity: 'sensitive'
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
        sensitivity: 'sensitive'
      };
    }
  }
}

export class PhoneNumberMetadataProvider
  implements OsintProvider<string, Record<string, unknown>>
{
  id = 'phone-metadata';
  name = 'ITU Numbering Plan & E.164 Metadata Analyzer (libphonenumber)';
  category = 'identity' as const;
  supportedTypes = ['phone' as const];
  requiresApiKey = false;
  envVarNames: string[] = [];
  isFreeTierAvailable = true;
  rateLimitPerMinute = 120;
  disclosureNotice =
    'Analyzes phone numbering structure locally via libphonenumber-js. Zero external network calls or carrier subscriber queries are made.';
  featureIds = ['ID-07', 'ID-08'];

  isConfigured(): boolean {
    return true;
  }

  validateInput(input: unknown): string {
    const val = validateAndNormalizePhone(String(input || ''));
    if (!val.valid) throw new Error(val.error);
    return val.normalizedValue;
  }

  async execute(
    input: string,
    _context: InvestigationContext
  ): Promise<ProviderResult<Record<string, unknown>>> {
    const startMs = Date.now();
    const queryTimestamp = new Date().toISOString();
    const e164 = this.validateInput(input);
    const parsed = parsePhoneNumberFromString(e164);

    if (!parsed || !parsed.isValid()) {
      throw new Error('Phone number failed ITU numbering plan validation.');
    }

    const numberType = parsed.getType() || 'FIXED_LINE_OR_MOBILE';
    const countryIso = parsed.country || 'International';
    const countryCallingCode = `+${parsed.countryCallingCode}`;
    const internationalFormat = parsed.formatInternational();
    const nationalFormat = parsed.formatNational();
    const rfc3966Uri = parsed.getURI();

    const findings: NormalizedFindingInput[] = [
      {
        moduleCode: 'ID-07',
        category: 'identity',
        title: `Phone Format & ITU E.164 Validation (${internationalFormat})`,
        summary: `Valid ITU-T E.164 number (${e164}). National format: ${nationalFormat} | URI: ${rfc3966Uri}.`,
        severity: 'info',
        confidence: 'confirmed',
        tags: ['phone', 'e164', 'libphonenumber'],
        attributes: {
          e164,
          internationalFormat,
          nationalFormat,
          rfc3966Uri,
          isValid: true,
          isPossible: parsed.isPossible()
        }
      },
      {
        moduleCode: 'ID-08',
        category: 'identity',
        title: `Country & Numbering Plan Metadata (${countryIso} ${countryCallingCode} — ${numberType})`,
        summary: `Assigned Region: ${countryIso} (${countryCallingCode}) | Numbering Plan Range Type: ${numberType}. Privacy Note: No carrier subscriber or CNAM lookup performed.`,
        severity: 'info',
        confidence: 'confirmed',
        tags: ['numbering-plan', countryIso.toLowerCase()],
        attributes: {
          countryIso,
          countryCallingCode,
          numberType,
          nationalNumber: parsed.nationalNumber,
          privacySafeguard:
            'ITU numbering plan metadata only. Private subscriber records and carrier HLR lookups are prohibited.'
        }
      }
    ];

    const entities: DiscoveredEntityInput[] = [
      {
        key: `phone:${e164}`,
        entityType: 'phone',
        label: internationalFormat,
        value: e164,
        confidence: 'confirmed',
        metadata: { countryIso, countryCallingCode, numberType }
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
          sensitivity: 'public',
          verificationStatus: 'verified',
          citationNote: 'Local ITU-T E.164 numbering plan evaluation via libphonenumber-js'
        }
      ],
      rawResult: {
        e164,
        internationalFormat,
        nationalFormat,
        countryIso,
        countryCallingCode,
        numberType
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

interface DiscoveredSocialProfile {
  platform: string;
  username: string;
  profileUrl: string;
  displayName?: string;
  bio?: string;
  createdAt?: string;
  accountType?: string;
  externalLinks?: string[];
  cryptographicProofs?: Array<{ service: string; handle: string; proofUrl?: string }>;
  confidence: 'high' | 'low';
}

export class PublicProfileDiscoveryProvider
  implements OsintProvider<string, { profiles: DiscoveredSocialProfile[] }>
{
  id = 'public-profiles';
  name = 'Official Public Developer & Social Profile Discovery';
  category = 'social' as const;
  supportedTypes = ['username' as const, 'organization' as const];
  requiresApiKey = false;
  envVarNames: string[] = [];
  isFreeTierAvailable = true;
  rateLimitPerMinute = 20;
  disclosureNotice =
    'Queries official unauthenticated public JSON APIs (GitHub, GitLab, Keybase, HackerNews) to check public handle existence and metadata.';
  featureIds = [
    'ID-05',
    'ID-06',
    'ID-09',
    'SOC-01',
    'SOC-02',
    'SOC-03',
    'SOC-04',
    'SOC-05',
    'SOC-06',
    'SOC-07',
    'SOC-08'
  ];

  isConfigured(): boolean {
    return true;
  }

  validateInput(input: unknown): string {
    const raw = String(input || '')
      .trim()
      .replace(/^@/, '')
      .replace(/\s+/g, '');
    const val = validateAndNormalizeUsername(raw);
    if (!val.valid) throw new Error(val.error);
    return val.normalizedValue;
  }

  async execute(
    input: string,
    _context: InvestigationContext
  ): Promise<ProviderResult<{ profiles: DiscoveredSocialProfile[] }>> {
    const startMs = Date.now();
    const queryTimestamp = new Date().toISOString();
    const username = this.validateInput(input);

    const profiles: DiscoveredSocialProfile[] = [];
    const errors: string[] = [];

    // 1. GitHub Official REST API
    const ghPromise = (async () => {
      try {
        const res = await fetch(
          `https://api.github.com/users/${encodeURIComponent(username)}`,
          {
            headers: {
              Accept: 'application/vnd.github+json',
              'User-Agent': 'Sentinel-OSINT-Platform/2.0'
            },
            signal: AbortSignal.timeout(5500)
          }
        );
        if (res.status === 200) {
          const data = (await res.json()) as {
            login?: string;
            html_url?: string;
            name?: string;
            bio?: string;
            blog?: string;
            type?: string;
            created_at?: string;
            public_repos?: number;
            followers?: number;
          };
          const links: string[] = [];
          if (data.blog) links.push(sanitizeText(data.blog, 200));
          profiles.push({
            platform: 'GitHub',
            username: sanitizeText(data.login || username, 64),
            profileUrl:
              sanitizeText(data.html_url, 200) ||
              `https://github.com/${encodeURIComponent(username)}`,
            displayName: sanitizeText(data.name, 100) || undefined,
            bio: sanitizeText(data.bio, 250) || undefined,
            createdAt: data.created_at,
            accountType: data.type || 'User',
            externalLinks: links,
            confidence: 'low'
          });
        } else if (res.status !== 404) {
          errors.push(`GitHub API returned HTTP ${res.status}`);
        }
      } catch (e) {
        errors.push(`GitHub lookup error: ${(e as Error).message}`);
      }
    })();

    // 2. GitLab Official Public API
    const glPromise = (async () => {
      try {
        const res = await fetch(
          `https://gitlab.com/api/v4/users?username=${encodeURIComponent(username)}`,
          {
            headers: { Accept: 'application/json', 'User-Agent': 'Sentinel-OSINT/2.0' },
            signal: AbortSignal.timeout(5500)
          }
        );
        if (res.status === 200) {
          const arr = (await res.json()) as Array<{
            username?: string;
            name?: string;
            web_url?: string;
          }>;
          if (Array.isArray(arr) && arr.length > 0) {
            const u = arr[0];
            profiles.push({
              platform: 'GitLab',
              username: sanitizeText(u.username || username, 64),
              profileUrl:
                sanitizeText(u.web_url, 200) ||
                `https://gitlab.com/${encodeURIComponent(username)}`,
              displayName: sanitizeText(u.name, 100) || undefined,
              accountType: 'User',
              confidence: 'low'
            });
          }
        } else if (res.status !== 404) {
          errors.push(`GitLab API returned HTTP ${res.status}`);
        }
      } catch (e) {
        errors.push(`GitLab lookup error: ${(e as Error).message}`);
      }
    })();

    // 3. Keybase Official Public Lookup API (with Cryptographic Proofs!)
    const kbPromise = (async () => {
      try {
        const res = await fetch(
          `https://keybase.io/_/api/1.0/user/lookup.json?usernames=${encodeURIComponent(username)}`,
          {
            headers: { Accept: 'application/json' },
            signal: AbortSignal.timeout(5500)
          }
        );
        if (res.status === 200) {
          const data = (await res.json()) as {
            them?: Array<{
              basics?: { username?: string; ctime?: number };
              profile?: { full_name?: string; bio?: string; location?: string };
              proofs_summary?: {
                all?: Array<{
                  proof_type?: string;
                  nametag?: string;
                  service_url?: string;
                }>;
              };
            } | null>;
          };
          const entry = data.them?.[0];
          if (entry && entry.basics?.username) {
            const proofs = (entry.proofs_summary?.all || []).map((p) => ({
              service: sanitizeText(p.proof_type, 40),
              handle: sanitizeText(p.nametag, 80),
              proofUrl: sanitizeText(p.service_url, 200) || undefined
            }));
            profiles.push({
              platform: 'Keybase',
              username: sanitizeText(entry.basics.username, 64),
              profileUrl: `https://keybase.io/${encodeURIComponent(entry.basics.username)}`,
              displayName: sanitizeText(entry.profile?.full_name, 100) || undefined,
              bio: sanitizeText(entry.profile?.bio, 250) || undefined,
              createdAt: entry.basics.ctime
                ? new Date(entry.basics.ctime * 1000).toISOString()
                : undefined,
              accountType: 'User',
              cryptographicProofs: proofs,
              confidence: proofs.length > 0 ? 'high' : 'low'
            });
          }
        }
      } catch (e) {
        errors.push(`Keybase lookup error: ${(e as Error).message}`);
      }
    })();

    // 4. HackerNews Official Firebase API
    const hnPromise = (async () => {
      try {
        const res = await fetch(
          `https://hacker-news.firebaseio.com/v0/user/${encodeURIComponent(username)}.json`,
          {
            headers: { Accept: 'application/json' },
            signal: AbortSignal.timeout(5000)
          }
        );
        if (res.status === 200) {
          const data = (await res.json()) as {
            id?: string;
            created?: number;
            karma?: number;
            about?: string;
          } | null;
          if (data && data.id) {
            profiles.push({
              platform: 'HackerNews',
              username: sanitizeText(data.id, 64),
              profileUrl: `https://news.ycombinator.com/user?id=${encodeURIComponent(data.id)}`,
              bio: data.about ? sanitizeText(data.about, 250) : `Karma: ${data.karma ?? 0}`,
              createdAt: data.created
                ? new Date(data.created * 1000).toISOString()
                : undefined,
              accountType: 'User',
              confidence: 'low'
            });
          }
        }
      } catch (e) {
        errors.push(`HackerNews lookup error: ${(e as Error).message}`);
      }
    })();

    await Promise.allSettled([ghPromise, glPromise, kbPromise, hnPromise]);

    const findings: NormalizedFindingInput[] = [
      {
        moduleCode: 'ID-05',
        category: 'social',
        title: `Public Handle Discovery (${profiles.length} Confirmed Public Account(s) for "${username}")`,
        summary:
          profiles.length > 0
            ? `Confirmed public profiles on [${profiles.map((p) => p.platform).join(', ')}]. Safeguard: Handle string match alone does NOT prove same natural person ownership.`
            : `No public profiles matched "${username}" across queried official APIs.`,
        severity: 'info',
        confidence: profiles.some((p) => p.confidence === 'high') ? 'high' : 'low',
        tags: ['username', 'social-osint', ...profiles.map((p) => p.platform.toLowerCase())],
        attributes: {
          username,
          confirmedProfileCount: profiles.length,
          profiles,
          providerErrors: errors,
          identitySafeguard:
            'Coincidental username matches are classified as low-confidence correlations unless backed by cryptographic proofs (e.g. Keybase).'
        },
        sourceUrl: profiles[0]?.profileUrl
      }
    ];

    // Timeline finding if creation timestamps exist (SOC-08)
    const datedProfiles = profiles
      .filter((p) => Boolean(p.createdAt))
      .sort((a, b) => (a.createdAt || '').localeCompare(b.createdAt || ''));
    if (datedProfiles.length > 0) {
      findings.push({
        moduleCode: 'SOC-08',
        category: 'social',
        title: `Public Account Registration Timeline (${datedProfiles.length} timestamped source(s))`,
        summary: datedProfiles
          .map((p) => `${p.platform}: ${p.createdAt?.slice(0, 10)}`)
          .join(' → '),
        severity: 'info',
        confidence: 'confirmed',
        tags: ['timeline', 'account-creation'],
        attributes: {
          chronologicalAccounts: datedProfiles.map((p) => ({
            platform: p.platform,
            username: p.username,
            createdAt: p.createdAt,
            profileUrl: p.profileUrl
          }))
        }
      });
    }

    const rootKey = `profile:handle:${username.toLowerCase()}`;
    const entities: DiscoveredEntityInput[] = [
      {
        key: rootKey,
        entityType: 'profile',
        label: `@${username}`,
        value: username,
        confidence: 'confirmed'
      }
    ];
    const relationships: DiscoveredRelationshipInput[] = [];

    for (const prof of profiles) {
      const pKey = `profile:${prof.platform.toLowerCase()}:${prof.username.toLowerCase()}`;
      entities.push({
        key: pKey,
        entityType: 'profile',
        label: `${prof.platform}: ${prof.username}`,
        value: prof.profileUrl,
        confidence: prof.confidence,
        metadata: {
          platform: prof.platform,
          displayName: prof.displayName,
          createdAt: prof.createdAt,
          accountType: prof.accountType
        }
      });
      relationships.push({
        sourceKey: rootKey,
        targetKey: pKey,
        relationshipType:
          prof.confidence === 'high'
            ? 'cryptographically_verified_profile'
            : 'handle_string_match_unverified_owner',
        confidence: prof.confidence,
        verificationStatus: prof.confidence === 'high' ? 'verified' : 'unverified'
      });
    }

    const observedTimestamp = new Date().toISOString();
    return {
      providerId: this.id,
      providerName: this.name,
      status: profiles.length > 0 || errors.length === 0 ? 'completed' : 'partial',
      findings,
      entities,
      relationships,
      sourceReferences: profiles.map((p) => ({
        providerId: this.id,
        providerName: `${this.name} (${p.platform})`,
        sourceUrl: p.profileUrl,
        observedAt: observedTimestamp,
        queriedAt: queryTimestamp,
        confidence: p.confidence,
        sensitivity: 'public' as const,
        verificationStatus:
          p.confidence === 'high' ? ('verified' as const) : ('unverified' as const),
        citationNote: `Public ${p.platform} profile API record for ${p.username}`
      })),
      rawResult: { profiles },
      observedTimestamp,
      queryTimestamp,
      durationMs: Date.now() - startMs,
      errors,
      confidence: profiles.some((p) => p.confidence === 'high') ? 'high' : 'low',
      sensitivity: 'public'
    };
  }
}
