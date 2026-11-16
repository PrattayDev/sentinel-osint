# Sentinel OSINT — Provider & Tool Integrations

## 1. Provider Adapter Architecture

Every integration in Sentinel OSINT implements the canonical `OsintProvider<TInput, TResult>` interface (`src/types/osint.ts`):

```ts
export interface OsintProvider<TInput, TResult = Record<string, unknown>> {
  id: string;
  name: string;
  category: OsintCategory;
  supportedTypes: TargetType[];
  requiresApiKey: boolean;
  envVarNames: string[];
  rateLimitPerMinute: number;
  disclosureNotice: string;

  isConfigured(): boolean;
  validateInput(input: unknown): TInput;
  execute(
    input: TInput,
    context: InvestigationContext
  ): Promise<ProviderResult<TResult>>;
}
```

### Explicit Status Model
Every provider execution returns one of:
- `completed` — Live lookup succeeded and returned normalized findings.
- `partial` — Lookup returned partial intelligence (e.g., some sub-queries timed out or returned empty).
- `not_configured` — Required API key environment variable is not set; no network request was attempted.
- `rate_limited` — Upstream provider returned HTTP 429 or local rate limiter throttled the request.
- `failed` — Upstream endpoint returned an error or timed out.
- `unsupported` — Input does not qualify for this provider (e.g., private IP blocked from external transmission).

---

## 2. Integrated Providers Catalog

### 2.1 Zero-Key Standards & Public APIs (Work Out-of-the-Box)

| Provider ID | Name | Endpoint / Mechanism | Supported Targets | Data Sent | Timeout | Rate Limit |
|---|---|---|---|---|---|---|
| `dns-core` | Authoritative DNS & DoH | Node `dns.promises` + `https://cloudflare-dns.com/dns-query` | `domain`, `email` | Domain name | 6,000 ms | 60 / min |
| `rdap-registry` | IANA / RIR RDAP | `https://rdap.org/domain/{d}` & `https://rdap.org/ip/{ip}` | `domain`, `ip` | Domain or public IP | 8,000 ms | 30 / min |
| `tls-inspector` | Direct TLS Handshake Inspector | Node `tls.connect` (port 443, SSRF-guarded) | `domain`, `url` | Hostname (SNI) | 6,000 ms | 30 / min |
| `ct-logs` | Certificate Transparency (`crt.sh` & CertSpotter) | `https://crt.sh/?q=%.{d}&output=json`, `https://api.certspotter.com/v1/issuances` | `domain` | Domain name | 10,000 ms | 15 / min |
| `http-security` | Safe HTTP & Security Header Inspector | SSRF-guarded `fetch` (`redirect: manual`, max 5 hops) | `domain`, `url` | URL / Hostname | 8,000 ms | 30 / min |
| `ripestat-bgp` | RIPEstat ASN, BGP & GeoLite | `https://stat.ripe.net/data/{endpoint}/data.json` | `ip` | Public IP | 7,000 ms | 40 / min |
| `shodan-internetdb` | Shodan InternetDB Passive Ports/Vulns | `https://internetdb.shodan.io/{ip}` | `ip` | Public IP | 6,000 ms | 30 / min |
| `wayback-archive` | Internet Archive Wayback & CDX | `https://archive.org/wayback/available`, `https://web.archive.org/cdx/search/cdx` | `url`, `domain` | URL / Domain | 8,000 ms | 20 / min |
| `abusech-threat` | abuse.ch URLhaus, ThreatFox & MalwareBazaar | `https://urlhaus-api.abuse.ch/v1/`, `https://threatfox-api.abuse.ch/api/v1/`, `https://mb-api.abuse.ch/api/v1/` | `domain`, `ip`, `url`, `file_hash` | Indicator string | 8,000 ms | 20 / min |
| `public-profiles` | Official Public Developer & Social APIs | GitHub API, GitLab API, Keybase API, HackerNews Firebase API, Reddit `/about.json`, Gravatar JSON | `username`, `email`, `organization` | Username or SHA-256 email hash | 7,000 ms | 20 / min |
| `gleif-lei` | GLEIF Global Legal Entity Identifier Registry | `https://api.gleif.org/api/v1/lei-records` | `organization` | Organization name | 8,000 ms | 30 / min |
| `wikidata-org` | Wikipedia / Wikidata Public Entity API | `https://en.wikipedia.org/w/api.php` | `organization` | Organization name | 6,000 ms | 30 / min |
| `phone-metadata` | ITU Numbering Plan Analyzer (`libphonenumber-js`) | Local deterministic library (zero external transmission) | `phone` | None (local only) | 1,000 ms | 120 / min |
| `email-posture` | Email Syntax, Disposable & DMARC/SPF Posture | Local dataset + DNS TXT/MX | `email` | Domain part only (to DNS) | 6,000 ms | 60 / min |
| `file-metadata` | Binary EXIF, PDF Metadata & Cryptographic/Perceptual Hash | Local in-memory sandboxed binary parser | `file` | None (local only) | 5,000 ms | 30 / min |

### 2.2 Keyed Official APIs (Enabled Automatically When Configured)

| Provider ID | Name | Required Environment Variable(s) | Official Endpoint | Free Tier Available? |
|---|---|---|---|---|
| `hibp-breach` | Have I Been Pwned v3 | `HIBP_API_KEY` | `https://haveibeenpwned.com/api/v3/breachedaccount/{email}` | Paid subscription required by HIBP v3 |
| `virustotal-v3` | VirusTotal API v3 | `VIRUSTOTAL_API_KEY` | `https://www.virustotal.com/api/v3/{files\|urls\|domains\|ip_addresses}/{id}` | Yes (Public API: 4 req/min, 500/day; non-commercial) |
| `abuseipdb-v2` | AbuseIPDB API v2 | `ABUSEIPDB_API_KEY` | `https://api.abuseipdb.com/api/v2/check` | Yes (1,000 checks/day free tier) |
| `google-safebrowsing` | Google Safe Browsing v4 | `GOOGLE_SAFE_BROWSING_API_KEY` | `https://safebrowsing.googleapis.com/v4/threatMatches:find` | Yes (Free non-commercial quota via Google Cloud) |
| `shodan-full` | Shodan REST API | `SHODAN_API_KEY` | `https://api.shodan.io/shodan/host/{ip}` | Freemium / Paid membership |
| `censys-v2` | Censys Search v2 API | `CENSYS_API_ID`, `CENSYS_API_SECRET` | `https://search.censys.io/api/v2/hosts/{ip}` | Yes (250 queries/month Community tier) |
| `securitytrails` | SecurityTrails Historical DNS | `SECURITYTRAILS_API_KEY` | `https://api.securitytrails.com/v1/history/{domain}/dns/a` | Yes (50 queries/month free tier) |
| `brave-search` | Brave Web Search API | `BRAVE_SEARCH_API_KEY` | `https://api.search.brave.com/res/v1/web/search` | Yes (Free tier / $5 credit tier) |
| `opencti-misp` | OpenCTI / MISP Threat Intel | `OPENCTI_URL`, `OPENCTI_TOKEN` | `{OPENCTI_URL}/graphql` | Self-hosted open source |

---

## 3. Compliance & Anti-Scraping Safeguards

- **No Login/CAPTCHA Bypass**: Sentinel never uses headless browsers to bypass Cloudflare challenges, CAPTCHAs, paywalls, or login walls.
- **No Unapproved Bulk Enumeration**: Third-party enumeration tools (such as raw Sherlock/Maigret lists containing hundreds of fragile scraped sites) are intentionally replaced by curated, official JSON API adapters (`GitHub`, `GitLab`, `Keybase`, `HackerNews`, `Reddit JSON`) that respect HTTP `Retry-After` headers.
- **Explicit Consent & Disclosure**: Every provider declares `disclosureNotice` specifying whether the query remains 100% local or transmits the target indicator to a third-party API.
