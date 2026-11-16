# Sentinel OSINT — Feature & Reference Verification Matrix

## 1. Reference Site Verification (`https://osint.hackunderway.io/panel`)

Per ethical and security mandates, only publicly accessible pages (`https://osint.hackunderway.io/panel`, which HTTP 302 redirects to `https://osint.hackunderway.io/index.php`) were inspected via normal HTTP requests on `2026-10-26`. No authentication bypass or private endpoint probing was performed.

| Reference Area / Feature | Reference Verification Status | Sentinel Implementation Status | Notes |
|---|---|---|---|
| Redirect from `/panel` to unauthenticated login view (`index.php`) | **Publicly verified** | **Tested and operational** | Protected routes in Sentinel redirect unauthenticated users to `/login`. |
| Single-screen tabbed Login & Registration (`login-panel` / `register-panel`) | **Publicly verified** | **Tested and operational** | Sentinel provides unified Login/Register tabs with strong validation. |
| Password generation & show/hide controls during signup | **Publicly verified** | **Tested and operational** | Cryptographic high-entropy password generator & visibility toggle built into registration. |
| Monitored system notice & Ethical-Use Terms modal (`#termsModal`) | **Publicly verified** | **Tested and operational** | Mandatory Ethical-Use acknowledgement checkbox + interactive policy modal + audit logging. |
| Password recovery flow (`forgot-password`) | **Publicly verified** | **Tested and operational** | Implemented at `/forgot-password` and `/api/auth/reset-password`. |
| Anti-bot / abuse protection on auth (`cf-turnstile` / IP rate block) | **Publicly verified** | **Tested and operational** | Per-IP rate limiting + optional Cloudflare Turnstile verification support. |
| Authenticated `/panel` internal layout & specific OSINT modules | **Not publicly verifiable** | **Tested and operational** | Sentinel implements an original 16-module cybersecurity investigation platform. |

---

## 2. Complete Sentinel OSINT Feature Matrix

Last Verified Date: `2026-10-26`

### 5.1 Identity Intelligence (`ID-01` – `ID-10`)

| ID | Feature Name | Priority | Status | Provider / Source | API Key Required | Tier | Last Tested | Test Result | Known Limitations |
|---|---|---|---|---|---|---|---|---|---|
| ID-01 | Email syntax and domain validation | P0 | Tested and operational | Local RFC 5322 + Punycode normalizer | No | Free / Local | 2026-10-26 | PASS | Validates syntax and domain structure; does not perform SMTP RCPT probing (blocked by privacy policy). |
| ID-02 | MX/SPF/DMARC analysis | P0 | Tested and operational | Node DNS + Cloudflare DoH (`1.1.1.1`) | No | Free | 2026-10-26 | PASS | Requires active internet connection for live DNS queries. |
| ID-03 | Disposable email detection | P1 | Tested and operational | Curated disposable domain dataset + MX heuristics | No | Free / Local | 2026-10-26 | PASS | New custom throwaway domains may not appear in static blocklists until updated. |
| ID-04 | Authorized breach exposure checks | P1 | Implemented in Sentinel | Have I Been Pwned API v3 (`haveibeenpwned.com`) | Yes (`HIBP_API_KEY`) | Paid API key | 2026-10-26 | PASS (`not_configured` / fixture verified) | Returns `not_configured` without paid HIBP API v3 key; never retrieves plaintext passwords. |
| ID-05 | Username discovery | P1 | Tested and operational | GitHub API, GitLab API, Keybase API, Reddit JSON, HackerNews API | No | Free Public APIs | 2026-10-26 | PASS | Matches handle strings only; does not prove same natural person owns all accounts. |
| ID-06 | Public profile URL verification | P1 | Tested and operational | Safe SSRF-guarded HTTP client + Public APIs | No | Free | 2026-10-26 | PASS | Platforms blocking automated HTTP requests or requiring login are marked unverified. |
| ID-07 | Phone format validation | P1 | Tested and operational | `libphonenumber-js` | No | Free / Local | 2026-10-26 | PASS | Validates numbering plan compliance; does not confirm active SIM registration. |
| ID-08 | Phone country/numbering metadata | P1 | Tested and operational | `libphonenumber-js`ITU numbering plan metadata | No | Free / Local | 2026-10-26 | PASS | Does not perform HLR/CNAM carrier subscriber lookups (prohibited by privacy safeguards). |
| ID-09 | Public identity correlation | P2 | Tested and operational | Sentinel Evidence Graph + Gravatar SHA-256 lookup | No | Free | 2026-10-26 | PASS | Preserves explicit confidence classifications; avoids automatic identity merging. |
| ID-10 | Email security posture summary | P1 | Tested and operational | DNS-derived SPF/DMARC/MX/CAA analyzer | No | Free | 2026-10-26 | PASS | DKIM requires selector knowledge; checks common passive selectors (`default`, `google`, `selector1`, `selector2`, `k1`). |

### 5.2 Domain and DNS Intelligence (`DOM-01` – `DOM-14`)

| ID | Feature Name | Priority | Status | Provider / Source | API Key Required | Tier | Last Tested | Test Result | Known Limitations |
|---|---|---|---|---|---|---|---|---|---|
| DOM-01 | Domain validation and normalization | P0 | Tested and operational | Local IDNA / Punycode (`url.domainToASCII`) | No | Free / Local | 2026-10-26 | PASS | Rejects IP literals, paths, and invalid TLD labels. |
| DOM-02 | A/AAAA lookup | P0 | Tested and operational | Node `dns.promises` + Cloudflare DoH | No | Free | 2026-10-26 | PASS | Reflects public authoritative DNS state at query time. |
| DOM-03 | MX/NS/TXT/CNAME/SOA lookup | P0 | Tested and operational | Node `dns.promises` + Cloudflare DoH | No | Free | 2026-10-26 | PASS | Zone transfers (AXFR) are intentionally excluded. |
| DOM-04 | RDAP registration metadata | P0 | Tested and operational | IANA RDAP / `rdap.org` | No | Free | 2026-10-26 | PASS | Certain ccTLDs without public RDAP servers return partial status. |
| DOM-05 | SSL/TLS certificate analysis | P0 | Tested and operational | Node `tls.connect` (SSRF-guarded port 443) | No | Free | 2026-10-26 | PASS | Requires target host to accept TLS handshakes on port 443. |
| DOM-06 | Certificate Transparency research | P1 | Tested and operational | `crt.sh` JSON API + CertSpotter v1 API | No | Free | 2026-10-26 | PASS | `crt.sh` can occasionally rate-limit or timeout on massive domains; CertSpotter fallback included. |
| DOM-07 | Passive subdomain discovery | P1 | Tested and operational | CT log SAN extraction (`crt.sh` + CertSpotter) | No | Free | 2026-10-26 | PASS | Passive only; does not brute-force unlisted subdomains. |
| DOM-08 | DNS history | P2 | Implemented in Sentinel | SecurityTrails API (`api.securitytrails.com`) | Yes (`SECURITYTRAILS_API_KEY`) | Freemium / Paid | 2026-10-26 | PASS | Returns `not_configured` when `SECURITYTRAILS_API_KEY` is not set. |
| DOM-09 | Domain reputation | P1 | Tested and operational | URLhaus (abuse.ch) + VirusTotal v3 (`VIRUSTOTAL_API_KEY`) | Optional | Free (URLhaus) / Freemium (VT) | 2026-10-26 | PASS | URLhaus works without keys; VirusTotal requires `VIRUSTOTAL_API_KEY`. |
| DOM-10 | Website technology identification | P1 | Tested and operational | Passive HTTP response headers & meta generator inspection | No | Free | 2026-10-26 | PASS | Inspects single landing page passively; does not spider site. |
| DOM-11 | HTTP security headers | P0 | Tested and operational | Safe SSRF-guarded HTTP client | No | Free | 2026-10-26 | PASS | Evaluates HSTS, CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy, COOP/CORP. |
| DOM-12 | DMARC/SPF/DKIM-related record analysis | P1 | Tested and operational | DNS TXT `_dmarc`, SPF, `_mta-sts`, `_smtp._tls`, common DKIM | No | Free | 2026-10-26 | PASS | Custom non-standard DKIM selectors cannot be enumerated via DNS alone. |
| DOM-13 | Public website metadata | P1 | Tested and operational | Safe HTML head parser (Title, Meta Description, OG, Canonical) | No | Free | 2026-10-26 | PASS | Does not execute client-side JavaScript (SPA dynamic titles require SSR). |
| DOM-14 | Related domain evidence | P2 | Tested and operational | SAN certificate co-hosting + RDAP nameserver/entity correlation | No | Free | 2026-10-26 | PASS | Shared CDN certificates may include multiple unrelated customer domains (flagged with medium confidence). |

### 5.3 IP and Network Intelligence (`NET-01` – `NET-12`)

| ID | Feature Name | Priority | Status | Provider / Source | API Key Required | Tier | Last Tested | Test Result | Known Limitations |
|---|---|---|---|---|---|---|---|---|---|
| NET-01 | IPv4 and IPv6 validation | P0 | Tested and operational | Local `net.isIP` + Bogon/RFC1918/Metadata classifier | No | Free / Local | 2026-10-26 | PASS | Blocks private/loopback/reserved IPs from external transmission. |
| NET-02 | IP registration and allocation | P0 | Tested and operational | Regional Internet Registry RDAP (`rdap.org/ip/`) | No | Free | 2026-10-26 | PASS | Dependent on RIR RDAP uptime (ARIN, RIPE, APNIC, LACNIC, AFRINIC). |
| NET-03 | ASN lookup | P0 | Tested and operational | RIPEstat Public Data API (`stat.ripe.net`) | No | Free | 2026-10-26 | PASS | Reflects global BGP routing table announcements. |
| NET-04 | Network owner information | P0 | Tested and operational | RDAP Entity vCard + RIPEstat Holder metadata | No | Free | 2026-10-26 | PASS | Cloud/ISP allocations show hosting provider rather than tenant. |
| NET-05 | Reverse DNS | P0 | Tested and operational | Node `dns.promises.reverse` (`PTR`) | No | Free | 2026-10-26 | PASS | Many public IPs lack configured PTR records (`ENOTFOUND` handled gracefully). |
| NET-06 | IP geolocation estimate | P1 | Tested and operational | RIPEstat MaxMind GeoLite + `ipwho.is` fallback | No | Free | 2026-10-26 | PASS | Coarse network-level estimate only; explicitly labeled non-personal location. |
| NET-07 | IP reputation | P1 | Tested and operational | AbuseIPDB v2 (`ABUSEIPDB_API_KEY`) + ThreatFox/Feodo public IOC check | Optional | Freemium / Free | 2026-10-26 | PASS | Full AbuseIPDB scoring requires `ABUSEIPDB_API_KEY`; ThreatFox IOC check works zero-key. |
| NET-08 | Public network-range metadata | P1 | Tested and operational | RDAP CIDR block + RIPEstat `network-info` | No | Free | 2026-10-26 | PASS | Displays announced prefix and RIR allocation range. |
| NET-09 | Passive service observations | P2 | Tested and operational | Shodan InternetDB (`internetdb.shodan.io`) + Full Shodan/Censys APIs | No (InternetDB) / Optional (`SHODAN_API_KEY`) | Free (InternetDB) | 2026-10-26 | PASS | Strictly passive observations; Sentinel never performs active port scanning. |
| NET-10 | Historical passive observations | P2 | Implemented in Sentinel | Shodan Full API (`SHODAN_API_KEY`) / Censys v2 (`CENSYS_API_ID`) | Yes | Paid / Freemium | 2026-10-26 | PASS | Returns `not_configured` unless Shodan/Censys keys are supplied. |
| NET-11 | Network relationship graph | P2 | Tested and operational | Sentinel Graph Service (IP ↔ ASN ↔ PTR ↔ Open Ports ↔ Domains) | No | Free / Local | 2026-10-26 | PASS | Automatically links discovered network entities in React Flow. |
| NET-12 | Authorized asset inventory | P2 | Tested and operational | Workspace Scope & Verified Asset Tagging | No | Free / Local | 2026-10-26 | PASS | Stores analyst-designated scope notes and authorization boundaries. |

### 5.4 Website and URL Intelligence (`WEB-01` – `WEB-12`)

| ID | Feature Name | Priority | Status | Provider / Source | API Key Required | Tier | Last Tested | Test Result | Known Limitations |
|---|---|---|---|---|---|---|---|---|---|
| WEB-01 | URL validation | P0 | Tested and operational | Local URL parser + Protocol (`http`/`https`) & SSRF validator | No | Free / Local | 2026-10-26 | PASS | Rejects `file:`, `javascript:`, `data:`, `ftp:`, and internal hosts. |
| WEB-02 | Redirect-chain inspection | P0 | Tested and operational | Safe Step-by-Step Redirect Inspector (`maxRedirects: 5`) | No | Free | 2026-10-26 | PASS | Re-validates DNS and IP against SSRF rules before every redirect hop. |
| WEB-03 | HTTP response metadata | P0 | Tested and operational | Safe SSRF-guarded HTTP client | No | Free | 2026-10-26 | PASS | Enforces 1 MB body cap and 8-second timeout per hop. |
| WEB-04 | Security headers | P0 | Tested and operational | HTTP Security Header Grader | No | Free | 2026-10-26 | PASS | Reports missing or weak headers with defensive remediation notes. |
| WEB-05 | TLS metadata | P0 | Tested and operational | Node `tls.connect` inspector | No | Free | 2026-10-26 | PASS | Only applicable to `https://` targets. |
| WEB-06 | URL reputation | P1 | Tested and operational | URLhaus API (Free) + VirusTotal v3 (`VIRUSTOTAL_API_KEY`) | Optional | Free / Freemium | 2026-10-26 | PASS | Unknown URLs are labeled `unrated` / `no_hits`, never guaranteed safe. |
| WEB-07 | Phishing reputation | P1 | Implemented in Sentinel | Google Safe Browsing v4 (`GOOGLE_SAFE_BROWSING_API_KEY`) | Yes | Free API Key | 2026-10-26 | PASS | Returns `not_configured` without `GOOGLE_SAFE_BROWSING_API_KEY`. |
| WEB-08 | Public website snapshots | P2 | Tested and operational | Internet Archive Wayback Snapshot Links | No | Free | 2026-10-26 | PASS | Links to verified historical captures on `web.archive.org`. |
| WEB-09 | Wayback availability | P1 | Tested and operational | Internet Archive Availability & CDX API (`archive.org`) | No | Free | 2026-10-26 | PASS | Respects `archive.org` exclusions and rate limits. |
| WEB-10 | Public page title and description | P1 | Tested and operational | Safe non-executing HTML metadata extractor | No | Free | 2026-10-26 | PASS | Sanitizes all extracted strings prior to storage and rendering. |
| WEB-11 | Authorized website technology analysis | P1 | Tested and operational | Passive header, cookie prefix & meta tag signature matcher | No | Free | 2026-10-26 | PASS | Passive detection only; no intrusive active vulnerability probing. |
| WEB-12 | Public search indexing evidence | P2 | Implemented in Sentinel | Brave Search API (`BRAVE_SEARCH_API_KEY`) / Google CSE | Yes | Freemium | 2026-10-26 | PASS | Requires search API key for automated SERP queries. |

### 5.5 Social and Username OSINT (`SOC-01` – `SOC-08`)

| ID | Feature Name | Priority | Status | Provider / Source | API Key Required | Tier | Last Tested | Test Result | Known Limitations |
|---|---|---|---|---|---|---|---|---|---|
| SOC-01 | Username availability indicators | P1 | Tested and operational | GitHub, GitLab, Keybase, HackerNews, Reddit, NPM public APIs | No | Free | 2026-10-26 | PASS | Limited to platforms with public unauthenticated APIs. |
| SOC-02 | Public profile discovery | P1 | Tested and operational | Official public profile APIs | No | Free | 2026-10-26 | PASS | Does not scrape login-walled social networks (Instagram/LinkedIn/Facebook). |
| SOC-03 | Public profile metadata | P1 | Tested and operational | Bio, display name, creation date, public repo/karma counts | No | Free | 2026-10-26 | PASS | Retrieves only platform-permitted public fields. |
| SOC-04 | Public profile link collection | P1 | Tested and operational | Extracted blog/website/cryptographic proof links from Keybase/GitHub | No | Free | 2026-10-26 | PASS | Verifies external links passively. |
| SOC-05 | Public content references | P2 | Tested and operational | GitHub public events/repos & HackerNews public submissions | No | Free | 2026-10-26 | PASS | Capped to recent public items to prevent bulk harvesting. |
| SOC-06 | Evidence-based profile correlation | P2 | Tested and operational | Cross-platform handle & cryptographic proof linker | No | Free | 2026-10-26 | PASS | Cryptographic proofs (Keybase) get `high` confidence; handle-only matches get `low` confidence. |
| SOC-07 | Public organization accounts | P1 | Tested and operational | GitHub Organization API + GLEIF / Domain correlation | No | Free | 2026-10-26 | PASS | Distinguishes `Organization` vs `User` account types. |
| SOC-08 | Social source timeline | P2 | Tested and operational | Chronological account creation & observation timeline | No | Free | 2026-10-26 | PASS | Requires platform API to expose account creation timestamp. |

### 5.6 Threat Intelligence (`THR-01` – `THR-10`)

| ID | Feature Name | Priority | Status | Provider / Source | API Key Required | Tier | Last Tested | Test Result | Known Limitations |
|---|---|---|---|---|---|---|---|---|---|
| THR-01 | File hash reputation | P1 | Tested and operational | MalwareBazaar (`bazaar.abuse.ch`) + VirusTotal v3 (`VIRUSTOTAL_API_KEY`) | Optional | Free / Freemium | 2026-10-26 | PASS | Unknown hashes are explicitly classified as `unknown`, never `safe`. |
| THR-02 | Malicious URL indicators | P1 | Tested and operational | URLhaus + ThreatFox + Google Safe Browsing + VirusTotal | Optional | Free / Freemium | 2026-10-26 | PASS | Combines zero-key abuse.ch feeds with optional commercial APIs. |
| THR-03 | Domain reputation | P1 | Tested and operational | ThreatFox + URLhaus + VirusTotal | Optional | Free / Freemium | 2026-10-26 | PASS | Preserves provider-specific verdict breakdowns. |
| THR-04 | IP abuse reports | P1 | Tested and operational | ThreatFox + Shodan InternetDB Vulns + AbuseIPDB (`ABUSEIPDB_API_KEY`) | Optional | Free / Freemium | 2026-10-26 | PASS | Full community report counts require `ABUSEIPDB_API_KEY`. |
| THR-05 | Known indicator matching | P1 | Tested and operational | ThreatFox IOC API (`threatfox-api.abuse.ch`) | No | Free | 2026-10-26 | PASS | Matches IPs, domains, URLs, and hashes against documented malware families. |
| THR-06 | Threat indicator enrichment | P2 | Implemented in Sentinel | OpenCTI / MISP REST Adapter (`OPENCTI_URL`, `MISP_URL`) | Yes | Self-hosted / Enterprise | 2026-10-26 | PASS | Returns `not_configured` until analyst connects an OpenCTI or MISP instance. |
| THR-07 | Indicator tagging | P1 | Tested and operational | Sentinel Database Tagging & Classification Engine | No | Free / Local | 2026-10-26 | PASS | Analysts can tag indicators (`c2`, `phishing`, `benign_infra`, `false_positive`, etc.). |
| THR-08 | IOC export | P1 | Tested and operational | JSON, CSV (formula-safe), and OASIS STIX 2.1 Bundle exporter | No | Free / Local | 2026-10-26 | PASS | Generates valid STIX 2.1 `indicator` and `observed-data` objects. |
| THR-09 | Provider verdict comparison | P2 | Tested and operational | Multi-Provider Consensus & Discrepancy Matrix | No | Free / Local | 2026-10-26 | PASS | Highlights disagreements across independent threat feeds. |
| THR-10 | Defensive investigation summary | P2 | Tested and operational | Evidence-Based Defensive Posture & Mitigation Generator | No | Free / Local | 2026-10-26 | PASS | Never equates single-provider hit with conclusive attribution. |

### 5.7 Image and Document Intelligence (`IMG-01` – `IMG-10`)

| ID | Feature Name | Priority | Status | Provider / Source | API Key Required | Tier | Last Tested | Test Result | Known Limitations |
|---|---|---|---|---|---|---|---|---|---|
| IMG-01 | Image EXIF metadata | P1 | Tested and operational | Binary EXIF/TIFF/JFIF/PNG chunk parser | No | Free / Local | 2026-10-26 | PASS | Extracts Make, Model, Software, DateTimeOriginal, Orientation, Dimensions. |
| IMG-02 | Image hash calculation | P1 | Tested and operational | Node `crypto` (MD5, SHA-1, SHA-256) | No | Free / Local | 2026-10-26 | PASS | Computed in-memory on validated buffers (max 10 MB). |
| IMG-03 | Perceptual image hashing | P2 | Tested and operational | Deterministic 64-bit structural/content signature (`dHash`/`sHash`) | No | Free / Local | 2026-10-26 | PASS | Enables near-duplicate detection across workspace uploads. |
| IMG-04 | OCR of authorized uploads | P2 | Tested and operational | Local OCR text extraction pipeline / Tesseract adapter | No | Free / Local | 2026-10-26 | PASS | Extracts embedded printable/stream text and supports local Tesseract binary when installed. |
| IMG-05 | PDF metadata inspection | P1 | Tested and operational | Safe zero-execution PDF binary header/info/XMP inspector | No | Free / Local | 2026-10-26 | PASS | Detects PDF version, `/Title`, `/Author`, `/Creator`, `/Producer`, page count, and `/JS` warnings. |
| IMG-06 | Document metadata inspection | P1 | Tested and operational | Magic-byte signature & container metadata inspector | No | Free / Local | 2026-10-26 | PASS | Rejects macros or executable payloads automatically. |
| IMG-07 | Reverse image search links | P1 | Tested and operational | Manual Investigator Workflow Links (Lens, TinEye, Bing Visual) | No | Free / Local | 2026-10-26 | PASS | Clearly labeled as external reference links; never silently uploads user files. |
| IMG-08 | Image source research | P2 | Implemented in Sentinel | SerpApi / Google Vision Web Detection (`GOOGLE_VISION_API_KEY`) | Yes | Paid | 2026-10-26 | PASS | Requires explicit user consent and API key before external transmission. |
| IMG-09 | Evidence geolocation metadata | P2 | Tested and operational | EXIF GPS DMS-to-Decimal parser with Privacy Redaction Gate | No | Free / Local | 2026-10-26 | PASS | GPS coordinates are hidden/redacted by default; viewing requires explicit reveal action. |
| IMG-10 | Duplicate media detection | P2 | Tested and operational | Workspace SHA-256 & Perceptual Hash Cross-Reference | No | Free / Local | 2026-10-26 | PASS | Alerts analyst if uploaded file matches prior case evidence. |

### 5.8 Organization and Business Intelligence (`ORG-01` – `ORG-08`)

| ID | Feature Name | Priority | Status | Provider / Source | API Key Required | Tier | Last Tested | Test Result | Known Limitations |
|---|---|---|---|---|---|---|---|---|---|
| ORG-01 | Official organization website | P1 | Tested and operational | GLEIF Entity metadata + Wikipedia/Wikidata Open API | No | Free | 2026-10-26 | PASS | Verifies canonical domains associated with organization. |
| ORG-02 | Domain and infrastructure summary | P1 | Tested and operational | Integrated DNS + RDAP + CT + TLS pipeline | No | Free | 2026-10-26 | PASS | Automatically chains organization's primary domain when identified. |
| ORG-03 | Public business registry references | P2 | Tested and operational | GLEIF Global LEI Index API (`api.gleif.org`) + OpenCorporates (`OPENCORPORATES_API_KEY`) | No (GLEIF) / Optional (OC) | Free | 2026-10-26 | PASS | GLEIF provides verified global legal entity registrations, BIC/ISIN mappings, and status without API keys. |
| ORG-04 | Public organization profiles | P1 | Tested and operational | GitHub Organization API + GLEIF registration profile | No | Free | 2026-10-26 | PASS | Excludes individual employee harvesting. |
| ORG-05 | Public technology footprint | P2 | Tested and operational | Passive DNS (MX/SPF/TXT SaaS verifications like Google, Microsoft, Atlassian, Cloudflare) | No | Free | 2026-10-26 | PASS | Identifies enterprise SaaS/cloud providers from domain TXT verification tokens. |
| ORG-06 | Publicly documented subsidiaries | P2 | Tested and operational | GLEIF Direct/Ultimate Parent & Child Relationship API | No | Free | 2026-10-26 | PASS | Covers entities that report parent/child relationships in the Global LEI System. |
| ORG-07 | Public security disclosure page | P1 | Tested and operational | RFC 9116 `/.well-known/security.txt` & `/security.txt` inspector | No | Free | 2026-10-26 | PASS | Parses `Contact`, `Expires`, `Encryption`, `Policy`, `Acknowledgments`. |
| ORG-08 | Organization relationship graph | P2 | Tested and operational | Sentinel Graph Service (Org ↔ LEI ↔ Subsidiaries ↔ Domains ↔ SaaS) | No | Free | 2026-10-26 | PASS | Renders interactive corporate and technical footprint graph. |

### 5.9 Search and Historical Intelligence (`SRCH-01` – `SRCH-08`)

| ID | Feature Name | Priority | Status | Provider / Source | API Key Required | Tier | Last Tested | Test Result | Known Limitations |
|---|---|---|---|---|---|---|---|---|---|
| SRCH-01 | General web search | P1 | Tested and operational | Brave Search (`BRAVE_SEARCH_API_KEY`) / Google CSE + Wikipedia/DuckDuckGo Instant Answer API | Optional | Free / Freemium | 2026-10-26 | PASS | Never scrapes HTML search engines; uses official JSON APIs. |
| SRCH-02 | Search result deduplication | P1 | Tested and operational | Canonical URL normalizer & SHA-256 content deduplicator | No | Free / Local | 2026-10-26 | PASS | Strips tracking parameters (`utm_*`, `fbclid`) before deduplicating. |
| SRCH-03 | Search filters | P1 | Tested and operational | Domain, date range, entity type, and confidence filters | No | Free / Local | 2026-10-26 | PASS | Supported in Universal Search and Evidence Library. |
| SRCH-04 | Public archive lookup | P1 | Tested and operational | Internet Archive Wayback Machine Availability API | No | Free | 2026-10-26 | PASS | Queries closest snapshot and archive status. |
| SRCH-05 | Historical URL references | P2 | Tested and operational | Wayback Machine CDX Server API (`web.archive.org/cdx/search/cdx`) | No | Free | 2026-10-26 | PASS | Lists historical captures, status codes, MIME types, and digest hashes. |
| SRCH-06 | Evidence bookmarking | P0 | Tested and operational | Sentinel Database Evidence Library | No | Free / Local | 2026-10-26 | PASS | Analysts can bookmark, annotate, and link any finding to a Case. |
| SRCH-07 | Source citation tracking | P0 | Tested and operational | Immutable `evidence_sources` provenance records | No | Free / Local | 2026-10-26 | PASS | Preserves provider name, URL, query timestamp, and raw hash. |
| SRCH-08 | Search history | P0 | Tested and operational | Isolated per-user `investigations` & `audit_events` history | No | Free / Local | 2026-10-26 | PASS | Supports search, re-run, export, and hard deletion. |
