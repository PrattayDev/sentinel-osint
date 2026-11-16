# Sentinel OSINT — API Keys & Environment Configuration Guide

## 1. Zero-Key Core Capability

Sentinel OSINT is architected so that **all P0 Core MVP modules and 15+ public intelligence providers work immediately with zero API keys required**:
- Authoritative DNS & Cloudflare DNS-over-HTTPS (`A`, `AAAA`, `MX`, `NS`, `TXT`, `SOA`, `CAA`, `SPF`, `DMARC`)
- IANA & Regional Internet Registry RDAP (`domain` & `ip`)
- Direct SSL/TLS Certificate & Cipher Handshake Inspector
- Certificate Transparency & Passive Subdomain Discovery (`crt.sh` & CertSpotter)
- Safe HTTP Response, Redirect-Chain & Security Header Grader
- RIPEstat BGP, ASN, Holder & GeoLite Intelligence
- Shodan InternetDB Passive Ports, CPEs, Hostnames & CVE Observations
- Internet Archive Wayback Machine Availability & CDX Snapshot History
- abuse.ch URLhaus, ThreatFox & MalwareBazaar Threat Feeds
- Official Public Profile APIs (GitHub, GitLab, Keybase, HackerNews, Reddit JSON, Gravatar)
- GLEIF Global Legal Entity Identifier Registry & Corporate Parent/Subsidiary Graph
- ITU Phone Numbering Plan Analyzer (`libphonenumber-js`)
- Local Binary EXIF, PDF Metadata, Cryptographic (`MD5`/`SHA-1`/`SHA-256`) & Perceptual (`dHash`) File Inspector

---

## 2. Optional Environment Variables (`.env.local`)

Copy `.env.example` to `.env.local` and configure only the optional commercial or freemium providers you wish to enable. Missing keys never break the application—unconfigured providers honestly report `not_configured` in the UI and investigation results.

```dotenv
# --- Application & Session Security ---
NEXT_PUBLIC_APP_URL=http://localhost:3000
SENTINEL_SESSION_SECRET=replace-with-at-least-32-bytes-of-random-hex-secret

# --- Supabase PostgreSQL & Auth (Optional in local dev; required for multi-node cloud deployment) ---
NEXT_PUBLIC_SUPABASE_URL=https://your-project-ref.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-supabase-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-supabase-service-role-key

# --- Optional OSINT & Threat Intelligence Provider API Keys ---
# Have I Been Pwned API v3 (Paid subscription: https://haveibeenpwned.com/API/Key)
HIBP_API_KEY=

# VirusTotal API v3 (Free Community tier available: https://www.virustotal.com/gui/my-apikey)
VIRUSTOTAL_API_KEY=

# AbuseIPDB API v2 (Free tier 1,000 checks/day: https://www.abuseipdb.com/account/api)
ABUSEIPDB_API_KEY=

# Google Safe Browsing API v4 (Free non-commercial quota via Google Cloud Console)
GOOGLE_SAFE_BROWSING_API_KEY=

# Shodan Full REST API (Optional; Shodan InternetDB works without a key)
SHODAN_API_KEY=

# Censys Search v2 API (Community tier available: https://search.censys.io/account/api)
CENSYS_API_ID=
CENSYS_API_SECRET=

# SecurityTrails Historical DNS API
SECURITYTRAILS_API_KEY=

# Brave Web Search API (https://brave.com/search/api/)
BRAVE_SEARCH_API_KEY=

# OpenCTI / MISP Threat Intelligence Instance (Self-Hosted)
OPENCTI_URL=
OPENCTI_TOKEN=

# Optional AI Analysis Layer (Google Gemini API - Disabled unless explicitly set and consented per-request)
GEMINI_API_KEY=
```

---

## 3. Security Rules for API Keys

1. **Never prefix provider API keys with `NEXT_PUBLIC_`**: All OSINT provider keys (`VIRUSTOTAL_API_KEY`, `HIBP_API_KEY`, `ABUSEIPDB_API_KEY`, etc.) are accessed strictly inside server-side route handlers and background workers.
2. **Encrypted Workspace Keys**: Keys stored via the `/integrations` settings page are held server-side and masked (`••••••••••••abcd`) in all client API responses.
