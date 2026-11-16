# Sentinel OSINT — Phased Implementation Plan & Risk Register

## 1. Execution Phases

### Phase 0 — Discovery, Architecture & Risk Register
- Inspect current workspace and publicly accessible reference page (`https://osint.hackunderway.io/panel` -> `index.php`).
- Define canonical `OsintProvider<TInput, TResult>` contract, 19-table database schema, SSRF defense model, and 90-feature matrix.
- Deliver `ARCHITECTURE.md`, `FEATURE_MATRIX.md`, `INTEGRATIONS.md`, `SECURITY_MODEL.md`, `IMPLEMENTATION_PLAN.md`, `API_KEYS_SETUP.md`, `TESTING.md`, `DEPLOYMENT.md`, `LIMITATIONS.md`, and `implementation_tracker.json`.

### Phase 1 — Application Foundation
- Initialize Next.js (App Router, TypeScript, Tailwind CSS, Lucide, Recharts, `@xyflow/react`, `@tanstack/react-table`, `react-hook-form`, `zod`).
- Build complete 19-table PostgreSQL DDL + RLS migration (`supabase/migrations/0001_sentinel_osint_schema.sql`) and dual-mode persistence layer (`src/lib/db/`).
- Implement authentication (Login, Register with password generator & Ethical-Use Terms acceptance modal, Password Reset, Session Cookie Guard, Account Deletion, RBAC, Audit Logging).
- Build the 16-section responsive cybersecurity workspace shell with dark/light theme support.

### Phase 2 — Core OSINT MVP
- Implement SSRF guard (`src/lib/security/ssrf-guard.ts`), input normalizers (`src/lib/validation/schemas.ts`), and rate limiter (`src/lib/security/rate-limiter.ts`).
- Implement Universal Investigation Engine (`src/lib/engine/orchestrator.ts`) with bounded concurrency, provenance tracking, deduplication, and graph entity extraction.
- Build live zero-key P0 adapters:
  - Authoritative DNS & Cloudflare DoH (`A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, `CAA`, `SPF`, `DMARC`)
  - Domain & IP RDAP (`rdap.org` / IANA RIR bootstrap)
  - Direct TLS Certificate Handshake Inspector (`tls.connect`)
  - Safe HTTP Response, Redirect-Chain & Security Header Inspector
  - JSON, Formula-Safe CSV, STIX 2.1, and PDF Report Exporters.

### Phase 3 — Major OSINT Integrations
- Email syntax, disposable domain detection, DMARC/SPF posture scorer, Gravatar hash check, and HIBP v3 adapter (`HIBP_API_KEY`).
- Public profile discovery across GitHub, GitLab, Keybase (with cryptographic proofs), HackerNews, and Reddit JSON.
- Phone numbering plan metadata (`libphonenumber-js`).
- Certificate Transparency & passive subdomain discovery (`crt.sh` + CertSpotter).
- IP BGP/ASN (`RIPEstat`), passive ports/CVEs (`Shodan InternetDB`), and AbuseIPDB v2 (`ABUSEIPDB_API_KEY`).
- Threat intelligence via `abuse.ch` (URLhaus, ThreatFox, MalwareBazaar), VirusTotal v3 (`VIRUSTOTAL_API_KEY`), Google Safe Browsing v4 (`GOOGLE_SAFE_BROWSING_API_KEY`), and OpenCTI/MISP.
- Historical web archives via Internet Archive Wayback Availability & CDX APIs.

### Phase 4 — Advanced Investigation Workspace
- Case Management workspace (Draft, Active, Completed, Archived cases; timeline, notes, tags, linked investigations, isolated user ownership).
- Interactive Entity Relationship Graph (`@xyflow/react`) with zoom, pan, search, type filter, node inspector, layout persistence, and JSON/SVG/PNG export.
- Evidence Library with bookmarking, source citation verification, and indicator tagging.
- Image & Document Intelligence module: magic-byte validation, binary EXIF parser with default GPS privacy redaction gate, PDF metadata & `/JS` anomaly inspector, cryptographic (`MD5`/`SHA-1`/`SHA-256`) & perceptual (`dHash`) hashing, duplicate detection, and manual reverse-image workflow links.
- Organization Intelligence module: GLEIF Global LEI Registry (`api.gleif.org`), parent/subsidiary relationships, Wikidata, `/.well-known/security.txt`, and SaaS TXT footprinting.

### Phase 5 & 6 — Security Hardening, Testing & Deployment Readiness
- Comprehensive Vitest suite covering SSRF, auth/tenant isolation, CSV formula injection, file upload magic bytes, unknown hash handling, and live provider execution.
- Production build verification (`npm run build`), health check endpoint (`/api/health`), Vercel configuration (`vercel.json`), and standalone worker (`worker/index.ts`).

---

## 2. Technical & Security Risk Register

| Risk ID | Risk Description | Likelihood | Impact | Mitigation Implemented |
|---|---|---|---|---|
| `RISK-01` | SSRF via URL inspection or HTTP redirect to `127.0.0.1` / `169.254.169.254` | High | Critical | Pre-flight URL/DNS validation + `redirect: 'manual'` validating every hop's resolved IPv4/IPv6 addresses against RFC1918, loopback, link-local, CGNAT, and IPv4-mapped IPv6 ranges. |
| `RISK-02` | Spreadsheet formula execution when opening exported CSV in Excel | Medium | High | `escapeCsvCell()` prefixes any cell starting with `=`, `+`, `-`, `@`, `\t`, or `\r` with a single quote `'` and wraps in escaped double quotes. |
| `RISK-03` | False positive identity attribution from matching usernames | High | High | UI and reports attach explicit `low` confidence and non-inferential warnings to handle-only matches unless backed by cryptographic proof (e.g., Keybase signed proof). |
| `RISK-04` | Accidental exposure of GPS location from uploaded image EXIF | Medium | High | EXIF `GPSLatitude`/`GPSLongitude` are redacted by default in API/UI behind an audited analyst reveal action. |
| `RISK-05` | Unknown file hash misinterpreted as "Clean/Safe" | Medium | High | Zero-hit hashes are strictly labeled `unknown` (`unrated`), never `safe`. |
| `RISK-06` | Upstream public API rate-limiting (`crt.sh`, GitHub, Reddit) | Medium | Medium | Bounded concurrency (`4`), per-provider token bucket rate limiter, `AbortSignal.timeout`, and secondary fallbacks (e.g., CertSpotter for CT logs). |
