# Sentinel OSINT — Advanced All-in-One Intelligence Platform

[![Live Demo on Vercel](https://img.shields.io/badge/Live_Production-sentinel--osint--chi.vercel.app-06b6d4?style=for-the-badge&logo=vercel)](https://sentinel-osint-chi.vercel.app)
[![GitHub Repository](https://img.shields.io/badge/GitHub-PrattayDev%2Fsentinel--osint-181717?style=for-the-badge&logo=github)](https://github.com/PrattayDev/sentinel-osint)
[![Automated Tests](https://img.shields.io/badge/Vitest_Suite-38%2F38_Passing-10b981?style=for-the-badge&logo=vitest)](./TESTING.md)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6_Strict-3178c6?style=for-the-badge&logo=typescript)](./tsconfig.json)

**Live Deployment:** [https://sentinel-osint-chi.vercel.app](https://sentinel-osint-chi.vercel.app)  
**GitHub Repository:** [https://github.com/PrattayDev/sentinel-osint](https://github.com/PrattayDev/sentinel-osint)

**Sentinel OSINT** is a production-oriented, defense-in-depth Open Source Intelligence (OSINT) and defensive threat-intelligence workspace built with **Next.js 14 App Router, TypeScript, Tailwind CSS, React Flow (`@xyflow/react`), TanStack Table, Recharts, Zod, and Supabase PostgreSQL**.

It consolidates 90+ investigative capabilities across **9 intelligence domains** with strict provenance tracking, uncertainty preservation, SSRF & DNS-rebinding protection, user/workspace tenant isolation, interactive entity relationship graphs, case management, and formal multi-format reporting (PDF, JSON, formula-safe CSV, and OASIS STIX 2.1).

---

## Key Capabilities

1. **Universal Investigation Engine**: Classify, normalize, and concurrently query 15+ zero-key standards/public providers and 9 optional commercial threat APIs with explicit provider disclosure and consent.
2. **9 Specialized Intelligence Modules**:
   - **Identity Intelligence**: RFC 5322 validation, MX/SPF/DMARC/DKIM security posture scoring, disposable email detection, Gravatar hash correlation, Have I Been Pwned v3 (`HIBP_API_KEY`), and ITU phone numbering plan analysis (`libphonenumber-js`).
   - **Domain & DNS Intelligence**: Punycode/IDNA normalization, authoritative DNS + Cloudflare DoH (`A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, `CAA`), IANA RDAP registration, direct TLS certificate handshake analysis, Certificate Transparency (`crt.sh` & CertSpotter), passive subdomain discovery, HTTP security header grading, and passive tech fingerprinting.
   - **IP & Network Intelligence**: IPv4/IPv6 validation, bogon/RFC1918/metadata classification, RIR RDAP allocation, RIPEstat BGP & ASN holder lookup, Reverse DNS (`PTR`), coarse GeoIP estimation (with explicit non-personal location disclaimer), Shodan InternetDB passive open ports/CVEs, and AbuseIPDB v2.
   - **Website & URL Intelligence**: Step-by-step SSRF-guarded redirect chain inspection (`redirect: manual`, validating every hop's resolved IP), HTTP response & security headers, safe HTML `<title>`/meta extraction, URLhaus/VirusTotal/Google Safe Browsing reputation, and Internet Archive Wayback & CDX history.
   - **Social & Username OSINT**: Official unauthenticated API lookups across GitHub, GitLab, Keybase (with cryptographic proof extraction), HackerNews, and Reddit JSON—preserving explicit confidence ratings and non-inferential safeguards.
   - **Threat Intelligence**: File hash (`MD5`, `SHA-1`, `SHA-256`), URL, Domain, and IP matching against abuse.ch (`MalwareBazaar`, `ThreatFox`, `URLhaus`), `VirusTotal v3`, `AbuseIPDB`, and `OpenCTI`/`MISP`, with unknown hashes strictly classified as `unknown` (never `safe`), indicator tagging, multi-provider verdict comparison, and STIX 2.1 export.
   - **Image & Document Intelligence**: Strict 10 MB size cap and binary magic-byte verification (`JPEG`, `PNG`, `GIF`, `WebP`, `PDF`), binary EXIF parser with **GPS coordinates hidden/redacted by default** behind an audited reveal gate, PDF metadata & `/JS` warning inspector, `MD5`/`SHA-1`/`SHA-256` + 64-bit perceptual hash (`dHash`) duplicate detection, and manual reverse-image workflow links.
   - **Organization & Business Intelligence**: GLEIF Global Legal Entity Identifier (`api.gleif.org`) corporate registry lookup, parent/subsidiary hierarchies, Wikidata entity enrichment, `/.well-known/security.txt` parser, and SaaS DNS verification footprinting.
   - **Search & Historical Intelligence**: Wayback CDX capture timeline, public search APIs, canonical URL deduplication, Evidence Library bookmarking, and immutable source citations.
3. **Interactive Entity Relationship Graph (`@xyflow/react`)**: Filter, search, inspect provenance on edges, expand nodes, and export graph layouts.
4. **Case Management & Multi-Format Reporting**: Organize investigations, evidence, notes, and timelines into isolated Cases (`draft`, `active`, `completed`, `archived`) and export traceable reports in **PDF**, **JSON**, **Formula-Safe CSV**, and **STIX 2.1**.

---

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. (Optional) Copy environment template
cp .env.example .env.local

# 3. Start development server
npm run dev

# 4. Run automated verification & security regression suite
npm test

# 5. Build for production
npm run build
```

---

## Documentation Index

- [System Architecture](file:///C:/Users/spyh7/.gemini/antigravity/scratch/sentinel-osint/ARCHITECTURE.md)
- [Feature & Reference Verification Matrix](file:///C:/Users/spyh7/.gemini/antigravity/scratch/sentinel-osint/FEATURE_MATRIX.md)
- [Provider & Tool Integrations](file:///C:/Users/spyh7/.gemini/antigravity/scratch/sentinel-osint/INTEGRATIONS.md)
- [Application Security Model](file:///C:/Users/spyh7/.gemini/antigravity/scratch/sentinel-osint/SECURITY_MODEL.md)
- [API Keys Setup Guide](file:///C:/Users/spyh7/.gemini/antigravity/scratch/sentinel-osint/API_KEYS_SETUP.md)
- [Testing & Acceptance Matrix](file:///C:/Users/spyh7/.gemini/antigravity/scratch/sentinel-osint/TESTING.md)
- [Deployment & Operations Runbook](file:///C:/Users/spyh7/.gemini/antigravity/scratch/sentinel-osint/DEPLOYMENT.md)
- [Known Limitations & Ethical Boundaries](file:///C:/Users/spyh7/.gemini/antigravity/scratch/sentinel-osint/LIMITATIONS.md)
- [Implementation Plan & Risk Register](file:///C:/Users/spyh7/.gemini/antigravity/scratch/sentinel-osint/IMPLEMENTATION_PLAN.md)
- [Implementation Tracker (JSON)](file:///C:/Users/spyh7/.gemini/antigravity/scratch/sentinel-osint/implementation_tracker.json)
