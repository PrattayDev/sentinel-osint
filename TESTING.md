# Sentinel OSINT — Testing Strategy & Acceptance Matrix

## 1. Test Suite Architecture

Sentinel OSINT uses **Vitest** for unit, integration, provider contract, and security regression tests, alongside **Playwright** / HTTP route verification for end-to-end user journeys.

```bash
# Run the complete unit, integration, and security regression suite
npm test

# Run tests with coverage
npm run test:coverage

# Type-check the entire project
npm run typecheck

# Run production build verification
npm run build
```

---

## 2. Acceptance Test Matrix Coverage (`tests/`)

| Acceptance Domain | Test File | Verified Scenarios |
|---|---|---|
| **Authentication & Tenant Isolation** | `tests/security-and-auth.test.ts` | Unauthenticated requests rejected (`401`); cross-user case/investigation access blocked (`403`/`404`); password hashing (`scrypt`); session invalidation on logout; ethical-use terms enforcement. |
| **SSRF & Network Hardening** | `tests/ssrf-and-url.test.ts` | Blocks `localhost`, `127.0.0.1`, `10.x.x.x`, `172.16.x.x`, `192.168.x.x`, `169.254.169.254` (cloud metadata), `::1`, `::ffff:127.0.0.1`, `fe80::`, `fc00::`; blocks unsafe schemes (`file:`, `javascript:`, `ftp:`); blocks redirect chains hopping to internal IPs. |
| **Domain, DNS & IP Intelligence** | `tests/osint-providers.test.ts` | Punycode/IDNA domain normalization; invalid domain rejection; IPv4 & IPv6 validation; private IP blocking before external lookup; live DNS/RDAP/InternetDB execution and provenance attribution. |
| **Identity, Username & Phone** | `tests/osint-providers.test.ts` | RFC 5322 email validation; disposable email detection; `libphonenumber-js` E.164 & region parsing; public username discovery with source URLs and non-inferential confidence labels. |
| **Threat Intelligence** | `tests/osint-providers.test.ts` | Valid MD5/SHA-1/SHA-256 acceptance; invalid hash rejection; missing API keys return `not_configured`; unknown hashes classified as `unknown` (never `safe`). |
| **File Metadata & Upload Security** | `tests/file-and-exports.test.ts` | Magic-byte validation (JPEG, PNG, PDF); oversized payload rejection (`>10 MB`); executable/script rejection; EXIF GPS coordinates redacted by default; cryptographic & perceptual hash calculation. |
| **Exports & Formula Injection** | `tests/file-and-exports.test.ts` | JSON export validity; CSV formula injection neutralization (`=`, `+`, `-`, `@`, `\t`, `\r` prefixed safely); PDF report structure & source citations; STIX 2.1 bundle schema conformance. |
| **Investigation Engine & Persistence** | `tests/investigation-engine.test.ts` | Bounded concurrent execution; partial provider failure resilience; deduplication; entity & relationship graph extraction; user-scoped CRUD and hard deletion. |
