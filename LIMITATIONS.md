# Sentinel OSINT — Known Limitations & Operational Boundaries

## 1. Ethical & Legal Boundaries (Intentional Restrictions)

1. **No Active Port Scanning or Vulnerability Exploitation**: Network intelligence (`NET-09`) relies strictly on passive observations (Shodan InternetDB, RIPEstat, RDAP, reverse DNS). Sentinel never sends SYN scans, port sweeps, or exploit payloads to target hosts.
2. **No Private Subscriber or Carrier Account Lookups**: Phone intelligence (`ID-07`, `ID-08`) parses numbering plans, country codes, and line types locally via `libphonenumber-js`. It does not query restricted telecom CNAM/HLR subscriber records or real-time SIM location.
3. **No Plaintext Password or Credential Dump Retrieval**: Breach exposure (`ID-04`) queries metadata (breach name, date, exposed data classes) via authorized APIs (Have I Been Pwned v3) when configured and never retrieves or stores leaked plaintext passwords.
4. **No Login-Walled Social Scraping**: Social/username discovery (`ID-05`, `SOC-01`–`SOC-08`) queries only platforms with public unauthenticated REST/JSON APIs (`GitHub`, `GitLab`, `Keybase`, `HackerNews`, `Reddit JSON`, `Gravatar`). Platforms requiring authentication or blocking automated access are not scraped.
5. **No Automated Face Recognition**: Image intelligence (`IMG-01`–`IMG-10`) extracts technical EXIF/PDF metadata and hashes only. It never performs biometric facial recognition.

---

## 2. Technical & Provider Limitations

1. **Keyed Commercial Providers**:
   - **Have I Been Pwned (`ID-04`)**: Requires a paid `HIBP_API_KEY` subscription. Without this key, the provider reports `not_configured`.
   - **VirusTotal (`THR-01`, `WEB-06`), AbuseIPDB (`NET-07`), Google Safe Browsing (`WEB-07`), SecurityTrails (`DOM-08`), Censys (`NET-10`)**: Require their respective environment variables (`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, etc.). Zero-key alternatives (`abuse.ch` URLhaus/ThreatFox/MalwareBazaar, `Shodan InternetDB`, `crt.sh`) are active by default so threat and passive infrastructure lookups still return live data.
2. **Certificate Transparency Latency (`crt.sh`)**:
   - Public `crt.sh` queries on massive root domains (e.g., `google.com` or `amazonaws.com`) can occasionally time out due to upstream PostgreSQL load on `crt.sh`. Sentinel mitigates this with a 10-second timeout and automatic fallback to the `CertSpotter` v1 API.
3. **GeoIP Precision (`NET-06`)**:
   - IP geolocation reflects ISP/ASN registration or coarse routing PoP locations, never the physical street address of an individual user. All UI cards and reports explicitly display this caveat.
4. **Unknown Hash Verdicts (`THR-01`)**:
   - When a file hash (MD5/SHA-1/SHA-256) returns zero hits in MalwareBazaar or VirusTotal, Sentinel classifies the indicator as `unknown` (`unrated`), never `safe` or `benign`, because novel or targeted malware may simply not yet exist in public corpora.
5. **Reference Website (`https://osint.hackunderway.io/panel`)**:
   - Only the unauthenticated redirect target (`index.php`) is publicly accessible. Internal modules behind authentication were not accessed or copied; Sentinel OSINT is an original implementation.
6. **Active Runtime Persistence Engine vs. Supabase DDL**:
   - At runtime, `src/lib/db/repository.ts` uses an isolated local file-backed JSON repository (`.data/sentinel-db.json` with in-memory fallback) enforcing strict `ownerId` tenant filtering, `scrypt` password hashing, and SHA-256 session token digests.
   - While `supabase/migrations/0001_sentinel_osint_schema.sql` provides the complete 19-table PostgreSQL DDL and Row-Level Security (RLS) policies, the repository functions in `src/lib/db/repository.ts` do not yet execute remote Supabase SQL queries directly. In multi-instance serverless deployments (e.g., Vercel), the local `.data/sentinel-db.json` store is instance-local and ephemeral across cold starts until `repository.ts` is wired to query Supabase tables directly.
