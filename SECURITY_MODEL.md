# Sentinel OSINT — Application Security Model

## 1. Defense-in-Depth Architecture

Sentinel OSINT processes untrusted external data (DNS records, HTTP headers, HTML titles, TLS certificates, RDAP responses, threat feeds, and uploaded files) and executes outbound requests on behalf of authenticated analysts. Therefore, the platform enforces strict defense-in-depth controls across six layers:

1. **Authentication & Session Integrity**
2. **Authorization & Row-Level Tenant Isolation (RLS)**
3. **Server-Side Request Forgery (SSRF) & DNS Rebinding Prevention**
4. **Untrusted Content Sanitization & Formula Injection Prevention**
5. **Zero-Execution File Upload Sandboxing & Sensitive Metadata Redaction**
6. **Per-User / Per-Provider Rate Limiting & Immutable Audit Logging**

---

## 2. SSRF & Redirect-Chain Protection (`src/lib/security/ssrf-guard.ts`)

All outbound URL, domain HTTP metadata, and TLS connections pass through `validateSafeUrlAndResolve()`:

### 2.1 Protocol Restrictions
- Only `http:` and `https:` schemes are permitted.
- `file:`, `ftp:`, `gopher:`, `ws:`, `wss:`, `data:`, `javascript:`, and `dict:` are rejected immediately.
- Embedded URL credentials (`https://user:pass@example.com`) and non-standard ports (anything other than `80`, `443`, `8080`, `8443`) are blocked.

### 2.2 Blocked Hostnames & IP Ranges
Any hostname or resolved IPv4/IPv6 address matching the following is blocked before socket connection:
- **Localhost & Internal Names**: `localhost`, `*.localhost`, `*.local`, `*.internal`, `metadata.google.internal`, `instance-data`, `kubernetes.default`.
- **IPv4 Loopback**: `127.0.0.0/8`
- **IPv4 Private (RFC 1918)**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- **IPv4 Link-Local & Cloud Instance Metadata (AWS/GCP/Azure/DigitalOcean)**: `169.254.0.0/16` (including `169.254.169.254` and `169.254.170.2`)
- **IPv4 Carrier-Grade NAT (RFC 6598)**: `100.64.0.0/10`
- **IPv4 Current Network / Broadcast / Multicast / Benchmarking / Reserved**: `0.0.0.0/8`, `192.0.0.0/24`, `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, `240.0.0.0/4`, `255.255.255.255/32`
- **IPv6 Unspecified & Loopback**: `::`, `::1`
- **IPv6 IPv4-Mapped & Translated Addresses**: `::ffff:0:0/96` (unwrapped and validated against all IPv4 block rules to prevent `::ffff:127.0.0.1` or `::ffff:169.254.169.254` bypasses)
- **IPv6 Unique Local (ULA, RFC 4193)**: `fc00::/7` (`fc00::` – `fdff::`)
- **IPv6 Link-Local**: `fe80::/10`
- **IPv6 Multicast & Documentation**: `ff00::/8`, `2001:db8::/32`

### 2.3 Manual Redirect Inspection & DNS Rebinding Mitigation
- Outbound `fetch` calls use `redirect: 'manual'`.
- Each `3xx` `Location` header is parsed, resolved via DNS (`lookupAll`), and every returned A/AAAA record is verified against `isBlockedIpAddress()` before the next hop is requested.
- Maximum redirect depth is capped at `5` hops.
- Maximum response stream read is capped at `512 KB` for HTML metadata extraction, with an `8,000 ms` `AbortSignal.timeout`.
- **TLS Handshake DNS Rebinding Prevention (`src/lib/providers/tls-provider.ts`)**: `validateSafeUrlAndResolve()` resolves and validates the target hostname's IP address first, and `inspectRemoteTlsCertificate()` connects the TCP socket directly to the validated `pinnedIp` while preserving `servername: hostname` for SNI and certificate verification, eliminating the Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding window.

---

## 3. Injection & Output Encoding (`src/lib/security/sanitizer.ts`)

1. **Database Operations**: All SQL queries in Supabase use parameterized client builders and PostgreSQL RLS policies. Local storage uses typed schema serialization with UUID validation.
2. **HTML / XSS Prevention**: Sentinel never renders raw provider HTML via `dangerouslySetInnerHTML`. Extracted strings are stripped of control characters and HTML tags.
3. **CSV Formula Injection Prevention (`escapeCsvCell`)**:
   - Any exported CSV field starting with `=`, `+`, `-`, `@`, `\t` (`0x09`), or `\r` (`0x0D`)—even after leading whitespace—is prefixed with a single quote (`'`) and wrapped in escaped double quotes (`"..."`) so spreadsheet applications (Excel, LibreOffice, Google Sheets) never execute formulas from attacker-controlled OSINT fields (such as a malicious HTTP `<title>=CMD|' /C calc'!A0</title>`).
4. **Zero Shell Execution**: Local analyzers (`libphonenumber-js`, binary EXIF/PDF parsers, SHA-256/dHash calculators) run in pure memory buffers without invoking `child_process.exec` or shell interpolation.

---

## 4. File Upload Security & Privacy Redaction (`src/lib/security/file-validator.ts`)

- **Strict Size Limit**: Maximum `10 MB` (`10,485,760` bytes) enforced prior to parsing.
- **Magic-Byte File Signature Verification**: File type is verified against actual binary magic bytes (`FF D8 FF` for JPEG, `89 50 4E 47 0D 0A 1A 0A` for PNG, `47 49 46 38` for GIF, `52 49 46 46....57 45 42 50` for WebP, `25 50 44 46 2D` for PDF)—never trusting client `Content-Type` or filename extensions alone.
- **Blocked Payloads**: Executables (`MZ`, `ELF`), archives (`PK` ZIP/DOCX macros unless explicitly inspected safely), HTML/SVG scripts (`<script`, `onload=`), and polyglot files are rejected.
- **Location Privacy Default**: EXIF GPS coordinates (`GPSLatitude`, `GPSLongitude`, `GPSAltitude`) are automatically flagged `sensitivity: 'restricted'` and redacted (`[REDACTED — Explicit Analyst Reveal Required]`) in default API responses and UI views until explicitly unlocked by an authorized user action (which writes an `audit_events` log entry).

---

## 5. Authentication, Authorization & Row-Level Security

- **Server-Side Session Validation**: Every protected API route calls `requireAuthenticatedUser(request)` on the server. Client-supplied `userId` or `role` fields in request bodies or query strings are ignored.
- **Tenant Isolation**: Every `Investigation`, `Case`, `Finding`, `Report`, and `EvidenceSource` belongs to an `owner_id` and `workspace_id`. Attempting to read, update, export, or delete another user's resource returns `403 Forbidden` or `404 Not Found` (preventing ID enumeration) and records a security audit event.
- **Non-Predictable Identifiers**: All primary keys are cryptographically random UUIDv4 values.
- **Development Auth Shortcut & Reset Token Gating**:
  - The `"Initialize Authenticated Analyst Session"` button in `src/components/auth/AuthScreen.tsx` is strictly disabled and hidden unless both `process.env.NODE_ENV === 'development'` and `process.env.NEXT_PUBLIC_ENABLE_DEV_AUTH_SHORTCUT === 'true'` are explicitly set. It cannot be rendered or triggered in production builds.
  - Password reset tokens (`devResetToken` in `src/app/api/auth/route.ts`) are only surfaced in API responses when `(process.env.NODE_ENV === 'development' && process.env.ENABLE_DEV_AUTH_SHORTCUT === 'true') || process.env.NODE_ENV === 'test'`.
