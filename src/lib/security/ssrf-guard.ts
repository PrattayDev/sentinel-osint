import net from 'net';
import dns from 'dns/promises';
import { URL } from 'url';

export interface IpClassification {
  ip: string;
  version: 4 | 6 | 0;
  isPublic: boolean;
  isBlocked: boolean;
  reason?: string;
}

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'metadata',
  'metadata.google.internal',
  'metadata.goog',
  'instance-data',
  'kubernetes',
  'kubernetes.default',
  'kubernetes.default.svc',
  'kubernetes.default.svc.cluster.local',
  'docker.internal',
  'host.docker.internal'
]);

const ALLOWED_PORTS = new Set(['', '80', '443', '8080', '8443']);

function parseIpv4ToUint32(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    if (part.length > 1 && part.startsWith('0')) {
      // Disallow ambiguous octal notation
      return null;
    }
    const num = Number(part);
    if (num < 0 || num > 255) return null;
    result = ((result << 8) | num) >>> 0;
  }
  return result >>> 0;
}

function inCidr4(ipNum: number, baseIp: string, prefixLength: number): boolean {
  const baseNum = parseIpv4ToUint32(baseIp);
  if (baseNum === null) return false;
  const mask = prefixLength === 0 ? 0 : (~0 << (32 - prefixLength)) >>> 0;
  return (ipNum & mask) >>> 0 === (baseNum & mask) >>> 0;
}

/**
 * Expands an IPv6 address into 8 16-bit integer groups.
 */
function parseIpv6Groups(ip: string): number[] | null {
  const zoneCleaned = ip.split('%')[0].toLowerCase();

  // Check if embedded IPv4 at end (e.g. ::ffff:127.0.0.1)
  let work = zoneCleaned;
  if (work.includes('.')) {
    const lastColon = work.lastIndexOf(':');
    if (lastColon === -1) return null;
    const ipv4Part = work.slice(lastColon + 1);
    const ipv4Uint = parseIpv4ToUint32(ipv4Part);
    if (ipv4Uint === null) return null;
    const high = (ipv4Uint >>> 16) & 0xffff;
    const low = ipv4Uint & 0xffff;
    work = `${work.slice(0, lastColon)}:${high.toString(16)}:${low.toString(16)}`;
  }

  const doubleColonParts = work.split('::');
  if (doubleColonParts.length > 2) return null;

  const left = doubleColonParts[0] ? doubleColonParts[0].split(':') : [];
  const right =
    doubleColonParts.length === 2 && doubleColonParts[1]
      ? doubleColonParts[1].split(':')
      : [];

  if (doubleColonParts.length === 1 && left.length !== 8) return null;
  if (left.length + right.length > 8) return null;

  const missing = 8 - (left.length + right.length);
  const full = [
    ...left,
    ...Array(doubleColonParts.length === 2 ? missing : 0).fill('0'),
    ...right
  ];
  if (full.length !== 8) return null;

  const groups: number[] = [];
  for (const g of full) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    groups.push(parseInt(g, 16));
  }
  return groups;
}

/**
 * Classifies an IPv4 or IPv6 address and determines whether it must be blocked for SSRF/external OSINT queries.
 */
export function classifyIpAddress(rawIp: string): IpClassification {
  const trimmed = rawIp.trim().replace(/^\[|\]$/g, '');
  const version = net.isIP(trimmed) as 0 | 4 | 6;

  if (version === 0) {
    return {
      ip: trimmed,
      version: 0,
      isPublic: false,
      isBlocked: true,
      reason: 'Invalid IP address format'
    };
  }

  if (version === 4) {
    const ipNum = parseIpv4ToUint32(trimmed);
    if (ipNum === null) {
      return {
        ip: trimmed,
        version: 4,
        isPublic: false,
        isBlocked: true,
        reason: 'Malformed or non-standard IPv4 representation'
      };
    }

    const blockedRanges: Array<[string, number, string]> = [
      ['0.0.0.0', 8, 'Current network (RFC 1122)'],
      ['10.0.0.0', 8, 'Private network (RFC 1918)'],
      ['100.64.0.0', 10, 'Carrier-Grade NAT (RFC 6598)'],
      ['127.0.0.0', 8, 'Loopback (RFC 1122)'],
      ['169.254.0.0', 16, 'Link-local / Cloud Metadata Service (RFC 3927)'],
      ['172.16.0.0', 12, 'Private network (RFC 1918)'],
      ['192.0.0.0', 24, 'IETF Protocol Assignments (RFC 6890)'],
      ['192.0.2.0', 24, 'TEST-NET-1 Documentation (RFC 5737)'],
      ['192.88.99.0', 24, '6to4 Relay Anycast (RFC 7526)'],
      ['192.168.0.0', 16, 'Private network (RFC 1918)'],
      ['198.18.0.0', 15, 'Benchmarking network (RFC 2544)'],
      ['198.51.100.0', 24, 'TEST-NET-2 Documentation (RFC 5737)'],
      ['203.0.113.0', 24, 'TEST-NET-3 Documentation (RFC 5737)'],
      ['224.0.0.0', 4, 'Multicast (RFC 5771)'],
      ['240.0.0.0', 4, 'Reserved for future use (RFC 1112)'],
      ['255.255.255.255', 32, 'Limited broadcast']
    ];

    for (const [base, prefix, label] of blockedRanges) {
      if (inCidr4(ipNum, base, prefix)) {
        return {
          ip: trimmed,
          version: 4,
          isPublic: false,
          isBlocked: true,
          reason: `Blocked IPv4 range: ${label}`
        };
      }
    }

    return {
      ip: trimmed,
      version: 4,
      isPublic: true,
      isBlocked: false
    };
  }

  // IPv6 verification
  const groups = parseIpv6Groups(trimmed);
  if (!groups) {
    return {
      ip: trimmed,
      version: 6,
      isPublic: false,
      isBlocked: true,
      reason: 'Malformed IPv6 address'
    };
  }

  // Unspecified ::
  if (groups.every((g) => g === 0)) {
    return {
      ip: trimmed,
      version: 6,
      isPublic: false,
      isBlocked: true,
      reason: 'Blocked IPv6 unspecified address (::)'
    };
  }

  // Loopback ::1
  if (groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) {
    return {
      ip: trimmed,
      version: 6,
      isPublic: false,
      isBlocked: true,
      reason: 'Blocked IPv6 loopback address (::1)'
    };
  }

  // IPv4-mapped IPv6 ::ffff:0:0/96 or IPv4-compatible ::w.x.y.z
  const isIpv4Mapped =
    groups.slice(0, 5).every((g) => g === 0) &&
    (groups[5] === 0xffff || groups[5] === 0x0000);
  if (isIpv4Mapped) {
    const a = (groups[6] >>> 8) & 0xff;
    const b = groups[6] & 0xff;
    const c = (groups[7] >>> 8) & 0xff;
    const d = groups[7] & 0xff;
    const embeddedV4 = `${a}.${b}.${c}.${d}`;
    const v4Check = classifyIpAddress(embeddedV4);
    if (v4Check.isBlocked) {
      return {
        ip: trimmed,
        version: 6,
        isPublic: false,
        isBlocked: true,
        reason: `Blocked IPv4-mapped IPv6 address (${v4Check.reason})`
      };
    }
  }

  // Unique Local fc00::/7 (fc00..fdff)
  if ((groups[0] & 0xfe00) === 0xfc00) {
    return {
      ip: trimmed,
      version: 6,
      isPublic: false,
      isBlocked: true,
      reason: 'Blocked IPv6 Unique Local Address (RFC 4193)'
    };
  }

  // Link-Local fe80::/10
  if ((groups[0] & 0xffc0) === 0xfe80) {
    return {
      ip: trimmed,
      version: 6,
      isPublic: false,
      isBlocked: true,
      reason: 'Blocked IPv6 Link-Local Address'
    };
  }

  // Multicast ff00::/8
  if ((groups[0] & 0xff00) === 0xff00) {
    return {
      ip: trimmed,
      version: 6,
      isPublic: false,
      isBlocked: true,
      reason: 'Blocked IPv6 Multicast Address'
    };
  }

  // Documentation 2001:db8::/32
  if (groups[0] === 0x2001 && groups[1] === 0x0db8) {
    return {
      ip: trimmed,
      version: 6,
      isPublic: false,
      isBlocked: true,
      reason: 'Blocked IPv6 Documentation Range (2001:db8::/32)'
    };
  }

  return {
    ip: trimmed,
    version: 6,
    isPublic: true,
    isBlocked: false
  };
}

export function isBlockedIpAddress(ip: string): boolean {
  return classifyIpAddress(ip).isBlocked;
}

export function isBlockedHostname(hostname: string): {
  blocked: boolean;
  reason?: string;
} {
  const clean = hostname.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (!clean) {
    return { blocked: true, reason: 'Empty hostname' };
  }

  if (BLOCKED_HOSTNAMES.has(clean)) {
    return { blocked: true, reason: `Blocked internal hostname (${clean})` };
  }

  if (
    clean.endsWith('.localhost') ||
    clean.endsWith('.local') ||
    clean.endsWith('.internal') ||
    clean.endsWith('.localdomain') ||
    clean.endsWith('.home.arpa') ||
    clean.endsWith('.intranet') ||
    clean.endsWith('.lan')
  ) {
    return {
      blocked: true,
      reason: `Blocked internal/reserved TLD hostname (${clean})`
    };
  }

  // Reject integer/hex/octal IP encodings disguised as hostnames (e.g. 2130706433 or 0x7f000001 or 0177.0.0.1)
  if (/^\d+$/.test(clean) || /^0x[0-9a-f]+$/i.test(clean)) {
    return {
      blocked: true,
      reason: 'Blocked numeric/hexadecimal IP obfuscation'
    };
  }

  if (/^[0-9.]+$/.test(clean) && net.isIPv4(clean) === false) {
    return {
      blocked: true,
      reason: 'Blocked malformed/octal dotted-quad hostname'
    };
  }

  // If the hostname is an IP literal, validate it directly
  if (net.isIP(clean) !== 0) {
    const check = classifyIpAddress(clean);
    if (check.isBlocked) {
      return { blocked: true, reason: check.reason };
    }
  }

  return { blocked: false };
}

export interface ValidatedUrlTarget {
  url: URL;
  normalizedUrl: string;
  hostname: string;
  resolvedIps: string[];
}

/**
 * Validates a URL for safe outbound fetching and resolves its DNS records to prevent SSRF and DNS rebinding.
 */
export async function validateSafeUrlAndResolve(
  rawUrl: string,
  options?: { skipDnsResolutionInOfflineTest?: boolean }
): Promise<ValidatedUrlTarget> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    throw new Error('SSRF_GUARD: Invalid URL syntax');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(
      `SSRF_GUARD: Unsupported URL protocol "${parsed.protocol}". Only http: and https: are permitted.`
    );
  }

  if (parsed.username || parsed.password) {
    throw new Error('SSRF_GUARD: Embedded credentials in URL are prohibited.');
  }

  if (!ALLOWED_PORTS.has(parsed.port)) {
    throw new Error(
      `SSRF_GUARD: Port ${parsed.port} is not permitted for outbound web inspection.`
    );
  }

  const hostCheck = isBlockedHostname(parsed.hostname);
  if (hostCheck.blocked) {
    throw new Error(`SSRF_GUARD: ${hostCheck.reason}`);
  }

  const cleanHost = parsed.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(cleanHost) !== 0) {
    const ipCheck = classifyIpAddress(cleanHost);
    if (ipCheck.isBlocked) {
      throw new Error(`SSRF_GUARD: ${ipCheck.reason}`);
    }
    return {
      url: parsed,
      normalizedUrl: parsed.toString(),
      hostname: cleanHost,
      resolvedIps: [cleanHost]
    };
  }

  if (options?.skipDnsResolutionInOfflineTest) {
    return {
      url: parsed,
      normalizedUrl: parsed.toString(),
      hostname: cleanHost,
      resolvedIps: []
    };
  }

  // Resolve all A and AAAA records and verify EVERY resolved IP is public
  let records: Array<{ address: string; family: number }> = [];
  try {
    records = await dns.lookup(cleanHost, { all: true, verbatim: true });
  } catch (err) {
    throw new Error(
      `DNS resolution failed for ${cleanHost}: ${(err as Error).message}`
    );
  }

  if (!records || records.length === 0) {
    throw new Error(`DNS resolution returned no addresses for ${cleanHost}`);
  }

  const resolvedIps: string[] = [];
  for (const rec of records) {
    const ipCheck = classifyIpAddress(rec.address);
    if (ipCheck.isBlocked) {
      throw new Error(
        `SSRF_GUARD: Hostname ${cleanHost} resolved to blocked address ${rec.address} (${ipCheck.reason})`
      );
    }
    resolvedIps.push(rec.address);
  }

  return {
    url: parsed,
    normalizedUrl: parsed.toString(),
    hostname: cleanHost,
    resolvedIps
  };
}

export interface RedirectHop {
  hop: number;
  url: string;
  statusCode: number;
  location?: string;
  resolvedIps: string[];
  serverHeader?: string;
}

export interface SafeHttpInspectResult {
  finalUrl: string;
  statusCode: number;
  statusText: string;
  headers: Record<string, string>;
  redirectChain: RedirectHop[];
  bodySnippet: string;
  bodyBytesRead: number;
  resolvedIps: string[];
}

/**
 * Fetches a public URL using manual redirect handling so that every redirect hop is re-validated against SSRF rules.
 */
export async function safeFetchWithRedirectInspection(
  initialUrl: string,
  options?: {
    maxRedirects?: number;
    timeoutMs?: number;
    maxBytes?: number;
  }
): Promise<SafeHttpInspectResult> {
  const maxRedirects = options?.maxRedirects ?? 5;
  const timeoutMs = options?.timeoutMs ?? 8000;
  const maxBytes = options?.maxBytes ?? 512 * 1024; // 512 KB cap

  let currentUrl = initialUrl;
  const redirectChain: RedirectHop[] = [];

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const validated = await validateSafeUrlAndResolve(currentUrl);

    const response = await fetch(validated.normalizedUrl, {
      method: 'GET',
      redirect: 'manual',
      headers: {
        'User-Agent': 'Sentinel-OSINT-Inspector/2.0 (+Passive-Security-Research)',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      },
      signal: AbortSignal.timeout(timeoutMs)
    });

    const locationHeader = response.headers.get('location') || undefined;
    redirectChain.push({
      hop,
      url: validated.normalizedUrl,
      statusCode: response.status,
      location: locationHeader,
      resolvedIps: validated.resolvedIps,
      serverHeader: response.headers.get('server') || undefined
    });

    if (
      response.status >= 300 &&
      response.status < 400 &&
      locationHeader
    ) {
      if (hop === maxRedirects) {
        throw new Error(
          `Maximum redirect limit (${maxRedirects}) exceeded while inspecting URL.`
        );
      }
      const nextUrl = new URL(locationHeader, validated.url).toString();
      // Validate next hop before following!
      await validateSafeUrlAndResolve(nextUrl);
      currentUrl = nextUrl;
      continue;
    }

    const headersRecord: Record<string, string> = {};
    response.headers.forEach((val, key) => {
      headersRecord[key.toLowerCase()] = val;
    });

    // Read up to maxBytes safely from response body stream
    let bodySnippet = '';
    let bodyBytesRead = 0;
    if (response.body) {
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          bodyBytesRead += value.byteLength;
          if (bodyBytesRead > maxBytes) {
            const allowedSlice = value.slice(
              0,
              Math.max(0, maxBytes - (bodyBytesRead - value.byteLength))
            );
            if (allowedSlice.byteLength > 0) chunks.push(allowedSlice);
            await reader.cancel();
            break;
          }
          chunks.push(value);
        }
      }
      const combined = Buffer.concat(chunks.map((c) => Buffer.from(c)));
      bodySnippet = combined.toString('utf8');
    }

    return {
      finalUrl: validated.normalizedUrl,
      statusCode: response.status,
      statusText: response.statusText,
      headers: headersRecord,
      redirectChain,
      bodySnippet,
      bodyBytesRead,
      resolvedIps: validated.resolvedIps
    };
  }

  throw new Error('Unexpected end of redirect loop');
}
