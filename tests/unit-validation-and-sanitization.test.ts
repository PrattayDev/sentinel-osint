import { describe, it, expect, beforeEach } from 'vitest';
import {
  classifyAndValidateTarget,
  CreateCaseSchema,
  CreateInvestigationSchema,
  validateAndNormalizeDomain,
  validateAndNormalizeEmail,
  validateAndNormalizeFileHash,
  validateAndNormalizeIp,
  validateAndNormalizeOrganization,
  validateAndNormalizePhone,
  validateAndNormalizeUrl,
  validateAndNormalizeUsername
} from '@/lib/validation/schemas';
import {
  escapeCsvCell,
  redactSensitiveAttributes,
  sanitizeRecord,
  sanitizeText
} from '@/lib/security/sanitizer';
import {
  checkRateLimit,
  resetRateLimitsForTest
} from '@/lib/security/rate-limiter';

describe('Unit Tests: Target Input Validators & Normalizers (schemas.ts)', () => {
  it('validates and normalizes ASCII & IDNA/Punycode domains and rejects invalid domains', () => {
    const ascii = validateAndNormalizeDomain('  ExAmPlE.CoM. ');
    expect(ascii.valid).toBe(true);
    expect(ascii.normalizedValue).toBe('example.com');
    expect(ascii.metadata.tld).toBe('com');
    expect(ascii.metadata.labelCount).toBe(2);

    const idna = validateAndNormalizeDomain('münchen.de');
    expect(idna.valid).toBe(true);
    expect(idna.normalizedValue).toBe('xn--mnchen-3ya.de');
    expect(idna.metadata.isInternationalized).toBe(true);

    // Reject protocol, path, port, spaces, IP literals, single-label, numeric TLD, internal hosts
    expect(validateAndNormalizeDomain('https://example.com').valid).toBe(false);
    expect(validateAndNormalizeDomain('example.com/path').valid).toBe(false);
    expect(validateAndNormalizeDomain('example.com:8080').valid).toBe(false);
    expect(validateAndNormalizeDomain('93.184.216.34').valid).toBe(false);
    expect(validateAndNormalizeDomain('singlelabel').valid).toBe(false);
    expect(validateAndNormalizeDomain('bad.123').valid).toBe(false);
    expect(validateAndNormalizeDomain('-leadinghyphen.com').valid).toBe(false);
    expect(validateAndNormalizeDomain('localhost').valid).toBe(false);
    expect(validateAndNormalizeDomain('service.internal').valid).toBe(false);
  });

  it('validates and normalizes RFC 5322 email addresses and subaddressing tags', () => {
    const valid = validateAndNormalizeEmail('  SecOps+Incident42@ExAmPlE.cOm ');
    expect(valid.valid).toBe(true);
    expect(valid.normalizedValue).toBe('secops+incident42@example.com');
    expect(valid.metadata.baseLocalPart).toBe('secops');
    expect(valid.metadata.subaddressTag).toBe('incident42');
    expect(valid.metadata.domain).toBe('example.com');

    // Reject malformed local-parts and domains
    expect(validateAndNormalizeEmail('no-at-symbol.com').valid).toBe(false);
    expect(validateAndNormalizeEmail('@example.com').valid).toBe(false);
    expect(validateAndNormalizeEmail('user@').valid).toBe(false);
    expect(validateAndNormalizeEmail('.leadingdot@example.com').valid).toBe(false);
    expect(validateAndNormalizeEmail('trailingdot.@example.com').valid).toBe(false);
    expect(validateAndNormalizeEmail('double..dot@example.com').valid).toBe(false);
    expect(validateAndNormalizeEmail('user@localhost').valid).toBe(false);
  });

  it('validates public IPv4/IPv6 addresses and blocks private/loopback/reserved ranges', () => {
    const v4 = validateAndNormalizeIp(' 1.1.1.1 ');
    expect(v4.valid).toBe(true);
    expect(v4.normalizedValue).toBe('1.1.1.1');
    expect(v4.metadata.ipVersion).toBe('IPv4');

    const v6 = validateAndNormalizeIp('2606:4700:4700::1111');
    expect(v6.valid).toBe(true);
    expect(v6.metadata.ipVersion).toBe('IPv6');

    // Reject private, loopback, link-local, metadata, and non-IP strings
    expect(validateAndNormalizeIp('127.0.0.1').valid).toBe(false);
    expect(validateAndNormalizeIp('10.0.0.1').valid).toBe(false);
    expect(validateAndNormalizeIp('172.16.5.4').valid).toBe(false);
    expect(validateAndNormalizeIp('192.168.1.1').valid).toBe(false);
    expect(validateAndNormalizeIp('169.254.169.254').valid).toBe(false);
    expect(validateAndNormalizeIp('::1').valid).toBe(false);
    expect(validateAndNormalizeIp('fe80::1').valid).toBe(false);
    expect(validateAndNormalizeIp('not-an-ip').valid).toBe(false);
  });

  it('validates HTTP/HTTPS URLs and blocks unsafe schemes, embedded credentials, and non-standard ports', () => {
    const valid = validateAndNormalizeUrl('https://example.com:8443/research?q=1');
    expect(valid.valid).toBe(true);
    expect(valid.metadata.port).toBe('8443');
    expect(valid.metadata.hostname).toBe('example.com');

    expect(validateAndNormalizeUrl('ftp://example.com/file').valid).toBe(false);
    expect(validateAndNormalizeUrl('javascript:alert(1)').valid).toBe(false);
    expect(validateAndNormalizeUrl('https://user:pass@example.com/').valid).toBe(false);
    expect(validateAndNormalizeUrl('http://example.com:22/').valid).toBe(false);
    expect(validateAndNormalizeUrl('http://example.com:3306/').valid).toBe(false);
    expect(validateAndNormalizeUrl('http://localhost:8080/').valid).toBe(false);
  });

  it('validates MD5, SHA-1, and SHA-256 hashes and rejects invalid hex strings', () => {
    const md5 = validateAndNormalizeFileHash('D41D8CD98F00B204E9800998ECF8427E');
    expect(md5.valid).toBe(true);
    expect(md5.normalizedValue).toBe('d41d8cd98f00b204e9800998ecf8427e');
    expect(md5.metadata.algorithm).toBe('MD5');
    expect(md5.metadata.bitLength).toBe(128);

    const sha1 = validateAndNormalizeFileHash('da39a3ee5e6b4b0d3255bfef95601890afd80709');
    expect(sha1.valid).toBe(true);
    expect(sha1.metadata.algorithm).toBe('SHA-1');

    const sha256 = validateAndNormalizeFileHash(
      'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855'
    );
    expect(sha256.valid).toBe(true);
    expect(sha256.metadata.algorithm).toBe('SHA-256');
    expect(sha256.metadata.bitLength).toBe(256);

    expect(validateAndNormalizeFileHash('abcd1234').valid).toBe(false);
    expect(validateAndNormalizeFileHash('g41d8cd98f00b204e9800998ecf8427e').valid).toBe(false);
  });

  it('validates phones, usernames, organizations, and auto-classifies all indicator types', () => {
    const phone = validateAndNormalizePhone('+44 20 7946 0958');
    expect(phone.valid).toBe(true);
    expect(phone.normalizedValue).toBe('+442079460958');
    expect(phone.metadata.countryIso).toBe('GB');

    const user = validateAndNormalizeUsername('@octo_cat-99');
    expect(user.valid).toBe(true);
    expect(user.normalizedValue).toBe('octo_cat-99');
    expect(validateAndNormalizeUsername('a').valid).toBe(false);
    expect(validateAndNormalizeUsername('bad space').valid).toBe(false);

    const org = validateAndNormalizeOrganization('  Cloudflare, Inc. <script>bad</script> ');
    expect(org.valid).toBe(true);
    expect(org.normalizedValue).toBe('Cloudflare, Inc.');

    // Auto-classification matrix
    expect(classifyAndValidateTarget('https://iana.org').targetType).toBe('url');
    expect(classifyAndValidateTarget('soc@example.com').targetType).toBe('email');
    expect(classifyAndValidateTarget('8.8.8.8').targetType).toBe('ip');
    expect(classifyAndValidateTarget('d41d8cd98f00b204e9800998ecf8427e').targetType).toBe(
      'file_hash'
    );
    expect(classifyAndNormalizeTargetHelper('+14155552671')).toBe('phone');
    expect(classifyAndValidateTarget('example.org').targetType).toBe('domain');
    expect(classifyAndValidateTarget('Acme Cyber Corp').targetType).toBe('organization');
    expect(classifyAndValidateTarget('torvalds').targetType).toBe('username');

    // Zod schema checks
    expect(
      CreateInvestigationSchema.safeParse({
        targetValue: 'example.com',
        scope: 'Authorized defensive test',
        purpose: 'Unit test validation'
      }).success
    ).toBe(true);
    expect(
      CreateCaseSchema.safeParse({
        title: 'Incident #402',
        description: 'Investigating phishing infrastructure',
        scopeAndAuthorization: 'SOC Ticket #402'
      }).success
    ).toBe(true);
  });
});

function classifyAndNormalizeTargetHelper(val: string) {
  return classifyAndValidateTarget(val).targetType;
}

describe('Unit Tests: Sanitizer, Prototype Pollution Guard & Rate Limiter', () => {
  beforeEach(() => {
    resetRateLimitsForTest();
  });

  it('strips scripts, HTML tags, null bytes, and blocks prototype pollution keys in sanitizeRecord', () => {
    const dirty = 'Hello \0<script>evil()</script><b>World</b>\x07!';
    expect(sanitizeText(dirty, 100)).toBe('Hello World!');

    const maliciousObj = JSON.parse(
      '{"normal":"<b>safe</b>","__proto__":{"polluted":true},"constructor":{"bad":1},"nested":["<script>x</script>ok"]}'
    );
    const cleaned = sanitizeRecord(maliciousObj) as Record<string, unknown>;
    expect(cleaned.normal).toBe('safe');
    expect((cleaned as { nested: string[] }).nested[0]).toBe('ok');
    expect(Object.prototype.hasOwnProperty.call(cleaned, '__proto__')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(cleaned, 'constructor')).toBe(false);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('escapes nested sensitive location attributes and formula triggers', () => {
    const nested = {
      camera: 'Sony',
      location: {
        gpsLatitude: 51.5074,
        gpsLongitude: -0.1278,
        city: 'London'
      }
    };
    const redacted = redactSensitiveAttributes(nested, false) as {
      location: Record<string, unknown>;
    };
    expect(redacted.location.gpsLatitude).toContain('REDACTED');
    expect(redacted.location.city).toBe('London');
    expect(escapeCsvCell(null)).toBe('""');
    expect(escapeCsvCell('\t=1+1')).toBe('"\'\t=1+1"');
  });

  it('enforces sliding-window rate limits per key and calculates retryAfterSeconds', () => {
    const key = 'unit:test:bucket';
    expect(checkRateLimit(key, 3, 60_000).allowed).toBe(true);
    expect(checkRateLimit(key, 3, 60_000).allowed).toBe(true);
    const third = checkRateLimit(key, 3, 60_000);
    expect(third.allowed).toBe(true);
    expect(third.remaining).toBe(0);

    const fourth = checkRateLimit(key, 3, 60_000);
    expect(fourth.allowed).toBe(false);
    expect(fourth.retryAfterSeconds).toBeGreaterThan(0);

    // Separate bucket is unaffected
    expect(checkRateLimit('unit:other:bucket', 3, 60_000).allowed).toBe(true);
  });
});
