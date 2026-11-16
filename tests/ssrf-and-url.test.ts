import { describe, it, expect } from 'vitest';
import {
  classifyIpAddress,
  isBlockedHostname,
  isBlockedIpAddress,
  validateSafeUrlAndResolve
} from '@/lib/security/ssrf-guard';
import {
  validateAndNormalizeDomain,
  validateAndNormalizeIp,
  validateAndNormalizeUrl
} from '@/lib/validation/schemas';

describe('SSRF Guard & URL/IP Security Defenses', () => {
  it('allows valid public IPv4 and IPv6 addresses', () => {
    expect(classifyIpAddress('93.184.216.34').isPublic).toBe(true);
    expect(classifyIpAddress('8.8.8.8').isBlocked).toBe(false);
    expect(classifyIpAddress('2606:4700:4700::1111').isPublic).toBe(true);
    expect(classifyIpAddress('2606:4700:4700::1111').isBlocked).toBe(false);
  });

  it('blocks localhost, loopback, RFC1918 private, link-local, CGNAT, and cloud metadata IPs', () => {
    expect(isBlockedIpAddress('127.0.0.1')).toBe(true);
    expect(isBlockedIpAddress('127.0.1.1')).toBe(true);
    expect(isBlockedIpAddress('0.0.0.0')).toBe(true);
    expect(isBlockedIpAddress('10.0.0.1')).toBe(true);
    expect(isBlockedIpAddress('172.16.0.1')).toBe(true);
    expect(isBlockedIpAddress('172.31.255.254')).toBe(true);
    expect(isBlockedIpAddress('192.168.1.1')).toBe(true);
    expect(isBlockedIpAddress('100.64.0.1')).toBe(true);
    expect(isBlockedIpAddress('169.254.169.254')).toBe(true); // AWS/GCP/Azure metadata
    expect(isBlockedIpAddress('::1')).toBe(true);
    expect(isBlockedIpAddress('::')).toBe(true);
    expect(isBlockedIpAddress('fe80::1')).toBe(true);
    expect(isBlockedIpAddress('fc00::1')).toBe(true);
    expect(isBlockedIpAddress('fd12:3456:789a::1')).toBe(true);
  });

  it('blocks IPv4-mapped IPv6 bypass attempts (::ffff:127.0.0.1 and ::ffff:169.254.169.254)', () => {
    expect(isBlockedIpAddress('::ffff:127.0.0.1')).toBe(true);
    expect(isBlockedIpAddress('::ffff:10.0.0.1')).toBe(true);
    expect(isBlockedIpAddress('::ffff:169.254.169.254')).toBe(true);
  });

  it('blocks internal hostnames and numeric/octal IP obfuscation', () => {
    expect(isBlockedHostname('localhost').blocked).toBe(true);
    expect(isBlockedHostname('sub.localhost').blocked).toBe(true);
    expect(isBlockedHostname('metadata.google.internal').blocked).toBe(true);
    expect(isBlockedHostname('printer.local').blocked).toBe(true);
    expect(isBlockedHostname('2130706433').blocked).toBe(true); // integer 127.0.0.1
    expect(isBlockedHostname('0x7f000001').blocked).toBe(true); // hex 127.0.0.1
    expect(isBlockedHostname('0177.0.0.1').blocked).toBe(true); // octal 127.0.0.1
  });

  it('rejects private/internal IPs from external OSINT validation', () => {
    expect(validateAndNormalizeIp('192.168.1.50').valid).toBe(false);
    expect(validateAndNormalizeIp('169.254.169.254').valid).toBe(false);
    expect(validateAndNormalizeIp('not-an-ip').valid).toBe(false);
    expect(validateAndNormalizeIp('1.1.1.1').valid).toBe(true);
  });

  it('rejects unsafe URL protocols, embedded credentials, and non-standard ports', async () => {
    await expect(validateSafeUrlAndResolve('file:///etc/passwd')).rejects.toThrow(
      /SSRF_GUARD/
    );
    await expect(validateSafeUrlAndResolve('ftp://example.com/file')).rejects.toThrow(
      /SSRF_GUARD/
    );
    await expect(
      validateSafeUrlAndResolve('http://admin:secret@example.com/')
    ).rejects.toThrow(/SSRF_GUARD/);
    await expect(
      validateSafeUrlAndResolve('http://example.com:22/')
    ).rejects.toThrow(/SSRF_GUARD/);
    await expect(
      validateSafeUrlAndResolve('http://127.0.0.1/admin')
    ).rejects.toThrow(/SSRF_GUARD/);
    await expect(
      validateSafeUrlAndResolve('http://169.254.169.254/latest/meta-data/')
    ).rejects.toThrow(/SSRF_GUARD/);
    await expect(
      validateSafeUrlAndResolve('http://localhost:3000/api')
    ).rejects.toThrow(/SSRF_GUARD/);
  });

  it('normalizes internationalized domains (IDNA/Punycode) safely and rejects invalid domains', () => {
    const idn = validateAndNormalizeDomain('münchen.de');
    expect(idn.valid).toBe(true);
    expect(idn.normalizedValue).toBe('xn--mnchen-3ya.de');
    expect(idn.metadata.isInternationalized).toBe(true);

    expect(validateAndNormalizeDomain('invalid domain with spaces.com').valid).toBe(
      false
    );
    expect(validateAndNormalizeDomain('http://example.com').valid).toBe(false);
    expect(validateAndNormalizeDomain('127.0.0.1').valid).toBe(false);
    expect(validateAndNormalizeDomain('localhost').valid).toBe(false);
    expect(validateAndNormalizeUrl('https://example.com/path').valid).toBe(true);
  });
});
