import { describe, it, expect } from 'vitest';
import { AuthoritativeDnsProvider } from '@/lib/providers/dns-provider';
import { RdapRegistryProvider } from '@/lib/providers/rdap-provider';
import { TlsCertificateProvider } from '@/lib/providers/tls-provider';
import { CertificateTransparencyProvider } from '@/lib/providers/ct-provider';
import { SafeHttpSecurityProvider } from '@/lib/providers/http-provider';
import {
  RipeStatBgpProvider,
  SecurityTrailsDnsHistoryProvider,
  ShodanFullApiProvider,
  ShodanInternetDbProvider
} from '@/lib/providers/network-provider';
import {
  EmailIntelligenceProvider,
  HibpBreachProvider,
  PhoneNumberMetadataProvider,
  PublicProfileDiscoveryProvider
} from '@/lib/providers/identity-provider';
import {
  AbuseChThreatProvider,
  AbuseIpDbProvider,
  GoogleSafeBrowsingProvider,
  VirusTotalV3Provider
} from '@/lib/providers/threat-provider';
import {
  BraveWebSearchProvider,
  GleifOrganizationProvider,
  WaybackArchiveProvider
} from '@/lib/providers/org-and-archive-provider';
import {
  validateAndNormalizeFileHash,
  validateAndNormalizePhone
} from '@/lib/validation/schemas';

const testContext = {
  investigationId: '00000000-0000-4000-8000-000000000001',
  userId: '00000000-0000-4000-8000-000000000002',
  workspaceId: '00000000-0000-4000-8000-000000000003',
  scope: 'Automated unit/integration test',
  purpose: 'Defensive QA',
  externalConsent: true
};

describe('OSINT Provider Contracts & Live Lookup Verification', () => {
  it('resolves live DNS records and computes email security posture for example.com', async () => {
    const dnsProvider = new AuthoritativeDnsProvider();
    const res = await dnsProvider.execute('example.com', testContext);

    expect(res.providerId).toBe('dns-core');
    expect(['completed', 'partial']).toContain(res.status);
    expect(res.findings.length).toBeGreaterThanOrEqual(2);
    expect(res.entities.some((e) => e.value === 'example.com')).toBe(true);
    expect(res.sourceReferences.length).toBeGreaterThan(0);
  });

  it('evaluates email syntax, disposable detection, and returns not_configured for HIBP when key is absent', async () => {
    const emailProvider = new EmailIntelligenceProvider();
    const disposableRes = await emailProvider.execute(
      'security+alert@mailinator.com',
      testContext
    );

    expect(disposableRes.status).toBe('completed');
    const dispFinding = disposableRes.findings.find(
      (f) => f.moduleCode === 'ID-03'
    );
    expect(dispFinding?.attributes.isDisposable).toBe(true);

    const savedHibp = process.env.HIBP_API_KEY;
    delete process.env.HIBP_API_KEY;
    const hibp = new HibpBreachProvider();
    const hibpRes = await hibp.execute('analyst@example.com', testContext);
    expect(hibpRes.status).toBe('not_configured');
    if (savedHibp) process.env.HIBP_API_KEY = savedHibp;
  });

  it('validates ITU phone numbers locally via libphonenumber-js without subscriber lookup', async () => {
    const phoneProvider = new PhoneNumberMetadataProvider();
    const res = await phoneProvider.execute('+1 415 555 2671', testContext);

    expect(res.status).toBe('completed');
    expect(res.rawResult?.e164).toBe('+14155552671');
    expect(res.rawResult?.countryIso).toBe('US');
    expect(validateAndNormalizePhone('not-a-phone').valid).toBe(false);
  });

  it('validates hashes, reports not_configured for missing VT key, and classifies unknown hashes as UNKNOWN (never safe)', async () => {
    expect(
      validateAndNormalizeFileHash('d41d8cd98f00b204e9800998ecf8427e').valid
    ).toBe(true);
    expect(validateAndNormalizeFileHash('invalid-hash-123').valid).toBe(false);

    const savedVt = process.env.VIRUSTOTAL_API_KEY;
    delete process.env.VIRUSTOTAL_API_KEY;
    const vt = new VirusTotalV3Provider();
    const vtRes = await vt.execute(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      testContext
    );
    expect(vtRes.status).toBe('not_configured');
    if (savedVt) process.env.VIRUSTOTAL_API_KEY = savedVt;

    // Test unknown random SHA-256 hash against AbuseChThreatProvider
    const randomUnknownSha256 =
      '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';
    const abuseCh = new AbuseChThreatProvider();
    const hashRes = await abuseCh.execute(randomUnknownSha256, testContext);

    expect(hashRes.status).toBe('completed');
    const finding = hashRes.findings.find((f) => f.moduleCode === 'THR-01');
    expect(finding).toBeDefined();
    expect(finding?.attributes.verdict).toBe('unknown');
    expect(finding?.attributes.isClassifiedSafe).toBe(false);
  });

  it('verifies live RDAP, TLS handshake (pinned IP), Certificate Transparency, and HTTP security headers on example.com', async () => {
    const rdap = new RdapRegistryProvider();
    const rdapRes = await rdap.execute('example.com', testContext);
    expect(['completed', 'partial']).toContain(rdapRes.status);
    if (rdapRes.status === 'completed') {
      expect(rdapRes.findings.some((f) => f.moduleCode === 'DOM-04')).toBe(true);
    }

    const tlsProv = new TlsCertificateProvider();
    const tlsRes = await tlsProv.execute('example.com', testContext);
    expect(tlsRes.status).toBe('completed');
    expect(tlsRes.findings.some((f) => f.moduleCode === 'DOM-05')).toBe(true);
    expect(tlsRes.rawResult?.protocol).toContain('TLS');

    const ctProv = new CertificateTransparencyProvider();
    const ctRes = await ctProv.execute('example.com', testContext);
    expect(['completed', 'partial']).toContain(ctRes.status);

    const httpProv = new SafeHttpSecurityProvider();
    const httpRes = await httpProv.execute('https://example.com', testContext);
    expect(httpRes.status).toBe('completed');
    expect(httpRes.findings.some((f) => f.moduleCode === 'WEB-02')).toBe(true);
    expect(httpRes.findings.some((f) => f.moduleCode === 'DOM-11')).toBe(true);
  }, 25000);

  it('verifies live IP BGP/ASN (RIPEstat), Shodan InternetDB, Public Profiles, Wayback, GLEIF, and all 7 missing-key statuses', async () => {
    const ripe = new RipeStatBgpProvider();
    const ripeRes = await ripe.execute('1.1.1.1', testContext);
    expect(ripeRes.status).toBe('completed');
    expect(ripeRes.findings.some((f) => f.moduleCode === 'NET-03')).toBe(true);

    const shodanIdb = new ShodanInternetDbProvider();
    const idbRes = await shodanIdb.execute('1.1.1.1', testContext);
    expect(idbRes.status).toBe('completed');
    expect(idbRes.findings.some((f) => f.moduleCode === 'NET-09')).toBe(true);

    const social = new PublicProfileDiscoveryProvider();
    const socRes = await social.execute('torvalds', testContext);
    expect(['completed', 'partial']).toContain(socRes.status);

    const wayback = new WaybackArchiveProvider();
    const wbRes = await wayback.execute('example.com', testContext);
    expect(['completed', 'partial']).toContain(wbRes.status);

    const gleif = new GleifOrganizationProvider();
    const gleifRes = await gleif.execute('Cloudflare', testContext);
    expect(['completed', 'partial']).toContain(gleifRes.status);

    // Verify all remaining keyed providers report not_configured when keys are absent
    const abuseIp = new AbuseIpDbProvider();
    expect((await abuseIp.execute('1.1.1.1', testContext)).status).toBe('not_configured');

    const shodanFull = new ShodanFullApiProvider();
    expect((await shodanFull.execute('1.1.1.1', testContext)).status).toBe('not_configured');

    const secTrails = new SecurityTrailsDnsHistoryProvider();
    expect((await secTrails.execute('example.com', testContext)).status).toBe('not_configured');

    const gsb = new GoogleSafeBrowsingProvider();
    expect((await gsb.execute('https://example.com', testContext)).status).toBe('not_configured');

    const brave = new BraveWebSearchProvider();
    expect((await brave.execute('example.com', testContext)).status).toBe('not_configured');
  }, 25000);
});
