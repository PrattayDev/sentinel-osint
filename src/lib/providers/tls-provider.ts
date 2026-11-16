import tls from 'tls';
import {
  DiscoveredEntityInput,
  DiscoveredRelationshipInput,
  InvestigationContext,
  NormalizedFindingInput,
  OsintProvider,
  ProviderResult
} from '@/types/osint';
import {
  validateAndNormalizeDomain,
  validateAndNormalizeUrl
} from '@/lib/validation/schemas';
import { validateSafeUrlAndResolve } from '@/lib/security/ssrf-guard';
import { sanitizeText } from '@/lib/security/sanitizer';

export interface TlsCertificateMetadata {
  hostname: string;
  subjectCommonName: string;
  subjectOrganization?: string;
  issuerCommonName: string;
  issuerOrganization?: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  serialNumber: string;
  fingerprint256: string;
  protocol: string;
  cipherName: string;
  subjectAltNames: string[];
  authorized: boolean;
}

function inspectRemoteTlsCertificate(
  hostname: string,
  connectHost = hostname,
  port = 443,
  timeoutMs = 5500
): Promise<TlsCertificateMetadata> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: connectHost,
        port,
        servername: hostname,
        rejectUnauthorized: false
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(false);
          const protocol = socket.getProtocol() || 'Unknown';
          const cipher = socket.getCipher();
          const authorized = socket.authorized;
          socket.end();

          if (!cert || Object.keys(cert).length === 0) {
            reject(new Error('No peer TLS certificate returned by host.'));
            return;
          }

          const validToDate = new Date(cert.valid_to);
          const daysRemaining = Math.floor(
            (validToDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24)
          );

          const sanRaw = cert.subjectaltname || '';
          const subjectAltNames = sanRaw
            .split(',')
            .map((part) => part.trim())
            .filter((part) => part.startsWith('DNS:'))
            .map((part) => part.replace(/^DNS:/, '').toLowerCase());

          resolve({
            hostname,
            subjectCommonName: sanitizeText(cert.subject?.CN || hostname, 128),
            subjectOrganization: sanitizeText(cert.subject?.O || '', 128) || undefined,
            issuerCommonName: sanitizeText(cert.issuer?.CN || 'Unknown Issuer', 128),
            issuerOrganization: sanitizeText(cert.issuer?.O || '', 128) || undefined,
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            daysRemaining,
            serialNumber: sanitizeText(cert.serialNumber, 128),
            fingerprint256: sanitizeText(cert.fingerprint256, 128),
            protocol,
            cipherName: cipher?.name || 'Unknown',
            subjectAltNames: Array.from(new Set(subjectAltNames)).slice(0, 40),
            authorized
          });
        } catch (err) {
          socket.destroy();
          reject(err);
        }
      }
    );

    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      reject(new Error(`TLS handshake timed out after ${timeoutMs}ms`));
    });

    socket.on('error', (err) => {
      socket.destroy();
      reject(err);
    });
  });
}

export class TlsCertificateProvider
  implements OsintProvider<string, TlsCertificateMetadata>
{
  id = 'tls-inspector';
  name = 'Direct SSL/TLS Handshake & Certificate Inspector';
  category = 'domain' as const;
  supportedTypes = ['domain' as const, 'url' as const];
  requiresApiKey = false;
  envVarNames: string[] = [];
  isFreeTierAvailable = true;
  rateLimitPerMinute = 30;
  disclosureNotice =
    'Performs a standard TLS client handshake on port 443 to inspect the public X.509 server certificate.';
  featureIds = ['DOM-05', 'DOM-14', 'WEB-05'];

  isConfigured(): boolean {
    return true;
  }

  validateInput(input: unknown): string {
    const raw = String(input || '').trim();
    if (/^https?:\/\//i.test(raw)) {
      const urlVal = validateAndNormalizeUrl(raw);
      if (!urlVal.valid) throw new Error(urlVal.error);
      return String(urlVal.metadata.hostname);
    }
    const domVal = validateAndNormalizeDomain(raw);
    if (!domVal.valid) throw new Error(domVal.error);
    return domVal.normalizedValue;
  }

  async execute(
    input: string,
    _context: InvestigationContext
  ): Promise<ProviderResult<TlsCertificateMetadata>> {
    const startMs = Date.now();
    const queryTimestamp = new Date().toISOString();
    const hostname = this.validateInput(input);

    try {
      // Enforce SSRF check on hostname and its DNS resolutions before opening TLS socket
      const validated = await validateSafeUrlAndResolve(`https://${hostname}`);
      const pinnedIp = validated.resolvedIps[0] || hostname;

      const certMeta = await inspectRemoteTlsCertificate(hostname, pinnedIp);
      const isExpired = certMeta.daysRemaining < 0;
      const isExpiringSoon = certMeta.daysRemaining >= 0 && certMeta.daysRemaining <= 14;

      const findings: NormalizedFindingInput[] = [
        {
          moduleCode: 'DOM-05',
          category: 'domain',
          title: `SSL/TLS Certificate (${certMeta.subjectCommonName} — ${certMeta.protocol})`,
          summary: `Issued by ${certMeta.issuerOrganization || certMeta.issuerCommonName}. Valid ${certMeta.validFrom} to ${certMeta.validTo} (${certMeta.daysRemaining} days remaining). Cipher: ${certMeta.cipherName}. SAN count: ${certMeta.subjectAltNames.length}.`,
          severity: isExpired ? 'high' : isExpiringSoon ? 'medium' : 'info',
          confidence: 'confirmed',
          tags: ['tls', 'certificate', 'x509', certMeta.protocol.toLowerCase()],
          attributes: {
            ...certMeta
          },
          sourceUrl: `https://${hostname}`
        }
      ];

      if (certMeta.subjectAltNames.length > 1) {
        findings.push({
          moduleCode: 'DOM-14',
          category: 'domain',
          title: `Certificate Subject Alternative Names (${certMeta.subjectAltNames.length} DNS names)`,
          summary: `Co-hosted or related domains on certificate: ${certMeta.subjectAltNames.slice(0, 12).join(', ')}.`,
          severity: 'info',
          confidence: 'confirmed',
          tags: ['san', 'related-domains', 'certificate'],
          attributes: {
            primaryHost: hostname,
            subjectAltNames: certMeta.subjectAltNames
          }
        });
      }

      const certKey = `cert:${certMeta.fingerprint256 || certMeta.serialNumber}`;
      const entities: DiscoveredEntityInput[] = [
        {
          key: `domain:${hostname}`,
          entityType: 'domain',
          label: hostname,
          value: hostname,
          confidence: 'confirmed'
        },
        {
          key: certKey,
          entityType: 'certificate',
          label: `Cert: ${certMeta.subjectCommonName}`,
          value: certMeta.fingerprint256 || certMeta.serialNumber,
          confidence: 'confirmed',
          metadata: {
            issuer: certMeta.issuerCommonName,
            validTo: certMeta.validTo,
            protocol: certMeta.protocol
          }
        }
      ];

      const relationships: DiscoveredRelationshipInput[] = [
        {
          sourceKey: `domain:${hostname}`,
          targetKey: certKey,
          relationshipType: 'presents_certificate',
          confidence: 'confirmed'
        }
      ];

      for (const san of certMeta.subjectAltNames
        .filter((s) => !s.startsWith('*.') && s !== hostname)
        .slice(0, 8)) {
        entities.push({
          key: `domain:${san}`,
          entityType: 'domain',
          label: san,
          value: san,
          confidence: 'high',
          metadata: { discoveredVia: 'tls_san' }
        });
        relationships.push({
          sourceKey: certKey,
          targetKey: `domain:${san}`,
          relationshipType: 'covers_san_domain',
          confidence: 'confirmed'
        });
      }

      const observedTimestamp = new Date().toISOString();
      return {
        providerId: this.id,
        providerName: this.name,
        status: 'completed',
        findings,
        entities,
        relationships,
        sourceReferences: [
          {
            providerId: this.id,
            providerName: this.name,
            sourceUrl: `https://${hostname}`,
            observedAt: observedTimestamp,
            queriedAt: queryTimestamp,
            confidence: 'confirmed',
            sensitivity: 'public',
            verificationStatus: 'verified',
            citationNote: `Direct TLS X.509 handshake on ${hostname}:443 (SHA-256: ${certMeta.fingerprint256})`
          }
        ],
        rawResult: certMeta,
        observedTimestamp,
        queryTimestamp,
        durationMs: Date.now() - startMs,
        errors: [],
        confidence: 'confirmed',
        sensitivity: 'public'
      };
    } catch (err) {
      return {
        providerId: this.id,
        providerName: this.name,
        status: 'partial',
        findings: [],
        entities: [],
        relationships: [],
        sourceReferences: [],
        observedTimestamp: new Date().toISOString(),
        queryTimestamp,
        durationMs: Date.now() - startMs,
        errors: [`TLS inspection skipped/failed: ${(err as Error).message}`],
        confidence: 'low',
        sensitivity: 'public'
      };
    }
  }
}
