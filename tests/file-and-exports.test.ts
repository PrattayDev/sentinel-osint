import { describe, it, expect } from 'vitest';
import {
  inspectUploadedFile,
  MAX_UPLOAD_SIZE_BYTES,
  validateUploadedFileBuffer
} from '@/lib/security/file-validator';
import { escapeCsvCell, redactSensitiveAttributes } from '@/lib/security/sanitizer';
import {
  exportFindingsToCsv,
  exportInvestigationToJson,
  exportInvestigationToStix21,
  generatePdfReportBuffer
} from '@/lib/reports/exporter';
import { ExecutedInvestigationBundle } from '@/lib/engine/orchestrator';

describe('File Upload Sandboxing, EXIF Redaction & Export Hardening', () => {
  it('accepts valid PNG/PDF magic bytes and rejects executables, scripts, and oversized buffers', () => {
    const validPdf = Buffer.from(
      '%PDF-1.7\n1 0 obj << /Title (Sentinel Evidence Document) /Author (SOC Analyst) /Type /Page >> endobj\n%%EOF',
      'utf8'
    );
    const pdfRes = inspectUploadedFile(validPdf, 'report.pdf');
    expect(pdfRes.detectedMime).toBe('application/pdf');
    expect(pdfRes.pdfMetadata?.title).toBe('Sentinel Evidence Document');
    expect(pdfRes.hashes.sha256).toHaveLength(64);
    expect(pdfRes.hashes.perceptualDHash).toHaveLength(16);

    // Reject Windows PE executable (MZ)
    const exeBuffer = Buffer.from('MZ\x90\x00\x03\x00\x00\x00', 'binary');
    expect(validateUploadedFileBuffer(exeBuffer, 'malware.exe').valid).toBe(false);

    // Reject HTML/script disguised as image
    const scriptBuf = Buffer.from('<script>alert(1)</script>', 'utf8');
    expect(validateUploadedFileBuffer(scriptBuf, 'photo.jpg').valid).toBe(false);

    // Reject oversized buffer (> 10 MB)
    const oversized = Buffer.alloc(MAX_UPLOAD_SIZE_BYTES + 1024, 0x41);
    expect(validateUploadedFileBuffer(oversized, 'huge.pdf').valid).toBe(false);
  });

  it('redacts sensitive GPS coordinates by default unless explicitly revealed', () => {
    const rawAttrs = {
      Make: 'Canon',
      gpsLatitude: 37.774929,
      gpsLongitude: -122.419416
    };

    const redacted = redactSensitiveAttributes(rawAttrs, false);
    expect(redacted.Make).toBe('Canon');
    expect(redacted.gpsLatitude).toContain('REDACTED');
    expect(redacted.gpsLongitude).toContain('REDACTED');

    const revealed = redactSensitiveAttributes(rawAttrs, true);
    expect(revealed.gpsLatitude).toBe(37.774929);
  });

  it('neutralizes CSV spreadsheet formula injection and generates valid JSON, STIX 2.1, and PDF exports', () => {
    expect(escapeCsvCell('=CMD|\' /C calc\'!A0')).toBe('"\'=CMD|\' /C calc\'!A0"');
    expect(escapeCsvCell('+SUM(A1:A10)')).toBe('"\'+SUM(A1:A10)"');
    expect(escapeCsvCell('-2+3')).toBe('"\'-2+3"');
    expect(escapeCsvCell('@IMPORTXML(...)')).toBe('"\'@IMPORTXML(...)"');
    expect(escapeCsvCell('   =HYPERLINK("http://evil")')).toBe(
      '"\'   =HYPERLINK(""http://evil"")"'
    );

    const mockBundle: ExecutedInvestigationBundle = {
      investigation: {
        id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
        workspaceId: '11111111-1111-4111-8111-111111111111',
        ownerId: '22222222-2222-4222-8222-222222222222',
        title: 'Domain: example.com',
        targetType: 'domain',
        targetValue: 'example.com',
        normalizedTarget: 'example.com',
        scope: 'Authorized defensive check',
        purpose: 'Verify export formats',
        externalProviderConsent: true,
        status: 'completed',
        tags: ['domain'],
        summary: {
          totalProviders: 1,
          completedProviders: 1,
          partialProviders: 0,
          notConfiguredProviders: 0,
          failedProviders: 0,
          totalFindings: 1,
          totalEntities: 1,
          totalRelationships: 0,
          highestSeverity: 'info'
        },
        createdAt: '2026-10-26T10:00:00.000Z',
        updatedAt: '2026-10-26T10:00:02.000Z',
        completedAt: '2026-10-26T10:00:02.000Z'
      },
      providerExecutions: [
        {
          id: '33333333-3333-4333-8333-333333333333',
          investigationId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
          ownerId: '22222222-2222-4222-8222-222222222222',
          providerId: 'dns-core',
          providerName: 'Authoritative DNS & DoH Analyzer',
          status: 'completed',
          durationMs: 120,
          findingsCount: 1,
          queriedAt: '2026-10-26T10:00:01.000Z',
          observedAt: '2026-10-26T10:00:01.000Z'
        }
      ],
      evidenceSources: [
        {
          id: '44444444-4444-4444-8444-444444444444',
          investigationId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
          ownerId: '22222222-2222-4222-8222-222222222222',
          providerId: 'dns-core',
          providerName: 'Authoritative DNS & DoH Analyzer',
          sourceUrl: 'https://cloudflare-dns.com/dns-query?name=example.com',
          observedAt: '2026-10-26T10:00:01.000Z',
          queriedAt: '2026-10-26T10:00:01.000Z',
          confidence: 'confirmed',
          sensitivity: 'public',
          verificationStatus: 'verified',
          bookmarked: false,
          citationNote: 'DNS citation',
          createdAt: '2026-10-26T10:00:01.000Z'
        }
      ],
      findings: [
        {
          id: '55555555-5555-4555-8555-555555555555',
          investigationId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
          ownerId: '22222222-2222-4222-8222-222222222222',
          providerId: 'dns-core',
          providerName: 'Authoritative DNS & DoH Analyzer',
          category: 'domain',
          moduleCode: 'DOM-02',
          title: '=MALICIOUS_TITLE_FORMULA',
          summary: 'Resolved A records for example.com',
          severity: 'info',
          confidence: 'confirmed',
          sensitivity: 'public',
          redactedByDefault: false,
          bookmarked: false,
          tags: ['dns'],
          attributes: {},
          sourceUrl: 'https://cloudflare-dns.com/dns-query?name=example.com',
          observedAt: '2026-10-26T10:00:01.000Z',
          queriedAt: '2026-10-26T10:00:01.000Z',
          createdAt: '2026-10-26T10:00:01.000Z'
        }
      ],
      entities: [
        {
          id: '66666666-6666-4666-8666-666666666666',
          investigationId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
          ownerId: '22222222-2222-4222-8222-222222222222',
          entityType: 'domain',
          label: 'example.com',
          value: 'example.com',
          confidence: 'confirmed',
          providerId: 'dns-core',
          metadata: {},
          observedAt: '2026-10-26T10:00:01.000Z',
          createdAt: '2026-10-26T10:00:01.000Z'
        }
      ],
      relationships: []
    };

    const jsonStr = exportInvestigationToJson(mockBundle);
    const parsedJson = JSON.parse(jsonStr);
    expect(parsedJson.reportMetadata.checksumSha256).toHaveLength(64);
    expect(parsedJson.evidenceReferences[0].sourceUrl).toBe(
      'https://cloudflare-dns.com/dns-query?name=example.com'
    );

    const csvStr = exportFindingsToCsv(mockBundle);
    expect(csvStr).toContain('"\'=MALICIOUS_TITLE_FORMULA"');

    const stixStr = exportInvestigationToStix21(mockBundle);
    const parsedStix = JSON.parse(stixStr);
    expect(parsedStix.type).toBe('bundle');
    expect(
      parsedStix.objects.some(
        (o: { pattern?: string }) =>
          o.pattern === "[domain-name:value = 'example.com']"
      )
    ).toBe(true);

    const pdfBuf = generatePdfReportBuffer(mockBundle);
    const pdfAscii = pdfBuf.toString('utf8');
    expect(pdfAscii.startsWith('%PDF-1.4')).toBe(true);
    expect(pdfAscii).toContain('https://cloudflare-dns.com/dns-query?name=example.com');
  });
});
