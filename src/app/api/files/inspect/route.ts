import { NextRequest, NextResponse } from 'next/server';
import { getAuthenticatedUserFromRequest } from '@/lib/auth/session';
import {
  computeHammingDistanceHex,
  inspectUploadedFile,
  MAX_UPLOAD_SIZE_BYTES,
  validateUploadedFileBuffer
} from '@/lib/security/file-validator';
import { executeUniversalInvestigation } from '@/lib/engine/orchestrator';
import { listUserFindings } from '@/lib/db/repository';
import { checkRateLimit } from '@/lib/security/rate-limiter';

export async function POST(req: NextRequest) {
  const user = getAuthenticatedUserFromRequest(req);
  if (!user) {
    return NextResponse.json(
      { error: 'Authentication required' },
      { status: 401 }
    );
  }

  const rate = checkRateLimit(`user:${user.id}:file_upload`, 15, 60_000);
  if (!rate.allowed) {
    return NextResponse.json(
      {
        error: `File inspection rate limit reached. Retry after ${rate.retryAfterSeconds}s.`
      },
      { status: 429 }
    );
  }

  try {
    const formData = await req.formData();
    const file = formData.get('file') as File | null;
    const scope = String(
      formData.get('scope') || 'Authorized local media/document forensic inspection'
    );
    const purpose = String(
      formData.get('purpose') || 'Metadata, EXIF, PDF & cryptographic hash verification'
    );
    const caseId = formData.get('caseId') ? String(formData.get('caseId')) : undefined;

    if (!file) {
      return NextResponse.json(
        { error: 'No file provided in multipart form upload.' },
        { status: 400 }
      );
    }

    if (file.size > MAX_UPLOAD_SIZE_BYTES) {
      return NextResponse.json(
        {
          error: `File size (${file.size} bytes) exceeds 10 MB maximum upload limit.`
        },
        { status: 400 }
      );
    }

    const arrayBuf = await file.arrayBuffer();
    const buffer = Buffer.from(arrayBuf);

    const sig = validateUploadedFileBuffer(buffer, file.name);
    if (!sig.valid) {
      return NextResponse.json(
        { error: sig.error || 'Unsupported or unsafe file type.' },
        { status: 400 }
      );
    }

    const previewReport = inspectUploadedFile(buffer, file.name);

    // Check duplicate media across user's existing workspace findings (IMG-10)
    const priorFindings = listUserFindings(user.id).filter(
      (f) => f.moduleCode === 'IMG-02'
    );
    const duplicateMatches: Array<{
      findingId: string;
      fileName: string;
      matchType: 'exact_sha256' | 'near_perceptual_dhash';
      hammingDistance: number;
    }> = [];

    for (const pf of priorFindings) {
      const priorSha256 = String(pf.attributes.sha256 || '');
      const priorDHash = String(pf.attributes.perceptualDHash || '');
      const priorName = String(pf.attributes.fileName || 'prior_upload');

      if (priorSha256 && priorSha256 === previewReport.hashes.sha256) {
        duplicateMatches.push({
          findingId: pf.id,
          fileName: priorName,
          matchType: 'exact_sha256',
          hammingDistance: 0
        });
      } else if (priorDHash && priorDHash.length === 16) {
        const dist = computeHammingDistanceHex(
          priorDHash,
          previewReport.hashes.perceptualDHash
        );
        if (dist <= 6) {
          duplicateMatches.push({
            findingId: pf.id,
            fileName: priorName,
            matchType: 'near_perceptual_dhash',
            hammingDistance: dist
          });
        }
      }
    }

    const bundle = await executeUniversalInvestigation({
      userId: user.id,
      targetValue: file.name,
      targetType: 'file',
      title: `File Inspection: ${file.name}`,
      scope,
      purpose,
      externalProviderConsent: false, // File inspection is 100% local by default
      caseId,
      fileBuffer: buffer,
      fileName: file.name,
      mimeType: sig.detectedMime
    });

    return NextResponse.json({
      bundle,
      fileReport: {
        ...previewReport,
        gpsMetadata: {
          hasGps: previewReport.gpsMetadata.hasGps,
          redactedByDefault: true,
          // Never expose raw GPS coordinates in the default upload response
          redactedCoordinates: previewReport.gpsMetadata.hasGps
            ? '[REDACTED — Click Reveal Sensitive Metadata (Audited) on Finding IMG-09 to Unlock]'
            : null
        },
        duplicateMatches
      }
    });
  } catch (err) {
    return NextResponse.json(
      { error: (err as Error).message || 'File inspection failed' },
      { status: 400 }
    );
  }
}
