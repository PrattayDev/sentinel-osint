import { NextRequest, NextResponse } from 'next/server';
import { getAuthenticatedUserFromRequest } from '@/lib/auth/session';
import {
  createReportRecordForUser,
  getCaseForUser,
  getInvestigationDetailsForUser
} from '@/lib/db/repository';
import {
  exportFindingsToCsv,
  exportInvestigationToJson,
  exportInvestigationToStix21,
  generatePdfReportBuffer
} from '@/lib/reports/exporter';

export async function GET(req: NextRequest) {
  const user = getAuthenticatedUserFromRequest(req);
  if (!user) {
    return NextResponse.json(
      { error: 'Authentication required' },
      { status: 401 }
    );
  }

  const { searchParams } = new URL(req.url);
  const investigationId = searchParams.get('id');
  const format = (searchParams.get('format') || 'json').toLowerCase();
  const classification = (searchParams.get('classification') || 'TLP:AMBER') as
    | 'TLP:CLEAR'
    | 'TLP:GREEN'
    | 'TLP:AMBER'
    | 'TLP:RED';
  const caseId = searchParams.get('caseId') || undefined;

  if (!investigationId) {
    return NextResponse.json(
      { error: 'Investigation id query parameter is required' },
      { status: 400 }
    );
  }

  const bundle = getInvestigationDetailsForUser(investigationId, user.id);
  if (!bundle) {
    return NextResponse.json(
      { error: 'Investigation not found or access denied' },
      { status: 404 }
    );
  }

  const caseRecord = caseId ? getCaseForUser(caseId, user.id) : null;

  createReportRecordForUser(user.id, {
    title: `Export (${format.toUpperCase()}): ${bundle.investigation.title}`,
    classification,
    executiveSummary: `${bundle.findings.length} findings across ${bundle.providerExecutions.length} providers for ${bundle.investigation.normalizedTarget}`,
    conclusions: `Exported in ${format.toUpperCase()} format by ${user.fullName}.`,
    caseId,
    investigationId: bundle.investigation.id
  });

  const safeSlug = bundle.investigation.normalizedTarget
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .slice(0, 48);

  if (format === 'csv') {
    const csv = exportFindingsToCsv(bundle);
    return new NextResponse(csv, {
      status: 200,
      headers: {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': `attachment; filename="sentinel-${safeSlug}.csv"`
      }
    });
  }

  if (format === 'stix') {
    const stix = exportInvestigationToStix21(bundle);
    return new NextResponse(stix, {
      status: 200,
      headers: {
        'Content-Type': 'application/stix+json; charset=utf-8',
        'Content-Disposition': `attachment; filename="sentinel-${safeSlug}-stix21.json"`
      }
    });
  }

  if (format === 'pdf') {
    const pdfBuf = generatePdfReportBuffer(bundle, {
      classification,
      caseRecord
    });
    return new NextResponse(new Uint8Array(pdfBuf), {
      status: 200,
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="sentinel-${safeSlug}-report.pdf"`
      }
    });
  }

  const json = exportInvestigationToJson(bundle, {
    classification,
    caseRecord
  });
  return new NextResponse(json, {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': `attachment; filename="sentinel-${safeSlug}-report.json"`
    }
  });
}
