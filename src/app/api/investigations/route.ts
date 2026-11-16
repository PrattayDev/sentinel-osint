import { NextRequest, NextResponse } from 'next/server';
import { getAuthenticatedUserFromRequest } from '@/lib/auth/session';
import {
  deleteInvestigationForUser,
  getInvestigationDetailsForUser,
  listUserCases,
  listUserFindings,
  listUserGraphData,
  listUserInvestigations
} from '@/lib/db/repository';
import { CreateInvestigationSchema } from '@/lib/validation/schemas';
import { executeUniversalInvestigation } from '@/lib/engine/orchestrator';
import { checkRateLimit } from '@/lib/security/rate-limiter';

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

  if (investigationId) {
    const details = getInvestigationDetailsForUser(investigationId, user.id);
    if (!details) {
      return NextResponse.json(
        { error: 'Investigation not found or access denied' },
        { status: 404 }
      );
    }
    return NextResponse.json(details);
  }

  const investigations = listUserInvestigations(user.id);
  const findings = listUserFindings(user.id);
  const cases = listUserCases(user.id);
  const graph = listUserGraphData(user.id);

  return NextResponse.json({
    investigations,
    recentFindings: findings.slice(0, 50),
    cases,
    graph
  });
}

export async function POST(req: NextRequest) {
  const user = getAuthenticatedUserFromRequest(req);
  if (!user) {
    return NextResponse.json(
      { error: 'Authentication required' },
      { status: 401 }
    );
  }

  const rate = checkRateLimit(`user:${user.id}:investigations`, 30, 60_000);
  if (!rate.allowed) {
    return NextResponse.json(
      {
        error: `Investigation rate limit reached. Retry after ${rate.retryAfterSeconds}s.`
      },
      { status: 429 }
    );
  }

  try {
    const body = await req.json();
    const parsed = CreateInvestigationSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        {
          error:
            parsed.error.issues[0]?.message || 'Invalid investigation parameters'
        },
        { status: 400 }
      );
    }

    const bundle = await executeUniversalInvestigation({
      userId: user.id,
      targetValue: parsed.data.targetValue,
      targetType: parsed.data.targetType,
      title: parsed.data.title,
      scope: parsed.data.scope,
      purpose: parsed.data.purpose,
      externalProviderConsent: parsed.data.externalProviderConsent,
      caseId: parsed.data.caseId,
      tags: parsed.data.tags,
      existingInvestigationId:
        typeof body.existingInvestigationId === 'string'
          ? body.existingInvestigationId
          : undefined
    });

    return NextResponse.json(bundle, { status: 201 });
  } catch (err) {
    return NextResponse.json(
      { error: (err as Error).message || 'Investigation execution failed' },
      { status: 400 }
    );
  }
}

export async function DELETE(req: NextRequest) {
  const user = getAuthenticatedUserFromRequest(req);
  if (!user) {
    return NextResponse.json(
      { error: 'Authentication required' },
      { status: 401 }
    );
  }

  const { searchParams } = new URL(req.url);
  const id = searchParams.get('id');
  if (!id) {
    return NextResponse.json(
      { error: 'Investigation ID is required' },
      { status: 400 }
    );
  }

  try {
    const deleted = deleteInvestigationForUser(id, user.id);
    if (!deleted) {
      return NextResponse.json(
        { error: 'Investigation not found' },
        { status: 404 }
      );
    }
    return NextResponse.json({ deleted: true, id });
  } catch (err) {
    return NextResponse.json(
      { error: (err as Error).message },
      { status: 403 }
    );
  }
}
