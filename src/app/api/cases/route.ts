import { NextRequest, NextResponse } from 'next/server';
import { getAuthenticatedUserFromRequest } from '@/lib/auth/session';
import {
  createCaseForUser,
  deleteCaseForUser,
  getCaseForUser,
  listUserCases,
  updateCaseForUser
} from '@/lib/db/repository';
import { CreateCaseSchema } from '@/lib/validation/schemas';

export async function GET(req: NextRequest) {
  const user = getAuthenticatedUserFromRequest(req);
  if (!user) {
    return NextResponse.json(
      { error: 'Authentication required' },
      { status: 401 }
    );
  }

  const { searchParams } = new URL(req.url);
  const caseId = searchParams.get('id');

  if (caseId) {
    const c = getCaseForUser(caseId, user.id);
    if (!c) {
      return NextResponse.json(
        { error: 'Case not found or access denied' },
        { status: 404 }
      );
    }
    return NextResponse.json({ case: c });
  }

  return NextResponse.json({
    cases: listUserCases(user.id)
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

  try {
    const body = await req.json();
    const parsed = CreateCaseSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { error: parsed.error.issues[0]?.message || 'Invalid case data' },
        { status: 400 }
      );
    }

    const created = createCaseForUser(user.id, parsed.data);
    return NextResponse.json({ case: created }, { status: 201 });
  } catch (err) {
    return NextResponse.json(
      { error: (err as Error).message || 'Failed to create case' },
      { status: 400 }
    );
  }
}

export async function PATCH(req: NextRequest) {
  const user = getAuthenticatedUserFromRequest(req);
  if (!user) {
    return NextResponse.json(
      { error: 'Authentication required' },
      { status: 401 }
    );
  }

  try {
    const body = (await req.json()) as Record<string, unknown>;
    const caseId = String(body.caseId || '');
    if (!caseId) {
      return NextResponse.json(
        { error: 'caseId is required' },
        { status: 400 }
      );
    }

    const updated = updateCaseForUser(caseId, user.id, {
      title: typeof body.title === 'string' ? body.title : undefined,
      description:
        typeof body.description === 'string' ? body.description : undefined,
      scopeAndAuthorization:
        typeof body.scopeAndAuthorization === 'string'
          ? body.scopeAndAuthorization
          : undefined,
      status:
        typeof body.status === 'string'
          ? (body.status as 'draft' | 'active' | 'completed' | 'archived')
          : undefined,
      priority:
        typeof body.priority === 'string'
          ? (body.priority as 'low' | 'medium' | 'high' | 'critical')
          : undefined,
      tags: Array.isArray(body.tags) ? body.tags.map(String) : undefined,
      addNote:
        typeof body.noteContent === 'string' && body.noteContent.trim()
          ? { content: body.noteContent, authorName: user.fullName }
          : undefined,
      linkInvestigationId:
        typeof body.linkInvestigationId === 'string'
          ? body.linkInvestigationId
          : undefined
    });

    if (!updated) {
      return NextResponse.json({ error: 'Case not found' }, { status: 404 });
    }
    return NextResponse.json({ case: updated });
  } catch (err) {
    return NextResponse.json(
      { error: (err as Error).message },
      { status: 403 }
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
    return NextResponse.json({ error: 'Case id is required' }, { status: 400 });
  }

  try {
    const deleted = deleteCaseForUser(id, user.id);
    if (!deleted) {
      return NextResponse.json({ error: 'Case not found' }, { status: 404 });
    }
    return NextResponse.json({ deleted: true, id });
  } catch (err) {
    return NextResponse.json(
      { error: (err as Error).message },
      { status: 403 }
    );
  }
}
