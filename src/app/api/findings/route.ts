import { NextRequest, NextResponse } from 'next/server';
import { getAuthenticatedUserFromRequest } from '@/lib/auth/session';
import {
  listUserFindings,
  recordAuditEvent,
  toggleFindingBookmarkOrTags
} from '@/lib/db/repository';

export async function GET(req: NextRequest) {
  const user = getAuthenticatedUserFromRequest(req);
  if (!user) {
    return NextResponse.json(
      { error: 'Authentication required' },
      { status: 401 }
    );
  }

  return NextResponse.json({
    findings: listUserFindings(user.id)
  });
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
    const body = (await req.json()) as {
      findingId?: string;
      bookmarked?: boolean;
      tags?: string[];
      auditSensitiveReveal?: boolean;
    };

    if (!body.findingId) {
      return NextResponse.json(
        { error: 'findingId is required' },
        { status: 400 }
      );
    }

    if (body.auditSensitiveReveal) {
      recordAuditEvent({
        actorId: user.id,
        action: 'privacy.sensitive_metadata_revealed',
        resourceType: 'finding',
        resourceId: body.findingId,
        metadata: { reason: 'Explicit analyst action' }
      });
    }

    const updated = toggleFindingBookmarkOrTags(body.findingId, user.id, {
      bookmarked: body.bookmarked,
      tags: body.tags,
      revealSensitive: Boolean(body.auditSensitiveReveal)
    });

    if (!updated) {
      return NextResponse.json(
        { error: 'Finding not found or access denied' },
        { status: 404 }
      );
    }

    return NextResponse.json({ finding: updated });
  } catch (err) {
    return NextResponse.json(
      { error: (err as Error).message },
      { status: 400 }
    );
  }
}
