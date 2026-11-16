import { NextRequest, NextResponse } from 'next/server';
import {
  applySessionCookie,
  clearSessionCookie,
  extractSessionTokenFromRequest,
  getAuthenticatedUserFromRequest
} from '@/lib/auth/session';
import {
  authenticateUser,
  completePasswordReset,
  createPasswordResetToken,
  createUserAccount,
  deleteUserAccountAndData,
  getOrCreatePrimaryWorkspace,
  getUserRetentionPolicy,
  invalidateSessionToken,
  listUserAuditEvents,
  updateUserRetentionPolicy
} from '@/lib/db/repository';
import { checkRateLimit } from '@/lib/security/rate-limiter';

export async function GET(req: NextRequest) {
  const user = getAuthenticatedUserFromRequest(req);
  if (!user) {
    return NextResponse.json({ authenticated: false }, { status: 200 });
  }

  const workspace = getOrCreatePrimaryWorkspace(user.id);
  const retentionPolicy = getUserRetentionPolicy(user.id);
  const auditEvents = listUserAuditEvents(user.id, 30);

  return NextResponse.json({
    authenticated: true,
    user: {
      id: user.id,
      email: user.email,
      fullName: user.fullName,
      role: user.role,
      mfaEnabled: user.mfaEnabled,
      acceptedEthicalTerms: user.acceptedEthicalTerms,
      acceptedTermsAt: user.acceptedTermsAt,
      createdAt: user.createdAt
    },
    workspace,
    retentionPolicy,
    auditEvents
  });
}

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as Record<string, unknown>;
    const action = String(body.action || '');
    const clientIp =
      req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || '127.0.0.1';

    const rate = checkRateLimit(`auth:${clientIp}:${action}`, 25, 60_000);
    if (!rate.allowed) {
      return NextResponse.json(
        {
          error: `Too many authentication requests. Retry after ${rate.retryAfterSeconds}s.`
        },
        { status: 429 }
      );
    }

    if (action === 'register') {
      const email = String(body.email || '');
      const password = String(body.password || '');
      const fullName = String(body.fullName || '');
      const acceptedEthicalTerms = Boolean(body.acceptedEthicalTerms);

      // Note: role is NEVER trusted from client input
      const user = createUserAccount({
        email,
        password,
        fullName,
        acceptedEthicalTerms,
        role: 'analyst'
      });

      const { sessionToken } = authenticateUser(email, password);
      const res = NextResponse.json({
        authenticated: true,
        user: {
          id: user.id,
          email: user.email,
          fullName: user.fullName,
          role: user.role,
          acceptedEthicalTerms: user.acceptedEthicalTerms
        }
      });
      return applySessionCookie(res, sessionToken);
    }

    if (action === 'login') {
      const email = String(body.email || '');
      const password = String(body.password || '');

      const { user, sessionToken } = authenticateUser(email, password);
      const res = NextResponse.json({
        authenticated: true,
        user: {
          id: user.id,
          email: user.email,
          fullName: user.fullName,
          role: user.role,
          acceptedEthicalTerms: user.acceptedEthicalTerms
        }
      });
      return applySessionCookie(res, sessionToken);
    }

    if (action === 'logout') {
      const token = extractSessionTokenFromRequest(req);
      invalidateSessionToken(token);
      const res = NextResponse.json({ authenticated: false });
      return clearSessionCookie(res);
    }

    if (action === 'request_reset') {
      const email = String(body.email || '');
      const { resetToken, expiresAt } = createPasswordResetToken(email);
      const allowDevTokenSurface =
        (process.env.NODE_ENV === 'development' &&
          process.env.ENABLE_DEV_AUTH_SHORTCUT === 'true') ||
        process.env.NODE_ENV === 'test';
      return NextResponse.json({
        message:
          'If an account matches that email, a password reset token has been generated.',
        // Only surface raw reset token in explicit local dev shortcut or automated test mode
        devResetToken: allowDevTokenSurface ? resetToken : undefined,
        expiresAt
      });
    }

    if (action === 'complete_reset') {
      const token = String(body.token || '');
      const newPassword = String(body.newPassword || '');
      completePasswordReset(token, newPassword);
      return NextResponse.json({
        success: true,
        message: 'Password has been reset and all prior sessions invalidated.'
      });
    }

    if (action === 'delete_account') {
      const user = getAuthenticatedUserFromRequest(req);
      if (!user) {
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
      }
      deleteUserAccountAndData(user.id);
      const res = NextResponse.json({
        deleted: true,
        message: 'Account and all associated OSINT records have been permanently deleted.'
      });
      return clearSessionCookie(res);
    }

    if (action === 'update_retention') {
      const user = getAuthenticatedUserFromRequest(req);
      if (!user) {
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
      }
      const policy = updateUserRetentionPolicy(user.id, {
        investigationRetentionDays:
          typeof body.investigationRetentionDays === 'number'
            ? body.investigationRetentionDays
            : undefined,
        autoRedactSensitiveExif:
          typeof body.autoRedactSensitiveExif === 'boolean'
            ? body.autoRedactSensitiveExif
            : undefined
      });
      return NextResponse.json({ retentionPolicy: policy });
    }

    return NextResponse.json(
      { error: `Unsupported auth action: ${action}` },
      { status: 400 }
    );
  } catch (err) {
    return NextResponse.json(
      { error: (err as Error).message || 'Authentication error' },
      { status: 400 }
    );
  }
}
