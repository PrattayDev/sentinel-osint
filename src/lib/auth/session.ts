import { NextRequest, NextResponse } from 'next/server';
import { getUserBySessionToken } from '@/lib/db/repository';
import { UserProfile } from '@/types/osint';

export const SESSION_COOKIE_NAME = 'sentinel_session';

export function extractSessionTokenFromRequest(req: NextRequest): string | null {
  const cookieToken = req.cookies.get(SESSION_COOKIE_NAME)?.value;
  if (cookieToken) return cookieToken;

  const authHeader = req.headers.get('authorization');
  if (authHeader && authHeader.toLowerCase().startsWith('bearer ')) {
    return authHeader.slice(7).trim();
  }

  return null;
}

export function getAuthenticatedUserFromRequest(req: NextRequest): UserProfile | null {
  const token = extractSessionTokenFromRequest(req);
  if (!token) return null;
  return getUserBySessionToken(token);
}

export function applySessionCookie(
  res: NextResponse,
  sessionToken: string
): NextResponse {
  res.cookies.set({
    name: SESSION_COOKIE_NAME,
    value: sessionToken,
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: 7 * 24 * 60 * 60
  });
  return res;
}

export function clearSessionCookie(res: NextResponse): NextResponse {
  res.cookies.set({
    name: SESSION_COOKIE_NAME,
    value: '',
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: 0
  });
  return res;
}
