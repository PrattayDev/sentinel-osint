import { describe, it, expect, beforeEach } from 'vitest';
import { NextRequest } from 'next/server';
import { POST as postAuth, GET as getAuth } from '@/app/api/auth/route';
import { POST as postAiSummary } from '@/app/api/ai-summary/route';
import { GET as getFindings, PATCH as patchFinding } from '@/app/api/findings/route';
import { GET as getProviders } from '@/app/api/providers/route';
import { executeUniversalInvestigation } from '@/lib/engine/orchestrator';
import {
  authenticateUser,
  createUserAccount,
  getUserBySessionToken,
  invalidateSessionToken,
  resetDatabaseForTest
} from '@/lib/db/repository';
import { resetRateLimitsForTest } from '@/lib/security/rate-limiter';
import {
  computeHammingDistanceHex,
  computePerceptualDHash
} from '@/lib/security/file-validator';

describe('Bug Regression & Edge Case Verification Suite', () => {
  beforeEach(() => {
    resetDatabaseForTest();
    resetRateLimitsForTest();
  });

  it('rehydrates HMAC-signed session tokens across serverless cold starts while rejecting tampered or logged-out tokens', () => {
    const user = createUserAccount({
      email: 'serverless@sentinel.local',
      password: 'ServerlessStrongPassword#2026!',
      fullName: 'Serverless Analyst',
      acceptedEthicalTerms: true
    });
    const { sessionToken } = authenticateUser(
      'serverless@sentinel.local',
      'ServerlessStrongPassword#2026!'
    );
    expect(sessionToken.startsWith('st2.')).toBe(true);

    // Simulate a Vercel serverless cold start on a new lambda instance where memoryDb is fresh
    resetDatabaseForTest();

    // Valid signed token seamlessly rehydrates user profile on the new instance
    const rehydrated = getUserBySessionToken(sessionToken);
    expect(rehydrated).not.toBeNull();
    expect(rehydrated?.id).toBe(user.id);
    expect(rehydrated?.email).toBe('serverless@sentinel.local');

    // Tampered token signature must be strictly rejected
    const tampered = sessionToken.slice(0, -4) + 'XXXX';
    expect(getUserBySessionToken(tampered)).toBeNull();

    // Explicit logout revokes the token immediately
    invalidateSessionToken(sessionToken);
    expect(getUserBySessionToken(sessionToken)).toBeNull();
  });

  it('verifies /api/providers, /api/findings bookmark/tag updates, and /api/ai-summary synthesis with tenant isolation', async () => {
    // 1. Unauthenticated /api/providers returns 401
    const unauthProv = await getProviders(
      new NextRequest('http://localhost:3000/api/providers')
    );
    expect(unauthProv.status).toBe(401);

    // 2. Register Analyst 1 and Analyst 2
    const reg1 = await postAuth(
      new NextRequest('http://localhost:3000/api/auth', {
        method: 'POST',
        body: JSON.stringify({
          action: 'register',
          fullName: 'Analyst One',
          email: 'one@sentinel.local',
          password: 'PasswordOneStrong#2026!',
          acceptedEthicalTerms: true
        })
      })
    );
    const token1 = reg1.cookies.get('sentinel_session')?.value!;
    const user1Id = (await reg1.json()).user.id;

    const reg2 = await postAuth(
      new NextRequest('http://localhost:3000/api/auth', {
        method: 'POST',
        body: JSON.stringify({
          action: 'register',
          fullName: 'Analyst Two',
          email: 'two@sentinel.local',
          password: 'PasswordTwoStrong#2026!',
          acceptedEthicalTerms: true
        })
      })
    );
    const token2 = reg2.cookies.get('sentinel_session')?.value!;

    // 3. Authenticated /api/providers returns all 21 providers
    const authProv = await getProviders(
      new NextRequest('http://localhost:3000/api/providers', {
        headers: { Authorization: `Bearer ${token1}` }
      })
    );
    expect(authProv.status).toBe(200);
    const provData = await authProv.json();
    expect(provData.providers).toHaveLength(21);

    // 4. Run local phone investigation for Analyst 1
    const bundle = await executeUniversalInvestigation({
      userId: user1Id,
      targetValue: '+14155552671',
      targetType: 'phone',
      scope: 'Authorized defensive test',
      purpose: 'Bug regression check',
      externalProviderConsent: false
    });
    const findingId = bundle.findings[0].id;

    // 5. Analyst 1 bookmarks and tags finding via PATCH /api/findings
    const patchRes = await patchFinding(
      new NextRequest('http://localhost:3000/api/findings', {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${token1}` },
        body: JSON.stringify({
          findingId,
          bookmarked: true,
          tags: ['verified-phone', '<script>xss</script>clean-tag']
        })
      })
    );
    expect(patchRes.status).toBe(200);
    const patchedFinding = (await patchRes.json()).finding;
    expect(patchedFinding.bookmarked).toBe(true);
    expect(patchedFinding.tags).toContain('clean-tag');

    // 6. Analyst 2 cannot mutate Analyst 1's finding (returns 404)
    const crossPatch = await patchFinding(
      new NextRequest('http://localhost:3000/api/findings', {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${token2}` },
        body: JSON.stringify({
          findingId,
          bookmarked: false
        })
      })
    );
    expect(crossPatch.status).toBe(404);

    // 7. Analyst 1 generates Defensive AI Summary via POST /api/ai-summary
    const aiRes = await postAiSummary(
      new NextRequest('http://localhost:3000/api/ai-summary', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token1}` },
        body: JSON.stringify({
          investigationId: bundle.investigation.id,
          consentToExternalAi: false
        })
      })
    );
    expect(aiRes.status).toBe(200);
    const aiData = await aiRes.json();
    expect(aiData.isAiInterpretation).toBe(true);
    expect(aiData.defensiveFollowUpQuestions.length).toBeGreaterThan(0);

    // 8. Analyst 2 cannot generate AI summary for Analyst 1's investigation (returns 404)
    const crossAi = await postAiSummary(
      new NextRequest('http://localhost:3000/api/ai-summary', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token2}` },
        body: JSON.stringify({
          investigationId: bundle.investigation.id
        })
      })
    );
    expect(crossAi.status).toBe(404);
  });

  it('supports retention policy updates and hard account deletion with cascading cleanup', async () => {
    const reg = await postAuth(
      new NextRequest('http://localhost:3000/api/auth', {
        method: 'POST',
        body: JSON.stringify({
          action: 'register',
          fullName: 'Temp Analyst',
          email: 'temp@sentinel.local',
          password: 'TempPasswordStrong#2026!',
          acceptedEthicalTerms: true
        })
      })
    );
    const token = reg.cookies.get('sentinel_session')?.value!;
    const userId = (await reg.json()).user.id;

    await executeUniversalInvestigation({
      userId,
      targetValue: '+14155552671',
      targetType: 'phone',
      scope: 'Retention test',
      purpose: 'Cascade delete test',
      externalProviderConsent: false
    });

    // Update retention policy
    const retRes = await postAuth(
      new NextRequest('http://localhost:3000/api/auth', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          action: 'update_retention',
          investigationRetentionDays: 30,
          autoRedactSensitiveExif: true
        })
      })
    );
    expect(retRes.status).toBe(200);
    expect((await retRes.json()).retentionPolicy.investigationRetentionDays).toBe(30);

    // Hard delete account
    const delRes = await postAuth(
      new NextRequest('http://localhost:3000/api/auth', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: JSON.stringify({ action: 'delete_account' })
      })
    );
    expect(delRes.status).toBe(200);

    // Token is now revoked and findings are purged
    const afterAuth = await getAuth(
      new NextRequest('http://localhost:3000/api/auth', {
        headers: { Authorization: `Bearer ${token}` }
      })
    );
    expect((await afterAuth.json()).authenticated).toBe(false);

    const afterFindings = await getFindings(
      new NextRequest('http://localhost:3000/api/findings', {
        headers: { Authorization: `Bearer ${token}` }
      })
    );
    expect(afterFindings.status).toBe(401);
  });

  it('computes deterministic perceptual dHash and Hamming distance for duplicate detection', () => {
    const bufA = Buffer.alloc(1024, 0x3c);
    const bufB = Buffer.alloc(1024, 0x3c);
    const hashA = computePerceptualDHash(bufA);
    const hashB = computePerceptualDHash(bufB);
    expect(hashA).toHaveLength(16);
    expect(computeHammingDistanceHex(hashA, hashB)).toBe(0);
    expect(computeHammingDistanceHex('0000000000000000', '000000000000000f')).toBe(4);
  });
});
