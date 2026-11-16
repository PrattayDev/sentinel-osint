import { describe, it, expect, beforeEach } from 'vitest';
import {
  authenticateUser,
  completePasswordReset,
  createCaseForUser,
  createPasswordResetToken,
  createUserAccount,
  deleteCaseForUser,
  deleteInvestigationForUser,
  getCaseForUser,
  getInvestigationDetailsForUser,
  getUserBySessionToken,
  invalidateSessionToken,
  resetDatabaseForTest,
  saveInvestigationBundle,
  updateCaseForUser
} from '@/lib/db/repository';

describe('Authentication, Session Lifecycle & Multi-Tenant Isolation', () => {
  beforeEach(() => {
    resetDatabaseForTest();
  });

  it('requires ethical-use acceptance and enforces scrypt password hashing + session invalidation on logout', () => {
    expect(() =>
      createUserAccount({
        email: 'unethical@example.com',
        password: 'StrongPassword123!',
        fullName: 'Bad Actor',
        acceptedEthicalTerms: false
      })
    ).toThrow(/Ethical-use terms/);

    const alice = createUserAccount({
      email: 'alice@sentinel.local',
      password: 'AliceSecretPassword99!',
      fullName: 'Alice Analyst',
      acceptedEthicalTerms: true
    });

    expect(alice.email).toBe('alice@sentinel.local');
    expect(alice.passwordHash).not.toBe('AliceSecretPassword99!');

    const { sessionToken } = authenticateUser(
      'alice@sentinel.local',
      'AliceSecretPassword99!'
    );
    expect(getUserBySessionToken(sessionToken)?.id).toBe(alice.id);

    invalidateSessionToken(sessionToken);
    expect(getUserBySessionToken(sessionToken)).toBeNull();
  });

  it('supports secure password reset workflow and invalidates prior sessions', () => {
    const user = createUserAccount({
      email: 'reset-user@sentinel.local',
      password: 'OldPassword123!',
      fullName: 'Reset User',
      acceptedEthicalTerms: true
    });

    const { sessionToken: oldSession } = authenticateUser(
      'reset-user@sentinel.local',
      'OldPassword123!'
    );

    const { resetToken } = createPasswordResetToken('reset-user@sentinel.local');
    expect(resetToken).toBeTruthy();

    completePasswordReset(resetToken!, 'NewSecurePassword456!');

    // Old session must be invalidated
    expect(getUserBySessionToken(oldSession)).toBeNull();

    // New password works
    const { user: loggedIn } = authenticateUser(
      'reset-user@sentinel.local',
      'NewSecurePassword456!'
    );
    expect(loggedIn.id).toBe(user.id);
  });

  it('strictly isolates cases and investigations between users (blocks cross-user IDOR)', () => {
    const alice = createUserAccount({
      email: 'alice@sentinel.local',
      password: 'AlicePassword123!',
      fullName: 'Alice',
      acceptedEthicalTerms: true
    });

    const bob = createUserAccount({
      email: 'bob@sentinel.local',
      password: 'BobPassword123!',
      fullName: 'Bob',
      acceptedEthicalTerms: true
    });

    const aliceCase = createCaseForUser(alice.id, {
      title: 'Alice Private Incident Case',
      description: 'Confidential defensive investigation',
      scopeAndAuthorization: 'Authorized SOC ticket #402'
    });

    // Bob cannot read, update, or delete Alice's case by ID
    expect(getCaseForUser(aliceCase.id, bob.id)).toBeNull();
    expect(() =>
      updateCaseForUser(aliceCase.id, bob.id, { title: 'Hacked Title' })
    ).toThrow(/FORBIDDEN/);
    expect(() => deleteCaseForUser(aliceCase.id, bob.id)).toThrow(/FORBIDDEN/);

    // Save an investigation for Alice
    saveInvestigationBundle({
      investigation: {
        id: '11111111-2222-4333-8444-555555555555',
        workspaceId: aliceCase.workspaceId,
        ownerId: alice.id,
        title: 'Domain: example.com',
        targetType: 'domain',
        targetValue: 'example.com',
        normalizedTarget: 'example.com',
        scope: 'Authorized',
        purpose: 'Test',
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
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      },
      providerExecutions: [],
      evidenceSources: [],
      findings: [],
      entities: [],
      relationships: []
    });

    // Bob cannot read or delete Alice's investigation
    expect(
      getInvestigationDetailsForUser(
        '11111111-2222-4333-8444-555555555555',
        bob.id
      )
    ).toBeNull();
    expect(() =>
      deleteInvestigationForUser(
        '11111111-2222-4333-8444-555555555555',
        bob.id
      )
    ).toThrow(/FORBIDDEN/);

    // Alice can read and delete her own investigation
    expect(
      getInvestigationDetailsForUser(
        '11111111-2222-4333-8444-555555555555',
        alice.id
      )
    ).not.toBeNull();
    expect(
      deleteInvestigationForUser(
        '11111111-2222-4333-8444-555555555555',
        alice.id
      )
    ).toBe(true);
  });
});
