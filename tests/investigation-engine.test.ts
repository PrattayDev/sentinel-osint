import { describe, it, expect, beforeEach } from 'vitest';
import {
  createCaseForUser,
  createUserAccount,
  getCaseForUser,
  getInvestigationDetailsForUser,
  resetDatabaseForTest
} from '@/lib/db/repository';
import { executeUniversalInvestigation } from '@/lib/engine/orchestrator';
import { resetRateLimitsForTest } from '@/lib/security/rate-limiter';

describe('Universal Investigation Engine Orchestration & Persistence', () => {
  beforeEach(() => {
    resetDatabaseForTest();
    resetRateLimitsForTest();
  });

  it('executes phone numbering investigation, links to a Case, and persists provenance', async () => {
    const analyst = createUserAccount({
      email: 'engine-analyst@sentinel.local',
      password: 'AnalystPassword123!',
      fullName: 'Engine Analyst',
      acceptedEthicalTerms: true
    });

    const userCase = createCaseForUser(analyst.id, {
      title: 'Telecom Verification Case',
      description: 'Verify numbering plan metadata',
      scopeAndAuthorization: 'Authorized internal test'
    });

    const bundle = await executeUniversalInvestigation({
      userId: analyst.id,
      targetValue: '+44 20 7946 0958',
      targetType: 'phone',
      scope: 'Authorized test',
      purpose: 'Numbering plan check',
      caseId: userCase.id
    });

    expect(bundle.investigation.normalizedTarget).toBe('+442079460958');
    expect(bundle.investigation.status).toBe('completed');
    expect(bundle.findings.length).toBeGreaterThanOrEqual(2);
    expect(bundle.evidenceSources.length).toBeGreaterThanOrEqual(1);

    const persisted = getInvestigationDetailsForUser(
      bundle.investigation.id,
      analyst.id
    );
    expect(persisted).not.toBeNull();
    expect(persisted?.findings.length).toBe(bundle.findings.length);

    const updatedCase = getCaseForUser(userCase.id, analyst.id);
    expect(updatedCase?.investigationIds).toContain(bundle.investigation.id);
  });

  it('respects externalProviderConsent=false by skipping third-party network lookups', async () => {
    const analyst = createUserAccount({
      email: 'privacy-analyst@sentinel.local',
      password: 'AnalystPassword123!',
      fullName: 'Privacy Analyst',
      acceptedEthicalTerms: true
    });

    const bundle = await executeUniversalInvestigation({
      userId: analyst.id,
      targetValue: 'example.com',
      targetType: 'domain',
      scope: 'Local-only check',
      purpose: 'Test consent enforcement',
      externalProviderConsent: false
    });

    expect(
      bundle.providerExecutions.every((p) => p.status === 'unsupported')
    ).toBe(true);
    expect(bundle.findings.length).toBe(0);
  });
});
