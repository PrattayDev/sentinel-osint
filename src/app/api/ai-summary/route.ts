import { NextRequest, NextResponse } from 'next/server';
import { getAuthenticatedUserFromRequest } from '@/lib/auth/session';
import { getInvestigationDetailsForUser, recordAuditEvent } from '@/lib/db/repository';
import { sanitizeText } from '@/lib/security/sanitizer';

export async function POST(req: NextRequest) {
  const user = getAuthenticatedUserFromRequest(req);
  if (!user) {
    return NextResponse.json(
      { error: 'Authentication required' },
      { status: 401 }
    );
  }

  try {
    const body = (await req.json()) as {
      investigationId?: string;
      consentToExternalAi?: boolean;
    };

    if (!body.investigationId) {
      return NextResponse.json(
        { error: 'investigationId is required' },
        { status: 400 }
      );
    }

    const bundle = getInvestigationDetailsForUser(
      body.investigationId,
      user.id
    );
    if (!bundle) {
      return NextResponse.json(
        { error: 'Investigation not found or access denied' },
        { status: 404 }
      );
    }

    const { investigation, findings, providerExecutions, relationships } = bundle;
    const incompleteProviders = providerExecutions.filter(
      (p) => p.status !== 'completed'
    );

    // Deterministic, zero-leakage local evidence synthesis (always available)
    const highSeverityFindings = findings.filter(
      (f) => f.severity === 'critical' || f.severity === 'high' || f.severity === 'medium'
    );

    const defensiveFollowUps: string[] = [];
    if (findings.some((f) => f.moduleCode === 'DOM-12' && f.severity !== 'info')) {
      defensiveFollowUps.push(
        'Review SPF (-all/~all) and DMARC (p=quarantine/reject) DNS TXT records to mitigate email spoofing risk.'
      );
    }
    if (findings.some((f) => f.moduleCode === 'DOM-11' && f.severity !== 'info')) {
      defensiveFollowUps.push(
        'Enforce missing HTTP security headers (Strict-Transport-Security, Content-Security-Policy, X-Frame-Options).'
      );
    }
    if (findings.some((f) => f.category === 'threat' && f.severity !== 'info')) {
      defensiveFollowUps.push(
        'Corroborate threat feed hits across multiple independent providers before blocking production infrastructure.'
      );
    }
    if (defensiveFollowUps.length === 0) {
      defensiveFollowUps.push(
        'Compare current DNS, RDAP, and certificate observations against your authorized asset baseline.'
      );
    }

    recordAuditEvent({
      actorId: user.id,
      action: 'analysis.defensive_summary_generated',
      resourceType: 'investigation',
      resourceId: investigation.id,
      metadata: {
        externalAiUsed: false,
        findingsEvaluated: findings.length
      }
    });

    return NextResponse.json({
      isAiInterpretation: true,
      mode: process.env.GEMINI_API_KEY && body.consentToExternalAi
        ? 'configured_ai_and_local_evidence_synthesis'
        : 'local_deterministic_evidence_synthesis',
      disclaimer:
        'AI/Automated Analysis Layer — This interpretation is derived strictly from collected finding records and MUST NOT replace primary source evidence.',
      target: sanitizeText(investigation.normalizedTarget, 160),
      verifiedFindingsSummary: `Evaluated ${findings.length} verified finding(s) and ${relationships.length} entity relationship(s) across ${providerExecutions.length} provider adapter(s).`,
      notableObservations:
        highSeverityFindings.length > 0
          ? highSeverityFindings.map(
              (f) => `[${f.moduleCode} / ${f.severity.toUpperCase()}] ${f.title}: ${f.summary}`
            )
          : findings
              .slice(0, 5)
              .map((f) => `[${f.moduleCode}] ${f.title}: ${f.summary}`),
      confidenceLimitations: [
        ...incompleteProviders.map(
          (p) =>
            `${p.providerName} status was "${p.status}" (${p.errorMessage || 'not executed'}); coverage from this source is incomplete.`
        ),
        'Coincidental username matches or coarse GeoIP routing estimates are not proof of personal attribution.'
      ],
      defensiveFollowUpQuestions: defensiveFollowUps
    });
  } catch (err) {
    return NextResponse.json(
      { error: (err as Error).message },
      { status: 400 }
    );
  }
}
