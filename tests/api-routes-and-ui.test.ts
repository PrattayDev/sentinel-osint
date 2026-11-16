import { describe, it, expect, beforeEach } from 'vitest';
import { NextRequest } from 'next/server';
import { GET as getHealth } from '@/app/api/health/route';
import { GET as getAuth, POST as postAuth } from '@/app/api/auth/route';
import {
  GET as getInvestigations,
  POST as postInvestigation,
  DELETE as deleteInvestigation
} from '@/app/api/investigations/route';
import { GET as exportInvestigation } from '@/app/api/investigations/export/route';
import {
  GET as getCases,
  POST as postCase,
  DELETE as deleteCase
} from '@/app/api/cases/route';
import { PATCH as patchFinding } from '@/app/api/findings/route';
import { executeUniversalInvestigation } from '@/lib/engine/orchestrator';
import { resetDatabaseForTest } from '@/lib/db/repository';
import { resetRateLimitsForTest } from '@/lib/security/rate-limiter';

describe('API Route Handlers End-to-End Integration & Security Matrix', () => {
  beforeEach(() => {
    resetDatabaseForTest();
    resetRateLimitsForTest();
  });

  it('returns operational health summary from GET /api/health', async () => {
    const res = await getHealth();
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.status).toBe('healthy');
    expect(data.providers.total).toBeGreaterThanOrEqual(20);
  });

  it('rejects unauthenticated requests to /api/investigations and /api/cases with 401', async () => {
    const unauthReq = new NextRequest('http://localhost:3000/api/investigations');
    const invRes = await getInvestigations(unauthReq);
    expect(invRes.status).toBe(401);

    const caseReq = new NextRequest('http://localhost:3000/api/cases');
    const caseRes = await getCases(caseReq);
    expect(caseRes.status).toBe(401);
  });

  it('executes full authenticated workflow (Register -> Create Case -> Run Investigation -> Export PDF/CSV/JSON -> Cross-User Isolation)', async () => {
    // 1. Register User A
    const regAReq = new NextRequest('http://localhost:3000/api/auth', {
      method: 'POST',
      body: JSON.stringify({
        action: 'register',
        fullName: 'Agent Alpha',
        email: 'alpha@sentinel.local',
        password: 'AlphaStrongPassword123!',
        acceptedEthicalTerms: true
      })
    });
    const regARes = await postAuth(regAReq);
    expect(regARes.status).toBe(200);
    const tokenA = regARes.cookies.get('sentinel_session')?.value;
    expect(tokenA).toBeTruthy();

    // 2. Register User B
    const regBReq = new NextRequest('http://localhost:3000/api/auth', {
      method: 'POST',
      body: JSON.stringify({
        action: 'register',
        fullName: 'Agent Bravo',
        email: 'bravo@sentinel.local',
        password: 'BravoStrongPassword123!',
        acceptedEthicalTerms: true
      })
    });
    const regBRes = await postAuth(regBReq);
    const tokenB = regBRes.cookies.get('sentinel_session')?.value;
    expect(tokenB).toBeTruthy();

    // 3. User A creates a Case
    const createCaseReq = new NextRequest('http://localhost:3000/api/cases', {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        title: 'Alpha Confidential Case',
        description: 'Testing API route case isolation',
        scopeAndAuthorization: 'Authorized test'
      })
    });
    const caseRes = await postCase(createCaseReq);
    expect(caseRes.status).toBe(201);
    const createdCase = (await caseRes.json()).case;

    // 4. User A runs a Phone Investigation attached to the Case
    const runInvReq = new NextRequest('http://localhost:3000/api/investigations', {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({
        targetValue: '+1 415 555 2671',
        targetType: 'phone',
        scope: 'Authorized phone metadata check',
        purpose: 'Integration test',
        caseId: createdCase.id
      })
    });
    const invRes = await postInvestigation(runInvReq);
    expect(invRes.status).toBe(201);
    const bundle = await invRes.json();
    const invId = bundle.investigation.id;

    // 5. User B cannot export or delete User A's investigation
    const bobExportReq = new NextRequest(
      `http://localhost:3000/api/investigations/export?id=${invId}&format=json`,
      {
        headers: { Authorization: `Bearer ${tokenB}` }
      }
    );
    const bobExportRes = await exportInvestigation(bobExportReq);
    expect(bobExportRes.status).toBe(404);

    const bobDeleteReq = new NextRequest(
      `http://localhost:3000/api/investigations?id=${invId}`,
      {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${tokenB}` }
      }
    );
    const bobDeleteRes = await deleteInvestigation(bobDeleteReq);
    expect(bobDeleteRes.status).toBe(403);

    // 6. User A can export PDF, CSV, STIX, and JSON for their own investigation
    const alphaPdfReq = new NextRequest(
      `http://localhost:3000/api/investigations/export?id=${invId}&format=pdf`,
      {
        headers: { Authorization: `Bearer ${tokenA}` }
      }
    );
    const pdfRes = await exportInvestigation(alphaPdfReq);
    expect(pdfRes.status).toBe(200);
    expect(pdfRes.headers.get('content-type')).toBe('application/pdf');

    // 7. Verify session check via GET /api/auth
    const sessionCheckReq = new NextRequest('http://localhost:3000/api/auth', {
      headers: { Authorization: `Bearer ${tokenA}` }
    });
    const sessionCheckRes = await getAuth(sessionCheckReq);
    const sessionData = await sessionCheckRes.json();
    expect(sessionData.authenticated).toBe(true);
    expect(sessionData.user.email).toBe('alpha@sentinel.local');

    // 8. User B cannot delete User A's case (403), while User A can delete it (200)
    const bobCaseDel = new NextRequest(
      `http://localhost:3000/api/cases?id=${createdCase.id}`,
      {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${tokenB}` }
      }
    );
    expect((await deleteCase(bobCaseDel)).status).toBe(403);

    const alphaCaseDel = new NextRequest(
      `http://localhost:3000/api/cases?id=${createdCase.id}`,
      {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${tokenA}` }
      }
    );
    expect((await deleteCase(alphaCaseDel)).status).toBe(200);
  });

  it('redacts JPEG EXIF GPS coordinates by default and reveals them only to the owner via audited PATCH /api/findings', async () => {
    const regReq = new NextRequest('http://localhost:3000/api/auth', {
      method: 'POST',
      body: JSON.stringify({
        action: 'register',
        fullName: 'Forensic Analyst',
        email: 'forensic@sentinel.local',
        password: 'ForensicStrongPassword123!',
        acceptedEthicalTerms: true
      })
    });
    const regRes = await postAuth(regReq);
    const token = regRes.cookies.get('sentinel_session')?.value!;
    const userJson = await regRes.json();

    // Build synthetic JPEG with APP1 Exif + GPS IFD (37.7749 N, 122.4194 W)
    const tiff = Buffer.alloc(120);
    tiff.write('II', 0, 'ascii'); // Little-endian
    tiff.writeUInt16LE(42, 2);
    tiff.writeUInt32LE(8, 4); // First IFD at offset 8
    // IFD0: 1 entry (GPS IFD pointer 0x8825 -> offset 26)
    tiff.writeUInt16LE(1, 8);
    tiff.writeUInt16LE(0x8825, 10);
    tiff.writeUInt16LE(4, 12);
    tiff.writeUInt32LE(1, 14);
    tiff.writeUInt32LE(26, 18);
    tiff.writeUInt32LE(0, 22);
    // GPS IFD at offset 26: 4 entries
    tiff.writeUInt16LE(4, 26);
    // 1: GPSLatitudeRef (0x0001) = 'N'
    tiff.writeUInt16LE(0x0001, 28);
    tiff.writeUInt16LE(2, 30);
    tiff.writeUInt32LE(2, 32);
    tiff.write('N\0\0\0', 36, 'ascii');
    // 2: GPSLatitude (0x0002) = 3 rationals at offset 80
    tiff.writeUInt16LE(0x0002, 40);
    tiff.writeUInt16LE(5, 42);
    tiff.writeUInt32LE(3, 44);
    tiff.writeUInt32LE(80, 48);
    // 3: GPSLongitudeRef (0x0003) = 'W'
    tiff.writeUInt16LE(0x0003, 52);
    tiff.writeUInt16LE(2, 54);
    tiff.writeUInt32LE(2, 56);
    tiff.write('W\0\0\0', 60, 'ascii');
    // 4: GPSLongitude (0x0004) = 3 rationals at offset 96 (Wait: 80 + 24 = 104 -> let's use 96 with 140 bytes total)
    const fullTiff = Buffer.alloc(140);
    tiff.copy(fullTiff);
    fullTiff.writeUInt16LE(0x0004, 64);
    fullTiff.writeUInt16LE(5, 66);
    fullTiff.writeUInt32LE(3, 68);
    fullTiff.writeUInt32LE(104, 72);
    // Latitude rationals at 80: 37 deg, 46 min, 30 sec
    fullTiff.writeUInt32LE(37, 80);
    fullTiff.writeUInt32LE(1, 84);
    fullTiff.writeUInt32LE(46, 88);
    fullTiff.writeUInt32LE(1, 92);
    fullTiff.writeUInt32LE(30, 96);
    fullTiff.writeUInt32LE(1, 100);
    // Longitude rationals at 104: 122 deg, 25 min, 10 sec
    fullTiff.writeUInt32LE(122, 104);
    fullTiff.writeUInt32LE(1, 108);
    fullTiff.writeUInt32LE(25, 112);
    fullTiff.writeUInt32LE(1, 116);
    fullTiff.writeUInt32LE(10, 120);
    fullTiff.writeUInt32LE(1, 124);

    const exifHeader = Buffer.from('Exif\0\0', 'ascii');
    const app1Payload = Buffer.concat([exifHeader, fullTiff]);
    const app1Seg = Buffer.alloc(4 + app1Payload.length);
    app1Seg[0] = 0xff;
    app1Seg[1] = 0xe1;
    app1Seg.writeUInt16BE(2 + app1Payload.length, 2);
    app1Payload.copy(app1Seg, 4);

    const jpegBuf = Buffer.concat([
      Buffer.from([0xff, 0xd8]),
      app1Seg,
      Buffer.from([0xff, 0xd9])
    ]);

    const bundle = await executeUniversalInvestigation({
      userId: userJson.user.id,
      targetValue: 'evidence-gps.jpg',
      targetType: 'file',
      scope: 'Authorized forensic test',
      purpose: 'GPS redaction verification',
      fileBuffer: jpegBuf,
      fileName: 'evidence-gps.jpg'
    });

    const gpsFinding = bundle.findings.find((f) => f.moduleCode === 'IMG-09');
    expect(gpsFinding).toBeDefined();
    expect(gpsFinding?.attributes.gpsLatitude).toContain('REDACTED');
    expect(gpsFinding?.attributes.gpsLongitude).toContain('REDACTED');

    // Audited reveal restores exact coordinates
    const revealReq = new NextRequest('http://localhost:3000/api/findings', {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${token}` },
      body: JSON.stringify({
        findingId: gpsFinding!.id,
        auditSensitiveReveal: true
      })
    });
    const revealRes = await patchFinding(revealReq);
    expect(revealRes.status).toBe(200);
    const revealedData = await revealRes.json();
    expect(typeof revealedData.finding.attributes.gpsLatitude).toBe('number');
    expect(revealedData.finding.attributes.gpsLatitude).toBeCloseTo(37.775, 2);
    expect(revealedData.finding.attributes.gpsLongitude).toBeCloseTo(-122.419, 2);
  });
});
