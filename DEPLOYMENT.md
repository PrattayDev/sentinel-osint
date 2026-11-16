# Sentinel OSINT — Deployment & Operations Runbook

## 1. Local Development & Standalone Execution

```bash
cd sentinel-osint
npm install
npm run dev
```
- The web application starts at `http://localhost:3000`.
- When `NEXT_PUBLIC_SUPABASE_URL` is not provided, Sentinel automatically initializes its local persistent datastore at `.data/sentinel-db.json` with full multi-user RBAC isolation, audit trails, and live OSINT provider execution.

---

## 2. Supabase PostgreSQL Database Deployment

1. Create a new Supabase project at `https://supabase.com/dashboard`.
2. Apply the full schema and Row Level Security (RLS) migration located at:
   `supabase/migrations/0001_sentinel_osint_schema.sql`
   using the Supabase CLI or SQL Editor:
   ```bash
   npx supabase db push
   ```
3. Set `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY` in your environment.

---

## 3. Vercel Frontend & API Deployment

Sentinel includes a production `vercel.json` with security headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`) and function duration settings.

1. Import the repository into Vercel or run:
   ```bash
   npx vercel --prod
   ```
2. Configure environment variables in Vercel Project Settings (see `API_KEYS_SETUP.md`).
3. Verify operational health via `GET /api/health`.

---

## 4. Dedicated Background Worker Deployment

For long-running batch investigations or scheduled re-runs that exceed serverless timeout limits, run the standalone worker process (`worker/index.ts`):

```bash
npm run worker
```

---

## 5. Data Retention & Hard Deletion

- Each workspace defines a configurable retention policy (`retention_policies` table, default `90` days).
- Deleting an investigation, case, or user account executes an immediate hard delete of associated findings, evidence sources, and uploaded file hashes while recording a redaction entry in `audit_events`.
