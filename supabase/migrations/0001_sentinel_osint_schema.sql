-- =============================================================================
-- SENTINEL OSINT — PRODUCTION POSTGRESQL SCHEMA & ROW LEVEL SECURITY (RLS)
-- Migration: 0001_sentinel_osint_schema.sql
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- -----------------------------------------------------------------------------
-- 1. PROFILES (Users)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email TEXT UNIQUE NOT NULL,
  full_name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('analyst', 'senior_analyst', 'admin')),
  mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  accepted_ethical_terms BOOLEAN NOT NULL DEFAULT TRUE,
  accepted_terms_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 2. WORKSPACES
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.workspaces (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL,
  description TEXT,
  owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 3. WORKSPACE_MEMBERS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.workspace_members (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  workspace_id UUID NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(workspace_id, user_id)
);

-- -----------------------------------------------------------------------------
-- 4. INVESTIGATIONS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.investigations (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  workspace_id UUID NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  target_type TEXT NOT NULL CHECK (target_type IN ('email', 'domain', 'ip', 'url', 'username', 'phone', 'file_hash', 'organization', 'file')),
  target_value TEXT NOT NULL,
  normalized_target TEXT NOT NULL,
  scope TEXT NOT NULL,
  purpose TEXT NOT NULL,
  external_provider_consent BOOLEAN NOT NULL DEFAULT TRUE,
  status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('queued', 'running', 'completed', 'partial', 'failed', 'cancelled')),
  tags TEXT[] NOT NULL DEFAULT '{}',
  summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_investigations_owner ON public.investigations(owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_investigations_workspace ON public.investigations(workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_investigations_target ON public.investigations(target_type, normalized_target);

-- -----------------------------------------------------------------------------
-- 5. INVESTIGATION_TARGETS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.investigation_targets (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  investigation_id UUID NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
  owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  target_type TEXT NOT NULL,
  raw_input TEXT NOT NULL,
  normalized_input TEXT NOT NULL,
  validation_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 6. INVESTIGATION_JOBS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.investigation_jobs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  investigation_id UUID NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
  owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'completed', 'partial', 'failed', 'cancelled')),
  total_providers INT NOT NULL DEFAULT 0,
  completed_providers INT NOT NULL DEFAULT 0,
  failed_providers INT NOT NULL DEFAULT 0,
  worker_id TEXT,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 7. PROVIDER_EXECUTIONS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.provider_executions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  investigation_id UUID NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
  owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL,
  provider_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('available', 'not_configured', 'running', 'completed', 'partial', 'rate_limited', 'failed', 'unsupported')),
  duration_ms INT NOT NULL DEFAULT 0,
  findings_count INT NOT NULL DEFAULT 0,
  error_message TEXT,
  rate_limit_remaining INT,
  queried_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  raw_metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_provider_exec_inv ON public.provider_executions(investigation_id);

-- -----------------------------------------------------------------------------
-- 8. EVIDENCE_SOURCES
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.evidence_sources (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  investigation_id UUID NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
  owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL,
  provider_name TEXT NOT NULL,
  source_url TEXT,
  observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  queried_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  confidence TEXT NOT NULL CHECK (confidence IN ('confirmed', 'high', 'medium', 'low', 'unverified_heuristic')),
  sensitivity TEXT NOT NULL DEFAULT 'public' CHECK (sensitivity IN ('public', 'internal', 'sensitive', 'restricted')),
  verification_status TEXT NOT NULL DEFAULT 'verified' CHECK (verification_status IN ('verified', 'corroborated', 'unverified', 'disputed')),
  bookmarked BOOLEAN NOT NULL DEFAULT FALSE,
  citation_note TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 9. FINDINGS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.findings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  investigation_id UUID NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
  owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL,
  provider_name TEXT NOT NULL,
  category TEXT NOT NULL,
  module_code TEXT NOT NULL,
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  confidence TEXT NOT NULL CHECK (confidence IN ('confirmed', 'high', 'medium', 'low', 'unverified_heuristic')),
  sensitivity TEXT NOT NULL DEFAULT 'public' CHECK (sensitivity IN ('public', 'internal', 'sensitive', 'restricted')),
  redacted_by_default BOOLEAN NOT NULL DEFAULT FALSE,
  bookmarked BOOLEAN NOT NULL DEFAULT FALSE,
  tags TEXT[] NOT NULL DEFAULT '{}',
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
  source_url TEXT,
  evidence_source_id UUID REFERENCES public.evidence_sources(id) ON DELETE SET NULL,
  observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  queried_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_investigation ON public.findings(investigation_id);
CREATE INDEX IF NOT EXISTS idx_findings_owner ON public.findings(owner_id, created_at DESC);

-- -----------------------------------------------------------------------------
-- 10. ENTITIES
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.entities (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  investigation_id UUID NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
  owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  entity_type TEXT NOT NULL CHECK (entity_type IN ('domain', 'ip', 'asn', 'url', 'profile', 'organization', 'email', 'file_hash', 'certificate', 'phone', 'evidence_source')),
  label TEXT NOT NULL,
  value TEXT NOT NULL,
  confidence TEXT NOT NULL CHECK (confidence IN ('confirmed', 'high', 'medium', 'low', 'unverified_heuristic')),
  provider_id TEXT NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  position_x DOUBLE PRECISION,
  position_y DOUBLE PRECISION,
  observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_entities_investigation ON public.entities(investigation_id);

-- -----------------------------------------------------------------------------
-- 11. ENTITY_RELATIONSHIPS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.entity_relationships (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  investigation_id UUID NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
  owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  source_entity_id UUID NOT NULL REFERENCES public.entities(id) ON DELETE CASCADE,
  target_entity_id UUID NOT NULL REFERENCES public.entities(id) ON DELETE CASCADE,
  relationship_type TEXT NOT NULL,
  source_provider TEXT NOT NULL,
  evidence_id UUID REFERENCES public.findings(id) ON DELETE SET NULL,
  confidence TEXT NOT NULL CHECK (confidence IN ('confirmed', 'high', 'medium', 'low', 'unverified_heuristic')),
  verification_status TEXT NOT NULL DEFAULT 'verified',
  observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_entity_rel_investigation ON public.entity_relationships(investigation_id);

-- -----------------------------------------------------------------------------
-- 12. CASES
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.cases (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  workspace_id UUID NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  scope_and_authorization TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('draft', 'active', 'completed', 'archived')),
  priority TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('low', 'medium', 'high', 'critical')),
  tags TEXT[] NOT NULL DEFAULT '{}',
  notes JSONB NOT NULL DEFAULT '[]'::jsonb,
  timeline JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cases_owner ON public.cases(owner_id, updated_at DESC);

-- -----------------------------------------------------------------------------
-- 13. CASE_INVESTIGATIONS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.case_investigations (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  case_id UUID NOT NULL REFERENCES public.cases(id) ON DELETE CASCADE,
  investigation_id UUID NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
  owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(case_id, investigation_id)
);

-- -----------------------------------------------------------------------------
-- 14. REPORTS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.reports (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  workspace_id UUID NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  case_id UUID REFERENCES public.cases(id) ON DELETE SET NULL,
  investigation_id UUID REFERENCES public.investigations(id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  classification TEXT NOT NULL DEFAULT 'TLP:AMBER',
  executive_summary TEXT NOT NULL,
  conclusions TEXT NOT NULL,
  report_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 15. REPORT_EXPORTS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.report_exports (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  report_id UUID NOT NULL REFERENCES public.reports(id) ON DELETE CASCADE,
  owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  format TEXT NOT NULL CHECK (format IN ('pdf', 'json', 'csv', 'stix')),
  checksum_sha256 TEXT NOT NULL,
  exported_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 16. PROVIDER_CONFIGURATION (Server-Only Metadata; Never Exposes Secret Values)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.provider_configuration (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  workspace_id UUID NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  custom_rate_limit INT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(workspace_id, provider_id)
);

-- -----------------------------------------------------------------------------
-- 17. USAGE_EVENTS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.usage_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  quota_cost INT NOT NULL DEFAULT 1,
  status TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 18. AUDIT_EVENTS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.audit_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  actor_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT,
  ip_address TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_actor ON public.audit_events(actor_id, created_at DESC);

-- -----------------------------------------------------------------------------
-- 19. RETENTION_POLICIES
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.retention_policies (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  workspace_id UUID UNIQUE NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  investigation_retention_days INT NOT NULL DEFAULT 90 CHECK (investigation_retention_days BETWEEN 1 AND 3650),
  auto_redact_sensitive_exif BOOLEAN NOT NULL DEFAULT TRUE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES FOR ALL 19 TABLES
-- =============================================================================

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.investigation_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.investigation_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.provider_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.evidence_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.entity_relationships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.case_investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.report_exports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.provider_configuration ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.usage_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.retention_policies ENABLE ROW LEVEL SECURITY;

-- Strict Owner-Scoped Isolation Policies
CREATE POLICY "profiles_self_access" ON public.profiles
  FOR ALL USING (auth.uid() = id) WITH CHECK (auth.uid() = id);

CREATE POLICY "workspaces_owner_access" ON public.workspaces
  FOR ALL USING (auth.uid() = owner_id) WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "workspace_members_access" ON public.workspace_members
  FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

CREATE POLICY "investigations_owner_access" ON public.investigations
  FOR ALL USING (auth.uid() = owner_id) WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "investigation_targets_owner_access" ON public.investigation_targets
  FOR ALL USING (auth.uid() = owner_id) WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "investigation_jobs_owner_access" ON public.investigation_jobs
  FOR ALL USING (auth.uid() = owner_id) WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "provider_executions_owner_access" ON public.provider_executions
  FOR ALL USING (auth.uid() = owner_id) WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "evidence_sources_owner_access" ON public.evidence_sources
  FOR ALL USING (auth.uid() = owner_id) WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "findings_owner_access" ON public.findings
  FOR ALL USING (auth.uid() = owner_id) WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "entities_owner_access" ON public.entities
  FOR ALL USING (auth.uid() = owner_id) WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "entity_relationships_owner_access" ON public.entity_relationships
  FOR ALL USING (auth.uid() = owner_id) WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "cases_owner_access" ON public.cases
  FOR ALL USING (auth.uid() = owner_id) WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "case_investigations_owner_access" ON public.case_investigations
  FOR ALL USING (auth.uid() = owner_id) WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "reports_owner_access" ON public.reports
  FOR ALL USING (auth.uid() = owner_id) WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "report_exports_owner_access" ON public.report_exports
  FOR ALL USING (auth.uid() = owner_id) WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "provider_configuration_owner_access" ON public.provider_configuration
  FOR ALL USING (auth.uid() = owner_id) WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "usage_events_owner_access" ON public.usage_events
  FOR ALL USING (auth.uid() = owner_id) WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "audit_events_owner_access" ON public.audit_events
  FOR SELECT USING (auth.uid() = actor_id);

CREATE POLICY "retention_policies_owner_access" ON public.retention_policies
  FOR ALL USING (auth.uid() = owner_id) WITH CHECK (auth.uid() = owner_id);
