'use client';

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertCircle,
  Bookmark,
  Building2,
  CheckCircle2,
  Compass,
  Database,
  Download,
  ExternalLink,
  Eye,
  FileSearch,
  FileText,
  FolderKanban,
  Globe,
  HardDrive,
  History,
  Key,
  Layers,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  Network,
  Play,
  Plus,
  RefreshCw,
  Search,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  Sparkles,
  Sun,
  Tag,
  Trash2,
  Upload,
  UserCheck,
  Users,
  X
} from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from 'recharts';
import {
  AuditEventRecord,
  CaseRecord,
  EntityRecord,
  EntityRelationshipRecord,
  EvidenceSourceRecord,
  FindingRecord,
  InvestigationRecord,
  ProviderExecutionRecord,
  RetentionPolicyRecord,
  TargetType
} from '@/types/osint';
import { RelationshipGraph } from '@/components/graph/RelationshipGraph';

export type NavSectionId =
  | 'overview'
  | 'universal'
  | 'investigations'
  | 'identity'
  | 'domain'
  | 'network'
  | 'web'
  | 'social'
  | 'threat'
  | 'media'
  | 'organization'
  | 'graph'
  | 'evidence'
  | 'reports'
  | 'integrations'
  | 'settings';

interface ProviderCatalogItem {
  id: string;
  name: string;
  category: string;
  supportedTypes: TargetType[];
  requiresApiKey: boolean;
  envVarNames: string[];
  isFreeTierAvailable: boolean;
  rateLimitPerMinute: number;
  disclosureNotice: string;
  featureIds: string[];
  status: 'available' | 'not_configured';
}

interface ActiveBundle {
  investigation: InvestigationRecord;
  providerExecutions: ProviderExecutionRecord[];
  evidenceSources: EvidenceSourceRecord[];
  findings: FindingRecord[];
  entities: EntityRecord[];
  relationships: EntityRelationshipRecord[];
}

interface AiSummaryPayload {
  isAiInterpretation: boolean;
  mode: string;
  disclaimer: string;
  target: string;
  verifiedFindingsSummary: string;
  notableObservations: string[];
  confidenceLimitations: string[];
  defensiveFollowUpQuestions: string[];
}

interface SentinelWorkspaceProps {
  user: {
    id: string;
    email: string;
    fullName: string;
    role: string;
    acceptedEthicalTerms: boolean;
    acceptedTermsAt?: string;
    createdAt?: string;
  };
  initialRetention: RetentionPolicyRecord | null;
  initialAuditEvents: AuditEventRecord[];
  onLogout: () => void;
}

const NAV_ITEMS: Array<{
  id: NavSectionId;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  group: string;
  defaultTargetType?: TargetType;
  placeholder?: string;
  moduleRange?: string;
}> = [
  { id: 'overview', label: '1. Overview', icon: LayoutDashboard, group: 'Core' },
  {
    id: 'universal',
    label: '2. Universal Search',
    icon: Search,
    group: 'Core',
    placeholder: 'Enter domain, IP, email, URL, username, phone, hash, or org...'
  },
  {
    id: 'investigations',
    label: '3. Investigations',
    icon: History,
    group: 'Core'
  },
  {
    id: 'identity',
    label: '4. Identity Intelligence',
    icon: UserCheck,
    group: 'OSINT Modules',
    defaultTargetType: 'email',
    placeholder: 'e.g. security@example.com or +14155552671',
    moduleRange: 'ID-01 – ID-10'
  },
  {
    id: 'domain',
    label: '5. Domain Intelligence',
    icon: Globe,
    group: 'OSINT Modules',
    defaultTargetType: 'domain',
    placeholder: 'e.g. example.com or cloudflare.com',
    moduleRange: 'DOM-01 – DOM-14'
  },
  {
    id: 'network',
    label: '6. Network Intelligence',
    icon: Server,
    group: 'OSINT Modules',
    defaultTargetType: 'ip',
    placeholder: 'e.g. 1.1.1.1 or 93.184.216.34',
    moduleRange: 'NET-01 – NET-12'
  },
  {
    id: 'web',
    label: '7. Web Intelligence',
    icon: Compass,
    group: 'OSINT Modules',
    defaultTargetType: 'url',
    placeholder: 'e.g. https://example.com',
    moduleRange: 'WEB-01 – WEB-12'
  },
  {
    id: 'social',
    label: '8. Social Intelligence',
    icon: Users,
    group: 'OSINT Modules',
    defaultTargetType: 'username',
    placeholder: 'e.g. torvalds or octocat',
    moduleRange: 'SOC-01 – SOC-08'
  },
  {
    id: 'threat',
    label: '9. Threat Intelligence',
    icon: ShieldAlert,
    group: 'OSINT Modules',
    defaultTargetType: 'file_hash',
    placeholder: 'e.g. SHA-256 / MD5 hash, domain, IP, or URL',
    moduleRange: 'THR-01 – THR-10'
  },
  {
    id: 'media',
    label: '10. Image & Document Intel',
    icon: FileSearch,
    group: 'OSINT Modules',
    defaultTargetType: 'file',
    moduleRange: 'IMG-01 – IMG-10'
  },
  {
    id: 'organization',
    label: '11. Organization Intel',
    icon: Building2,
    group: 'OSINT Modules',
    defaultTargetType: 'organization',
    placeholder: 'e.g. Cloudflare or Microsoft',
    moduleRange: 'ORG-01 – ORG-08'
  },
  {
    id: 'graph',
    label: '12. Investigation Graph',
    icon: Network,
    group: 'Analysis & Casework'
  },
  {
    id: 'evidence',
    label: '13. Evidence Library',
    icon: Database,
    group: 'Analysis & Casework'
  },
  {
    id: 'reports',
    label: '14. Cases & Reports',
    icon: FileText,
    group: 'Analysis & Casework'
  },
  {
    id: 'integrations',
    label: '15. Integrations',
    icon: Key,
    group: 'Platform'
  },
  {
    id: 'settings',
    label: '16. Settings',
    icon: Settings,
    group: 'Platform'
  }
];

export function SentinelWorkspace({
  user,
  initialRetention,
  initialAuditEvents,
  onLogout
}: SentinelWorkspaceProps) {
  const [activeNav, setActiveNav] = useState<NavSectionId>('overview');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [lightMode, setLightMode] = useState(false);

  // Real persisted application records
  const [investigations, setInvestigations] = useState<InvestigationRecord[]>([]);
  const [findings, setFindings] = useState<FindingRecord[]>([]);
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [entities, setEntities] = useState<EntityRecord[]>([]);
  const [relationships, setRelationships] = useState<EntityRelationshipRecord[]>([]);
  const [providers, setProviders] = useState<ProviderCatalogItem[]>([]);
  const [retention, setRetention] = useState<RetentionPolicyRecord | null>(
    initialRetention
  );
  const [auditEvents, setAuditEvents] =
    useState<AuditEventRecord[]>(initialAuditEvents);

  // Universal Search & Module Execution Form State
  const [targetValue, setTargetValue] = useState('');
  const [targetType, setTargetType] = useState<TargetType | 'auto'>('auto');
  const [scopeInput, setScopeInput] = useState(
    'Authorized defensive cybersecurity & public OSINT assessment'
  );
  const [purposeInput, setPurposeInput] = useState(
    'Verify public infrastructure, attribution provenance, and security posture'
  );
  const [externalConsent, setExternalConsent] = useState(true);
  const [selectedCaseId, setSelectedCaseId] = useState<string>('');
  const [runningJob, setRunningJob] = useState(false);
  const [jobError, setJobError] = useState<string | null>(null);
  const [activeBundle, setActiveBundle] = useState<ActiveBundle | null>(null);
  const [aiSummary, setAiSummary] = useState<AiSummaryPayload | null>(null);
  const [loadingAi, setLoadingAi] = useState(false);

  // File Inspection state (IMG-01..IMG-10)
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [fileReport, setFileReport] = useState<Record<string, unknown> | null>(
    null
  );
  const [revealedGpsIds, setRevealedGpsIds] = useState<Set<string>>(new Set());

  // Case Creation & Note state
  const [newCaseTitle, setNewCaseTitle] = useState('');
  const [newCaseDesc, setNewCaseDesc] = useState('');
  const [newCaseScope, setNewCaseScope] = useState(
    'Authorized SOC / Defensive Research Scope'
  );
  const [newCasePriority, setNewCasePriority] = useState<
    'low' | 'medium' | 'high' | 'critical'
  >('medium');
  const [caseNoteInput, setCaseNoteInput] = useState<Record<string, string>>({});
  const [reportTlp, setReportTlp] = useState<
    'TLP:CLEAR' | 'TLP:GREEN' | 'TLP:AMBER' | 'TLP:RED'
  >('TLP:AMBER');

  // Evidence Filter state
  const [evidenceFilter, setEvidenceFilter] = useState('');
  const [evidenceCategoryFilter, setEvidenceCategoryFilter] = useState('all');
  const [tagDrafts, setTagDrafts] = useState<Record<string, string>>({});

  const refreshWorkspaceData = useCallback(async () => {
    try {
      const [invRes, provRes, authRes] = await Promise.all([
        fetch('/api/investigations'),
        fetch('/api/providers'),
        fetch('/api/auth')
      ]);

      if (invRes.ok) {
        const invData = await invRes.json();
        setInvestigations(invData.investigations || []);
        setFindings(invData.recentFindings || []);
        setCases(invData.cases || []);
        setEntities(invData.graph?.entities || []);
        setRelationships(invData.graph?.relationships || []);
      }

      if (provRes.ok) {
        const provData = await provRes.json();
        setProviders(provData.providers || []);
      }

      if (authRes.ok) {
        const authData = await authRes.json();
        if (authData.retentionPolicy) setRetention(authData.retentionPolicy);
        if (authData.auditEvents) setAuditEvents(authData.auditEvents);
      }
    } catch {
      // Non-fatal refresh error
    }
  }, []);

  useEffect(() => {
    refreshWorkspaceData();
  }, [refreshWorkspaceData]);

  const handleRunInvestigation = async (
    e?: React.FormEvent,
    overrideTarget?: string,
    overrideType?: TargetType,
    existingId?: string
  ) => {
    if (e) e.preventDefault();
    const finalTarget = (overrideTarget ?? targetValue).trim();
    if (!finalTarget) {
      setJobError('Please enter a target indicator to investigate.');
      return;
    }

    setJobError(null);
    setRunningJob(true);
    setAiSummary(null);

    const resolvedType =
      overrideType || (targetType === 'auto' ? undefined : targetType);

    try {
      const res = await fetch('/api/investigations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetValue: finalTarget,
          targetType: resolvedType,
          scope: scopeInput,
          purpose: purposeInput,
          externalProviderConsent: externalConsent,
          caseId: selectedCaseId || undefined,
          existingInvestigationId: existingId
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Investigation failed');
      }

      setActiveBundle(data);
      await refreshWorkspaceData();
    } catch (err) {
      setJobError((err as Error).message);
    } finally {
      setRunningJob(false);
    }
  };

  const handleLoadInvestigationDetails = async (id: string) => {
    setJobError(null);
    setAiSummary(null);
    try {
      const res = await fetch(`/api/investigations?id=${encodeURIComponent(id)}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to load investigation');
      setActiveBundle(data);
    } catch (err) {
      setJobError((err as Error).message);
    }
  };

  const handleDeleteInvestigation = async (id: string) => {
    try {
      const res = await fetch(
        `/api/investigations?id=${encodeURIComponent(id)}`,
        { method: 'DELETE' }
      );
      if (res.ok) {
        if (activeBundle?.investigation.id === id) {
          setActiveBundle(null);
        }
        await refreshWorkspaceData();
      }
    } catch {
      // Ignore error
    }
  };

  const handleGenerateAiSummary = async (investigationId: string) => {
    setLoadingAi(true);
    try {
      const res = await fetch('/api/ai-summary', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          investigationId,
          consentToExternalAi: externalConsent
        })
      });
      const data = await res.json();
      if (res.ok) {
        setAiSummary(data);
      }
    } finally {
      setLoadingAi(false);
    }
  };

  const handleFileInspectSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!uploadFile) {
      setJobError('Select a valid JPEG, PNG, GIF, WebP, or PDF file to inspect.');
      return;
    }

    setJobError(null);
    setRunningJob(true);
    try {
      const formData = new FormData();
      formData.append('file', uploadFile);
      formData.append('scope', scopeInput);
      formData.append('purpose', purposeInput);
      if (selectedCaseId) formData.append('caseId', selectedCaseId);

      const res = await fetch('/api/files/inspect', {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'File inspection failed');

      setActiveBundle(data.bundle);
      setFileReport(data.fileReport);
      await refreshWorkspaceData();
    } catch (err) {
      setJobError((err as Error).message);
    } finally {
      setRunningJob(false);
    }
  };

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCaseTitle.trim() || !newCaseDesc.trim()) return;
    const res = await fetch('/api/cases', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: newCaseTitle,
        description: newCaseDesc,
        scopeAndAuthorization: newCaseScope,
        priority: newCasePriority,
        status: 'active'
      })
    });
    if (res.ok) {
      setNewCaseTitle('');
      setNewCaseDesc('');
      await refreshWorkspaceData();
    }
  };

  const handleUpdateCaseStatusOrNote = async (
    caseId: string,
    updates: {
      status?: 'draft' | 'active' | 'completed' | 'archived';
      noteContent?: string;
      linkInvestigationId?: string;
    }
  ) => {
    const res = await fetch('/api/cases', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        caseId,
        ...updates
      })
    });
    if (res.ok) {
      if (updates.noteContent) {
        setCaseNoteInput((prev) => ({ ...prev, [caseId]: '' }));
      }
      await refreshWorkspaceData();
    }
  };

  const handleDeleteCase = async (caseId: string) => {
    const res = await fetch(`/api/cases?id=${encodeURIComponent(caseId)}`, {
      method: 'DELETE'
    });
    if (res.ok) {
      if (selectedCaseId === caseId) {
        setSelectedCaseId('');
      }
      await refreshWorkspaceData();
    }
  };

  const handleToggleFindingBookmark = async (finding: FindingRecord) => {
    const res = await fetch('/api/findings', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        findingId: finding.id,
        bookmarked: !finding.bookmarked
      })
    });
    if (res.ok) {
      await refreshWorkspaceData();
      if (activeBundle) {
        setActiveBundle({
          ...activeBundle,
          findings: activeBundle.findings.map((f) =>
            f.id === finding.id ? { ...f, bookmarked: !f.bookmarked } : f
          )
        });
      }
    }
  };

  const handleAddFindingTag = async (finding: FindingRecord) => {
    const draft = (tagDrafts[finding.id] || '').trim();
    if (!draft) return;
    const nextTags = Array.from(new Set([...finding.tags, draft]));
    const res = await fetch('/api/findings', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        findingId: finding.id,
        tags: nextTags
      })
    });
    if (res.ok) {
      setTagDrafts((prev) => ({ ...prev, [finding.id]: '' }));
      await refreshWorkspaceData();
    }
  };

  const handleRevealSensitiveFinding = async (findingId: string) => {
    const res = await fetch('/api/findings', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        findingId,
        auditSensitiveReveal: true
      })
    });
    const data = res.ok ? await res.json() : null;
    setRevealedGpsIds((prev) => {
      const next = new Set(prev);
      next.add(findingId);
      return next;
    });
    if (data?.finding) {
      setFindings((prev) =>
        prev.map((f) => (f.id === findingId ? data.finding : f))
      );
      setActiveBundle((prev) =>
        prev
          ? {
              ...prev,
              findings: prev.findings.map((f) =>
                f.id === findingId ? data.finding : f
              )
            }
          : prev
      );
    }
  };

  // Real Dashboard Metrics derived strictly from persisted application records
  const metrics = useMemo(() => {
    const total = investigations.length;
    const completed = investigations.filter(
      (i) => i.status === 'completed'
    ).length;
    const partialOrFailed = investigations.filter(
      (i) => i.status === 'partial' || i.status === 'failed'
    ).length;
    const activeCount = runningJob ? 1 : 0;

    const byTypeMap: Record<string, number> = {};
    for (const inv of investigations) {
      byTypeMap[inv.targetType] = (byTypeMap[inv.targetType] || 0) + 1;
    }
    const byTypeChart = Object.entries(byTypeMap).map(([type, count]) => ({
      type: type.toUpperCase(),
      count
    }));

    const availableProviders = providers.filter(
      (p) => p.status === 'available'
    ).length;

    return {
      total,
      completed,
      partialOrFailed,
      activeCount,
      byTypeChart,
      availableProviders,
      totalProviders: providers.length
    };
  }, [investigations, providers, runningJob]);

  const currentNavMeta = useMemo(
    () => NAV_ITEMS.find((n) => n.id === activeNav) || NAV_ITEMS[0],
    [activeNav]
  );

  // Switch default targetType when navigating to a specialized module
  const selectNavSection = (id: NavSectionId) => {
    setActiveNav(id);
    setMobileMenuOpen(false);
    setJobError(null);
    const meta = NAV_ITEMS.find((n) => n.id === id);
    if (meta?.defaultTargetType) {
      setTargetType(meta.defaultTargetType);
    } else if (id === 'universal') {
      setTargetType('auto');
    }
  };

  const renderExecutionForm = (moduleTitle: string, moduleBadge?: string) => (
    <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-5 space-y-4 shadow-lg">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-bold text-white">{moduleTitle}</h2>
            {moduleBadge && (
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                {moduleBadge}
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            All inputs are validated, normalized, and checked against SSRF & privacy safeguards before querying providers.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono text-slate-400">
            Active Providers: {metrics.availableProviders}/{metrics.totalProviders}
          </span>
        </div>
      </div>

      {jobError && (
        <div className="p-3 rounded-lg bg-rose-500/15 border border-rose-500/40 text-rose-200 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{jobError}</span>
        </div>
      )}

      <form onSubmit={(e) => handleRunInvestigation(e)} className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
          <div className="md:col-span-3">
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Target Classification
            </label>
            <select
              value={targetType}
              onChange={(e) =>
                setTargetType(e.target.value as TargetType | 'auto')
              }
              className="w-full px-3 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
            >
              <option value="auto">Auto-Classify Indicator</option>
              <option value="domain">Domain (DOM-01..14)</option>
              <option value="ip">Public IPv4 / IPv6 (NET-01..12)</option>
              <option value="email">Email Address (ID-01..10)</option>
              <option value="url">Website URL (WEB-01..12)</option>
              <option value="username">Username Handle (SOC-01..08)</option>
              <option value="phone">Phone Number E.164 (ID-07..08)</option>
              <option value="file_hash">File Hash MD5/SHA1/SHA256 (THR-01)</option>
              <option value="organization">Organization Name (ORG-01..08)</option>
            </select>
          </div>

          <div className="md:col-span-6">
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Target Indicator
            </label>
            <input
              type="text"
              required
              value={targetValue}
              onChange={(e) => setTargetValue(e.target.value)}
              placeholder={
                currentNavMeta.placeholder ||
                'Enter domain, IP, email, URL, username, E.164 phone, hash, or organization...'
              }
              className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="md:col-span-3 flex items-end">
            <button
              type="submit"
              disabled={runningJob}
              className="w-full py-2.5 px-4 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-semibold text-xs transition flex items-center justify-center gap-2"
            >
              {runningJob ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Querying Providers...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  Execute Investigation
                </>
              )}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2 border-t border-slate-800/80">
          <div>
            <label className="block text-[11px] text-slate-400 mb-1">
              Investigation Scope & Authorization
            </label>
            <input
              type="text"
              required
              value={scopeInput}
              onChange={(e) => setScopeInput(e.target.value)}
              className="w-full px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-xs text-slate-200"
            />
          </div>

          <div>
            <label className="block text-[11px] text-slate-400 mb-1">
              Analytical Purpose
            </label>
            <input
              type="text"
              required
              value={purposeInput}
              onChange={(e) => setPurposeInput(e.target.value)}
              className="w-full px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-xs text-slate-200"
            />
          </div>

          <div>
            <label className="block text-[11px] text-slate-400 mb-1">
              Attach to Case (Optional)
            </label>
            <select
              value={selectedCaseId}
              onChange={(e) => setSelectedCaseId(e.target.value)}
              className="w-full px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-xs text-slate-200"
            >
              <option value="">— Standalone Investigation —</option>
              {cases.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.title} ({c.status})
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2 pt-2 text-xs text-slate-400">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={externalConsent}
              onChange={(e) => setExternalConsent(e.target.checked)}
              className="rounded border-slate-700 bg-slate-950 text-cyan-500"
            />
            <span>
              <strong className="text-slate-200">
                Third-Party Provider Disclosure Consent:
              </strong>{' '}
              Allow querying configured external public APIs (DNS, RDAP, CT, RIPEstat, Shodan InternetDB, abuse.ch). Uncheck to restrict to 100% local offline validation.
            </span>
          </label>

          <div className="flex items-center gap-1.5 text-[11px]">
            <span className="text-slate-400">Quick Examples:</span>
            {[
              { label: 'example.com', type: 'domain' as TargetType },
              { label: '1.1.1.1', type: 'ip' as TargetType },
              { label: 'security@mailinator.com', type: 'email' as TargetType },
              { label: '+14155552671', type: 'phone' as TargetType },
              { label: 'torvalds', type: 'username' as TargetType },
              { label: 'Cloudflare', type: 'organization' as TargetType }
            ].map((ex) => (
              <button
                key={ex.label}
                type="button"
                onClick={() => {
                  setTargetValue(ex.label);
                  setTargetType(ex.type);
                }}
                className="px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-cyan-300 border border-slate-800 font-mono"
              >
                {ex.label}
              </button>
            ))}
          </div>
        </div>
      </form>
    </div>
  );

  const renderActiveBundleResults = () => {
    if (!activeBundle) return null;
    const {
      investigation,
      providerExecutions,
      findings: bundleFindings,
      evidenceSources
    } = activeBundle;

    return (
      <div className="space-y-4 mt-6">
        {/* Header & Export Toolbar */}
        <div className="bg-[#0d1424] border border-cyan-500/30 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono uppercase px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300">
                {investigation.targetType}
              </span>
              <h3 className="text-base font-bold text-white font-mono">
                {investigation.normalizedTarget}
              </h3>
              <span
                className={`text-[11px] font-mono px-2 py-0.5 rounded ${
                  investigation.status === 'completed'
                    ? 'bg-emerald-500/15 text-emerald-300'
                    : 'bg-amber-500/15 text-amber-300'
                }`}
              >
                {investigation.status.toUpperCase()}
              </span>
            </div>
            <div className="text-xs text-slate-400 mt-1">
              Scope: {investigation.scope} | Findings: {bundleFindings.length} | Entities: {activeBundle.entities.length} | Executed: {investigation.completedAt || investigation.createdAt}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={runningJob}
              onClick={() =>
                handleRunInvestigation(
                  undefined,
                  investigation.targetValue,
                  investigation.targetType,
                  investigation.id
                )
              }
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 border border-slate-700"
            >
              <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
              Authorized Re-Run
            </button>

            <button
              type="button"
              disabled={loadingAi}
              onClick={() => handleGenerateAiSummary(investigation.id)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-500/15 hover:bg-purple-500/25 text-xs text-purple-300 border border-purple-500/30"
            >
              <Sparkles className="w-3.5 h-3.5" />
              {loadingAi ? 'Synthesizing...' : 'Defensive Summary'}
            </button>

            {(['pdf', 'json', 'csv', 'stix'] as const).map((fmt) => (
              <a
                key={fmt}
                href={`/api/investigations/export?id=${encodeURIComponent(investigation.id)}&format=${fmt}&classification=${encodeURIComponent(reportTlp)}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 text-xs font-mono uppercase text-cyan-300 border border-cyan-500/30"
              >
                <Download className="w-3.5 h-3.5" />
                {fmt}
              </a>
            ))}
          </div>
        </div>

        {/* Optional AI / Automated Defensive Analysis Banner */}
        {aiSummary && (
          <div className="bg-purple-950/25 border border-purple-500/40 rounded-xl p-4 space-y-2.5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-semibold text-purple-300">
                <Sparkles className="w-4 h-4" />
                <span>
                  Automated Evidence Synthesis ({aiSummary.mode})
                </span>
              </div>
              <span className="text-[11px] font-mono text-purple-300/80">
                {aiSummary.disclaimer}
              </span>
            </div>
            <p className="text-xs text-slate-200">
              {aiSummary.verifiedFindingsSummary}
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
              <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800">
                <div className="text-xs font-semibold text-cyan-300 mb-1">
                  Recommended Defensive Follow-Ups
                </div>
                <ul className="list-disc list-inside text-xs text-slate-300 space-y-1">
                  {aiSummary.defensiveFollowUpQuestions.map((q, idx) => (
                    <li key={idx}>{q}</li>
                  ))}
                </ul>
              </div>
              <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800">
                <div className="text-xs font-semibold text-amber-300 mb-1">
                  Confidence & Coverage Limitations
                </div>
                <ul className="list-disc list-inside text-xs text-slate-300 space-y-1">
                  {aiSummary.confidenceLimitations.map((lim, idx) => (
                    <li key={idx}>{lim}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        )}

        {/* Provider Execution Breakdown */}
        <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-4">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
            Provider Adapter Execution Status ({providerExecutions.length})
          </h4>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
            {providerExecutions.map((exec) => (
              <div
                key={exec.id}
                className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-col justify-between"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold text-slate-200 truncate">
                    {exec.providerName}
                  </span>
                  <span
                    className={`text-[10px] font-mono px-1.5 py-0.5 rounded uppercase shrink-0 ${
                      exec.status === 'completed'
                        ? 'bg-emerald-500/15 text-emerald-300'
                        : exec.status === 'not_configured'
                          ? 'bg-slate-800 text-slate-400'
                          : exec.status === 'rate_limited'
                            ? 'bg-amber-500/15 text-amber-300'
                            : 'bg-rose-500/15 text-rose-300'
                    }`}
                  >
                    {exec.status}
                  </span>
                </div>
                <div className="text-[11px] text-slate-400 mt-2 flex items-center justify-between">
                  <span>{exec.findingsCount} finding(s)</span>
                  <span className="font-mono">{exec.durationMs}ms</span>
                </div>
                {exec.errorMessage && (
                  <div className="text-[10px] text-amber-300/90 mt-1.5 truncate" title={exec.errorMessage}>
                    {exec.errorMessage}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Normalized Findings Cards */}
        <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-4 space-y-3">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Normalized Intelligence Findings & Provenance ({bundleFindings.length})
          </h4>
          {bundleFindings.length === 0 ? (
            <div className="text-xs text-slate-400 py-4 text-center">
              No findings were returned by the executed providers. Check provider status cards above for missing API keys or errors.
            </div>
          ) : (
            <div className="space-y-3">
              {bundleFindings.map((f) => {
                const isRevealed = revealedGpsIds.has(f.id);
                return (
                  <div
                    key={f.id}
                    className="p-4 rounded-xl bg-slate-950 border border-slate-800/90 space-y-2"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                          {f.moduleCode}
                        </span>
                        <span
                          className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded ${
                            f.severity === 'critical' || f.severity === 'high'
                              ? 'bg-rose-500/20 text-rose-300'
                              : f.severity === 'medium'
                                ? 'bg-amber-500/20 text-amber-300'
                                : 'bg-slate-800 text-slate-300'
                          }`}
                        >
                          Severity: {f.severity}
                        </span>
                        <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800">
                          Confidence: {f.confidence}
                        </span>
                        <span className="text-xs font-semibold text-white">
                          {f.title}
                        </span>
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => handleToggleFindingBookmark(f)}
                          className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs border ${
                            f.bookmarked
                              ? 'bg-amber-500/20 border-amber-500/40 text-amber-300'
                              : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white'
                          }`}
                        >
                          <Bookmark className="w-3.5 h-3.5" />
                          {f.bookmarked ? 'Bookmarked' : 'Bookmark'}
                        </button>
                        {f.sourceUrl && (
                          <a
                            href={f.sourceUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-xs text-cyan-400 border border-slate-800"
                          >
                            Source
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        )}
                      </div>
                    </div>

                    <p className="text-xs text-slate-300 leading-relaxed">
                      {f.summary}
                    </p>

                    {f.redactedByDefault && !isRevealed && (
                      <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-between">
                        <span className="text-xs text-amber-200">
                          Sensitive EXIF location metadata is redacted by default per privacy policy.
                        </span>
                        <button
                          type="button"
                          onClick={() => handleRevealSensitiveFinding(f.id)}
                          className="px-2.5 py-1 rounded bg-amber-500 text-slate-950 font-semibold text-xs flex items-center gap-1"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          Reveal Sensitive Metadata (Audited)
                        </button>
                      </div>
                    )}

                    <details className="text-xs">
                      <summary className="cursor-pointer text-cyan-400 hover:text-cyan-300 font-mono text-[11px]">
                        Inspect Normalized Attributes & Provenance ({f.providerName} @ {f.observedAt})
                      </summary>
                      <pre className="mt-2 p-3 rounded-lg bg-[#070b14] border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
                        {JSON.stringify(f.attributes, null, 2)}
                      </pre>
                    </details>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Source Citations Table */}
        {evidenceSources.length > 0 && (
          <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-4">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
              Evidence Source Citations ({evidenceSources.length})
            </h4>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2 pr-3">Provider</th>
                    <th className="py-2 px-3">Verification</th>
                    <th className="py-2 px-3">Confidence</th>
                    <th className="py-2 px-3">Observed At</th>
                    <th className="py-2 pl-3">Source URL / Citation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {evidenceSources.map((src) => (
                    <tr key={src.id} className="text-slate-300">
                      <td className="py-2 pr-3 font-medium">{src.providerName}</td>
                      <td className="py-2 px-3 font-mono text-emerald-400">
                        {src.verificationStatus}
                      </td>
                      <td className="py-2 px-3 font-mono">{src.confidence}</td>
                      <td className="py-2 px-3 font-mono text-[11px]">
                        {src.observedAt}
                      </td>
                      <td className="py-2 pl-3">
                        {src.sourceUrl ? (
                          <a
                            href={src.sourceUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-cyan-400 hover:underline font-mono text-[11px]"
                          >
                            {src.sourceUrl}
                          </a>
                        ) : (
                          <span className="text-slate-400">
                            {src.citationNote || 'Local deterministic analyzer'}
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div
      className={`min-h-screen flex ${
        lightMode ? 'bg-slate-100 text-slate-900' : 'bg-[#070b14] text-slate-100'
      }`}
    >
      {/* Desktop & Mobile Sidebar */}
      <aside
        className={`${
          mobileMenuOpen ? 'fixed inset-y-0 left-0 z-50 block' : 'hidden'
        } lg:block w-68 shrink-0 bg-[#0d1424] border-r border-slate-800/90 flex flex-col justify-between overflow-y-auto`}
      >
        <div className="p-4">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center">
                <Shield className="w-4 h-4 text-cyan-400" />
              </div>
              <div>
                <div className="text-sm font-bold text-white tracking-tight">
                  SENTINEL OSINT
                </div>
                <div className="text-[10px] font-mono text-cyan-400">
                  DEFENSIVE INTEL v2.0
                </div>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setMobileMenuOpen(false)}
              className="lg:hidden text-slate-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          <nav className="mt-4 space-y-4" aria-label="Main OSINT Navigation">
            {['Core', 'OSINT Modules', 'Analysis & Casework', 'Platform'].map(
              (groupName) => (
                <div key={groupName}>
                  <div className="px-2.5 text-[10px] font-mono uppercase tracking-wider text-slate-500 mb-1.5">
                    {groupName}
                  </div>
                  <div className="space-y-0.5">
                    {NAV_ITEMS.filter((item) => item.group === groupName).map(
                      (item) => {
                        const Icon = item.icon;
                        const active = activeNav === item.id;
                        return (
                          <button
                            key={item.id}
                            type="button"
                            onClick={() => selectNavSection(item.id)}
                            className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition ${
                              active
                                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                                : 'text-slate-300 hover:bg-slate-900 hover:text-white'
                            }`}
                          >
                            <span className="flex items-center gap-2.5 truncate">
                              <Icon className="w-4 h-4 shrink-0" />
                              <span className="truncate">{item.label}</span>
                            </span>
                            {item.moduleRange && (
                              <span className="text-[9px] font-mono text-slate-500">
                                {item.moduleRange.split(' ')[0]}
                              </span>
                            )}
                          </button>
                        );
                      }
                    )}
                  </div>
                </div>
              )
            )}
          </nav>
        </div>

        <div className="p-4 border-t border-slate-800 bg-slate-950/60 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-medium text-slate-200 truncate">
              {user.fullName}
            </span>
            <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-cyan-500/15 text-cyan-300">
              {user.role}
            </span>
          </div>
          <div className="text-[11px] text-slate-400 truncate">{user.email}</div>
          <button
            type="button"
            onClick={onLogout}
            className="w-full mt-1 inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-rose-500/20 text-xs text-slate-300 hover:text-rose-300 border border-slate-800 transition"
          >
            <LogOut className="w-3.5 h-3.5" />
            Sign Out Session
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Bar */}
        <header className="h-14 bg-[#0d1424] border-b border-slate-800 px-4 lg:px-6 flex items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden p-1.5 rounded-lg bg-slate-900 text-slate-200 border border-slate-800"
              aria-label="Open navigation menu"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div>
              <h1 className="text-sm font-bold text-white">
                {currentNavMeta.label}
              </h1>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              type="button"
              onClick={() => selectNavSection('universal')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs"
            >
              <Search className="w-3.5 h-3.5" />
              New Investigation
            </button>
            <button
              type="button"
              onClick={() => setLightMode(!lightMode)}
              className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800"
              aria-label="Toggle color theme"
            >
              {lightMode ? (
                <Moon className="w-4 h-4" />
              ) : (
                <Sun className="w-4 h-4" />
              )}
            </button>
          </div>
        </header>

        {/* Workspace Body */}
        <main className="flex-1 p-4 lg:p-6 overflow-y-auto space-y-6">
          {/* 1. OVERVIEW DASHBOARD */}
          {activeNav === 'overview' && (
            <div className="space-y-6">
              {/* Top Metric Widgets (100% Real Application Records) */}
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
                <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-4">
                  <div className="text-[11px] text-slate-400">
                    Total Investigations
                  </div>
                  <div className="text-2xl font-bold text-white mt-1 font-mono">
                    {metrics.total}
                  </div>
                </div>
                <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-4">
                  <div className="text-[11px] text-slate-400">Active Jobs</div>
                  <div className="text-2xl font-bold text-cyan-400 mt-1 font-mono">
                    {metrics.activeCount}
                  </div>
                </div>
                <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-4">
                  <div className="text-[11px] text-slate-400">
                    Completed Investigations
                  </div>
                  <div className="text-2xl font-bold text-emerald-400 mt-1 font-mono">
                    {metrics.completed}
                  </div>
                </div>
                <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-4">
                  <div className="text-[11px] text-slate-400">
                    Partial / Failed Jobs
                  </div>
                  <div className="text-2xl font-bold text-amber-400 mt-1 font-mono">
                    {metrics.partialOrFailed}
                  </div>
                </div>
                <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-4">
                  <div className="text-[11px] text-slate-400">Saved Cases</div>
                  <div className="text-2xl font-bold text-white mt-1 font-mono">
                    {cases.length}
                  </div>
                </div>
                <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-4">
                  <div className="text-[11px] text-slate-400">
                    Providers Available
                  </div>
                  <div className="text-2xl font-bold text-cyan-300 mt-1 font-mono">
                    {metrics.availableProviders}/{metrics.totalProviders}
                  </div>
                </div>
              </div>

              {/* Quick Universal Launch inside Overview */}
              {renderExecutionForm(
                'Universal OSINT Investigation Launcher',
                '90+ Modules Ready'
              )}
              {renderActiveBundleResults()}

              {/* Charts, Recent Findings, Provider Availability & Activity */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
                <div className="lg:col-span-5 bg-[#0d1424] border border-slate-800 rounded-xl p-4">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
                    Investigations by Target Type
                  </h3>
                  {metrics.byTypeChart.length === 0 ? (
                    <div className="h-52 flex items-center justify-center text-xs text-slate-500">
                      No investigations recorded yet. Run your first lookup above.
                    </div>
                  ) : (
                    <div className="h-52">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={metrics.byTypeChart}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                          <XAxis
                            dataKey="type"
                            stroke="#94a3b8"
                            fontSize={10}
                          />
                          <YAxis
                            stroke="#94a3b8"
                            fontSize={10}
                            allowDecimals={false}
                          />
                          <Tooltip
                            contentStyle={{
                              backgroundColor: '#070b14',
                              borderColor: '#1e293b',
                              fontSize: '12px'
                            }}
                          />
                          <Bar dataKey="count" fill="#06b6d4" radius={[4, 4, 0, 0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  )}
                </div>

                <div className="lg:col-span-7 bg-[#0d1424] border border-slate-800 rounded-xl p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                      Recent Verified Findings ({findings.length})
                    </h3>
                    <button
                      type="button"
                      onClick={() => selectNavSection('evidence')}
                      className="text-xs text-cyan-400 hover:underline"
                    >
                      Open Evidence Library →
                    </button>
                  </div>
                  {findings.length === 0 ? (
                    <div className="text-xs text-slate-500 py-8 text-center">
                      Findings from live provider executions will appear here automatically.
                    </div>
                  ) : (
                    <div className="space-y-2 max-h-56 overflow-y-auto">
                      {findings.slice(0, 8).map((f) => (
                        <div
                          key={f.id}
                          className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between gap-2 text-xs"
                        >
                          <div className="truncate">
                            <span className="font-mono text-cyan-400 mr-2">
                              [{f.moduleCode}]
                            </span>
                            <span className="text-slate-200 font-medium">
                              {f.title}
                            </span>
                          </div>
                          <span className="text-[10px] font-mono text-slate-400 shrink-0">
                            {f.providerName}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* Shortcuts & Recent Audit Activity */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-4">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
                    Specialized Module Shortcuts
                  </h3>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                    {NAV_ITEMS.filter((n) => n.group === 'OSINT Modules').map(
                      (mod) => {
                        const Icon = mod.icon;
                        return (
                          <button
                            key={mod.id}
                            type="button"
                            onClick={() => selectNavSection(mod.id)}
                            className="p-3 rounded-lg bg-slate-950 hover:bg-slate-900 border border-slate-800 text-left transition"
                          >
                            <Icon className="w-4 h-4 text-cyan-400 mb-1.5" />
                            <div className="text-xs font-semibold text-slate-200 truncate">
                              {mod.label.replace(/^\d+\.\s*/, '')}
                            </div>
                            <div className="text-[10px] font-mono text-slate-400 mt-0.5">
                              {mod.moduleRange}
                            </div>
                          </button>
                        );
                      }
                    )}
                  </div>
                </div>

                <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-4">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
                    Recent Security & Investigation Audit Log
                  </h3>
                  <div className="space-y-1.5 max-h-44 overflow-y-auto">
                    {auditEvents.slice(0, 8).map((ev) => (
                      <div
                        key={ev.id}
                        className="flex items-center justify-between text-xs py-1.5 px-2.5 rounded bg-slate-950 border border-slate-800/80"
                      >
                        <span className="font-mono text-cyan-300">
                          {ev.action}
                        </span>
                        <span className="text-[11px] font-mono text-slate-400">
                          {ev.createdAt.slice(0, 19).replace('T', ' ')}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* 2, 4, 5, 6, 7, 8, 9, 11: UNIVERSAL SEARCH & SPECIALIZED OSINT MODULES */}
          {[
            'universal',
            'identity',
            'domain',
            'network',
            'web',
            'social',
            'threat',
            'organization'
          ].includes(activeNav) && (
            <div className="space-y-6">
              {renderExecutionForm(
                currentNavMeta.label.replace(/^\d+\.\s*/, ''),
                currentNavMeta.moduleRange
              )}
              {renderActiveBundleResults()}
            </div>
          )}

          {/* 10. IMAGE & DOCUMENT INTELLIGENCE (IMG-01..IMG-10) */}
          {activeNav === 'media' && (
            <div className="space-y-6">
              <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-base font-bold text-white">
                      Image & Document Intelligence (IMG-01 – IMG-10)
                    </h2>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Sandboxed local binary parser for JPEG, PNG, GIF, WebP, and PDF files (max 10 MB). Computes MD5, SHA-1, SHA-256, and 64-bit Perceptual dHash. Embedded GPS coordinates are hidden by default.
                    </p>
                  </div>
                  <span className="text-xs font-mono px-2.5 py-1 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                    100% Local Zero-Execution Sandbox
                  </span>
                </div>

                {jobError && (
                  <div className="p-3 rounded-lg bg-rose-500/15 border border-rose-500/40 text-rose-200 text-xs">
                    {jobError}
                  </div>
                )}

                <form onSubmit={handleFileInspectSubmit} className="space-y-4">
                  <div className="border-2 border-dashed border-slate-700 hover:border-cyan-500/60 rounded-xl p-6 text-center bg-slate-950/60">
                    <Upload className="w-8 h-8 text-cyan-400 mx-auto mb-2" />
                    <label className="cursor-pointer">
                      <span className="text-xs font-semibold text-cyan-300 underline">
                        Select an authorized image or PDF document
                      </span>
                      <input
                        type="file"
                        accept=".jpg,.jpeg,.png,.gif,.webp,.pdf,image/jpeg,image/png,image/gif,image/webp,application/pdf"
                        onChange={(e) =>
                          setUploadFile(e.target.files?.[0] || null)
                        }
                        className="hidden"
                      />
                    </label>
                    <p className="text-[11px] text-slate-400 mt-1">
                      {uploadFile
                        ? `Selected: ${uploadFile.name} (${(uploadFile.size / 1024).toFixed(1)} KB)`
                        : 'Maximum size: 10 MB. Magic-byte signature verified prior to parsing.'}
                    </p>
                  </div>

                  <button
                    type="submit"
                    disabled={!uploadFile || runningJob}
                    className="px-5 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-semibold text-xs inline-flex items-center gap-2"
                  >
                    <FileSearch className="w-4 h-4" />
                    {runningJob
                      ? 'Inspecting Binary Container...'
                      : 'Inspect File Metadata & Compute Hashes'}
                  </button>
                </form>
              </div>

              {fileReport && (
                <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-4 space-y-2">
                  <h3 className="text-xs font-semibold uppercase text-cyan-400">
                    Duplicate Media Cross-Reference (IMG-10)
                  </h3>
                  {Array.isArray(fileReport.duplicateMatches) &&
                  fileReport.duplicateMatches.length > 0 ? (
                    <div className="text-xs text-amber-300">
                      Detected {fileReport.duplicateMatches.length} prior workspace upload(s) matching SHA-256 or Perceptual dHash!
                    </div>
                  ) : (
                    <div className="text-xs text-slate-400">
                      No duplicate or near-duplicate media matches found in current workspace evidence.
                    </div>
                  )}
                </div>
              )}

              {renderActiveBundleResults()}
            </div>
          )}

          {/* 3. INVESTIGATIONS HISTORY */}
          {activeNav === 'investigations' && (
            <div className="space-y-6">
              <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h2 className="text-base font-bold text-white">
                      Saved Investigation History ({investigations.length})
                    </h2>
                    <p className="text-xs text-slate-400">
                      Strictly isolated to your authenticated analyst workspace.
                    </p>
                  </div>
                </div>

                {investigations.length === 0 ? (
                  <div className="text-xs text-slate-400 py-8 text-center">
                    No investigations saved yet.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400">
                          <th className="py-2.5 pr-3">Target Indicator</th>
                          <th className="py-2.5 px-3">Type</th>
                          <th className="py-2.5 px-3">Status</th>
                          <th className="py-2.5 px-3">Findings</th>
                          <th className="py-2.5 px-3">Scope</th>
                          <th className="py-2.5 px-3">Created</th>
                          <th className="py-2.5 pl-3 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/70">
                        {investigations.map((inv) => (
                          <tr key={inv.id} className="hover:bg-slate-900/50">
                            <td className="py-2.5 pr-3 font-mono font-semibold text-white">
                              {inv.normalizedTarget}
                            </td>
                            <td className="py-2.5 px-3 font-mono uppercase text-cyan-400">
                              {inv.targetType}
                            </td>
                            <td className="py-2.5 px-3">
                              <span
                                className={`px-2 py-0.5 rounded font-mono text-[10px] uppercase ${
                                  inv.status === 'completed'
                                    ? 'bg-emerald-500/15 text-emerald-300'
                                    : 'bg-amber-500/15 text-amber-300'
                                }`}
                              >
                                {inv.status}
                              </span>
                            </td>
                            <td className="py-2.5 px-3 font-mono">
                              {inv.summary.totalFindings}
                            </td>
                            <td className="py-2.5 px-3 text-slate-400 truncate max-w-[180px]">
                              {inv.scope}
                            </td>
                            <td className="py-2.5 px-3 font-mono text-[11px] text-slate-400">
                              {inv.createdAt.slice(0, 19).replace('T', ' ')}
                            </td>
                            <td className="py-2.5 pl-3 text-right space-x-1.5">
                              <button
                                type="button"
                                onClick={() =>
                                  handleLoadInvestigationDetails(inv.id)
                                }
                                className="px-2.5 py-1 rounded bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/30"
                              >
                                Inspect
                              </button>
                              <button
                                type="button"
                                onClick={() =>
                                  handleRunInvestigation(
                                    undefined,
                                    inv.targetValue,
                                    inv.targetType,
                                    inv.id
                                  )
                                }
                                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200"
                              >
                                Re-Run
                              </button>
                              <button
                                type="button"
                                onClick={() =>
                                  handleDeleteInvestigation(inv.id)
                                }
                                className="px-2 py-1 rounded bg-rose-500/15 hover:bg-rose-500/25 text-rose-300"
                                aria-label="Delete investigation"
                              >
                                <Trash2 className="w-3.5 h-3.5 inline" />
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {renderActiveBundleResults()}
            </div>
          )}

          {/* 12. INVESTIGATION GRAPH */}
          {activeNav === 'graph' && (
            <div className="space-y-4">
              <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-4">
                <h2 className="text-base font-bold text-white">
                  Interactive Entity Relationship Graph
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Corroborated entities and relationships with source attribution, observation timestamps, confidence classification, and JSON/SVG export.
                </p>
              </div>
              <RelationshipGraph
                entities={
                  activeBundle ? activeBundle.entities : entities
                }
                relationships={
                  activeBundle ? activeBundle.relationships : relationships
                }
                onInvestigateEntity={(entity) => {
                  const mapType: Record<string, TargetType> = {
                    domain: 'domain',
                    ip: 'ip',
                    url: 'url',
                    email: 'email',
                    organization: 'organization',
                    file_hash: 'file_hash'
                  };
                  const tType = mapType[entity.entityType];
                  if (tType) {
                    setTargetValue(entity.value);
                    setTargetType(tType);
                    setActiveNav('universal');
                    handleRunInvestigation(undefined, entity.value, tType);
                  }
                }}
              />
            </div>
          )}

          {/* 13. EVIDENCE LIBRARY */}
          {activeNav === 'evidence' && (
            <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h2 className="text-base font-bold text-white">
                    Evidence Library & Indicator Tagging ({findings.length})
                  </h2>
                  <p className="text-xs text-slate-400">
                    Filter, bookmark, and tag normalized findings with immutable provenance timestamps.
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <input
                    type="text"
                    value={evidenceFilter}
                    onChange={(e) => setEvidenceFilter(e.target.value)}
                    placeholder="Search findings, tags, or modules..."
                    className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
                  />
                  <select
                    value={evidenceCategoryFilter}
                    onChange={(e) => setEvidenceCategoryFilter(e.target.value)}
                    className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200"
                  >
                    <option value="all">All Categories</option>
                    <option value="identity">Identity</option>
                    <option value="domain">Domain</option>
                    <option value="network">Network</option>
                    <option value="web">Web</option>
                    <option value="social">Social</option>
                    <option value="threat">Threat</option>
                    <option value="media">Media / File</option>
                    <option value="organization">Organization</option>
                    <option value="search">Search / Archive</option>
                  </select>
                </div>
              </div>

              <div className="space-y-3">
                {findings
                  .filter((f) => {
                    const catMatch =
                      evidenceCategoryFilter === 'all' ||
                      f.category === evidenceCategoryFilter;
                    const textMatch =
                      !evidenceFilter.trim() ||
                      f.title
                        .toLowerCase()
                        .includes(evidenceFilter.toLowerCase()) ||
                      f.summary
                        .toLowerCase()
                        .includes(evidenceFilter.toLowerCase()) ||
                      f.moduleCode
                        .toLowerCase()
                        .includes(evidenceFilter.toLowerCase()) ||
                      f.tags.some((t) =>
                        t.toLowerCase().includes(evidenceFilter.toLowerCase())
                      );
                    return catMatch && textMatch;
                  })
                  .map((f) => (
                    <div
                      key={f.id}
                      className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300">
                            {f.moduleCode}
                          </span>
                          <span className="text-xs font-semibold text-white">
                            {f.title}
                          </span>
                          <span className="text-[10px] font-mono text-slate-400">
                            ({f.providerName})
                          </span>
                        </div>
                        <button
                          type="button"
                          onClick={() => handleToggleFindingBookmark(f)}
                          className={`px-2.5 py-1 rounded text-xs border ${
                            f.bookmarked
                              ? 'bg-amber-500/20 border-amber-500/40 text-amber-300'
                              : 'bg-slate-900 border-slate-800 text-slate-400'
                          }`}
                        >
                          {f.bookmarked ? '★ Bookmarked' : '☆ Bookmark'}
                        </button>
                      </div>

                      <p className="text-xs text-slate-300">{f.summary}</p>

                      <div className="flex flex-wrap items-center justify-between gap-2 pt-2">
                        <div className="flex flex-wrap items-center gap-1.5">
                          {f.tags.map((t) => (
                            <span
                              key={t}
                              className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-cyan-300 border border-slate-800"
                            >
                              #{t}
                            </span>
                          ))}
                        </div>

                        <div className="flex items-center gap-1.5">
                          <input
                            type="text"
                            value={tagDrafts[f.id] || ''}
                            onChange={(e) =>
                              setTagDrafts((prev) => ({
                                ...prev,
                                [f.id]: e.target.value
                              }))
                            }
                            placeholder="Add indicator tag..."
                            className="px-2 py-1 rounded bg-slate-900 border border-slate-800 text-xs text-white"
                          />
                          <button
                            type="button"
                            onClick={() => handleAddFindingTag(f)}
                            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-cyan-300"
                          >
                            <Tag className="w-3 h-3 inline mr-1" />
                            Tag
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          )}

          {/* 14. CASES & REPORTS WORKSPACE */}
          {activeNav === 'reports' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                {/* Create Case Form */}
                <div className="lg:col-span-5 bg-[#0d1424] border border-slate-800 rounded-xl p-5 space-y-4">
                  <h2 className="text-base font-bold text-white flex items-center gap-2">
                    <FolderKanban className="w-4 h-4 text-cyan-400" />
                    Create Investigation Case
                  </h2>
                  <form onSubmit={handleCreateCase} className="space-y-3">
                    <div>
                      <label className="block text-xs text-slate-300 mb-1">
                        Case Title
                      </label>
                      <input
                        type="text"
                        required
                        value={newCaseTitle}
                        onChange={(e) => setNewCaseTitle(e.target.value)}
                        placeholder="e.g. Phishing Domain Infrastructure Review #104"
                        className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-300 mb-1">
                        Case Description
                      </label>
                      <textarea
                        rows={2}
                        required
                        value={newCaseDesc}
                        onChange={(e) => setNewCaseDesc(e.target.value)}
                        placeholder="Summarize investigation objectives..."
                        className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-300 mb-1">
                        Scope & Authorization Notes
                      </label>
                      <input
                        type="text"
                        required
                        value={newCaseScope}
                        onChange={(e) => setNewCaseScope(e.target.value)}
                        className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
                      />
                    </div>
                    <div className="flex items-center justify-between gap-2">
                      <select
                        value={newCasePriority}
                        onChange={(e) =>
                          setNewCasePriority(
                            e.target.value as 'low' | 'medium' | 'high' | 'critical'
                          )
                        }
                        className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200"
                      >
                        <option value="low">Priority: Low</option>
                        <option value="medium">Priority: Medium</option>
                        <option value="high">Priority: High</option>
                        <option value="critical">Priority: Critical</option>
                      </select>

                      <button
                        type="submit"
                        className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs inline-flex items-center gap-1.5"
                      >
                        <Plus className="w-4 h-4" />
                        Initialize Case
                      </button>
                    </div>
                  </form>

                  {/* Formal Report Export Settings */}
                  <div className="pt-4 border-t border-slate-800 space-y-3">
                    <h3 className="text-xs font-semibold uppercase text-slate-400">
                      Formal Report Classification & Multi-Format Export
                    </h3>
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">
                        Report TLP Classification
                      </label>
                      <select
                        value={reportTlp}
                        onChange={(e) =>
                          setReportTlp(
                            e.target.value as
                              | 'TLP:CLEAR'
                              | 'TLP:GREEN'
                              | 'TLP:AMBER'
                              | 'TLP:RED'
                          )
                        }
                        className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-cyan-300 font-mono"
                      >
                        <option value="TLP:CLEAR">TLP:CLEAR</option>
                        <option value="TLP:GREEN">TLP:GREEN</option>
                        <option value="TLP:AMBER">TLP:AMBER</option>
                        <option value="TLP:RED">TLP:RED</option>
                      </select>
                    </div>

                    {investigations.length > 0 && (
                      <div className="space-y-2">
                        <div className="text-xs text-slate-300">
                          Download Traceable Evidence Report for Latest Investigation ({investigations[0].normalizedTarget}):
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {(['pdf', 'json', 'csv', 'stix'] as const).map((fmt) => (
                            <a
                              key={fmt}
                              href={`/api/investigations/export?id=${encodeURIComponent(investigations[0].id)}&format=${fmt}&classification=${encodeURIComponent(reportTlp)}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="px-3 py-1.5 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 text-xs font-mono uppercase text-cyan-300 border border-cyan-500/30 inline-flex items-center gap-1"
                            >
                              <Download className="w-3.5 h-3.5" />
                              Export {fmt.toUpperCase()}
                            </a>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Active Cases List */}
                <div className="lg:col-span-7 bg-[#0d1424] border border-slate-800 rounded-xl p-5 space-y-4">
                  <h2 className="text-base font-bold text-white">
                    Isolated Analyst Cases ({cases.length})
                  </h2>
                  {cases.length === 0 ? (
                    <div className="text-xs text-slate-400 py-8 text-center">
                      No cases created yet. Use the form on the left to open a structured case workspace.
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {cases.map((c) => (
                        <div
                          key={c.id}
                          className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div>
                              <span className="text-sm font-bold text-white">
                                {c.title}
                              </span>
                              <span className="ml-2 text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300">
                                {c.priority}
                              </span>
                            </div>
                            <div className="flex items-center gap-2">
                              <select
                                value={c.status}
                                onChange={(e) =>
                                  handleUpdateCaseStatusOrNote(c.id, {
                                    status: e.target.value as
                                      | 'draft'
                                      | 'active'
                                      | 'completed'
                                      | 'archived'
                                  })
                                }
                                className="px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-slate-200"
                              >
                                <option value="draft">Status: DRAFT</option>
                                <option value="active">Status: ACTIVE</option>
                                <option value="completed">Status: COMPLETED</option>
                                <option value="archived">Status: ARCHIVED</option>
                              </select>
                              <button
                                type="button"
                                onClick={() => handleDeleteCase(c.id)}
                                className="px-2 py-1 rounded bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 border border-rose-500/30"
                                aria-label="Delete case"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </div>

                          <p className="text-xs text-slate-300">{c.description}</p>
                          <div className="text-[11px] text-slate-400 font-mono">
                            Scope: {c.scopeAndAuthorization} | Linked Investigations: {c.investigationIds.length}
                          </div>

                          {/* Add Note to Case */}
                          <div className="flex gap-2">
                            <input
                              type="text"
                              value={caseNoteInput[c.id] || ''}
                              onChange={(e) =>
                                setCaseNoteInput((prev) => ({
                                  ...prev,
                                  [c.id]: e.target.value
                                }))
                              }
                              placeholder="Add timestamped investigator note..."
                              className="flex-1 px-3 py-1.5 rounded bg-slate-900 border border-slate-800 text-xs text-white"
                            />
                            <button
                              type="button"
                              onClick={() =>
                                handleUpdateCaseStatusOrNote(c.id, {
                                  noteContent: caseNoteInput[c.id]
                                })
                              }
                              className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs text-cyan-300"
                            >
                              Add Note
                            </button>
                          </div>

                          {c.notes.length > 0 && (
                            <div className="space-y-1 pt-2 border-t border-slate-800/80">
                              <div className="text-[10px] font-mono uppercase text-slate-400">
                                Investigator Notes ({c.notes.length})
                              </div>
                              {c.notes.slice(0, 3).map((n) => (
                                <div
                                  key={n.id}
                                  className="text-xs text-slate-300 bg-slate-900/70 p-2 rounded"
                                >
                                  <span className="font-mono text-[10px] text-cyan-400 mr-2">
                                    [{n.createdAt.slice(0, 16).replace('T', ' ')}]
                                  </span>
                                  {n.content}
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* 15. INTEGRATIONS & PROVIDER CATALOG */}
          {activeNav === 'integrations' && (
            <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-5 space-y-4">
              <div>
                <h2 className="text-base font-bold text-white">
                  Provider Adapter Catalog & Live Configuration Status ({providers.length})
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Sentinel never fakes or mocks missing integrations. Zero-key standards/public providers are active immediately; commercial APIs report <code className="text-amber-300">not_configured</code> until their environment variables are supplied in <code className="text-cyan-300">.env.local</code>.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {providers.map((p) => (
                  <div
                    key={p.id}
                    className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex flex-col justify-between space-y-2"
                  >
                    <div>
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-bold text-white">
                          {p.name}
                        </span>
                        <span
                          className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded ${
                            p.status === 'available'
                              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                              : 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                          }`}
                        >
                          {p.status}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 mt-1">
                        {p.disclosureNotice}
                      </p>
                    </div>

                    <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-400">
                      <span>
                        Targets: {p.supportedTypes.join(', ')}
                      </span>
                      <span>Rate: {p.rateLimitPerMinute}/min</span>
                      <span>
                        {p.requiresApiKey
                          ? `Env: ${p.envVarNames.join(', ')}`
                          : 'Zero-Key Public Standard'}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 16. SETTINGS, PRIVACY RETENTION & ACCOUNT DELETION */}
          {activeNav === 'settings' && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-5 space-y-4">
                <h2 className="text-base font-bold text-white">
                  Analyst Profile & Data Retention Policy
                </h2>
                <div className="space-y-2 text-xs">
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                    <div className="text-slate-400">Authenticated User</div>
                    <div className="font-semibold text-white mt-0.5">
                      {user.fullName} ({user.email})
                    </div>
                    <div className="font-mono text-cyan-400 text-[11px] mt-0.5">
                      Role: {user.role.toUpperCase()} | Ethical Use Accepted: {String(user.acceptedEthicalTerms)}
                    </div>
                  </div>

                  {retention && (
                    <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
                      <div>
                        <label className="block text-xs font-medium text-slate-300 mb-1">
                          Investigation Retention Window (Days)
                        </label>
                        <input
                          type="number"
                          min={1}
                          max={3650}
                          value={retention.investigationRetentionDays}
                          onChange={(e) =>
                            setRetention({
                              ...retention,
                              investigationRetentionDays: Number(e.target.value)
                            })
                          }
                          className="w-full px-3 py-2 rounded bg-slate-900 border border-slate-800 text-xs text-white font-mono"
                        />
                      </div>

                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={retention.autoRedactSensitiveExif}
                          onChange={(e) =>
                            setRetention({
                              ...retention,
                              autoRedactSensitiveExif: e.target.checked
                            })
                          }
                          className="rounded border-slate-700 bg-slate-900 text-cyan-500"
                        />
                        <span className="text-xs text-slate-300">
                          Hide/Redact EXIF GPS coordinates by default on all image uploads
                        </span>
                      </label>

                      <button
                        type="button"
                        onClick={async () => {
                          await fetch('/api/auth', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                              action: 'update_retention',
                              investigationRetentionDays:
                                retention.investigationRetentionDays,
                              autoRedactSensitiveExif:
                                retention.autoRedactSensitiveExif
                            })
                          });
                          await refreshWorkspaceData();
                        }}
                        className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs"
                      >
                        Save Retention & Privacy Policy
                      </button>
                    </div>
                  )}
                </div>
              </div>

              <div className="bg-[#0d1424] border border-rose-500/30 rounded-xl p-5 space-y-4">
                <h2 className="text-base font-bold text-rose-300">
                  Hard Account & Workspace Deletion
                </h2>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Permanently deletes your analyst account, workspace, saved investigations, findings, entity graph records, cases, and reports. This action is immediate and irreversible.
                </p>
                <button
                  type="button"
                  onClick={async () => {
                    const res = await fetch('/api/auth', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ action: 'delete_account' })
                    });
                    if (res.ok) {
                      onLogout();
                    }
                  }}
                  className="px-4 py-2.5 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 text-rose-200 text-xs font-semibold inline-flex items-center gap-2"
                >
                  <Trash2 className="w-4 h-4" />
                  Permanently Delete Account & All OSINT Records
                </button>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
