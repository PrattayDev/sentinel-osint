'use client';

import React, { useCallback, useEffect, useState } from 'react';
import { AuthScreen } from '@/components/auth/AuthScreen';
import { SentinelWorkspace } from '@/components/workspace/SentinelWorkspace';
import { AuditEventRecord, RetentionPolicyRecord } from '@/types/osint';
import { Shield } from 'lucide-react';

export default function HomePage() {
  const [checkingSession, setCheckingSession] = useState(true);
  const [user, setUser] = useState<{
    id: string;
    email: string;
    fullName: string;
    role: string;
    acceptedEthicalTerms: boolean;
    acceptedTermsAt?: string;
    createdAt?: string;
  } | null>(null);
  const [retention, setRetention] = useState<RetentionPolicyRecord | null>(null);
  const [auditEvents, setAuditEvents] = useState<AuditEventRecord[]>([]);

  const checkSession = useCallback(async () => {
    setCheckingSession(true);
    try {
      const res = await fetch('/api/auth', { cache: 'no-store' });
      if (res.ok) {
        const data = await res.json();
        if (data.authenticated && data.user) {
          setUser(data.user);
          setRetention(data.retentionPolicy || null);
          setAuditEvents(data.auditEvents || []);
          return;
        }
      }
      setUser(null);
    } catch {
      setUser(null);
    } finally {
      setCheckingSession(false);
    }
  }, []);

  useEffect(() => {
    checkSession();
  }, [checkSession]);

  const handleLogout = async () => {
    await fetch('/api/auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'logout' })
    });
    setUser(null);
  };

  if (checkingSession) {
    return (
      <div className="min-h-screen bg-[#070b14] text-slate-200 flex flex-col items-center justify-center p-6">
        <div className="w-12 h-12 rounded-2xl bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center animate-pulse mb-4">
          <Shield className="w-6 h-6 text-cyan-400" />
        </div>
        <div className="text-sm font-semibold text-white">
          Initializing Sentinel OSINT Security Context...
        </div>
        <div className="text-xs text-slate-400 mt-1 font-mono">
          Verifying session integrity & provider adapter status
        </div>
      </div>
    );
  }

  if (!user) {
    return <AuthScreen onAuthenticated={checkSession} />;
  }

  return (
    <SentinelWorkspace
      user={user}
      initialRetention={retention}
      initialAuditEvents={auditEvents}
      onLogout={handleLogout}
    />
  );
}
