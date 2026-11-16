'use client';

import React, { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Eye,
  EyeOff,
  KeyRound,
  Lock,
  RefreshCw,
  Shield,
  Sparkles,
  UserPlus
} from 'lucide-react';

interface AuthScreenProps {
  onAuthenticated: () => void;
}

export function AuthScreen({ onAuthenticated }: AuthScreenProps) {
  const [activeTab, setActiveTab] = useState<'login' | 'register' | 'reset'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [acceptedTerms, setAcceptedTerms] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showTermsModal, setShowTermsModal] = useState(false);
  const [resetTokenInput, setResetTokenInput] = useState('');
  const [newResetPassword, setNewResetPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [infoMsg, setInfoMsg] = useState<string | null>(null);

  const generateStrongPassword = () => {
    const chars =
      'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*_-+=';
    const array = new Uint32Array(18);
    window.crypto.getRandomValues(array);
    const generated = Array.from(array, (x) => chars[x % chars.length]).join('');
    setPassword(generated);
    setConfirmPassword(generated);
    setShowPassword(true);
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setInfoMsg(null);
    setLoading(true);
    try {
      const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'login',
          email,
          password
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Login failed');
      onAuthenticated();
    } catch (err) {
      setErrorMsg((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setInfoMsg(null);

    if (password !== confirmPassword) {
      setErrorMsg('Passwords do not match.');
      return;
    }
    if (!acceptedTerms) {
      setErrorMsg(
        'You must review and accept the Ethical Use Terms and Conditions.'
      );
      return;
    }

    setLoading(true);
    try {
      const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'register',
          fullName,
          email,
          password,
          acceptedEthicalTerms: acceptedTerms
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Registration failed');
      onAuthenticated();
    } catch (err) {
      setErrorMsg((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const handleRequestReset = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setInfoMsg(null);
    setLoading(true);
    try {
      const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'request_reset',
          email
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Reset request failed');
      if (data.devResetToken) {
        setResetTokenInput(data.devResetToken);
        setInfoMsg(
          `Reset token generated (local dev mode auto-filled token below). Set your new password to complete recovery.`
        );
      } else {
        setInfoMsg(data.message);
      }
    } catch (err) {
      setErrorMsg((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const handleCompleteReset = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setLoading(true);
    try {
      const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'complete_reset',
          token: resetTokenInput,
          newPassword: newResetPassword
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Password reset failed');
      setInfoMsg('Password reset complete. You may now sign in.');
      setActiveTab('login');
      setPassword(newResetPassword);
    } catch (err) {
      setErrorMsg((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const isDevShortcutEnabled =
    process.env.NODE_ENV === 'development' &&
    process.env.NEXT_PUBLIC_ENABLE_DEV_AUTH_SHORTCUT === 'true';

  const handleQuickAnalystInitialize = async () => {
    if (!isDevShortcutEnabled) {
      setErrorMsg('Development auth shortcut is disabled in this environment.');
      return;
    }
    setErrorMsg(null);
    setLoading(true);
    const demoEmail = 'analyst@sentinel-osint.local';
    const demoPass = 'SentinelAnalyst#2026!';
    try {
      const loginRes = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'login',
          email: demoEmail,
          password: demoPass
        })
      });
      if (loginRes.ok) {
        onAuthenticated();
        return;
      }

      const regRes = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'register',
          fullName: 'Lead SOC Analyst',
          email: demoEmail,
          password: demoPass,
          acceptedEthicalTerms: true
        })
      });
      const data = await regRes.json();
      if (!regRes.ok) throw new Error(data.error || 'Initialization failed');
      onAuthenticated();
    } catch (err) {
      setErrorMsg((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex items-center justify-center p-4">
      <div className="w-full max-w-5xl grid grid-cols-1 lg:grid-cols-12 bg-[#0d1424] border border-slate-800/90 rounded-2xl shadow-2xl overflow-hidden">
        {/* Left Brand & Monitored Access Panel */}
        <div className="lg:col-span-5 bg-gradient-to-br from-[#0f1b33] via-[#0b1324] to-[#070b14] p-8 flex flex-col justify-between border-b lg:border-b-0 lg:border-r border-slate-800">
          <div>
            <div className="inline-flex items-center gap-2.5 px-3 py-1.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono mb-6">
              <Shield className="w-4 h-4 text-cyan-400" />
              SENTINEL OSINT WORKSPACE v2.0
            </div>
            <h1 className="text-2xl lg:text-3xl font-bold text-white tracking-tight leading-snug">
              Secure intelligence access for analysts, investigators, and defensive researchers.
            </h1>
            <p className="text-sm text-slate-300 mt-4 leading-relaxed">
              Consolidate multi-provider public OSINT, passive DNS/RDAP/CT reconnaissance, threat intelligence, and sandboxed file metadata analysis with verifiable provenance and tenant isolation.
            </p>

            <div className="grid grid-cols-2 gap-3 mt-6">
              <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="text-xs font-semibold text-cyan-400">
                  Single View Access
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  Unified login, registration & recovery
                </div>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="text-xs font-semibold text-cyan-400">
                  Monitored Access
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  Ethical-use acknowledgement required
                </div>
              </div>
            </div>
          </div>

          {isDevShortcutEnabled && (
            <div className="mt-8 pt-6 border-t border-slate-800/80 space-y-3">
              <div className="text-xs text-slate-400">
                Local Development Mode Only (NEXT_PUBLIC_ENABLE_DEV_AUTH_SHORTCUT=true):
              </div>
              <button
                type="button"
                disabled={loading}
                onClick={handleQuickAnalystInitialize}
                className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/40 text-cyan-300 text-xs font-semibold transition"
              >
                <Sparkles className="w-4 h-4" />
                Initialize Authenticated Analyst Session
              </button>
            </div>
          )}
        </div>

        {/* Right Form Panel */}
        <div className="lg:col-span-7 p-8">
          <div
            className="flex items-center gap-2 border-b border-slate-800 pb-4 mb-6"
            role="tablist"
            aria-label="Authentication tabs"
          >
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'login'}
              onClick={() => {
                setActiveTab('login');
                setErrorMsg(null);
              }}
              className={`px-4 py-2 rounded-lg text-xs font-semibold transition ${
                activeTab === 'login'
                  ? 'bg-cyan-500 text-slate-950'
                  : 'bg-slate-900 text-slate-300 hover:bg-slate-800'
              }`}
            >
              Login
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'register'}
              onClick={() => {
                setActiveTab('register');
                setErrorMsg(null);
              }}
              className={`px-4 py-2 rounded-lg text-xs font-semibold transition ${
                activeTab === 'register'
                  ? 'bg-cyan-500 text-slate-950'
                  : 'bg-slate-900 text-slate-300 hover:bg-slate-800'
              }`}
            >
              Register Now
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'reset'}
              onClick={() => {
                setActiveTab('reset');
                setErrorMsg(null);
              }}
              className={`px-4 py-2 rounded-lg text-xs font-semibold transition ${
                activeTab === 'reset'
                  ? 'bg-cyan-500 text-slate-950'
                  : 'bg-slate-900 text-slate-300 hover:bg-slate-800'
              }`}
            >
              Password Recovery
            </button>
          </div>

          {errorMsg && (
            <div className="mb-4 p-3 rounded-lg bg-rose-500/15 border border-rose-500/40 text-rose-200 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {infoMsg && (
            <div className="mb-4 p-3 rounded-lg bg-emerald-500/15 border border-emerald-500/40 text-emerald-200 text-xs flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{infoMsg}</span>
            </div>
          )}

          {activeTab === 'login' && (
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <h2 className="text-lg font-semibold text-white">Welcome back</h2>
                <p className="text-xs text-slate-400">
                  Enter your credentials to continue to the Sentinel intelligence dashboard.
                </p>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Your Email
                </label>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@organization.org"
                  className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Your Password
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter password"
                    className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white focus:outline-none focus:border-cyan-500 pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-2.5 text-slate-400 hover:text-slate-200"
                    aria-label="Toggle password visibility"
                  >
                    {showPassword ? (
                      <EyeOff className="w-4 h-4" />
                    ) : (
                      <Eye className="w-4 h-4" />
                    )}
                  </button>
                </div>
              </div>

              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-400">
                  Session protected via HttpOnly cookie
                </span>
                <button
                  type="button"
                  onClick={() => setActiveTab('reset')}
                  className="text-cyan-400 hover:underline"
                >
                  Lost password?
                </button>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm transition flex items-center justify-center gap-2"
              >
                <Lock className="w-4 h-4" />
                {loading ? 'Authenticating...' : 'Login to Sentinel'}
              </button>
            </form>
          )}

          {activeTab === 'register' && (
            <form onSubmit={handleRegister} className="space-y-4">
              <div>
                <h2 className="text-lg font-semibold text-white">Create account</h2>
                <p className="text-xs text-slate-400">
                  Registration stays on this screen so you can review ethical access expectations before continuing.
                </p>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Full Name
                </label>
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Name and surname"
                  className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Your Email
                </label>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@organization.org"
                  className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Password (min 8 chars)
                  </label>
                  <div className="flex gap-1.5">
                    <input
                      type={showPassword ? 'text' : 'password'}
                      required
                      minLength={8}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Create password"
                      className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-cyan-500"
                    />
                    <button
                      type="button"
                      onClick={generateStrongPassword}
                      className="px-2.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-cyan-300 border border-slate-700 shrink-0"
                    >
                      Generate
                    </button>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Confirm Password
                  </label>
                  <div className="flex gap-1.5">
                    <input
                      type={showPassword ? 'text' : 'password'}
                      required
                      minLength={8}
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      placeholder="Repeat password"
                      className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-cyan-500"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="px-2.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 border border-slate-700 shrink-0"
                    >
                      {showPassword ? 'Hide' : 'Show'}
                    </button>
                  </div>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-xs text-amber-200 space-y-1">
                <strong className="block text-amber-300">
                  Monitored system notice.
                </strong>
                <span>
                  This platform is monitored for security, abuse prevention, and compliance review. Registration is limited to ethical and lawful investigative use.
                </span>
              </div>

              <label className="flex items-start gap-2.5 text-xs text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={acceptedTerms}
                  onChange={(e) => setAcceptedTerms(e.target.checked)}
                  className="mt-0.5 rounded border-slate-700 bg-slate-950 text-cyan-500"
                />
                <span>
                  I accept the{' '}
                  <button
                    type="button"
                    onClick={() => setShowTermsModal(true)}
                    className="text-cyan-400 underline hover:text-cyan-300 font-medium"
                  >
                    Terms and Conditions
                  </button>{' '}
                  for ethical and authorized OSINT use.
                </span>
              </label>

              <button
                type="submit"
                disabled={loading}
                className="w-full py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm transition flex items-center justify-center gap-2"
              >
                <UserPlus className="w-4 h-4" />
                {loading ? 'Creating Workspace...' : 'Create Account'}
              </button>
            </form>
          )}

          {activeTab === 'reset' && (
            <div className="space-y-5">
              <form onSubmit={handleRequestReset} className="space-y-3">
                <div>
                  <h2 className="text-lg font-semibold text-white">
                    Password Recovery
                  </h2>
                  <p className="text-xs text-slate-400">
                    Request a password reset token to rotate your credentials and invalidate active sessions.
                  </p>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Account Email
                  </label>
                  <div className="flex gap-2">
                    <input
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="analyst@organization.org"
                      className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
                    />
                    <button
                      type="submit"
                      disabled={loading}
                      className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-cyan-300 border border-slate-700 shrink-0"
                    >
                      Generate Token
                    </button>
                  </div>
                </div>
              </form>

              <form
                onSubmit={handleCompleteReset}
                className="space-y-3 pt-4 border-t border-slate-800"
              >
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Reset Token
                  </label>
                  <input
                    type="text"
                    required
                    value={resetTokenInput}
                    onChange={(e) => setResetTokenInput(e.target.value)}
                    placeholder="Paste reset token"
                    className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    New Password (min 8 characters)
                  </label>
                  <input
                    type="password"
                    required
                    minLength={8}
                    value={newResetPassword}
                    onChange={(e) => setNewResetPassword(e.target.value)}
                    placeholder="Enter new strong password"
                    className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
                  />
                </div>
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs flex items-center justify-center gap-2"
                >
                  <KeyRound className="w-4 h-4" />
                  Complete Password Reset
                </button>
              </form>
            </div>
          )}
        </div>
      </div>

      {/* Ethical Use Terms and Conditions Modal */}
      {showTermsModal && (
        <div
          className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4"
          role="dialog"
          aria-modal="true"
          aria-labelledby="termsTitle"
        >
          <div className="bg-[#0d1424] border border-slate-700 rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 id="termsTitle" className="text-base font-bold text-white">
                Ethical Use Terms and Conditions
              </h3>
              <button
                type="button"
                onClick={() => setShowTermsModal(false)}
                className="text-slate-400 hover:text-white text-sm font-bold"
              >
                ✕
              </button>
            </div>
            <div className="text-xs text-slate-300 space-y-2.5 leading-relaxed">
              <p>
                1. Sentinel OSINT is provided exclusively for lawful, authorized, and ethical open-source intelligence, defensive cybersecurity, and fraud-research activities.
              </p>
              <p>
                2. You agree not to use this platform for harassment, stalking, credential theft, unlawful surveillance, unauthorized active scanning, or any activity that violates privacy rights or applicable law.
              </p>
              <p>
                3. Account activity, submitted indicators, and operational audit logs are recorded for security governance, rate-limit enforcement, and compliance verification.
              </p>
              <p>
                4. Coincidental handle matches, passive network observations, and unrated hashes must be interpreted with explicit uncertainty and corroborated before operational action.
              </p>
            </div>
            <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => {
                  setAcceptedTerms(true);
                  setShowTermsModal(false);
                }}
                className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs"
              >
                Accept Ethical Use Terms
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
