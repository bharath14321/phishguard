import React, { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { analysis, mailSecurity } from '../services/api';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import LoadingState from '../components/LoadingState';
import EmptyState from '../components/EmptyState';
import ErrorState from '../components/ErrorState';
import {
  Link2,
  Hash,
  Mail,
  QrCode,
  FileCode,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
  Bot,
  Globe,
  Clock,
  Activity,
  ChevronRight,
  ExternalLink,
  Inbox,
  Radio,
  Zap,
} from 'lucide-react';

/**
 * Quick analysis action definitions
 */
const quickActions = [
  {
    mode: 'url',
    title: 'URL Analysis',
    description: 'Inspect links, redirect chains, domain age, typosquatting & reputation',
    icon: Link2,
    badge: 'Real-time',
    color: 'from-blue-600 to-cyan-600',
  },
  {
    mode: 'hash',
    title: 'Hash Lookup',
    description: 'Check MD5, SHA-1, and SHA-256 signatures against threat intelligence',
    icon: Hash,
    badge: 'Signatures',
    color: 'from-indigo-600 to-blue-600',
  },
  {
    mode: 'email',
    title: 'Email Inspector',
    description: 'Parse headers, SPF/DKIM/DMARC authentication & social engineering cues',
    icon: Mail,
    badge: 'Headers & EML',
    color: 'from-purple-600 to-indigo-600',
  },
  {
    mode: 'qr',
    title: 'QR Code Scanner',
    description: 'Decode and inspect embedded quishing payloads & obfuscated URLs',
    icon: QrCode,
    badge: 'Quishing',
    color: 'from-cyan-600 to-teal-600',
  },
  {
    mode: 'file',
    title: 'File Artifact',
    description: 'Scan suspicious documents, macros, archives, and executable attachments',
    icon: FileCode,
    badge: 'Static Analysis',
    color: 'from-slate-700 to-slate-900 dark:from-slate-600 dark:to-slate-800',
  },
];

/**
 * Map risk level to badge variants and styles
 */
const getRiskBadgeVariant = (level) => {
  const norm = String(level || '').toUpperCase();
  if (norm === 'CRITICAL' || norm === 'HIGH') return 'danger';
  if (norm === 'MEDIUM') return 'warning';
  if (norm === 'LOW' || norm === 'SAFE') return 'success';
  return 'neutral';
};

/**
 * Format timestamp safely
 */
const formatDateTime = (isoString) => {
  if (!isoString) return '—';
  try {
    const date = new Date(isoString);
    if (isNaN(date.getTime())) return '—';
    return date.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return '—';
  }
};

const Dashboard = () => {
  const { user } = useAuth();
  const navigate = useNavigate();

  const [stats, setStats] = useState(null);
  const [recentAnalyses, setRecentAnalyses] = useState([]);
  const [mailStats, setMailStats] = useState(null);
  const [mailAccounts, setMailAccounts] = useState([]);
  const [recentEmails, setRecentEmails] = useState([]);
  const [syncingAccountId, setSyncingAccountId] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchDashboardData = async () => {
    setLoading(true);
    setError(null);
    try {
      // Execute backend calls in parallel using existing endpoints
      const [statsData, recentData, mailStatsData, accountsData, messagesData] = await Promise.all([
        analysis.stats().catch((err) => {
          console.warn('Stats fetch warning:', err);
          return null;
        }),
        analysis.recent(10).catch((err) => {
          console.warn('Recent analyses fetch warning:', err);
          return [];
        }),
        mailSecurity.getStats().catch((err) => {
          console.warn('Mail stats fetch warning:', err);
          return null;
        }),
        mailSecurity.getAccounts().catch((err) => {
          console.warn('Mail accounts fetch warning:', err);
          return [];
        }),
        mailSecurity.getMessages({ limit: 5 }).catch((err) => {
          console.warn('Mail messages fetch warning:', err);
          return null;
        }),
      ]);

      setStats(statsData);
      setRecentAnalyses(Array.isArray(recentData) ? recentData : []);
      setMailStats(mailStatsData);
      setMailAccounts(Array.isArray(accountsData) ? accountsData : []);
      setRecentEmails(messagesData?.items || []);
    } catch (err) {
      setError(err?.message || 'Failed to load security dashboard telemetry.');
    } finally {
      setLoading(false);
    }
  };

  const handleSyncAccount = async (accId) => {
    setSyncingAccountId(accId);
    try {
      await mailSecurity.syncAccount(accId);
      await fetchDashboardData();
    } catch (err) {
      console.warn('Manual mailbox sync failed:', err);
    } finally {
      setSyncingAccountId(null);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const handleQuickAction = (mode) => {
    navigate('/analyze', { state: { mode } });
  };

  // Safe user presentation
  const displayName = user?.username || (user?.email ? user.email.split('@')[0] : 'Analyst');

  return (
    <div className="space-y-8">
      {/* 1. Header Section */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-200 dark:border-slate-800">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
              Security Overview
            </h1>
            <span className="px-2 py-0.5 text-xs font-semibold rounded-md bg-blue-100 text-blue-800 dark:bg-blue-900/60 dark:text-blue-300">
              SOC Live
            </span>
          </div>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Welcome back, <span className="font-semibold text-slate-700 dark:text-slate-200">{displayName}</span>. Monitor recent investigations and quickly analyze new suspicious artifacts.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <Button
            variant="secondary"
            onClick={fetchDashboardData}
            disabled={loading}
            className="flex items-center gap-1.5 text-xs"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </Button>
          <Button
            variant="primary"
            onClick={() => navigate('/analyze')}
            className="flex items-center gap-1.5 text-xs"
          >
            <ShieldAlert size={14} />
            <span>New Analysis</span>
          </Button>
        </div>
      </div>

      {/* Global Error Banner if initial fetch failed */}
      {error && (
        <ErrorState
          title="Telemetry Connection Issue"
          message={error}
          onRetry={fetchDashboardData}
        />
      )}

      {/* 2. Risk Overview (Real Statistics) */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
            Risk & Telemetry Metrics
          </h2>
          {stats && (
            <span className="text-xs text-slate-400 dark:text-slate-500">
              User-isolated telemetry
            </span>
          )}
        </div>

        {loading ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-28 rounded-xl bg-slate-100 dark:bg-slate-800/40 animate-pulse" />
            ))}
          </div>
        ) : stats && stats.total > 0 ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Total Analyzed */}
            <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm flex items-center justify-between">
              <div>
                <p className="text-xs font-medium text-slate-500 dark:text-slate-400">Total Analyzed</p>
                <p className="text-2xl font-bold text-slate-900 dark:text-slate-100 mt-1">{stats.total}</p>
                <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5">Recorded artifacts</p>
              </div>
              <div className="w-10 h-10 rounded-lg bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 flex items-center justify-center">
                <Activity size={20} />
              </div>
            </div>

            {/* High & Critical Threats */}
            <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm flex items-center justify-between">
              <div>
                <p className="text-xs font-medium text-slate-500 dark:text-slate-400">High / Critical</p>
                <p className="text-2xl font-bold text-red-600 dark:text-red-400 mt-1">{stats.high}</p>
                <p className="text-[11px] text-red-500/80 dark:text-red-400/80 mt-0.5">Actionable threats</p>
              </div>
              <div className="w-10 h-10 rounded-lg bg-red-50 dark:bg-red-950/60 text-red-600 dark:text-red-400 flex items-center justify-center">
                <ShieldAlert size={20} />
              </div>
            </div>

            {/* Medium Risk */}
            <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm flex items-center justify-between">
              <div>
                <p className="text-xs font-medium text-slate-500 dark:text-slate-400">Medium Suspicion</p>
                <p className="text-2xl font-bold text-amber-600 dark:text-amber-400 mt-1">{stats.medium}</p>
                <p className="text-[11px] text-amber-500/80 dark:text-amber-400/80 mt-0.5">Under investigation</p>
              </div>
              <div className="w-10 h-10 rounded-lg bg-amber-50 dark:bg-amber-950/60 text-amber-600 dark:text-amber-400 flex items-center justify-center">
                <AlertTriangle size={20} />
              </div>
            </div>

            {/* Low / Benign */}
            <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm flex items-center justify-between">
              <div>
                <p className="text-xs font-medium text-slate-500 dark:text-slate-400">Low / Benign</p>
                <p className="text-2xl font-bold text-emerald-600 dark:text-emerald-400 mt-1">{stats.low}</p>
                <p className="text-[11px] text-emerald-500/80 dark:text-emerald-400/80 mt-0.5">Safe indicators</p>
              </div>
              <div className="w-10 h-10 rounded-lg bg-emerald-50 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400 flex items-center justify-center">
                <ShieldCheck size={20} />
              </div>
            </div>
          </div>
        ) : (
          <div className="p-6 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-center">
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Risk statistics will appear after analyses are available.
            </p>
          </div>
        )}
      </div>

      {/* 2.5 Mailbox Protection & Continuous Ingestion Section */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
              Mail Security & Continuous Ingestion
            </h2>
            {mailAccounts.length > 0 ? (
              <span className="flex items-center gap-1 px-2 py-0.5 text-[11px] font-semibold rounded-md bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300">
                <Radio size={10} className="animate-pulse text-emerald-500" />
                {mailAccounts.length} Connected
              </span>
            ) : (
              <span className="px-2 py-0.5 text-[11px] font-semibold rounded-md bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400">
                0 Connected
              </span>
            )}
          </div>
          <Link
            to="/settings?category=integrations"
            className="text-xs font-semibold text-blue-600 dark:text-blue-400 hover:underline flex items-center gap-1"
          >
            <span>Mailbox Settings</span>
            <ChevronRight size={14} />
          </Link>
        </div>

        {mailAccounts.length === 0 ? (
          <div className="p-6 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 rounded-xl bg-red-50 dark:bg-red-950/50 text-red-600 dark:text-red-400 flex items-center justify-center shrink-0 border border-red-200 dark:border-red-900/50">
                <Mail size={24} />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  No Mailbox Connected
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-xl">
                  Connect your Google Workspace or Gmail mailbox in Settings to enable continuous inbox threat monitoring, automated RFC 822 ingestion, attachment sandbox scanning, and real-time phishing alerts.
                </p>
              </div>
            </div>
            <div className="shrink-0">
              <Button
                variant="primary"
                onClick={() => navigate('/settings?category=integrations')}
                className="flex items-center gap-2 text-xs"
              >
                <Zap size={14} />
                <span>Connect Gmail</span>
              </Button>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            {/* Mail Security Metric Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {/* Mailboxes */}
              <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm flex items-center justify-between">
                <div>
                  <p className="text-xs font-medium text-slate-500 dark:text-slate-400">Connected Mailboxes</p>
                  <p className="text-xl font-bold text-slate-900 dark:text-slate-100 mt-1">
                    {mailStats?.connected_mailboxes ?? mailAccounts.length}
                  </p>
                  <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5">Live Pub/Sub watches</p>
                </div>
                <div className="w-9 h-9 rounded-lg bg-indigo-50 dark:bg-indigo-950/60 text-indigo-600 dark:text-indigo-400 flex items-center justify-center">
                  <Inbox size={18} />
                </div>
              </div>

              {/* Total Ingested */}
              <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm flex items-center justify-between">
                <div>
                  <p className="text-xs font-medium text-slate-500 dark:text-slate-400">Emails Ingested</p>
                  <p className="text-xl font-bold text-slate-900 dark:text-slate-100 mt-1">
                    {mailStats?.total_scanned ?? 0}
                  </p>
                  <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5">Multi-layer evaluated</p>
                </div>
                <div className="w-9 h-9 rounded-lg bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 flex items-center justify-center">
                  <Mail size={18} />
                </div>
              </div>

              {/* Threats Detected */}
              <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm flex items-center justify-between">
                <div>
                  <p className="text-xs font-medium text-slate-500 dark:text-slate-400">Inbox Threats</p>
                  <p className="text-xl font-bold text-red-600 dark:text-red-400 mt-1">
                    {(mailStats?.phishing_count ?? 0) + (mailStats?.critical_count ?? 0)}
                  </p>
                  <p className="text-[11px] text-red-500/80 dark:text-red-400/80 mt-0.5">Phishing & High risk</p>
                </div>
                <div className="w-9 h-9 rounded-lg bg-red-50 dark:bg-red-950/60 text-red-600 dark:text-red-400 flex items-center justify-center">
                  <ShieldAlert size={18} />
                </div>
              </div>

              {/* Suspicious / Quishing */}
              <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm flex items-center justify-between">
                <div>
                  <p className="text-xs font-medium text-slate-500 dark:text-slate-400">Suspicious / Quishing</p>
                  <p className="text-xl font-bold text-amber-600 dark:text-amber-400 mt-1">
                    {(mailStats?.suspicious_count ?? 0) + (mailStats?.quishing_count ?? 0)}
                  </p>
                  <p className="text-[11px] text-amber-500/80 dark:text-amber-400/80 mt-0.5">
                    {mailStats?.last_sync ? `Synced ${formatDateTime(mailStats.last_sync)}` : 'Continuous'}
                  </p>
                </div>
                <div className="w-9 h-9 rounded-lg bg-amber-50 dark:bg-amber-950/60 text-amber-600 dark:text-amber-400 flex items-center justify-center">
                  <AlertTriangle size={18} />
                </div>
              </div>
            </div>

            {/* Connected Mailboxes Bar */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 shadow-sm">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100 dark:border-slate-800">
                <span className="text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider">
                  Active Connected Accounts
                </span>
                <span className="text-[11px] text-slate-400 dark:text-slate-500">
                  Protected with encrypted OAuth credentials & Pub/Sub push
                </span>
              </div>
              <div className="divide-y divide-slate-100 dark:divide-slate-800 mt-2">
                {mailAccounts.map((acc) => (
                  <div key={acc.id} className="py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <div className={`w-7 h-7 rounded-lg flex items-center justify-center text-white text-xs font-bold ${
                        acc.provider === 'gmail' ? 'bg-red-600' : 'bg-blue-600'
                      }`}>
                        {acc.provider === 'gmail' ? 'G' : 'M'}
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                            {acc.account_email}
                          </span>
                          <span className={`px-1.5 py-0.2 rounded text-[10px] font-semibold ${
                            acc.sync_status === 'connected'
                              ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300'
                              : 'bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300'
                          }`}>
                            {acc.sync_status === 'connected' ? (acc.has_watch ? 'Live Watch' : 'Connected') : (acc.sync_status || 'Disconnected')}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 dark:text-slate-500">
                          Scanned: {acc.total_scanned || 0} • Threats: {acc.threats_detected || 0} • Last sync: {formatDateTime(acc.last_synced_at)}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 self-end sm:self-auto">
                      <Button
                        variant="secondary"
                        onClick={() => handleSyncAccount(acc.id)}
                        disabled={syncingAccountId === acc.id}
                        className="px-2.5 py-1 text-xs font-medium flex items-center gap-1"
                      >
                        <RefreshCw size={12} className={syncingAccountId === acc.id ? 'animate-spin' : ''} />
                        <span>Sync Now</span>
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Recent Email Activity Table (if any) */}
            {recentEmails.length > 0 && (
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-sm overflow-hidden">
                <div className="px-4 py-3 bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider">
                    Recent Ingested Email Activity
                  </span>
                  <span className="text-[11px] text-slate-400 dark:text-slate-500">
                    Showing latest {recentEmails.length} messages
                  </span>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm" aria-label="Recent Email Activity">
                    <thead className="bg-slate-50/50 dark:bg-slate-800/30 text-slate-500 dark:text-slate-400 text-xs font-semibold uppercase border-b border-slate-200 dark:border-slate-800">
                      <tr>
                        <th scope="col" className="px-4 py-2.5">Provider</th>
                        <th scope="col" className="px-4 py-2.5">Sender</th>
                        <th scope="col" className="px-4 py-2.5">Subject</th>
                        <th scope="col" className="px-4 py-2.5">Classification</th>
                        <th scope="col" className="px-4 py-2.5">Risk Score</th>
                        <th scope="col" className="px-4 py-2.5">Received</th>
                        <th scope="col" className="px-4 py-2.5 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-slate-700 dark:text-slate-300">
                      {recentEmails.map((msg) => {
                        const riskVariant = getRiskBadgeVariant(msg.risk_level);
                        return (
                          <tr key={msg.id} className="hover:bg-slate-50/80 dark:hover:bg-slate-800/40 transition-colors">
                            <td className="px-4 py-2.5">
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 uppercase">
                                {msg.provider || 'EMAIL'}
                              </span>
                            </td>
                            <td className="px-4 py-2.5 text-xs text-slate-800 dark:text-slate-200 max-w-[140px] truncate" title={msg.sender_email}>
                              {msg.sender_name || msg.sender_email}
                            </td>
                            <td className="px-4 py-2.5 text-xs font-medium text-slate-900 dark:text-slate-100 max-w-[200px] truncate" title={msg.subject || '—'}>
                              {msg.subject || '—'}
                            </td>
                            <td className="px-4 py-2.5">
                              <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase ${
                                msg.status === 'processing'
                                  ? 'bg-blue-100 text-blue-800 dark:bg-blue-950/60 dark:text-blue-300 animate-pulse'
                                  : msg.status === 'failed'
                                  ? 'bg-red-200 text-red-900 dark:bg-red-950 dark:text-red-200'
                                  : msg.classification === 'phishing'
                                  ? 'bg-red-100 text-red-800 dark:bg-red-950/60 dark:text-red-300'
                                  : msg.classification === 'quishing'
                                  ? 'bg-purple-100 text-purple-800 dark:bg-purple-950/60 dark:text-purple-300'
                                  : msg.classification === 'suspicious'
                                  ? 'bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300'
                                  : 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300'
                              }`}>
                                {msg.status === 'processing' ? 'PROCESSING' : msg.status === 'failed' ? 'FAILED' : (msg.classification || 'CLEAN')}
                              </span>
                            </td>
                            <td className="px-4 py-2.5 text-xs font-semibold">
                              <span className={msg.risk_score >= 70 ? 'text-red-600 dark:text-red-400' : msg.risk_score >= 40 ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'}>
                                {typeof msg.risk_score === 'number' ? `${Math.round(msg.risk_score)}/100` : '—'}
                              </span>
                            </td>
                            <td className="px-4 py-2.5 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
                              {formatDateTime(msg.received_at || msg.created_at)}
                            </td>
                            <td className="px-4 py-2.5 text-right">
                              {msg.analysis_id ? (
                                <Button
                                  variant="secondary"
                                  onClick={() => navigate(`/analysis/${msg.analysis_id}`)}
                                  className="px-2.5 py-0.5 text-xs font-medium"
                                >
                                  View
                                </Button>
                              ) : (
                                <span className="text-xs text-slate-400">—</span>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* 3. Quick Analysis Actions */}
      <div>
        <div className="mb-3">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
            Quick Multi-Mode Analysis
          </h2>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
          {quickActions.map((action) => {
            const Icon = action.icon;
            return (
              <button
                key={action.mode}
                type="button"
                onClick={() => handleQuickAction(action.mode)}
                className="group relative flex flex-col justify-between p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-blue-500/50 dark:hover:border-blue-500/50 shadow-sm hover:shadow-md transition-all duration-200 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <div className={`w-10 h-10 rounded-lg bg-gradient-to-tr ${action.color} text-white flex items-center justify-center shadow-sm group-hover:scale-105 transition-transform`}>
                      <Icon size={20} />
                    </div>
                    <span className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
                      {action.badge}
                    </span>
                  </div>

                  <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                    {action.title}
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 line-clamp-2">
                    {action.description}
                  </p>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between text-xs font-semibold text-blue-600 dark:text-blue-400">
                  <span>Start Scan</span>
                  <ArrowRight size={14} className="group-hover:translate-x-1 transition-transform" />
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* 4. Recent Analyses Section */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
            Recent Investigations
          </h2>
          {recentAnalyses.length > 0 && (
            <Link
              to="/history"
              className="text-xs font-semibold text-blue-600 dark:text-blue-400 hover:underline flex items-center gap-1"
            >
              <span>View Full History</span>
              <ChevronRight size={14} />
            </Link>
          )}
        </div>

        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-sm overflow-hidden">
          {loading ? (
            <LoadingState message="Loading recent investigation records..." />
          ) : recentAnalyses.length === 0 ? (
            <EmptyState
              title="No analyses yet"
              description="You have not submitted any artifacts for inspection yet. Launch your first analysis to see real-time detection telemetry."
              action={
                <Button onClick={() => navigate('/analyze')} variant="primary" className="text-xs">
                  Start your first analysis
                </Button>
              }
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm" aria-label="Recent Investigations">
                <thead className="bg-slate-50 dark:bg-slate-800/50 text-slate-500 dark:text-slate-400 text-xs font-semibold uppercase border-b border-slate-200 dark:border-slate-800">
                  <tr>
                    <th scope="col" className="px-4 py-3">ID</th>
                    <th scope="col" className="px-4 py-3">Type</th>
                    <th scope="col" className="px-4 py-3">Artifact / Target</th>
                    <th scope="col" className="px-4 py-3">Risk Score</th>
                    <th scope="col" className="px-4 py-3">Risk Level</th>
                    <th scope="col" className="px-4 py-3">Timestamp</th>
                    <th scope="col" className="px-4 py-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-slate-700 dark:text-slate-300">
                  {recentAnalyses.map((item) => {
                    const riskVariant = getRiskBadgeVariant(item.risk_level);
                    return (
                      <tr
                        key={item.id}
                        className="hover:bg-slate-50/80 dark:hover:bg-slate-800/40 transition-colors"
                      >
                        <td className="px-4 py-3 font-mono text-xs font-semibold text-slate-500">
                          #{item.id}
                        </td>
                        <td className="px-4 py-3">
                          <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 uppercase">
                            {item.artifact_type || 'URL'}
                          </span>
                        </td>
                        <td className="px-4 py-3 font-mono text-xs max-w-xs truncate text-slate-800 dark:text-slate-200" title={item.url || '—'}>
                          {item.url || '—'}
                        </td>
                        <td className="px-4 py-3 text-xs font-semibold">
                          <span className={item.risk_score >= 70 ? 'text-red-600 dark:text-red-400' : item.risk_score >= 40 ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'}>
                            {typeof item.risk_score === 'number' ? `${Math.round(item.risk_score)}/100` : '—'}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <Badge variant={riskVariant}>
                            {item.risk_level || 'UNKNOWN'}
                          </Badge>
                        </td>
                        <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
                          {formatDateTime(item.created_at)}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <Button
                            variant="secondary"
                            onClick={() => navigate(`/analysis/${item.id}`)}
                            className="px-2.5 py-1 text-xs font-medium"
                          >
                            View
                          </Button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* 5. AI Analyst & Threat Intelligence Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* AI Security Analyst Prominent Card */}
        <div className="lg:col-span-2 p-6 rounded-xl bg-gradient-to-br from-blue-900/10 via-slate-900/5 to-purple-900/10 dark:from-blue-950/40 dark:via-slate-900 dark:to-purple-950/40 border border-blue-200 dark:border-blue-900/50 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-3">
              <div className="w-8 h-8 rounded-lg bg-blue-600 text-white flex items-center justify-center shadow-sm">
                <Bot size={18} />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  AI Security Analyst
                </h3>
                <span className="text-[11px] font-semibold text-blue-600 dark:text-blue-400 uppercase tracking-wider">
                  Explainable Assistant
                </span>
              </div>
            </div>

            <p className="text-sm text-slate-600 dark:text-slate-300 mb-4 max-w-xl">
              Ask questions about PHISHGUARD evidence, risk factors and investigation findings in natural language. The AI analyst is grounded strictly in authenticated scan telemetry.
            </p>
          </div>

          <div>
            <Button
              variant="primary"
              onClick={() => navigate('/analyst')}
              className="inline-flex items-center gap-2 text-xs"
            >
              <Bot size={14} />
              <span>Open AI Analyst</span>
            </Button>
          </div>
        </div>

        {/* Threat Intelligence Card */}
        <div className="p-6 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-3">
              <div className="w-8 h-8 rounded-lg bg-indigo-100 dark:bg-indigo-950 text-indigo-600 dark:text-indigo-400 flex items-center justify-center">
                <Globe size={18} />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  Threat Intelligence
                </h3>
                <span className="text-[11px] font-semibold text-indigo-600 dark:text-indigo-400 uppercase tracking-wider">
                  External Enrichment
                </span>
              </div>
            </div>

            <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
              PHISHGUARD enriches artifact investigations with external threat telemetry, including VirusTotal multi-engine scans and reputation feeds.
            </p>
          </div>

          <div>
            <Button
              variant="secondary"
              onClick={() => navigate('/threat-intelligence')}
              className="w-full justify-center text-xs"
            >
              <span>View Threat Intelligence</span>
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
