import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { analysis } from '../services/api';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import LoadingState from '../components/LoadingState';
import EmptyState from '../components/EmptyState';
import ErrorState from '../components/ErrorState';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Search,
  Database,
  Globe,
  Hash as HashIcon,
  ExternalLink,
  Clock,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  Layers,
  Bot,
  RefreshCw,
  Lock,
  Server,
  Activity,
  Zap,
  Info,
  ChevronRight,
  FileCode,
} from 'lucide-react';

/**
 * Maps risk level to badge variants
 */
const getRiskBadgeVariant = (level) => {
  const norm = String(level || '').toUpperCase();
  if (norm === 'CRITICAL' || norm === 'HIGH') return 'danger';
  if (norm === 'MEDIUM') return 'warning';
  if (norm === 'LOW') return 'success';
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
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return '—';
  }
};

/**
 * List of extensible threat intelligence providers
 */
const EXTENSIBLE_PROVIDERS = [
  {
    id: 'virustotal',
    name: 'VirusTotal Multi-Engine',
    type: 'Reputation & Multi-AV Matrix',
    description: 'Aggregates 70+ antivirus engines, domain reputation blacklists, and community detection engines.',
    status: 'ACTIVE',
    badgeVariant: 'success',
    badgeLabel: 'Active Provider',
    icon: Shield,
    color: 'blue',
  },
  {
    id: 'hybrid_analysis',
    name: 'Hybrid Analysis',
    type: 'Dynamic Malware Sandbox',
    description: 'Automated dynamic execution sandbox detecting evasion techniques and process injection.',
    status: 'PLANNED',
    badgeVariant: 'neutral',
    badgeLabel: 'Coming later',
    icon: Activity,
    color: 'purple',
  },
  {
    id: 'malwarebazaar',
    name: 'MalwareBazaar (abuse.ch)',
    type: 'Malware Sample Repository',
    description: 'Community-driven repository collecting verified malware samples, hashes, and distribution signatures.',
    status: 'PLANNED',
    badgeVariant: 'neutral',
    badgeLabel: 'Coming later',
    icon: Database,
    color: 'emerald',
  },
  {
    id: 'urlhaus',
    name: 'URLhaus Threat Feed',
    type: 'Malicious URL Exchange',
    description: 'Real-time database tracking malicious URLs used for malware distribution and credential harvesting.',
    status: 'PLANNED',
    badgeVariant: 'neutral',
    badgeLabel: 'Coming later',
    icon: Globe,
    color: 'amber',
  },
  {
    id: 'abuseipdb',
    name: 'AbuseIPDB',
    type: 'IP Reputation & Abuse DB',
    description: 'Crowdsourced IP address reputation, port scanning reports, and brute-force tracking.',
    status: 'PLANNED',
    badgeVariant: 'neutral',
    badgeLabel: 'Coming later',
    icon: Server,
    color: 'orange',
  },
  {
    id: 'shodan',
    name: 'Shodan / Censys',
    type: 'Infrastructure & Port Recon',
    description: 'Internet-wide scanner intelligence for server banners, open ports, and SSL certificate telemetry.',
    status: 'PLANNED',
    badgeVariant: 'neutral',
    badgeLabel: 'Coming later',
    icon: Zap,
    color: 'slate',
  },
];

const ThreatIntelligence = () => {
  const navigate = useNavigate();

  // Query workspace state
  const [queryType, setQueryType] = useState('url'); // 'url' | 'hash'
  const [inputValue, setInputValue] = useState('');
  const [queryLoading, setQueryLoading] = useState(false);
  const [queryError, setQueryError] = useState(null);
  const [currentResult, setCurrentResult] = useState(null);

  // Recent history feeds
  const [recentIntel, setRecentIntel] = useState([]);
  const [recentLoading, setRecentLoading] = useState(true);
  const [recentError, setRecentError] = useState(null);

  // Fetch recent analyses for the intelligence feed
  const fetchRecentIntelligence = async () => {
    setRecentLoading(true);
    setRecentError(null);
    try {
      const data = await analysis.history(10);
      setRecentIntel(Array.isArray(data) ? data : []);
    } catch (err) {
      setRecentError(err?.message || 'Failed to retrieve recent intelligence records.');
    } finally {
      setRecentLoading(false);
    }
  };

  useEffect(() => {
    fetchRecentIntelligence();
  }, []);

  // Validate inputs client-side before dispatching to backend
  const validateInput = () => {
    const trimmed = inputValue.trim();
    if (!trimmed) {
      return 'Please enter a target to investigate.';
    }

    if (queryType === 'url') {
      try {
        const parsed = new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`);
        if (!parsed.hostname || !parsed.hostname.includes('.')) {
          return 'Please provide a valid URL or domain (e.g. example.com or https://example.com).';
        }
      } catch {
        return 'Please enter a valid URL (e.g. https://target-domain.com/path).';
      }
    } else if (queryType === 'hash') {
      const hexRegex = /^[a-fA-F0-9]+$/;
      if (!hexRegex.test(trimmed)) {
        return 'File hash must contain hexadecimal characters only (0-9, a-f).';
      }
      if (![32, 40, 64].includes(trimmed.length)) {
        return `Invalid hash length (${trimmed.length} chars). Expected MD5 (32), SHA-1 (40), or SHA-256 (64).`;
      }
    }

    return null;
  };

  // Submit query through backend analysis pipeline
  const handleQuerySubmit = async (e) => {
    if (e) e.preventDefault();
    const validationErr = validateInput();
    if (validationErr) {
      setQueryError(validationErr);
      return;
    }

    setQueryError(null);
    setQueryLoading(true);
    setCurrentResult(null);

    const trimmed = inputValue.trim();

    try {
      let response;
      if (queryType === 'url') {
        const targetUrl = trimmed.includes('://') ? trimmed : `https://${trimmed}`;
        response = await analysis.submitUrl(targetUrl);
      } else {
        response = await analysis.submitHash(trimmed);
      }

      setCurrentResult(response);
      // Refresh the recent list
      fetchRecentIntelligence();
    } catch (err) {
      setQueryError(err?.message || 'Failed to query threat intelligence. Please verify the target format.');
    } finally {
      setQueryLoading(false);
    }
  };

  // Extract VT details from result
  const extractVtIntel = (res) => {
    if (!res) return null;
    const details = res.details || {};
    return (
      details.virustotal ||
      details.vt_reputation ||
      (details.url_details && details.url_details.virustotal) ||
      details.vt ||
      null
    );
  };

  const vtData = extractVtIntel(currentResult);

  return (
    <div className="space-y-8 max-w-6xl mx-auto pb-12">
      {/* 1. Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
              Threat Intelligence
            </h1>
            <Badge variant="info">VirusTotal Integrated</Badge>
          </div>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            Investigate external reputation and intelligence signals associated with PHISHGUARD analyses.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            onClick={fetchRecentIntelligence}
            disabled={recentLoading}
            className="flex items-center gap-1.5 text-xs"
          >
            <RefreshCw size={13} className={recentLoading ? 'animate-spin' : ''} />
            <span>Refresh Feeds</span>
          </Button>
          <Button
            variant="primary"
            onClick={() => navigate('/analyze')}
            className="flex items-center gap-1.5 text-xs"
          >
            <span>Full Multi-Vector Scan</span>
            <ArrowRight size={13} />
          </Button>
        </div>
      </div>

      {/* 2. Primary Provider Status Banner */}
      <div className="p-5 rounded-xl bg-gradient-to-r from-blue-500/10 via-indigo-500/5 to-purple-500/10 border border-blue-200/60 dark:border-blue-800/40">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start gap-3.5">
            <div className="p-2.5 rounded-lg bg-blue-600 text-white shadow-sm shrink-0">
              <Shield size={22} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                  VirusTotal Multi-Vendor Threat Intelligence
                </h3>
                <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300">
                  ✓ Configured & Secure
                </span>
              </div>
              <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5 max-w-2xl">
                PHISHGUARD communicates with VirusTotal securely via backend service proxying. Secrets remain protected server-side with strict safe-failure semantics to prevent false negatives.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3 text-xs text-slate-500 dark:text-slate-400 font-mono self-start md:self-center shrink-0">
            <div className="flex items-center gap-1">
              <Lock size={12} className="text-emerald-600 dark:text-emerald-400" />
              <span>Zero Client Exposure</span>
            </div>
          </div>
        </div>
      </div>

      {/* 3. Interactive Threat Intelligence Query Workspace */}
      <Card
        title="Threat Intelligence Lookup"
        subtitle="Perform live URL reputation checks or payload hash intelligence queries"
      >
        <div className="space-y-5">
          {/* Query Type Selector Tabs */}
          <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-3">
            <button
              type="button"
              onClick={() => {
                setQueryType('url');
                setInputValue('');
                setQueryError(null);
              }}
              className={`flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-colors ${
                queryType === 'url'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              <Globe size={14} />
              <span>URL / Domain Reputation</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setQueryType('hash');
                setInputValue('');
                setQueryError(null);
              }}
              className={`flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-colors ${
                queryType === 'hash'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              <HashIcon size={14} />
              <span>File Hash Intelligence (SHA-256 / SHA-1 / MD5)</span>
            </button>
          </div>

          {/* Search Form */}
          <form onSubmit={handleQuerySubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                {queryType === 'url' ? 'Target URL or Hostname' : 'Artifact File Hash'}
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                  {queryType === 'url' ? <Globe size={16} /> : <HashIcon size={16} />}
                </div>
                <input
                  type="text"
                  value={inputValue}
                  onChange={(e) => {
                    setInputValue(e.target.value);
                    if (queryError) setQueryError(null);
                  }}
                  placeholder={
                    queryType === 'url'
                      ? 'e.g. https://auth-secure-login.suspicious.net/session'
                      : 'e.g. e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
                  }
                  disabled={queryLoading}
                  className="w-full pl-10 pr-24 py-2.5 rounded-xl text-xs font-mono bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                />
                <div className="absolute inset-y-0 right-1.5 flex items-center">
                  <Button
                    type="submit"
                    variant="primary"
                    disabled={queryLoading || !inputValue.trim()}
                    className="text-xs px-3.5 py-1.5 h-8 flex items-center gap-1.5"
                  >
                    {queryLoading ? (
                      <>
                        <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                        <span>Querying…</span>
                      </>
                    ) : (
                      <>
                        <Search size={13} />
                        <span>Lookup</span>
                      </>
                    )}
                  </Button>
                </div>
              </div>
              <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-1.5">
                {queryType === 'url'
                  ? 'Queries multi-engine reputation sources and evaluates known phishing signatures.'
                  : 'Supports SHA-256 (64 hex), SHA-1 (40 hex), and MD5 (32 hex) artifact checksums.'}
              </p>
            </div>

            {queryError && (
              <div className="p-3 rounded-lg bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900/60 text-xs text-red-700 dark:text-red-300 flex items-start gap-2">
                <AlertTriangle size={15} className="shrink-0 mt-0.5 text-red-600 dark:text-red-400" />
                <span>{queryError}</span>
              </div>
            )}
          </form>

          {/* Query Loading State */}
          {queryLoading && (
            <div className="py-6 border-t border-slate-100 dark:border-slate-800">
              <LoadingState message="Executing threat intelligence correlation through backend security proxy…" />
            </div>
          )}

          {/* Current Query Result View */}
          {currentResult && !queryLoading && (
            <div className="pt-4 border-t border-slate-200 dark:border-slate-800 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-xl bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700/60">
                <div className="space-y-1 min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-500">
                      Query Result
                    </span>
                    <Badge variant={getRiskBadgeVariant(currentResult.risk_level)}>
                      {currentResult.risk_level || 'ANALYZED'}
                    </Badge>
                    <span className="text-xs font-mono text-slate-400">
                      Score: {currentResult.risk_score ?? '—'}/100
                    </span>
                  </div>
                  <p className="text-xs font-mono font-bold text-slate-800 dark:text-slate-200 truncate">
                    {currentResult.url || currentResult.details?.url || currentResult.details?.hash || inputValue}
                  </p>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <Link
                    to={`/analysis/${currentResult.analysis_id || currentResult.id}`}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors shadow-sm"
                  >
                    <span>Full Forensics</span>
                    <ChevronRight size={13} />
                  </Link>
                  <Button
                    variant="primary"
                    onClick={() =>
                      navigate('/analyst', {
                        state: {
                          analysisId: currentResult.analysis_id || currentResult.id,
                          artifactType: currentResult.artifact_type || queryType,
                          target: currentResult.url || currentResult.details?.url || inputValue,
                        },
                      })
                    }
                    className="flex items-center gap-1.5 text-xs bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700"
                  >
                    <Bot size={13} />
                    <span>Ask AI Analyst</span>
                  </Button>
                </div>
              </div>

              {/* VirusTotal Telemetry Breakdown */}
              <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-4">
                <div className="flex items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800 pb-3">
                  <div className="flex items-center gap-2">
                    <Shield className="text-blue-600 dark:text-blue-400" size={18} />
                    <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                      VirusTotal Telemetry & Multi-AV Matrix
                    </h4>
                  </div>
                  {vtData && (
                    <Badge
                      variant={
                        vtData.malicious_count > 0 || vtData.malicious
                          ? 'danger'
                          : vtData.status === 'SUCCESS' || vtData.status === 'NOT_FOUND'
                          ? 'success'
                          : 'neutral'
                      }
                    >
                      {vtData.status || (vtData.malicious_count > 0 ? 'MALICIOUS' : 'CHECKED')}
                    </Badge>
                  )}
                </div>

                {!vtData ? (
                  <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/40 text-xs text-slate-500">
                    <p className="font-semibold text-slate-700 dark:text-slate-300">
                      No standalone VirusTotal block returned in response payload.
                    </p>
                    <p className="mt-0.5">
                      The core PHISHGUARD heuristics completed. View the full investigation for detailed signal correlation.
                    </p>
                  </div>
                ) : vtData.status === 'UNAVAILABLE' || vtData.status === 'ERROR' ? (
                  <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 text-xs text-slate-600 dark:text-slate-400 space-y-1">
                    <p className="font-semibold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                      <AlertTriangle size={14} className="text-amber-500" />
                      VirusTotal intelligence lookup unavailable
                    </p>
                    <p>
                      {vtData.error || 'Provider lookup was not available for this artifact. This is truthfully recorded as unverified rather than safe.'}
                    </p>
                  </div>
                ) : vtData.status === 'RATE_LIMITED' ? (
                  <div className="p-4 rounded-xl bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-900/50 text-xs text-amber-800 dark:text-amber-300 space-y-1">
                    <p className="font-semibold flex items-center gap-1.5">
                      <Clock size={14} />
                      VirusTotal Rate Limit Reached
                    </p>
                    <p>
                      The external reputation service quota has been reached. Heuristic analysis remains active.
                    </p>
                  </div>
                ) : vtData.status === 'NOT_FOUND' ? (
                  <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 text-xs text-slate-600 dark:text-slate-400 space-y-1">
                    <p className="font-semibold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                      <Info size={14} className="text-blue-500" />
                      Artifact Not Indexed in VirusTotal
                    </p>
                    <p>
                      VirusTotal has no prior record for this specific artifact. This means it has not been indexed yet, not that it is confirmed benign.
                    </p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                    <div className="p-3.5 rounded-xl bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/40">
                      <p className="text-[11px] font-semibold text-red-600 dark:text-red-400 uppercase tracking-wider">
                        Malicious Detections
                      </p>
                      <p className="text-2xl font-bold text-red-700 dark:text-red-300 mt-1">
                        {vtData.malicious_count ?? (vtData.malicious ? 1 : 0)} / {vtData.total_engines || 70}
                      </p>
                      <p className="text-[11px] text-red-500/80 dark:text-red-400/70 mt-0.5">
                        Security vendor flags
                      </p>
                    </div>

                    <div className="p-3.5 rounded-xl bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-900/40">
                      <p className="text-[11px] font-semibold text-amber-600 dark:text-amber-400 uppercase tracking-wider">
                        Suspicious Votes
                      </p>
                      <p className="text-2xl font-bold text-amber-700 dark:text-amber-300 mt-1">
                        {vtData.suspicious_count ?? (vtData.suspicious ? 1 : 0)}
                      </p>
                      <p className="text-[11px] text-amber-600/80 dark:text-amber-400/70 mt-0.5">
                        Heuristic flags
                      </p>
                    </div>

                    <div className="p-3.5 rounded-xl bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-900/40">
                      <p className="text-[11px] font-semibold text-emerald-600 dark:text-emerald-400 uppercase tracking-wider">
                        Clean / Harmless
                      </p>
                      <p className="text-2xl font-bold text-emerald-700 dark:text-emerald-300 mt-1">
                        {vtData.harmless_count ?? (vtData.total_engines ? vtData.total_engines - (vtData.malicious_count || 0) : '—')}
                      </p>
                      <p className="text-[11px] text-emerald-600/80 dark:text-emerald-400/70 mt-0.5">
                        Passing engines
                      </p>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </Card>

      {/* 4. Recent Intelligence Feed */}
      <Card
        title="Recent Intelligence Analyses"
        subtitle="Recent user-isolated scans evaluated against threat intelligence feeds"
      >
        {recentLoading ? (
          <LoadingState message="Loading recent intelligence feeds…" />
        ) : recentError ? (
          <ErrorState
            title="Failed to Load Feeds"
            message={recentError}
            onRetry={fetchRecentIntelligence}
          />
        ) : recentIntel.length === 0 ? (
          <EmptyState
            title="No intelligence records found"
            description="Run a URL or Hash query above to populate your threat intelligence activity feed."
            actionLabel="Run First Scan"
            onAction={() => {
              setQueryType('url');
              setInputValue('https://example.com');
            }}
          />
        ) : (
          <div className="divide-y divide-slate-100 dark:divide-slate-800">
            {recentIntel.map((item) => {
              const itemType = String(item.artifact_type || 'url').toLowerCase();
              const itemTarget = item.target || item.url || item.hash || `Investigation #${item.id || item.analysis_id}`;
              const itemId = item.id || item.analysis_id;

              return (
                <div
                  key={itemId}
                  className="py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-50 dark:hover:bg-slate-800/50 px-2 rounded-lg transition-colors"
                >
                  <div className="flex items-center gap-3 min-w-0 flex-1">
                    <div className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 shrink-0">
                      {itemType === 'url' ? (
                        <Globe size={16} />
                      ) : itemType === 'hash' || itemType === 'file' ? (
                        <HashIcon size={16} />
                      ) : (
                        <Shield size={16} />
                      )}
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                          {itemType}
                        </span>
                        <Badge variant={getRiskBadgeVariant(item.risk_level)}>
                          {item.risk_level || 'UNKNOWN'}
                        </Badge>
                        <span className="text-xs font-mono text-slate-400">
                          Score: {item.risk_score ?? '—'}/100
                        </span>
                      </div>
                      <p className="text-xs font-mono text-slate-800 dark:text-slate-200 truncate mt-0.5">
                        {itemTarget}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0 self-end sm:self-center">
                    <span className="text-[11px] text-slate-400 dark:text-slate-500 flex items-center gap-1">
                      <Clock size={11} />
                      {formatDateTime(item.created_at || item.timestamp)}
                    </span>
                    <Link
                      to={`/analysis/${itemId}`}
                      className="p-1.5 rounded-lg text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                      title="View Forensic Details"
                    >
                      <ArrowRight size={15} />
                    </Link>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Card>

      {/* 5. Extensible Threat Intelligence Sources Grid */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-bold text-slate-900 dark:text-slate-100">
            Threat Intelligence Sources & Providers
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Modular architecture supporting multi-vendor feeds and community telemetry engines.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {EXTENSIBLE_PROVIDERS.map((provider) => {
            const Icon = provider.icon;
            const isActive = provider.status === 'ACTIVE';

            return (
              <div
                key={provider.id}
                className={`p-5 rounded-xl border transition-all flex flex-col justify-between ${
                  isActive
                    ? 'bg-white dark:bg-slate-900 border-blue-200 dark:border-blue-800/60 shadow-sm ring-1 ring-blue-500/20'
                    : 'bg-slate-50/70 dark:bg-slate-900/40 border-slate-200 dark:border-slate-800 opacity-90'
                }`}
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between gap-2">
                    <div
                      className={`p-2 rounded-lg ${
                        isActive
                          ? 'bg-blue-100 dark:bg-blue-900/40 text-blue-600 dark:text-blue-400'
                          : 'bg-slate-200 dark:bg-slate-800 text-slate-500 dark:text-slate-400'
                      }`}
                    >
                      <Icon size={18} />
                    </div>
                    <Badge variant={provider.badgeVariant}>{provider.badgeLabel}</Badge>
                  </div>

                  <div>
                    <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                      {provider.name}
                    </h3>
                    <p className="text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                      {provider.type}
                    </p>
                  </div>

                  <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                    {provider.description}
                  </p>
                </div>

                <div className="pt-4 mt-3 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between text-xs">
                  {isActive ? (
                    <span className="text-emerald-600 dark:text-emerald-400 font-semibold flex items-center gap-1">
                      <CheckCircle2 size={13} />
                      Connected to Pipeline
                    </span>
                  ) : (
                    <span className="text-slate-400 dark:text-slate-500 font-mono">
                      Phase 2 Integration
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default ThreatIntelligence;
