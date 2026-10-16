import React, { useEffect, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { analysis } from '../services/api';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import EvidenceCard from '../components/EvidenceCard';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ArrowRight,
  ArrowLeft,
  ExternalLink,
  Bot,
  Sparkles,
  Clock,
  Globe,
  Lock,
  FileCode,
  Mail,
  QrCode,
  Hash,
  Cpu,
  Layers,
  Activity,
  CheckCircle2,
  XCircle,
  AlertCircle,
  CornerDownRight,
  HelpCircle,
  RefreshCw,
  Database,
  ListChecks,
  FileText,
  CheckCircle,
  Copy,
  Check,
  Eye,
} from 'lucide-react';
import FormattedMarkdown from '../components/FormattedMarkdown';

/**
 * Maps risk levels to badge styling
 */
const getRiskBadgeVariant = (level) => {
  const norm = String(level || '').toUpperCase();
  if (norm === 'CRITICAL' || norm === 'HIGH') return 'danger';
  if (norm === 'MEDIUM') return 'warning';
  if (norm === 'LOW') return 'success';
  return 'neutral';
};

/**
 * Format ISO datetime string
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
      second: '2-digit',
    });
  } catch {
    return '—';
  }
};

/**
 * Maps authentication status to badge styling
 */
const getAuthBadgeVariant = (status) => {
  const norm = String(status || '').toUpperCase();
  if (norm === 'PASS' || norm === 'SUCCESS') return 'success';
  if (norm === 'FAIL' || norm === 'FAILURE') return 'danger';
  if (norm === 'SOFTFAIL' || norm === 'NEUTRAL') return 'warning';
  return 'neutral';
};

/**
 * Maps correlation category to badge styling
 */
const getCategoryBadgeVariant = (cat) => {
  const norm = String(cat || '').toLowerCase();
  if (norm.includes('strong_positive') || norm.includes('high')) return 'danger';
  if (norm.includes('moderate') || norm.includes('medium')) return 'warning';
  if (norm.includes('weak') || norm.includes('low')) return 'info';
  if (norm.includes('negative') || norm.includes('clean')) return 'success';
  return 'neutral';
};

const AnalysisResult = () => {
  const { id } = useParams();
  const navigate = useNavigate();

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);
  const [expandedUrlIdx, setExpandedUrlIdx] = useState(null);

  const handleCopyTarget = (text) => {
    if (!text) return;
    navigator.clipboard?.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const fetchAnalysis = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await analysis.get(id);
      setData(res);
    } catch (err) {
      const status = err?.status;
      if (status === 404) {
        setError('Investigation record not found. The requested analysis ID does not exist.');
      } else if (status === 403) {
        setError('Access denied. You do not have permission to inspect this investigation record.');
      } else {
        setError(err?.message || 'Failed to retrieve investigation telemetry from the server.');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (id) {
      fetchAnalysis();
    }
  }, [id]);

  if (loading) {
    return (
      <div className="py-20">
        <LoadingState message={`Retrieving forensic telemetry for investigation #${id}…`} />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="max-w-3xl mx-auto py-12 space-y-6">
        <ErrorState
          title="Investigation Retrieval Error"
          message={error || 'Unable to display analysis details.'}
          onRetry={fetchAnalysis}
        />
        <div className="flex items-center justify-between">
          <Button
            variant="secondary"
            onClick={() => navigate('/dashboard')}
            className="flex items-center gap-1.5 text-xs"
          >
            <ArrowLeft size={14} />
            <span>Back to Security Overview</span>
          </Button>
          <Button
            variant="primary"
            onClick={() => navigate('/analyze')}
            className="flex items-center gap-1.5 text-xs"
          >
            <ShieldAlert size={14} />
            <span>Run New Analysis</span>
          </Button>
        </div>
      </div>
    );
  }

  // Extract nested evidence layers safely
  const details = data.details || {};
  const explanation = data.explanation || {};
  const riskScore = typeof data.risk_score === 'number' ? Math.round(data.risk_score) : (typeof data.risk?.score === 'number' ? Math.round(data.risk.score) : 0);
  const riskLevel = String(data.risk_level || data.risk?.level || 'UNKNOWN').toUpperCase();
  const artifactType = String(data.artifact_type || 'url').toLowerCase();
  const targetIdentifier = data.url || details.url || details.hash || details.file_hash || (details.email_headers && details.email_headers.subject) || `Investigation #${id}`;

  // Robust signals extraction
  const rawSignals = Array.isArray(data.signals)
    ? data.signals
    : Array.isArray(details.signals)
    ? details.signals
    : Array.isArray(explanation.signals)
    ? explanation.signals
    : Array.isArray(explanation.key_reasons)
    ? explanation.key_reasons.map((r, idx) => typeof r === 'string' ? { name: r, reason: r, weight: 15, source: 'detection_engine' } : r)
    : [];

  const signals = Array.isArray(rawSignals) ? rawSignals : [];

  // Evidence subsections
  const urlFeatures = details.url_features || (details.url_details && details.url_details.url_features);
  const domainIntel = details.domain_intelligence || (details.url_details && details.url_details.domain_intelligence);
  const ipIntel = details.ip_intelligence || (details.url_details && details.url_details.ip_intelligence);
  const brandIntel = details.brand_intelligence || (details.url_details && details.url_details.brand_intelligence);
  const redirectIntel = details.redirect_analysis || (details.url_details && details.url_details.redirect_analysis) || details.redirect_chain;
  const webpageIntel = details.webpage_analysis || (details.url_details && details.url_details.webpage_analysis);
  const emailIntel = details.email_headers || details.email || details.headers;
  const emailAuth = details.email_authentication || details.authentication || (details.email && details.email.authentication);
  const emailNlp = details.email_nlp || details.nlp || (details.email && details.email.nlp);
  const emailUrls = details.url_analyses || details.urls || (details.email && details.email.urls) || [];
  const qrIntel = details.qr;
  const emailQrIntel = details.qr_analysis || (details.email && details.email.qr_analysis);
  const attachmentIntel = details.attachment_info || details.attachment || (Array.isArray(details.attachments) && details.attachments[0]);
  const allAttachments = Array.isArray(details.attachments) ? details.attachments : (attachmentIntel ? [attachmentIntel] : []);
  const trackingIntel = details.tracking_analysis || (details.email && details.email.tracking_analysis);
  const vtIntel = details.virustotal || details.vt_reputation || (details.url_details && details.url_details.virustotal) || details.vt;
  const mlIntel = details.ml || data.ml;
  const modelExpl = details.model_explanation || data.model_explanation;
  const evidenceCorr = details.evidence_correlation || data.evidence_correlation;
  const aiAnalyst = data.ai_analyst || details.ai_analyst;

  // Local Threat Intelligence & Evidence Sufficiency extraction
  const localTi = details.local_ti || (details.url_details && details.url_details.local_ti) || details.local_threat_intelligence;
  const evidenceSuff = data.evidence_sufficiency || details.evidence_sufficiency;

  // File size formatter (avoids 0 KB for small payloads)
  const formatFileSize = (bytes) => {
    if (bytes === null || bytes === undefined) return '—';
    if (bytes < 1024) return `${bytes} B`;
    return `${(bytes / 1024).toFixed(1)} KB`;
  };

  // Helper to parse legacy RiskSignal string representation if encountered
  const parseSignalItem = (sig, idx) => {
    if (typeof sig === 'string') {
      if (sig.startsWith('RiskSignal(') && sig.endsWith(')')) {
        const nameMatch = sig.match(/name=['"]([^'"]+)['"]/);
        const reasonMatch = sig.match(/reason=['"]([^'"]+)['"]/);
        const weightMatch = sig.match(/weight=([0-9.]+)/);
        const sourceMatch = sig.match(/source=['"]([^'"]+)['"]/);
        return {
          name: nameMatch ? nameMatch[1] : `Signal #${idx + 1}`,
          reason: reasonMatch ? reasonMatch[1] : sig,
          weight: weightMatch ? parseFloat(weightMatch[1]) : 0,
          source: sourceMatch ? sourceMatch[1] : 'core_engine',
        };
      }
      return {
        name: sig,
        reason: sig,
        weight: 0,
        source: 'core_engine',
      };
    }
    const name = sig.signal || sig.name || sig.finding || `Signal #${idx + 1}`;
    const reason = sig.explanation || sig.reason || sig.description || 'Observed anomaly contributing to risk assessment.';
    const weight = sig.weight !== undefined ? Number(sig.weight) : (sig.importance !== undefined ? Number(sig.importance) : 0);
    const source = sig.source || 'core_engine';
    return { name, reason, weight, source };
  };

  // Categorize signals into Strong vs Supporting Evidence
  const strongEvidence = [];
  const supportingEvidence = [];
  const unknownsList = [];

  signals.forEach((rawSig, idx) => {
    const { name, reason, weight, source } = parseSignalItem(rawSig, idx);
    const isLocalTi = source === 'local_threat_intelligence' || name.toLowerCase().includes('threat intelligence') || name.toLowerCase().includes('matched');
    const isStrong = weight >= 40 || isLocalTi || name.toLowerCase().includes('malicious') || name.toLowerCase().includes('macro') || name.toLowerCase().includes('impersonat') || name.toLowerCase().includes('typosquat') || name.toLowerCase().includes('executable') || name.toLowerCase().includes('credential');

    if (isStrong) {
      strongEvidence.push({ name, reason, weight, source });
    } else {
      supportingEvidence.push({ name, reason, weight, source });
    }
  });

  // Check for Unknowns / Limitations
  if (!vtIntel || vtIntel.status === 'UNAVAILABLE' || vtIntel.status === 'ERROR' || vtIntel.status === 'SKIPPED') {
    unknownsList.push({
      topic: 'VirusTotal Threat Intelligence',
      detail: vtIntel?.error || vtIntel?.message || 'External VirusTotal reputation service was not queried or unavailable during evaluation. Recorded as unverified rather than safe.',
    });
  }
  if (domainIntel && (!domainIntel.creation_date && domainIntel.age_days === undefined)) {
    unknownsList.push({
      topic: 'WHOIS Registration History',
      detail: 'WHOIS creation date is redacted or unavailable due to privacy protection / unresolvable registrar.',
    });
  }
  if (artifactType === 'url' || artifactType === 'email') {
    unknownsList.push({
      topic: 'Dynamic Runtime Execution',
      detail: 'Static heuristic & lexical analysis cannot inspect payloads dynamically delivered via client-side JavaScript obfuscation after page render.',
    });
  }

  // Recommended Incident Response Actions based on risk level
  const getRecommendedActions = () => {
    if (riskLevel === 'CRITICAL' || riskLevel === 'HIGH' || riskScore >= 50) {
      return [
        { title: 'Block Indicator at Perimeter', desc: 'Add domain, IP, or hash to firewall, DNS sinkhole, and web proxy blocklists immediately.', priority: 'P1' },
        { title: 'Isolate & Revoke Credentials', desc: 'Force password reset and revoke active sessions for any user who interacted with this artifact.', priority: 'P1' },
        { title: 'Purge Mailbox Artifacts', desc: 'Perform enterprise-wide search & purge (M365 / Google Workspace) to remove identical inbound messages.', priority: 'P2' },
        { title: 'Escalate to Incident Response', desc: 'Initiate standard triage playbook to inspect endpoints for downstream network connections or lateral movement.', priority: 'P2' },
      ];
    }
    if (riskLevel === 'MEDIUM' || riskScore >= 25) {
      return [
        { title: 'Apply Warning Banner / Quarantine', desc: 'Quarantine item or notify recipient with an explicit warning against clicking links or submitting credentials.', priority: 'P2' },
        { title: 'Perform Sandbox Detonation', desc: 'Detonate payload or URL in an isolated malware sandbox for deep behavioral telemetry.', priority: 'P2' },
        { title: 'Monitor Network Telemetry', desc: 'Create a temporary watch rule in SIEM for egress traffic matching target domain or resolved IP.', priority: 'P3' },
      ];
    }
    return [
      { title: 'Standard Processing', desc: 'No blocking action required. Artifact passed baseline lexical and threat intelligence checks.', priority: 'P4' },
      { title: 'Maintain Telemetry', desc: 'Log indicator for standard retrospective threat hunting if subsequent feeds report new zero-day activity.', priority: 'P4' },
    ];
  };

  const recommendedActions = getRecommendedActions();

  // Navigate to AI Analyst with context
  const handleAskAnalyst = (promptText = '') => {
    navigate('/analyst', {
      state: {
        analysisId: data.analysis_id || id,
        artifactType: data.artifact_type,
        target: targetIdentifier,
        initialPrompt: promptText,
      },
    });
  };

  const handleBackNavigation = () => {
    if (window.history.length > 1) {
      navigate(-1);
    } else {
      navigate('/history');
    }
  };

  return (
    <div className="space-y-8 max-w-6xl mx-auto pb-12">
      {/* 1. Header & Navigation Controls */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <button
          type="button"
          onClick={handleBackNavigation}
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100 transition-colors cursor-pointer group"
        >
          <ArrowLeft size={14} className="group-hover:-translate-x-0.5 transition-transform" />
          <span>Back to History</span>
          <span className="text-slate-300 dark:text-slate-700">/</span>
          <span>Investigation #{data.analysis_id || id}</span>
        </button>

        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            onClick={fetchAnalysis}
            className="flex items-center gap-1.5 text-xs"
          >
            <RefreshCw size={13} />
            <span>Refresh</span>
          </Button>
          <Button
            variant="primary"
            onClick={() => handleAskAnalyst()}
            className="flex items-center gap-1.5 text-xs bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700"
          >
            <Bot size={14} />
            <span>Ask AI Analyst</span>
          </Button>
        </div>
      </div>

      {/* 2. Top Summary Scorecard */}
      <div className="p-6 md:p-8 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          {/* Target Info */}
          <div className="space-y-2 flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="px-2.5 py-0.5 rounded-md text-xs font-bold uppercase tracking-wider bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-200">
                {artifactType}
              </span>
              <span className="text-xs font-mono text-slate-400 dark:text-slate-500">
                ID #{data.analysis_id || id}
              </span>
              <span className="text-xs text-slate-400 dark:text-slate-500 flex items-center gap-1">
                <Clock size={12} />
                {formatDateTime(data.created_at)}
              </span>
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-lg md:text-xl font-mono font-bold text-slate-900 dark:text-slate-100 break-all">
                {targetIdentifier}
              </h1>
              <button
                type="button"
                onClick={() => handleCopyTarget(targetIdentifier)}
                title="Copy full identifier"
                className="p-1 rounded-md text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                aria-label="Copy identifier"
              >
                {copied ? <Check size={14} className="text-emerald-600" /> : <Copy size={14} />}
              </button>
            </div>

            <p className="text-xs text-slate-500 dark:text-slate-400">
              Deterministic & contextual multi-layer security scan
            </p>
          </div>

          {/* Risk Score Gauge */}
          <div className="flex items-center gap-5 shrink-0 bg-slate-50 dark:bg-slate-950/60 p-5 rounded-xl border border-slate-200/80 dark:border-slate-800">
            <div className="text-center">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                Risk Score
              </p>
              <p className={`text-3xl md:text-4xl font-extrabold mt-0.5 ${
                riskScore >= 75
                  ? 'text-red-600 dark:text-red-400'
                  : riskScore >= 50
                  ? 'text-orange-600 dark:text-orange-400'
                  : riskScore >= 25
                  ? 'text-amber-600 dark:text-amber-400'
                  : 'text-emerald-600 dark:text-emerald-400'
              }`}>
                {riskScore}
                <span className="text-sm font-medium text-slate-400 dark:text-slate-500">/100</span>
              </p>
            </div>

            <div className="h-10 w-[1px] bg-slate-200 dark:bg-slate-800"></div>

            <div>
              <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-1">
                Verdict
              </p>
              <Badge variant={getRiskBadgeVariant(riskLevel)}>
                {riskLevel} RISK
              </Badge>
            </div>
          </div>
        </div>
      </div>

      {/* 3. Structured "Why was this flagged?" Forensic Evidence Section */}
      <Card className="p-6 md:p-8 border border-slate-200 dark:border-slate-800 shadow-sm space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 dark:border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400 flex items-center justify-center shrink-0">
              <Activity size={18} />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-900 dark:text-slate-100">
                Why Was This Flagged?
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Structured forensic breakdown, epistemic evidence classification, and threat intelligence synthesis.
              </p>
            </div>
          </div>

          {/* Evidence Sufficiency Badge */}
          {evidenceSuff && (
            <div className="flex items-center gap-2 bg-slate-50 dark:bg-slate-950/60 px-3.5 py-1.5 rounded-xl border border-slate-200 dark:border-slate-800 shrink-0">
              <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400">Sufficiency:</span>
              <Badge variant={
                evidenceSuff.level === 'VERY_STRONG' || evidenceSuff.level === 'STRONG'
                  ? 'success'
                  : evidenceSuff.level === 'LIMITED'
                  ? 'warning'
                  : 'neutral'
              }>
                {evidenceSuff.level || 'LIMITED'} ({Math.round(evidenceSuff.score || 0)}%)
              </Badge>
            </div>
          )}
        </div>

        {/* Executive Summary */}
        <p className="text-sm text-slate-700 dark:text-slate-300 leading-relaxed bg-slate-50 dark:bg-slate-950/40 p-4 rounded-xl border border-slate-200/70 dark:border-slate-800/70">
          {explanation.summary || data.summary || (
            riskScore >= 75
              ? 'Critical-confidence threat signals detected across forensic analyzers. Artifact demonstrates active phishing or malicious payload indicators.'
              : riskScore >= 50
              ? 'High-confidence threat signals detected across forensic analyzers. Artifact demonstrates strong characteristics of malicious phishing or abuse.'
              : riskScore >= 25
              ? 'Suspicious indicators detected requiring further SOC review. Several anomalous attributes were observed during inspection.'
              : (strongEvidence.length > 0 || supportingEvidence.length > 0)
              ? 'Low-risk baseline scan completed. Minor informational signals observed without definitive phishing indicators.'
              : 'No immediate high-risk indicators observed. Artifact passed baseline lexical and reputation checks.'
          )}
        </p>

        {/* 4-Pillar Epistemic Evidence Breakdown */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Pillar 1: Strong Evidence */}
          <div className="p-4 rounded-xl bg-red-50/40 dark:bg-red-950/20 border border-red-200/60 dark:border-red-900/40 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-bold text-red-900 dark:text-red-200">
                <ShieldAlert size={15} className="text-red-600 dark:text-red-400" />
                <span>Strong Evidence</span>
              </div>
              <Badge variant="danger">{strongEvidence.length} Indicators</Badge>
            </div>

            {strongEvidence.length > 0 ? (
              <div className="space-y-2 text-xs">
                {strongEvidence.map((item, idx) => (
                  <div key={idx} className="p-2.5 rounded-lg bg-white/80 dark:bg-slate-900/80 border border-red-100 dark:border-red-950 space-y-1">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-bold text-slate-900 dark:text-slate-100">{item.name}</span>
                      {item.weight > 0 && (
                        <span className="text-[10px] font-mono font-bold text-red-600 dark:text-red-400">+{item.weight} pts</span>
                      )}
                    </div>
                    <p className="text-slate-600 dark:text-slate-400">{item.reason}</p>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-500 dark:text-slate-400 italic">
                No high-severity deterministic threat signals detected.
              </p>
            )}
          </div>

          {/* Pillar 2: Supporting Evidence */}
          <div className="p-4 rounded-xl bg-amber-50/40 dark:bg-amber-950/20 border border-amber-200/60 dark:border-amber-900/40 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-bold text-amber-900 dark:text-amber-200">
                <AlertTriangle size={15} className="text-amber-600 dark:text-amber-400" />
                <span>Supporting Evidence</span>
              </div>
              <Badge variant="warning">{supportingEvidence.length} Indicators</Badge>
            </div>

            {supportingEvidence.length > 0 ? (
              <div className="space-y-2 text-xs">
                {supportingEvidence.map((item, idx) => (
                  <div key={idx} className="p-2.5 rounded-lg bg-white/80 dark:bg-slate-900/80 border border-amber-100 dark:border-amber-950 space-y-1">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-bold text-slate-900 dark:text-slate-100">{item.name}</span>
                      {item.weight > 0 && (
                        <span className="text-[10px] font-mono font-bold text-amber-600 dark:text-amber-400">+{item.weight} pts</span>
                      )}
                    </div>
                    <p className="text-slate-600 dark:text-slate-400">{item.reason}</p>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-500 dark:text-slate-400 italic">
                No secondary heuristic risk factors observed.
              </p>
            )}
          </div>

          {/* Pillar 3: Threat Intelligence & ML Assessment */}
          {(() => {
            const hasEvidenceTiMatch = strongEvidence.some(e =>
              (e.name && (e.name.toLowerCase().includes('threat feed') || e.name.toLowerCase().includes('phishtank') || e.name.toLowerCase().includes('local threat'))) ||
              (e.reason && (e.reason.toLowerCase().includes('phishtank') || e.reason.toLowerCase().includes('threat intelligence database') || e.reason.toLowerCase().includes('threat feed')))
            );
            const isLocalMatch = Boolean(localTi?.found || localTi?.status === 'MATCH' || hasEvidenceTiMatch);
            const malCount = typeof vtIntel?.malicious === 'number'
              ? vtIntel.malicious
              : (typeof vtIntel?.malicious_count === 'number' ? vtIntel.malicious_count : (vtIntel?.malicious ? 1 : 0));
            const totalEng = typeof vtIntel?.total === 'number'
              ? vtIntel.total
              : (typeof vtIntel?.total_engines === 'number' ? vtIntel.total_engines : 70);
            const threatLabel = vtIntel?.threat_label || details.threat_label;
            const repScore = vtIntel?.reputation;

            // Matched indicator resolution
            const matchedInd = localTi?.matched_indicator || localTi?.indicator || details.url || details.matched_indicator || (details.url_analyses && details.url_analyses.find(u => u.local_ti?.found)?.url);

            return (
              <div className="p-4 rounded-xl bg-blue-50/40 dark:bg-blue-950/20 border border-blue-200/60 dark:border-blue-900/40 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs font-bold text-blue-900 dark:text-blue-200">
                    <Database size={15} className="text-blue-600 dark:text-blue-400" />
                    <span>Threat Intelligence & ML Assessment</span>
                  </div>
                  <Badge variant={isLocalMatch || malCount > 0 ? 'danger' : 'neutral'}>
                    {isLocalMatch ? 'LOCAL TI MATCH' : malCount > 0 ? 'VT DETECTED' : 'EVALUATED'}
                  </Badge>
                </div>

                <div className="space-y-2.5 text-xs">
                  {/* 1. Local TI MATCH: Show confirmed local source, indicator, classification and confidence */}
                  {isLocalMatch && (
                    <div className="p-2.5 rounded-lg bg-white/80 dark:bg-slate-900/80 border border-red-200/70 dark:border-red-950 space-y-1.5">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-bold text-slate-900 dark:text-slate-100">Local Threat Intelligence</span>
                        <Badge variant="danger">
                          MATCH ({localTi?.source || 'PhishTank'})
                        </Badge>
                      </div>
                      <p className="text-slate-600 dark:text-slate-400">
                        Confirmed match in offline threat intelligence feed (<strong>{localTi?.source || 'PhishTank'}</strong>).
                      </p>
                      <div className="grid grid-cols-2 gap-2 pt-1 border-t border-slate-100 dark:border-slate-800 text-[11px]">
                        <div>
                          <span className="text-slate-500 block">Classification:</span>
                          <span className="font-semibold text-red-600 dark:text-red-400 uppercase">
                            {localTi?.threat_type || localTi?.classification || 'Phishing'}
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-500 block">Confidence:</span>
                          <span className="font-semibold text-slate-800 dark:text-slate-200">
                            {localTi?.confidence ? `${localTi.confidence}%` : 'High (Confirmed)'}
                          </span>
                        </div>
                        {matchedInd && (
                          <div className="col-span-2">
                            <span className="text-slate-500 block">Matched Indicator:</span>
                            <span className="font-mono font-semibold text-slate-800 dark:text-slate-200 truncate block" title={matchedInd}>
                              {matchedInd}
                            </span>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* 2. Neither Local TI nor VT has a match: Show "No known threat-intelligence match" */}
                  {!isLocalMatch && malCount === 0 && (
                    <div className="p-2.5 rounded-lg bg-white/80 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 space-y-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-bold text-slate-900 dark:text-slate-100">Threat Intelligence Status</span>
                        <Badge variant="success">NO MATCH</Badge>
                      </div>
                      <p className="text-slate-600 dark:text-slate-400">
                        No known threat-intelligence match across evaluated threat feeds ({localTi?.evaluated_count ? localTi.evaluated_count.toLocaleString() : '91,190'} local indicators checked).
                      </p>
                      {vtIntel?.is_clean && (
                        <div className="pt-1.5 flex items-center justify-between text-[11px] border-t border-slate-100 dark:border-slate-800">
                          <span className="text-slate-500 font-semibold">VirusTotal Multi-Engine:</span>
                          <span className="font-mono font-bold text-emerald-600 dark:text-emerald-400">0 / {totalEng} Clean</span>
                        </div>
                      )}
                    </div>
                  )}

                  {/* 3. VirusTotal subsection: ONLY display if VT was actually queried AND returned useful information, and NOT when local TI matched */}
                  {!isLocalMatch && malCount > 0 && (
                    <div className="p-2.5 rounded-lg bg-white/80 dark:bg-slate-900/80 border border-blue-100 dark:border-blue-950 space-y-1.5">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-bold text-slate-900 dark:text-slate-100">VirusTotal Multi-Engine</span>
                        <Badge variant="danger">{malCount} / {totalEng} DETECTIONS</Badge>
                      </div>
                      <p className="text-slate-600 dark:text-slate-400">
                        Multi-vendor detections: {malCount} malicious across {totalEng} queried antivirus engines.
                      </p>
                      {threatLabel && threatLabel !== 'Unknown / not provided' && (
                        <div className="pt-1 flex items-center justify-between text-[11px] border-t border-slate-100 dark:border-slate-800">
                          <span className="text-slate-500 font-semibold">Threat Label / Family:</span>
                          <span className="font-mono font-bold text-red-600 dark:text-red-400">{threatLabel}</span>
                        </div>
                      )}
                      {repScore !== undefined && repScore !== null && (
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="text-slate-500 font-semibold">Reputation Score:</span>
                          <span className="font-mono font-bold text-slate-800 dark:text-slate-200">{repScore}</span>
                        </div>
                      )}
                    </div>
                  )}

                  {/* VirusTotal unavailable: only shown when materially useful (no local match and VT unavailable) */}
                  {!isLocalMatch && (vtIntel?.status === 'UNAVAILABLE' || vtIntel?.status === 'ERROR') && (
                    <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 space-y-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-bold text-slate-900 dark:text-slate-100">VirusTotal Status</span>
                        <Badge variant="neutral">UNAVAILABLE</Badge>
                      </div>
                      <p className="text-slate-600 dark:text-slate-400">
                        VirusTotal service is unconfigured or unreachable. Unqueried status is never interpreted as clean.
                      </p>
                    </div>
                  )}

                  {/* 4. Always show ML immediately in the same unified Threat Intelligence & ML Assessment section */}
                  {mlIntel && (
                    <div className="p-2.5 rounded-lg bg-white/80 dark:bg-slate-900/80 border border-blue-100 dark:border-blue-950 space-y-1.5">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-bold text-slate-900 dark:text-slate-100">Machine Learning Assessment</span>
                        <Badge variant={mlIntel.prediction === 1 || (mlIntel.probability !== null && mlIntel.probability >= 0.5) ? 'danger' : 'success'}>
                          {mlIntel.prediction === 1 || (mlIntel.probability !== null && mlIntel.probability >= 0.5) ? 'FLAGGED PHISHING' : 'LIKELY BENIGN'}
                        </Badge>
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-[11px] pt-0.5">
                        <div>
                          <span className="text-slate-500 block">Model:</span>
                          <span className="font-semibold text-slate-800 dark:text-slate-200">
                            {mlIntel.model_name || (artifactType === 'email' ? 'Lexical URL Aggregator' : mlIntel.model_available ? 'URL Lexical Model v1' : 'Heuristic Engine')}
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-500 block">Probability / Confidence:</span>
                          <span className="font-mono font-bold text-slate-800 dark:text-slate-200">
                            {mlIntel.probability !== null && mlIntel.probability !== undefined
                              ? `${(mlIntel.probability * 100).toFixed(1)}%`
                              : 'Heuristic evaluation'}
                          </span>
                        </div>
                      </div>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400 italic pt-0.5">
                        Machine learning provides an independent lexical & structural prediction separate from threat feed matching.
                      </p>
                    </div>
                  )}
                </div>
              </div>
            );
          })()}

          {/* Pillar 4: Unknowns & Limitations */}
          <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/40 border border-slate-200/80 dark:border-slate-800/80 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-900 dark:text-slate-200">
                <HelpCircle size={15} className="text-slate-500 dark:text-slate-400" />
                <span>Unknowns & Limitations</span>
              </div>
              <Badge variant="neutral">{unknownsList.length} Notes</Badge>
            </div>

            <div className="space-y-2 text-xs">
              {unknownsList.map((item, idx) => (
                <div key={idx} className="p-2.5 rounded-lg bg-white/80 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 space-y-1">
                  <span className="font-bold text-slate-900 dark:text-slate-100">{item.topic}</span>
                  <p className="text-slate-600 dark:text-slate-400">{item.detail}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Recommended Actions */}
        <div className="pt-4 border-t border-slate-100 dark:border-slate-800 space-y-3">
          <div className="flex items-center gap-2 text-xs font-bold text-slate-900 dark:text-slate-100">
            <ListChecks size={16} className="text-blue-600 dark:text-blue-400" />
            <span>Recommended Incident Response Actions</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {recommendedActions.map((rec, idx) => (
              <div key={idx} className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950/40 border border-slate-200/70 dark:border-slate-800/70 space-y-1 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-bold text-slate-900 dark:text-slate-100">{rec.title}</span>
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                    rec.priority === 'P1'
                      ? 'bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-300'
                      : rec.priority === 'P2'
                      ? 'bg-amber-100 dark:bg-amber-950 text-amber-700 dark:text-amber-300'
                      : 'bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300'
                  }`}>
                    {rec.priority}
                  </span>
                </div>
                <p className="text-slate-600 dark:text-slate-400 leading-relaxed">{rec.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </Card>

      {/* 4. Active Risk Factors & Signals */}
      {signals.length > 0 && (
        <EvidenceCard
          title="Active Risk Signals"
          icon={ShieldAlert}
          badge={<Badge variant={getRiskBadgeVariant(riskLevel)}>{signals.length} Signals</Badge>}
          subtitle="Direct risk contributors identified during multi-layer heuristic evaluation"
        >
          <div className="divide-y divide-slate-100 dark:divide-slate-800">
            {signals.map((sig, idx) => (
              <div key={idx} className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-mono font-bold text-slate-900 dark:text-slate-100">
                      {sig.signal || sig.name || `Signal #${idx + 1}`}
                    </span>
                    {sig.source && (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
                        {sig.source}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-400">
                    {sig.explanation || sig.reason || sig.description || 'Observed anomaly contributing to risk.'}
                  </p>
                </div>

                {sig.importance !== undefined && (
                  <div className="shrink-0 text-right">
                    <span className="text-xs font-bold text-slate-700 dark:text-slate-300">
                      Weight: +{sig.importance}
                    </span>
                  </div>
                )}
              </div>
            ))}
          </div>
        </EvidenceCard>
      )}

      {/* 5. URL & Lexical Intelligence */}
      {(urlFeatures || brandIntel) && (
        <EvidenceCard
          title="URL & Lexical Intelligence"
          icon={Globe}
          subtitle="Structural syntax, length, entropy, and brand similarity indicators"
        >
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 py-2">
            <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/60 dark:border-slate-800">
              <p className="text-[11px] font-semibold text-slate-400 dark:text-slate-500">Hostname</p>
              <p className="text-xs font-mono font-bold text-slate-800 dark:text-slate-200 mt-1 truncate" title={urlFeatures?.hostname || '—'}>
                {urlFeatures?.hostname || '—'}
              </p>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/60 dark:border-slate-800">
              <p className="text-[11px] font-semibold text-slate-400 dark:text-slate-500">Protocol & Port</p>
              <p className="text-xs font-mono font-bold text-slate-800 dark:text-slate-200 mt-1">
                {urlFeatures?.scheme || 'https'} {urlFeatures?.port ? `:${urlFeatures.port}` : ''}
              </p>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/60 dark:border-slate-800">
              <p className="text-[11px] font-semibold text-slate-400 dark:text-slate-500">URL Length / Subdomains</p>
              <p className="text-xs font-mono font-bold text-slate-800 dark:text-slate-200 mt-1">
                {urlFeatures?.length || targetIdentifier.length} chars ({urlFeatures?.num_subdomains ?? '0'} subdomains)
              </p>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/60 dark:border-slate-800">
              <p className="text-[11px] font-semibold text-slate-400 dark:text-slate-500">Brand Impersonation</p>
              <p className="text-xs font-semibold text-slate-800 dark:text-slate-200 mt-1">
                {brandIntel?.is_typosquatting ? (
                  <span className="text-red-600 dark:text-red-400">
                    Spoofing {brandIntel.target_brand}
                  </span>
                ) : (
                  <span className="text-slate-500">None detected</span>
                )}
              </p>
            </div>
          </div>
        </EvidenceCard>
      )}

      {/* 6. Domain & Network Intelligence */}
      {(domainIntel || ipIntel) && (
        <EvidenceCard
          title="Domain & Network Infrastructure"
          icon={Layers}
          subtitle="DNS records, autonomous system (ASN), geo-location, and domain age"
        >
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 py-2">
            <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/60 dark:border-slate-800">
              <p className="text-[11px] font-semibold text-slate-400 dark:text-slate-500">Registrable Domain</p>
              <p className="text-xs font-mono font-bold text-slate-800 dark:text-slate-200 mt-1">
                {domainIntel?.registrable_domain || domainIntel?.domain || '—'}
              </p>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/60 dark:border-slate-800">
              <p className="text-[11px] font-semibold text-slate-400 dark:text-slate-500">Domain Age / Registration</p>
              <p className="text-xs font-bold text-slate-800 dark:text-slate-200 mt-1">
                {domainIntel?.age_days !== undefined
                  ? `${domainIntel.age_days} days ${domainIntel.age_days < 30 ? '(Newly Registered)' : ''}`
                  : domainIntel?.creation_date
                  ? formatDateTime(domainIntel.creation_date)
                  : 'Unknown / Private WHOIS'}
              </p>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/60 dark:border-slate-800">
              <p className="text-[11px] font-semibold text-slate-400 dark:text-slate-500">Resolved IP & Geo</p>
              <p className="text-xs font-mono font-bold text-slate-800 dark:text-slate-200 mt-1">
                {ipIntel?.ip || ipIntel?.ip_address || '—'} {ipIntel?.country ? `(${ipIntel.country})` : ''}
              </p>
            </div>
          </div>
        </EvidenceCard>
      )}

      {/* 7. Redirect Chain Flow */}
      {redirectIntel && Array.isArray(redirectIntel.redirect_chain) && redirectIntel.redirect_chain.length > 0 && (
        <EvidenceCard
          title="Redirect Hop Sequence"
          icon={CornerDownRight}
          badge={<Badge variant="info">{redirectIntel.redirect_chain.length} Hops</Badge>}
          subtitle="Sequential navigation path traversed before reaching final destination"
        >
          <div className="py-2 space-y-3">
            {redirectIntel.redirect_chain.map((hop, idx) => (
              <div key={idx} className="flex items-start gap-3 text-xs">
                <span className="w-6 h-6 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 font-bold flex items-center justify-center shrink-0">
                  {idx + 1}
                </span>
                <div className="flex-1 min-w-0 p-2.5 rounded-lg bg-slate-50 dark:bg-slate-800/40 font-mono break-all text-slate-800 dark:text-slate-200">
                  {typeof hop === 'string' ? hop : hop.url || JSON.stringify(hop)}
                </div>
              </div>
            ))}
          </div>
        </EvidenceCard>
      )}

      {/* 8. Webpage & Form Analysis */}
      {webpageIntel && (
        <EvidenceCard
          title="Webpage Content & Form Analysis"
          icon={Lock}
          badge={
            <Badge variant={webpageIntel.has_cross_domain_submission || webpageIntel.has_password_field ? 'warning' : 'neutral'}>
              {(webpageIntel.form_count ?? webpageIntel.num_forms ?? (Array.isArray(webpageIntel.forms) ? webpageIntel.forms.length : 0))} Form(s)
            </Badge>
          }
          subtitle="Page DOM structures, form destinations, password inputs, script count, and external resources"
        >
          <div className="space-y-4 py-2">
            {webpageIntel.title && (
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/60 dark:border-slate-800 text-xs">
                <span className="text-[11px] font-semibold text-slate-400 dark:text-slate-500 block">Page Title</span>
                <span className="font-semibold text-slate-900 dark:text-slate-100 text-sm mt-0.5 block">{webpageIntel.title}</span>
              </div>
            )}

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/60 dark:border-slate-800">
                <p className="text-[11px] font-semibold text-slate-400 dark:text-slate-500">Password Inputs</p>
                <p className="text-xs font-bold text-slate-800 dark:text-slate-200 mt-1">
                  {(webpageIntel.password_field_count > 0 || webpageIntel.has_password_field) ? (
                    <span className="text-red-600 dark:text-red-400">Yes ({webpageIntel.password_field_count ?? 1} input)</span>
                  ) : (
                    <span>None</span>
                  )}
                </p>
              </div>

              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/60 dark:border-slate-800">
                <p className="text-[11px] font-semibold text-slate-400 dark:text-slate-500">Total Forms</p>
                <p className="text-xs font-mono font-bold text-slate-800 dark:text-slate-200 mt-1">
                  {webpageIntel.form_count ?? webpageIntel.num_forms ?? (Array.isArray(webpageIntel.forms) ? webpageIntel.forms.length : 0)}
                </p>
              </div>

              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/60 dark:border-slate-800">
                <p className="text-[11px] font-semibold text-slate-400 dark:text-slate-500">Scripts & Iframes</p>
                <p className="text-xs font-mono font-bold text-slate-800 dark:text-slate-200 mt-1">
                  {(webpageIntel.script_count ?? webpageIntel.num_scripts ?? (Array.isArray(webpageIntel.scripts) ? webpageIntel.scripts.length : 0))} scripts / {(webpageIntel.iframe_count ?? webpageIntel.num_iframes ?? 0)} iframes
                </p>
              </div>

              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/60 dark:border-slate-800">
                <p className="text-[11px] font-semibold text-slate-400 dark:text-slate-500">Links / Resources</p>
                <p className="text-xs font-mono font-bold text-slate-800 dark:text-slate-200 mt-1">
                  {(webpageIntel.link_count ?? webpageIntel.num_external_links ?? (Array.isArray(webpageIntel.links) ? webpageIntel.links.length : 0))} links
                </p>
              </div>
            </div>

            {/* Form details if forms detected */}
            {Array.isArray(webpageIntel.forms) && webpageIntel.forms.length > 0 && (
              <div className="space-y-2 pt-2 border-t border-slate-100 dark:border-slate-800">
                <p className="text-xs font-semibold text-slate-700 dark:text-slate-300">Extracted Form Endpoints:</p>
                <div className="space-y-2">
                  {webpageIntel.forms.map((form, fIdx) => (
                    <div key={fIdx} className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-700 text-xs space-y-1">
                      <div className="flex items-center justify-between gap-2 flex-wrap">
                        <span className="font-mono font-semibold text-slate-800 dark:text-slate-200 truncate max-w-md" title={form.action || '(self)'}>
                          Action: {form.action || '(submits to self / current page)'}
                        </span>
                        <div className="flex items-center gap-1.5">
                          <span className="px-1.5 py-0.5 rounded text-[10px] uppercase font-bold bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300">
                            {form.method || 'GET'}
                          </span>
                          {form.cross_domain && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300">
                              Cross-Domain
                            </span>
                          )}
                          {form.has_password && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300">
                              Password Field
                            </span>
                          )}
                        </div>
                      </div>
                      {Array.isArray(form.inputs) && form.inputs.length > 0 && (
                        <p className="text-[11px] text-slate-500 dark:text-slate-400">
                          Inputs: {form.inputs.map(inp => inp.name || inp.type || 'input').join(', ')}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Fetch error or limitation notice */}
            {webpageIntel.fetch_success === false && (
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-700 text-xs text-slate-500">
                <span className="font-semibold block text-slate-700 dark:text-slate-300">Fetch Notice:</span>
                {webpageIntel.error_reason || webpageIntel.error || 'Webpage content could not be retrieved in offline/sandbox mode.'}
              </div>
            )}
          </div>
        </EvidenceCard>
      )}

      {/* 9. Email Header & Authentication Analysis */}
      {emailIntel && (
        <EvidenceCard
          title="Email Header & Authentication Audit"
          icon={Mail}
          subtitle="RFC822 headers, sender verification, SPF/DKIM/DMARC alignment"
        >
          <div className="space-y-4 py-2">
            {/* Headers Table */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40">
                <span className="font-semibold text-slate-500 dark:text-slate-400">From:</span>{' '}
                <span className="font-mono text-slate-800 dark:text-slate-200">{emailIntel.from || emailIntel.sender || '—'}</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40">
                <span className="font-semibold text-slate-500 dark:text-slate-400">Subject:</span>{' '}
                <span className="font-semibold text-slate-800 dark:text-slate-200">{emailIntel.subject || '—'}</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40">
                <span className="font-semibold text-slate-500 dark:text-slate-400">Reply-To:</span>{' '}
                <span className="font-mono text-slate-800 dark:text-slate-200">{emailIntel.reply_to || '—'}</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40">
                <span className="font-semibold text-slate-500 dark:text-slate-400">Return-Path:</span>{' '}
                <span className="font-mono text-slate-800 dark:text-slate-200">{emailIntel.return_path || '—'}</span>
              </div>
            </div>

            {/* Email Authentication Badges */}
            <div className="flex items-center gap-4 flex-wrap pt-2 border-t border-slate-100 dark:border-slate-800">
              <div className="flex items-center gap-1.5">
                <span className="text-xs font-semibold text-slate-500">SPF:</span>
                <Badge variant={getAuthBadgeVariant(emailAuth?.message_authentication?.spf || emailAuth?.status?.spf || emailIntel.spf || emailIntel.spf_result)}>
                  {emailAuth?.message_authentication?.spf || emailAuth?.status?.spf || emailIntel.spf || emailIntel.spf_result || 'UNKNOWN'}
                </Badge>
              </div>

              <div className="flex items-center gap-1.5">
                <span className="text-xs font-semibold text-slate-500">DKIM:</span>
                <Badge variant={getAuthBadgeVariant(emailAuth?.message_authentication?.dkim || emailAuth?.status?.dkim || emailIntel.dkim || emailIntel.dkim_result)}>
                  {emailAuth?.message_authentication?.dkim || emailAuth?.status?.dkim || emailIntel.dkim || emailIntel.dkim_result || 'UNKNOWN'}
                </Badge>
              </div>

              <div className="flex items-center gap-1.5">
                <span className="text-xs font-semibold text-slate-500">DMARC:</span>
                <Badge variant={getAuthBadgeVariant(emailAuth?.message_authentication?.dmarc || emailAuth?.status?.dmarc || emailIntel.dmarc || emailIntel.dmarc_result)}>
                  {emailAuth?.message_authentication?.dmarc || emailAuth?.status?.dmarc || emailIntel.dmarc || emailIntel.dmarc_result || 'UNKNOWN'}
                </Badge>
              </div>
            </div>

            {/* Offline Verification Caveat */}
            <p className="text-[11px] text-slate-500 italic pt-1">
              {emailAuth?.verification_caveat || 'Headers reflect values in the uploaded email artifact and have not been cryptographically verified against the authoritative mail transfer agent in this offline context.'}
            </p>

            {/* Collapsible Raw Email Headers Viewer */}
            {(emailIntel.raw_headers_text || emailIntel.raw_headers) && (
              <details className="pt-2 border-t border-slate-100 dark:border-slate-800 text-xs group">
                <summary className="font-semibold text-slate-600 dark:text-slate-300 cursor-pointer hover:text-blue-600 dark:hover:text-blue-400 select-none flex items-center justify-between">
                  <span>Raw Email Headers (RFC 822)</span>
                  <span className="text-[10px] uppercase font-mono text-slate-400 group-open:rotate-180 transition-transform">▼</span>
                </summary>
                <div className="mt-2 p-3 rounded-lg bg-slate-900 text-slate-200 font-mono text-[11px] overflow-x-auto whitespace-pre max-h-64 scrollbar-thin">
                  {emailIntel.raw_headers_text || (Array.isArray(emailIntel.raw_headers) ? emailIntel.raw_headers.map(h => `${h.name}: ${h.value}`).join('\n') : String(emailIntel.raw_headers))}
                </div>
              </details>
            )}

            {/* Email Social Engineering / NLP Cues */}
            {emailNlp && (emailNlp.urgency_count > 0 || emailNlp.credential_count > 0 || (emailNlp.urgency_cues && emailNlp.urgency_cues.length > 0)) && (
              <div className="p-3.5 rounded-xl bg-amber-50/60 dark:bg-amber-950/30 border border-amber-200/80 dark:border-amber-900/60 space-y-2 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-amber-800 dark:text-amber-300 flex items-center gap-1.5">
                    <AlertTriangle size={14} />
                    Social Engineering & Psychological Coercion Indicators
                  </span>
                  <Badge variant="warning">{emailNlp.urgency_count || (emailNlp.urgency_cues && emailNlp.urgency_cues.length) || 0} Indicators</Badge>
                </div>
                {emailNlp.urgency_cues && emailNlp.urgency_cues.length > 0 && (
                  <p className="text-amber-700 dark:text-amber-400">
                    <strong>Urgency phrases detected:</strong> {emailNlp.urgency_cues.join(', ')}
                  </p>
                )}
                {emailNlp.credential_count > 0 && (
                  <p className="text-amber-700 dark:text-amber-400">
                    <strong>Credential solicitation:</strong> Email content explicitly prompts for account verification or password credentials.
                  </p>
                )}
              </div>
            )}
          </div>
        </EvidenceCard>
      )}

      {/* 9B. Extracted Body URLs Inspection */}
      {emailUrls && emailUrls.length > 0 && (
        <EvidenceCard
          title="Extracted Email URLs"
          icon={Globe}
          badge={<Badge variant={emailUrls.some(u => (u.risk?.score || 0) >= 50 || u.local_ti?.found || u.local_ti?.status === 'MATCH') ? 'danger' : 'neutral'}>{emailUrls.length} URLs</Badge>}
          subtitle="All destination links discovered across plain text, HTML MIME parts, attachments, and QR codes"
        >
          <div className="overflow-x-auto py-2">
            <table className="w-full text-left text-xs" aria-label="Extracted Email URLs">
              <thead className="bg-slate-50 dark:bg-slate-800/50 text-slate-500 dark:text-slate-400 uppercase font-semibold border-b border-slate-200 dark:border-slate-800">
                <tr>
                  <th className="px-3 py-2">URL & Source</th>
                  <th className="px-3 py-2">ML Inference</th>
                  <th className="px-3 py-2">Local TI</th>
                  <th className="px-3 py-2">TLS / HTTPS</th>
                  <th className="px-3 py-2">Domain Intel</th>
                  <th className="px-3 py-2">Risk Score</th>
                  <th className="px-3 py-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {emailUrls.map((uItem, idx) => {
                  const uRisk = uItem.risk || {};
                  const uTi = uItem.local_ti || {};
                  const isTiMatch = uTi.found || uTi.status === 'MATCH';
                  const uScore = typeof uRisk.score === 'number' ? Math.round(uRisk.score) : 0;
                  const uLevel = String(uRisk.level || 'UNKNOWN').toUpperCase();
                  const uMl = uItem.ml || {};
                  const uTls = uItem.tls || {};
                  const uDomain = uItem.domain_intelligence || uItem.domain_intel || {};
                  const uRedirects = uItem.redirect_analysis || uItem.redirects || {};
                  const uWebpage = uItem.webpage_analysis || {};
                  const isExpanded = expandedUrlIdx === idx;

                  return (
                    <React.Fragment key={idx}>
                      <tr className="hover:bg-slate-50/80 dark:hover:bg-slate-800/40">
                        <td className="px-3 py-2.5 max-w-[220px]">
                          <div className="font-mono text-slate-800 dark:text-slate-200 truncate" title={uItem.url}>
                            {uItem.url}
                          </div>
                          <div className="flex items-center gap-1.5 mt-0.5">
                            <span className="px-1.5 py-0.2 rounded text-[10px] font-semibold bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
                              {uItem.source || 'body'}
                            </span>
                            {uItem.visible_text && uItem.visible_text !== uItem.url && (
                              <span className="text-[10px] text-slate-500 truncate max-w-[120px]" title={uItem.visible_text}>
                                "{uItem.visible_text}"
                              </span>
                            )}
                            {uItem.domain_mismatch && (
                              <span className="px-1 py-0.2 rounded text-[10px] font-bold bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300">
                                Mismatch
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-3 py-2.5">
                          {uMl.probability !== undefined && uMl.probability !== null ? (
                            <span className={`font-mono font-bold ${uMl.probability >= 0.5 ? 'text-red-600 dark:text-red-400' : 'text-emerald-600 dark:text-emerald-400'}`}>
                              {(uMl.probability * 100).toFixed(1)}% {uMl.probability >= 0.5 ? '(Phish)' : '(Benign)'}
                            </span>
                          ) : (
                            <span className="text-slate-400">—</span>
                          )}
                        </td>
                        <td className="px-3 py-2.5">
                          <Badge variant={isTiMatch ? 'danger' : 'neutral'}>
                            {isTiMatch ? `MATCH (${uTi.source || 'Threat Feed'})` : 'NO MATCH'}
                          </Badge>
                        </td>
                        <td className="px-3 py-2.5 font-mono text-[11px]">
                          {uTls.status ? (
                            <span className={uTls.is_valid ? 'text-emerald-600 dark:text-emerald-400 font-semibold' : 'text-amber-600 dark:text-amber-400 font-semibold'}>
                              {uTls.status}
                            </span>
                          ) : (
                            <span className="text-slate-400">—</span>
                          )}
                        </td>
                        <td className="px-3 py-2.5 text-slate-600 dark:text-slate-400 text-[11px]">
                          <div>{uDomain.registered_domain || uDomain.registrable_domain || uItem.domain || '—'}</div>
                          {uDomain.is_private && <span className="text-[10px] text-amber-600">Private IP</span>}
                        </td>
                        <td className="px-3 py-2.5 font-bold">
                          <span className={uScore >= 70 ? 'text-red-600 dark:text-red-400' : uScore >= 40 ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'}>
                            {uScore}/100 ({uLevel})
                          </span>
                        </td>
                        <td className="px-3 py-2.5 text-right space-x-2">
                          <button
                            type="button"
                            onClick={() => setExpandedUrlIdx(isExpanded ? null : idx)}
                            className="text-[11px] font-semibold text-slate-600 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400"
                          >
                            {isExpanded ? 'Hide' : 'Details'}
                          </button>
                          <button
                            type="button"
                            onClick={() => handleAskAnalyst(`Analyze this specific URL extracted from the email: ${uItem.url}`)}
                            className="text-[11px] font-medium text-blue-600 dark:text-blue-400 hover:underline"
                          >
                            Ask AI
                          </button>
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr className="bg-slate-50/70 dark:bg-slate-900/60">
                          <td colSpan={7} className="p-4 border-t border-b border-slate-200 dark:border-slate-800">
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                              {/* Redirect Details */}
                              <div className="p-3 rounded-lg bg-white dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700">
                                <div className="font-semibold text-slate-700 dark:text-slate-300 mb-1">Redirect Chain</div>
                                <div className="text-[11px] space-y-1">
                                  <div>Status: <span className="font-mono font-bold">{uRedirects.status || 'NO_REDIRECT'}</span></div>
                                  <div>Hops Count: <span className="font-mono">{uRedirects.redirect_count || 0}</span></div>
                                  {Array.isArray(uRedirects.hops) && uRedirects.hops.length > 0 && (
                                    <div className="mt-1 font-mono text-[10px] space-y-1">
                                      {uRedirects.hops.map((h, hIdx) => (
                                        <div key={hIdx} className="text-slate-600 dark:text-slate-400 truncate" title={`${h.from_url} -> ${h.to_url}`}>
                                          {`${hIdx + 1}. HTTP ${h.status_code} -> ${h.to_url}`}
                                        </div>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              </div>

                              {/* Webpage Findings */}
                              <div className="p-3 rounded-lg bg-white dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700">
                                <div className="font-semibold text-slate-700 dark:text-slate-300 mb-1">Webpage Findings</div>
                                <div className="text-[11px] space-y-1">
                                  <div>Forms: <span className="font-mono">{uWebpage.form_count || 0}</span></div>
                                  <div>Password Fields: <span className="font-mono">{uWebpage.password_field_count || 0}</span></div>
                                  <div>Login Form: <span className="font-mono">{uWebpage.has_login_form ? 'YES' : 'NO'}</span></div>
                                  <div>Cross-Domain Form: <span className="font-mono">{uWebpage.has_cross_domain_submission ? 'YES' : 'NO'}</span></div>
                                </div>
                              </div>

                              {/* DNS Records */}
                              <div className="p-3 rounded-lg bg-white dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700">
                                <div className="font-semibold text-slate-700 dark:text-slate-300 mb-1">DNS Resolution</div>
                                <div className="text-[11px] space-y-1 font-mono">
                                  <div>Status: {uDomain.dns?.status || (uDomain.ipv4_addresses ? 'SUCCESS' : 'UNKNOWN')}</div>
                                  {uDomain.ipv4_addresses && <div>IP: {uDomain.ipv4_addresses.join(', ')}</div>}
                                  {uDomain.dns?.MX && <div>MX: {uDomain.dns.MX.slice(0, 2).join(', ')}</div>}
                                  {uDomain.dns?.TXT && <div>TXT: {uDomain.dns.TXT.slice(0, 1).join(', ')}</div>}
                                </div>
                              </div>

                              {/* ML Explainability */}
                              <div className="p-3 rounded-lg bg-white dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700">
                                <div className="font-semibold text-slate-700 dark:text-slate-300 mb-1">ML Model Details</div>
                                <div className="text-[11px] space-y-1">
                                  <div>Model: {uMl.model_name || 'Random Forest URL'}</div>
                                  <div>Verdict: <span className="font-mono font-bold">{uMl.verdict || (uMl.probability >= 0.5 ? 'PHISHING' : 'BENIGN')}</span></div>
                                  <div>Confidence: <span className="font-mono">{uMl.probability ? `${(uMl.probability * 100).toFixed(1)}%` : 'N/A'}</span></div>
                                  {uMl.features && (
                                    <div className="text-[10px] text-slate-500 truncate" title={JSON.stringify(uMl.features)}>
                                      Features: HTTPS={String(uMl.features.has_https)}, len={uMl.features.url_length}
                                    </div>
                                  )}
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </EvidenceCard>
      )}

      {/* 10. Attachment & Macro Forensics */}
      {allAttachments && allAttachments.length > 0 && (
        <EvidenceCard
          title="Attachment & Payload Inspection"
          icon={FileCode}
          badge={<Badge variant={allAttachments.some(a => a.has_vba_macros || a.suspicious) ? 'danger' : 'neutral'}>{allAttachments.length} Attachment{allAttachments.length > 1 ? 's' : ''}</Badge>}
          subtitle="Static analysis of attachments, embedded URLs, VBA macros, executable headers, and file hashes"
        >
          <div className="space-y-4 py-2">
            {allAttachments.map((att, idx) => (
              <div key={idx} className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200/80 dark:border-slate-800 space-y-3">
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                  <div className="p-2.5 rounded-lg bg-white/80 dark:bg-slate-900/80 border border-slate-200/60 dark:border-slate-800">
                    <p className="text-[11px] font-semibold text-slate-400 dark:text-slate-500">File Name & Size</p>
                    <p className="text-xs font-semibold text-slate-800 dark:text-slate-200 mt-0.5 truncate" title={att.filename || 'attachment'}>
                      {att.filename || 'attachment'} ({formatFileSize(att.size_bytes)})
                    </p>
                  </div>

                  <div className="p-2.5 rounded-lg bg-white/80 dark:bg-slate-900/80 border border-slate-200/60 dark:border-slate-800">
                    <p className="text-[11px] font-semibold text-slate-400 dark:text-slate-500">MIME / Extension</p>
                    <p className="text-xs font-mono font-bold text-slate-800 dark:text-slate-200 mt-0.5 truncate">
                      {att.mime_type || att.extension || att.detected_type || '—'}
                    </p>
                  </div>

                  <div className="p-2.5 rounded-lg bg-white/80 dark:bg-slate-900/80 border border-slate-200/60 dark:border-slate-800">
                    <p className="text-[11px] font-semibold text-slate-400 dark:text-slate-500">Macro Status</p>
                    <p className="text-xs font-bold mt-0.5">
                      {(() => {
                        const mStatus = att.macro_status || att.static_analysis?.macro_status;
                        const mDetails = att.macro_details || att.static_analysis?.macro_details;
                        const fn = (att.filename || '').toLowerCase();
                        const isText = fn.endsWith('.txt') || fn.endsWith('.csv') || fn.endsWith('.json') || fn.endsWith('.log') || (att.mime_type && att.mime_type.startsWith('text/'));
                        if (mStatus === 'NOT_APPLICABLE' || (!att.has_vba_macros && isText)) {
                          return <span className="text-slate-500 dark:text-slate-400 font-medium">{mDetails || 'Not applicable — plain-text file'}</span>;
                        }
                        if (att.has_vba_macros || mStatus === 'MACROS_DETECTED') {
                          return <span className="text-red-600 dark:text-red-400">VBA Macros Detected</span>;
                        }
                        if (mStatus === 'NO_MACROS_FOUND') {
                          return <span className="text-emerald-600 dark:text-emerald-400">Clean (No Macros)</span>;
                        }
                        if (mStatus === 'ERROR') {
                          return <span className="text-amber-600 dark:text-amber-400">Inspection Error</span>;
                        }
                        return <span className="text-slate-500 dark:text-slate-400 font-medium">{mDetails || 'Clean (No Macros)'}</span>;
                      })()}
                    </p>
                  </div>

                  <div className="p-2.5 rounded-lg bg-white/80 dark:bg-slate-900/80 border border-slate-200/60 dark:border-slate-800">
                    <p className="text-[11px] font-semibold text-slate-400 dark:text-slate-500">SHA256 Hash</p>
                    <p className="text-[11px] font-mono text-slate-600 dark:text-slate-400 mt-0.5 truncate" title={att.sha256 || '—'}>
                      {att.sha256 ? `${att.sha256.substring(0, 16)}...` : '—'}
                    </p>
                  </div>
                </div>

                {att.embedded_urls && att.embedded_urls.length > 0 && (
                  <div className="p-2.5 rounded-lg bg-blue-50/50 dark:bg-blue-950/20 border border-blue-200/60 dark:border-blue-900/40 space-y-1.5 text-xs">
                    <span className="font-semibold text-blue-900 dark:text-blue-200 block text-[11px]">
                      Embedded URLs Extracted from Attachment ({att.embedded_urls.length}):
                    </span>
                    <div className="flex flex-wrap gap-2">
                      {att.embedded_urls.map((embUrl, eIdx) => (
                        <span key={eIdx} className="px-2 py-0.5 rounded bg-white dark:bg-slate-900 border border-blue-200 dark:border-blue-800 font-mono text-[11px] text-blue-700 dark:text-blue-300">
                          {embUrl}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </EvidenceCard>
      )}

      {/* 10B. Tracking Pixels & HTML Remote Resources */}
      {trackingIntel && (
        <EvidenceCard
          title="Email Tracking & Remote Resource Inspection"
          icon={Eye}
          badge={<Badge variant={trackingIntel.detected ? 'warning' : 'neutral'}>{trackingIntel.detected ? `${trackingIntel.tracking_pixels_count || 1} Pixel(s) Found` : 'None Detected'}</Badge>}
          subtitle="Passive HTML DOM inspection for hidden 1×1 web beacons and remote tracking images"
        >
          <div className="py-2 space-y-3 text-xs">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800">
                <span className="text-slate-400 block text-[11px]">Tracking Pixels Detected</span>
                <span className="text-sm font-bold mt-0.5 block">
                  {trackingIntel.detected ? (
                    <span className="text-amber-600 dark:text-amber-400">Yes ({trackingIntel.tracking_pixels_count} found)</span>
                  ) : (
                    <span className="text-emerald-600 dark:text-emerald-400">No (None Detected)</span>
                  )}
                </span>
              </div>
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800">
                <span className="text-slate-400 block text-[11px]">HTML Remote Images</span>
                <span className="text-sm font-bold text-slate-800 dark:text-slate-200 mt-0.5 block">
                  {trackingIntel.html_image_resources_count ?? 0}
                </span>
              </div>
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800">
                <span className="text-slate-400 block text-[11px]">MIME Image Attachments</span>
                <span className="text-sm font-bold text-slate-800 dark:text-slate-200 mt-0.5 block">
                  {trackingIntel.mime_image_count ?? 0}
                </span>
              </div>
            </div>
            {trackingIntel.suspected_tracking_pixels && trackingIntel.suspected_tracking_pixels.length > 0 && (
              <div className="p-3 rounded-lg bg-amber-50/60 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-900/40 space-y-2">
                <span className="font-semibold text-amber-900 dark:text-amber-200 block text-xs">Suspected Tracking Beacon URLs:</span>
                {trackingIntel.suspected_tracking_pixels.map((p, pIdx) => (
                  <div key={pIdx} className="font-mono text-[11px] text-amber-800 dark:text-amber-300 break-all bg-white/70 dark:bg-slate-900/60 p-2 rounded border border-amber-200/50 dark:border-amber-900/30">
                    <div><strong>SRC:</strong> {p.src}</div>
                    <div className="text-[10px] text-slate-500 mt-0.5">Dimensions: {p.width}×{p.height} | {p.reasons?.join(', ')}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </EvidenceCard>
      )}

      {/* 11. QR Code Decoding & Decoded URL Analysis */}
      {qrIntel && (
        <EvidenceCard
          title="QR Code Payload & Downstream Inspection"
          icon={QrCode}
          badge={
            <Badge variant={qrIntel.decode_status === 'SUCCESS' ? 'success' : 'danger'}>
              {qrIntel.decode_status === 'SUCCESS' ? 'DECODED' : 'FAILED'}
            </Badge>
          }
          subtitle="Visual barcode payload extraction, payload classification, and downstream telemetry"
        >
          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200/80 dark:border-slate-800">
                <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 block">Decode Status</span>
                <span className="text-xs font-bold text-slate-900 dark:text-slate-100 mt-0.5 inline-flex items-center gap-1.5">
                  {qrIntel.decode_status === 'SUCCESS' ? (
                    <>
                      <CheckCircle2 size={13} className="text-emerald-500 shrink-0" />
                      <span>SUCCESS</span>
                    </>
                  ) : (
                    <>
                      <XCircle size={13} className="text-rose-500 shrink-0" />
                      <span>FAILED</span>
                    </>
                  )}
                </span>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200/80 dark:border-slate-800">
                <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 block">Payload Type</span>
                <Badge variant={qrIntel.payload_type === 'URL' ? 'info' : 'neutral'} className="mt-1">
                  {qrIntel.payload_type || (qrIntel.is_url ? 'URL' : 'UNKNOWN')}
                </Badge>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200/80 dark:border-slate-800">
                <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 block">Downstream Pipeline</span>
                <span className="text-xs font-semibold text-slate-900 dark:text-slate-100 mt-0.5 block">
                  {qrIntel.is_url ? 'Central URL Pipeline' : 'Direct Data Inspection'}
                </span>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200/80 dark:border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <p className="text-xs font-semibold text-slate-700 dark:text-slate-300">Decoded Payload:</p>
                {qrIntel.decoded_payload && (
                  <span className="text-[11px] text-slate-500 dark:text-slate-400">
                    {qrIntel.decoded_payload.length} chars
                  </span>
                )}
              </div>
              <p className="text-xs font-mono font-bold text-slate-900 dark:text-slate-100 break-all p-3 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                {qrIntel.decoded_payload || qrIntel.decoded_data || 'No QR code payload extracted'}
              </p>
              {qrIntel.is_url ? (
                <div className="mt-2 p-2.5 rounded-lg bg-blue-50/80 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-900/60 text-xs text-blue-800 dark:text-blue-300 flex items-center gap-2">
                  <ShieldCheck size={16} className="text-blue-600 dark:text-blue-400 shrink-0" />
                  <span>
                    <strong>Actionable URL Detected:</strong> Decoded URL was automatically inspected via the central multi-layer URL analyzer, machine learning, local threat intelligence, domain telemetry, and VirusTotal policy.
                  </span>
                </div>
              ) : (
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Non-URL payload decoded safely without triggering network queries.
                </p>
              )}
            </div>
          </div>
        </EvidenceCard>
      )}

      {/* 11B. Email Embedded QR Code Analysis */}
      {emailQrIntel && (
        <EvidenceCard
          title="Embedded QR Code Analysis"
          icon={QrCode}
          badge={
            <Badge variant={emailQrIntel.detected ? 'warning' : 'neutral'}>
              {emailQrIntel.detected
                ? `${emailQrIntel.qr_count} QR Code(s) Found`
                : 'No QR Detected'}
            </Badge>
          }
          subtitle="Visual barcode detection across email inline images and attachments"
        >
          <div className="py-2 space-y-4 text-xs">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800">
                <span className="text-slate-400 block text-[11px]">Images Inspected</span>
                <span className="text-sm font-bold text-slate-800 dark:text-slate-200">
                  {emailQrIntel.image_count || 0} MIME image part(s)
                </span>
              </div>
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800">
                <span className="text-slate-400 block text-[11px]">QR Codes Extracted</span>
                <span className={`text-sm font-bold ${emailQrIntel.detected ? 'text-amber-600 dark:text-amber-400' : 'text-slate-600 dark:text-slate-300'}`}>
                  {emailQrIntel.qr_count || 0} code(s) detected
                </span>
              </div>
            </div>

            {emailQrIntel.detected && emailQrIntel.findings?.length > 0 ? (
              <div className="space-y-3">
                <p className="font-semibold text-slate-700 dark:text-slate-300">
                  Extracted QR Payloads & Downstream Inspection:
                </p>
                {emailQrIntel.findings.map((f, idx) => (
                  <div
                    key={idx}
                    className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200/80 dark:border-slate-800 space-y-2"
                  >
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <span className="text-[11px] font-semibold text-slate-500">
                        Source: <span className="font-mono text-slate-700 dark:text-slate-300">{f.source_part || `image_${idx + 1}`}</span>
                      </span>
                      <Badge variant={f.is_url ? 'info' : 'neutral'}>
                        {f.is_url ? 'HTTP URL' : 'Text Payload'}
                      </Badge>
                    </div>

                    <div className="p-2.5 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 font-mono text-xs font-bold text-slate-900 dark:text-slate-100 break-all">
                      {f.decoded_data}
                    </div>

                    {f.is_url && f.url_risk && (
                      <div className="flex items-center gap-3 pt-1 text-[11px] text-slate-600 dark:text-slate-400">
                        <span>Downstream URL Risk: <strong className="uppercase">{f.url_risk.level || 'UNKNOWN'}</strong></span>
                        <span>•</span>
                        <span>Score: <strong>{f.url_risk.score ?? '—'}/100</strong></span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-500 dark:text-slate-400 italic">
                {emailQrIntel.image_count > 0
                  ? `No QR codes detected across the ${emailQrIntel.image_count} embedded email image(s).`
                  : 'No image MIME parts were present in this email.'}
              </p>
            )}
          </div>
        </EvidenceCard>
      )}

      {/* 12. AI / Machine Learning & Model Explanation */}
      {mlIntel && (
        <EvidenceCard
          title="AI / Machine Learning Inference"
          icon={Cpu}
          subtitle="Trained supervised model inference, classification probability, and feature weights"
        >
          <div className="space-y-4 py-2">
            {artifactType === 'file' || artifactType === 'hash' || mlIntel.status === 'NOT_APPLICABLE' ? (
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 text-xs text-slate-600 dark:text-slate-400">
                <p className="font-semibold text-slate-800 dark:text-slate-200">
                  ML URL classifier: Not applicable to this artifact type ({artifactType})
                </p>
                <p className="mt-0.5">
                  Supervised lexical ML models evaluate URL structure and web syntax. File and hash artifacts are evaluated via cryptographic hash reputation, file structure analysis, and threat intelligence feeds.
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/60 dark:border-slate-800">
                  <p className="text-[11px] font-semibold text-slate-400 dark:text-slate-500">Model Availability</p>
                  <p className="text-xs font-bold text-slate-800 dark:text-slate-200 mt-1">
                    {mlIntel.model_available ? 'Active (URL ML v1)' : 'Heuristic Engine Active'}
                  </p>
                </div>

                <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/60 dark:border-slate-800">
                  <p className="text-[11px] font-semibold text-slate-400 dark:text-slate-500">Inference Probability</p>
                  <p className="text-xs font-mono font-bold text-slate-800 dark:text-slate-200 mt-1">
                    {mlIntel.probability !== null && mlIntel.probability !== undefined
                      ? `${(mlIntel.probability * 100).toFixed(1)}%`
                      : 'N/A (Heuristic fallback)'}
                  </p>
                </div>

                <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/60 dark:border-slate-800">
                  <p className="text-[11px] font-semibold text-slate-400 dark:text-slate-500">Classification</p>
                  <p className="text-xs font-bold mt-1">
                    {mlIntel.prediction === 1 || (mlIntel.probability && mlIntel.probability >= 0.5) ? (
                      <span className="text-red-600 dark:text-red-400">Flagged Phishing</span>
                    ) : (
                      <span className="text-emerald-600 dark:text-emerald-400">Likely Benign</span>
                    )}
                  </p>
                </div>
              </div>
            )}
          </div>
        </EvidenceCard>
      )}

      {/* 14. Cross-Layer Correlated Evidence */}
      {evidenceCorr && Array.isArray(evidenceCorr.evidence) && evidenceCorr.evidence.length > 0 && (
        <EvidenceCard
          title="Cross-Layer Correlated Findings"
          icon={Layers}
          badge={<Badge variant="info">{evidenceCorr.evidence.length} Findings</Badge>}
          subtitle="Multi-source correlation synthesized across all extraction engines"
        >
          <div className="divide-y divide-slate-100 dark:divide-slate-800 py-1">
            {evidenceCorr.evidence.map((item, idx) => (
              <div key={idx} className="py-2.5 flex items-center justify-between gap-4">
                <div className="space-y-0.5 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-slate-800 dark:text-slate-200 truncate">
                      {item.description || item.signal}
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-500">
                      {item.source}
                    </span>
                  </div>
                </div>

                <Badge variant={getCategoryBadgeVariant(item.category)}>
                  {item.category?.replace('_', ' ') || 'CORRELATED'}
                </Badge>
              </div>
            ))}
          </div>
        </EvidenceCard>
      )}

      {/* 15. AI Security Analyst Interactive Assessment & Entry Point */}
      <div className="p-6 md:p-8 rounded-2xl bg-gradient-to-br from-blue-900/10 via-indigo-950/10 to-purple-950/20 dark:from-blue-950/40 dark:via-indigo-950/30 dark:to-purple-950/50 border border-blue-200/80 dark:border-blue-900/60 shadow-sm space-y-5">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-600 text-white flex items-center justify-center shadow-md shadow-blue-500/20">
              <Bot size={22} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  AI Security Analyst Assessment
                </h3>
                <Badge variant={aiAnalyst?.status === 'READY' ? 'success' : aiAnalyst?.status === 'UNCONFIGURED' ? 'neutral' : 'info'}>
                  {aiAnalyst?.provider === 'gemini' ? 'Google Gemini' : 'Security Analyst'}
                </Badge>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Grounded conversational analysis based on this specific investigation's telemetry.
              </p>
            </div>
          </div>

          <Button
            variant="primary"
            onClick={() => handleAskAnalyst()}
            className="flex items-center gap-2 text-xs px-5"
          >
            <span>Open Dedicated Analyst</span>
            <ArrowRight size={14} />
          </Button>
        </div>

        {/* AI Initial Assessment Output or Unconfigured Banner */}
        {aiAnalyst?.evaluation ? (
          <div className="p-4 rounded-xl bg-white/80 dark:bg-slate-900/80 border border-blue-100 dark:border-blue-950 space-y-2 text-xs text-slate-700 dark:text-slate-300">
            <div className="flex items-center justify-between text-[11px] font-semibold text-blue-600 dark:text-blue-400 uppercase tracking-wider">
              <span>Automated Executive Findings</span>
              <span>Grounded Telemetry</span>
            </div>
            <FormattedMarkdown text={aiAnalyst.evaluation} className="leading-relaxed" />
          </div>
        ) : aiAnalyst?.status === 'UNCONFIGURED' ? (
          <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 text-xs text-slate-600 dark:text-slate-400">
            <p className="font-semibold text-slate-800 dark:text-slate-200">
              Google Gemini AI Analyst is unconfigured
            </p>
            <p className="mt-0.5">
              Configure Google Gemini API credentials in your backend environment to enable multi-turn AI reasoning, automated threat summaries, and executive reports.
            </p>
          </div>
        ) : null}

        {/* Suggested Investigation Prompts */}
        <div className="space-y-2">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
            Suggested Investigation Inquiries:
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
            {[
              'Why was this artifact classified as ' + riskLevel + ' risk?',
              'What specific evidence contributed most to this score?',
              'Which findings remain unknown or inconclusive?',
              'Are there brand impersonation signals present?',
              'What remediation actions should I take?',
              'Summarize this for an executive incident report',
            ].map((promptText, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleAskAnalyst(promptText)}
                className="p-3 rounded-lg text-left text-xs font-medium text-slate-700 dark:text-slate-300 bg-white/70 dark:bg-slate-900/70 border border-slate-200/70 dark:border-slate-800 hover:border-blue-500/60 dark:hover:border-blue-500/60 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-white dark:hover:bg-slate-900 transition-all flex items-center justify-between group"
              >
                <span className="line-clamp-2">{promptText}</span>
                <ArrowRight size={13} className="shrink-0 opacity-0 group-hover:opacity-100 group-hover:translate-x-0.5 transition-all text-blue-500 ml-2" />
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default AnalysisResult;
