import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import { analysis } from '../services/api';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import LoadingState from '../components/LoadingState';
import EmptyState from '../components/EmptyState';
import ErrorState from '../components/ErrorState';
import {
  FileText,
  Printer,
  Search,
  Filter,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Clock,
  ExternalLink,
  ChevronRight,
  ArrowLeft,
  RefreshCw,
  Bot,
  Globe,
  Hash as HashIcon,
  Mail,
  QrCode,
  FileCode,
  Layers,
  Database,
  CheckCircle2,
  XCircle,
  HelpCircle,
  SlidersHorizontal,
  Info,
  Server,
  Lock,
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
 * Map authentication status to badge variant
 */
const getAuthBadgeVariant = (status) => {
  const s = String(status || '').toUpperCase();
  if (s === 'PASS' || s === 'TRUE' || s === 'VALID') return 'success';
  if (s === 'FAIL' || s === 'FALSE' || s === 'INVALID') return 'danger';
  if (s === 'SOFTFAIL' || s === 'NEUTRAL' || s === 'NONE') return 'warning';
  return 'neutral';
};

const Reports = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  // Registry state
  const [historyList, setHistoryList] = useState([]);
  const [loadingList, setLoadingList] = useState(true);
  const [listError, setListError] = useState(null);

  // Search & Filter state
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState('ALL');
  const [selectedRisk, setSelectedRisk] = useState('ALL');

  // Selected report detail state
  const selectedIdFromUrl = searchParams.get('id');
  const [selectedAnalysisId, setSelectedAnalysisId] = useState(selectedIdFromUrl ? parseInt(selectedIdFromUrl, 10) : null);
  const [reportData, setReportData] = useState(null);
  const [loadingReport, setLoadingReport] = useState(false);
  const [reportError, setReportError] = useState(null);

  // Fetch list of user's past analyses
  const fetchAnalysesList = async () => {
    setLoadingList(true);
    setListError(null);
    try {
      const data = await analysis.history(50);
      setHistoryList(Array.isArray(data) ? data : []);
    } catch (err) {
      setListError(err?.message || 'Failed to retrieve analysis registry from the security server.');
    } finally {
      setLoadingList(false);
    }
  };

  useEffect(() => {
    fetchAnalysesList();
  }, []);

  // Fetch single report when selected
  const loadReport = async (id) => {
    if (!id) return;
    setLoadingReport(true);
    setReportError(null);
    try {
      const data = await analysis.get(id);
      setReportData(data);
      setSelectedAnalysisId(id);
      setSearchParams({ id });
      // Scroll to top of report view
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (err) {
      setReportError(err?.message || `Failed to load investigation details for #${id}.`);
    } finally {
      setLoadingReport(false);
    }
  };

  // Sync with URL query parameter
  useEffect(() => {
    if (selectedIdFromUrl) {
      const parsedId = parseInt(selectedIdFromUrl, 10);
      if (!isNaN(parsedId) && (!reportData || reportData.analysis_id !== parsedId)) {
        loadReport(parsedId);
      }
    } else {
      setSelectedAnalysisId(null);
      setReportData(null);
    }
  }, [selectedIdFromUrl]);

  // Handle return to list
  const handleBackToList = () => {
    setSelectedAnalysisId(null);
    setReportData(null);
    setSearchParams({});
  };

  // Filtered registry items
  const filteredList = useMemo(() => {
    return historyList.filter((item) => {
      const itemType = String(item.artifact_type || 'url').toUpperCase();
      const itemRisk = String(item.risk_level || 'UNKNOWN').toUpperCase();
      const targetStr = String(item.target || item.url || item.hash || item.filename || '').toLowerCase();
      const idStr = String(item.id || item.analysis_id || '');

      // Type filter
      if (selectedType !== 'ALL' && itemType !== selectedType) {
        return false;
      }

      // Risk filter
      if (selectedRisk !== 'ALL' && itemRisk !== selectedRisk) {
        return false;
      }

      // Text search
      if (searchTerm.trim()) {
        const query = searchTerm.toLowerCase().trim();
        const matchesTarget = targetStr.includes(query);
        const matchesId = idStr.includes(query);
        if (!matchesTarget && !matchesId) {
          return false;
        }
      }

      return true;
    });
  }, [historyList, selectedType, selectedRisk, searchTerm]);

  // Trigger print dialog
  const handlePrint = () => {
    window.print();
  };

  // -------------------------------------------------------------
  // RENDER: REPORT DETAIL VIEW
  // -------------------------------------------------------------
  if (selectedAnalysisId || loadingReport || reportError) {
    if (loadingReport) {
      return (
        <div className="max-w-5xl mx-auto py-12">
          <LoadingState message="Compiling formal security investigation report from telemetry archive…" />
        </div>
      );
    }

    if (reportError) {
      return (
        <div className="max-w-5xl mx-auto py-12 space-y-4">
          <Button
            variant="secondary"
            onClick={handleBackToList}
            className="flex items-center gap-1.5 text-xs"
          >
            <ArrowLeft size={14} />
            <span>Back to Report Registry</span>
          </Button>
          <ErrorState
            title="Unable to Generate Report"
            message={reportError}
            onRetry={() => loadReport(selectedAnalysisId)}
          />
        </div>
      );
    }

    if (!reportData) return null;

    const details = reportData.details || {};
    const explanation = reportData.explanation || {};
    const artifactType = String(reportData.artifact_type || 'url').toLowerCase();
    const targetIdentifier = reportData.url || details.url || details.hash || details.file_hash || `Investigation #${selectedAnalysisId}`;

    // Actual Forensics from Backend
    const urlFeatures = details.url_features || (details.url_details && details.url_details.url_features);
    const domainIntel = details.domain_intelligence || (details.url_details && details.url_details.domain_intelligence);
    const ipIntel = details.ip_intelligence || (details.url_details && details.url_details.ip_intelligence);
    const brandIntel = details.brand_intelligence || (details.url_details && details.url_details.brand_intelligence);
    const emailIntel = details.email;
    const qrIntel = details.qr;
    const attachmentIntel = details.attachment_info || details.attachment;
    const vtIntel = details.virustotal || details.vt_reputation || (details.url_details && details.url_details.virustotal) || details.vt;
    const mlIntel = details.ml || reportData.ml;
    const evidenceCorr = details.evidence_correlation || reportData.evidence_correlation;

    const signals = explanation.explanations || explanation.key_reasons || reportData.signals || [];

    // Observed / Inferred / Unknown Categorization (Strictly Grounded)
    const observedFacts = [];
    const inferredFindings = [];
    const unknownLimitations = [];

    // 1. Observed Facts (Grounded directly in returned backend data)
    if (domainIntel?.registrable_domain) {
      observedFacts.push(`Registrable Domain: ${domainIntel.registrable_domain} (TLD: .${domainIntel.tld || '—'})`);
    }
    if (domainIntel?.subdomain) {
      observedFacts.push(`Subdomain structure: ${domainIntel.subdomain}`);
    }
    if (domainIntel?.ipv4_addresses?.length > 0) {
      observedFacts.push(`DNS Resolved IPv4: ${domainIntel.ipv4_addresses.join(', ')}`);
    }
    if (domainIntel?.is_ip_address) {
      observedFacts.push(`Target hostname is a raw IP literal (${domainIntel.ip_version ? `IPv${domainIntel.ip_version}` : 'IP'})`);
    }
    if (emailIntel?.spf || emailIntel?.spf_result) {
      observedFacts.push(`SPF Authentication Result: ${emailIntel.spf || emailIntel.spf_result}`);
    }
    if (emailIntel?.dkim || emailIntel?.dkim_result) {
      observedFacts.push(`DKIM Cryptographic Signature: ${emailIntel.dkim || emailIntel.dkim_result}`);
    }
    if (emailIntel?.dmarc || emailIntel?.dmarc_result) {
      observedFacts.push(`DMARC Policy Evaluation: ${emailIntel.dmarc || emailIntel.dmarc_result}`);
    }
    if (emailIntel?.from || emailIntel?.sender) {
      observedFacts.push(`Sender Header: ${emailIntel.from || emailIntel.sender}`);
    }
    if (attachmentIntel?.filename) {
      observedFacts.push(`Attachment File: ${attachmentIntel.filename} (${attachmentIntel.mime_type || 'binary'}, ${attachmentIntel.size_bytes ? `${Math.round(attachmentIntel.size_bytes / 1024)} KB` : 'size unknown'})`);
    }
    if (attachmentIntel?.has_vba_macros !== undefined) {
      observedFacts.push(`VBA Macro Payload: ${attachmentIntel.has_vba_macros ? 'Detected in file header' : 'Clean (No macro streams detected)'}`);
    }
    if (qrIntel?.decoded_data) {
      observedFacts.push(`Decoded QR Payload: ${qrIntel.decoded_data}`);
    }
    if (vtIntel && vtIntel.status === 'SUCCESS') {
      observedFacts.push(`VirusTotal Multi-AV Matrix: ${vtIntel.malicious_count ?? (vtIntel.malicious ? 1 : 0)} / ${vtIntel.total_engines || 70} vendor engines detected threats`);
    }

    // 2. Inferred Findings (Algorithmic, heuristic, or model-derived)
    inferredFindings.push(`Heuristic Risk Rating: ${reportData.risk_level || 'UNKNOWN'} (Composite Score: ${reportData.risk_score ?? '—'}/100)`);
    if (mlIntel && (mlIntel.confidence !== undefined || mlIntel.phishing_probability !== undefined || mlIntel.probability !== undefined)) {
      const prob = mlIntel.phishing_probability ?? mlIntel.probability ?? mlIntel.confidence ?? 0;
      inferredFindings.push(`Machine Learning Phishing Probability: ${Math.round(prob * 100)}% (Classifier Inference)`);
    }
    if (brandIntel?.impersonated_brand || brandIntel?.target_brand) {
      inferredFindings.push(`Brand Impersonation Target: ${brandIntel.impersonated_brand || brandIntel.target_brand} (Lexical/Content Heuristic)`);
    }
    if (evidenceCorr?.high_risk_patterns?.length > 0) {
      evidenceCorr.high_risk_patterns.forEach((p) => {
        inferredFindings.push(`Correlated Attack Pattern: ${typeof p === 'string' ? p : p.name || p.description}`);
      });
    }
    if (signals.length > 0) {
      signals.slice(0, 5).forEach((s) => {
        inferredFindings.push(`Risk Indicator: ${typeof s === 'string' ? s : s.description || s.name}`);
      });
    }

    // 3. Unknowns & Telemetry Limitations (Strictly truthful)
    if (!vtIntel || vtIntel.status === 'UNAVAILABLE' || vtIntel.status === 'ERROR') {
      unknownLimitations.push('VirusTotal intelligence was unavailable or unconfigured during this analysis. External reputation unverified.');
    } else if (vtIntel.status === 'RATE_LIMITED') {
      unknownLimitations.push('VirusTotal API rate limit was reached during this lookup. External telemetry omitted.');
    } else if (vtIntel.status === 'NOT_FOUND') {
      unknownLimitations.push('Artifact is not indexed in VirusTotal global database. Lack of prior record does not confirm safety.');
    }
    if (domainIntel && domainIntel.dns_resolution_success === false) {
      unknownLimitations.push('DNS resolution failed for hostname. Live IP addresses could not be verified.');
    }
    unknownLimitations.push('WHOIS registration age and dynamic sandbox execution telemetry are not evaluated in static heuristics.');

    return (
      <div className="space-y-6 max-w-5xl mx-auto pb-16 print:p-0 print:max-w-none print:space-y-4">
        {/* Navigation & Action Bar (Hidden on Print) */}
        <div className="flex items-center justify-between gap-4 flex-wrap print:hidden bg-slate-50 dark:bg-slate-900/80 p-3.5 rounded-xl border border-slate-200 dark:border-slate-800">
          <Button
            variant="secondary"
            onClick={handleBackToList}
            className="flex items-center gap-1.5 text-xs"
          >
            <ArrowLeft size={14} />
            <span>Back to Reports List</span>
          </Button>

          <div className="flex items-center gap-2">
            <Link
              to={`/analysis/${reportData.analysis_id || selectedAnalysisId}`}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors shadow-sm"
            >
              <span>Full Forensics</span>
              <ExternalLink size={13} />
            </Link>

            <Button
              variant="secondary"
              onClick={() =>
                navigate('/analyst', {
                  state: {
                    analysisId: reportData.analysis_id || selectedAnalysisId,
                    artifactType: reportData.artifact_type,
                    target: targetIdentifier,
                    initialPrompt: 'Provide an executive summary of this security report and recommended mitigation steps.',
                  },
                })
              }
              className="flex items-center gap-1.5 text-xs"
            >
              <Bot size={13} />
              <span>Ask AI Analyst</span>
            </Button>

            <Button
              variant="primary"
              onClick={handlePrint}
              className="flex items-center gap-1.5 text-xs bg-slate-900 hover:bg-slate-800 text-white dark:bg-blue-600 dark:hover:bg-blue-700"
            >
              <Printer size={13} />
              <span>Print / Save as PDF</span>
            </Button>
          </div>
        </div>

        {/* ========================================================= */}
        {/* PRINT-READY SECURITY INVESTIGATION REPORT CONTAINER */}
        {/* ========================================================= */}
        <div className="bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 p-8 md:p-12 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-md print:shadow-none print:border-none print:p-0 print:bg-white print:text-black space-y-8">
          
          {/* Formal Report Header */}
          <div className="border-b-2 border-slate-900 dark:border-slate-100 print:border-black pb-6 space-y-4">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded bg-blue-600 text-white print:bg-black">
                    <Shield size={20} />
                  </div>
                  <span className="font-extrabold tracking-wider text-sm text-blue-600 dark:text-blue-400 print:text-black uppercase">
                    PHISHGUARD SECURITY PLATFORM
                  </span>
                </div>
                <h1 className="text-2xl md:text-3xl font-black tracking-tight mt-2 text-slate-900 dark:text-slate-100 print:text-black">
                  Security Investigation Report
                </h1>
                <p className="text-xs text-slate-500 dark:text-slate-400 print:text-gray-600 mt-1">
                  Automated Multi-Engine Forensic Analysis & Threat Intelligence Assessment
                </p>
              </div>

              <div className="text-right space-y-1 text-xs">
                <p className="font-mono text-slate-600 dark:text-slate-400 print:text-gray-700 text-xs font-bold">
                  REF: #PG-INV-{reportData.analysis_id || selectedAnalysisId}
                </p>
                <p className="text-slate-500 dark:text-slate-400 print:text-gray-600 text-[11px]">
                  Generated: {formatDateTime(new Date().toISOString())}
                </p>
              </div>
            </div>
          </div>

          {/* 1. Executive Summary & Verdict Scorecard */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 p-6 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 print:border-gray-300 print:bg-gray-50">
            <div className="md:col-span-2 space-y-2">
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-400 print:text-gray-600">
                1. Executive Summary
              </h2>
              <p className="text-sm text-slate-800 dark:text-slate-200 print:text-black leading-relaxed font-medium">
                {explanation.verdict ||
                  explanation.summary ||
                  `Investigation evaluated artifact '${targetIdentifier}' against PHISHGUARD heuristic detectors, machine learning classifiers, and threat intelligence feeds. The target artifact exhibits characteristics consistent with a ${reportData.risk_level || 'UNKNOWN'} threat level.`}
              </p>
              <div className="pt-2 flex items-center gap-4 text-xs font-mono text-slate-500 dark:text-slate-400 print:text-gray-600">
                <span>Artifact Type: <strong className="uppercase text-slate-800 dark:text-slate-200 print:text-black">{artifactType}</strong></span>
                <span>•</span>
                <span>Analyzed: {formatDateTime(reportData.created_at)}</span>
              </div>
            </div>

            <div className="flex flex-col items-center justify-center p-4 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700/80 text-center print:bg-white print:border-black">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                Risk Classification
              </span>
              <div className="text-3xl md:text-4xl font-black mt-1 text-slate-900 dark:text-slate-100 print:text-black">
                {reportData.risk_score ?? '—'}
                <span className="text-base font-normal text-slate-400">/100</span>
              </div>
              <div className="mt-2">
                <Badge variant={getRiskBadgeVariant(reportData.risk_level)}>
                  {reportData.risk_level || 'UNKNOWN'} RISK
                </Badge>
              </div>
            </div>
          </div>

          {/* 2. Target Profile & Artifact Information */}
          <div className="space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-400 print:text-gray-600 flex items-center gap-1.5">
              <Globe size={14} />
              <span>2. Artifact Information & Metadata</span>
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 print:border-gray-300">
                <span className="text-slate-400 print:text-gray-500 block text-[11px]">Investigation ID</span>
                <span className="font-mono font-bold text-slate-800 dark:text-slate-200 print:text-black">
                  #{reportData.analysis_id || selectedAnalysisId}
                </span>
              </div>
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 print:border-gray-300">
                <span className="text-slate-400 print:text-gray-500 block text-[11px]">Artifact Category</span>
                <span className="font-bold uppercase text-slate-800 dark:text-slate-200 print:text-black">
                  {artifactType}
                </span>
              </div>
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 print:border-gray-300 sm:col-span-2">
                <span className="text-slate-400 print:text-gray-500 block text-[11px]">Target Identifier</span>
                <span className="font-mono font-bold text-slate-800 dark:text-slate-200 print:text-black truncate block">
                  {targetIdentifier}
                </span>
              </div>
            </div>
          </div>

          {/* 3. Epistemic Separation (Observed vs Inferred vs Unknown) */}
          <div className="space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-400 print:text-gray-600 flex items-center gap-1.5">
              <Layers size={14} />
              <span>3. Epistemic Separation of Findings</span>
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Observed */}
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/30 border border-slate-200 dark:border-slate-800 print:border-gray-300 space-y-2">
                <div className="flex items-center gap-1.5 text-xs font-bold text-emerald-700 dark:text-emerald-400 print:text-black uppercase">
                  <CheckCircle2 size={14} />
                  <span>Observed Facts (Direct)</span>
                </div>
                {observedFacts.length === 0 ? (
                  <p className="text-xs text-slate-500 italic">No direct static attributes recorded.</p>
                ) : (
                  <ul className="space-y-1.5 text-xs text-slate-700 dark:text-slate-300 print:text-black">
                    {observedFacts.map((fact, idx) => (
                      <li key={idx} className="flex items-start gap-1.5">
                        <span className="text-emerald-500 font-bold">•</span>
                        <span>{fact}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {/* Inferred */}
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/30 border border-slate-200 dark:border-slate-800 print:border-gray-300 space-y-2">
                <div className="flex items-center gap-1.5 text-xs font-bold text-blue-700 dark:text-blue-400 print:text-black uppercase">
                  <Bot size={14} />
                  <span>Inferred (ML & Heuristic)</span>
                </div>
                {inferredFindings.length === 0 ? (
                  <p className="text-xs text-slate-500 italic">No heuristic models triggered.</p>
                ) : (
                  <ul className="space-y-1.5 text-xs text-slate-700 dark:text-slate-300 print:text-black">
                    {inferredFindings.map((finding, idx) => (
                      <li key={idx} className="flex items-start gap-1.5">
                        <span className="text-blue-500 font-bold">•</span>
                        <span>{finding}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {/* Unknowns */}
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/30 border border-slate-200 dark:border-slate-800 print:border-gray-300 space-y-2">
                <div className="flex items-center gap-1.5 text-xs font-bold text-amber-700 dark:text-amber-400 print:text-black uppercase">
                  <HelpCircle size={14} />
                  <span>Unknowns & Limitations</span>
                </div>
                {unknownLimitations.length === 0 ? (
                  <p className="text-xs text-slate-500 italic">All telemetry feeds returned definitive responses.</p>
                ) : (
                  <ul className="space-y-1.5 text-xs text-slate-700 dark:text-slate-300 print:text-black">
                    {unknownLimitations.map((lim, idx) => (
                      <li key={idx} className="flex items-start gap-1.5">
                        <span className="text-amber-500 font-bold">•</span>
                        <span>{lim}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          </div>

          {/* 4. Risk Signals & Detection Explanations */}
          {signals.length > 0 && (
            <div className="space-y-3">
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-400 print:text-gray-600 flex items-center gap-1.5">
                <ShieldAlert size={14} />
                <span>4. Triggered Risk Signals</span>
              </h2>
              <div className="rounded-xl border border-slate-200 dark:border-slate-800 divide-y divide-slate-100 dark:divide-slate-800 print:border-gray-300 print:divide-gray-200">
                {signals.map((sig, idx) => (
                  <div key={idx} className="p-3 text-xs flex items-start gap-2.5">
                    <span className="w-5 h-5 rounded-full bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400 flex items-center justify-center text-[10px] font-bold shrink-0 mt-0.5 print:bg-gray-200 print:text-black">
                      {idx + 1}
                    </span>
                    <span className="text-slate-800 dark:text-slate-200 print:text-black font-medium">
                      {typeof sig === 'string' ? sig : sig.description || sig.name || JSON.stringify(sig)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 5. Technical Evidence Details */}
          <div className="space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-400 print:text-gray-600 flex items-center gap-1.5">
              <SlidersHorizontal size={14} />
              <span>5. Technical Evidence & Forensic Telemetry</span>
            </h2>

            <div className="space-y-3 text-xs">
              {/* URL & Domain Info */}
              {(domainIntel || ipIntel || urlFeatures) && (
                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/30 border border-slate-200 dark:border-slate-800 print:border-gray-300 space-y-2">
                  <h3 className="font-bold text-slate-900 dark:text-slate-100 print:text-black">
                    Network & Domain Forensics
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 text-[11px]">
                    <div><span className="text-slate-400">Registrable Domain:</span> <span className="font-mono font-semibold">{domainIntel?.registrable_domain || domainIntel?.domain || urlFeatures?.domain || '—'}</span></div>
                    <div><span className="text-slate-400">Subdomain:</span> <span className="font-semibold">{domainIntel?.subdomain || 'none'}</span></div>
                    <div><span className="text-slate-400">Top-Level Domain:</span> <span className="font-semibold">{domainIntel?.tld || '—'}</span></div>
                    <div><span className="text-slate-400">Resolved IPv4:</span> <span className="font-mono font-semibold">{domainIntel?.ipv4_addresses?.join(', ') || (ipIntel?.dns_resolved_ips?.join(', ')) || 'None resolved'}</span></div>
                    <div><span className="text-slate-400">IP Literal Host:</span> <span className="font-semibold">{domainIntel?.is_ip_address ? 'Yes' : 'No'}</span></div>
                    <div><span className="text-slate-400">DNS Resolution:</span> <span className="font-semibold">{domainIntel?.dns_resolution_success ? 'Successful' : 'Unresolved / Failed'}</span></div>
                  </div>
                </div>
              )}

              {/* Email Authentication */}
              {emailIntel && (
                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/30 border border-slate-200 dark:border-slate-800 print:border-gray-300 space-y-2">
                  <h3 className="font-bold text-slate-900 dark:text-slate-100 print:text-black">
                    Email Authentication & Envelope Analysis
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px]">
                    <div><span className="text-slate-400">SPF:</span> <Badge variant={getAuthBadgeVariant(emailIntel.spf || emailIntel.spf_result)}>{emailIntel.spf || emailIntel.spf_result || 'UNKNOWN'}</Badge></div>
                    <div><span className="text-slate-400">DKIM:</span> <Badge variant={getAuthBadgeVariant(emailIntel.dkim || emailIntel.dkim_result)}>{emailIntel.dkim || emailIntel.dkim_result || 'UNKNOWN'}</Badge></div>
                    <div><span className="text-slate-400">DMARC:</span> <Badge variant={getAuthBadgeVariant(emailIntel.dmarc || emailIntel.dmarc_result)}>{emailIntel.dmarc || emailIntel.dmarc_result || 'UNKNOWN'}</Badge></div>
                    <div className="sm:col-span-3 pt-1"><span className="text-slate-400">Sender:</span> <span className="font-mono font-semibold">{emailIntel.from || emailIntel.sender || '—'}</span></div>
                  </div>
                </div>
              )}

              {/* Attachment & Macros */}
              {attachmentIntel && (
                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/30 border border-slate-200 dark:border-slate-800 print:border-gray-300 space-y-2">
                  <h3 className="font-bold text-slate-900 dark:text-slate-100 print:text-black">
                    Attachment & Macro Forensics
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px]">
                    <div><span className="text-slate-400">Filename:</span> <span className="font-semibold">{attachmentIntel.filename || '—'}</span></div>
                    <div><span className="text-slate-400">MIME Type:</span> <span className="font-mono font-semibold">{attachmentIntel.mime_type || '—'}</span></div>
                    <div><span className="text-slate-400">VBA Macros:</span> <span className="font-bold">{attachmentIntel.has_vba_macros ? 'Detected' : 'Clean'}</span></div>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* 6. Threat Intelligence & Multi-Engine Matrix */}
          <div className="space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-400 print:text-gray-600 flex items-center gap-1.5">
              <Database size={14} />
              <span>6. Threat Intelligence (VirusTotal)</span>
            </h2>

            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/30 border border-slate-200 dark:border-slate-800 print:border-gray-300 text-xs">
              {!vtIntel ? (
                <p className="text-slate-500 italic">No external reputation intelligence attached to this record.</p>
              ) : vtIntel.status === 'UNAVAILABLE' || vtIntel.status === 'ERROR' ? (
                <div className="text-slate-600 dark:text-slate-400 print:text-black space-y-1">
                  <p className="font-bold text-slate-800 dark:text-slate-200 print:text-black">
                    VirusTotal Intelligence Unavailable
                  </p>
                  <p>{vtIntel.error || 'Provider lookup was not available for this artifact. This is recorded as unverified rather than safe.'}</p>
                </div>
              ) : vtIntel.status === 'RATE_LIMITED' ? (
                <p className="text-amber-700 dark:text-amber-400 font-semibold">
                  VirusTotal rate limit reached. External API quota exceeded.
                </p>
              ) : vtIntel.status === 'NOT_FOUND' ? (
                <p className="text-slate-600 dark:text-slate-400">
                  VirusTotal has no record for this artifact in its global index.
                </p>
              ) : (
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div>
                    <span className="text-slate-400 block text-[11px]">Malicious Detections</span>
                    <span className="text-base font-bold text-red-600 dark:text-red-400 print:text-black">
                      {vtIntel.malicious_count ?? (vtIntel.malicious ? 1 : 0)} / {vtIntel.total_engines || 70}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px]">Suspicious Votes</span>
                    <span className="text-base font-bold text-amber-600 dark:text-amber-400 print:text-black">
                      {vtIntel.suspicious_count ?? (vtIntel.suspicious ? 1 : 0)}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px]">Clean / Harmless</span>
                    <span className="text-base font-bold text-emerald-600 dark:text-emerald-400 print:text-black">
                      {vtIntel.harmless_count ?? (vtIntel.total_engines ? vtIntel.total_engines - (vtIntel.malicious_count || 0) : '—')}
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* 7. SOC Remediation Guidance */}
          <div className="space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-400 print:text-gray-600 flex items-center gap-1.5">
              <CheckCircle2 size={14} />
              <span>7. Recommended SOC Response (Operator Guidance)</span>
            </h2>
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/30 border border-slate-200 dark:border-slate-800 print:border-gray-300 text-xs space-y-2">
              <p className="text-[11px] text-slate-500 dark:text-slate-400 italic">
                Note: The following containment and remediation actions are recommended operational procedures for SOC teams based on the assigned threat level. PHISHGUARD provides detection and forensic analysis; administrative actions must be executed in your respective security controls.
              </p>
              <ul className="space-y-1.5 text-slate-700 dark:text-slate-300 print:text-black list-disc pl-4 pt-1">
                {reportData.risk_level === 'CRITICAL' || reportData.risk_level === 'HIGH' ? (
                  <>
                    <li><strong>Perimeter Defense:</strong> Recommend blocking target hostname/IP on edge firewalls and secure web gateways.</li>
                    <li><strong>Mailbox Containment:</strong> Recommend searching and quarantining incoming emails referencing this domain or attachment checksum.</li>
                    <li><strong>User Identity:</strong> Recommend forcing password resets and revoking active sessions for users who interacted with the link.</li>
                    <li><strong>SIEM Ingestion:</strong> Ingest indicator of compromise (IOC) into SIEM/EDR detection rules.</li>
                  </>
                ) : reportData.risk_level === 'MEDIUM' ? (
                  <>
                    <li><strong>Proxy Logging:</strong> Recommend monitoring outbound proxy logs for connections to this host.</li>
                    <li><strong>User Notification:</strong> Advise recipient of suspicious characteristics (unverified domain/reputation).</li>
                    <li><strong>Scheduled Rescan:</strong> Resubmit artifact after 24 hours to check for newly indexed AV signatures.</li>
                  </>
                ) : (
                  <>
                    <li><strong>Baseline Logging:</strong> No immediate perimeter blocks required. Retain record in security audit log.</li>
                    <li><strong>Standard Hygiene:</strong> Continue adhering to standard organizational email and link hygiene protocols.</li>
                  </>
                )}
              </ul>
            </div>
          </div>

          {/* Report Footer / Signature */}
          <div className="pt-6 border-t border-slate-200 dark:border-slate-800 print:border-gray-300 flex flex-col sm:flex-row items-center justify-between text-[11px] text-slate-400 dark:text-slate-500 print:text-gray-500 gap-2">
            <div>
              <span>PHISHGUARD Automated Forensic Suite</span>
              <span className="mx-2">•</span>
              <span>Investigation #{reportData.analysis_id || selectedAnalysisId}</span>
            </div>
            <div>
              <span>Security Investigation Summary</span>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // -------------------------------------------------------------
  // RENDER: REPORT REGISTRY LIST
  // -------------------------------------------------------------
  return (
    <div className="space-y-8 max-w-6xl mx-auto pb-12">
      {/* 1. Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Security Reports
          </h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            Review and export investigation findings from PHISHGUARD analyses.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            onClick={fetchAnalysesList}
            disabled={loadingList}
            className="flex items-center gap-1.5 text-xs"
          >
            <RefreshCw size={13} className={loadingList ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </Button>
          <Button
            variant="primary"
            onClick={() => navigate('/analyze')}
            className="flex items-center gap-1.5 text-xs"
          >
            <span>New Investigation</span>
            <ChevronRight size={14} />
          </Button>
        </div>
      </div>

      {/* 2. Filter & Search Controls */}
      <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-4">
        <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
          {/* Search bar */}
          <div className="relative flex-1">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
              <Search size={15} />
            </div>
            <input
              type="text"
              placeholder="Search reports by Target, Domain, Hash, or Investigation ID…"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-4 py-2 text-xs rounded-lg bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
            />
          </div>

          {/* Type Selector */}
          <div className="flex items-center gap-2 flex-wrap">
            <div className="flex items-center gap-1 text-xs text-slate-500">
              <Filter size={13} />
              <span>Type:</span>
            </div>
            <select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              className="text-xs py-2 px-2.5 rounded-lg bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="ALL">All Types</option>
              <option value="URL">URL</option>
              <option value="EMAIL">Email</option>
              <option value="HASH">Hash</option>
              <option value="FILE">File</option>
              <option value="QR">QR Code</option>
            </select>

            {/* Risk Selector */}
            <select
              value={selectedRisk}
              onChange={(e) => setSelectedRisk(e.target.value)}
              className="text-xs py-2 px-2.5 rounded-lg bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="ALL">All Risk Levels</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>
        </div>
      </div>

      {/* 3. Reports Registry Table */}
      <Card
        title="Investigation Archive & Report Registry"
        subtitle="Select any past investigation to inspect the formal report or export print-ready PDF documentation"
      >
        {loadingList ? (
          <LoadingState message="Loading security report archive…" />
        ) : listError ? (
          <ErrorState
            title="Failed to Load Reports"
            message={listError}
            onRetry={fetchAnalysesList}
          />
        ) : filteredList.length === 0 ? (
          <EmptyState
            title="No reports match your filters"
            description={
              historyList.length === 0
                ? "You haven't run any security analyses yet. Submit an artifact on the Analyze page to generate your first report."
                : 'Try adjusting your search criteria or resetting filters to find investigation reports.'
            }
            actionLabel={historyList.length === 0 ? 'Run First Analysis' : 'Clear Filters'}
            onAction={() => {
              if (historyList.length === 0) {
                navigate('/analyze');
              } else {
                setSearchTerm('');
                setSelectedType('ALL');
                setSelectedRisk('ALL');
              }
            }}
          />
        ) : (
          <div className="overflow-x-auto -mx-6 -my-4">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/75 dark:bg-slate-800/40 text-slate-500 dark:text-slate-400">
                  <th className="py-3 px-4 font-semibold">ID</th>
                  <th className="py-3 px-4 font-semibold">Artifact Type</th>
                  <th className="py-3 px-4 font-semibold">Target Identifier</th>
                  <th className="py-3 px-4 font-semibold">Risk Rating</th>
                  <th className="py-3 px-4 font-semibold">Score</th>
                  <th className="py-3 px-4 font-semibold">Created</th>
                  <th className="py-3 px-4 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                {filteredList.map((item) => {
                  const itemId = item.id || item.analysis_id;
                  const itemType = String(item.artifact_type || 'url').toUpperCase();
                  const targetStr = item.target || item.url || item.hash || item.filename || `Investigation #${itemId}`;

                  return (
                    <tr
                      key={itemId}
                      className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors"
                    >
                      <td className="py-3.5 px-4 font-mono font-bold text-slate-600 dark:text-slate-400">
                        #{itemId}
                      </td>

                      <td className="py-3.5 px-4">
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wider bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                          {itemType}
                        </span>
                      </td>

                      <td className="py-3.5 px-4 max-w-xs truncate font-mono text-slate-800 dark:text-slate-200">
                        {targetStr}
                      </td>

                      <td className="py-3.5 px-4">
                        <Badge variant={getRiskBadgeVariant(item.risk_level)}>
                          {item.risk_level || 'UNKNOWN'}
                        </Badge>
                      </td>

                      <td className="py-3.5 px-4 font-mono font-bold text-slate-700 dark:text-slate-300">
                        {item.risk_score ?? '—'}/100
                      </td>

                      <td className="py-3.5 px-4 text-slate-400 whitespace-nowrap">
                        {formatDateTime(item.created_at || item.timestamp)}
                      </td>

                      <td className="py-3.5 px-4 text-right whitespace-nowrap">
                        <div className="flex items-center justify-end gap-2">
                          <Link
                            to={`/analysis/${itemId}`}
                            className="px-2.5 py-1 text-[11px] font-semibold rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
                          >
                            View
                          </Link>
                          <Button
                            variant="primary"
                            onClick={() => loadReport(itemId)}
                            className="px-2.5 py-1 text-[11px] h-7 flex items-center gap-1 bg-blue-600 hover:bg-blue-700"
                          >
                            <FileText size={12} />
                            <span>Generate Report</span>
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
};

export default Reports;
