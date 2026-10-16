import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useLocation, useSearchParams, Link } from 'react-router-dom';
import { analysis } from '../services/api';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import ErrorState from '../components/ErrorState';
import {
  Link2,
  Hash,
  Mail,
  QrCode,
  FileCode,
  Upload,
  X,
  AlertCircle,
  CheckCircle2,
  ArrowRight,
  Shield,
  ShieldAlert,
  Info,
  Lock,
  Layers,
  Cpu,
  Zap,
  RefreshCw,
} from 'lucide-react';

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

const MODES = [
  {
    id: 'url',
    label: 'URL Analysis',
    shortLabel: 'URL',
    icon: Link2,
    placeholder: 'https://example-security-alert.com/login',
    description: 'Inspect live links, redirection hops, domain intelligence, and brand spoofing.',
    details: [
      'SSL Certificate & WHOIS domain age validation',
      'Typosquatting and Levenshtein target similarity',
      'Redirect chains and HTTP status tracking',
      'VirusTotal & threat intelligence correlation',
    ],
  },
  {
    id: 'hash',
    label: 'Hash Lookup',
    shortLabel: 'HASH',
    icon: Hash,
    placeholder: 'e.g. 5d41402abc4b2a76b9719d911017c592 or SHA-256',
    description: 'Query MD5, SHA-1, and SHA-256 artifact signatures against reputation feeds.',
    details: [
      'Multi-source threat database lookup',
      'Known malware signature identification',
      'VirusTotal detection telemetry',
      'Confidence scoring and risk assessment',
    ],
  },
  {
    id: 'email',
    label: 'Email Inspector',
    shortLabel: 'EMAIL',
    icon: Mail,
    accept: '.eml,.msg,message/rfc822',
    description: 'Upload raw .eml or .msg files to audit headers, sender authentication, and content signals.',
    details: [
      'SPF, DKIM, and DMARC alignment validation',
      'Header anomaly and spoofed display-name analysis',
      'Suspicious urgent phrasing & NLP cues',
      'Embedded attachment and link extraction',
    ],
  },
  {
    id: 'qr',
    label: 'QR Code Scanner',
    shortLabel: 'QR CODE',
    icon: QrCode,
    accept: 'image/png,image/jpeg,image/jpg,image/webp,image/bmp',
    description: 'Upload QR code images to decode quishing payloads and evaluate downstream URLs.',
    details: [
      'High-precision QR visual decoding',
      'Payload extraction & obfuscation detection',
      'Automated routing to multi-layer URL engine',
      'Quishing risk determination',
    ],
  },
  {
    id: 'file',
    label: 'File Artifact',
    shortLabel: 'FILE',
    icon: FileCode,
    accept: '*/*',
    description: 'Inspect suspicious documents, scripts, executables, and compressed archives statically.',
    details: [
      'File format and MIME type verification',
      'VBA macro and embedded script detection',
      'High-risk extension & entropy inspection',
      'Cryptographic hash generation and lookup',
    ],
  },
];

const Analyze = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();

  // Determine initial mode from search params, navigation state, or default to 'url'
  const initialMode =
    searchParams.get('mode') || location.state?.mode || 'url';
  const [activeMode, setActiveMode] = useState(
    MODES.some((m) => m.id === initialMode) ? initialMode : 'url'
  );

  // Form states
  const [urlInput, setUrlInput] = useState('');
  const [hashInput, setHashInput] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [filePreview, setFilePreview] = useState(null);
  const [dragOver, setDragOver] = useState(false);

  // Submission & Validation states
  const [fieldError, setFieldError] = useState('');
  const [apiError, setApiError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [analysisStage, setAnalysisStage] = useState(0);

  const fileInputRef = useRef(null);

  // Sync mode changes with URL search params
  const handleModeChange = (modeId) => {
    setActiveMode(modeId);
    setSearchParams({ mode: modeId }, { replace: true });
    setFieldError('');
    setApiError('');
    setSelectedFile(null);
    if (filePreview) {
      URL.revokeObjectURL(filePreview);
      setFilePreview(null);
    }
  };

  // Clean up object URLs on unmount
  useEffect(() => {
    return () => {
      if (filePreview) URL.revokeObjectURL(filePreview);
    };
  }, [filePreview]);

  // Handle file selection
  const handleFileChange = (file) => {
    setFieldError('');
    setApiError('');
    if (!file) return;

    if (file.size > MAX_FILE_SIZE) {
      setFieldError(`File size (${(file.size / (1024 * 1024)).toFixed(1)} MB) exceeds the 10 MB limit.`);
      setSelectedFile(null);
      return;
    }

    setSelectedFile(file);

    // If QR mode, generate preview
    if (activeMode === 'qr' && file.type.startsWith('image/')) {
      const url = URL.createObjectURL(file);
      setFilePreview(url);
    } else {
      if (filePreview) URL.revokeObjectURL(filePreview);
      setFilePreview(null);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setDragOver(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileChange(e.dataTransfer.files[0]);
    }
  };

  const removeSelectedFile = () => {
    setSelectedFile(null);
    if (filePreview) {
      URL.revokeObjectURL(filePreview);
      setFilePreview(null);
    }
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  // Format file size
  const formatFileSize = (bytes) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  // Submit Handler
  const handleSubmit = async (e) => {
    e.preventDefault();
    setFieldError('');
    setApiError('');

    let result = null;

    try {
      if (activeMode === 'url') {
        const trimmed = urlInput.trim();
        if (!trimmed) {
          setFieldError('Please enter a URL to inspect.');
          return;
        }
        if (!/^https?:\/\//i.test(trimmed)) {
          setFieldError('URL must begin with http:// or https://');
          return;
        }
        if (trimmed.length > 2048) {
          setFieldError('URL must not exceed 2048 characters.');
          return;
        }

        setSubmitting(true);
        setAnalysisStage(1);
        result = await analysis.submitUrl(trimmed);
      } else if (activeMode === 'hash') {
        const cleanHash = hashInput.trim().toLowerCase();
        if (!cleanHash) {
          setFieldError('Please enter a hash to inspect.');
          return;
        }
        if (!/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(cleanHash)) {
          setFieldError('Invalid hash format. Must be MD5 (32 hex), SHA-1 (40 hex), or SHA-256 (64 hex).');
          return;
        }

        setSubmitting(true);
        setAnalysisStage(1);
        result = await analysis.submitHash(cleanHash);
      } else if (activeMode === 'email') {
        if (!selectedFile) {
          setFieldError('Please select or drop an email file (.eml / .msg).');
          return;
        }
        setSubmitting(true);
        setAnalysisStage(1);
        result = await analysis.submitEmail(selectedFile);
      } else if (activeMode === 'qr') {
        if (!selectedFile) {
          setFieldError('Please select or drop a QR code image.');
          return;
        }
        setSubmitting(true);
        setAnalysisStage(1);
        result = await analysis.submitQr(selectedFile);
      } else if (activeMode === 'file') {
        if (!selectedFile) {
          setFieldError('Please select or drop a suspicious file artifact.');
          return;
        }
        setSubmitting(true);
        setAnalysisStage(1);
        result = await analysis.submitFile(selectedFile);
      }

      // Navigate to analysis result page on success
      const analysisId = result?.analysis_id || result?.id;
      if (analysisId) {
        navigate(`/analysis/${analysisId}`);
      } else {
        throw new Error('Analysis completed but no investigation ID was returned.');
      }
    } catch (err) {
      setSubmitting(false);
      const detail = err?.data?.detail || err?.message || 'Analysis request failed. Please check parameters and retry.';
      setApiError(typeof detail === 'string' ? detail : JSON.stringify(detail));
    }
  };

  const currentModeConfig = MODES.find((m) => m.id === activeMode) || MODES[0];

  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      {/* Header */}
      <div className="border-b border-slate-200 dark:border-slate-800 pb-4">
        <div className="flex items-center gap-2 mb-1">
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Threat Analysis Console
          </h1>
          <span className="px-2 py-0.5 text-xs font-semibold rounded-md bg-blue-100 text-blue-800 dark:bg-blue-900/60 dark:text-blue-300">
            Multi-Layer
          </span>
        </div>
        <p className="text-sm text-slate-500 dark:text-slate-400">
          Submit suspicious URLs, file signatures, emails, QR images, or documents for multi-engine threat detection and explainable risk scoring.
        </p>
      </div>

      {/* Mode Segmented Controls / Tabs */}
      <div className="flex items-center gap-1.5 p-1.5 bg-slate-100 dark:bg-slate-900/80 rounded-xl border border-slate-200 dark:border-slate-800 overflow-x-auto">
        {MODES.map((mode) => {
          const Icon = mode.icon;
          const isActive = activeMode === mode.id;
          return (
            <button
              key={mode.id}
              type="button"
              onClick={() => handleModeChange(mode.id)}
              disabled={submitting}
              className={`flex-1 min-w-[120px] flex items-center justify-center gap-2 py-2.5 px-3 rounded-lg text-xs font-semibold transition-all duration-150 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                isActive
                  ? 'bg-white dark:bg-slate-800 text-blue-600 dark:text-blue-400 shadow-sm border border-slate-200/80 dark:border-slate-700'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-200/50 dark:hover:bg-slate-800/40'
              }`}
            >
              <Icon size={16} />
              <span>{mode.shortLabel}</span>
            </button>
          );
        })}
      </div>

      {/* Main Grid: Analysis Form (Left) & Engine Info (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        {/* Left 2 Cols: Form Panel */}
        <div className="lg:col-span-2">
          <Card className="border border-slate-200 dark:border-slate-800 p-6 shadow-sm">
            {submitting ? (
              /* Processing Animation State */
              <div className="py-12 px-4 text-center space-y-6">
                <div className="relative inline-flex items-center justify-center">
                  <div className="w-16 h-16 border-4 border-blue-600/20 border-t-blue-600 rounded-full animate-spin"></div>
                  <ShieldAlert className="w-7 h-7 text-blue-600 dark:text-blue-400 absolute" />
                </div>

                <div className="space-y-2">
                  <h3 className="text-lg font-bold text-slate-900 dark:text-slate-100">
                    Executing Multi-Layer Security Scan
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400 max-w-md mx-auto">
                    Artifact uploaded. Extracting structural signals, querying threat intelligence feeds, and computing the explainable risk matrix.
                  </p>
                </div>

                {/* Simulated Pipeline Stages Indicator */}
                <div className="max-w-md mx-auto bg-slate-50 dark:bg-slate-950/60 p-4 rounded-xl border border-slate-200 dark:border-slate-800 text-left space-y-2.5">
                  <div className="flex items-center gap-2 text-xs font-semibold text-emerald-600 dark:text-emerald-400">
                    <CheckCircle2 size={14} className="shrink-0" />
                    <span>Artifact received & validated</span>
                  </div>
                  <div className="flex items-center gap-2 text-xs font-semibold text-blue-600 dark:text-blue-400 animate-pulse">
                    <Zap size={14} className="shrink-0" />
                    <span>Running multi-layer analyzers & correlation</span>
                  </div>
                  <div className="flex items-center gap-2 text-xs text-slate-400 dark:text-slate-500">
                    <Layers size={14} className="shrink-0" />
                    <span>Generating explainable verdict & evidence logs</span>
                  </div>
                </div>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-6">
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                      {currentModeConfig.label}
                    </h2>
                    <Badge variant="info">Max 10 MB</Badge>
                  </div>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    {currentModeConfig.description}
                  </p>
                </div>

                {/* Mode Specific Inputs */}
                {activeMode === 'url' && (
                  <div className="space-y-2">
                    <label
                      htmlFor="url-input"
                      className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
                    >
                      Target URL <span className="text-red-500">*</span>
                    </label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                        <Link2 size={18} />
                      </div>
                      <input
                        id="url-input"
                        type="url"
                        value={urlInput}
                        onChange={(e) => {
                          setUrlInput(e.target.value);
                          if (fieldError) setFieldError('');
                        }}
                        placeholder="https://example-security-alert.com/login"
                        className="w-full pl-10 pr-4 py-2.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 text-sm placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                        autoFocus
                      />
                    </div>
                  </div>
                )}

                {activeMode === 'hash' && (
                  <div className="space-y-2">
                    <label
                      htmlFor="hash-input"
                      className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
                    >
                      Cryptographic Hash (MD5 / SHA-1 / SHA-256) <span className="text-red-500">*</span>
                    </label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                        <Hash size={18} />
                      </div>
                      <input
                        id="hash-input"
                        type="text"
                        value={hashInput}
                        onChange={(e) => {
                          setHashInput(e.target.value);
                          if (fieldError) setFieldError('');
                        }}
                        placeholder="e.g. 5d41402abc4b2a76b9719d911017c592"
                        className="w-full pl-10 pr-4 py-2.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 text-sm font-mono placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                        autoFocus
                      />
                    </div>
                  </div>
                )}

                {(activeMode === 'email' || activeMode === 'qr' || activeMode === 'file') && (
                  <div className="space-y-2">
                    <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300">
                      Upload Artifact <span className="text-red-500">*</span>
                    </label>

                    {!selectedFile ? (
                      <div
                        onDragOver={handleDragOver}
                        onDragLeave={handleDragLeave}
                        onDrop={handleDrop}
                        onClick={() => fileInputRef.current?.click()}
                        className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-colors ${
                          dragOver
                            ? 'border-blue-500 bg-blue-50/50 dark:bg-blue-950/20'
                            : 'border-slate-300 dark:border-slate-700 hover:border-blue-400 dark:hover:border-blue-500 bg-slate-50/50 dark:bg-slate-900/40'
                        }`}
                      >
                        <input
                          ref={fileInputRef}
                          type="file"
                          accept={currentModeConfig.accept}
                          onChange={(e) => handleFileChange(e.target.files?.[0])}
                          className="hidden"
                        />
                        <div className="w-12 h-12 rounded-full bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 flex items-center justify-center mx-auto mb-3">
                          <Upload size={22} />
                        </div>
                        <p className="text-sm font-semibold text-slate-800 dark:text-slate-200">
                          Click to browse or drag & drop artifact
                        </p>
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                          Supported: {currentModeConfig.accept === '*/*' ? 'Any file up to 10 MB' : currentModeConfig.accept}
                        </p>
                      </div>
                    ) : (
                      /* Selected File Preview Box */
                      <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/40 flex items-center justify-between gap-4">
                        <div className="flex items-center gap-3 min-w-0">
                          {filePreview ? (
                            <img
                              src={filePreview}
                              alt="QR Preview"
                              className="w-14 h-14 object-contain rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-1 shrink-0"
                            />
                          ) : (
                            <div className="w-10 h-10 rounded-lg bg-blue-100 dark:bg-blue-900/60 text-blue-600 dark:text-blue-400 flex items-center justify-center shrink-0">
                              <currentModeConfig.icon size={20} />
                            </div>
                          )}
                          <div className="min-w-0">
                            <p className="text-sm font-semibold text-slate-800 dark:text-slate-200 truncate">
                              {selectedFile.name}
                            </p>
                            <p className="text-xs text-slate-500 dark:text-slate-400">
                              {formatFileSize(selectedFile.size)}
                            </p>
                          </div>
                        </div>

                        <button
                          type="button"
                          onClick={removeSelectedFile}
                          aria-label="Remove selected file"
                          className="p-1.5 rounded-lg text-slate-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-slate-200/60 dark:hover:bg-slate-700 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500"
                        >
                          <X size={18} />
                        </button>
                      </div>
                    )}
                  </div>
                )}

                {/* Inline Field Error */}
                {fieldError && (
                  <div className="p-3 rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 flex items-center gap-2 text-xs font-semibold text-red-700 dark:text-red-400">
                    <AlertCircle size={15} className="shrink-0" />
                    <span>{fieldError}</span>
                  </div>
                )}

                {/* API Error Box */}
                {apiError && (
                  <ErrorState
                    title="Analysis Request Failed"
                    message={apiError}
                  />
                )}

                {/* Submit Action */}
                <div className="pt-2 flex items-center justify-between">
                  <div className="text-[11px] text-slate-400 dark:text-slate-500 flex items-center gap-1">
                    <Lock size={12} />
                    <span>Multi-tenant isolated scan</span>
                  </div>

                  <Button
                    type="submit"
                    variant="primary"
                    disabled={submitting}
                    className="flex items-center gap-2 px-6"
                  >
                    <span>Inspect Artifact</span>
                    <ArrowRight size={15} />
                  </Button>
                </div>
              </form>
            )}
          </Card>
        </div>

        {/* Right 1 Col: Engine Explanation & Telemetry Details */}
        <div className="space-y-6">
          <Card className="border border-slate-200 dark:border-slate-800 p-5 shadow-sm">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-7 h-7 rounded-lg bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400 flex items-center justify-center">
                <Cpu size={16} />
              </div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                Inspection Capabilities
              </h3>
            </div>

            <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">
              Every artifact submitted to PHISHGUARD is processed through specialized static and contextual heuristic engines:
            </p>

            <ul className="space-y-2">
              {currentModeConfig.details.map((detail, idx) => (
                <li
                  key={idx}
                  className="flex items-start gap-2 text-xs text-slate-700 dark:text-slate-300"
                >
                  <CheckCircle2 size={14} className="text-emerald-500 shrink-0 mt-0.5" />
                  <span>{detail}</span>
                </li>
              ))}
            </ul>
          </Card>

          {/* Quick Shortcut to History */}
          <div className="p-5 rounded-xl bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 space-y-2">
            <h4 className="text-xs font-bold text-slate-800 dark:text-slate-200">
              Need Previous Scans?
            </h4>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Access your historical investigation logs, score breakdowns, and exported reports.
            </p>
            <Link
              to="/history"
              className="inline-flex items-center gap-1.5 text-xs font-semibold text-blue-600 dark:text-blue-400 hover:underline pt-1"
            >
              <span>Go to Investigation History</span>
              <ArrowRight size={13} />
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Analyze;
