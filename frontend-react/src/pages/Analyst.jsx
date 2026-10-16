import React, { useState, useEffect, useRef } from 'react';
import { useLocation, useSearchParams, useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { chat, analysis } from '../services/api';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import ErrorState from '../components/ErrorState';
import {
  Bot,
  Sparkles,
  Send,
  User,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Trash2,
  HelpCircle,
  ArrowLeft,
  ExternalLink,
  Layers,
  Lock,
  Cpu,
  CornerDownLeft,
  CheckCircle2,
  XCircle,
  FileCode,
} from 'lucide-react';
import FormattedMarkdown from '../components/FormattedMarkdown';

/**
 * Format markdown text safely for chat messages
 */
const FormattedMessage = ({ text }) => <FormattedMarkdown text={text} />;

const DEFAULT_SUGGESTIONS = [
  'Why was this artifact classified as suspicious?',
  'What evidence contributed most to the risk score?',
  'What does the VirusTotal threat intelligence indicate?',
  'What remains unknown or unverified in this scan?',
  'What containment and incident response steps should I take?',
  'Summarize this investigation for an executive incident report',
];

const Analyst = () => {
  const { user } = useAuth();
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  // Active investigation context ID (if any)
  const queryAnalysisId = searchParams.get('analysis_id');
  const [activeAnalysisId, setActiveAnalysisId] = useState(
    location.state?.analysisId || (queryAnalysisId ? parseInt(queryAnalysisId, 10) : null)
  );

  const [activeContextInfo, setActiveContextInfo] = useState({
    target: location.state?.target || '',
    artifactType: location.state?.artifactType || '',
    riskLevel: location.state?.riskLevel || '',
  });

  // Conversation history
  const [messages, setMessages] = useState([
    {
      id: 'welcome',
      role: 'analyst',
      content:
        'Hello! I am your **PHISHGUARD AI Security Analyst**. I analyze forensic evidence, explain multi-layer risk factors, and guide triage investigations.\n\n' +
        'My responses are grounded strictly in authenticated scan telemetry, distinguishing confirmed ground truth from heuristic predictions and unresolved lookups.',
      provider: 'security_analyst',
      timestamp: new Date().toISOString(),
    },
  ]);

  const [inputMessage, setInputMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [suggestions, setSuggestions] = useState(DEFAULT_SUGGESTIONS);

  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);
  const prevAnalysisIdRef = useRef(activeAnalysisId);
  const isSubmittingRef = useRef(false);
  const hasHandledInitialPromptRef = useRef(false);

  // Sync state when location.state or query params change
  useEffect(() => {
    const newId = location.state?.analysisId || (queryAnalysisId ? parseInt(queryAnalysisId, 10) : null);
    if (newId !== activeAnalysisId) {
      setActiveAnalysisId(newId);
    }
    if (location.state?.target || location.state?.artifactType || location.state?.riskLevel) {
      setActiveContextInfo({
        target: location.state?.target || '',
        artifactType: location.state?.artifactType || '',
        riskLevel: location.state?.riskLevel || '',
      });
    }
  }, [location.state, queryAnalysisId]);

  // Isolate conversation history when activeAnalysisId changes
  useEffect(() => {
    if (prevAnalysisIdRef.current !== activeAnalysisId) {
      prevAnalysisIdRef.current = activeAnalysisId;
      setMessages([
        {
          id: `welcome-${activeAnalysisId || 'general'}`,
          role: 'analyst',
          content: activeAnalysisId
            ? `Hello! I am your **PHISHGUARD AI Security Analyst** ready to investigate **Investigation #${activeAnalysisId}**.\n\nAsk me any question regarding this artifact's forensic signals, threat intelligence, ML probability, evidence sufficiency, or recommended triage steps.`
            : 'Hello! I am your **PHISHGUARD AI Security Analyst**. I analyze forensic evidence, explain multi-layer risk factors, and guide triage investigations.\n\nMy responses are grounded strictly in authenticated scan telemetry, distinguishing confirmed ground truth from heuristic predictions and unresolved lookups.',
          provider: 'security_analyst',
          timestamp: new Date().toISOString(),
        },
      ]);
    }
  }, [activeAnalysisId]);

  // Auto-scroll to bottom of conversation
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading]);

  // Load context metadata & suggestions if an analysisId is active
  useEffect(() => {
    if (activeAnalysisId) {
      chat.suggestions(activeAnalysisId)
        .then((res) => {
          if (res?.suggestions && Array.isArray(res.suggestions) && res.suggestions.length > 0) {
            setSuggestions(res.suggestions);
          }
          if (res?.artifact_type || res?.risk_level) {
            setActiveContextInfo((prev) => ({
              ...prev,
              artifactType: res.artifact_type || prev.artifactType,
              riskLevel: res.risk_level || prev.riskLevel,
            }));
          }
        })
        .catch((err) => {
          console.warn('Suggestions lookup warning:', err);
        });

      // Also retrieve analysis basic info if target not yet loaded
      if (!activeContextInfo.target) {
        analysis.get(activeAnalysisId)
          .then((res) => {
            setActiveContextInfo({
              target: res.url || `Investigation #${activeAnalysisId}`,
              artifactType: res.artifact_type,
              riskLevel: res.risk_level,
            });
          })
          .catch(() => {});
      }
    }
  }, [activeAnalysisId]);

  // Handle initial prompt passed from AnalysisResult page (single execution guard)
  useEffect(() => {
    if (location.state?.initialPrompt && !hasHandledInitialPromptRef.current) {
      hasHandledInitialPromptRef.current = true;
      const initialPrompt = location.state.initialPrompt;
      // Clear initialPrompt from location state to prevent replay on history navigations
      navigate(location.pathname + location.search, {
        replace: true,
        state: { ...location.state, initialPrompt: undefined },
      });
      sendMessage(initialPrompt);
    }
  }, [location.state?.initialPrompt]);

  const sendMessage = async (textToSend) => {
    const text = (textToSend || inputMessage).trim();
    if (!text || isSubmittingRef.current) return;

    isSubmittingRef.current = true;
    setError(null);
    setInputMessage('');

    // Append user message
    const userMsg = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: text,
      timestamp: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setLoading(true);

    try {
      const payload = {
        message: text,
        analysis_id: activeAnalysisId || null,
      };

      const response = await chat.send(payload);

      const analystMsg = {
        id: `analyst-${Date.now()}`,
        role: 'analyst',
        content: response.response || 'No response generated.',
        provider: response.provider || 'security_analyst',
        risk_level: response.risk_level,
        artifact_type: response.artifact_type,
        timestamp: response.timestamp || new Date().toISOString(),
      };

      setMessages((prev) => [...prev, analystMsg]);
    } catch (err) {
      setError(err?.data?.detail || err?.message || 'Failed to communicate with the Security Analyst engine.');
    } finally {
      isSubmittingRef.current = false;
      setLoading(false);
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      // Form submit handler will cleanly trigger sendMessage
      e.target.form?.requestSubmit();
    }
  };

  const clearChat = () => {
    setMessages([
      {
        id: 'welcome',
        role: 'analyst',
        content:
          'Conversation cleared. Ask any question about your investigations, threat intelligence indicators, or remediation steps.',
        provider: 'security_analyst',
        timestamp: new Date().toISOString(),
      },
    ]);
    setError(null);
  };

  const clearActiveContext = () => {
    setActiveAnalysisId(null);
    setActiveContextInfo({ target: '', artifactType: '', riskLevel: '' });
    setSearchParams({}, { replace: true });
    setSuggestions(DEFAULT_SUGGESTIONS);
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto flex flex-col h-[calc(100vh-8rem)]">
      {/* 1. Header & Active Context Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-3 border-b border-slate-200 dark:border-slate-800 shrink-0">
        <div>
          <div className="flex items-center gap-2 mb-0.5">
            <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Bot size={22} className="text-blue-600 dark:text-blue-400" />
              <span>AI Security Analyst</span>
            </h1>
            <span className="px-2 py-0.5 text-xs font-semibold rounded-md bg-gradient-to-r from-blue-600 to-indigo-600 text-white shadow-sm">
              Gemini-Powered
            </span>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Authoritative, evidence-grounded cybersecurity assistant.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {messages.length > 1 && (
            <Button
              variant="secondary"
              onClick={clearChat}
              className="flex items-center gap-1.5 text-xs py-1.5 px-2.5"
            >
              <Trash2 size={13} />
              <span>Clear History</span>
            </Button>
          )}
        </div>
      </div>

      {/* Context Indicator Pill */}
      {activeAnalysisId ? (
        <div className="p-3 rounded-xl bg-blue-50/80 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-900/60 flex items-center justify-between gap-3 text-xs shrink-0">
          <div className="flex items-center gap-2 min-w-0">
            <ShieldAlert size={16} className="text-blue-600 dark:text-blue-400 shrink-0" />
            <span className="font-semibold text-slate-800 dark:text-slate-200 shrink-0">
              Active Context:
            </span>
            <span className="font-mono text-slate-700 dark:text-slate-300 truncate" title={activeContextInfo.target || `#${activeAnalysisId}`}>
              Investigation #{activeAnalysisId} {activeContextInfo.target ? `— ${activeContextInfo.target}` : ''}
            </span>
            {activeContextInfo.riskLevel && (
              <Badge variant={activeContextInfo.riskLevel === 'HIGH' || activeContextInfo.riskLevel === 'CRITICAL' ? 'danger' : 'warning'}>
                {activeContextInfo.riskLevel}
              </Badge>
            )}
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <Link
              to={`/analysis/${activeAnalysisId}`}
              className="font-semibold text-blue-600 dark:text-blue-400 hover:underline flex items-center gap-1"
            >
              <span>View Scan</span>
              <ExternalLink size={12} />
            </Link>
            <button
              type="button"
              onClick={clearActiveContext}
              aria-label="Detach active analysis context"
              className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 p-1"
            >
              ✕
            </button>
          </div>
        </div>
      ) : (
        <div className="p-2.5 rounded-xl bg-slate-100/60 dark:bg-slate-900/40 border border-slate-200/80 dark:border-slate-800 flex items-center justify-between gap-3 text-xs text-slate-500 dark:text-slate-400 shrink-0">
          <div className="flex items-center gap-2">
            <Layers size={15} />
            <span>Global Knowledge Mode — No single artifact attached. You can query threat vectors, detection logic, and IOC analysis.</span>
          </div>
          <Link to="/analyze" className="text-blue-600 dark:text-blue-400 font-semibold hover:underline shrink-0">
            Analyze Artifact
          </Link>
        </div>
      )}

      {/* 2. Messages Conversation Area */}
      <div className="flex-1 overflow-y-auto space-y-4 p-4 rounded-2xl bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 shadow-inner">
        {messages.map((msg) => {
          const isAnalyst = msg.role === 'analyst';
          return (
            <div
              key={msg.id}
              className={`flex items-start gap-3 ${isAnalyst ? 'justify-start' : 'justify-end'}`}
            >
              {isAnalyst && (
                <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-blue-600 to-indigo-600 text-white flex items-center justify-center shrink-0 shadow-sm mt-0.5">
                  <Bot size={18} />
                </div>
              )}

              <div
                className={`max-w-[85%] md:max-w-[75%] rounded-2xl p-4 space-y-2 shadow-sm ${
                  isAnalyst
                    ? 'bg-slate-50 dark:bg-slate-800/80 border border-slate-200/80 dark:border-slate-700/80'
                    : 'bg-blue-600 text-white'
                }`}
              >
                {/* Message Header / Provider info */}
                <div className="flex items-center justify-between gap-4 text-[10px] font-semibold opacity-75 pb-1 border-b border-slate-200/50 dark:border-slate-700/50">
                  <span>{isAnalyst ? 'PHISHGUARD ANALYST' : (user?.username || 'ANALYST')}</span>
                  {isAnalyst && (
                    <span className="flex items-center gap-1 font-mono">
                      <Sparkles size={11} className="text-indigo-400" />
                      {msg.provider === 'gemini' ? 'Gemini AI Analyst' : 'Grounded Analyst Engine'}
                    </span>
                  )}
                </div>

                {/* Content */}
                {isAnalyst ? (
                  <FormattedMessage text={msg.content} />
                ) : (
                  <p className="text-xs md:text-sm whitespace-pre-wrap leading-relaxed">
                    {msg.content}
                  </p>
                )}
              </div>

              {!isAnalyst && (
                <div className="w-8 h-8 rounded-lg bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300 flex items-center justify-center shrink-0 font-bold text-xs mt-0.5">
                  {(user?.username || user?.email || 'U').charAt(0).toUpperCase()}
                </div>
              )}
            </div>
          );
        })}

        {/* Loading Indicator */}
        {loading && (
          <div className="flex items-start gap-3">
            <div className="w-8 h-8 rounded-lg bg-blue-600 text-white flex items-center justify-center shrink-0 animate-pulse">
              <Bot size={18} />
            </div>
            <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 space-y-2">
              <div className="flex items-center gap-2 text-xs font-semibold text-blue-600 dark:text-blue-400">
                <RefreshCw size={13} className="animate-spin" />
                <span>Correlating evidence and synthesizing response…</span>
              </div>
              <p className="text-[11px] text-slate-400 dark:text-slate-500">
                Analyzing cross-layer signals, VirusTotal intelligence, and epistemic findings.
              </p>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* 3. Error Banner */}
      {error && (
        <ErrorState
          title="Analyst Query Failed"
          message={error}
          className="shrink-0 py-3"
        />
      )}

      {/* 4. Suggested Questions Quick Buttons */}
      <div className="space-y-1.5 shrink-0">
        <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
          <HelpCircle size={12} />
          <span>Suggested Questions:</span>
        </div>
        <div className="flex items-center gap-2 overflow-x-auto pb-1 scrollbar-none">
          {suggestions.slice(0, 4).map((q, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => sendMessage(q)}
              disabled={loading}
              className="shrink-0 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-700 dark:text-slate-300 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700/80 border border-slate-200 dark:border-slate-700 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 text-left truncate max-w-xs"
            >
              {q}
            </button>
          ))}
        </div>
      </div>

      {/* 5. Message Composer */}
      <div className="shrink-0">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            sendMessage();
          }}
          className="relative flex items-center"
        >
          <input
            ref={inputRef}
            type="text"
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={
              activeAnalysisId
                ? `Ask about Investigation #${activeAnalysisId} (e.g. "What evidence increased the risk?")...`
                : 'Ask the AI Security Analyst a question...'
            }
            disabled={loading}
            className="w-full pl-4 pr-24 py-3 rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 text-xs md:text-sm placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent shadow-sm"
          />

          <button
            type="submit"
            disabled={loading || !inputMessage.trim()}
            aria-label="Send message to AI analyst"
            className="absolute right-2 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed text-white text-xs font-semibold flex items-center gap-1.5 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <span>Send</span>
            <Send size={13} />
          </button>
        </form>
      </div>
    </div>
  );
};

export default Analyst;
