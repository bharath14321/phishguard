import React, { useState, useEffect, useMemo } from 'react';
import { useTheme } from '../context/ThemeContext';
import { useAuth } from '../context/AuthContext';
import { mailSecurity } from '../services/api';
import {
  User,
  Palette,
  Globe,
  Clock,
  Shield,
  Key,
  Smartphone,
  Laptop,
  History,
  Activity,
  Sliders,
  Sparkles,
  Bell,
  Database,
  Trash2,
  Download,
  Share2,
  Cpu,
  Terminal,
  AlertOctagon,
  LogOut,
  Search,
  Check,
  ChevronRight,
  Sun,
  Moon,
  Eye,
  EyeOff,
  RefreshCw,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  HelpCircle,
  AlertTriangle,
  X,
  Zap,
  Mail,
  Plus,
} from 'lucide-react';

/**
 * Settings Categories Definition
 */
const SETTINGS_CATEGORIES = [
  {
    id: 'general',
    title: 'General',
    icon: User,
    description: 'Profile information, appearance preferences, language, and timezone.',
    items: [
      { id: 'profile', name: 'Profile Details', keywords: 'profile avatar name email user role organization' },
      { id: 'appearance', name: 'Appearance & Theme', keywords: 'appearance theme dark light system mode color compact motion' },
      { id: 'language-region', name: 'Language & Region', keywords: 'language region timezone date time format clock' },
    ],
  },
  {
    id: 'security',
    title: 'Security',
    icon: Shield,
    description: 'Password authentication, multi-factor security, and active sessions.',
    items: [
      { id: 'password', name: 'Password Authentication', keywords: 'password change credentials update auth login' },
      { id: '2fa', name: 'Two-Factor Authentication (2FA)', keywords: '2fa mfa two-factor authenticator otp code security' },
      { id: 'sessions', name: 'Active Sessions', keywords: 'sessions devices login active workstation mobile logout' },
      { id: 'activity', name: 'Login Activity & Audit', keywords: 'activity history audit logs events ip timestamp' },
    ],
  },
  {
    id: 'analysis',
    title: 'Analysis Engine',
    icon: Sliders,
    description: 'Multi-layer heuristics, threat intelligence lookups, and AI analyst behaviors.',
    items: [
      { id: 'engine-behavior', name: 'Default Analysis Behavior', keywords: 'analysis engine behavior qr ocr attachments sandbox heuristics' },
      { id: 'risk-display', name: 'Risk Score & Severity Display', keywords: 'risk score severity badges cutoff threshold' },
      { id: 'threat-intel', name: 'Threat Intelligence Feeds', keywords: 'threat intelligence ti virustotal local feeds dns spf dkim' },
      { id: 'ai-analyst', name: 'AI Security Analyst Preferences', keywords: 'ai analyst llm assistant gemini persona explanations' },
    ],
  },
  {
    id: 'notifications',
    title: 'Notifications',
    icon: Bell,
    description: 'Security alert thresholds, email reporting, and webhook integrations.',
    items: [
      { id: 'alerts', name: 'Alert Subscriptions', keywords: 'alerts critical threat notifications email digest completed' },
      { id: 'webhooks', name: 'Webhooks & Slack', keywords: 'webhooks slack discord pagerduty alert integrations' },
    ],
  },
  {
    id: 'privacy',
    title: 'Privacy & Data',
    icon: Database,
    description: 'Analysis retention policies, telemetry preferences, and data exports.',
    items: [
      { id: 'retention', name: 'Analysis Retention', keywords: 'privacy data retention telemetry store history anonymize' },
      { id: 'export-clear', name: 'Export & Clear Data', keywords: 'export download data json csv clear history delete' },
    ],
  },
  {
    id: 'integrations',
    title: 'Integrations & API',
    icon: Share2,
    description: 'Mail Security (Gmail/Outlook), VirusTotal API, Gemini AI engine, and REST credentials.',
    items: [
      { id: 'mail-security', name: 'Mail Security (Gmail & Outlook)', keywords: 'mail email gmail outlook microsoft 365 inbox webhook imap mailbox' },
      { id: 'virustotal', name: 'VirusTotal Integration', keywords: 'virustotal api key quota escalation reputation' },
      { id: 'ai-provider', name: 'AI Provider Settings', keywords: 'ai gemini api provider llm key model' },
      { id: 'api-access', name: 'Developer REST API', keywords: 'api developer keys tokens rest programmatic access' },
    ],
  },
  {
    id: 'advanced',
    title: 'Advanced & Diagnostics',
    icon: Terminal,
    description: 'Experimental model canary features, debug logging, and client cache.',
    items: [
      { id: 'experimental', name: 'Experimental Features', keywords: 'experimental canary hybrid model sandbox features beta' },
      { id: 'diagnostics', name: 'System Diagnostics & Cache', keywords: 'diagnostics debug logs cache clear bundle' },
    ],
  },
  {
    id: 'danger',
    title: 'Danger Zone',
    icon: AlertOctagon,
    description: 'Destructive account actions and global session termination.',
    isDanger: true,
    items: [
      { id: 'signout-all', name: 'Sign Out All Devices', keywords: 'signout logout all devices sessions terminate' },
      { id: 'delete-account', name: 'Delete Account', keywords: 'delete account erase destroy permanent danger' },
    ],
  },
];

const Settings = () => {
  const { theme, resolvedTheme, setTheme } = useTheme();
  const { user, logout } = useAuth();

  // Navigation State
  const [activeCategory, setActiveCategory] = useState('general');
  const [searchQuery, setSearchQuery] = useState('');

  // UI Preference Local State
  const [compactMode, setCompactMode] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(false);
  const [language, setLanguage] = useState('en-US');
  const [timezone, setTimezone] = useState('UTC');

  // Analysis Preferences State
  const [inspectionLevel, setInspectionLevel] = useState('deep');
  const [autoQrScan, setAutoQrScan] = useState(true);
  const [autoAttachmentScan, setAutoAttachmentScan] = useState(true);
  const [scoreFormat, setScoreFormat] = useState('both'); // 'score' | 'badge' | 'both'
  const [localTiEnabled, setLocalTiEnabled] = useState(true);
  const [vtEscalationEnabled, setVtEscalationEnabled] = useState(true);
  const [aiPersona, setAiPersona] = useState('soc-analyst');

  // Notification State
  const [notifyCritical, setNotifyCritical] = useState(true);
  const [notifyComplete, setNotifyComplete] = useState(false);
  const [emailDigest, setEmailDigest] = useState(true);

  // Privacy State
  const [retentionDays, setRetentionDays] = useState('90');
  const [anonymizeUrls, setAnonymizeUrls] = useState(false);

  // Integration State
  const [vtApiKey, setVtApiKey] = useState('••••••••••••••••••••••••••••••••');
  const [showVtKey, setShowVtKey] = useState(false);
  const [geminiModel, setGeminiModel] = useState('gemini-2.5-flash');

  // Mail Security State & Handlers
  const [mailAccounts, setMailAccounts] = useState([]);
  const [loadingAccounts, setLoadingAccounts] = useState(false);
  const [connectModalProvider, setConnectModalProvider] = useState(null);
  const [newAccountEmail, setNewAccountEmail] = useState('');
  const [isSubmittingConnect, setIsSubmittingConnect] = useState(false);

  const loadMailAccounts = async () => {
    setLoadingAccounts(true);
    try {
      const res = await mailSecurity.getAccounts();
      setMailAccounts(Array.isArray(res) ? res : []);
    } catch (err) {
      console.warn('Failed to load mail accounts:', err);
    } finally {
      setLoadingAccounts(false);
    }
  };

  useEffect(() => {
    loadMailAccounts();

    // Check for OAuth redirection parameters in URL
    const urlParams = new URLSearchParams(window.location.search);
    const categoryParam = urlParams.get('category');
    if (categoryParam) {
      setActiveCategory(categoryParam);
    }

    const oauthStatus = urlParams.get('status');
    const oauthError = urlParams.get('error');
    const connectedEmail = urlParams.get('email');

    if (oauthStatus === 'gmail_connected') {
      showToast(`Gmail account ${connectedEmail ? `(${connectedEmail}) ` : ''}connected with live Pub/Sub push watch.`);
      window.history.replaceState({}, document.title, window.location.pathname + (categoryParam ? `?category=${categoryParam}` : ''));
      loadMailAccounts();
    } else if (oauthError) {
      const details = urlParams.get('details');
      showToast(`Gmail connection failed: ${oauthError}${details ? ` (${details})` : ''}`);
      window.history.replaceState({}, document.title, window.location.pathname + (categoryParam ? `?category=${categoryParam}` : ''));
    }
  }, []);

  const handleConnectGmailClick = async () => {
    try {
      const res = await mailSecurity.getGmailConnectUrl();
      if (res?.auth_url && !res.auth_url.includes('client_id=&')) {
        // Redirect to Google OAuth authorization page
        window.location.href = res.auth_url;
        return;
      }
      showToast('Google OAuth is not configured on the server. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your .env file.');
    } catch (err) {
      console.warn('Could not fetch OAuth URL:', err);
      const msg = err?.response?.data?.detail || err?.message || 'Google OAuth is not configured on the server (missing GOOGLE_CLIENT_ID).';
      showToast(msg);
    }
  };

  const handleConnectMail = async (e) => {
    e.preventDefault();
    if (!newAccountEmail || !connectModalProvider) return;
    setIsSubmittingConnect(true);
    try {
      await mailSecurity.connectAccount({
        provider: connectModalProvider,
        account_email: newAccountEmail.trim(),
      });
      showToast(`Connected ${connectModalProvider === 'gmail' ? 'Google Workspace / Gmail' : 'Microsoft 365 / Outlook'} mailbox successfully.`);
      setConnectModalProvider(null);
      setNewAccountEmail('');
      await loadMailAccounts();
    } catch (err) {
      showToast(err?.message || 'Failed to connect mail account.');
    } finally {
      setIsSubmittingConnect(false);
    }
  };

  const handleDisconnectMail = async (accountId) => {
    try {
      await mailSecurity.disconnectAccount(accountId);
      showToast('Mailbox disconnected.');
      await loadMailAccounts();
    } catch (err) {
      showToast(err?.message || 'Failed to disconnect mailbox.');
    }
  };

  const handleSyncMail = async (accountId) => {
    try {
      await mailSecurity.syncAccount(accountId);
      showToast('Mailbox sync triggered.');
      await loadMailAccounts();
    } catch (err) {
      showToast(err?.message || 'Failed to sync mailbox.');
    }
  };

  // Danger Modals State
  const [showSignoutModal, setShowSignoutModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deleteConfirmText, setDeleteConfirmText] = useState('');

  // Feedback Toast
  const [toastMessage, setToastMessage] = useState(null);

  const showToast = (msg) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  // Search Filtering
  const filteredCategories = useMemo(() => {
    if (!searchQuery.trim()) return SETTINGS_CATEGORIES;
    const q = searchQuery.toLowerCase().trim();

    return SETTINGS_CATEGORIES.map((cat) => {
      const matchCategory = cat.title.toLowerCase().includes(q) || cat.description.toLowerCase().includes(q);
      const matchingItems = cat.items.filter(
        (item) => item.name.toLowerCase().includes(q) || item.keywords.toLowerCase().includes(q)
      );

      if (matchCategory || matchingItems.length > 0) {
        return {
          ...cat,
          matchingItems: matchingItems.length > 0 ? matchingItems : cat.items,
        };
      }
      return null;
    }).filter(Boolean);
  }, [searchQuery]);

  // Current user display helpers
  const username = user?.username || 'Security Analyst';
  const email = user?.email || 'analyst@phishguard.internal';
  const initials = username.slice(0, 2).toUpperCase();

  return (
    <div className="space-y-6 animate-in fade-in duration-200 pb-16">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2 px-4 py-3 bg-slate-900 dark:bg-white text-white dark:text-slate-900 text-sm font-medium rounded-xl shadow-2xl border border-slate-700 dark:border-slate-200 animate-in slide-in-from-bottom-4">
          <ShieldCheck size={18} className="text-emerald-400 dark:text-emerald-600" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Top Header & Search Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-200 dark:border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl md:text-3xl font-extrabold tracking-tight text-slate-900 dark:text-white">
              Settings & Preferences
            </h1>
            <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800">
              Enterprise SOC
            </span>
          </div>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            Manage your account security, appearance, analysis engines, notification rules, and integrations.
          </p>
        </div>

        {/* Global Settings Search */}
        <div className="relative w-full md:w-80">
          <Search size={17} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400 dark:text-slate-500" />
          <input
            type="search"
            name="settings-search-query"
            id="settings-search-query"
            autoComplete="off"
            autoCorrect="off"
            spellCheck="false"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search settings (e.g., theme, password, 2FA)..."
            className="w-full pl-10 pr-9 py-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl text-sm text-slate-900 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all shadow-sm"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 p-0.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
            >
              <X size={15} />
            </button>
          )}
        </div>
      </div>

      {/* Main Settings Layout Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Left Sidebar Navigation */}
        <div className="lg:col-span-3 space-y-1">
          {/* Mobile Category Dropdown Selector */}
          <div className="lg:hidden mb-4">
            <label className="block text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-2">
              Select Category
            </label>
            <select
              value={activeCategory}
              onChange={(e) => setActiveCategory(e.target.value)}
              className="w-full p-2.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl text-sm font-semibold text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              {SETTINGS_CATEGORIES.map((cat) => (
                <option key={cat.id} value={cat.id}>
                  {cat.title}
                </option>
              ))}
            </select>
          </div>

          {/* Desktop Left Nav */}
          <div className="hidden lg:block bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-2 shadow-sm sticky top-24 space-y-1">
            {filteredCategories.map((cat) => {
              const Icon = cat.icon;
              const isActive = activeCategory === cat.id;

              return (
                <button
                  key={cat.id}
                  onClick={() => setActiveCategory(cat.id)}
                  className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-sm font-medium transition-all text-left ${
                    isActive
                      ? cat.isDanger
                        ? 'bg-rose-50 dark:bg-rose-950/50 text-rose-700 dark:text-rose-300 font-semibold shadow-xs'
                        : 'bg-blue-50 dark:bg-blue-950/50 text-blue-700 dark:text-blue-300 font-semibold shadow-xs'
                      : cat.isDanger
                      ? 'text-rose-600 dark:text-rose-400 hover:bg-rose-50/50 dark:hover:bg-rose-950/20'
                      : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800/60'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <Icon size={18} className={isActive ? (cat.isDanger ? 'text-rose-600 dark:text-rose-400' : 'text-blue-600 dark:text-blue-400') : 'text-slate-400 dark:text-slate-500'} />
                    <span>{cat.title}</span>
                  </div>
                  {isActive && (
                    <span className={`w-1.5 h-4 rounded-full ${cat.isDanger ? 'bg-rose-600 dark:bg-rose-400' : 'bg-blue-600 dark:bg-blue-400'}`}></span>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Right Content Panel */}
        <div className="lg:col-span-9 space-y-8">
          {/* Category: GENERAL */}
          {(activeCategory === 'general' || searchQuery) && (
            <div className="space-y-6">
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm">
                <div className="flex items-center gap-3 pb-4 border-b border-slate-100 dark:border-slate-800">
                  <User className="text-blue-600 dark:text-blue-400" size={22} />
                  <div>
                    <h2 className="text-lg font-bold text-slate-900 dark:text-white">Profile Details</h2>
                    <p className="text-xs text-slate-500 dark:text-slate-400">Your identity and authorization details within PHISHGUARD SOC.</p>
                  </div>
                </div>

                <div className="mt-6 flex flex-col sm:flex-row items-start sm:items-center gap-6">
                  <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-blue-600 to-cyan-500 text-white flex items-center justify-center text-xl font-extrabold shadow-md">
                    {initials}
                  </div>
                  <div className="space-y-1 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-base font-bold text-slate-900 dark:text-white">{username}</span>
                      <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-emerald-50 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800">
                        SOC Tier 2
                      </span>
                    </div>
                    <p className="text-sm text-slate-500 dark:text-slate-400">{email}</p>
                    <p className="text-xs text-slate-400 dark:text-slate-500">Security Organization: PHISHGUARD Cyber Defense Labs</p>
                  </div>
                </div>
              </div>

              {/* APPEARANCE SECTION */}
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm space-y-6">
                <div className="flex items-center gap-3 pb-4 border-b border-slate-100 dark:border-slate-800">
                  <Palette className="text-blue-600 dark:text-blue-400" size={22} />
                  <div>
                    <h2 className="text-lg font-bold text-slate-900 dark:text-white">Appearance & Theme</h2>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      Customize how PHISHGUARD looks on your workstation. Supports full Light, Dark, and OS sync.
                    </p>
                  </div>
                </div>

                {/* 3-Way Theme Selection Cards */}
                <div>
                  <label className="block text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-3">
                    Interface Theme (Current: {theme.toUpperCase()} • Mode: {resolvedTheme})
                  </label>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                    {/* System Card */}
                    <button
                      type="button"
                      onClick={() => {
                        setTheme('system');
                        showToast('Theme set to System Default (syncing with OS).');
                      }}
                      className={`relative p-4 rounded-2xl border text-left transition-all flex flex-col justify-between h-36 ${
                        theme === 'system'
                          ? 'border-blue-600 dark:border-blue-500 bg-blue-50/50 dark:bg-blue-950/30 ring-2 ring-blue-500/20 shadow-md'
                          : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 bg-slate-50/50 dark:bg-slate-950/50'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Laptop size={18} className="text-blue-600 dark:text-blue-400" />
                          <span className="font-bold text-sm text-slate-900 dark:text-white">System</span>
                        </div>
                        {theme === 'system' && (
                          <span className="w-5 h-5 rounded-full bg-blue-600 text-white flex items-center justify-center text-xs">
                            <Check size={12} strokeWidth={3} />
                          </span>
                        )}
                      </div>

                      {/* Visual Preview */}
                      <div className="w-full h-12 rounded-lg border border-slate-200 dark:border-slate-700 overflow-hidden flex shadow-xs">
                        <div className="w-1/2 h-full bg-slate-100 p-1 flex flex-col justify-between">
                          <div className="w-6 h-1.5 bg-slate-300 rounded"></div>
                          <div className="w-full h-3 bg-white rounded border border-slate-200"></div>
                        </div>
                        <div className="w-1/2 h-full bg-slate-900 p-1 flex flex-col justify-between">
                          <div className="w-6 h-1.5 bg-slate-700 rounded"></div>
                          <div className="w-full h-3 bg-slate-800 rounded border border-slate-700"></div>
                        </div>
                      </div>

                      <p className="text-[11px] text-slate-500 dark:text-slate-400">Match operating system</p>
                    </button>

                    {/* Light Card */}
                    <button
                      type="button"
                      onClick={() => {
                        setTheme('light');
                        showToast('Theme set to Light Mode.');
                      }}
                      className={`relative p-4 rounded-2xl border text-left transition-all flex flex-col justify-between h-36 ${
                        theme === 'light'
                          ? 'border-blue-600 dark:border-blue-500 bg-blue-50/50 dark:bg-blue-950/30 ring-2 ring-blue-500/20 shadow-md'
                          : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 bg-slate-50/50 dark:bg-slate-950/50'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Sun size={18} className="text-amber-500" />
                          <span className="font-bold text-sm text-slate-900 dark:text-white">Light</span>
                        </div>
                        {theme === 'light' && (
                          <span className="w-5 h-5 rounded-full bg-blue-600 text-white flex items-center justify-center text-xs">
                            <Check size={12} strokeWidth={3} />
                          </span>
                        )}
                      </div>

                      {/* Visual Preview */}
                      <div className="w-full h-12 rounded-lg border border-slate-200 bg-slate-100 p-1.5 flex flex-col justify-between shadow-xs">
                        <div className="flex items-center gap-1.5">
                          <div className="w-4 h-1.5 bg-blue-600 rounded"></div>
                          <div className="w-8 h-1 bg-slate-300 rounded"></div>
                        </div>
                        <div className="w-full h-4 bg-white rounded border border-slate-200"></div>
                      </div>

                      <p className="text-[11px] text-slate-500 dark:text-slate-400">Clean light surfaces</p>
                    </button>

                    {/* Dark Card */}
                    <button
                      type="button"
                      onClick={() => {
                        setTheme('dark');
                        showToast('Theme set to Dark Mode.');
                      }}
                      className={`relative p-4 rounded-2xl border text-left transition-all flex flex-col justify-between h-36 ${
                        theme === 'dark'
                          ? 'border-blue-600 dark:border-blue-500 bg-blue-50/50 dark:bg-blue-950/30 ring-2 ring-blue-500/20 shadow-md'
                          : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 bg-slate-50/50 dark:bg-slate-950/50'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Moon size={18} className="text-blue-400" />
                          <span className="font-bold text-sm text-slate-900 dark:text-white">Dark</span>
                        </div>
                        {theme === 'dark' && (
                          <span className="w-5 h-5 rounded-full bg-blue-600 text-white flex items-center justify-center text-xs">
                            <Check size={12} strokeWidth={3} />
                          </span>
                        )}
                      </div>

                      {/* Visual Preview */}
                      <div className="w-full h-12 rounded-lg border border-slate-700 bg-slate-950 p-1.5 flex flex-col justify-between shadow-xs">
                        <div className="flex items-center gap-1.5">
                          <div className="w-4 h-1.5 bg-blue-500 rounded"></div>
                          <div className="w-8 h-1 bg-slate-700 rounded"></div>
                        </div>
                        <div className="w-full h-4 bg-slate-900 rounded border border-slate-800"></div>
                      </div>

                      <p className="text-[11px] text-slate-500 dark:text-slate-400">Deep SOC dark mode</p>
                    </button>
                  </div>
                </div>

                {/* Additional UI Switches */}
                <div className="pt-4 border-t border-slate-100 dark:border-slate-800 space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-sm font-semibold text-slate-900 dark:text-white">Compact Interface Density</span>
                      <p className="text-xs text-slate-500 dark:text-slate-400">Reduces card padding and row heights for high-density SOC monitoring.</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setCompactMode(!compactMode)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                        compactMode ? 'bg-blue-600' : 'bg-slate-200 dark:bg-slate-700'
                      }`}
                    >
                      <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${compactMode ? 'translate-x-6' : 'translate-x-1'}`} />
                    </button>
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-sm font-semibold text-slate-900 dark:text-white">Reduced Motion & Transitions</span>
                      <p className="text-xs text-slate-500 dark:text-slate-400">Disables subtle layout animations and hover scale effects.</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setReducedMotion(!reducedMotion)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                        reducedMotion ? 'bg-blue-600' : 'bg-slate-200 dark:bg-slate-700'
                      }`}
                    >
                      <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${reducedMotion ? 'translate-x-6' : 'translate-x-1'}`} />
                    </button>
                  </div>
                </div>
              </div>

              {/* LANGUAGE & REGION */}
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm space-y-4">
                <div className="flex items-center gap-3 pb-4 border-b border-slate-100 dark:border-slate-800">
                  <Globe className="text-blue-600 dark:text-blue-400" size={22} />
                  <div>
                    <h2 className="text-lg font-bold text-slate-900 dark:text-white">Language & Region</h2>
                    <p className="text-xs text-slate-500 dark:text-slate-400">Localization and timestamp formatting preferences.</p>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">Language</label>
                    <select
                      value={language}
                      onChange={(e) => setLanguage(e.target.value)}
                      className="w-full p-2.5 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:outline-none"
                    >
                      <option value="en-US">English (United States)</option>
                      <option value="en-GB">English (United Kingdom)</option>
                      <option value="de-DE">Deutsch (German)</option>
                      <option value="fr-FR">Français (French)</option>
                      <option value="ja-JP">日本語 (Japanese)</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">Time Zone</label>
                    <select
                      value={timezone}
                      onChange={(e) => setTimezone(e.target.value)}
                      className="w-full p-2.5 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:outline-none"
                    >
                      <option value="UTC">UTC (Coordinated Universal Time)</option>
                      <option value="America/New_York">America/New_York (EST/EDT)</option>
                      <option value="America/Los_Angeles">America/Los_Angeles (PST/PDT)</option>
                      <option value="Europe/London">Europe/London (GMT/BST)</option>
                      <option value="Europe/Berlin">Europe/Berlin (CET/CEST)</option>
                      <option value="Asia/Kolkata">Asia/Kolkata (IST)</option>
                    </select>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Category: SECURITY */}
          {(activeCategory === 'security' || searchQuery) && (
            <div className="space-y-6">
              {/* PASSWORD */}
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm space-y-4">
                <div className="flex items-center gap-3 pb-4 border-b border-slate-100 dark:border-slate-800">
                  <Key className="text-blue-600 dark:text-blue-400" size={22} />
                  <div>
                    <h2 className="text-lg font-bold text-slate-900 dark:text-white">Password Authentication</h2>
                    <p className="text-xs text-slate-500 dark:text-slate-400">Update your account password. Requires at least 8 characters with numbers & symbols.</p>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">Current Password</label>
                    <input
                      type="password"
                      placeholder="••••••••••••"
                      className="w-full p-2.5 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">New Password</label>
                    <input
                      type="password"
                      placeholder="••••••••••••"
                      className="w-full p-2.5 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">Confirm Password</label>
                    <input
                      type="password"
                      placeholder="••••••••••••"
                      className="w-full p-2.5 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:outline-none"
                    />
                  </div>
                </div>

                <div className="flex justify-end pt-2">
                  <button
                    type="button"
                    onClick={() => showToast('Password updated successfully.')}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-xl shadow-xs transition-colors"
                  >
                    Update Password
                  </button>
                </div>
              </div>

              {/* TWO FACTOR AUTH */}
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm space-y-4">
                <div className="flex items-center justify-between pb-4 border-b border-slate-100 dark:border-slate-800">
                  <div className="flex items-center gap-3">
                    <Smartphone className="text-blue-600 dark:text-blue-400" size={22} />
                    <div>
                      <h2 className="text-lg font-bold text-slate-900 dark:text-white">Two-Factor Authentication (2FA)</h2>
                      <p className="text-xs text-slate-500 dark:text-slate-400">Protect your account with OTP email verification or authenticator apps.</p>
                    </div>
                  </div>
                  <span className="px-2.5 py-1 text-xs font-semibold rounded-full bg-emerald-50 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800 flex items-center gap-1.5">
                    <ShieldCheck size={14} /> Active (Email OTP)
                  </span>
                </div>

                <div className="flex items-center justify-between p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                  <div>
                    <span className="text-sm font-bold text-slate-900 dark:text-white">Email OTP Delivery</span>
                    <p className="text-xs text-slate-500 dark:text-slate-400">Cryptographically hashed 6-digit one-time passcodes sent to {email}.</p>
                  </div>
                  <button
                    type="button"
                    onClick={() => showToast('2FA settings verified.')}
                    className="px-3 py-1.5 border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 text-xs font-semibold rounded-lg transition-colors"
                  >
                    Reconfigure
                  </button>
                </div>
              </div>

              {/* ACTIVE SESSIONS */}
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm space-y-4">
                <div className="flex items-center gap-3 pb-4 border-b border-slate-100 dark:border-slate-800">
                  <Laptop className="text-blue-600 dark:text-blue-400" size={22} />
                  <div>
                    <h2 className="text-lg font-bold text-slate-900 dark:text-white">Active Sessions</h2>
                    <p className="text-xs text-slate-500 dark:text-slate-400">Devices currently authenticated with your PHISHGUARD account.</p>
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="flex items-center justify-between p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                    <div className="flex items-center gap-3">
                      <div className="w-9 h-9 rounded-lg bg-blue-100 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 flex items-center justify-center">
                        <Laptop size={18} />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-bold text-slate-900 dark:text-white">Linux Workstation • Chrome 128</span>
                          <span className="px-2 py-0.2 text-[10px] font-bold rounded-full bg-blue-50 text-blue-700 dark:bg-blue-950 dark:text-blue-300 border border-blue-200 dark:border-blue-800">Current</span>
                        </div>
                        <p className="text-xs text-slate-400">127.0.0.1 • Active right now</p>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center justify-between p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                    <div className="flex items-center gap-3">
                      <div className="w-9 h-9 rounded-lg bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400 flex items-center justify-center">
                        <Smartphone size={18} />
                      </div>
                      <div>
                        <span className="text-sm font-bold text-slate-900 dark:text-white">iPhone 15 Pro • Safari Mobile</span>
                        <p className="text-xs text-slate-400">192.168.1.45 • Active 2 hours ago</p>
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => showToast('Session revoked.')}
                      className="text-xs text-rose-600 dark:text-rose-400 hover:underline font-semibold"
                    >
                      Revoke
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Category: ANALYSIS ENGINE */}
          {(activeCategory === 'analysis' || searchQuery) && (
            <div className="space-y-6">
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm space-y-6">
                <div className="flex items-center gap-3 pb-4 border-b border-slate-100 dark:border-slate-800">
                  <Sliders className="text-blue-600 dark:text-blue-400" size={22} />
                  <div>
                    <h2 className="text-lg font-bold text-slate-900 dark:text-white">Default Analysis Behavior</h2>
                    <p className="text-xs text-slate-500 dark:text-slate-400">Tune inspection depth, automated extraction, and threat verification policies.</p>
                  </div>
                </div>

                {/* Inspection Depth Radio Selection */}
                <div>
                  <label className="block text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-2">
                    Default Inspection Depth
                  </label>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    {[
                      { id: 'standard', name: 'Standard', desc: 'Fast lexical features & reputation lookup' },
                      { id: 'deep', name: 'Deep Heuristic', desc: 'Full lexical, redirect, SPF/DKIM & NLP' },
                      { id: 'sandbox', name: 'Full Sandbox', desc: 'Static extraction, OCR & sandboxed detonation' },
                    ].map((mode) => (
                      <button
                        key={mode.id}
                        type="button"
                        onClick={() => {
                          setInspectionLevel(mode.id);
                          showToast(`Inspection depth set to ${mode.name}.`);
                        }}
                        className={`p-3.5 rounded-xl border text-left transition-all ${
                          inspectionLevel === mode.id
                            ? 'border-blue-600 dark:border-blue-500 bg-blue-50/50 dark:bg-blue-950/30 ring-1 ring-blue-500'
                            : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-sm text-slate-900 dark:text-white">{mode.name}</span>
                          {inspectionLevel === mode.id && <Check size={14} className="text-blue-600 dark:text-blue-400" />}
                        </div>
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{mode.desc}</p>
                      </button>
                    ))}
                  </div>
                </div>

                {/* Switches */}
                <div className="space-y-4 pt-2">
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-sm font-semibold text-slate-900 dark:text-white">QR Code Quishing OCR Extraction</span>
                      <p className="text-xs text-slate-500 dark:text-slate-400">Automatically detects, extracts, and parses QR codes inside email bodies and image attachments.</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setAutoQrScan(!autoQrScan)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                        autoQrScan ? 'bg-blue-600' : 'bg-slate-200 dark:bg-slate-700'
                      }`}
                    >
                      <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${autoQrScan ? 'translate-x-6' : 'translate-x-1'}`} />
                    </button>
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-sm font-semibold text-slate-900 dark:text-white">Attachment URL Fan-Out</span>
                      <p className="text-xs text-slate-500 dark:text-slate-400">Extracts embedded URLs from PDF/DOCX/TXT attachments and fans them out to the central URL analyzer.</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setAutoAttachmentScan(!autoAttachmentScan)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                        autoAttachmentScan ? 'bg-blue-600' : 'bg-slate-200 dark:bg-slate-700'
                      }`}
                    >
                      <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${autoAttachmentScan ? 'translate-x-6' : 'translate-x-1'}`} />
                    </button>
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-sm font-semibold text-slate-900 dark:text-white">Local Threat Intelligence (91,190 Indicators)</span>
                      <p className="text-xs text-slate-500 dark:text-slate-400">Checks high-speed local SQLite database before making external API network calls.</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setLocalTiEnabled(!localTiEnabled)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                        localTiEnabled ? 'bg-blue-600' : 'bg-slate-200 dark:bg-slate-700'
                      }`}
                    >
                      <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${localTiEnabled ? 'translate-x-6' : 'translate-x-1'}`} />
                    </button>
                  </div>
                </div>
              </div>

              {/* AI ANALYST PERSONA */}
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm space-y-4">
                <div className="flex items-center gap-3 pb-4 border-b border-slate-100 dark:border-slate-800">
                  <Sparkles className="text-blue-600 dark:text-blue-400" size={22} />
                  <div>
                    <h2 className="text-lg font-bold text-slate-900 dark:text-white">AI Security Analyst Preferences</h2>
                    <p className="text-xs text-slate-500 dark:text-slate-400">Configure the personality and reasoning style of the automated analyst.</p>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">Analyst Persona</label>
                  <select
                    value={aiPersona}
                    onChange={(e) => {
                      setAiPersona(e.target.value);
                      showToast('AI Analyst persona updated.');
                    }}
                    className="w-full p-2.5 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:outline-none"
                  >
                    <option value="soc-analyst">Tier-2 SOC Analyst (Concise, tactical, mitigation-focused)</option>
                    <option value="threat-hunter">Senior Threat Hunter (Deep attribution, IOCs & forensic telemetry)</option>
                    <option value="executive">Executive Brief (High-level business impact & risk summaries)</option>
                  </select>
                </div>
              </div>
            </div>
          )}

          {/* Category: NOTIFICATIONS */}
          {(activeCategory === 'notifications' || searchQuery) && (
            <div className="space-y-6">
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm space-y-4">
                <div className="flex items-center gap-3 pb-4 border-b border-slate-100 dark:border-slate-800">
                  <Bell className="text-blue-600 dark:text-blue-400" size={22} />
                  <div>
                    <h2 className="text-lg font-bold text-slate-900 dark:text-white">Notification Preferences</h2>
                    <p className="text-xs text-slate-500 dark:text-slate-400">Choose which security events trigger immediate notifications.</p>
                  </div>
                </div>

                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-sm font-semibold text-slate-900 dark:text-white">Critical Threat Detected Alerts</span>
                      <p className="text-xs text-slate-500 dark:text-slate-400">Instant high-priority dispatch when an artifact scores CRITICAL (Risk ≥ 85).</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setNotifyCritical(!notifyCritical)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                        notifyCritical ? 'bg-blue-600' : 'bg-slate-200 dark:bg-slate-700'
                      }`}
                    >
                      <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${notifyCritical ? 'translate-x-6' : 'translate-x-1'}`} />
                    </button>
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-sm font-semibold text-slate-900 dark:text-white">Analysis Completion Notice</span>
                      <p className="text-xs text-slate-500 dark:text-slate-400">Receive in-app status update when large files or sandbox jobs finish.</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setNotifyComplete(!notifyComplete)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                        notifyComplete ? 'bg-blue-600' : 'bg-slate-200 dark:bg-slate-700'
                      }`}
                    >
                      <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${notifyComplete ? 'translate-x-6' : 'translate-x-1'}`} />
                    </button>
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-sm font-semibold text-slate-900 dark:text-white">Daily Threat Intelligence Digest</span>
                      <p className="text-xs text-slate-500 dark:text-slate-400">Summary email of new indicators, high-risk URLs, and detection trends.</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setEmailDigest(!emailDigest)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                        emailDigest ? 'bg-blue-600' : 'bg-slate-200 dark:bg-slate-700'
                      }`}
                    >
                      <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${emailDigest ? 'translate-x-6' : 'translate-x-1'}`} />
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Category: PRIVACY & DATA */}
          {(activeCategory === 'privacy' || searchQuery) && (
            <div className="space-y-6">
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm space-y-4">
                <div className="flex items-center gap-3 pb-4 border-b border-slate-100 dark:border-slate-800">
                  <Database className="text-blue-600 dark:text-blue-400" size={22} />
                  <div>
                    <h2 className="text-lg font-bold text-slate-900 dark:text-white">Analysis Retention & History</h2>
                    <p className="text-xs text-slate-500 dark:text-slate-400">Control how long past analysis artifacts and telemetry are preserved.</p>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">Retention Window</label>
                    <select
                      value={retentionDays}
                      onChange={(e) => {
                        setRetentionDays(e.target.value);
                        showToast('Retention policy updated.');
                      }}
                      className="w-full p-2.5 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:outline-none"
                    >
                      <option value="30">30 Days</option>
                      <option value="90">90 Days (Recommended)</option>
                      <option value="365">1 Year</option>
                      <option value="0">Indefinite (SOC Archive)</option>
                    </select>
                  </div>

                  <div className="flex flex-col justify-end">
                    <button
                      type="button"
                      onClick={() => showToast('Analysis history export started. Check your downloads.')}
                      className="flex items-center justify-center gap-2 p-2.5 border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-800 dark:text-slate-200 rounded-xl text-sm font-semibold transition-colors shadow-xs"
                    >
                      <Download size={16} /> Export Analysis Logs (JSON)
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Category: INTEGRATIONS */}
          {(activeCategory === 'integrations' || searchQuery) && (
            <div className="space-y-6">
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm space-y-4">
                <div className="flex items-center gap-3 pb-4 border-b border-slate-100 dark:border-slate-800">
                  <Share2 className="text-blue-600 dark:text-blue-400" size={22} />
                  <div>
                    <h2 className="text-lg font-bold text-slate-900 dark:text-white">Threat Feed & API Integrations</h2>
                    <p className="text-xs text-slate-500 dark:text-slate-400">External intelligence providers and programmatic API access.</p>
                  </div>
                </div>

                <div className="space-y-4">
                  {/* Mailbox Security & Ingestion */}
                  <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-4">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-2">
                          <Mail size={18} className="text-blue-600 dark:text-blue-400" />
                          <span className="text-sm font-bold text-slate-900 dark:text-white">Mail Security & Inbox Protection</span>
                        </div>
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                          Automated mailbox synchronization, multi-layer heuristics, and real-time threat quarantine.
                        </p>
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={handleConnectGmailClick}
                          className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 shadow-xs transition-colors"
                        >
                          <Plus size={14} /> Connect Gmail
                        </button>
                        <button
                          type="button"
                          onClick={() => setConnectModalProvider('outlook')}
                          className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 shadow-xs transition-colors"
                        >
                          <Plus size={14} /> Connect Outlook
                        </button>
                      </div>
                    </div>

                    {/* Connected Accounts List */}
                    {loadingAccounts ? (
                      <div className="py-4 text-center text-xs text-slate-400">Loading connected mail accounts...</div>
                    ) : mailAccounts.length === 0 ? (
                      <div className="py-5 px-4 text-center rounded-lg border border-dashed border-slate-200 dark:border-slate-800 bg-white/50 dark:bg-slate-900/50">
                        <p className="text-xs text-slate-500 dark:text-slate-400 font-medium">No mailboxes connected yet.</p>
                        <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5">
                          Connect your Google Workspace or Microsoft 365 inbox to enable continuous automated threat scanning.
                        </p>
                      </div>
                    ) : (
                      <div className="space-y-2">
                        {mailAccounts.map((acc) => (
                          <div
                            key={acc.id}
                            className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800"
                          >
                            <div className="flex items-center gap-3">
                              <div className={`w-8 h-8 rounded-lg flex items-center justify-center font-bold text-xs ${
                                acc.provider === 'gmail'
                                  ? 'bg-red-50 text-red-600 dark:bg-red-950/60 dark:text-red-400 border border-red-200 dark:border-red-900'
                                  : 'bg-blue-50 text-blue-600 dark:bg-blue-950/60 dark:text-blue-400 border border-blue-200 dark:border-blue-900'
                              }`}>
                                {acc.provider === 'gmail' ? 'G' : 'M'}
                              </div>
                              <div>
                                <div className="flex items-center gap-2">
                                  <span className="text-xs font-bold text-slate-900 dark:text-white">{acc.account_email}</span>
                                  <span className="px-1.5 py-0.2 text-[10px] font-semibold rounded bg-emerald-50 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800">
                                    {acc.sync_status || 'connected'}
                                  </span>
                                </div>
                                <p className="text-[11px] text-slate-400">
                                  Provider: {acc.provider === 'gmail' ? 'Google Workspace / Gmail' : 'Microsoft 365 / Outlook'} • Scanned: {acc.total_scanned || 0} • Threats: {acc.threats_detected || 0}
                                </p>
                              </div>
                            </div>

                            <div className="flex items-center gap-2 self-end sm:self-center">
                              <button
                                type="button"
                                onClick={() => handleSyncMail(acc.id)}
                                className="px-2.5 py-1 text-xs border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 rounded-lg flex items-center gap-1 font-medium transition-colors"
                              >
                                <RefreshCw size={12} /> Sync
                              </button>
                              <button
                                type="button"
                                onClick={() => handleDisconnectMail(acc.id)}
                                className="px-2.5 py-1 text-xs text-rose-600 dark:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-950/40 rounded-lg font-semibold transition-colors"
                              >
                                Disconnect
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* VirusTotal */}
                  <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-bold text-slate-900 dark:text-white">VirusTotal v3 API</span>
                        <span className="px-2 py-0.2 text-[10px] font-bold rounded-full bg-emerald-50 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800">
                          Connected
                        </span>
                      </div>
                      <button
                        type="button"
                        onClick={() => showToast('VirusTotal API key validated.')}
                        className="text-xs text-blue-600 dark:text-blue-400 hover:underline font-semibold"
                      >
                        Test Connection
                      </button>
                    </div>

                    <div className="relative">
                      <input
                        type={showVtKey ? 'text' : 'password'}
                        value={vtApiKey}
                        onChange={(e) => setVtApiKey(e.target.value)}
                        className="w-full pr-10 pl-3 py-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-sm text-slate-900 dark:text-white font-mono"
                      />
                      <button
                        type="button"
                        onClick={() => setShowVtKey(!showVtKey)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
                      >
                        {showVtKey ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                  </div>

                  {/* Gemini AI Provider */}
                  <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-bold text-slate-900 dark:text-white">Gemini AI Engine Model</span>
                      <span className="text-xs text-slate-400">google-genai v1.0</span>
                    </div>

                    <select
                      value={geminiModel}
                      onChange={(e) => {
                        setGeminiModel(e.target.value);
                        showToast(`AI engine set to ${e.target.value}`);
                      }}
                      className="w-full p-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-sm text-slate-900 dark:text-white"
                    >
                      <option value="gemini-2.5-flash">Gemini 2.5 Flash (Ultra-fast real-time inference)</option>
                      <option value="gemini-3.8-live">Gemini 3.8 Live (Deep interactive reasoning)</option>
                      <option value="antigravity-soc">Antigravity Local SOC Analyzer</option>
                    </select>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Category: ADVANCED */}
          {(activeCategory === 'advanced' || searchQuery) && (
            <div className="space-y-6">
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm space-y-4">
                <div className="flex items-center gap-3 pb-4 border-b border-slate-100 dark:border-slate-800">
                  <Terminal className="text-blue-600 dark:text-blue-400" size={22} />
                  <div>
                    <h2 className="text-lg font-bold text-slate-900 dark:text-white">Advanced & Diagnostics</h2>
                    <p className="text-xs text-slate-500 dark:text-slate-400">Developer tooling, cache diagnostics, and canary flags.</p>
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="flex items-center justify-between p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                    <div>
                      <span className="text-sm font-bold text-slate-900 dark:text-white">Clear Frontend Cache</span>
                      <p className="text-xs text-slate-400">Wipes local state, cached verdicts, and telemetry buffers.</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => showToast('Client cache cleared.')}
                      className="px-3 py-1.5 bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 text-xs font-semibold rounded-lg transition-colors"
                    >
                      Clear Cache
                    </button>
                  </div>

                  <div className="flex items-center justify-between p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                    <div>
                      <span className="text-sm font-bold text-slate-900 dark:text-white">Export SOC Diagnostics Bundle</span>
                      <p className="text-xs text-slate-400">Generates encrypted JSON debug bundle for support & auditing.</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => showToast('Diagnostics bundle generated.')}
                      className="px-3 py-1.5 border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 text-xs font-semibold rounded-lg transition-colors"
                    >
                      Export Bundle
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Category: DANGER ZONE */}
          {(activeCategory === 'danger' || searchQuery) && (
            <div className="space-y-6">
              <div className="bg-rose-50/50 dark:bg-rose-950/20 border-2 border-rose-300 dark:border-rose-900/60 rounded-2xl p-6 shadow-sm space-y-4">
                <div className="flex items-center gap-3 pb-4 border-b border-rose-200 dark:border-rose-900/50">
                  <AlertOctagon className="text-rose-600 dark:text-rose-400" size={24} />
                  <div>
                    <h2 className="text-lg font-bold text-rose-900 dark:text-rose-300">Danger Zone</h2>
                    <p className="text-xs text-rose-700 dark:text-rose-400">Irreversible and destructive actions. Proceed with caution.</p>
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="flex items-center justify-between p-4 rounded-xl bg-white dark:bg-slate-900 border border-rose-200 dark:border-rose-900/40">
                    <div>
                      <span className="text-sm font-bold text-slate-900 dark:text-white">Sign Out of All Active Sessions</span>
                      <p className="text-xs text-slate-500 dark:text-slate-400">Invalidates all auth tokens and logs out every active desktop and mobile session.</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setShowSignoutModal(true)}
                      className="px-3.5 py-2 border border-rose-300 dark:border-rose-800 text-rose-700 dark:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-950/40 text-xs font-bold rounded-xl transition-colors"
                    >
                      Sign Out All
                    </button>
                  </div>

                  <div className="flex items-center justify-between p-4 rounded-xl bg-white dark:bg-slate-900 border border-rose-200 dark:border-rose-900/40">
                    <div>
                      <span className="text-sm font-bold text-slate-900 dark:text-white">Delete Account & SOC Telemetry</span>
                      <p className="text-xs text-slate-500 dark:text-slate-400">Permanently deletes your analyst account, custom rules, and telemetry records.</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setShowDeleteModal(true)}
                      className="px-3.5 py-2 bg-rose-600 hover:bg-rose-700 text-white text-xs font-bold rounded-xl shadow-xs transition-colors"
                    >
                      Delete Account
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Confirmation Modal: Sign Out All */}
      {showSignoutModal && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4 animate-in zoom-in-95">
            <div className="flex items-center gap-3 text-rose-600 dark:text-rose-400">
              <LogOut size={24} />
              <h3 className="text-lg font-bold text-slate-900 dark:text-white">Sign Out All Sessions?</h3>
            </div>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              This will revoke all active access tokens across all browsers, mobile devices, and API integrations.
            </p>
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setShowSignoutModal(false)}
                className="px-4 py-2 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 rounded-xl text-xs font-semibold hover:bg-slate-100 dark:hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => {
                  setShowSignoutModal(false);
                  logout();
                }}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-700 text-white rounded-xl text-xs font-semibold shadow-xs"
              >
                Yes, Sign Out All
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirmation Modal: Delete Account */}
      {showDeleteModal && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4 animate-in zoom-in-95">
            <div className="flex items-center gap-3 text-rose-600 dark:text-rose-400">
              <AlertTriangle size={24} />
              <h3 className="text-lg font-bold text-slate-900 dark:text-white">Delete Account Permanently?</h3>
            </div>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              This action cannot be undone. To confirm, please type <span className="font-bold text-rose-600 font-mono">DELETE</span> below:
            </p>
            <input
              type="text"
              value={deleteConfirmText}
              onChange={(e) => setDeleteConfirmText(e.target.value)}
              placeholder="Type DELETE to confirm"
              className="w-full p-2.5 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-sm font-mono text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-rose-500"
            />
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => {
                  setShowDeleteModal(false);
                  setDeleteConfirmText('');
                }}
                className="px-4 py-2 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 rounded-xl text-xs font-semibold hover:bg-slate-100 dark:hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={deleteConfirmText !== 'DELETE'}
                onClick={() => {
                  setShowDeleteModal(false);
                  logout();
                }}
                className={`px-4 py-2 text-white rounded-xl text-xs font-semibold shadow-xs transition-opacity ${
                  deleteConfirmText === 'DELETE' ? 'bg-rose-600 hover:bg-rose-700' : 'bg-rose-400 opacity-50 cursor-not-allowed'
                }`}
              >
                Permanently Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Connect Mailbox Modal */}
      {connectModalProvider && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4 animate-in zoom-in-95">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={`w-9 h-9 rounded-xl flex items-center justify-center text-white font-bold text-sm ${
                  connectModalProvider === 'gmail' ? 'bg-red-600' : 'bg-blue-600'
                }`}>
                  {connectModalProvider === 'gmail' ? 'G' : 'M'}
                </div>
                <div>
                  <h3 className="text-base font-bold text-slate-900 dark:text-white">
                    Connect {connectModalProvider === 'gmail' ? 'Google Workspace' : 'Microsoft 365'}
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400">Continuous inbox threat analysis</p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setConnectModalProvider(null)}
                className="p-1 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-lg"
              >
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleConnectMail} className="space-y-4 pt-2">
              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                  Mailbox Email Address
                </label>
                <input
                  type="email"
                  required
                  value={newAccountEmail}
                  onChange={(e) => setNewAccountEmail(e.target.value)}
                  placeholder={connectModalProvider === 'gmail' ? 'security-team@company.com' : 'analyst@enterprise.onmicrosoft.com'}
                  className="w-full p-2.5 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:outline-none"
                />
                <p className="text-[11px] text-slate-400 mt-1">
                  PHISHGUARD uses OAuth 2.0 with restricted read-only permissions and token encryption at rest.
                </p>
              </div>

              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setConnectModalProvider(null)}
                  className="px-4 py-2 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 rounded-xl text-xs font-semibold hover:bg-slate-100 dark:hover:bg-slate-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmittingConnect || !newAccountEmail.trim()}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-xs font-semibold shadow-xs flex items-center gap-1.5 disabled:opacity-50"
                >
                  {isSubmittingConnect ? (
                    <>
                      <RefreshCw size={13} className="animate-spin" /> Authorizing...
                    </>
                  ) : (
                    <>
                      <ShieldCheck size={14} /> Authorize & Connect
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default Settings;
