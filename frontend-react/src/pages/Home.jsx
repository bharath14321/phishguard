import React from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  Mail,
  Globe,
  Link2,
  FileText,
  Zap,
  Brain,
  BarChart2,
  CheckCircle,
  AlertTriangle,
  XCircle,
  HelpCircle,
  RefreshCw,
  TrendingUp,
  Bot,
  Cpu,
} from 'lucide-react';

/**
 * Home – PHISHGUARD landing page implementation.
 * Follows the detailed design specification.
 * Uses Tailwind CSS for layout and lucide-react icons.
 * No external images are used; all UI elements are built with React + Tailwind.
 */
const Home = () => (
  <div className="bg-gray-50 dark:bg-gray-950 text-gray-900 dark:text-gray-100">
    {/* SECTION 2 – HERO */}
    <section className="max-w-7xl mx-auto px-4 py-16 md:py-24 lg:py-32">
      <div className="grid md:grid-cols-2 gap-12 items-center">
        {/* Left side */}
        <div className="space-y-6">
          <h1 className="text-4xl md:text-5xl font-extrabold text-gray-800 dark:text-gray-100 leading-tight">
            See the threat.<br />Understand the evidence.
          </h1>
          <p className="text-lg text-gray-600 dark:text-gray-300">
            AI‑powered phishing and threat analysis across URLs, emails, QR codes, and files.
          </p>
          <div className="flex flex-col sm:flex-row gap-4">
            <Link
              to="/login"
              className="inline-block px-6 py-3 bg-cyan-600 text-white rounded-lg font-medium hover:bg-cyan-700 transition"
            >
              Analyze a Threat
            </Link>
            <Link
              to="/signup"
              className="inline-block px-6 py-3 border border-cyan-600 text-cyan-600 rounded-lg font-medium hover:bg-cyan-50 dark:hover:bg-cyan-900 transition"
            >
              Explore Platform
            </Link>
          </div>
        </div>
        {/* Right side – mock dashboard */}
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold text-gray-800 dark:text-gray-100">PHISHGUARD</h2>
            <div className="flex items-center space-x-2 text-sm text-gray-500 dark:text-gray-400">
              <Shield size={18} />
              <span>THREAT DETECTED</span>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <AlertTriangle className="text-red-600" size={20} />
            <span className="font-bold text-red-600">Risk: HIGH</span>
          </div>
          <div className="border-t border-gray-200 dark:border-gray-700 pt-4 space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="flex items-center space-x-1">
                <Link2 size={16} />
                <span>Brand / Domain mismatch</span>
              </span>
              <Badge text="Evidence" />
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="flex items-center space-x-1">
                <RefreshCw size={16} />
                <span>Suspicious redirect</span>
              </span>
              <Badge text="Evidence" />
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="flex items-center space-x-1">
                <Mail size={16} />
                <span>Credential form</span>
              </span>
              <Badge text="Evidence" />
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="flex items-center space-x-1">
                <Zap size={16} />
                <span>Threat intelligence</span>
              </span>
              <Badge text="Evidence" />
            </div>
          </div>
          <p className="mt-4 text-sm text-gray-600 dark:text-gray-300 italic">
            "Multiple independent signals indicate elevated phishing risk."
          </p>
        </div>
      </div>
    </section>

    {/* SECTION 3 – TRUST / CAPABILITIES */}
    <section id="capabilities" className="bg-gray-100 dark:bg-gray-900 py-12">
      <div className="max-w-6xl mx-auto px-4">
        <h2 className="text-2xl font-bold text-center text-gray-800 dark:text-gray-100 mb-8">
          One threat. Multiple signals.
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-6">
          {capabilityCards.map((card) => (
            <div
              key={card.title}
              className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 text-center hover:shadow-md transition"
            >
              <card.icon className="mx-auto mb-2 text-cyan-600" size={32} />
              <h3 className="font-semibold text-gray-800 dark:text-gray-100 mb-1">{card.title}</h3>
              <p className="text-sm text-gray-600 dark:text-gray-300">{card.description}</p>
            </div>
          ))}
        </div>
      </div>
    </section>

    {/* SECTION 4 – PROBLEM / VALUE */}
    <section id="value" className="py-12">
      <div className="max-w-6xl mx-auto px-4 grid md:grid-cols-2 gap-8 items-center">
        <div className="space-y-4">
          <h2 className="text-3xl font-bold text-gray-800 dark:text-gray-100">
            A suspicious link is only the beginning.
          </h2>
          <p className="text-lg text-gray-600 dark:text-gray-300">
            PHISHGUARD correlates identity, domain, webpage, attachment, reputation, and AI evidence to help analysts understand the full threat.
          </p>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <SignalCard title="Brand mismatch" icon={AlertTriangle} />
          <SignalCard title="Domain signal" icon={Globe} />
          <SignalCard title="Redirect" icon={RefreshCw} />
          <SignalCard title="Credential form" icon={Mail} />
          <div className="col-span-2 flex justify-center items-center mt-4">
            <div className="flex items-center space-x-2">
              <TrendingUp className="text-cyan-600" size={20} />
              <span className="font-bold text-cyan-600">RISK ASSESSMENT</span>
            </div>
          </div>
        </div>
      </div>
    </section>

    {/* SECTION 5 – PRODUCT VISUAL */}
    <section id="product-visual" className="bg-gray-100 dark:bg-gray-900 py-12">
      <div className="max-w-5xl mx-auto px-4">
        <h2 className="text-2xl font-bold text-center text-gray-800 dark:text-gray-100 mb-6">
          See what the analyst sees.
        </h2>
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6 space-y-4">
          <div className="flex justify-between items-center">
            <span className="font-semibold text-gray-800 dark:text-gray-100">Risk Score</span>
            <span className="bg-red-600 text-white px-2 py-0.5 rounded">85%</span>
          </div>
          <div className="border-t border-gray-200 dark:border-gray-700 pt-4">
            <h3 className="font-medium text-gray-700 dark:text-gray-200 mb-2">Evidence Timeline</h3>
            <ul className="space-y-2">
              <li className="flex items-center space-x-2 text-sm">
                <CheckCircle className="text-green-600" size={16} />
                <span>Domain reputation OK</span>
              </li>
              <li className="flex items-center space-x-2 text-sm">
                <AlertTriangle className="text-yellow-600" size={16} />
                <span>Redirect to suspicious URL</span>
              </li>
              <li className="flex items-center space-x-2 text-sm">
                <XCircle className="text-red-600" size={16} />
                <span>Credential collection form detected</span>
              </li>
            </ul>
          </div>
          <div className="border-t border-gray-200 dark:border-gray-700 pt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <h4 className="font-medium text-gray-700 dark:text-gray-200 mb-1">Domain Intelligence</h4>
              <p className="text-sm text-gray-600 dark:text-gray-300">example.com – registered 2022, no prior abuse.</p>
            </div>
            <div>
              <h4 className="font-medium text-gray-700 dark:text-gray-200 mb-1">Redirect Evidence</h4>
              <p className="text-sm text-gray-600 dark:text-gray-300">302 → malicious.example.org</p>
            </div>
          </div>
          <div className="border-t border-gray-200 dark:border-gray-700 pt-4">
            <h4 className="font-medium text-gray-700 dark:text-gray-200 mb-1">AI Explanation</h4>
            <p className="text-sm text-gray-600 dark:text-gray-300 italic">
              Multiple signals (domain mismatch, redirect, credential form) contribute to a high‑risk assessment.
            </p>
          </div>
        </div>
      </div>
    </section>

    {/* SECTION 6 – MULTI‑LAYER PIPELINE */}
    <section id="pipeline" className="py-12">
      <div className="max-w-4xl mx-auto px-4 text-center">
        <h2 className="text-2xl font-bold text-gray-800 dark:text-gray-100 mb-6">
          From artifact to evidence.
        </h2>
        <div className="flex flex-col items-center space-y-4">
          {pipelineSteps.map((step, idx) => (
            <React.Fragment key={step}>
              <div className="inline-block bg-cyan-100 dark:bg-cyan-900 text-cyan-800 dark:text-cyan-200 px-4 py-2 rounded-full font-medium">
                {step}
              </div>
              {idx < pipelineSteps.length - 1 && (
                <svg className="w-6 h-6 text-cyan-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 5v14M5 12h14" />
                </svg>
              )}
            </React.Fragment>
          ))}
        </div>
      </div>
    </section>

    {/* SECTION 7 – AI SECURITY ANALYST */}
    <section id="ai-analyst" className="bg-gray-100 dark:bg-gray-900 py-12">
      <div className="max-w-5xl mx-auto px-4 space-y-6">
        <h2 className="text-2xl font-bold text-center text-gray-800 dark:text-gray-100">
          Don't just classify the threat. Understand why.
        </h2>
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="space-y-4">
            <div className="flex items-start space-x-3">
              <HelpCircle className="text-cyan-600" size={24} />
              <div>
                <p className="font-medium text-gray-800 dark:text-gray-100">Analyst:</p>
                <p className="text-sm text-gray-600 dark:text-gray-300">Why is this artifact high risk?</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <Bot className="text-cyan-600" size={24} />
              <div>
                <p className="font-medium text-gray-800 dark:text-gray-100">PHISHGUARD AI Analyst:</p>
                <ul className="list-disc list-inside text-sm text-gray-600 dark:text-gray-300">
                  <li>Observed evidence: brand/domain mismatch, suspicious redirect, credential collection form.</li>
                  <li>Inference: attacker attempts credential harvesting via phishing page.</li>
                  <li>Unknown: exact attacker infrastructure.</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>

    {/* SECTION 8 – THREAT INTELLIGENCE */}
    <section id="threat-intel" className="py-12">
      <div className="max-w-6xl mx-auto px-4">
        <h2 className="text-2xl font-bold text-center text-gray-800 dark:text-gray-100 mb-8">
          Put every signal in context.
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
          {threatCards.map((card) => (
            <div
              key={card.title}
              className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 text-center hover:shadow-md transition"
            >
              <card.icon className="mx-auto mb-2 text-cyan-600" size={28} />
              <h3 className="font-semibold text-gray-800 dark:text-gray-100 mb-1">{card.title}</h3>
              <p className="text-sm text-gray-600 dark:text-gray-300">{card.description}</p>
            </div>
          ))}
        </div>
      </div>
    </section>

    {/* SECTION 9 – EXPLAINABILITY */}
    <section id="explainability" className="bg-gray-100 dark:bg-gray-900 py-12">
      <div className="max-w-5xl mx-auto px-4">
        <h2 className="text-2xl font-bold text-center text-gray-800 dark:text-gray-100 mb-8">
          Every decision should have evidence.
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {explainCards.map((card) => (
            <div
              key={card.title}
              className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4"
            >
              <div className="flex items-center space-x-2 mb-2">
                <card.icon className="text-cyan-600" size={20} />
                <h3 className="font-medium text-gray-800 dark:text-gray-100">{card.title}</h3>
                <span className={`px-2 py-0.5 rounded text-xs ${card.severity === 'High' ? 'bg-red-200 text-red-800' : card.severity === 'Medium' ? 'bg-yellow-200 text-yellow-800' : 'bg-green-200 text-green-800'}`}>
                  {card.severity}
                </span>
              </div>
              <p className="text-sm text-gray-600 dark:text-gray-300">{card.description}</p>
            </div>
          ))}
        </div>
      </div>
    </section>

    {/* SECTION 10 – RESEARCH */}
    <section id="research" className="py-12">
      <div className="max-w-4xl mx-auto px-4 text-center space-y-4">
        <h2 className="text-2xl font-bold text-gray-800 dark:text-gray-100">
          Built to be evaluated, not just demonstrated.
        </h2>
        <p className="text-lg text-gray-600 dark:text-gray-300">
          Ongoing research focuses on detection performance, multi‑layer analysis, adversarial robustness, explainable AI, and model generalization.
        </p>
        <Link
          to="/research"
          className="inline-block mt-4 px-6 py-3 bg-cyan-600 text-white rounded-lg font-medium hover:bg-cyan-700 transition"
        >
          Explore Research
        </Link>
      </div>
    </section>

    {/* SECTION 11 – FINAL CTA */}
    <section className="bg-cyan-600 text-white py-12">
      <div className="max-w-3xl mx-auto px-4 text-center space-y-4">
        <h2 className="text-3xl font-bold">Your security analysis starts here.</h2>
        <p className="text-lg">Investigate suspicious URLs, emails, QR codes, and files with evidence‑driven analysis.</p>
        <div className="flex flex-col sm:flex-row justify-center gap-4 mt-4">
          <Link
            to="/signup"
            className="inline-block px-6 py-3 bg-white text-cyan-600 rounded-lg font-medium hover:bg-gray-100 transition"
          >
            Get Started
          </Link>
          <Link
            to="/login"
            className="inline-block px-6 py-3 border border-white text-white rounded-lg font-medium hover:bg-white hover:text-cyan-600 transition"
          >
            Analyze a Threat
          </Link>
        </div>
      </div>
    </section>

    {/* SECTION 12 – FOOTER handled by PublicLayout */}
  </div>
);

/** Badge component used in the mock dashboard */
const Badge = ({ text }) => (
  <span className="bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 px-2 py-0.5 rounded text-xs font-medium">
    {text}
  </span>
);

/** SignalCard component for the problem/value illustration */
const SignalCard = ({ title, icon: Icon }) => (
  <div className="flex flex-col items-center bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-3">
    <Icon className="text-cyan-600 mb-2" size={24} />
    <span className="text-sm font-medium text-gray-800 dark:text-gray-100">{title}</span>
  </div>
);

/** Capability cards data */
const capabilityCards = [
  { title: 'URL Analysis', description: 'Deep inspection of links and redirects.', icon: Globe },
  { title: 'Email Analysis', description: 'Parse headers, bodies, and attachments.', icon: Mail },
  { title: 'QR Analysis', description: 'Decode and evaluate embedded URLs.', icon: Zap },
  { title: 'File Analysis', description: 'Static and dynamic file inspection.', icon: FileText },
  { title: 'Threat Intelligence', description: 'Cross‑reference global intel sources.', icon: BarChart2 },
  { title: 'AI Security Analyst', description: 'Explainable AI‑driven insights.', icon: Brain },
];

/** Pipeline steps data */
const pipelineSteps = [
  'URL / Email / QR / File',
  'Artifact Analysis',
  'Domain & Identity',
  'Web / Attachment Intelligence',
  'Threat Intelligence',
  'AI + Evidence Correlation',
  'Risk + Explanation',
];

/** Threat intelligence cards data */
const threatCards = [
  { title: 'Reputation', description: 'Aggregated reputation scores.', icon: CheckCircle },
  { title: 'Domain Intelligence', description: 'WHOIS, age, SSL info.', icon: Globe },
  { title: 'IP Intelligence', description: 'Geolocation, abuse history.', icon: Cpu },
  { title: 'Redirect Analysis', description: 'Chain of redirects and endpoints.', icon: RefreshCw },
];

/** Explainability cards data */
const explainCards = [
  { title: 'Brand / Domain mismatch', severity: 'High', description: 'Observed mismatch indicates possible spoofing.', icon: AlertTriangle },
  { title: 'Suspicious redirect', severity: 'Medium', description: 'Redirect leads to a known malicious host.', icon: RefreshCw },
  { title: 'Credential collection', severity: 'High', description: 'Form collects login credentials.', icon: Mail },
  { title: 'Authentication anomaly', severity: 'Low', description: 'Unexpected auth flow detected.', icon: XCircle },
  { title: 'Suspicious attachment', severity: 'Medium', description: 'Attachment exhibits suspicious patterns.', icon: FileText },
  { title: 'Threat intelligence', severity: 'Low', description: 'External intel flags low‑risk.', icon: BarChart2 },
];

export default Home;
