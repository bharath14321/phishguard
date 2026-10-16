import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, FileText, ArrowLeft, CheckCircle2, AlertOctagon } from 'lucide-react';
import Card from '../components/Card';
import Badge from '../components/Badge';

const TermsOfService = () => {
  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-4xl mx-auto space-y-8">
        {/* Header navigation */}
        <div className="flex items-center justify-between">
          <Link
            to="/"
            className="inline-flex items-center gap-2 text-sm font-medium text-blue-400 hover:text-blue-300 transition-colors"
          >
            <ArrowLeft size={16} />
            <span>Back to PHISHGUARD</span>
          </Link>
          <div className="flex items-center gap-2">
            <Shield className="text-blue-500" size={24} />
            <span className="font-bold text-lg tracking-tight">PHISHGUARD</span>
          </div>
        </div>

        {/* Title block */}
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Badge variant="info">Terms of Service</Badge>
            <span className="text-xs text-slate-400">Effective Date: October 2026</span>
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">
            Terms of Service
          </h1>
          <p className="text-base text-slate-400 max-w-3xl">
            Please read these Terms of Service carefully before utilizing the PHISHGUARD Automated Threat Detection & Security Operations Platform.
          </p>
        </div>

        {/* Content sections */}
        <div className="space-y-6">
          <Card className="p-6 sm:p-8 space-y-4 bg-slate-950/80 border-slate-800">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <CheckCircle2 size={20} className="text-blue-400" />
              1. Acceptance of Terms
            </h2>
            <p className="text-sm text-slate-300 leading-relaxed">
              By creating an account, connecting a mailbox via OAuth, or submitting security artifacts (URLs, emails, attachments, hashes, QR codes) to PHISHGUARD, you agree to be bound by these Terms of Service and all applicable cybersecurity and data protection regulations.
            </p>
          </Card>

          <Card className="p-6 sm:p-8 space-y-4 bg-slate-950/80 border-slate-800">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <Shield size={20} className="text-indigo-400" />
              2. Authorized Security Defensive Use
            </h2>
            <p className="text-sm text-slate-300 leading-relaxed">
              PHISHGUARD is engineered solely for defensive cybersecurity operations, threat detection, incident triage, security awareness training, and phishing mitigation.
            </p>
            <p className="text-sm text-slate-300 leading-relaxed">
              You agree NOT to use PHISHGUARD to generate malicious payloads, evade antivirus detection, conduct unauthorized penetration testing against third-party systems without written authorization, or reverse engineer proprietary threat intelligence models.
            </p>
          </Card>

          <Card className="p-6 sm:p-8 space-y-4 bg-slate-950/80 border-slate-800">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <AlertOctagon size={20} className="text-amber-400" />
              3. Detection Accuracy & Operational Disclaimers
            </h2>
            <p className="text-sm text-slate-300 leading-relaxed">
              PHISHGUARD utilizes state-of-the-art machine learning models, local threat intelligence feeds, heuristic rule engines, and optional AI security analysts. However, no automated security platform can guarantee 100% detection of all zero-day phishing attacks or novel evasion techniques.
            </p>
            <p className="text-sm text-slate-300 leading-relaxed">
              Detection outputs, risk scores, and AI recommendations are provided to assist qualified human security analysts and should be evaluated alongside organizational security policies.
            </p>
          </Card>

          <Card className="p-6 sm:p-8 space-y-4 bg-slate-950/80 border-slate-800">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <FileText size={20} className="text-emerald-400" />
              4. Service Availability & Modifications
            </h2>
            <p className="text-sm text-slate-300 leading-relaxed">
              We reserve the right to update, enhance, or modify detection capabilities, heuristics, and API interfaces to respond to evolving cyber threat landscapes and maintain platform reliability.
            </p>
          </Card>
        </div>

        {/* Footer */}
        <div className="pt-6 border-t border-slate-800 text-center text-xs text-slate-500">
          <p>© {new Date().getFullYear()} PHISHGUARD Security Operations. All rights reserved.</p>
        </div>
      </div>
    </div>
  );
};

export default TermsOfService;
