import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, Lock, FileCheck, ArrowLeft, Database, Key } from 'lucide-react';
import Card from '../components/Card';
import Badge from '../components/Badge';

const PrivacyPolicy = () => {
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
            <Badge variant="info">Enterprise Security & Compliance</Badge>
            <span className="text-xs text-slate-400">Effective Date: October 2026</span>
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">
            Privacy Policy
          </h1>
          <p className="text-base text-slate-400 max-w-3xl">
            PHISHGUARD is committed to the highest standards of data security, tenant isolation, and cryptographic confidentiality when inspecting security artifacts and integrated mailboxes.
          </p>
        </div>

        {/* Content sections */}
        <div className="space-y-6">
          <Card className="p-6 sm:p-8 space-y-4 bg-slate-950/80 border-slate-800">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <Shield size={20} className="text-blue-400" />
              1. Information We Collect and Process
            </h2>
            <p className="text-sm text-slate-300 leading-relaxed">
              PHISHGUARD processes user-submitted and automated security artifacts strictly for phishing detection, malicious URL classification, email authentication auditing, attachment safety analysis, and social engineering threat prevention.
            </p>
            <ul className="list-disc list-inside space-y-1.5 text-sm text-slate-400 pl-2">
              <li><strong className="text-slate-200">Account Information:</strong> Username, email address, password hashes (Argon2id), and authentication session tokens.</li>
              <li><strong className="text-slate-200">Security Artifacts:</strong> URLs submitted for investigation, file hashes (SHA-256), email header telemetry (SPF, DKIM, DMARC), extracted attachment metadata, and decoded QR payload strings.</li>
              <li><strong className="text-slate-200">Integrated Mailbox Telemetry (Optional):</strong> When you link your Gmail account, PHISHGUARD accesses inbound email messages via Google OAuth 2.0 and Google Cloud Pub/Sub webhooks strictly to analyze threat indicators.</li>
            </ul>
          </Card>

          <Card className="p-6 sm:p-8 space-y-4 bg-slate-950/80 border-slate-800">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <Key size={20} className="text-indigo-400" />
              2. Google OAuth 2.0 & Gmail API Compliance
            </h2>
            <p className="text-sm text-slate-300 leading-relaxed">
              PHISHGUARD's use of information received from Gmail APIs adheres to Google API Services User Data Policy, including the Limited Use requirements:
            </p>
            <ul className="list-disc list-inside space-y-2 text-sm text-slate-400 pl-2">
              <li><strong className="text-slate-200">Limited Use:</strong> We only access email messages and metadata necessary to perform automated phishing and security risk analysis for your protection.</li>
              <li><strong className="text-slate-200">No Human Reading:</strong> No human personnel at PHISHGUARD read your emails unless you explicitly provide consent to diagnose a specific technical support ticket.</li>
              <li><strong className="text-slate-200">No Advertising:</strong> We never sell, transfer, or use email contents for advertising, profiling, or commercial data brokering.</li>
              <li><strong className="text-slate-200">Encryption at Rest:</strong> OAuth access tokens and refresh tokens are encrypted at rest using AES-256-GCM / Fernet cryptographic keys.</li>
            </ul>
          </Card>

          <Card className="p-6 sm:p-8 space-y-4 bg-slate-950/80 border-slate-800">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <Database size={20} className="text-cyan-400" />
              3. Multi-Tenant Isolation & Security Defenses
            </h2>
            <p className="text-sm text-slate-300 leading-relaxed">
              All user investigations, threat feeds, and mailbox records are strictly isolated at the database query layer. Every API endpoint enforces strict multi-tenant authorization guards preventing Insecure Direct Object References (IDOR).
            </p>
          </Card>

          <Card className="p-6 sm:p-8 space-y-4 bg-slate-950/80 border-slate-800">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <Lock size={20} className="text-emerald-400" />
              4. Data Retention and Deletion
            </h2>
            <p className="text-sm text-slate-300 leading-relaxed">
              You retain full ownership of your data. You may disconnect connected mail accounts or delete your investigation history at any time from the PHISHGUARD Settings console. Disconnecting a mailbox immediately terminates Google Cloud Pub/Sub push notification watches and purges stored authentication tokens.
            </p>
          </Card>

          <Card className="p-6 sm:p-8 space-y-4 bg-slate-950/80 border-slate-800">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <FileCheck size={20} className="text-purple-400" />
              5. Contact & Privacy Inquiries
            </h2>
            <p className="text-sm text-slate-300 leading-relaxed">
              For any questions regarding PHISHGUARD privacy practices, OAuth security posture, or data deletion requests, please contact our security team at{' '}
              <a href="mailto:security@phishguard.internal" className="text-blue-400 underline font-mono">
                security@phishguard.internal
              </a>.
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

export default PrivacyPolicy;
