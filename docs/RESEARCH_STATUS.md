# PHISHGUARD Research & Implementation Status Table

## 1. System Component Status Matrix

| Component / Layer | Status | Implementation File / Evidence | Current Capabilities & Verification |
| :--- | :--- | :--- | :--- |
| **URL Lexical ML** | `[IMPLEMENTED]` | `src/features/url_features.py`, `src/models/url_model_inference.py` | 14 lexical features extracted; runtime inference with graceful fallback. Verified via 114 passing tests. |
| **Domain Intelligence** | `[IMPLEMENTED]` | `src/features/domain_intelligence.py` | DNS resolution, TLD extraction, subdomain count, hostname length parsing. |
| **Brand Intelligence** | `[IMPLEMENTED]` | `src/features/brand_intelligence.py` | Brand mismatch detection for 10+ major targeted enterprises (PayPal, Google, Apple, etc.). |
| **IP Intelligence** | `[IMPLEMENTED]` | `src/features/ip_intelligence.py` | Hostname-to-IP resolution with private IP range detection. |
| **Redirect Analysis** | `[IMPLEMENTED]` | `src/features/redirect_analyzer.py` | Safe hop counting with SSRF re-validation at every redirect destination. |
| **Webpage Analysis** | `[IMPLEMENTED]` | `src/features/webpage_analyzer.py` | Static HTML parser detecting password fields, external form actions, and iframes. |
| **Email Authentication** | `[IMPLEMENTED]` | `src/features/email_authentication.py` | SPF, DKIM, DMARC header inspection, display-name spoofing detection. |
| **Email NLP Analysis** | `[IMPLEMENTED]` | `src/features/email_nlp.py` | Heuristic scoring of urgency, financial threat, and account suspension keywords. |
| **Attachment Analysis** | `[IMPLEMENTED]` | `src/features/attachment_analyzer.py` | MIME type verification via magic bytes, SHA-256 calculation, file type validation. |
| **Macro Analysis** | `[IMPLEMENTED]` | `src/features/macro_analyzer.py` | OLE/VBA stream parser detecting suspicious auto-exec macros via `olefile`. |
| **PE Static Analysis** | `[IMPLEMENTED]` | `src/features/pe_analyzer.py` | Windows Portable Executable header inspection and section entropy analysis. |
| **QR Code Analysis** | `[IMPLEMENTED]` | `src/features/qr_analyzer.py` | QR image decoding to extract embedded URLs for downstream threat scanning. |
| **Threat Intelligence** | `[IMPLEMENTED]` | `src/features/reputation.py` | VirusTotal v3 API query handler with local memory caching and error recovery. |
| **Evidence Correlator** | `[IMPLEMENTED]` | `src/analysis/evidence_correlator.py` | Detects compound multi-layer threats and applies calibrated risk modifiers. |
| **Central Risk Engine** | `[IMPLEMENTED]` | `src/analysis/risk_engine.py` | Weighted signal engine with clamp $[0, 100]$ and categorical levels (LOW-CRITICAL). |
| **Multi-Layer Aggregator** | `[IMPLEMENTED]` | `src/analysis/multi_layer_risk.py` | Non-intrusive aggregation maintaining caller risk posture and missing layers. |
| **AI Security Analyst** | `[IMPLEMENTED]` | `app/routers/chat.py`, `src/analysis/gemini_analyzer.py` | Conversational debriefing grounded in scan telemetry; deterministic rule fallback. |
| **FastAPI Backend** | `[IMPLEMENTED]` | `app/main.py`, `app/routers/` | Complete REST API with Argon2id auth, JWT verification, and scan history. |
| **Enterprise Frontend** | `[IMPLEMENTED]` | `frontend/` (HTML/CSS/JS) | SaaS dashboard, multi-layer analysis tabs, history filters, and chat drawer. |
| **Security Hardening** | `[IMPLEMENTED]` | `app/main.py`, `src/features/` | SSRF/DNS rebinding guards, CSP, X-Frame-Options, 10MB upload cap, IDOR checks. |
| **Sandbox VM Detonation** | `[PLANNED]` | `src/sandbox/analysis_engine.py`, `docs/sandbox_architecture.md` | Interface and security boundary defined; hypervisor execution intentionally not implemented. |

---

## 2. Research Experiments Status Matrix

| Experiment | Title | Status | Evidence / Location | Key Findings |
| :--- | :--- | :--- | :--- | :--- |
| **Experiment 1** | Layer-by-Layer Evaluation | `[COMPLETED]` | `src/research/experiment_01_layer_evaluation.py`, `data/processed/research/experiment_01_results.csv` | Multi-layer pipeline achieved 0 FP on missing layers; execution latency under 0.65 ms/sample. |
| **Experiment 2** | External Generalization | `[IMPLEMENTED]` | `src/analysis/external_evaluation.py` | Evaluation module constructed for measuring out-of-distribution dataset drift. |
| **Experiment 3** | Adversarial URL Robustness | `[HISTORICAL BASELINE]` | `docs/experiments.md/experiments_comparisions.md` | Subdomain manipulation caused 45% prediction change rate on 14-feature lexical models. |
| **Experiment 4** | Feature Ablation Study | `[PLANNED]` | Documented in `docs/RESEARCH_METHODOLOGY.md` | Full leave-one-out importance study on 641k samples scheduled for next phase. |
| **Experiment 5** | Explainable AI (XAI) | `[PARTIALLY IMPLEMENTED]` | `src/analysis/model_explainer.py`, `src/analysis/ai_analysis.py` | Rule-based attribution and conversational AI operational; human-in-the-loop study pending. |
| **Experiment 6** | Dynamic Sandbox Telemetry | `[PLANNED]` | `docs/sandbox_architecture.md` | Telemetry schema defined; VM automation planned. |
