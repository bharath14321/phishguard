# PHISHGUARD: Complete Technical & Scientific Documentation

**Project Title:** PHISHGUARD — AI-Powered Multi-Layer Phishing Detection and Threat Analysis Platform  
**System Version:** 1.0.0-PROD  
**Current Test Suite Status:** 114 Unit & Integration Tests Passing (100% Pass Rate)  
**Primary Architecture:** FastAPI Python Backend + SQLite/SQLAlchemy ORM + Vanilla JS/CSS/HTML Enterprise UI  

---

## 1. Abstract

PHISHGUARD is an enterprise-grade, multi-layer cybersecurity platform engineered to detect, correlate, and explain phishing campaigns, malicious infrastructure, and multi-vector cyber attacks. Unlike conventional single-point detectors that evaluate URLs or email headers in isolation, PHISHGUARD employs an evidence-based multi-tier architecture combining lexical machine learning inference, domain and brand intelligence, cryptographic email authentication, DOM heuristic parsing, static attachment extraction, and centralized evidence correlation. The platform features an explainable AI layer with a dedicated AI Security Analyst for natural-language telemetry debriefs, secured behind strict defenses against Server-Side Request Forgery (SSRF), DNS rebinding, and prompt injection attacks.

---

## 2. Problem Statement

Modern phishing attacks exploit multiple interconnected communication channels:
- **Evasion of Lexical Filters**: Attackers craft benign-looking lexical URL structures, employ subdomains, and register lookalike domains (typosquatting, IDN homoglyphs).
- **Multi-Stage Delivery**: Attacks utilize email phishing as initial entry, redirect through compromised content management systems, collect credentials via dynamic DOM forms, or deliver weaponized macro-enabled payloads.
- **Siloed Threat Intelligence**: Traditional Security Operations Center (SOC) tooling analyzes artifacts in silos, leading to alert fatigue, false positives, and delayed incident response.

---

## 3. Motivation

A robust security posture demands a defense-in-depth architecture where no single indicator (such as an isolated URL keyword or an external API score) dictates the final security posture. PHISHGUARD unifies independent evidence layers into a normalized risk score, correlates cross-layer signals (e.g., brand impersonation coupled with credential fields and SPF failures), and produces transparent, auditable explanations for security analysts.

---

## 4. Objectives

1. **Multi-Artifact Detection**: Analyze URLs, Domain/DNS infrastructure, Email headers, Webpages, Attachments, and QR codes across independent analyzers.
2. **Deterministic Evidence Correlation**: Correlate findings across disparate layers to detect coordinated deception.
3. **Calibrated Engineering Risk Scoring**: Compute a normalized risk score ($[0, 100]$) categorized into LOW, MEDIUM, HIGH, and CRITICAL bands.
4. **Explainable AI (XAI)**: Generate rule-grounded, human-readable rationale without black-box opacity.
5. **AI Security Analyst Chat**: Provide an isolated conversational assistant grounded strictly in verified analysis outputs.
6. **Robust Application Hardening**: Prevent SSRF, DNS rebinding, path traversal, IDOR, XSS, and authorization bypasses.

---

## 5. Scope

### In Scope
- Lexical URL feature extraction and ML inference (Random Forest, Logistic Regression, XGBoost baselines).
- Domain, IP, DNS, and brand mismatch intelligence.
- Email header parsing (SPF, DKIM, DMARC, Display Name Spoofing) and NLP social engineering analysis.
- Webpage HTML/DOM static analysis (password fields, external forms, iframe overlays).
- Static attachment analysis (MIME validation, macro detection, PE header inspection).
- QR code payload extraction and decoding.
- VirusTotal threat intelligence integration with local caching.
- Multi-layer risk aggregation and evidence correlation.
- FastAPI backend with Argon2id password hashing, JWT authentication, and RBAC.
- Enterprise SaaS responsive frontend dashboard, analysis views, history, and analyst chat UI.

### Out of Scope / Planned
- Live hypervisor orchestration for dynamic malware execution (VM sandbox execution engine).
- Distributed Redis caching for multi-node rate limiting.
- Automated external dataset downloading or unauthorized web crawling.

---

## 6. Core Research Questions

- **RQ1**: *Does combining independent evidence from multiple artifact layers improve phishing detection accuracy and resilience compared with single-layer URL-only detection?*
- **RQ2**: *How do tree-based ensemble models (Random Forest, XGBoost) compare to linear baselines when evaluated on external, uncurated URL distributions?*
- **RQ3**: *What is the vulnerability rate of lexical URL classifiers when subjected to adversarial evasion transformations (subdomain padding, case manipulation, path encoding)?*
- **RQ4**: *How does the presence of missing or unavailable artifact layers (`UNKNOWN / NOT_AVAILABLE`) impact multi-layer risk scoring consistency?*

---

## 7. System Overview & Architectural Diagram

```text
+-----------------------------------------------------------------------------------+
|                                 PHISHGUARD CLIENT                                 |
|          (Enterprise SaaS Dashboard / Vanilla HTML5 / CSS3 / Vanilla ES6)         |
+-----------------------------------------------------------------------------------+
                                         │  HTTPS / REST / Bearer JWT
                                         ▼
+-----------------------------------------------------------------------------------+
|                            FASTAPI BACKEND & SECURITY GATEWAY                     |
|  - Rate Limiting (In-Memory IP Bucket)    - CORS Middleware (Restricted Origins)  |
|  - Security Headers & Strict CSP          - SSRF & DNS Rebinding Validator        |
|  - Argon2id Auth & JWT Token Verification - SQLAlchemy 2.0 ORM Access Control     |
+-----------------------------------------------------------------------------------+
                                         │
        ┌────────────────────────────────┼────────────────────────────────┐
        ▼                                ▼                                ▼
+───────────────────+          +───────────────────+            +───────────────────+
|   URL ANALYZER    |          |   EMAIL ANALYZER  |            |ATTACHMENT ANALYZER|
| - Lexical Feats   |          | - Header Parser   |            | - Magic Bytes/MIME|
| - Domain / DNS    |          | - SPF/DKIM/DMARC  |            | - VBA Macro Check |
| - Brand Intel     |          | - NLP Urgency     |            | - PE Header Flags |
| - Redirect Chain  |          | - Extracted URLs  |            | - Hash Reputati.  |
+───────────────────+          +───────────────────+            +───────────────────+
        │                                │                                │
        └────────────────────────────────┼────────────────────────────────┘
                                         ▼
+-----------------------------------------------------------------------------------+
|                            EVIDENCE CORRELATION ENGINE                            |
|             (Correlates cross-layer contradictions and compound risks)            |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                        CENTRAL MULTI-LAYER RISK ENGINE                            |
|            - Signal Normalization & Weighting  - Clamping [0, 100]                |
|            - Level Assignment (LOW / MEDIUM / HIGH / CRITICAL)                    |
+-----------------------------------------------------------------------------------+
                                         │
        ┌────────────────────────────────┴────────────────────────────────┐
        ▼                                                                 ▼
+─────────────────────────────────+             +───────────────────────────────────+
|   MULTI-LAYER RISK AGGREGATOR   |             |   EXPLAINABILITY & AI ANALYST     |
| - Preserves caller risk posture |             | - Rule Rationale & SHAP Baseline  |
| - Surfaces all layer evidence   |             | - System Prompt Injection Defense |
| - Explicit UNKNOWN for missing  |             | - Deterministic Fallback Engine   |
+─────────────────────────────────+             +───────────────────────────────────+
```

---

## 8. Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Backend Framework** | Python 3.11+, FastAPI 0.110+, Uvicorn (ASGI) |
| **Database & ORM** | SQLite 3 (Production-ready via SQLAlchemy 2.0 async/sync pool) |
| **Authentication & Crypto** | `passlib[argon2]`, `python-jose` (HS256 JWT tokens) |
| **Machine Learning** | `scikit-learn`, `xgboost`, `joblib`, `numpy`, `pandas` |
| **Networking & Security** | `requests`, `urllib3`, `ipaddress`, `socket`, `dnspython` |
| **Email & Parsing** | Python built-in `email`, `BeautifulSoup4`, `lxml` |
| **Binary/Attachment Analysis** | `olefile`, `pefile`, `hashlib` |
| **Frontend** | Vanilla JavaScript (ES6+ Modules), HTML5 Semantic Elements, Modern CSS3 |
| **Testing** | `pytest 9.1+`, `pytest-cov`, `anyio` |

---

## 9. Comprehensive Component Directory Structure

```text
AI-Phishing-Detection/
├── app/
│   ├── main.py                     # FastAPI application entrypoint & middleware
│   ├── auth.py                     # JWT token generation, verification & Argon2id hashing
│   ├── database.py                 # SQLAlchemy engine, session maker, base model
│   ├── models.py                   # ORM models (User, ScanHistory, SecurityLog)
│   ├── schemas.py                  # Pydantic request/response validation schemas
│   └── routers/
│       ├── auth.py                 # /api/auth/register, /api/auth/login, /api/auth/me
│       ├── analyze.py              # /api/analyze/url, /email, /attachment, /qr, /unified
│       ├── history.py              # /api/history scans, /api/history/{id}
│       └── chat.py                 # /api/chat AI Security Analyst conversational endpoint
├── src/
│   ├── analysis/
│   │   ├── risk_engine.py          # Multi-layer signal weighting and score computation
│   │   ├── evidence_correlator.py  # Cross-artifact anomaly correlation
│   │   ├── multi_layer_risk.py     # Aggregation pass-through module
│   │   ├── unified_analyzer.py     # End-to-end unified analysis pipeline
│   │   ├── ai_analysis.py          # AI prompt construction and analyzer interface
│   │   ├── gemini_analyzer.py      # Google Gemini integration & local fallback
│   │   ├── model_explainer.py      # Feature attribution & explainability
│   │   └── external_evaluation.py  # Model generalization benchmarking utility
│   ├── features/
│   │   ├── url_features.py         # 14-dimensional lexical feature extractor
│   │   ├── url_analyzer.py         # Comprehensive URL inspection coordinator
│   │   ├── domain_intelligence.py  # DNS, TLD, subdomain, and domain length parsing
│   │   ├── brand_intelligence.py   # Lookalike brand keywords & mismatch detection
│   │   ├── ip_intelligence.py      # IP resolution and geo/ASN stubbing
│   │   ├── redirect_analyzer.py    # Safe redirect traversal and hop counting
│   │   ├── webpage_analyzer.py     # DOM parsing for forms, inputs, and scripts
│   │   ├── email_analyzer.py       # Email payload orchestrator
│   │   ├── email_authentication.py # SPF, DKIM, DMARC evaluation logic
│   │   ├── email_nlp.py            # Urgency, credential harvesting keyword parser
│   │   ├── attachment_analyzer.py  # Attachment coordinator
│   │   ├── macro_analyzer.py       # OLE/VBA macro detection via olefile
│   │   ├── pe_analyzer.py          # Windows PE header & suspicious section inspector
│   │   ├── malware_analyzer.py     # Static malware signatures and heuristics
│   │   ├── qr_analyzer.py          # QR image decoding & URL extraction
│   │   └── reputation.py           # VirusTotal API client & response cache
│   ├── models/
│   │   ├── url_model_inference.py  # Frozen ML inference loader and predictor
│   │   └── train_url_model.py      # Training script for URL Random Forest baseline
│   ├── sandbox/
│   │   └── analysis_engine.py      # Abstract interface & contract for future sandbox VM
│   └── research/
│       └── experiment_01_layer_evaluation.py # Multi-layer empirical evaluation harness
├── data/
│   ├── raw/                        # Original source datasets and sample artifacts
│   └── processed/                  # Cleaned CSV datasets and research outputs
├── docs/                           # Technical documentation and research logs
├── frontend/                       # Enterprise SaaS user interface
└── tests/                          # Automated Pytest suite (114 tests)
```

---

## 10. Detailed Component Specifications

### 10.1 URL Feature Extraction (`src/features/url_features.py`)
- **Purpose**: Extract 14 numeric lexical features from raw URL strings. `[IMPLEMENTED]`
- **Input**: `url: str`
- **Output**: `Dict[str, Union[int, float]]` containing:
  - `url_length`, `hostname_length`, `path_length`, `query_length`
  - `dot_count`, `hyphen_count`, `digit_count`, `special_char_count`, `subdomain_count`
  - `contains_ip` (binary), `uses_https` (binary), `contains_at` (binary), `contains_double_slash` (binary), `suspicious_keyword_count` (integer)
- **Security Considerations**: Handles malformed URLs without exceptions; rejects excessively large strings (>2048 chars).

### 10.2 Domain Intelligence (`src/features/domain_intelligence.py`)
- **Purpose**: Parse domain structure, top-level domains (TLDs), subdomain hierarchy, and DNS resolution. `[IMPLEMENTED]`
- **Input**: `url: str`
- **Output**: `domain`, `hostname`, `subdomain`, `tld`, `ipv4_addresses`, `is_ip_address`, `domain_has_hyphen`.
- **Security Considerations**: Safely catches DNS resolution failures; does not execute unvalidated socket calls.

### 10.3 Brand Intelligence (`src/features/brand_intelligence.py`)
- **Purpose**: Detect impersonated targets (e.g., PayPal, Microsoft, Apple, Google, Netflix) and identify brand-domain mismatch. `[IMPLEMENTED]`
- **Input**: `url: str`
- **Output**: `detected_brands: List[str]`, `brand_domain_mismatch: bool`, `brand_relationships: List[Dict]`.
- **Security Considerations**: Uses bounded string matching; resilient against regex denial of service (ReDoS).

### 10.4 IP Intelligence (`src/features/ip_intelligence.py`)
- **Purpose**: Resolve hostnames to IP addresses and extract networking metadata. `[IMPLEMENTED]`
- **Input**: `hostname: str`
- **Output**: `dns_resolved_ips: List[str]`, `is_ip_address: bool`.
- **Security Considerations**: Validates against reserved/private IP ranges.

### 10.5 Safe Redirect Analyzer (`src/features/redirect_analyzer.py`)
- **Purpose**: Follow HTTP redirect chains safely while counting hops and detecting evasion. `[IMPLEMENTED]`
- **Input**: `url: str`, `max_redirects: int = 5`
- **Output**: `redirect_chain: List[str]`, `redirect_count: int`, `final_url: str`, `status_codes: List[int]`.
- **Security Considerations**: SSRF protection strictly applied at every intermediate hop. Aborts on private/loopback IP resolution.

### 10.6 Webpage Analyzer (`src/features/webpage_analyzer.py`)
- **Purpose**: Safely inspect HTML content for credential harvesting signals. `[IMPLEMENTED]`
- **Input**: `url: str` / HTML body
- **Output**: `password_field_count: int`, `external_form_actions: List[str]`, `iframe_count: int`, `script_count: int`.
- **Security Considerations**: Webpage fetch is guarded by SSRF validation and non-execution sandbox.

### 10.7 Email Header & Authentication Analyzer (`src/features/email_authentication.py`)
- **Purpose**: Validate cryptographic authentication headers (SPF, DKIM, DMARC) and detect display name spoofing. `[IMPLEMENTED]`
- **Input**: Raw RFC 5322 email string / parsed headers
- **Output**: `spf_status: str`, `dkim_status: str`, `dmarc_status: str`, `display_name_spoofing: bool`.

### 10.8 Email NLP Analyzer (`src/features/email_nlp.py`)
- **Purpose**: Detect social engineering urgency, threat language, and credential prompts. `[IMPLEMENTED]`
- **Input**: Email subject and body text
- **Output**: `urgency_score: float`, `detected_social_engineering_triggers: List[str]`.

### 10.9 Attachment & Macro Analyzer (`src/features/attachment_analyzer.py`, `macro_analyzer.py`)
- **Purpose**: Inspect files for extension anomalies, MIME spoofing, and dangerous VBA macros. `[IMPLEMENTED]`
- **Input**: File path / binary buffer
- **Output**: `mime_type`, `sha256`, `has_macros: bool`, `suspicious_vba_keywords: List[str]`.
- **Security Considerations**: Files are parsed statically without execution; temporary files are strictly cleaned up.

### 10.10 PE Static Analyzer (`src/features/pe_analyzer.py`)
- **Purpose**: Inspect Windows Portable Executable headers for anomaly indicators (abnormal section entropy, suspicious imports). `[IMPLEMENTED]`
- **Input**: PE file buffer
- **Output**: `is_pe: bool`, `imphash: str`, `suspicious_sections: List[str]`.

### 10.11 QR Code Analyzer (`src/features/qr_analyzer.py`)
- **Purpose**: Decode QR image payloads to extract and scan embedded phishing URLs (Quishing). `[IMPLEMENTED]`
- **Input**: Image file (PNG, JPG)
- **Output**: `qr_detected: bool`, `extracted_url: str`.

### 10.12 VirusTotal Reputation (`src/features/reputation.py`)
- **Purpose**: Query VirusTotal API v3 for known malicious URL/hash verdicts with local memory caching. `[IMPLEMENTED]`
- **Input**: URL string or SHA-256 hash
- **Output**: `positives: int`, `total_engines: int`, `reputation_score: float`.
- **Security Considerations**: Graceful fallback when API key is missing or rate limits occur; never treated as ground truth.

### 10.13 Central Multi-Layer Risk Engine (`src/analysis/risk_engine.py`)
- **Purpose**: Compute an engineering risk score $[0, 100]$ based on additive weighted security signals. `[IMPLEMENTED]`
- **Thresholds**:
  - `0.0 - 24.9`: **LOW**
  - `25.0 - 49.9`: **MEDIUM**
  - `50.0 - 74.9`: **HIGH**
  - `75.0 - 100.0`: **CRITICAL**

### 10.14 Evidence Correlator (`src/analysis/evidence_correlator.py`)
- **Purpose**: Identify cross-layer compound threats (e.g., Brand Mention + Mismatched Domain + Password Field). `[IMPLEMENTED]`
- **Output**: Correlated risk modifiers and human-readable anomaly descriptions.

### 10.15 Multi-Layer Risk Aggregator (`src/analysis/multi_layer_risk.py`)
- **Purpose**: Aggregate evidence structures into a standardized payload without altering caller risk posture. `[IMPLEMENTED]`
- **Guarantees**: Does not recalculate risk scores or re-run correlation; passes missing layers as `None` / `UNKNOWN`.

### 10.16 AI Security Analyst (`app/routers/chat.py`, `src/analysis/ai_analysis.py`)
- **Purpose**: Interactive analysis assistant answering analyst inquiries about scan telemetry. `[IMPLEMENTED]`
- **Input**: `scan_id: int`, `message: str`
- **Processing**: Enforces prompt isolation; strictly bounds reasoning context to the specified scan; falls back to deterministic rule synthesis if Gemini API key is absent.
- **Security Considerations**: Enforces strict user scan ownership checks; filters system prompt override attempts.

### 10.17 Isolated Sandbox VM (`src/sandbox/analysis_engine.py`)
- **Purpose**: Define the telemetry collection interface for future isolated dynamic malware detonation. `[PLANNED / INTERFACE ONLY]`
- **Status**: Software boundary contracts defined; hypervisor execution intentionally not implemented in this version.

---

## 11. Security Hardening & Defenses

1. **SSRF & DNS Rebinding**: `is_safe_url()` resolves hostnames against `ipaddress.ip_address()` checking `is_private`, `is_loopback`, `is_link_local`, and `is_reserved`. Re-validates at every redirect hop.
2. **Cloud Metadata Protection**: Explicitly blocks `169.254.169.254` and `metadata.google.internal`.
3. **IDOR Prevention**: All scan access endpoints verify `scan.user_id == current_user.id`.
4. **Input Size & Type Limits**: Uploads capped at 10 MB with MIME header and extension verification.
5. **Security Headers**: Injects `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: strict-origin-when-cross-origin`.
6. **Authentication Security**: Argon2id password hashing with time-constant verification; JWT access tokens with 60-minute expiration.

---

## 12. Verification & Testing

- **Total Test Count**: 114 passing unit and integration tests.
- **Test Modules**:
  - `tests/test_auth.py`: Authentication, JWT issuance, password security.
  - `tests/test_security_chat.py`: AI Security Analyst authorization and ownership enforcement.
  - `tests/test_security_hardening.py`: SSRF, large uploads, path traversal, CSP validation.
  - `tests/test_experiment_01.py`: Multi-layer empirical evaluation and missing-layer resilience.
  - `tests/test_multi_layer_risk.py`: Aggregator pass-through and structural integrity.
  - `tests/test_unified_analyzer.py`: Full unified pipeline orchestration.
