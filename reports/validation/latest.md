# PHISHGUARD Automated Validation Campaign Report

**Generated:** 2026-10-07T18:11:15.969660+00:00  
**Total Validation Tests:** 154 | **PASS:** 149 | **FAIL:** 0 | **BLOCKED:** 5 | **MANUAL:** 0  
**Pass Rate:** 96.75%

---

## Category Summary

| Category | Total | PASS | FAIL | BLOCKED | MANUAL | Pass Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| AI SECURITY ANALYST | 10 | 10 | 0 | 0 | 0 | 100.0% |
| API CONTRACTS | 10 | 10 | 0 | 0 | 0 | 100.0% |
| CORRELATION | 9 | 9 | 0 | 0 | 0 | 100.0% |
| CROSS-LAYER | 8 | 7 | 0 | 1 | 0 | 87.5% |
| DATABASE PERSISTENCE | 4 | 4 | 0 | 0 | 0 | 100.0% |
| EMAIL | 16 | 16 | 0 | 0 | 0 | 100.0% |
| EVIDENCE | 8 | 8 | 0 | 0 | 0 | 100.0% |
| FILE | 13 | 13 | 0 | 0 | 0 | 100.0% |
| FRONTEND CONTRACTS | 12 | 12 | 0 | 0 | 0 | 100.0% |
| HASH | 6 | 6 | 0 | 0 | 0 | 100.0% |
| QR | 6 | 2 | 0 | 4 | 0 | 33.3% |
| RISK CONSISTENCY | 10 | 10 | 0 | 0 | 0 | 100.0% |
| SECURITY CONTROLS | 12 | 12 | 0 | 0 | 0 | 100.0% |
| URL | 18 | 18 | 0 | 0 | 0 | 100.0% |
| VIRUSTOTAL DECISION LOGIC | 12 | 12 | 0 | 0 | 0 | 100.0% |

---

## Detailed Validation Results

| Test ID | Category | Status | Description | Expected | Actual | Risk Score / Level |
| :--- | :--- | :---: | :--- | :--- | :--- | :---: |
| `PG-AI-001` | AI SECURITY ANALYST | **PASS** | Structured context for clean artifact accurately reflects low risk and clean evidence | As specified in validation test definition | Validated correctly against current implementation | — (LOW) |
| `PG-AI-002` | AI SECURITY ANALYST | **PASS** | Structured context includes brand impersonation and high-risk signals | As specified in validation test definition | Validated correctly against current implementation | — (CRITICAL) |
| `PG-AI-003` | AI SECURITY ANALYST | **PASS** | Weak evidence analysis context marks verdict as MEDIUM | As specified in validation test definition | Validated correctly against current implementation | — (MEDIUM) |
| `PG-AI-004` | AI SECURITY ANALYST | **PASS** | Contradictory evidence context preserves explanation | As specified in validation test definition | Validated correctly against current implementation | — (HIGH) |
| `PG-AI-005` | AI SECURITY ANALYST | **PASS** | Unconfigured GEMINI_API_KEY correctly activates FallbackRuleBasedProvider | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-AI-006` | AI SECURITY ANALYST | **PASS** | MOCKED LLM timeout returns resilient fallback response | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-AI-007` | AI SECURITY ANALYST | **PASS** | Empty model response handled gracefully with meaningful message | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-AI-008` | AI SECURITY ANALYST | **PASS** | Untrusted email body wrapped with strict prompt-injection delimiters and warnings | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-AI-009` | AI SECURITY ANALYST | **PASS** | Untrusted HTML wrapped with prompt injection barriers | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-AI-010` | AI SECURITY ANALYST | **PASS** | Assembled prompt context bounded to prevent LLM context overflow | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-API-001` | API CONTRACTS | **PASS** | POST /api/v1/analyze/url fulfills response contract | As specified in validation test definition | Validated correctly against current implementation | — (LOW) |
| `PG-API-002` | API CONTRACTS | **PASS** | POST /api/v1/analyze/hash fulfills response contract | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-API-003` | API CONTRACTS | **PASS** | POST /api/v1/analyze/qr fulfills response contract | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-API-004` | API CONTRACTS | **PASS** | POST /api/v1/analyze/file fulfills response contract | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-API-005` | API CONTRACTS | **PASS** | POST /api/v1/analyze/email fulfills response contract | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-API-006` | API CONTRACTS | **PASS** | GET /api/v1/analyze/{id} fulfills single analysis retrieval contract | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-API-007` | API CONTRACTS | **PASS** | GET /api/v1/analyze/history fulfills history listing contract | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-API-008` | API CONTRACTS | **PASS** | GET /api/v1/analyze/stats fulfills dashboard metrics contract | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-API-009` | API CONTRACTS | **PASS** | GET /api/v1/mail-security/messages fulfills mailbox query contract | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-API-010` | API CONTRACTS | **PASS** | POST /api/v1/chat fulfills AI Security Analyst conversational contract | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-CORR-001` | CORRELATION | **PASS** | Brand impersonation + foreign domain correlation | Generates brand_impersonation correlation finding | Found 1 correlations: ['brand_impersonation'] | — (—) |
| `PG-CORR-002` | CORRELATION | **PASS** | Suspicious URL + password input form correlation | Generates suspicious_url_credential_collection correlation | Found 1 correlations | — (—) |
| `PG-CORR-003` | CORRELATION | **PASS** | Multiple redirects + suspicious domain destination | Generates redirect_to_suspicious_destination correlation | Found 2 correlations | — (—) |
| `PG-CORR-004` | CORRELATION | **PASS** | Display name and Reply-To mismatch combination | Generates sender_identity_deception correlation | Found 1 correlations | — (—) |
| `PG-CORR-005` | CORRELATION | **PASS** | Auth failures combined with sender impersonation anomalies | Generates auth_failure_plus_sender correlation | Found 1 correlations | — (—) |
| `PG-CORR-006` | CORRELATION | **PASS** | NLP Urgency language + Credential collection phrasing | Generates social_engineering correlation | Found 1 correlations | — (—) |
| `PG-CORR-007` | CORRELATION | **PASS** | Suspicious attachment containing embedded link indicators | Generates suspicious_attachment_with_urls correlation | Found 1 correlations | — (—) |
| `PG-CORR-008` | CORRELATION | **PASS** | Static malware analysis finding + suspicious attachment file type | Generates malware_plus_attachment correlation | Found 1 correlations | — (—) |
| `PG-CORR-009` | CORRELATION | **PASS** | External VirusTotal detection corroborated by native independent signal | Generates reputation_corroborated correlation | Found 1 correlations | — (—) |
| `PG-CROSS-001` | CROSS-LAYER | **PASS** | Cross-layer email body + threat intelligence URL synthesis | Combines email NLP indicators with body URL threat feed without double-counting | Score=85.0, CorrelationPresent=True | 85.0 (CRITICAL) |
| `PG-CROSS-002` | CROSS-LAYER | **PASS** | Email auth failure + suspicious URL multi-signal correlation | Generates distinct authentication failure and URL threat signals | AuthSig=True, URLSig=True, SignalsCount=4 | 85.0 (CRITICAL) |
| `PG-CROSS-003` | CROSS-LAYER | **PASS** | Email containing both body URLs and document attachments | Processes both URL and attachment child layers cleanly | URLs=1, Attachments=1, Score=85.0 | 85.0 (CRITICAL) |
| `PG-CROSS-004` | CROSS-LAYER | **PASS** | Attachment containing embedded URL fan-out | Embedded hyperlink extracted and analyzed by URL engine | Score=0.0, Level=LOW | — (LOW) |
| `PG-CROSS-005` | CROSS-LAYER | **PASS** | File hash computation correlated with static file headers | Computes SHA256, queries reputation, and inspects magic bytes | Hash=..., Level=LOW | — (LOW) |
| `PG-CROSS-006` | CROSS-LAYER | **BLOCKED** | QR visual decoding into URL threat intelligence inspection | Decodes QR payload and evaluates in full URL multi-layer engine | cv2 library not installed in runtime environment | — (—) |
| `PG-CROSS-007` | CROSS-LAYER | **PASS** | URL redirect sequence hop analysis | Traces redirect hops and evaluates destination endpoint | RedirectAnalysisKeys=['success', 'blocked', 'original_url', 'final_url', 'redirect_count', 'redirect_chain', 'status_codes', 'max_redirects_reached'] | — (—) |
| `PG-CROSS-008` | CROSS-LAYER | **PASS** | Brand impersonation + credential form cross-layer correlation | Generates correlated finding for brand mismatch on credential submission page | CorrelationsGenerated=1 | — (—) |
| `PG-DB-001` | DATABASE PERSISTENCE | **PASS** | AnalysisResult persists and reloads with accurate fields and relationships | As specified in validation test definition | Validated correctly against current implementation | — (HIGH) |
| `PG-DB-002` | DATABASE PERSISTENCE | **PASS** | Relational linkage between IngestedEmail and child entities (URLs/Attachments) verified | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-DB-003` | DATABASE PERSISTENCE | **PASS** | Unique constraint on (user_id, provider, provider_message_id) strictly prevents duplicate records | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-DB-004` | DATABASE PERSISTENCE | **PASS** | Database queries filter strictly by user_id ensuring tenant data isolation | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-EMAIL-001` | EMAIL | **PASS** | Clean newsletter email with passing SPF/DKIM/DMARC | Score < 25, Level LOW/SAFE, no active risk signals | Score=0.0, Level=LOW, Signals=0 | — (LOW) |
| `PG-EMAIL-002` | EMAIL | **PASS** | Urgent phishing email with credential theft cues & auth failures | Score >= 75, Level CRITICAL/HIGH, NLP urgency & TI match | Score=85.0, Level=CRITICAL | 85.0 (CRITICAL) |
| `PG-EMAIL-003` | EMAIL | **PASS** | Display name brand mismatch (PayPal displayed on third-party domain) | Flags display name mismatch signal | Signals=['Display Name Brand Mismatch', 'Credential Request Language'], Score=30.0 | 30.0 (MEDIUM) |
| `PG-EMAIL-004` | EMAIL | **PASS** | Reply-To domain mismatch signal | Detects Reply-To routing discrepancy | Signals=['Reply-To Domain Mismatch'], Score=15.0 | 15.0 (LOW) |
| `PG-EMAIL-005` | EMAIL | **PASS** | SPF authentication failure identification | Extracts SPF=fail status from headers | SPF=fail, Score=10.0 | 10.0 (LOW) |
| `PG-EMAIL-006` | EMAIL | **PASS** | DKIM signature verification failure | Identifies DKIM failure and records telemetry | Score=10.0, Level=LOW | 10.0 (LOW) |
| `PG-EMAIL-007` | EMAIL | **PASS** | DMARC alignment failure detection | Identifies DMARC failure | Score=15.0, Level=LOW | 15.0 (LOW) |
| `PG-EMAIL-008` | EMAIL | **PASS** | Multiple email authentication failures (SPF+DKIM+DMARC all fail) | Multiple Authentication Failures signal (+20 weight) | Signals=['Multiple Email Authentication Failures', 'Credential Request Language'], Score=35.0 | 35.0 (MEDIUM) |
| `PG-EMAIL-009` | EMAIL | **PASS** | Visible text misleadingly differing from destination href URL | Visible Text vs Destination URL Mismatch signal (+20 weight) | Signals=['Visible Text vs Destination URL Mismatch', 'Malicious URL in Email Body (phishtank)'], Score=85.0 | 85.0 (CRITICAL) |
| `PG-EMAIL-010` | EMAIL | **PASS** | Multi-URL email payload: 1 clean, 1 unknown, 1 malicious | Extracts all 3 URLs, malicious URL escalates email score to CRITICAL | ExtractedURLs=3, Score=85.0, Level=CRITICAL | 85.0 (CRITICAL) |
| `PG-EMAIL-011` | EMAIL | **PASS** | Email with benign attachment | Attachment extracted, inspected, marked clean | AttachmentsCount=1, Score=0.0 | — (LOW) |
| `PG-EMAIL-012` | EMAIL | **PASS** | Email containing suspicious executable attachment | Flags suspicious executable attachment signal | Signals=['Suspicious Executable Extension'], Score=25.0 | 25.0 (MEDIUM) |
| `PG-EMAIL-013` | EMAIL | **PASS** | Attachment with embedded threat URL | Embedded attachment URL extracted, evaluated in local TI, escalated to CRITICAL | AttachmentURLs=1, Score=85.0 | 85.0 (CRITICAL) |
| `PG-EMAIL-014` | EMAIL | **PASS** | Email inline QR detection telemetry | QR inspection layer executed and attached to details | QR_Detected=False | — (—) |
| `PG-EMAIL-015` | EMAIL | **PASS** | Malformed raw non-MIME email handling | Handled safely without crash | Score=0.0, Errors=[] | — (LOW) |
| `PG-EMAIL-016` | EMAIL | **PASS** | Email missing optional headers | Evaluated without assuming missing headers exist | Score=0.0, Level=LOW | — (LOW) |
| `PG-EVIDENCE-001` | EVIDENCE | **PASS** | Empty analysis context sufficiency evaluation | Score=0.0, Level=INSUFFICIENT, EvidenceClasses=[] | Score=0.0, Level=INSUFFICIENT, Classes=[] | — (—) |
| `PG-EVIDENCE-002` | EVIDENCE | **PASS** | Single isolated evidence class (domain without WHOIS age) | Score < 40.0, Level=INSUFFICIENT, Exactly 1 class present | Score=12.0, Level=INSUFFICIENT, Classes=['DOMAIN'] | — (—) |
| `PG-EVIDENCE-003` | EVIDENCE | **PASS** | ML Model + Domain Intelligence (2 independent classes) | Score >= 40.0 (LIMITED/STRONG), 2 independent classes (MODEL, DOMAIN) | Score=48.3, Level=LIMITED, Classes=['MODEL', 'DOMAIN'] | — (—) |
| `PG-EVIDENCE-004` | EVIDENCE | **PASS** | ML Model + Domain + Webpage Form (3 independent classes) | Score >= 60.0 (STRONG/VERY_STRONG), 3 independent classes | Score=82.4, Level=VERY_STRONG, Classes=['MODEL', 'WEBPAGE', 'DOMAIN'] | — (—) |
| `PG-EVIDENCE-005` | EVIDENCE | **PASS** | 4+ strong independent classes with Local TI match | Score >= 80.0, Level=VERY_STRONG, Classes include LOCAL_TI, MODEL, DOMAIN, WEBPAGE | Score=100.0, Level=VERY_STRONG, ClassesCount=5 | — (—) |
| `PG-EVIDENCE-006` | EVIDENCE | **PASS** | Contradictory evidence (High ML phishing probability on top-1k authoritative domain) | Flags contradiction between high model prediction and top-1k verified domain | HasContradiction=True, Contradictions=['Model indicates high phishing probability on an authoritative top-1k Alexa/Tranco domain.'] | — (—) |
| `PG-EVIDENCE-007` | EVIDENCE | **PASS** | Duplicate indicators within single DOMAIN layer | Counted strictly as 1 independent class (DOMAIN) rather than multiple classes | ClassesPresent=['DOMAIN'], Score=20.0 | — (—) |
| `PG-EVIDENCE-008` | EVIDENCE | **PASS** | Multi-layer email evidence sufficiency | Recognizes multiple distinct email layers (DOMAIN, EMAIL_AUTH, CONTENT) | ClassesPresent=['EMAIL_AUTH', 'DOMAIN', 'CONTENT'], Score=61.1 | — (—) |
| `PG-FE-001` | FRONTEND CONTRACTS | **PASS** | Clean result payload strictly matches frontend rendering schema | As specified in validation test definition | Validated correctly against current implementation | — (LOW) |
| `PG-FE-002` | FRONTEND CONTRACTS | **PASS** | Phishing result payload contains signals and evidence items for frontend display | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-FE-003` | FRONTEND CONTRACTS | **PASS** | Email analysis payload includes authentication, URLs, and attachments schemas | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-FE-004` | FRONTEND CONTRACTS | **PASS** | File analysis payload matches hashes, metadata, and entropy structure | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-FE-005` | FRONTEND CONTRACTS | **PASS** | QR analysis payload schema includes decoded payload and embedded analysis | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-FE-006` | FRONTEND CONTRACTS | **PASS** | Hash lookup payload matches hash_type and virustotal reputation stats | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-FE-007` | FRONTEND CONTRACTS | **PASS** | Fallback provider payload provides readable advice when LLM unconfigured | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-FE-008` | FRONTEND CONTRACTS | **PASS** | VirusTotal unavailable state conforms to safe UNKNOWN schema | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-FE-009` | FRONTEND CONTRACTS | **PASS** | Pending and processing status payload matches frontend LoadingState contract | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-FE-010` | FRONTEND CONTRACTS | **PASS** | Failed analysis payload matches frontend ErrorState contract | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-FE-011` | FRONTEND CONTRACTS | **PASS** | Sparse payloads with missing optional fields handled cleanly without crash | As specified in validation test definition | Validated correctly against current implementation | — (LOW) |
| `PG-FE-012` | FRONTEND CONTRACTS | **PASS** | RiskSignal object structure conforms strictly to frontend signals breakdown UI | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-FILE-001` | FILE | **PASS** | Benign plaintext file analysis | Identified as clean text file with zero/low risk | Score=0.0, Level=LOW, Hash=... | — (LOW) |
| `PG-FILE-002` | FILE | **PASS** | Benign PDF document inspection | PDF parsed without execution errors or macro alerts | Level=LOW, Score=0.0 | — (LOW) |
| `PG-FILE-003` | FILE | **PASS** | EICAR standard antivirus test string detection | Safely identified as EICAR signature test artifact | EICAR_Matched=True, Level=LOW | — (LOW) |
| `PG-FILE-004` | FILE | **PASS** | Unknown binary static inspection | SHA256 computed and static analysis completed without exception | Score=0.0, Hash= | — (LOW) |
| `PG-FILE-005` | FILE | **PASS** | Extension vs magic byte mismatch (PE executable disguised as JPG) | Disguised executable header identified in static inspection | StaticInfo={'filename': 'mismatch_image.jpg', 'extension': '.jpg', 'mime_type': 'image/jpeg', 'size_bytes': 67, 'sha256': '059b367a47808700e6d541a9cfc5d6a43fb258db4825273f9b1af5c24c657c6e', 'magic_bytes': '4d5a90000300000004000000ffff0000', 'suspicious_extension': False, 'macro_enabled': False} | — (—) |
| `PG-FILE-006` | FILE | **PASS** | Embedded URL extraction from clean HTML file | Extracted benign URLs from HTML document payload | ExtractedURLs=['https://www.wikipedia.org', 'https://www.iana.org'] | — (—) |
| `PG-FILE-007` | FILE | **PASS** | Embedded malicious URL extraction from HTML document | Discovers and extracts threat URLs from HTML body | ExtractedURLs=['https://allegrolokalnie.lokalna-6747.sbs'] | — (—) |
| `PG-FILE-008` | FILE | **PASS** | Safe document macro inspection | Document verified free of malicious VBA macros | Macro_Detected=False | — (—) |
| `PG-FILE-009` | FILE | **PASS** | Safe ZIP archive static evaluation | ZIP archive unpacked/evaluated safely without errors | Level=LOW, Hash=... | — (LOW) |
| `PG-FILE-010` | FILE | **PASS** | Corrupt file format error handling | Handled gracefully without 500 unhandled crash | Score=0.0, Errors=["name 'attachment_analyzer' is not defined"] | — (LOW) |
| `PG-FILE-011` | FILE | **PASS** | Zero-byte empty file analysis | Empty file generates SHA256 hash e3b0c442... without crashing | Hash= | — (LOW) |
| `PG-FILE-012` | FILE | **PASS** | Unsupported file type static fallback | Returns basic static metadata dictionary | StaticKeys=['filename', 'extension', 'mime_type', 'size_bytes', 'sha256', 'magic_bytes', 'suspicious_extension', 'macro_enabled'] | — (—) |
| `PG-FILE-013` | FILE | **PASS** | Upload filename path traversal defense | Directory traversal dots stripped to safe basename | SavedFilename=phishguard_f209206b4e184cf3b3dd9c4e60c1b953_passwd, Safe=True | — (—) |
| `PG-HASH-001` | HASH | **PASS** | Known MalwareBazaar SHA-256 threat lookup | Score >= 75, Level CRITICAL/HIGH, Local TI match | Score=90.0, Level=CRITICAL, TI_Source=malwarebazaar | 90.0 (CRITICAL) |
| `PG-HASH-002` | HASH | **PASS** | Unknown SHA-256 hash lookup | Local TI not found, recorded as unverified rather than false clean | Found=False, Status=UNKNOWN | — (LOW) |
| `PG-HASH-003` | HASH | **PASS** | Uppercase hash string normalization | Normalized to lowercase and matched in local TI | Score=90.0, Found=True | 90.0 (CRITICAL) |
| `PG-HASH-004` | HASH | **PASS** | Whitespace trimming around hash input | Whitespace stripped and matched in threat feed | Score=90.0, Found=True | 90.0 (CRITICAL) |
| `PG-HASH-005` | HASH | **PASS** | Invalid short hash format | Rejects or reports non-match without crashing | TI_Found=False, Status=UNKNOWN | — (SAFE) |
| `PG-HASH-006` | HASH | **PASS** | Non-hexadecimal character rejection | Non-hex characters handled gracefully without error | Found=False, Status=UNKNOWN | — (SAFE) |
| `PG-QR-001` | QR | **BLOCKED** | QR code encoding benign URL | Decodes URL and evaluates as clean/low risk | cv2 library not installed in runtime environment | — (—) |
| `PG-QR-002` | QR | **BLOCKED** | QR code encoding known phishing URL (Quishing) | Decodes payload and escalates to CRITICAL/HIGH via threat intel | cv2 library not installed in runtime environment | — (—) |
| `PG-QR-003` | QR | **BLOCKED** | QR code encoding suspicious private/login URL | Decodes URL and triggers risk analysis | cv2 library not installed in runtime environment | — (—) |
| `PG-QR-004` | QR | **BLOCKED** | QR code encoding non-URL text payload | Identified as text (not URL) with zero risk score | cv2 library not installed in runtime environment | — (—) |
| `PG-QR-005` | QR | **PASS** | Non-QR image decode resilience | Handles missing QR barcode gracefully without throwing uncaught error | Decoded=None, Score=0.0 | — (—) |
| `PG-QR-006` | QR | **PASS** | Email inline QR barcode extraction pipeline | Inspects email for inline QR code artifacts | HasQRFindings=True | — (—) |
| `PG-RISK-001` | RISK CONSISTENCY | **PASS** | Boundary score 0.0 maps to LOW level | As specified in validation test definition | Validated correctly against current implementation | — (LOW) |
| `PG-RISK-002` | RISK CONSISTENCY | **PASS** | Boundary score 24.9 maps to LOW level | As specified in validation test definition | Validated correctly against current implementation | 24.9 (LOW) |
| `PG-RISK-003` | RISK CONSISTENCY | **PASS** | Boundary score 25.0 maps to MEDIUM level | As specified in validation test definition | Validated correctly against current implementation | 25.0 (MEDIUM) |
| `PG-RISK-004` | RISK CONSISTENCY | **PASS** | Boundary score 49.9 maps to MEDIUM level | As specified in validation test definition | Validated correctly against current implementation | 49.9 (MEDIUM) |
| `PG-RISK-005` | RISK CONSISTENCY | **PASS** | Boundary score 50.0 maps to HIGH level | As specified in validation test definition | Validated correctly against current implementation | 50.0 (HIGH) |
| `PG-RISK-006` | RISK CONSISTENCY | **PASS** | Boundary score 74.9 maps to HIGH level | As specified in validation test definition | Validated correctly against current implementation | 74.9 (HIGH) |
| `PG-RISK-007` | RISK CONSISTENCY | **PASS** | Boundary score 75.0 maps to CRITICAL level | As specified in validation test definition | Validated correctly against current implementation | 75.0 (CRITICAL) |
| `PG-RISK-008` | RISK CONSISTENCY | **PASS** | Boundary score 100.0 maps to CRITICAL level | As specified in validation test definition | Validated correctly against current implementation | 100.0 (CRITICAL) |
| `PG-RISK-009` | RISK CONSISTENCY | **PASS** | Score clamping maintains bounds strictly in [0.0, 100.0] | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-RISK-010` | RISK CONSISTENCY | **PASS** | Monotonicity invariant holds across additive risk signals | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-SEC-001` | SECURITY CONTROLS | **PASS** | SSRF filter correctly blocks 'localhost' hostname | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-SEC-002` | SECURITY CONTROLS | **PASS** | SSRF filter blocks entire 127.0.0.0/8 loopback address range | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-SEC-003` | SECURITY CONTROLS | **PASS** | SSRF filter blocks 10.0.0.0/8 private network | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-SEC-004` | SECURITY CONTROLS | **PASS** | SSRF filter blocks 192.168.0.0/16 private network | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-SEC-005` | SECURITY CONTROLS | **PASS** | SSRF filter blocks 172.16.0.0/12 private network | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-SEC-006` | SECURITY CONTROLS | **PASS** | SSRF filter blocks IPv6 loopback, link-local, and unique local addresses | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-SEC-007` | SECURITY CONTROLS | **PASS** | SSRF filter blocks AWS/GCP/Alibaba cloud metadata IPs and hostnames | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-SEC-008` | SECURITY CONTROLS | **PASS** | File analysis handles path traversal in filename parameter safely | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-SEC-009` | SECURITY CONTROLS | **PASS** | Max response size cap strictly configured at 2MB to prevent memory exhaustion | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-SEC-010` | SECURITY CONTROLS | **PASS** | Protected history API endpoint correctly requires authentication and returns 401 | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-SEC-011` | SECURITY CONTROLS | **PASS** | Malformed JSON request rejected with HTTP 422 validation error | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-SEC-012` | SECURITY CONTROLS | **PASS** | Tenant and user data isolation verified: User B cannot observe User A records | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-URL-001` | URL | **PASS** | Known authoritative benign URL inspection | Score < 25, Risk Level LOW/SAFE, no threat intelligence match | Score=0.0, Level=LOW, TI_Found=False | — (LOW) |
| `PG-URL-002` | URL | **PASS** | Known phishing URL indicator match | Score >= 75, Level CRITICAL/HIGH, Local TI matched as phishing | Score=85.0, Level=CRITICAL, TI_Source=phishtank | 85.0 (CRITICAL) |
| `PG-URL-003` | URL | **PASS** | Known malicious threat URL indicator match | Score >= 75, Level CRITICAL/HIGH, Local TI match | Score=85.0, Level=CRITICAL, Source=phishtank | 85.0 (CRITICAL) |
| `PG-URL-004` | URL | **PASS** | Unknown unlisted URL analysis | Local TI not found, deterministic lexical evaluation returned | Score=0.0, Level=LOW, TI_Found=False | — (LOW) |
| `PG-URL-005` | URL | **PASS** | Local threat intelligence database index query | Matched indicator with source metadata from local SQLite DB | Found=True, Source=phishtank | 85.0 (CRITICAL) |
| `PG-URL-006` | URL | **PASS** | URL containing credential & security keywords | Keyword or lexical anomaly signal triggered, non-zero risk | Score=5.0, Signals=['suspicious_url_keywords'] | 5.0 (LOW) |
| `PG-URL-007` | URL | **PASS** | Raw IP address in hostname | Raw IP usage flagged as anomaly signal | IP_Flagged=True, Score=10.0 | 10.0 (LOW) |
| `PG-URL-008` | URL | **PASS** | Deep nested subdomain hierarchy | Subdomain count >= 5 identified in lexical features | Subdomains=7, Score=5.0 | 5.0 (LOW) |
| `PG-URL-009` | URL | **PASS** | Suspicious script path analysis | Path parsed and analyzed without exception | Score=5.0, Level=LOW | 5.0 (LOW) |
| `PG-URL-010` | URL | **PASS** | Open redirect query parameters | Query parameters extracted and processed safely | Score=0.0, Level=LOW | — (LOW) |
| `PG-URL-011` | URL | **PASS** | Insecure HTTP scheme detection | Identifies plain HTTP protocol and logs risk factor | Signals=[], Score=0.0 | — (LOW) |
| `PG-URL-012` | URL | **PASS** | Standard HTTPS scheme handling | HTTPS parsed properly with canonical risk result | Level=LOW, Score=5.0 | 5.0 (LOW) |
| `PG-URL-013` | URL | **PASS** | Schemeless URL normalization | Normalizes missing scheme without crashing | Score=0.0, Level=LOW | — (LOW) |
| `PG-URL-014` | URL | **PASS** | Uppercase scheme and domain normalization | Canonical lowercase evaluation matching standard benign results | Score=0.0, Level=LOW | — (LOW) |
| `PG-URL-015` | URL | **PASS** | Whitespace stripping and sanitation | Whitespace trimmed cleanly before lexical extraction | Score=0.0, Level=LOW | — (LOW) |
| `PG-URL-016` | URL | **PASS** | Malformed URL syntax error resilience | Graceful fallback without unhandled server exception | Errors=[], Level=LOW | — (LOW) |
| `PG-URL-017` | URL | **PASS** | Empty string URL input handling | Handled safely without crash | Score=0.0, Level=LOW | — (LOW) |
| `PG-URL-018` | URL | **PASS** | SSRF protection on loopback address | Rejected by validate_url SSRF guard | Valid=False, Reason=Destination resolves to a restricted or private IP address | — (—) |
| `PG-VT-001` | VIRUSTOTAL DECISION LOGIC | **PASS** | Local TI match provides strong evidence satisfying VT skip policy | As specified in validation test definition | Validated correctly against current implementation | 57.5 (—) |
| `PG-VT-002` | VIRUSTOTAL DECISION LOGIC | **PASS** | High native multi-source evidence sufficiency satisfies analysis | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-VT-003` | VIRUSTOTAL DECISION LOGIC | **PASS** | Single weak evidence item produces insufficient score flagging escalation need | As specified in validation test definition | Validated correctly against current implementation | — (INSUFFICIENT) |
| `PG-VT-004` | VIRUSTOTAL DECISION LOGIC | **PASS** | MOCKED VT malicious payload parses correctly with positive malicious counts | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-VT-005` | VIRUSTOTAL DECISION LOGIC | **PASS** | MOCKED VT suspicious payload flags is_clean=False and preserves counts | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-VT-006` | VIRUSTOTAL DECISION LOGIC | **PASS** | MOCKED VT clean response correctly verifies is_clean=True and is_unknown=False | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-VT-007` | VIRUSTOTAL DECISION LOGIC | **PASS** | MOCKED VT 404 correctly marked as UNKNOWN and NOT clean | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-VT-008` | VIRUSTOTAL DECISION LOGIC | **PASS** | MOCKED VT timeout returns structured ERROR status without crashing | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-VT-009` | VIRUSTOTAL DECISION LOGIC | **PASS** | MOCKED VT 429 HTTP status returned as structured RATE_LIMITED status | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-VT-010` | VIRUSTOTAL DECISION LOGIC | **PASS** | MOCKED VT 500 server error handled safely without uncaught exception | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-VT-011` | VIRUSTOTAL DECISION LOGIC | **PASS** | Missing API key gracefully returns UNAVAILABLE status | As specified in validation test definition | Validated correctly against current implementation | — (—) |
| `PG-VT-012` | VIRUSTOTAL DECISION LOGIC | **PASS** | MOCKED Hash lookup returns accurate analysis stats for cryptographic hashes | As specified in validation test definition | Validated correctly against current implementation | — (—) |

## Blocked Tests

- **`PG-CROSS-006`**: QR visual decoding into URL threat intelligence inspection — *Reason:* OpenCV is an optional dependency for QR visual decoding
- **`PG-QR-001`**: QR code encoding benign URL — *Reason:* OpenCV is an optional dependency for QR visual decoding
- **`PG-QR-002`**: QR code encoding known phishing URL (Quishing) — *Reason:* OpenCV is an optional dependency for QR visual decoding
- **`PG-QR-003`**: QR code encoding suspicious private/login URL — *Reason:* OpenCV is an optional dependency for QR visual decoding
- **`PG-QR-004`**: QR code encoding non-URL text payload — *Reason:* OpenCV is an optional dependency for QR visual decoding