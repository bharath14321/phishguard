# PHISHGUARD Datasets and Feature Engineering

## 1. Dataset Inventory & Provenance

The PHISHGUARD repository contains benchmark datasets located in `data/raw/` and `data/processed/`.

| Dataset Path | File Type | Record Count | Description | Primary Use Case |
| :--- | :--- | :---: | :--- | :--- |
| `data/processed/clean_urls.csv` | CSV | 641,134 | Preprocessed, deduplicated URL corpus with normalized class labels. | URL Evaluation & Testing |
| `data/processed/url_features.csv` | CSV | 641,108 | Extracted 14-feature numeric matrix with binary and multiclass target columns. | Supervised ML Training |
| `data/raw/malicious_phish.csv` | CSV | 651,191 | Raw collected corpus containing mixed web URLs across multiple threat types. | Raw Source Archive |
| `data/raw/test_email.eml` | RFC 5322 | 1 sample | Synthetic phishing email with SPF failure and credential prompt. | Email Analyzer Unit Testing |
| `data/raw/test_attachment.docm` | OLE/VBA | 1 sample | Weaponized macro-enabled test document payload. | Attachment Unit Testing |
| `data/processed/research/experiment_01_results.csv` | CSV | 6 records | Empirical metrics from Research Experiment 1 Layer-by-Layer evaluation. | Research Verification |

---

## 2. Class Distribution & Taxonomy

In `data/processed/url_features.csv` ($N = 641,108$ usable samples):

### 2.1 Binary Mapping
- **Label 0 (Benign)**: $428,080$ samples ($66.77\%$)
- **Label 1 (Malicious)**: $213,028$ samples ($33.23\%$)

### 2.2 Multiclass Breakdown
- `benign`: $428,080$ ($66.77\%$)
- `phishing`: $94,111$ ($14.68\%$)
- `defacement`: $96,457$ ($15.05\%$)
- `malware`: $22,460$ ($3.50\%$)

---

## 3. Data Preprocessing Pipeline

1. **Deduplication**: Exact string duplicates in raw URL entries were identified and pruned ($651,191 \rightarrow 641,134$).
2. **Malformed URL Sanitization**: URLs with invalid ASCII encodings, empty strings, or unparseable delimiters were flagged and discarded ($26$ malformed records removed $\rightarrow 641,108$ usable).
3. **Data Leakage Prevention**: Ground-truth target columns (`type`, `binary_label`, `multiclass_label`) and raw string identifiers (`url`) are strictly isolated from feature matrix $X$ during model training.

---

## 4. 14-Dimensional Lexical Feature Specification

| Feature Name | Type | Range / Domain | Extraction Logic | Threat Rationale |
| :--- | :---: | :---: | :--- | :--- |
| `url_length` | Integer | $[1, 2048]$ | Total string character length. | Phishing URLs often use long randomized paths to evade detection. |
| `hostname_length` | Integer | $[1, 253]$ | Length of parsed NetLoc/hostname. | Domain padding and embedded subdomains increase hostname length. |
| `path_length` | Integer | $[0, 2048]$ | Character length of URL path component. | Deep nested directory structures frequently host credential forms. |
| `query_length` | Integer | $[0, 1024]$ | Length of query string after `?`. | Phishing payloads pass obfuscated tracking IDs in query strings. |
| `dot_count` | Integer | $[0, 50]$ | Count of dot (`.`) characters. | Excessive dots indicate complex subdomain structures (e.g., `paypal.com.account.verify.cc`). |
| `hyphen_count` | Integer | $[0, 50]$ | Count of `-` characters. | Used in typosquatting and deceptive brand mimicry (`secure-login-update`). |
| `digit_count` | Integer | $[0, 100]$ | Count of numeric characters $[0-9]$. | Automated phishing kits frequently generate hex or numerical directory IDs. |
| `special_char_count` | Integer | $[0, 100]$ | Count of `_`, `=`, `?`, `%`, `&`, `+`, `#`. | High special character density signifies parameter encoding or evasion. |
| `subdomain_count` | Integer | $[0, 20]$ | Number of dot-separated labels preceding domain. | Subdomain hopping allows attackers to abuse free DNS providers. |
| `contains_ip` | Binary | $\{0, 1\}$ | Regex matching IPv4/IPv6 address pattern. | Direct IP access bypasses domain reputation systems. |
| `uses_https` | Binary | $\{0, 1\}$ | Schema prefix equals `https://`. | Malicious sites exploit free SSL/TLS to create false user trust. |
| `contains_at` | Binary | $\{0, 1\}$ | Presence of `@` character. | RFC 1738 userinfo trick: browsers ignore text before `@` (`user@real.com`). |
| `contains_double_slash` | Binary | $\{0, 1\}$ | Occurrence of `//` in the path after schema. | Redirect evasion technique used to confuse naive URL parsers. |
| `suspicious_keyword_count` | Integer | $[0, 20]$ | Match count against targeted dictionary. | Keywords: `login`, `verify`, `account`, `banking`, `security`, `update`, `signin`. |

---

## 5. Known Dataset Limitations

1. **Single-Modality Bias**: `clean_urls.csv` contains exclusively URL strings. It does not include paired email bodies, raw MIME headers, network PCAP traces, or live HTML captures.
2. **Temporal Drift**: Phishing campaigns evolve rapidly; static lexical datasets do not capture modern zero-day brand campaigns without continuous retraining.
3. **Synthetic Test Artifacts**: Email (`test_email.eml`) and attachment (`test_attachment.docm`) are unit test fixtures rather than an evaluation corpus.
