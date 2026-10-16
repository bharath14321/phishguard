# PHISHGUARD AI & Machine Learning Architecture

## 1. Overview

PHISHGUARD integrates a hybrid artificial intelligence architecture combining statistical machine learning, heuristic expert systems, and large language model (LLM) reasoning:

1. **Statistical ML**: Supervised classification models trained on 14 lexical URL features to detect obfuscation patterns.
2. **Rule-Based Heuristic Engine**: Deterministic cybersecurity signal scoring for domain, brand, cryptographic email auth, and DOM heuristics.
3. **Large Language Model (LLM)**: An AI Security Analyst powered by Google Gemini (with deterministic rule-based fallback) for natural-language telemetry explanation.

---

## 2. Historical Machine Learning Baselines

The statistical URL classification engine was trained and evaluated on `data/processed/url_features.csv` ($N = 641,108$ samples; 428,080 Benign, 213,028 Malicious) using an 80/20 stratified split (`test_size=0.20`, `random_state=42`, `stratify=y`).

> [!NOTE]
> These figures represent the historical, offline baseline training results. They are distinct from the Research Experiment 1 Layer-by-Layer evaluation.

| Model | Hyperparameters / Configuration | Accuracy | Precision | Recall | F1-Score | Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **Logistic Regression** | `StandardScaler`, `class_weight='balanced'`, `max_iter=1000`, `random_state=42` | 75.99% | 62.24% | 70.57% | 66.14% | `[IMPLEMENTED]` |
| **Random Forest** | `n_estimators=200`, `class_weight='balanced'`, `random_state=42`, `n_jobs=-1` | **91.08%** | 85.17% | **88.59%** | **86.85%** | `[IMPLEMENTED]` |
| **XGBoost** | `n_estimators=300`, `max_depth=8`, `learning_rate=0.1`, `subsample=0.8`, `colsample_bytree=0.8` | 90.58% | **89.03%** | 81.73% | 85.22% | `[IMPLEMENTED]` |

### Historical Baseline Confusion Matrices ($N_{\text{test}} = 128,222$)

#### Logistic Regression
```text
                  Predicted Benign    Predicted Malicious
Actual Benign          67,371                18,245
Actual Malicious       12,538                30,068
```

#### Random Forest (Baseline Champion)
```text
                  Predicted Benign    Predicted Malicious
Actual Benign          79,044                 6,572
Actual Malicious        4,860                37,746
```

#### XGBoost
```text
                  Predicted Benign    Predicted Malicious
Actual Benign          81,325                 4,291
Actual Malicious        7,784                34,822
```

---

## 3. Feature Importance Analysis

Feature contributions were evaluated from the Random Forest ensemble baseline:

| Feature Rank | Feature Name | Description | Importance |
| :---: | :--- | :--- | :---: |
| 1 | `path_length` | Total character length of the URL path | 0.1991 |
| 2 | `dot_count` | Number of dot (`.`) delimiters | 0.1351 |
| 3 | `hostname_length` | Length of hostname segment | 0.1160 |
| 4 | `subdomain_count` | Count of subdomains | 0.1017 |
| 5 | `special_char_count` | Count of special characters (`-`, `_`, `=`, `?`, `%`) | 0.0981 |
| 6 | `url_length` | Overall length of full URL string | 0.0926 |
| 7 | `digit_count` | Total numeric digits | 0.0792 |
| 8 | `query_length` | Length of URL query parameters | 0.0562 |
| 9 | `hyphen_count` | Count of hyphens in hostname and path | 0.0418 |
| 10 | `uses_https` | HTTPS protocol indicator (0 or 1) | 0.0402 |
| 11 | `contains_ip` | Direct IP address indicator (0 or 1) | 0.0209 |
| 12 | `suspicious_keyword_count` | Frequency of security trigger words | 0.0172 |
| 13 | `contains_at` | `@` symbol presence | 0.0009 |
| 14 | `contains_double_slash` | Extraneous `//` in path | Trace |

---

## 4. Model Inference & Runtime Fallback

The runtime inference module (`src/models/url_model_inference.py`):
1. Lazily attempts to load the serialized artifact `url_random_forest.joblib` via `joblib`.
2. If the artifact exists, extracts the 14-feature vector and computes `predict_proba([features])[0][1]`.
3. If the model artifact is absent, provides a deterministic lexical heuristic fallback:
   $$\text{score} = \min(1.0, (\text{suspicious\_keyword\_count} \times 0.3) + (\text{contains\_ip} \times 0.5))$$
   with `model_available: False`.

---

## 5. Explainable AI & SHAP Integration

- **Rule-Grounded Rationale**: The explanation generator (`src/analysis/model_explainer.py`) converts active risk signals into human-readable causal descriptions. `[IMPLEMENTED]`
- **SHAP (SHapley Additive exPlanations)**: Architecture supports kernel and tree SHAP values for local feature attribution. `[EXPERIMENTAL / BASELINE RECORDED]`

---

## 6. AI Security Analyst & LLM Integration

### 6.1 Google Gemini Provider (`src/analysis/gemini_analyzer.py`) `[IMPLEMENTED / OPTIONAL KEY]`
- When `GEMINI_API_KEY` is configured in environment:
  - Formulates a system-prompt-isolated inquiry containing only sanitized analysis telemetry.
  - Generates comprehensive threat narratives, mitigation recommendations, and answers analyst queries.

### 6.2 Deterministic Fallback Engine `[IMPLEMENTED]`
- When `GEMINI_API_KEY` is not present or an API failure occurs:
  - Deterministically parses the scan's `RiskResult`, `signals`, and `correlated_evidence`.
  - Formats an executive threat debrief with breakdown by artifact layer and recommended remediation actions.
  - Guarantees zero downtime and complete functionality in air-gapped or keyless environments.
