# Research Experiment 3: Adversarial URL Robustness Evaluation Report

## 1. Research Question

> **Primary Research Question**: How robust is the PHISHGUARD URL detection model to adversarial URL transformations that preserve the underlying destination or semantic intent?

---

## 2. Hypothesis

> **Hypothesis**: The frozen lexical URL model will be sensitive to some transformations because its prediction depends on structural and lexical URL features.

---

## 3. Motivation

Lexical machine learning models extract statistical patterns from URL strings (character lengths, delimiter counts, suspicious tokens). Threat actors actively craft perturbations (such as subdomain nesting, case alternating, or URL encoding) to bypass detection filters. Evaluating model sensitivity across structured perturbations reveals specific architectural blind spots and quantifies both evasion vulnerability and false-positive fragility.

---

## 4. Threat Model

- **Adversary Capability**: Black-box or grey-box attacker who can manipulate the URL string structure (e.g. adding subdomains, modifying path parameters, altering casing, or encoding characters) prior to delivery to a victim.
- **Semantic Constraint**: The transformed URL must remain routable and preserve the attacker's intended credential collection or malicious payload destination.
- **Defensive Boundary**: PHISHGUARD's frozen lexical inference engine (`predict_url`).

---

## 5. Dataset

- **Benchmark Corpus**: `data/processed/clean_urls.csv` ($641,134$ records).
- **Sampling Strategy**: Stratified balanced sampling ($N = 200$; 100 Benign, 100 Malicious) with a deterministic seed (`random_state=42`).

---

## 6. Sampling & Baseline Performance

- **Evaluated Samples**: $N = 200$
- **Original Baseline Performance**:
  - Accuracy: $54.00\%$
  - Precision: $66.67\%$
  - Recall: $8.00\%$
  - F1-Score: $0.1481$
  - Correctly Classified Benign: $100$
  - Correctly Classified Malicious: $8$

---

## 7. Frozen Model Configuration

- **Model Type**: Frozen Scikit-Learn `RandomForestClassifier` (14 lexical features).
- **Inference Function**: `src.models.url_model_inference.predict_url`.
- **Classification Threshold**: $\tau = 0.50$.
- **Model Parameters**: $n\_estimators=200$, `class_weight='balanced'`, `random_state=42`.

---

## 8. Transformation Definitions

1. **T1 (`added_subdomain`)**: Prepends single subdomain level (`auth.`).
2. **T2 (`deeper_subdomain`)**: Prepends two subdomain levels (`portal.secure.`).
3. **T3 (`added_path`)**: Appends `/verify/account` to path component.
4. **T4 (`added_query`)**: Appends `?session_id=987654321&auth=true`.
5. **T5 (`added_fragment`)**: Appends `#security-notice`.
6. **T6 (`case_changed`)**: Converts scheme to uppercase and capitalizes path segments.
7. **T7 (`encoded_path`)**: Applies percent-encoding to path characters.

---

## 9. Transformation Validity & Safety Rules

- **Offline Isolation**: Executed strictly on local strings; zero socket connections or HTTP requests made.
- **Traceability**: Every output row references the immutable original `sample_id`.

---

## 10. Experimental Procedure

1. Extract baseline predictions and probabilities for all 200 original URLs.
2. Apply transformations T1 through T7 independently to all 200 URLs ($200 \times 7 = 1,400$ paired evaluations).
3. Compute predictions and probabilities on transformed URLs.
4. Measure directional flips (Malicious $\rightarrow$ Benign vs. Benign $\rightarrow$ Malicious).

---

## 11. Metrics Definitions

- **Evasion Rate**: $\frac{\text{Malicious Correct} \rightarrow \text{Predicted Benign}}{\text{Total Malicious Correct}}$
- **False-Alarm Rate**: $\frac{\text{Benign Correct} \rightarrow \text{Predicted Malicious}}{\text{Total Benign Correct}}$
- **Flip Rate**: $\frac{\text{Prediction Flips}}{\text{Total Samples}}$
- **Mean Probability Shift**: $\frac{1}{N}\sum (P_{\text{trans}} - P_{\text{orig}})$

---

## 12. Empirical Results Summary

| Transformation | Samples | Orig Acc | Trans Acc | Orig F1 | Trans F1 | Flips | Flip Rate | Evasion Rate | False-Alarm Rate | Mean $\Delta P$ |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`added_subdomain`** | 200 | 54.0% | 51.5% | 0.1481 | 0.0583 | 5 | 2.5% | **62.5%** | 0.0% | -0.0125 |
| **`deeper_subdomain`** | 200 | 54.0% | 48.5% | 0.1481 | 0.0721 | 13 | 6.5% | **62.5%** | **7.0%** | +0.2865 |
| **`added_path`** | 200 | 54.0% | 50.0% | 0.1481 | **0.6667** | 192 | **96.0%** | 0.0% | **100.0%** | **+0.5925** |
| **`added_query`** | 200 | 54.0% | 54.0% | 0.1481 | 0.1481 | 0 | 0.0% | 0.0% | 0.0% | +0.0000 |
| **`added_fragment`** | 200 | 54.0% | 54.0% | 0.1481 | 0.1481 | 0 | 0.0% | 0.0% | 0.0% | +0.0000 |
| **`case_changed`** | 200 | 54.0% | 51.5% | 0.1481 | 0.0583 | 5 | 2.5% | **62.5%** | 0.0% | -0.0125 |
| **`encoded_path`** | 200 | 54.0% | 54.0% | 0.1481 | 0.1481 | 0 | 0.0% | 0.0% | 0.0% | +0.0000 |

---

## 13. Per-Transformation Analysis & Directional Shifts

### 13.1 `added_path` (High False-Alarm Fragility)
- **Finding**: Appending `/verify/account` produced a **96.0% prediction flip rate** and a **100.0% benign false-alarm rate** with a large positive probability shift ($+0.5925$).
- **Explanation**: The feature extractor counts keywords (`verify`, `account`) and measures `path_length`. Injecting security-related tokens into benign URLs causes the lexical model to immediately classify benign URLs as malicious.

### 13.2 `added_subdomain` & `case_changed` (High Malicious Evasion)
- **Finding**: Both `added_subdomain` and `case_changed` produced a **62.5% malicious evasion rate** (5 out of 8 originally-correct malicious URLs became classified as benign).
- **Explanation**: Capitalizing tokens or adding subdomains disrupted exact lowercase keyword matching, suppressing the `suspicious_keyword_count` feature and causing malicious samples to drop below the decision threshold.

### 13.3 `added_query` & `added_fragment` (High Robustness)
- **Finding**: Yielded **0.0% flip rate** and **0.0% evasion**.
- **Explanation**: The baseline feature vector does not heavily weight query strings or fragments compared to path length and keyword presence.

---

## 14. Error Analysis

- **False Positive Induction**: Benign web pages (e.g. `wikipedia.org`, `espn.go.com`) were classified as malicious purely due to the presence of path tokens (`/verify/account`), demonstrating the inherent risk of relying solely on lexical keyword features.
- **False Negative Evasion**: Phishing URLs relying on lowercase keywords were sanitized by case changes, evading single-layer lexical scrutiny.

---

## 15. Limitations

- Only tested 7 distinct structural transformations.
- Transformations were applied uniformly across all samples without optimizing perturbation budgets per sample.

---

## 16. Threats to Validity

- Synthetic string transformations may not represent all zero-day phishing kit evasions.
- The sample size of $N=200$ captures prominent shifts, but rare edge cases require larger population sweeps.

---

## 17. Reproducibility Information

- **Execution Script**: [`src/research/experiment_03_adversarial_robustness.py`](file:///home/rahaman1407/AI-Phishing-Detection/src/research/experiment_03_adversarial_robustness.py)
- **Summary Results CSV**: [`data/processed/research/experiment_03_results.csv`](file:///home/rahaman1407/AI-Phishing-Detection/data/processed/research/experiment_03_results.csv)
- **Sample Results CSV**: [`data/processed/research/experiment_03_sample_results.csv`](file:///home/rahaman1407/AI-Phishing-Detection/data/processed/research/experiment_03_sample_results.csv)
- **Unit Test Suite**: [`tests/test_experiment_03.py`](file:///home/rahaman1407/AI-Phishing-Detection/tests/test_experiment_03.py)

---

## 18. Evidence-Based Conclusion

The empirical results confirm the hypothesis: **the frozen lexical URL model is highly sensitive to structural and token perturbations**. Specifically:
1. **Keyword Injection** (`added_path`) triggers an extreme false-alarm rate ($100\%$) on benign samples.
2. **Casing & Subdomain Modifications** (`case_changed`, `added_subdomain`) induce significant evasion ($62.5\%$) on malicious samples.
3. These findings provide strong empirical justification for PHISHGUARD's **multi-layer architecture**, which validates domain ownership, TLS certificates, SPF/DKIM authentication, and DOM forms to prevent single-layer lexical evasion.
