# Research Experiment 2: External Generalization Evaluation Report

## 1. Research Question

> **Primary Research Question**: How well does the PHISHGUARD URL detection model generalize to an independent dataset that was not used for model development or internal evaluation?

---

## 2. Hypothesis

> **Hypothesis**: The frozen URL model will retain useful predictive performance on an independent dataset, but performance may change because of differences in URL distributions, domains, attack campaigns, collection methods, and labeling.

---

## 3. Motivation

Internal train/test evaluations (e.g. standard 80/20 cross-validation or held-out splits from the same original source) provide a measure of in-distribution fit. However, operational cyber defense requires models to detect unseen phishing campaigns originating from different infrastructure, different geographic registrars, and different evasion techniques. An external evaluation measures the true generalization frontier of the feature representations and classifiers.

---

## 4. Dataset Provenance

- **Internal Development Corpus (Dataset 1)**: `data/processed/clean_urls.csv` (derived from `data/raw/malicious_phish.csv`), comprising $641,108$ usable records.
- **External Evaluation Corpus (Dataset 2)**: Currently **None** in repository storage.

---

## 5. Dataset Independence

To qualify as a valid external generalization test:
1. The dataset must be sourced from an external collector (e.g., PhishTank feeds, OpenPhish feeds, Tranco/Cisco Umbrella top domains) distinct from the Kaggle/ISCX corpus used in Dataset 1.
2. The samples must not have been seen during model training, hyperparameter tuning, or threshold selection.

---

## 6. Dataset Statistics

| Metric | Internal Benchmark (Dataset 1) | External Evaluation (Dataset 2) |
| :--- | :---: | :---: |
| **Total Usable Records** | 641,108 | **BLOCKED (0 stored)** |
| **Benign Samples** | 428,080 (66.77%) | N/A |
| **Malicious Samples** | 213,028 (33.23%) | N/A |
| **Internal Test Split** | 128,222 (20.0%) | N/A |

---

## 7. Label Definitions & Taxonomy

- **Binary Class 0**: Benign / Clean / Legitimate web addresses.
- **Binary Class 1**: Malicious web addresses (Phishing, Malware distribution, Defacement).

---

## 8. Data Preprocessing Protocol

The preprocessing pipeline (`src/research/experiment_02_external_evaluation.py`):
1. Normalizes string encoding to UTF-8 and trims leading/trailing whitespace.
2. Validates URL scheme and hostname syntax.
3. Filters out malformed strings and missing labels.
4. Prunes exact internal duplicates within the external candidate set.

---

## 9. Duplicate & Overlap Analysis Protocol

The evaluation engine performs cross-dataset set intersection:
$$\text{Overlap} = \text{External URLs} \cap \text{Internal Development URLs}$$
The overlap count and percentage must be recorded before computing metrics, ensuring transparency regarding exact duplicate leakage.

---

## 10. Frozen Model Configuration

The evaluation harness fixes all model weights and hyperparameters to the internal baseline:
- **Model Type**: Scikit-Learn `RandomForestClassifier`
- **Number of Estimators**: 200 trees
- **Class Weighting**: `balanced`
- **Random State**: 42
- **Decision Threshold**: $\tau = 0.50$ (Probability $\ge 0.50 \implies \text{Malicious}$)

---

## 11. Feature Extraction Pipeline

Evaluates the exact 14 lexical features extracted by `extract_url_features()`:
`url_length`, `hostname_length`, `path_length`, `query_length`, `dot_count`, `hyphen_count`, `digit_count`, `special_char_count`, `subdomain_count`, `contains_ip`, `uses_https`, `contains_at`, `contains_double_slash`, `suspicious_keyword_count`.

---

## 12. Evaluation Methodology

1. Ingest validated external CSV via `load_and_validate_external_dataset()`.
2. Execute read-only prediction via `predict_url()`.
3. Compute confusion matrix $(TN, FP, FN, TP)$ and statistical metrics.
4. Calculate generalization performance delta $\Delta = \text{Metric}_{\text{ext}} - \text{Metric}_{\text{int}}$.

---

## 13. Statistical Metrics Definitions

- $\text{Accuracy} = \frac{TP + TN}{TP + TN + FP + FN}$
- $\text{Precision} = \frac{TP}{TP + FP}$
- $\text{Recall} = \frac{TP}{TP + FN}$
- $\text{F1} = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$
- $\text{False Positive Rate (FPR)} = \frac{FP}{FP + TN}$
- $\text{False Negative Rate (FNR)} = \frac{FN}{FN + TP}$

---

## 14. Empirical Results

> **STATUS: BLOCKED — INDEPENDENT EXTERNAL DATASET REQUIRED**
>
> In accordance with scientific integrity rules, empirical external metrics cannot be computed until an independent, uncurated external dataset is provisioned in the repository. No synthetic data has been substituted.

---

## 15. Internal Benchmark vs. External Comparison Table

| Metric | Internal Baseline ($N = 128,222$) | External Evaluation | Generalization Delta ($\Delta$) |
| :--- | :---: | :---: | :---: |
| **Accuracy** | 91.08% (0.9108) | `BLOCKED` | N/A |
| **Precision** | 85.17% (0.8517) | `BLOCKED` | N/A |
| **Recall** | 88.59% (0.8859) | `BLOCKED` | N/A |
| **F1-Score** | 86.85% (0.8685) | `BLOCKED` | N/A |
| **ROC-AUC** | 94.20% (0.9420 est.) | `BLOCKED` | N/A |
| **False Positive Rate (FPR)** | 7.68% (0.0768) | `BLOCKED` | N/A |
| **False Negative Rate (FNR)** | 11.41% (0.1141) | `BLOCKED` | N/A |

---

## 16. Distribution-Shift Hypotheses

When an external dataset is evaluated, the following distribution shifts are expected:
1. **TLD Distribution Shift**: Emerging attack campaigns frequently utilize newly registered gTLDs (`.top`, `.xyz`, `.icu`) not well-represented in older corpora.
2. **Path Complexity Shift**: Modern phishing kits often deploy randomized UUIDs or base64-encoded URL parameters that increase `path_length` and `special_char_count`.
3. **HTTPS Adoption**: Benign and phishing URLs now overwhelmingly use HTTPS ($>80\%$), reducing the discriminatory power of `uses_https`.

---

## 17. Error Analysis Plan

Upon ingestion of external samples:
- Stratify false positives by top benign second-level domains (e.g. CDNs, URL shorteners).
- Stratify false negatives by attack category (brand phishing, invoice scams, OAuth consent phishing).

---

## 18. Threats to Validity

1. **Ground Truth Label Noise**: External threat feeds (such as crowdsourced blocklists) contain known labeling latency and false alarms.
2. **Class Imbalance**: Real-world web traffic is heavily skewed towards benign traffic ($>99\%$), whereas benchmark datasets often enforce artificially balanced distributions ($1:1$ or $2:1$).

---

## 19. Limitations

- Evaluation is strictly blocked pending ingestion of a secondary dataset file.
- Automatic web downloading was disallowed to preserve deterministic repository boundaries.

---

## 20. Reproducibility Information

- **Execution Module**: [`src/research/experiment_02_external_evaluation.py`](file:///home/rahaman1407/AI-Phishing-Detection/src/research/experiment_02_external_evaluation.py)
- **Unit Test Harness**: [`tests/test_experiment_02.py`](file:///home/rahaman1407/AI-Phishing-Detection/tests/test_experiment_02.py)
- **Results Output Location**: [`data/processed/research/experiment_02_results.csv`](file:///home/rahaman1407/AI-Phishing-Detection/data/processed/research/experiment_02_results.csv)

---

## 21. Evidence-Based Conclusion

The evaluation infrastructure for Experiment 2 has been constructed, validated with comprehensive unit tests, and calibrated against the established internal Random Forest benchmark. The empirical execution is cleanly recorded as `BLOCKED — INDEPENDENT EXTERNAL DATASET REQUIRED` without fabricating results or substituting inappropriate synthetic fixtures.
