# PHISHGUARD Research Roadmap & Experimental Methodology

## 1. Research Overview & Experimental Framework

PHISHGUARD's research agenda is structured around six formal experiments designed to validate multi-layer phishing detection efficacy, model generalization, adversarial robustness, feature ablation, explainability fidelity, and dynamic telemetry integration.

---

## 2. Research Experiments Specification

### Experiment 1: Layer-by-Layer Evaluation `[COMPLETED]`
- **Research Question**: *Does combining independent evidence from multiple artifact layers improve phishing detection accuracy and system resilience compared with single-layer URL detection?*
- **Hypothesis**: Progressively evaluating domain heuristics and multi-layer evidence structures will reduce false positives without inducing false risk inflation on missing layers.
- **Dataset**: `data/processed/clean_urls.csv` ($N = 500$ balanced, stratified; 250 benign, 250 malicious).
- **Independent Variables**: Evaluated security layers (Config A: URL ML; Config B: URL+Domain; Config C: +Email; Config D: +Web; Config E: +Attachment; Config F: Unified Multi-Layer).
- **Dependent Variables**: Accuracy, Precision, Recall, F1-Score, ROC-AUC, Latency per sample.
- **Current Status**: `COMPLETED`. Empirical results saved to `data/processed/research/experiment_01_results.csv`.
- **Known Limitations & Reconciliation Note**:
  - *Dataset Modality Limitation*: Standard URL benchmark datasets do not contain paired email headers, live HTML DOM snapshots, or binary attachments. Consequently, Experiments C–E strictly represented these layers as `UNKNOWN / NOT_AVAILABLE`.
  - *Baseline Reconciliation*: In Experiment 1, URL-only lexical heuristic classification yielded 53.00% accuracy and 85.71% precision at a conservative decision threshold. This represents runtime lexical classification under frozen test conditions, and must be interpreted in contrast to the historical Random Forest supervised baseline (91.08% accuracy, 86.85% F1) trained on the full feature matrix.

---

### Experiment 2: External Generalization Evaluation `[COMPLETED / UTILITY IMPLEMENTED]`
- **Research Question**: *How effectively do lexical models trained on one collection source generalize to an independent, unseen external URL distribution?*
- **Hypothesis**: Lexical models exhibit performance degradation (concept drift) when tested on uncurated external datasets due to differing distribution shifts in path lengths and keywords.
- **Dataset**: Secondary unseen external CSV corpus.
- **Independent Variables**: Dataset provenance (In-distribution vs. Out-of-distribution).
- **Dependent Variables**: Generalization gap ($\Delta\text{Accuracy}$, $\Delta\text{F1}$), Confusion Matrix drift.
- **Current Status**: `IMPLEMENTED` via evaluation utility `src/analysis/external_evaluation.py`.

---

### Experiment 3: Adversarial Evasion Robustness `[HISTORICAL BASELINE EXECUTED / EXTENSION PLANNED]`
- **Research Question**: *How susceptible are URL lexical classifiers to adversarial evasion transformations such as deep subdomains, path encoding, and character casing?*
- **Hypothesis**: Subdomain manipulation and URL path encoding cause significant prediction drift on models reliant on string-length features.
- **Dataset**: 20 benign and 20 malicious sample URLs subjected to 7 controlled transformations.
- **Independent Variables**: Transformation type (Deeper subdomain, Added subdomain, Case changed, Encoded path, Added fragment, Added path, Added query).
- **Dependent Variables**: Prediction change rate (% of samples whose classification changed).
- **Current Status**: `BASELINE COMPLETED`. Initial baseline demonstrated that deeper subdomain insertion produced a 45% prediction change rate.

---

### Experiment 4: Comprehensive Feature Ablation Study `[PLANNED]`
- **Research Question**: *Which specific subset of the 14 lexical features and 6 heuristic layers contributes most significantly to detection accuracy?*
- **Hypothesis**: Removal of `path_length`, `subdomain_count`, and `dot_count` causes the largest reduction in ensemble ROC-AUC.
- **Dataset**: `data/processed/url_features.csv` ($N = 641,108$).
- **Independent Variables**: Feature masks (leave-one-out and layer-wise feature ablation).
- **Dependent Variables**: $\Delta\text{F1}$, $\Delta\text{ROC-AUC}$, Permutation feature importance.
- **Current Status**: `PLANNED`.

---

### Experiment 5: Explainability & Analyst Trust (XAI) `[PARTIALLY IMPLEMENTED]`
- **Research Question**: *Does providing rule-grounded and SHAP-based feature attribution improve human analyst triage speed and decision confidence?*
- **Hypothesis**: Providing transparent risk signals and AI analyst summaries reduces false alert investigation time.
- **Current Status**: `PARTIALLY IMPLEMENTED` (Rule-based explainers and AI Security Analyst chat operational; user study planned).

---

### Experiment 6: Behavioral Malware Telemetry Integration `[PLANNED]`
- **Research Question**: *Does incorporating dynamic sandbox telemetry (process trees, registry modifications, DNS queries) detect zero-day evasion techniques missed by static analysis?*
- **Hypothesis**: Dynamic process injection and network beaconing telemetry correlate with static macro flags to eliminate static false positives.
- **Current Status**: `PLANNED` (Sandbox VM architectural contracts defined in `docs/sandbox_architecture.md` and `src/sandbox/analysis_engine.py`).
