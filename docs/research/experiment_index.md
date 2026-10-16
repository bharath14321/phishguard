# PHISHGUARD Research Experiment Index

This index defines the comprehensive research roadmap comprising six experimental studies.

---

## Experiment Index & Roadmap

### [Experiment 01: Layer-by-Layer Multi-Artifact Evaluation](file:///home/rahaman1407/AI-Phishing-Detection/docs/research/experiment_01_layer_evaluation.md)
- **Status**: `[COMPLETED]`
- **Code**: [`src/research/experiment_01_layer_evaluation.py`](file:///home/rahaman1407/AI-Phishing-Detection/src/research/experiment_01_layer_evaluation.py)
- **Data**: [`data/processed/research/experiment_01_results.csv`](file:///home/rahaman1407/AI-Phishing-Detection/data/processed/research/experiment_01_results.csv)
- **Focus**: Evaluates 6 cumulative security layer configurations (A through F) on stratified benchmark samples.

---

### Experiment 02: External & Out-of-Distribution Generalization
- **Status**: `[IMPLEMENTED / UTILITY READY]`
- **Code**: [`src/analysis/external_evaluation.py`](file:///home/rahaman1407/AI-Phishing-Detection/src/analysis/external_evaluation.py)
- **Focus**: Quantifies model performance degradation and distribution drift when evaluating independent, unseen URL corpora.

---

### Experiment 03: Adversarial URL Evasion Robustness
- **Status**: `[HISTORICAL BASELINE COMPLETED / EXTENSION PLANNED]`
- **Record**: [`docs/experiments.md/experiments_comparisions.md`](file:///home/rahaman1407/AI-Phishing-Detection/docs/experiments.md/experiments_comparisions.md)
- **Focus**: Tests classifier evasion rates against 7 transformation techniques (subdomains, character casing, URL encoding).

---

### Experiment 04: Systematic Feature & Layer Ablation Study
- **Status**: `[PLANNED]`
- **Focus**: Isolates feature and layer contributions using leave-one-out and permutation importance on 641,108 samples.

---

### Experiment 05: Explainable AI & Security Analyst Triage Fidelity
- **Status**: `[PARTIALLY IMPLEMENTED]`
- **Focus**: Evaluates rule-based feature attribution and conversational AI assistance in reducing SOC alert triage duration.

---

### Experiment 06: Dynamic Sandbox Behavioral Telemetry Integration
- **Status**: `[PLANNED]`
- **Focus**: Evaluates process injection and network beaconing telemetry from isolated VM sandboxes in resolving static attachment ambiguities.
