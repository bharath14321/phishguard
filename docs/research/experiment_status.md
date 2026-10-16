# PHISHGUARD Research Experiment Status Matrix

## 1. Experiment Lifecycle & Execution Status

| Experiment ID | Title | Lifecycle Status | Artifacts & Documentation | Test & Empirical Verification |
| :---: | :--- | :---: | :--- | :--- |
| **EXP-01** | Layer-by-Layer Evaluation | `[COMPLETED]` | [`docs/research/experiment_01_layer_evaluation.md`](file:///home/rahaman1407/AI-Phishing-Detection/docs/research/experiment_01_layer_evaluation.md)<br>[`data/processed/research/experiment_01_results.csv`](file:///home/rahaman1407/AI-Phishing-Detection/data/processed/research/experiment_01_results.csv) | Verified via `tests/test_experiment_01.py` (11 passing tests). Full empirical metrics table generated. |
| **EXP-02** | External Generalization | `[BLOCKED — INDEPENDENT DATASET REQUIRED]` | [`docs/research/experiment_02_external_evaluation.md`](file:///home/rahaman1407/AI-Phishing-Detection/docs/research/experiment_02_external_evaluation.md)<br>[`data/processed/research/experiment_02_results.csv`](file:///home/rahaman1407/AI-Phishing-Detection/data/processed/research/experiment_02_results.csv) | Evaluation harness verified via `tests/test_experiment_02.py` (10 passing tests). Empirical evaluation cleanly marked BLOCKED pending independent external dataset ingestion. |
| **EXP-03** | Adversarial URL Robustness | `[COMPLETED]` | [`docs/research/experiment_03_adversarial_robustness.md`](file:///home/rahaman1407/AI-Phishing-Detection/docs/research/experiment_03_adversarial_robustness.md)<br>[`data/processed/research/experiment_03_results.csv`](file:///home/rahaman1407/AI-Phishing-Detection/data/processed/research/experiment_03_results.csv) | Verified via `tests/test_experiment_03.py` (12 passing tests). Complete 1,400 paired evaluations executed across 7 transformations. |
| **EXP-04** | Feature Ablation Study | `[PLANNED]` | [`docs/RESEARCH_METHODOLOGY.md`](file:///home/rahaman1407/AI-Phishing-Detection/docs/RESEARCH_METHODOLOGY.md) | Methodology formulated; execution scheduled for next research sprint. |
| **EXP-05** | Explainability (XAI) | `[PARTIALLY IMPLEMENTED]` | [`src/analysis/model_explainer.py`](file:///home/rahaman1407/AI-Phishing-Detection/src/analysis/model_explainer.py)<br>[`app/routers/chat.py`](file:///home/rahaman1407/AI-Phishing-Detection/app/routers/chat.py) | Rule explainers & AI Analyst chat operational. Analyst triage study planned. |
| **EXP-06** | Behavioral Malware Telemetry | `[PLANNED]` | [`src/sandbox/analysis_engine.py`](file:///home/rahaman1407/AI-Phishing-Detection/src/sandbox/analysis_engine.py)<br>[`docs/sandbox_architecture.md`](file:///home/rahaman1407/AI-Phishing-Detection/docs/sandbox_architecture.md) | Abstract VM contracts defined; hypervisor integration planned. |

---

## 2. Key Methodological Caveats & Clarifications

1. **Experiment 1 Dataset Modality**:
   - In Experiment 1, the benchmark URL corpus (`clean_urls.csv`) lacks paired email, webpage DOM, and attachment artifacts.
   - For configurations C through E, missing layers were preserved as `None` / `UNKNOWN`.
   - The test verified that missing layers do **not** trigger false alarms (FP = 0), though full multi-layer recall requires multi-modal datasets.
2. **Reconciliation of URL Classification Baselines**:
   - Historical supervised Random Forest baseline achieved **91.08% accuracy, 86.85% F1** on the full 14-feature training split ($N_{\text{test}} = 128,222$).
   - Experiment 1 runtime lexical heuristic inference under frozen conditions achieved **53.00% accuracy, 85.71% precision** ($N=500$).
   - These are documented separately to maintain full scientific integrity.
