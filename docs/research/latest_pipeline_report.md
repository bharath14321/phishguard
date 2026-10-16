# PHISHGUARD Automated Data & Threat Intelligence Pipeline Report

**Generated at**: 2026-10-04T18:14:10.178779  
**Pipeline Duration**: 0.63 seconds  
**Production Model**: Unchanged (`src/models/url_random_forest.joblib`)

---

## 1. Threat Intelligence Ingestion
- **Total Local Indicators Loaded**: 0
- **Active Feeds**: 
- **Local DB Location**: `data/threat_intelligence.db`

---

## 2. Dataset Quality & Leakage Audit
- **Audit Status**: `PASSED`
- **Exact Duplicates**: 0
- **Label Conflicts**: 0
- **Train/Test Overlap**: 0

---

## 3. Candidate Model Training & Comparison

- **Candidate File**: `candidate_randomforest_20261004_181410.joblib`
- **Accuracy**: `0.9147` (Baseline: `0.9108`)
- **Precision**: `0.8282` (Baseline: `0.8517`)
- **Recall**: `0.8534` (Baseline: `0.8859`)
- **F1 Score**: `0.8406` (Baseline: `0.8685`)
- **Promotion Status**: `MANUAL_APPROVAL_REQUIRED_FOR_PRODUCTION_PROMOTION`


---

## 4. Manual Actions Required
- **openphish_academic**: OpenPhish academic access requires account approval and registration with academic email. Complete registration at openphish.com, configure OPENPHISH_API_KEY in .env, and re-run pipeline.
- **enron_email_sample**: Enron corpus is ~423MB compressed (~1.7GB raw). Requires user confirmation before automatic large download. Set ENRON_DOWNLOAD_APPROVED=true in .env to enable.
