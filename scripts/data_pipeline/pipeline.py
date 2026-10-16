"""
scripts/data_pipeline/pipeline.py

Unified Master Data, Threat Intelligence, and Model Training Orchestration Pipeline.

Executes End-to-End:
1. Source Inspection and Availability Check
2. Automated Threat Intelligence and Dataset Acquisition
3. SHA-256 integrity validation and metadata generation
4. Local Threat Intelligence SQLite Database compilation & indexing
5. Dataset quality & data leakage auditing (produces leakage_report.json)
6. Candidate Model Training & Baseline Comparison (produces evaluation reports)
7. Master Manifest & Markdown Executive Summary generation

Execution:
python scripts/data_pipeline/pipeline.py
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from scripts.data_pipeline.download_sources import download_all_sources, load_sources_config
from scripts.data_pipeline.build_ti_database import build_ti_database
from scripts.data_pipeline.leakage_check import check_dataset_leakage
from scripts.data_pipeline.train_models import train_candidate_model

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s - %(message)s")
logger = logging.getLogger("phishguard.pipeline")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
PROCESSED_DATA_DIR = BASE_DIR / "data" / "processed"
QUALITY_DIR = PROCESSED_DATA_DIR / "quality"
EVALUATION_DIR = PROCESSED_DATA_DIR / "model_evaluation"
DOCS_DIR = BASE_DIR / "docs" / "research"


def run_pipeline(train_candidate: bool = True, sample_size: int = 15000) -> Dict[str, Any]:
    """
    Run the complete automated PHISHGUARD pipeline.
    """
    pipeline_start = time.time()
    logger.info("=================================================================")
    logger.info("  STARTING PHISHGUARD AUTOMATED DATA & THREAT INTEL PIPELINE     ")
    logger.info("=================================================================")

    # 1. Source Discovery & Ingestion
    logger.info("--- Stage 1: Dataset & Threat Intel Feed Ingestion ---")
    download_results = download_all_sources()

    acquired_count = sum(1 for r in download_results if r["status"] == "SUCCESS")
    pending_manual = [r for r in download_results if r.get("manual_action_required")]

    logger.info(f"Sources processed: {len(download_results)} (Acquired: {acquired_count}, Pending Manual Action: {len(pending_manual)})")

    # 2. Build Local Threat Intelligence Database
    logger.info("--- Stage 2: Local Threat Intelligence Compilation ---")
    ti_result = build_ti_database()

    # 3. Quality Audit & Leakage Detection
    logger.info("--- Stage 3: Dataset Quality & Leakage Audit ---")
    features_csv = PROCESSED_DATA_DIR / "url_features.csv"
    if features_csv.exists():
        import pandas as pd
        df_sample = pd.read_csv(features_csv, nrows=sample_size)
        leakage_result = check_dataset_leakage(df_sample)
    else:
        leakage_result = {"status": "SKIPPED", "message": "url_features.csv not yet generated."}

    # 4. Candidate Model Training (Non-Destructive)
    candidate_result = None
    if train_candidate and features_csv.exists() and leakage_result.get("status") != "BLOCKED":
        logger.info("--- Stage 4: Candidate Model Training & Baseline Comparison ---")
        candidate_result = train_candidate_model(model_type="RandomForest", sample_size=sample_size)
    else:
        logger.info("--- Stage 4: Candidate Training Skipped or Blocked by Quality Audit ---")

    pipeline_duration = round(time.time() - pipeline_start, 2)

    # 5. Master Manifest Generation
    manifest = {
        "pipeline_version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "duration_seconds": pipeline_duration,
        "stages": {
            "ingestion": {
                "total_sources": len(download_results),
                "acquired": acquired_count,
                "pending_manual_actions": len(pending_manual),
                "sources": download_results,
            },
            "threat_intelligence": ti_result,
            "leakage_quality": leakage_result,
            "candidate_model": candidate_result,
        },
        "production_model_status": {
            "current_production_model": "src/models/url_random_forest.joblib",
            "status": "UNCHANGED",
            "approval_required": bool(candidate_result is not None),
        }
    }

    # Save manifest
    PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
    manifest_path = PROCESSED_DATA_DIR / "model_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    # 6. Generate Human-Readable Markdown Report
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    report_md_path = DOCS_DIR / "latest_pipeline_report.md"

    manual_actions_md = "\n".join([f"- **{s['name']}**: {s['message']}" for s in pending_manual]) if pending_manual else "None currently required."

    candidate_md = "No candidate trained in this run."
    if candidate_result and "metrics" in candidate_result:
        m = candidate_result["metrics"]
        candidate_md = f"""
- **Candidate File**: `{candidate_result['candidate_file']}`
- **Accuracy**: `{m['accuracy']}` (Baseline: `0.9108`)
- **Precision**: `{m['precision']}` (Baseline: `0.8517`)
- **Recall**: `{m['recall']}` (Baseline: `0.8859`)
- **F1 Score**: `{m['f1']}` (Baseline: `0.8685`)
- **Promotion Status**: `MANUAL_APPROVAL_REQUIRED_FOR_PRODUCTION_PROMOTION`
"""

    md_content = f"""# PHISHGUARD Automated Data & Threat Intelligence Pipeline Report

**Generated at**: {manifest['timestamp']}  
**Pipeline Duration**: {pipeline_duration} seconds  
**Production Model**: Unchanged (`src/models/url_random_forest.joblib`)

---

## 1. Threat Intelligence Ingestion
- **Total Local Indicators Loaded**: {ti_result.get('total_indicators', 0):,}
- **Active Feeds**: {", ".join([f"{k} ({v:,})" for k, v in ti_result.get('source_breakdown', {}).items()])}
- **Local DB Location**: `data/threat_intelligence.db`

---

## 2. Dataset Quality & Leakage Audit
- **Audit Status**: `{leakage_result.get('status', 'UNKNOWN')}`
- **Exact Duplicates**: {leakage_result.get('exact_duplicates', 0)}
- **Label Conflicts**: {leakage_result.get('label_conflicts', 0)}
- **Train/Test Overlap**: {leakage_result.get('train_test_overlap', 0)}

---

## 3. Candidate Model Training & Comparison
{candidate_md}

---

## 4. Manual Actions Required
{manual_actions_md}
"""

    with open(report_md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    logger.info(f"Pipeline finished in {pipeline_duration}s. Manifest saved to {manifest_path}, Report to {report_md_path}.")
    return manifest


if __name__ == "__main__":
    run_pipeline()
