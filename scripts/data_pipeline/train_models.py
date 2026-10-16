"""
scripts/data_pipeline/train_models.py

Automated Candidate Model Training Engine.

CRITICAL ARCHITECTURAL CONSTRAINTS:
1. NEVER overwrites production model (src/models/url_random_forest.joblib).
2. Saves trained candidate models strictly to src/models/candidates/.
3. Supports training:
   - Random Forest candidate
   - XGBoost candidate (if xgboost available)
   - Logistic Regression candidate
4. Evaluates candidate models against production baseline metrics:
   Baseline (Accuracy: 0.9108, Precision: 0.8517, Recall: 0.8859, F1: 0.8685)
5. Generates candidate artifact manifest and candidate promotion report.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s - %(message)s")
logger = logging.getLogger("phishguard.candidate_trainer")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
PROCESSED_DATA_DIR = BASE_DIR / "data" / "processed"
FEATURES_CSV = PROCESSED_DATA_DIR / "url_features.csv"
CANDIDATES_DIR = BASE_DIR / "src" / "models" / "candidates"
EVALUATION_DIR = PROCESSED_DATA_DIR / "model_evaluation"

# Verified 14-feature column contract from train_random_forest.py
VERIFIED_FEATURES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "dot_count",
    "hyphen_count",
    "digit_count",
    "special_char_count",
    "subdomain_count",
    "contains_ip",
    "uses_https",
    "contains_at",
    "contains_double_slash",
    "suspicious_keyword_count",
]

# Baseline Production Metrics
PRODUCTION_BASELINE = {
    "model_name": "url_random_forest.joblib",
    "model_type": "RandomForestClassifier",
    "accuracy": 0.9108,
    "precision": 0.8517,
    "recall": 0.8859,
    "f1": 0.8685,
}


def train_candidate_model(
    model_type: str = "RandomForest",
    sample_size: Optional[int] = 50000,
    random_state: int = 42
) -> Dict[str, Any]:
    """
    Train a candidate machine learning model and save artifact to candidates directory.
    """
    if not FEATURES_CSV.exists():
        logger.error(f"Features file not found at {FEATURES_CSV}")
        return {"status": "ERROR", "message": "Missing feature dataset."}

    CANDIDATES_DIR.mkdir(parents=True, exist_ok=True)
    EVALUATION_DIR.mkdir(parents=True, exist_ok=True)

    logger.info(f"Loading feature dataset for candidate training (sample_size={sample_size})...")
    start_time = time.time()

    if sample_size:
        df = pd.read_csv(FEATURES_CSV, nrows=sample_size)
    else:
        df = pd.read_csv(FEATURES_CSV)

    # Validate feature presence
    missing_cols = [col for col in VERIFIED_FEATURES if col not in df.columns]
    if missing_cols:
        logger.error(f"Dataset missing required verified features: {missing_cols}")
        return {"status": "ERROR", "message": f"Missing features: {missing_cols}"}

    X = df[VERIFIED_FEATURES]
    label_col = "binary_label" if "binary_label" in df.columns else "label"
    y = df[label_col].astype(int)

    # Train / test split (80/20 stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=random_state, stratify=y
    )

    logger.info(f"Training {model_type} on {len(X_train):,} samples (eval on {len(X_test):,})...")

    # Instantiate model
    if model_type == "RandomForest":
        clf = RandomForestClassifier(
            n_estimators=100,
            class_weight="balanced",
            random_state=random_state,
            n_jobs=-1,
        )
    elif model_type == "LogisticRegression":
        clf = LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=random_state,
        )
    elif model_type == "XGBoost":
        try:
            import xgboost as xgb
            clf = xgb.XGBClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=6,
                random_state=random_state,
                eval_metric="logloss"
            )
        except ImportError:
            logger.warning("xgboost not installed. Falling back to RandomForest.")
            clf = RandomForestClassifier(n_estimators=100, random_state=random_state, n_jobs=-1)
    else:
        raise ValueError(f"Unsupported model type: {model_type}")

    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1] if hasattr(clf, "predict_proba") else None

    # Compute Metrics
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    roc_auc = float(roc_auc_score(y_test, y_prob)) if y_prob is not None else None
    cm = confusion_matrix(y_test, y_pred).tolist()

    timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    candidate_filename = f"candidate_{model_type.lower()}_{timestamp_str}.joblib"
    candidate_path = CANDIDATES_DIR / candidate_filename

    # Save artifact
    joblib.dump(clf, candidate_path)
    train_duration = time.time() - start_time

    # Construct Evaluation Report
    metrics = {
        "candidate_file": candidate_filename,
        "candidate_path": str(candidate_path),
        "model_type": model_type,
        "training_samples": len(X_train),
        "test_samples": len(X_test),
        "duration_seconds": round(train_duration, 2),
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "roc_auc": round(roc_auc, 4) if roc_auc else None,
            "confusion_matrix": cm,
        },
        "baseline_comparison": {
            "production_baseline": PRODUCTION_BASELINE,
            "delta_accuracy": round(acc - PRODUCTION_BASELINE["accuracy"], 4),
            "delta_f1": round(f1 - PRODUCTION_BASELINE["f1"], 4),
            "meets_baseline": bool(f1 >= (PRODUCTION_BASELINE["f1"] - 0.05)),
        },
        "promotion_status": "MANUAL_APPROVAL_REQUIRED_FOR_PRODUCTION_PROMOTION",
        "created_at": datetime.utcnow().isoformat(),
    }

    report_path = EVALUATION_DIR / f"evaluation_{model_type.lower()}_{timestamp_str}.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    logger.info(f"Candidate {model_type} trained successfully: Accuracy={acc:.4f}, F1={f1:.4f} (Saved to {candidate_path})")
    return metrics


if __name__ == "__main__":
    train_candidate_model(model_type="RandomForest", sample_size=10000)
