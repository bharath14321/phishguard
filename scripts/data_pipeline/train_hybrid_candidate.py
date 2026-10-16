"""
scripts/data_pipeline/train_hybrid_candidate.py

PHISHGUARD Phase 1: Hybrid URL Model Training & Local Threat Intelligence Pipeline.

This script executes:
1. Audit of baseline and threat-intelligence URL feeds.
2. Cross-dataset overlap and deduplication analysis.
3. Feature extraction for genuinely new threat feed indicators.
4. Assembly of candidate training dataset with full source provenance.
5. Training of candidate Random Forest model saved strictly in src/models/candidates/.
6. Clean, leak-free, held-out evaluation comparing Baseline Production Model vs New Candidate Model.
7. Emission of evaluation metrics and candidate verdict.
"""

import csv
import hashlib
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
from sklearn.model_selection import train_test_split

BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.features.url_features import extract_url_features, normalize_url

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s - %(message)s")
logger = logging.getLogger("phishguard.hybrid_trainer")

RAW_DIR = BASE_DIR / "data" / "raw"
PROCESSED_DIR = BASE_DIR / "data" / "processed"
CANDIDATES_DIR = BASE_DIR / "src" / "models" / "candidates"
EVALUATION_DIR = PROCESSED_DIR / "model_evaluation"

PROD_MODEL_PATH = BASE_DIR / "src" / "models" / "url_random_forest.joblib"
BASE_FEATURES_CSV = PROCESSED_DIR / "url_features.csv"
CANDIDATE_FEATURES_CSV = PROCESSED_DIR / "candidate_url_features.csv"

# Canonical 14 features in exact order
FEATURE_COLUMNS = [
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


def file_sha256(path: Path) -> str:
    """Calculate SHA-256 checksum of a file."""
    if not path.exists():
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def audit_raw_feeds() -> Dict[str, Any]:
    """
    Audit all raw URL feeds and the baseline ML dataset.
    """
    logger.info("Auditing raw URL datasets and feeds...")
    audit = {}

    # 1. Baseline: malicious_phish.csv
    mp_path = RAW_DIR / "malicious_phish.csv"
    if mp_path.exists():
        df_mp = pd.read_csv(mp_path)
        audit["malicious_phish"] = {
            "path": str(mp_path),
            "sha256": file_sha256(mp_path),
            "size_bytes": mp_path.stat().st_size,
            "raw_records": len(df_mp),
            "valid_urls": int((df_mp["url"].notnull() & (df_mp["url"].str.strip() != "")).sum()),
            "malformed_count": int((df_mp["url"].isnull() | (df_mp["url"].str.strip() == "")).sum()),
            "duplicates": int(df_mp["url"].duplicated().sum()),
            "label_distribution": df_mp["type"].value_counts().to_dict(),
        }

    # 2. PhishTank: phishtank.csv
    pt_path = RAW_DIR / "phishtank.csv"
    if pt_path.exists():
        pt_rows = 0
        pt_valid = 0
        pt_malformed = 0
        pt_urls = []
        with open(pt_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for r in reader:
                pt_rows += 1
                u = r.get("url", "").strip()
                if u and (u.startswith("http://") or u.startswith("https://")):
                    pt_valid += 1
                    pt_urls.append(u)
                else:
                    pt_malformed += 1
        audit["phishtank"] = {
            "path": str(pt_path),
            "sha256": file_sha256(pt_path),
            "size_bytes": pt_path.stat().st_size,
            "raw_records": pt_rows,
            "valid_urls": pt_valid,
            "malformed_count": pt_malformed,
            "duplicates": pt_valid - len(set(pt_urls)),
            "unique_urls": len(set(pt_urls)),
            "label_distribution": {"phishing": pt_valid},
        }

    # 3. OpenPhish: openphish.txt
    op_path = RAW_DIR / "openphish.txt"
    if op_path.exists():
        op_rows = 0
        op_valid = 0
        op_malformed = 0
        op_urls = []
        with open(op_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                op_rows += 1
                u = line.strip()
                if u and (u.startswith("http://") or u.startswith("https://")):
                    op_valid += 1
                    op_urls.append(u)
                else:
                    op_malformed += 1
        audit["openphish"] = {
            "path": str(op_path),
            "sha256": file_sha256(op_path),
            "size_bytes": op_path.stat().st_size,
            "raw_records": op_rows,
            "valid_urls": op_valid,
            "malformed_count": op_malformed,
            "duplicates": op_valid - len(set(op_urls)),
            "unique_urls": len(set(op_urls)),
            "label_distribution": {"phishing": op_valid},
        }

    # 4. URLhaus: urlhaus.csv
    uh_path = RAW_DIR / "urlhaus.csv"
    if uh_path.exists():
        uh_rows = 0
        uh_valid = 0
        uh_malformed = 0
        uh_urls = []
        with open(uh_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f, skipinitialspace=True)
            for r in reader:
                if not r or not r[0] or r[0].startswith("#"):
                    continue
                uh_rows += 1
                if len(r) >= 3:
                    u = r[2].strip()
                    if u and (u.startswith("http://") or u.startswith("https://")):
                        uh_valid += 1
                        uh_urls.append(u)
                    else:
                        uh_malformed += 1
                else:
                    uh_malformed += 1
        audit["urlhaus"] = {
            "path": str(uh_path),
            "sha256": file_sha256(uh_path),
            "size_bytes": uh_path.stat().st_size,
            "raw_records": uh_rows,
            "valid_urls": uh_valid,
            "malformed_count": uh_malformed,
            "duplicates": uh_valid - len(set(uh_urls)),
            "unique_urls": len(set(uh_urls)),
            "label_distribution": {"malware": uh_valid},
        }

    return audit


def extract_genuinely_new_feed_records(
    existing_normalized_urls: Set[str]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Extract and feature-encode only genuinely new, non-overlapping URL records from threat feeds.
    """
    logger.info("Extracting genuinely new threat feed indicators...")
    seen_in_feeds: Set[str] = set()
    new_records: List[Dict[str, Any]] = []

    stats = {
        "phishtank_raw": 0,
        "phishtank_new": 0,
        "openphish_raw": 0,
        "openphish_new": 0,
        "urlhaus_raw": 0,
        "urlhaus_new": 0,
        "cross_feed_overlap": 0,
        "overlap_with_base": 0,
    }

    # 1. PhishTank
    pt_path = RAW_DIR / "phishtank.csv"
    if pt_path.exists():
        with open(pt_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for r in reader:
                stats["phishtank_raw"] += 1
                raw_u = r.get("url", "").strip()
                if not raw_u:
                    continue
                norm_u = normalize_url(raw_u)
                if norm_u in existing_normalized_urls:
                    stats["overlap_with_base"] += 1
                    continue
                if norm_u in seen_in_feeds:
                    stats["cross_feed_overlap"] += 1
                    continue
                seen_in_feeds.add(norm_u)
                stats["phishtank_new"] += 1

                feats = extract_url_features(raw_u)
                feats["url"] = raw_u
                feats["type"] = "phishing"
                feats["binary_label"] = 1
                feats["multiclass_label"] = 2  # Phishing
                feats["source"] = "phishtank"
                new_records.append(feats)

    # 2. OpenPhish
    op_path = RAW_DIR / "openphish.txt"
    if op_path.exists():
        with open(op_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                stats["openphish_raw"] += 1
                raw_u = line.strip()
                if not raw_u or not (raw_u.startswith("http://") or raw_u.startswith("https://")):
                    continue
                norm_u = normalize_url(raw_u)
                if norm_u in existing_normalized_urls:
                    stats["overlap_with_base"] += 1
                    continue
                if norm_u in seen_in_feeds:
                    stats["cross_feed_overlap"] += 1
                    continue
                seen_in_feeds.add(norm_u)
                stats["openphish_new"] += 1

                feats = extract_url_features(raw_u)
                feats["url"] = raw_u
                feats["type"] = "phishing"
                feats["binary_label"] = 1
                feats["multiclass_label"] = 2
                feats["source"] = "openphish"
                new_records.append(feats)

    # 3. URLhaus
    uh_path = RAW_DIR / "urlhaus.csv"
    if uh_path.exists():
        with open(uh_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f, skipinitialspace=True)
            for r in reader:
                if not r or not r[0] or r[0].startswith("#"):
                    continue
                stats["urlhaus_raw"] += 1
                if len(r) >= 3:
                    raw_u = r[2].strip()
                    if not raw_u or not (raw_u.startswith("http://") or raw_u.startswith("https://")):
                        continue
                    norm_u = normalize_url(raw_u)
                    if norm_u in existing_normalized_urls:
                        stats["overlap_with_base"] += 1
                        continue
                    if norm_u in seen_in_feeds:
                        stats["cross_feed_overlap"] += 1
                        continue
                    seen_in_feeds.add(norm_u)
                    stats["urlhaus_new"] += 1

                    feats = extract_url_features(raw_u)
                    feats["url"] = raw_u
                    feats["type"] = "malware"
                    feats["binary_label"] = 1
                    feats["multiclass_label"] = 3  # Malware
                    feats["source"] = "urlhaus"
                    new_records.append(feats)

    logger.info(f"Extracted {len(new_records):,} genuinely new threat feed feature records.")
    return new_records, stats


def build_and_evaluate_hybrid_candidate(random_seed: int = 42) -> Dict[str, Any]:
    """
    Complete orchestration:
    1. Load baseline feature dataset.
    2. Split baseline into 80% train and 20% test (the clean held-out evaluation set).
    3. Augment the 80% train split with genuinely new threat-intelligence indicators.
    4. Train candidate Random Forest model on the augmented training set.
    5. Evaluate both Production Model and Candidate Model on the SAME clean held-out test set.
    6. Generate comprehensive comparative report.
    """
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    CANDIDATES_DIR.mkdir(parents=True, exist_ok=True)
    EVALUATION_DIR.mkdir(parents=True, exist_ok=True)

    # Step 1: Audit raw feeds
    audit_results = audit_raw_feeds()

    # Step 2: Load baseline features
    logger.info(f"Loading baseline feature dataset from {BASE_FEATURES_CSV}...")
    df_base = pd.read_csv(BASE_FEATURES_CSV)
    logger.info(f"Loaded {len(df_base):,} baseline feature records.")

    # Mark source provenance for base dataset
    if "source" not in df_base.columns:
        df_base["source"] = "malicious_phish"

    # Step 3: Clean train/test split on baseline data (20% held-out test set)
    # Stratify by binary_label to preserve class distribution
    X_base = df_base[FEATURE_COLUMNS]
    y_base = df_base["binary_label"]

    X_base_train, X_heldout_test, y_base_train, y_heldout_test = train_test_split(
        X_base,
        y_base,
        test_size=0.20,
        random_state=random_seed,
        stratify=y_base,
    )

    df_base_train = df_base.iloc[X_base_train.index].copy()
    df_heldout_test = df_base.iloc[X_heldout_test.index].copy()

    logger.info(f"Baseline train split: {len(df_base_train):,} samples. Clean held-out test set: {len(df_heldout_test):,} samples.")

    # Step 4: Extract genuinely new threat feed indicators
    # Base set of normalized URLs from malicious_phish / clean_urls
    base_norm_urls = set(df_base["url"].astype(str).map(normalize_url))
    new_feed_records, feed_stats = extract_genuinely_new_feed_records(base_norm_urls)

    df_new_feeds = pd.DataFrame(new_feed_records)

    # Step 5: Construct Candidate Training Set (Base Train + New Feeds)
    df_candidate_train = pd.concat([df_base_train, df_new_feeds], ignore_index=True)

    # Save Candidate Dataset to separate CSV without overwriting base
    logger.info(f"Saving candidate feature dataset to {CANDIDATE_FEATURES_CSV}...")
    df_candidate_all = pd.concat([df_base, df_new_feeds], ignore_index=True)
    df_candidate_all.to_csv(CANDIDATE_FEATURES_CSV, index=False)

    # Document Class Distribution
    train_benign = int((df_candidate_train["binary_label"] == 0).sum())
    train_malicious = int((df_candidate_train["binary_label"] == 1).sum())
    total_train = len(df_candidate_train)

    logger.info(f"Candidate Training Set Size: {total_train:,} (Benign: {train_benign:,}, Malicious: {train_malicious:,})")
    source_distribution = df_candidate_train["source"].value_counts().to_dict()

    # Step 6: Train Candidate Random Forest Model
    logger.info("Training Candidate Random Forest model on augmented dataset...")
    X_train_cand = df_candidate_train[FEATURE_COLUMNS]
    y_train_cand = df_candidate_train["binary_label"]

    t0 = time.time()
    candidate_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=2,
        class_weight="balanced",
        random_state=random_seed,
        n_jobs=-1,
    )
    candidate_model.fit(X_train_cand, y_train_cand)
    train_duration = time.time() - t0
    logger.info(f"Candidate model trained successfully in {train_duration:.2f}s.")

    # Save candidate model artifact
    candidate_model_filename = f"candidate_hybrid_rf_{timestamp_str}.joblib"
    candidate_model_path = CANDIDATES_DIR / candidate_model_filename
    joblib.dump(candidate_model, candidate_model_path)
    cand_sha256 = file_sha256(candidate_model_path)
    cand_size = candidate_model_path.stat().st_size

    logger.info(f"Candidate model saved to {candidate_model_path} ({cand_size:,} bytes, SHA-256: {cand_sha256}).")

    # Step 7: Fair Evaluation on Clean Held-out Test Set (Unseen by both models)
    logger.info(f"Loading production model from {PROD_MODEL_PATH} for baseline comparison...")
    prod_model = joblib.load(PROD_MODEL_PATH)

    X_test = df_heldout_test[FEATURE_COLUMNS]
    y_test = df_heldout_test["binary_label"]

    # Production Model Evaluation
    y_pred_prod = prod_model.predict(X_test)
    prod_acc = float(accuracy_score(y_test, y_pred_prod))
    prod_prec = float(precision_score(y_test, y_pred_prod, zero_division=0))
    prod_rec = float(recall_score(y_test, y_pred_prod, zero_division=0))
    prod_f1 = float(f1_score(y_test, y_pred_prod, zero_division=0))
    cm_prod = confusion_matrix(y_test, y_pred_prod)
    tn_p, fp_p, fn_p, tp_p = [int(v) for v in cm_prod.ravel()]

    # Candidate Model Evaluation
    y_pred_cand = candidate_model.predict(X_test)
    cand_acc = float(accuracy_score(y_test, y_pred_cand))
    cand_prec = float(precision_score(y_test, y_pred_cand, zero_division=0))
    cand_rec = float(recall_score(y_test, y_pred_cand, zero_division=0))
    cand_f1 = float(f1_score(y_test, y_pred_cand, zero_division=0))
    cm_cand = confusion_matrix(y_test, y_pred_cand)
    tn_c, fp_c, fn_c, tp_c = [int(v) for v in cm_cand.ravel()]

    # Differences (Candidate - Production)
    diff_acc = cand_acc - prod_acc
    diff_prec = cand_prec - prod_prec
    diff_rec = cand_rec - prod_rec
    diff_f1 = cand_f1 - prod_f1

    # Verdict determination
    if diff_f1 > 0.005 and diff_prec >= -0.005:
        verdict = "BETTER"
    elif diff_f1 < -0.005 or diff_prec < -0.01:
        verdict = "WORSE"
    elif abs(diff_f1) <= 0.005 and abs(diff_prec) <= 0.005:
        verdict = "SIMILAR"
    else:
        verdict = "INCONCLUSIVE"

    evaluation_report = {
        "timestamp": timestamp_str,
        "evaluation_protocol": "Clean 20% Held-Out Test Set from malicious_phish.csv (128,222 samples)",
        "audit": audit_results,
        "feed_extraction_stats": feed_stats,
        "genuinely_new_records_count": len(new_feed_records),
        "candidate_training_size": total_train,
        "candidate_class_distribution": {
            "benign": train_benign,
            "malicious": train_malicious,
            "benign_percentage": round(train_benign / total_train * 100, 2),
            "malicious_percentage": round(train_malicious / total_train * 100, 2),
        },
        "candidate_source_provenance": source_distribution,
        "candidate_model": {
            "path": str(candidate_model_path),
            "filename": candidate_model_filename,
            "sha256": cand_sha256,
            "size_bytes": cand_size,
            "hyperparameters": {
                "n_estimators": 200,
                "max_depth": None,
                "min_samples_split": 2,
                "class_weight": "balanced",
                "random_state": random_seed,
            },
            "training_duration_seconds": round(train_duration, 2),
        },
        "production_model_metrics": {
            "accuracy": round(prod_acc, 4),
            "precision": round(prod_prec, 4),
            "recall": round(prod_rec, 4),
            "f1": round(prod_f1, 4),
            "confusion_matrix": {"tn": tn_p, "fp": fp_p, "fn": fn_p, "tp": tp_p},
            "false_positives": fp_p,
            "false_negatives": fn_p,
        },
        "candidate_model_metrics": {
            "accuracy": round(cand_acc, 4),
            "precision": round(cand_prec, 4),
            "recall": round(cand_rec, 4),
            "f1": round(cand_f1, 4),
            "confusion_matrix": {"tn": tn_c, "fp": fp_c, "fn": fn_c, "tp": tp_c},
            "false_positives": fp_c,
            "false_negatives": fn_c,
        },
        "metric_differences": {
            "accuracy": round(diff_acc, 4),
            "precision": round(diff_prec, 4),
            "recall": round(diff_rec, 4),
            "f1": round(diff_f1, 4),
            "false_positives_diff": fp_c - fp_p,
            "false_negatives_diff": fn_c - fn_p,
        },
        "candidate_verdict": verdict,
    }

    report_path = EVALUATION_DIR / f"candidate_hybrid_evaluation_{timestamp_str}.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(evaluation_report, f, indent=2)

    logger.info(f"Evaluation report written to {report_path}")
    return evaluation_report


if __name__ == "__main__":
    report = build_and_evaluate_hybrid_candidate()
    print(json.dumps(report, indent=2))
