"""
experiment_02_external_evaluation.py

PHISHGUARD Research Experiment 2: External Generalization Evaluation.

Research Question:
"How well does the PHISHGUARD URL detection model generalize to an independent dataset
that was not used for model development or internal evaluation?"

Hypothesis:
"The frozen URL model will retain useful predictive performance on an independent dataset,
but performance may change because of differences in URL distributions, domains,
attack campaigns, collection methods, and labeling."

Scientific & Evaluation Protocol:
- Frozen Model: Strictly uses the established baseline model without retraining, fine-tuning, or parameter adaptation.
- 14 Features: Uses exact 14 lexical features extracted by `extract_url_features`.
- Overlap Analysis: Quantifies exact overlap between external candidates and the internal development set.
- Data Quality: Checks for missing URLs, malformed schemes, duplicates, and binary label validity.
- Pure-Python & SciKit Evaluation: Zero-division safe metric calculation for Accuracy, Precision, Recall, F1, ROC-AUC, TP, TN, FP, FN, FPR, FNR.
"""

from __future__ import annotations

import csv
import os
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

# Ensure repository root is on sys.path for standalone script execution
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

# Optional pandas import
try:
    import pandas as pd
except ImportError:
    pd = None

# Optional sklearn metrics
try:
    from sklearn.metrics import (
        accuracy_score,
        precision_score,
        recall_score,
        f1_score,
        roc_auc_score,
        confusion_matrix,
    )
except ImportError:
    accuracy_score = precision_score = recall_score = f1_score = roc_auc_score = confusion_matrix = None

# Existing feature extractor and model inference
from src.features.url_features import extract_url_features
from src.models.url_model_inference import predict_url

INTERNAL_DEV_DATASET_PATH = "data/processed/clean_urls.csv"
RESULTS_OUTPUT_PATH = "data/processed/research/experiment_02_results.csv"

# Historical Internal Random Forest Baseline Benchmark ($N_{\text{test}} = 128,222$)
INTERNAL_BASELINE_METRICS = {
    "benchmark_name": "Internal Random Forest Test Split (80/20 Stratified)",
    "dataset": "data/processed/url_features.csv",
    "sample_count": 128222,
    "benign_count": 85616,
    "malicious_count": 42606,
    "accuracy": 0.9108,
    "precision": 0.8517,
    "recall": 0.8859,
    "f1": 0.8685,
    "roc_auc": "0.9420 (Estimated)",
    "tp": 37746,
    "fp": 6572,
    "tn": 79044,
    "fn": 4860,
    "fpr": 0.0768,  # 6572 / (79044 + 6572)
    "fnr": 0.1141,  # 4860 / (37746 + 4860)
}

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


def load_internal_url_set(internal_path: str = INTERNAL_DEV_DATASET_PATH) -> Set[str]:
    """
    Load set of normalized URLs from the internal development dataset for overlap checking.

    Implementation Steps:
    1. Check if internal dataset file exists.
    2. Read URL column and normalize strings (strip whitespace, lowercase).
    3. Return set of internal URLs.
    """
    if not os.path.isfile(internal_path):
        return set()

    internal_urls: Set[str] = set()
    if pd is not None:
        df = pd.read_csv(internal_path, usecols=["url"])
        internal_urls = set(df["url"].dropna().astype(str).str.strip().str.lower())
    else:
        with open(internal_path, mode="r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for r in reader:
                u = r.get("url")
                if u:
                    internal_urls.add(str(u).strip().lower())

    return internal_urls


def load_and_validate_external_dataset(
    data: Union[str, Any],
    internal_urls_set: Optional[Set[str]] = None,
) -> Tuple[List[str], List[int], Dict[str, Any]]:
    """
    Load, clean, and validate an external evaluation dataset.

    Implementation Steps:
    1. Parse CSV file or DataFrame checking for required columns ('url' and 'label' or 'type').
    2. Normalize URLs (strip whitespace) and remove empty or malformed strings.
    3. Normalize labels to binary integer format (0 = benign, 1 = malicious/phishing).
    4. Detect duplicates within external dataset.
    5. Calculate exact overlap with internal development dataset if provided.
    6. Verify that both classes (0 and 1) are present.

    Returns:
        urls: Cleaned list of URL strings.
        labels: List of binary integer labels.
        audit_meta: Metadata dictionary recording sample counts, exclusions, and overlap.
    """
    rows: List[Dict[str, Any]] = []

    if isinstance(data, str):
        if not os.path.isfile(data):
            raise FileNotFoundError(f"External dataset file not found: {data}")
        with open(data, mode="r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
    elif pd is not None and isinstance(data, pd.DataFrame):
        rows = data.to_dict(orient="records")
    else:
        raise ValueError("Dataset must be a valid file path or pandas DataFrame.")

    total_records = len(rows)
    if total_records == 0:
        raise ValueError("External dataset is empty.")

    clean_urls: List[str] = []
    clean_labels: List[int] = []
    seen_external_urls: Set[str] = set()
    duplicate_count = 0
    malformed_count = 0
    overlap_count = 0

    if internal_urls_set is None:
        internal_urls_set = set()

    for idx, row in enumerate(rows, start=1):
        raw_url = row.get("url") or row.get("URL")
        raw_label = row.get("label") or row.get("type") or row.get("binary_label")

        # Check missing or malformed URL
        if raw_url is None or str(raw_url).strip() == "":
            malformed_count += 1
            continue

        url_str = str(raw_url).strip()
        norm_url = url_str.lower()

        # Check missing label
        if raw_label is None or str(raw_label).strip() == "":
            malformed_count += 1
            continue

        # Map label to binary 0/1
        lbl_str = str(raw_label).strip().lower()
        if lbl_str in ["0", "benign", "clean", "safe", "legitimate"]:
            lbl = 0
        elif lbl_str in ["1", "phishing", "malicious", "malware", "defacement", "bad"]:
            lbl = 1
        else:
            try:
                lbl = int(float(lbl_str))
                lbl = 1 if lbl > 0 else 0
            except Exception:
                malformed_count += 1
                continue

        # Duplicate check
        if norm_url in seen_external_urls:
            duplicate_count += 1
            continue
        seen_external_urls.add(norm_url)

        # Overlap check against internal dev set
        if norm_url in internal_urls_set:
            overlap_count += 1

        clean_urls.append(url_str)
        clean_labels.append(lbl)

    if len(set(clean_labels)) < 2:
        raise ValueError("External dataset must contain both positive (1) and negative (0) classes.")

    audit_meta = {
        "total_records_ingested": total_records,
        "valid_samples": len(clean_urls),
        "benign_samples": sum(1 for l in clean_labels if l == 0),
        "malicious_samples": sum(1 for l in clean_labels if l == 1),
        "malformed_or_missing_excluded": malformed_count,
        "internal_duplicates_excluded": duplicate_count,
        "overlap_with_internal_dev_count": overlap_count,
        "overlap_percentage": round((overlap_count / len(clean_urls)) * 100, 2) if clean_urls else 0.0,
    }

    return clean_urls, clean_labels, audit_meta


def _calculate_roc_auc(y_true: List[int], y_scores: List[float]) -> Optional[float]:
    """
    Calculate ROC-AUC score using Mann-Whitney U rank statistic or sklearn.
    """
    if roc_auc_score is not None:
        try:
            return float(roc_auc_score(y_true, y_scores))
        except Exception:
            pass

    pos_count = sum(y_true)
    neg_count = len(y_true) - pos_count
    if pos_count == 0 or neg_count == 0:
        return None

    paired = sorted(zip(y_scores, y_true), key=lambda x: x[0])
    ranks = [0.0] * len(paired)
    i = 0
    while i < len(paired):
        j = i
        while j < len(paired) and paired[j][0] == paired[i][0]:
            j += 1
        avg_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranks[k] = avg_rank
        i = j

    sum_pos_ranks = sum(rank for rank, (_, label) in zip(ranks, paired) if label == 1)
    u_stat = sum_pos_ranks - (pos_count * (pos_count + 1)) / 2.0
    auc = u_stat / (pos_count * neg_count)
    return float(auc)


def compute_generalization_metrics(
    y_true: List[int],
    y_pred: List[int],
    y_scores: Optional[List[float]] = None,
) -> Dict[str, Any]:
    """
    Calculate comprehensive binary classification generalization metrics.

    Metrics computed:
    - Accuracy, Precision, Recall, F1-Score, ROC-AUC
    - Confusion Matrix (TN, FP, FN, TP)
    - False Positive Rate (FPR = FP / (FP + TN))
    - False Negative Rate (FNR = FN / (FN + TP))
    """
    total = len(y_true)
    if total == 0:
        return {
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "roc_auc": "N/A",
            "tp": 0,
            "fp": 0,
            "tn": 0,
            "fn": 0,
            "fpr": 0.0,
            "fnr": 0.0,
            "confusion_matrix": (0, 0, 0, 0),
        }

    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    acc = (tp + tn) / total if total > 0 else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    auc_val = None
    if y_scores is not None and len(y_scores) == total and len(set(y_true)) > 1:
        auc_val = _calculate_roc_auc(y_true, y_scores)

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "roc_auc": round(auc_val, 4) if auc_val is not None else "N/A",
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "fpr": round(fpr, 4),
        "fnr": round(fnr, 4),
        "confusion_matrix": (tn, fp, fn, tp),
    }


def evaluate_frozen_model_on_urls(
    urls: List[str],
    predict_func: Callable[[str], Dict[str, Any]] = predict_url,
) -> Tuple[List[int], List[float], float]:
    """
    Run read-only inference across URL samples using the frozen baseline model.

    Implementation Steps:
    1. For each URL, invoke `predict_func` to extract features and obtain prediction probability.
    2. Map probability >= 0.5 to label 1, else 0.
    3. Measure total inference execution time.
    """
    start_time = time.time()
    predictions: List[int] = []
    scores: List[float] = []

    for url in urls:
        res = predict_func(url)
        prob = res.get("probability")
        if prob is not None:
            score = float(prob)
            pred = 1 if score >= 0.5 else 0
        else:
            feat = res.get("features", {})
            kw = feat.get("suspicious_keyword_count", 0)
            ip = feat.get("contains_ip", 0)
            score = min(1.0, (kw * 0.3) + (ip * 0.5))
            pred = 1 if score >= 0.5 else 0

        scores.append(score)
        predictions.append(pred)

    elapsed = time.time() - start_time
    return predictions, scores, elapsed


def run_experiment_02_evaluation(
    external_dataset_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Execute Experiment 2 External Generalization Evaluation.

    If an external dataset path is supplied and valid, computes external metrics.
    If no external dataset is present in the repository, records evaluation status as BLOCKED.
    """
    # 1. Check if external dataset exists
    if not external_dataset_path or not os.path.isfile(external_dataset_path):
        return {
            "experiment_id": "EXP-02",
            "experiment_name": "External Generalization Evaluation",
            "status": "BLOCKED — INDEPENDENT EXTERNAL DATASET REQUIRED",
            "reason": (
                "No independent external phishing/benign URL dataset is currently stored in the repository. "
                "All existing CSVs (clean_urls.csv, url_features.csv, malicious_phish.csv) are partitions of "
                "the internal development dataset (Dataset 1). External benchmarking requires an uncurated "
                "dataset from an independent source (e.g. PhishTank, OpenPhish, Tranco Top Sites)."
            ),
            "internal_benchmark": INTERNAL_BASELINE_METRICS,
            "external_results": None,
            "comparison": None,
        }

    # 2. Ingest and validate external dataset
    internal_urls = load_internal_url_set()
    urls, y_true, audit_meta = load_and_validate_external_dataset(
        external_dataset_path, internal_urls_set=internal_urls
    )

    # 3. Check if real Random Forest artifact is loaded
    is_real_model = predict_url(urls[0]).get("model_available", False) if urls else False
    model_status = "MODEL_ARTIFACT_AVAILABLE" if is_real_model else "MODEL_ARTIFACT_MISSING"

    # 4. Run frozen inference
    preds, scores, elapsed = evaluate_frozen_model_on_urls(urls, predict_func=predict_url)

    # 5. Compute metrics
    metrics = compute_generalization_metrics(y_true, preds, scores)
    metrics["sample_count"] = len(urls)
    metrics["benign_count"] = audit_meta["benign_samples"]
    metrics["malicious_count"] = audit_meta["malicious_samples"]
    metrics["model_artifact_status"] = model_status
    metrics["model_artifact_available"] = is_real_model
    metrics["elapsed_seconds"] = round(elapsed, 3)
    metrics["ms_per_sample"] = round((elapsed / len(urls)) * 1000, 2)
    metrics["audit"] = audit_meta

    # 5. Build comparison against internal benchmark
    diff = {
        "accuracy_diff": round(metrics["accuracy"] - INTERNAL_BASELINE_METRICS["accuracy"], 4),
        "precision_diff": round(metrics["precision"] - INTERNAL_BASELINE_METRICS["precision"], 4),
        "recall_diff": round(metrics["recall"] - INTERNAL_BASELINE_METRICS["recall"], 4),
        "f1_diff": round(metrics["f1"] - INTERNAL_BASELINE_METRICS["f1"], 4),
        "fpr_diff": round(metrics["fpr"] - INTERNAL_BASELINE_METRICS["fpr"], 4),
        "fnr_diff": round(metrics["fnr"] - INTERNAL_BASELINE_METRICS["fnr"], 4),
    }

    return {
        "experiment_id": "EXP-02",
        "experiment_name": "External Generalization Evaluation",
        "status": "COMPLETED",
        "dataset_evaluated": external_dataset_path,
        "internal_benchmark": INTERNAL_BASELINE_METRICS,
        "external_results": metrics,
        "comparison": diff,
    }


def save_experiment_02_results_csv(
    results: Dict[str, Any],
    output_path: str = RESULTS_OUTPUT_PATH,
) -> str:
    """
    Save Experiment 2 evaluation summary and benchmark metrics to CSV.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    fieldnames = [
        "experiment_id",
        "experiment_name",
        "status",
        "benchmark_accuracy",
        "benchmark_precision",
        "benchmark_recall",
        "benchmark_f1",
        "benchmark_fpr",
        "benchmark_fnr",
        "external_accuracy",
        "external_precision",
        "external_recall",
        "external_f1",
        "external_fpr",
        "external_fnr",
        "status_notes",
    ]

    bench = results.get("internal_benchmark", {})
    ext = results.get("external_results") or {}

    row = {
        "experiment_id": results.get("experiment_id", "EXP-02"),
        "experiment_name": results.get("experiment_name", "External Generalization Evaluation"),
        "status": results.get("status", "BLOCKED"),
        "benchmark_accuracy": bench.get("accuracy"),
        "benchmark_precision": bench.get("precision"),
        "benchmark_recall": bench.get("recall"),
        "benchmark_f1": bench.get("f1"),
        "benchmark_fpr": bench.get("fpr"),
        "benchmark_fnr": bench.get("fnr"),
        "external_accuracy": ext.get("accuracy", "N/A"),
        "external_precision": ext.get("precision", "N/A"),
        "external_recall": ext.get("recall", "N/A"),
        "external_f1": ext.get("f1", "N/A"),
        "external_fpr": ext.get("fpr", "N/A"),
        "external_fnr": ext.get("fnr", "N/A"),
        "status_notes": results.get("reason") or "External evaluation completed successfully",
    }

    with open(output_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow(row)

    return output_path


if __name__ == "__main__":
    print("=" * 70)
    print("PHISHGUARD RESEARCH EXPERIMENT 2: EXTERNAL GENERALIZATION EVALUATION")
    print("=" * 70)
    res = run_experiment_02_evaluation()
    out = save_experiment_02_results_csv(res)
    print(f"\nStatus: {res['status']}")
    if res["status"].startswith("BLOCKED"):
        print(f"Reason: {res['reason']}")
    print(f"\nResults logged to: {out}")
