"""
experiment_03_adversarial_robustness.py

PHISHGUARD Research Experiment 3: Adversarial URL Robustness Evaluation.

Research Question:
"How robust is the PHISHGUARD URL detection model to adversarial URL transformations
that preserve the underlying destination or semantic intent?"

Hypothesis:
"The frozen lexical URL model will be sensitive to some transformations because its prediction
depends on structural and lexical URL features."

Scientific & Security Controls:
- 100% Offline: Operates strictly on in-memory string manipulations and frozen model inference.
- Zero Network Requests: No socket connections, no HTTP calls, no DNS lookups.
- Paired Evaluation: Every transformed sample is mapped to its original sample ID.
- Frozen Model: Strictly uses `src.models.url_model_inference.predict_url` without retraining.
- Deterministic: Fixed random seed (42) for dataset sampling and deterministic transformation logic.
"""

from __future__ import annotations

import csv
import os
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse, urlunparse, quote, parse_qsl, urlencode

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
        confusion_matrix,
    )
except ImportError:
    accuracy_score = precision_score = recall_score = f1_score = confusion_matrix = None

# Existing frozen inference loader
from src.models.url_model_inference import predict_url

DEFAULT_DATASET_PATH = "data/processed/clean_urls.csv"
FALLBACK_DATASET_PATH = "data/raw/malicious_phish.csv"
SUMMARY_OUTPUT_PATH = "data/processed/research/experiment_03_results.csv"
SAMPLE_OUTPUT_PATH = "data/processed/research/experiment_03_sample_results.csv"


# ---------------------------------------------------------------------------
# 1. DETERMINISTIC ADVERSARIAL TRANSFORMATIONS (T1 - T7)
# ---------------------------------------------------------------------------

def transform_added_subdomain(url: str) -> str:
    """
    T1 — added_subdomain: Prepend a controlled single subdomain level (e.g. 'auth.').

    Implementation Steps:
    1. Parse URL structure into components.
    2. Add 'auth.' prefix to netloc/hostname if not already present.
    3. Reconstruct and return transformed URL.
    """
    url_to_parse = url if "://" in url else f"http://{url}"
    parsed = urlparse(url_to_parse)
    netloc = parsed.netloc or parsed.path.split("/")[0]
    
    # If already begins with auth., use login.
    if netloc.startswith("auth."):
        new_netloc = f"login.{netloc}"
    else:
        new_netloc = f"auth.{netloc}"

    new_parsed = parsed._replace(netloc=new_netloc)
    res = urlunparse(new_parsed)
    return res if "://" in url else res.replace("http://", "", 1)


def transform_deeper_subdomain(url: str) -> str:
    """
    T2 — deeper_subdomain: Prepend two controlled subdomain levels (e.g. 'portal.secure.').

    Implementation Steps:
    1. Parse URL structure into components.
    2. Add 'portal.secure.' prefix to netloc/hostname.
    3. Reconstruct and return transformed URL.
    """
    url_to_parse = url if "://" in url else f"http://{url}"
    parsed = urlparse(url_to_parse)
    netloc = parsed.netloc or parsed.path.split("/")[0]

    new_netloc = f"portal.secure.{netloc}"
    new_parsed = parsed._replace(netloc=new_netloc)
    res = urlunparse(new_parsed)
    return res if "://" in url else res.replace("http://", "", 1)


def transform_added_path(url: str) -> str:
    """
    T3 — added_path: Append a controlled path component (e.g. '/verify/account').

    Implementation Steps:
    1. Parse URL structure.
    2. Append '/verify/account' to the path segment.
    3. Reconstruct and return transformed URL.
    """
    url_to_parse = url if "://" in url else f"http://{url}"
    parsed = urlparse(url_to_parse)
    path = parsed.path.rstrip("/")
    new_path = f"{path}/verify/account"

    new_parsed = parsed._replace(path=new_path)
    res = urlunparse(new_parsed)
    return res if "://" in url else res.replace("http://", "", 1)


def transform_added_query(url: str) -> str:
    """
    T4 — added_query: Append a controlled query parameter (e.g. '?session_id=987654321').

    Implementation Steps:
    1. Parse URL structure and existing query string.
    2. Append 'session_id=987654321&auth=true'.
    3. Reconstruct and return transformed URL.
    """
    url_to_parse = url if "://" in url else f"http://{url}"
    parsed = urlparse(url_to_parse)
    existing_query = parsed.query
    new_param = "session_id=987654321&auth=true"
    new_query = f"{existing_query}&{new_param}" if existing_query else new_param

    new_parsed = parsed._replace(query=new_query)
    res = urlunparse(new_parsed)
    return res if "://" in url else res.replace("http://", "", 1)


def transform_added_fragment(url: str) -> str:
    """
    T5 — added_fragment: Append a controlled fragment identifier (e.g. '#security-notice').

    Implementation Steps:
    1. Parse URL structure.
    2. Set fragment to 'security-notice'.
    3. Reconstruct and return transformed URL.
    """
    url_to_parse = url if "://" in url else f"http://{url}"
    parsed = urlparse(url_to_parse)
    new_parsed = parsed._replace(fragment="security-notice")
    res = urlunparse(new_parsed)
    return res if "://" in url else res.replace("http://", "", 1)


def transform_case_changed(url: str) -> str:
    """
    T6 — case_changed: Alter character casing where valid (scheme and path).

    Implementation Steps:
    1. Parse URL structure.
    2. Convert scheme to uppercase 'HTTP://' and capitalize path segments.
    3. Reconstruct and return transformed URL.
    """
    url_to_parse = url if "://" in url else f"http://{url}"
    parsed = urlparse(url_to_parse)
    scheme = parsed.scheme.upper()
    path_parts = parsed.path.split("/")
    new_path = "/".join(p.capitalize() for p in path_parts)

    new_parsed = parsed._replace(scheme=scheme, path=new_path)
    res = urlunparse(new_parsed)
    return res if "://" in url else res.replace("HTTP://", "", 1)


def transform_encoded_path(url: str) -> str:
    """
    T7 — encoded_path: Apply standard percent-encoding to eligible path characters.

    Implementation Steps:
    1. Parse URL structure.
    2. Apply percent-encoding to path characters using `urllib.parse.quote`.
    3. Reconstruct and return transformed URL.
    """
    url_to_parse = url if "://" in url else f"http://{url}"
    parsed = urlparse(url_to_parse)
    if not parsed.path or parsed.path == "/":
        path_to_encode = "/index.html"
    else:
        path_to_encode = parsed.path

    encoded_path = quote(path_to_encode, safe="/")
    if encoded_path == path_to_encode:
        # Force encode standard characters (e.g. '.' -> '%2E', '-' -> '%2D')
        encoded_path = path_to_encode.replace(".", "%2E").replace("-", "%2D")

    new_parsed = parsed._replace(path=encoded_path)
    res = urlunparse(new_parsed)
    return res if "://" in url else res.replace("http://", "", 1)


TRANSFORMATIONS: Dict[str, Callable[[str], str]] = {
    "added_subdomain": transform_added_subdomain,
    "deeper_subdomain": transform_deeper_subdomain,
    "added_path": transform_added_path,
    "added_query": transform_added_query,
    "added_fragment": transform_added_fragment,
    "case_changed": transform_case_changed,
    "encoded_path": transform_encoded_path,
}


# ---------------------------------------------------------------------------
# 2. DATASET SAMPLING & METRIC UTILITIES
# ---------------------------------------------------------------------------

def load_adversarial_dataset(
    dataset_path: Optional[str] = None,
    sample_size: int = 200,
    random_state: int = 42,
) -> Tuple[List[Dict[str, Any]], int, int]:
    """
    Load a stratified balanced evaluation sample from the benchmark dataset.

    Implementation Steps:
    1. Resolve dataset path.
    2. Sample equal number of benign (0) and malicious (1) records.
    3. Return structured sample list with assigned integer `sample_id`.
    """
    resolved_path = dataset_path
    if not resolved_path or not os.path.isfile(resolved_path):
        if os.path.isfile(DEFAULT_DATASET_PATH):
            resolved_path = DEFAULT_DATASET_PATH
        elif os.path.isfile(FALLBACK_DATASET_PATH):
            resolved_path = FALLBACK_DATASET_PATH
        else:
            raise FileNotFoundError(f"Dataset not found at {dataset_path or DEFAULT_DATASET_PATH}")

    samples: List[Dict[str, Any]] = []

    if pd is not None:
        df = pd.read_csv(resolved_path)
        url_col = "url" if "url" in df.columns else df.columns[0]
        label_col = "type" if "type" in df.columns else ("label" if "label" in df.columns else "binary_label")

        if label_col == "type":
            df["binary_target"] = df["type"].astype(str).str.lower().apply(
                lambda t: 0 if t in ["benign", "0", "clean"] else 1
            )
        else:
            df["binary_target"] = df[label_col].astype(int)

        pos_df = df[df["binary_target"] == 1]
        neg_df = df[df["binary_target"] == 0]

        half = sample_size // 2
        sampled_pos = pos_df.sample(n=min(half, len(pos_df)), random_state=random_state)
        sampled_neg = neg_df.sample(n=min(sample_size - len(sampled_pos), len(neg_df)), random_state=random_state)
        sampled_df = pd.concat([sampled_pos, sampled_neg]).sample(frac=1.0, random_state=random_state)

        for idx, row in enumerate(sampled_df.to_dict(orient="records"), start=1):
            samples.append({
                "sample_id": idx,
                "url": str(row[url_col]).strip(),
                "label": int(row["binary_target"]),
            })
    else:
        # Fallback pure-Python CSV reader
        benign_rows: List[str] = []
        malicious_rows: List[str] = []
        with open(resolved_path, mode="r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for r in reader:
                u = r.get("url") or r.get("URL")
                lbl_raw = r.get("type") or r.get("label") or r.get("binary_label")
                if u and lbl_raw is not None:
                    lbl = 0 if str(lbl_raw).lower() in ["benign", "0", "clean"] else 1
                    if lbl == 0:
                        benign_rows.append(str(u).strip())
                    else:
                        malicious_rows.append(str(u).strip())

        half = sample_size // 2
        b_sample = benign_rows[:half]
        m_sample = malicious_rows[:half]
        idx = 1
        for u in b_sample:
            samples.append({"sample_id": idx, "url": u, "label": 0})
            idx += 1
        for u in m_sample:
            samples.append({"sample_id": idx, "url": u, "label": 1})
            idx += 1

    benign_count = sum(1 for s in samples if s["label"] == 0)
    malicious_count = sum(1 for s in samples if s["label"] == 1)
    return samples, benign_count, malicious_count


def _compute_basic_metrics(y_true: List[int], y_pred: List[int]) -> Dict[str, float]:
    """
    Compute basic classification metrics with zero-division safety.
    """
    total = len(y_true)
    if total == 0:
        return {"accuracy": 0.0, "precision": 0.0, "recall": 0.0, "f1": 0.0}

    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    acc = (tp + tn) / total if total > 0 else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
    }


# ---------------------------------------------------------------------------
# 3. PAIRED ADVERSARIAL EVALUATION ENGINE
# ---------------------------------------------------------------------------

def evaluate_adversarial_robustness(
    samples: List[Dict[str, Any]],
    predict_func: Callable[[str], Dict[str, Any]] = predict_url,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Execute paired adversarial evaluation across all 7 transformations.

    Implementation Steps:
    1. Run frozen model prediction on all original URLs to establish baseline predictions and probabilities.
    2. For each transformation T1..T7, apply string transformation and obtain modified predictions.
    3. Calculate:
       - Transformed accuracy, precision, recall, F1
       - Prediction flip count and flip rate
       - Malicious evasion rate (Orig Correct Malicious -> Predicted Benign)
       - Benign false-alarm rate (Orig Correct Benign -> Predicted Malicious)
       - Mean probability change
    4. Compile per-sample results and per-transformation summary dictionaries.
    """
    # Step 1: Baseline inference on original samples
    orig_results: Dict[int, Dict[str, Any]] = {}
    for s in samples:
        sid = s["sample_id"]
        res = predict_func(s["url"])
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

        orig_results[sid] = {
            "prediction": pred,
            "probability": score,
            "is_correct": pred == s["label"],
        }

    y_true_orig = [s["label"] for s in samples]
    y_pred_orig = [orig_results[s["sample_id"]]["prediction"] for s in samples]
    orig_metrics = _compute_basic_metrics(y_true_orig, y_pred_orig)

    # Step 2: Per-transformation paired evaluation
    sample_records: List[Dict[str, Any]] = []
    transformation_summaries: Dict[str, Dict[str, Any]] = {}

    for t_name, t_func in TRANSFORMATIONS.items():
        t_y_true: List[int] = []
        t_y_pred: List[int] = []
        flips = 0
        mal_to_ben = 0
        mal_to_mal = 0
        ben_to_ben = 0
        ben_to_mal = 0
        prob_changes: List[float] = []

        orig_correct_mal_count = 0
        orig_correct_ben_count = 0

        for s in samples:
            sid = s["sample_id"]
            orig_url = s["url"]
            true_label = s["label"]
            orig_pred = orig_results[sid]["prediction"]
            orig_prob = orig_results[sid]["probability"]
            orig_correct = orig_results[sid]["is_correct"]

            if true_label == 1 and orig_correct:
                orig_correct_mal_count += 1
            if true_label == 0 and orig_correct:
                orig_correct_ben_count += 1

            # Apply deterministic transformation
            trans_url = t_func(orig_url)

            # Frozen inference on transformed string
            t_res = predict_func(trans_url)
            t_prob_raw = t_res.get("probability")
            if t_prob_raw is not None:
                t_prob = float(t_prob_raw)
                t_pred = 1 if t_prob >= 0.5 else 0
            else:
                feat = t_res.get("features", {})
                kw = feat.get("suspicious_keyword_count", 0)
                ip = feat.get("contains_ip", 0)
                t_prob = min(1.0, (kw * 0.3) + (ip * 0.5))
                t_pred = 1 if t_prob >= 0.5 else 0

            t_y_true.append(true_label)
            t_y_pred.append(t_pred)

            pred_changed = orig_pred != t_pred
            if pred_changed:
                flips += 1

            # Directional tracking
            is_mal_evasion = False
            is_ben_false_alarm = False

            if true_label == 1:
                if orig_correct and t_pred == 0:
                    mal_to_ben += 1
                    is_mal_evasion = True
                elif t_pred == 1:
                    mal_to_mal += 1
            elif true_label == 0:
                if orig_correct and t_pred == 1:
                    ben_to_mal += 1
                    is_ben_false_alarm = True
                elif t_pred == 0:
                    ben_to_ben += 1

            delta_prob = t_prob - orig_prob
            prob_changes.append(delta_prob)

            # Per-sample traceability record
            sample_records.append({
                "sample_id": sid,
                "original_url": orig_url,
                "transformation": t_name,
                "transformed_url": trans_url,
                "true_label": true_label,
                "original_prediction": orig_pred,
                "transformed_prediction": t_pred,
                "original_probability": round(orig_prob, 4),
                "transformed_probability": round(t_prob, 4),
                "probability_change": round(delta_prob, 4),
                "prediction_changed": pred_changed,
                "malicious_evasion": is_mal_evasion,
                "benign_false_alarm": is_ben_false_alarm,
            })

        t_metrics = _compute_basic_metrics(t_y_true, t_y_pred)
        evasion_rate = (mal_to_ben / orig_correct_mal_count) if orig_correct_mal_count > 0 else 0.0
        false_alarm_rate = (ben_to_mal / orig_correct_ben_count) if orig_correct_ben_count > 0 else 0.0
        mean_prob_change = sum(prob_changes) / len(prob_changes) if prob_changes else 0.0
        flip_rate = flips / len(samples) if samples else 0.0

        transformation_summaries[t_name] = {
            "transformation": t_name,
            "sample_count": len(samples),
            "original_accuracy": orig_metrics["accuracy"],
            "transformed_accuracy": t_metrics["accuracy"],
            "original_f1": orig_metrics["f1"],
            "transformed_f1": t_metrics["f1"],
            "prediction_flips": flips,
            "flip_rate": round(flip_rate, 4),
            "malicious_to_benign_evasion_count": mal_to_ben,
            "malicious_to_malicious_count": mal_to_mal,
            "benign_to_benign_count": ben_to_ben,
            "benign_to_malicious_count": ben_to_mal,
            "evasion_rate": round(evasion_rate, 4),
            "false_alarm_rate": round(false_alarm_rate, 4),
            "mean_probability_change": round(mean_prob_change, 4),
        }

    # Check if real Random Forest artifact is loaded
    is_real_model = predict_func(samples[0]["url"]).get("model_available", False) if samples else False
    model_status = "MODEL_ARTIFACT_AVAILABLE" if is_real_model else "MODEL_ARTIFACT_MISSING"

    overall_results = {
        "sample_count": len(samples),
        "benign_samples": sum(1 for s in samples if s["label"] == 0),
        "malicious_samples": sum(1 for s in samples if s["label"] == 1),
        "model_artifact_status": model_status,
        "model_artifact_available": is_real_model,
        "original_metrics": orig_metrics,
        "transformations": transformation_summaries,
    }

    return overall_results, sample_records


# ---------------------------------------------------------------------------
# 4. EXECUTION & PERSISTENCE
# ---------------------------------------------------------------------------

def run_experiment_03(
    dataset_path: Optional[str] = None,
    sample_size: int = 200,
    random_state: int = 42,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Main runner for Experiment 3 Adversarial Evaluation.
    """
    samples, b_cnt, m_cnt = load_adversarial_dataset(
        dataset_path=dataset_path,
        sample_size=sample_size,
        random_state=random_state,
    )
    results, sample_records = evaluate_adversarial_robustness(samples)
    return results, sample_records


def save_experiment_03_results(
    results: Dict[str, Any],
    sample_records: List[Dict[str, Any]],
    summary_path: str = SUMMARY_OUTPUT_PATH,
    sample_path: str = SAMPLE_OUTPUT_PATH,
) -> Tuple[str, str]:
    """
    Save both summary results and per-sample traceability files to CSV.
    """
    os.makedirs(os.path.dirname(summary_path), exist_ok=True)
    os.makedirs(os.path.dirname(sample_path), exist_ok=True)

    # 1. Summary CSV
    sum_fieldnames = [
        "transformation",
        "sample_count",
        "original_accuracy",
        "transformed_accuracy",
        "original_f1",
        "transformed_f1",
        "prediction_flips",
        "flip_rate",
        "malicious_to_benign_evasion_count",
        "malicious_to_malicious_count",
        "benign_to_benign_count",
        "benign_to_malicious_count",
        "evasion_rate",
        "false_alarm_rate",
        "mean_probability_change",
    ]

    with open(summary_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=sum_fieldnames)
        writer.writeheader()
        for t_name, data in results["transformations"].items():
            writer.writerow(data)

    # 2. Sample Traceability CSV
    sample_fieldnames = [
        "sample_id",
        "original_url",
        "transformation",
        "transformed_url",
        "true_label",
        "original_prediction",
        "transformed_prediction",
        "original_probability",
        "transformed_probability",
        "probability_change",
        "prediction_changed",
        "malicious_evasion",
        "benign_false_alarm",
    ]

    with open(sample_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=sample_fieldnames)
        writer.writeheader()
        for r in sample_records:
            writer.writerow(r)

    return summary_path, sample_path


if __name__ == "__main__":
    print("=" * 70)
    print("PHISHGUARD RESEARCH EXPERIMENT 3: ADVERSARIAL ROBUSTNESS EVALUATION")
    print("=" * 70)
    res, samples = run_experiment_03(sample_size=200)
    sum_p, sam_p = save_experiment_03_results(res, samples)
    print(f"\nExperiment complete. Evaluated {res['sample_count']} samples across {len(res['transformations'])} transformations.")
    print(f"Summary results: {sum_p}")
    print(f"Sample traceability: {sam_p}\n")
    for t_name, t_res in res["transformations"].items():
        print(f"[{t_name}]: Flips: {t_res['prediction_flips']} ({t_res['flip_rate']*100:.1f}%) | Evasion Rate: {t_res['evasion_rate']*100:.1f}% | False Alarm Rate: {t_res['false_alarm_rate']*100:.1f}% | Mean Prob Shift: {t_res['mean_probability_change']:+.4f}")
