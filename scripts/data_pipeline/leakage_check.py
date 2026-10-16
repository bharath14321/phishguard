"""
scripts/data_pipeline/leakage_check.py

Automated Dataset Quality, Overlap Detection, and Data Leakage Auditing.

Checks:
1. Exact duplicate records within dataset
2. Exact URL duplicates and URL canonicalization collisions
3. Cross-dataset overlap between training data and external evaluation feeds
4. Train/Test split contamination
5. Domain leakage (same rare private domain appearing in train and test splits)
6. Emits structured JSON quality report: data/processed/quality/leakage_report.json
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlparse
import pandas as pd

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s - %(message)s")
logger = logging.getLogger("phishguard.leakage_checker")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
QUALITY_DIR = BASE_DIR / "data" / "processed" / "quality"
REPORT_PATH = QUALITY_DIR / "leakage_report.json"


def normalize_url(url: str) -> str:
    """Canonicalize a URL for exact and structural comparison."""
    if not isinstance(url, str):
        return ""
    u = url.strip().lower()
    if not u.startswith("http://") and not u.startswith("https://"):
        u = "http://" + u
    try:
        parsed = urlparse(u)
        netloc = parsed.netloc.rstrip("/")
        path = parsed.path.rstrip("/")
        return f"{netloc}{path}"
    except Exception:
        return u.rstrip("/")


def extract_domain(url: str) -> str:
    """Extract domain host from URL."""
    if not isinstance(url, str):
        return ""
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        return (parsed.netloc or "").split(":")[0].lower()
    except Exception:
        return ""


def check_dataset_leakage(
    train_df: pd.DataFrame,
    test_df: Optional[pd.DataFrame] = None,
    external_urls: Optional[Set[str]] = None,
    url_column: str = "url",
    label_column: str = "label"
) -> Dict[str, Any]:
    """
    Perform deep leakage and overlap audit on training data.

    Returns:
        Structured audit report dict with status "PASSED", "WARNING", or "BLOCKED".
    """
    QUALITY_DIR.mkdir(parents=True, exist_ok=True)
    report = {
        "status": "PASSED",
        "total_train_records": len(train_df),
        "exact_duplicates": 0,
        "label_conflicts": 0,
        "train_test_overlap": 0,
        "domain_leakage_count": 0,
        "external_evaluation_overlap": 0,
        "details": {},
    }

    if url_column not in train_df.columns:
        report["status"] = "ERROR"
        report["details"]["error"] = f"Missing column {url_column}"
        return report

    # 1. Exact Duplicates within Train Set
    train_urls = train_df[url_column].astype(str)
    dup_mask = train_urls.duplicated(keep=False)
    report["exact_duplicates"] = int(dup_mask.sum())

    # 2. Inconsistent Labels (Same URL with conflicting labels)
    if label_column in train_df.columns:
        conflicts = train_df.groupby(url_column)[label_column].nunique()
        conflict_urls = conflicts[conflicts > 1].index.tolist()
        report["label_conflicts"] = len(conflict_urls)
        if len(conflict_urls) > 0:
            report["details"]["sample_label_conflicts"] = conflict_urls[:5]

    # 3. Train / Test Overlap (if split provided)
    if test_df is not None and url_column in test_df.columns:
        test_urls = set(test_df[url_column].astype(str).map(normalize_url))
        train_norm = set(train_urls.map(normalize_url))
        overlap = train_norm.intersection(test_urls)
        report["train_test_overlap"] = len(overlap)
        report["total_test_records"] = len(test_df)

        if len(overlap) > 0:
            report["details"]["sample_train_test_overlap"] = list(overlap)[:5]
            if len(overlap) > (0.01 * len(test_df)): # > 1% overlap is blocking
                report["status"] = "BLOCKED"
                report["details"]["block_reason"] = "Severe train/test leakage detected."

        # Domain Leakage check for uncommon domains
        train_domains = set(train_urls.map(extract_domain))
        test_domains = set(test_df[url_column].astype(str).map(extract_domain))
        common_domains = train_domains.intersection(test_domains)
        # Filter out massive shared public suffix domains
        major_hosts = {"", "com", "org", "net", "io", "co", "github.io", "pages.dev", "appspot.com"}
        suspicious_shared = [d for d in common_domains if d not in major_hosts and len(d) > 4]
        report["domain_leakage_count"] = len(suspicious_shared)

    # 4. External Evaluation Overlap
    if external_urls:
        train_norm = set(train_urls.map(normalize_url))
        ext_norm = set(normalize_url(u) for u in external_urls)
        ext_overlap = train_norm.intersection(ext_norm)
        report["external_evaluation_overlap"] = len(ext_overlap)
        if len(ext_overlap) > 0:
            report["details"]["sample_external_overlap"] = list(ext_overlap)[:5]

    # Overall Status determination
    if report["status"] != "BLOCKED":
        if report["label_conflicts"] > 100 or report["train_test_overlap"] > 0:
            report["status"] = "WARNING"
        else:
            report["status"] = "PASSED"

    # Save to JSON
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    logger.info(f"Leakage audit completed with status: {report['status']}")
    return report


if __name__ == "__main__":
    import numpy as np
    # Quick self-test if processed features exist
    features_csv = BASE_DIR / "data" / "processed" / "url_features.csv"
    if features_csv.exists():
        logger.info(f"Auditing existing features: {features_csv}")
        df = pd.read_csv(features_csv, nrows=5000)
        report = check_dataset_leakage(df)
        print(json.dumps(report, indent=2))
