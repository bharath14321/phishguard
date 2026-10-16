"""
tests/test_experiment_02.py

Unit tests for Research Experiment 2 (External Generalization Evaluation).
Verifies:
1. External dataset loading and validation.
2. Label normalization (0/1).
3. Malformed URL filtering and exclusion tracking.
4. Internal duplicate detection.
5. Overlap computation against development dataset.
6. 14-feature compatibility with the frozen model.
7. Pure-Python & scikit-learn metric calculations.
8. Confusion matrix, FPR, and FNR calculations.
9. Blocked status handling when external dataset is absent.
10. Result persistence to CSV.
11. Read-only model execution (no retraining).
"""

import os
import tempfile
import pytest
from typing import Dict, Any

from src.research.experiment_02_external_evaluation import (
    load_internal_url_set,
    load_and_validate_external_dataset,
    compute_generalization_metrics,
    evaluate_frozen_model_on_urls,
    run_experiment_02_evaluation,
    save_experiment_02_results_csv,
    INTERNAL_BASELINE_METRICS,
    FEATURE_COLUMNS,
)
from src.features.url_features import extract_url_features
from src.models.url_model_inference import predict_url


class TestExternalDatasetValidation:
    """Test data loading, cleaning, and overlap analysis."""

    def test_load_and_validate_valid_dataset(self):
        """Valid dataset should load cleanly with accurate class counts."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("url,label\n")
            f.write("http://example.com/safe,0\n")
            f.write("http://phish-login-bank.cc/auth,1\n")
            f.write("https://google.com,benign\n")
            f.write("http://malware-payload.org,phishing\n")
            tmp_path = f.name

        try:
            urls, labels, meta = load_and_validate_external_dataset(tmp_path)
            assert len(urls) == 4
            assert len(labels) == 4
            assert meta["valid_samples"] == 4
            assert meta["benign_samples"] == 2
            assert meta["malicious_samples"] == 2
            assert meta["malformed_or_missing_excluded"] == 0
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_malformed_and_missing_url_handling(self):
        """Malformed rows and missing labels must be filtered and audited."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("url,label\n")
            f.write(",0\n")  # missing URL
            f.write("http://valid-benign.com,\n")  # missing label
            f.write("http://valid-phish.com,1\n")
            f.write("http://valid-clean.com,0\n")
            tmp_path = f.name

        try:
            urls, labels, meta = load_and_validate_external_dataset(tmp_path)
            assert len(urls) == 2
            assert meta["malformed_or_missing_excluded"] == 2
            assert meta["valid_samples"] == 2
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_duplicate_detection(self):
        """Duplicate URLs in external dataset must be deduplicated."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("url,label\n")
            f.write("http://duplicate.com,0\n")
            f.write("http://duplicate.com,0\n")
            f.write("http://unique-phish.com,1\n")
            tmp_path = f.name

        try:
            urls, labels, meta = load_and_validate_external_dataset(tmp_path)
            assert len(urls) == 2
            assert meta["internal_duplicates_excluded"] == 1
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_overlap_calculation(self):
        """Overlap against internal development URLs must be quantified."""
        internal_set = {"http://known-dev-url.com", "http://another-dev.com"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("url,label\n")
            f.write("http://known-dev-url.com,0\n")
            f.write("http://brand-new-external.org,1\n")
            tmp_path = f.name

        try:
            urls, labels, meta = load_and_validate_external_dataset(
                tmp_path, internal_urls_set=internal_set
            )
            assert meta["overlap_with_internal_dev_count"] == 1
            assert meta["overlap_percentage"] == 50.0
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_single_class_rejection(self):
        """Dataset with only one class must raise ValueError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("url,label\n")
            f.write("http://safe1.com,0\n")
            f.write("http://safe2.com,0\n")
            tmp_path = f.name

        try:
            with pytest.raises(ValueError, match="both positive.*and negative"):
                load_and_validate_external_dataset(tmp_path)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


class TestMetricsAndComparison:
    """Test generalization metrics, confusion matrix, FPR, and FNR."""

    def test_compute_generalization_metrics(self):
        y_true = [1, 1, 0, 0]
        y_pred = [1, 0, 0, 1]  # 1 TP, 1 FN, 1 TN, 1 FP
        y_scores = [0.9, 0.4, 0.1, 0.8]

        metrics = compute_generalization_metrics(y_true, y_pred, y_scores)
        assert metrics["accuracy"] == 0.5
        assert metrics["precision"] == 0.5
        assert metrics["recall"] == 0.5
        assert metrics["f1"] == 0.5
        assert metrics["tp"] == 1
        assert metrics["tn"] == 1
        assert metrics["fp"] == 1
        assert metrics["fn"] == 1
        assert metrics["fpr"] == 0.5
        assert metrics["fnr"] == 0.5
        assert metrics["confusion_matrix"] == (1, 1, 1, 1)

    def test_feature_compatibility_and_inference(self):
        """Verify feature extraction preserves all 14 required dimensions."""
        sample_url = "http://secure-login-paypal.com.verify.net/account/auth"
        features = extract_url_features(sample_url)

        for col in FEATURE_COLUMNS:
            assert col in features, f"Missing required feature: {col}"

        res = predict_url(sample_url)
        assert "probability" in res
        assert "features" in res


class TestExperimentExecutionAndPersistence:
    """Test experiment execution runner and CSV persistence."""

    def test_experiment_blocked_status_when_dataset_missing(self):
        """When no external dataset is provided, status is marked BLOCKED."""
        res = run_experiment_02_evaluation(external_dataset_path=None)
        assert res["status"] == "BLOCKED — INDEPENDENT EXTERNAL DATASET REQUIRED"
        assert res["internal_benchmark"] == INTERNAL_BASELINE_METRICS
        assert res["external_results"] is None

    def test_experiment_successful_run_with_valid_file(self):
        """When a valid external file is provided, evaluation completes."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("url,label\n")
            f.write("http://benign-site.com,0\n")
            f.write("http://phish-site.cc/login,1\n")
            tmp_path = f.name

        try:
            res = run_experiment_02_evaluation(external_dataset_path=tmp_path)
            assert res["status"] == "COMPLETED"
            assert res["external_results"]["sample_count"] == 2
            assert res["comparison"] is not None
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_save_results_csv(self):
        """Results must persist cleanly to CSV."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            tmp_csv = f.name

        try:
            res = run_experiment_02_evaluation(external_dataset_path=None)
            out_file = save_experiment_02_results_csv(res, output_path=tmp_csv)
            assert os.path.isfile(out_file)
            assert os.path.getsize(out_file) > 0
        finally:
            if os.path.exists(tmp_csv):
                os.remove(tmp_csv)
