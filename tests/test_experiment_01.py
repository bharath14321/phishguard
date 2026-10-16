"""
tests/test_experiment_01.py

Unit tests for Research Experiment 1 (Layer-by-Layer Evaluation).
Verifies:
1. Configuration definitions (Experiments A through F).
2. Missing evidence handling (UNKNOWN / None).
3. UNKNOWN values do not default to benign or malicious.
4. Correct computation of metrics and confusion matrix.
5. CSV result persistence.
6. Non-regression of existing production risk behavior.
"""

import os
import tempfile
import pytest
from typing import Dict, Any

from src.research.experiment_01_layer_evaluation import (
    load_evaluation_dataset,
    compute_metrics,
    run_experiment_a_url_only,
    run_experiment_b_url_domain,
    run_experiment_c_url_domain_email,
    run_experiment_d_url_domain_email_webpage,
    run_experiment_e_url_domain_email_webpage_attachment,
    run_experiment_f_full_phishguard_system,
    run_layer_evaluation,
    save_results_to_csv,
)
from src.analysis.multi_layer_risk import aggregate_multi_layer_risk
from src.analysis.risk_engine import analyze_url_risk


class TestLayerEvaluationConfigurations:
    """Test individual experiment configuration runners."""

    @pytest.fixture
    def sample_urls(self):
        return [
            "http://example.com/safe",
            "http://192.168.1.1/login-bank-verify",
            "https://secure-paypal-update.phish.com/auth",
            "http://wikipedia.org/wiki/Phishing",
        ]

    def test_experiment_a_url_only(self, sample_urls):
        """Experiment A runs URL lexical inference."""
        preds, scores, elapsed = run_experiment_a_url_only(sample_urls)
        assert len(preds) == len(sample_urls)
        assert len(scores) == len(sample_urls)
        assert elapsed >= 0.0
        assert all(p in (0, 1) for p in preds)
        assert all(0.0 <= s <= 1.0 for s in scores)

    def test_experiment_b_url_domain(self, sample_urls):
        """Experiment B runs URL + Domain risk engine heuristics."""
        preds, scores, elapsed = run_experiment_b_url_domain(sample_urls)
        assert len(preds) == len(sample_urls)
        assert len(scores) == len(sample_urls)
        assert elapsed >= 0.0
        assert all(p in (0, 1) for p in preds)

    def test_experiment_c_missing_email_layer(self, sample_urls):
        """Experiment C evaluates URL + Domain with explicitly UNKNOWN email layer."""
        preds, scores, elapsed, meta = run_experiment_c_url_domain_email(sample_urls)
        assert len(preds) == len(sample_urls)
        assert "UNKNOWN" in meta["email_layer_status"]
        assert meta["samples_evaluated"] == len(sample_urls)

    def test_experiment_d_missing_webpage_layer(self, sample_urls):
        """Experiment D evaluates URL + Domain with UNKNOWN email and webpage layers."""
        preds, scores, elapsed, meta = run_experiment_d_url_domain_email_webpage(sample_urls)
        assert len(preds) == len(sample_urls)
        assert "UNKNOWN" in meta["webpage_layer_status"]

    def test_experiment_e_missing_attachment_layer(self, sample_urls):
        """Experiment E evaluates URL + Domain with UNKNOWN attachment layer."""
        preds, scores, elapsed, meta = run_experiment_e_url_domain_email_webpage_attachment(sample_urls)
        assert len(preds) == len(sample_urls)
        assert "UNKNOWN" in meta["attachment_layer_status"]

    def test_experiment_f_full_phishguard(self, sample_urls):
        """Experiment F evaluates full unified multi-layer pipeline."""
        preds, scores, elapsed = run_experiment_f_full_phishguard_system(sample_urls)
        assert len(preds) == len(sample_urls)
        assert len(scores) == len(sample_urls)
        assert all(p in (0, 1) for p in preds)


class TestMetricsComputation:
    """Test statistical metrics and confusion matrix accuracy."""

    def test_compute_metrics_perfect_classification(self):
        y_true = [1, 1, 0, 0]
        y_pred = [1, 1, 0, 0]
        y_scores = [0.9, 0.8, 0.2, 0.1]
        metrics = compute_metrics(y_true, y_pred, y_scores)

        assert metrics["accuracy"] == 1.0
        assert metrics["precision"] == 1.0
        assert metrics["recall"] == 1.0
        assert metrics["f1"] == 1.0
        assert metrics["tp"] == 2
        assert metrics["tn"] == 2
        assert metrics["fp"] == 0
        assert metrics["fn"] == 0
        assert metrics["confusion_matrix"] == (2, 0, 0, 2)
        assert metrics["roc_auc"] == 1.0

    def test_compute_metrics_all_negative_predictions(self):
        y_true = [1, 1, 0, 0]
        y_pred = [0, 0, 0, 0]
        metrics = compute_metrics(y_true, y_pred)

        assert metrics["accuracy"] == 0.5
        assert metrics["precision"] == 0.0
        assert metrics["recall"] == 0.0
        assert metrics["f1"] == 0.0
        assert metrics["tp"] == 0
        assert metrics["fn"] == 2
        assert metrics["tn"] == 2
        assert metrics["fp"] == 0

    def test_compute_metrics_empty(self):
        metrics = compute_metrics([], [])
        assert metrics["accuracy"] == 0.0
        assert metrics["f1"] == 0.0


class TestScientificControlsAndPreservation:
    """Verify scientific integrity and non-distortion of existing behavior."""

    def test_unknown_layers_do_not_default_to_malicious(self):
        """Passing None for optional layers must return UNKNOWN and not inflate risk."""
        clean_url_details = {
            "url": "http://example.com/clean",
            "url_features": {"contains_ip": 0, "suspicious_keyword_count": 0},
            "domain_intelligence": {"is_ip_address": False},
            "brand_intelligence": {"brand_domain_mismatch": False},
        }
        risk = analyze_url_risk(clean_url_details)
        assert risk.score == 0.0
        assert risk.level == "LOW"

        aggregated = aggregate_multi_layer_risk({
            "url_details": clean_url_details,
            "email": None,
            "webpage": None,
            "attachment": None,
            "final_risk": risk,
        })
        assert aggregated["email_evidence"] is None
        assert aggregated["web_evidence"] is None
        assert aggregated["attachment_evidence"] is None
        assert aggregated["final_risk"].score == 0.0

    def test_csv_results_generation(self):
        """Verify layer evaluation run generates structured CSV output."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            results = run_layer_evaluation(sample_size=10, random_state=42)
            assert len(results) == 6
            assert "Experiment_A" in results
            assert "Experiment_F" in results

            saved_path = save_results_to_csv(results, output_path=tmp_path)
            assert os.path.exists(saved_path)
            assert os.path.getsize(saved_path) > 0
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
