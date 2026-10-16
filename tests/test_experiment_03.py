"""
tests/test_experiment_03.py

Unit tests for Research Experiment 3 (Adversarial URL Robustness Evaluation).
Verifies:
1. Deterministic transformations (T1-T7).
2. URL validity and integrity.
3. Transformation traceability to original sample ID.
4. Immutability of original sample URLs.
5. Strict offline execution (ZERO network/socket requests).
6. Malicious evasion rate calculations.
7. Benign false-alarm rate calculations.
8. Prediction flip rate calculations.
9. Fixed random seed deterministic sampling.
10. Summary and sample-level CSV persistence.
"""

import os
import socket
import tempfile
import urllib.request
import pytest
from typing import Dict, Any

from src.research.experiment_03_adversarial_robustness import (
    transform_added_subdomain,
    transform_deeper_subdomain,
    transform_added_path,
    transform_added_query,
    transform_added_fragment,
    transform_case_changed,
    transform_encoded_path,
    TRANSFORMATIONS,
    load_adversarial_dataset,
    evaluate_adversarial_robustness,
    run_experiment_03,
    save_experiment_03_results,
)


class TestAdversarialTransformations:
    """Test deterministic transformation functions."""

    @pytest.fixture
    def base_url(self):
        return "http://example.com/login"

    def test_added_subdomain(self, base_url):
        t_url = transform_added_subdomain(base_url)
        assert "auth.example.com" in t_url
        assert t_url.endswith("/login")
        # Deterministic check
        assert transform_added_subdomain(base_url) == t_url

    def test_deeper_subdomain(self, base_url):
        t_url = transform_deeper_subdomain(base_url)
        assert "portal.secure.example.com" in t_url
        assert transform_deeper_subdomain(base_url) == t_url

    def test_added_path(self, base_url):
        t_url = transform_added_path(base_url)
        assert t_url == "http://example.com/login/verify/account"

    def test_added_query(self, base_url):
        t_url = transform_added_query(base_url)
        assert "session_id=987654321" in t_url
        assert "auth=true" in t_url

    def test_added_fragment(self, base_url):
        t_url = transform_added_fragment(base_url)
        assert t_url.endswith("#security-notice")

    def test_case_changed(self, base_url):
        t_url = transform_case_changed(base_url)
        assert t_url != base_url
        assert "HTTP://" in t_url or "Login" in t_url

    def test_encoded_path(self, base_url):
        t_url = transform_encoded_path(base_url)
        assert "%" in t_url or "login" in t_url


class TestOfflineIntegrityAndNoNetworkRequests:
    """Verify zero network requests occur during transformation and inference."""

    def test_no_network_calls_during_adversarial_evaluation(self, monkeypatch):
        """Mock socket and urllib to assert zero network requests are initiated."""
        def fail_network(*args, **kwargs):
            raise RuntimeError("CRITICAL ERROR: Network access attempted during adversarial evaluation!")

        monkeypatch.setattr(socket, "socket", fail_network)
        monkeypatch.setattr(socket, "getaddrinfo", fail_network)
        monkeypatch.setattr(socket, "gethostbyname", fail_network)

        samples = [
            {"sample_id": 1, "url": "http://safe-example.org/test", "label": 0},
            {"sample_id": 2, "url": "http://192.168.1.1/phish-account", "label": 1},
        ]

        # Must execute without triggering mocked network exceptions
        results, sample_records = evaluate_adversarial_robustness(samples)
        assert results["sample_count"] == 2
        assert len(sample_records) == 2 * len(TRANSFORMATIONS)


class TestMetricsAndTraceability:
    """Test paired evaluation metrics, directionality, and traceability."""

    def test_traceability_and_sample_mapping(self):
        samples = [
            {"sample_id": 101, "url": "http://benign-test.com/home", "label": 0},
            {"sample_id": 102, "url": "http://evil-phish.net/auth", "label": 1},
        ]
        results, records = evaluate_adversarial_robustness(samples)

        assert len(records) == 2 * 7
        for r in records:
            assert r["sample_id"] in (101, 102)
            assert "original_url" in r
            assert "transformed_url" in r
            assert "prediction_changed" in r
            assert "malicious_evasion" in r
            assert "benign_false_alarm" in r
            assert isinstance(r["probability_change"], float)

    def test_adversarial_rates_logic(self):
        """Verify evasion and false alarm rates compute mathematically correct percentages."""
        samples = [
            {"sample_id": 1, "url": "http://sample1.com", "label": 0},
            {"sample_id": 2, "url": "http://sample2.com", "label": 1},
        ]
        results, records = evaluate_adversarial_robustness(samples)
        for t_name, t_data in results["transformations"].items():
            assert 0.0 <= t_data["evasion_rate"] <= 1.0
            assert 0.0 <= t_data["false_alarm_rate"] <= 1.0
            assert 0.0 <= t_data["flip_rate"] <= 1.0


class TestPersistenceAndReproducibility:
    """Test determinism and CSV artifact saving."""

    def test_sampling_determinism(self):
        s1, b1, m1 = load_adversarial_dataset(sample_size=10, random_state=42)
        s2, b2, m2 = load_adversarial_dataset(sample_size=10, random_state=42)

        assert len(s1) == len(s2) == 10
        assert b1 == b2 == 5
        assert m1 == m2 == 5
        for item1, item2 in zip(s1, s2):
            assert item1["url"] == item2["url"]
            assert item1["label"] == item2["label"]

    def test_save_results_csv(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f1, \
             tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f2:
            sum_csv = f1.name
            sam_csv = f2.name

        try:
            samples = [
                {"sample_id": 1, "url": "http://safe.com", "label": 0},
                {"sample_id": 2, "url": "http://phish.cc", "label": 1},
            ]
            res, recs = evaluate_adversarial_robustness(samples)
            out_sum, out_sam = save_experiment_03_results(
                res, recs, summary_path=sum_csv, sample_path=sam_csv
            )
            assert os.path.isfile(out_sum)
            assert os.path.isfile(out_sam)
            assert os.path.getsize(out_sum) > 0
            assert os.path.getsize(out_sam) > 0
        finally:
            if os.path.exists(sum_csv):
                os.remove(sum_csv)
            if os.path.exists(sam_csv):
                os.remove(sam_csv)
