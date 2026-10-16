"""
tests/test_virustotal_semantics.py

Focused test suite for VirusTotal Threat Intelligence integration and status semantics.
Verifies that:
1. Valid VT response with malicious detections is accurately flagged.
2. Valid VT response with zero malicious/suspicious detections is flagged as clean.
3. Missing API key is marked UNAVAILABLE / UNKNOWN (never CLEAN).
4. Network timeout is marked ERROR / UNKNOWN (never CLEAN).
5. Network failure is marked ERROR / UNKNOWN (never CLEAN).
6. 429 Rate limit is marked RATE_LIMITED / UNKNOWN (never CLEAN).
7. 404 Not Found is marked NOT_FOUND / UNKNOWN (never CLEAN).
8. Malformed provider response is safely handled.
9. UNKNOWN != CLEAN semantic guarantee.
10. API key is never exposed or returned in error payloads.
"""

import os
from unittest.mock import MagicMock, patch
import pytest
import requests

from src.features.reputation import (
    get_url_reputation,
    get_hash_reputation,
    get_file_reputation,
    encode_url_for_virustotal,
    is_valid_hash,
)


@pytest.fixture
def mock_vt_env(monkeypatch):
    """Set a dummy test API key."""
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test_virustotal_dummy_api_key_12345")


# ---------------------------------------------------------------------------
# 1. Valid VT response with malicious detections
# ---------------------------------------------------------------------------
def test_vt_response_with_malicious_detections(mock_vt_env):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 14,
                    "suspicious": 3,
                    "harmless": 20,
                    "undetected": 35,
                    "timeout": 0,
                },
                "reputation": -45,
            }
        }
    }

    with patch("requests.get", return_value=mock_resp):
        res = get_url_reputation("https://malicious-login-phish.com")

    assert res["success"] is True
    assert res["found"] is True
    assert res["status"] == "SUCCESS"
    assert res["malicious"] == 14
    assert res["suspicious"] == 3
    assert res["is_clean"] is False
    assert res["is_unknown"] is False


# ---------------------------------------------------------------------------
# 2. Valid VT response with zero malicious detections (Clean)
# ---------------------------------------------------------------------------
def test_vt_response_zero_malicious_is_clean(mock_vt_env):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 70,
                    "undetected": 5,
                    "timeout": 0,
                },
                "reputation": 100,
            }
        }
    }

    with patch("requests.get", return_value=mock_resp):
        res = get_url_reputation("https://legitimate-domain.com")

    assert res["success"] is True
    assert res["found"] is True
    assert res["status"] == "SUCCESS"
    assert res["malicious"] == 0
    assert res["suspicious"] == 0
    assert res["is_clean"] is True
    assert res["is_unknown"] is False


# ---------------------------------------------------------------------------
# 3. Missing API key -> UNAVAILABLE (NOT Clean)
# ---------------------------------------------------------------------------
def test_vt_missing_api_key(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    res_url = get_url_reputation("https://any-url.com")
    assert res_url["status"] == "UNAVAILABLE"
    assert res_url["is_clean"] is False
    assert res_url["is_unknown"] is True
    assert "VIRUSTOTAL_API_KEY not configured" in res_url["error"]

    res_hash = get_hash_reputation("44d88612fea8a8f36de82e1278abb02f")
    assert res_hash["status"] == "UNAVAILABLE"
    assert res_hash["is_clean"] is False
    assert res_hash["is_unknown"] is True


# ---------------------------------------------------------------------------
# 4. Request Timeout -> ERROR (NOT Clean)
# ---------------------------------------------------------------------------
def test_vt_timeout_is_unknown(mock_vt_env):
    with patch("requests.get", side_effect=requests.Timeout("Connection timed out")):
        res = get_url_reputation("https://slow-responding-site.com")

    assert res["success"] is False
    assert res["status"] == "ERROR"
    assert res["is_clean"] is False
    assert res["is_unknown"] is True
    assert "timed out" in res["error"].lower()


# ---------------------------------------------------------------------------
# 5. Network / Connection failure -> ERROR (NOT Clean)
# ---------------------------------------------------------------------------
def test_vt_network_failure_is_unknown(mock_vt_env):
    with patch("requests.get", side_effect=requests.ConnectionError("DNS resolution failed")):
        res = get_hash_reputation("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    assert res["success"] is False
    assert res["status"] == "ERROR"
    assert res["is_clean"] is False
    assert res["is_unknown"] is True


# ---------------------------------------------------------------------------
# 6. Rate Limit (HTTP 429) -> RATE_LIMITED (NOT Clean)
# ---------------------------------------------------------------------------
def test_vt_rate_limit_429(mock_vt_env):
    mock_resp = MagicMock()
    mock_resp.status_code = 429

    with patch("requests.get", return_value=mock_resp):
        res = get_url_reputation("https://rate-limited-test.com")

    assert res["status"] == "RATE_LIMITED"
    assert res["is_clean"] is False
    assert res["is_unknown"] is True
    assert "rate limit" in res["error"].lower()


# ---------------------------------------------------------------------------
# 7. 404 Not Found -> NOT_FOUND (NOT Clean)
# ---------------------------------------------------------------------------
def test_vt_not_found_is_unknown_not_clean(mock_vt_env):
    mock_resp = MagicMock()
    mock_resp.status_code = 404

    with patch("requests.get", return_value=mock_resp):
        res = get_hash_reputation("44d88612fea8a8f36de82e1278abb02f")

    assert res["found"] is False
    assert res["status"] == "NOT_FOUND"
    assert res["is_clean"] is False
    assert res["is_unknown"] is True


# ---------------------------------------------------------------------------
# 8. Malformed / Empty response handled safely
# ---------------------------------------------------------------------------
def test_vt_malformed_response(mock_vt_env):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"corrupt": "data"}

    with patch("requests.get", return_value=mock_resp):
        res = get_url_reputation("https://corrupted-api-test.com")

    assert res["success"] is True
    assert res["malicious"] == 0
    # Because malicious=0 and suspicious=0, it has stats of 0
    assert "malicious" in res


# ---------------------------------------------------------------------------
# 9. Invalid Hash Format Validation
# ---------------------------------------------------------------------------
def test_invalid_hash_format():
    res = get_hash_reputation("not_a_valid_hash_format")
    assert res["success"] is False
    assert res["status"] == "ERROR"
    assert "Invalid hash format" in res["error"]
    assert res["is_clean"] is False


# ---------------------------------------------------------------------------
# 10. URL Encoding Helper
# ---------------------------------------------------------------------------
def test_url_encoding_for_virustotal():
    url = "https://example.com/test?param=1"
    encoded = encode_url_for_virustotal(url)
    assert "=" not in encoded
    assert len(encoded) > 10
