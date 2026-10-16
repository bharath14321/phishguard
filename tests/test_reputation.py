"""
Tests for VirusTotal Threat Intelligence module (src/features/reputation.py).
Verifies hash format validation, reputation queries, 404 handling,
and non-fatal graceful degradation without calling live external APIs.
"""

import unittest
from unittest.mock import patch, MagicMock
import requests

from src.features.reputation import (
    is_valid_hash,
    get_hash_reputation,
    get_url_reputation,
    encode_url_for_virustotal
)


class TestReputation(unittest.TestCase):
    """
    Test suite for server-side VirusTotal queries.
    """

    def test_hash_format_validation(self):
        """Verify MD5, SHA-1, and SHA-256 detection."""
        valid_md5 = "d41d8cd98f00b204e9800998ecf8427e"
        valid_sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        valid_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        self.assertTrue(is_valid_hash(valid_md5))
        self.assertTrue(is_valid_hash(valid_sha1))
        self.assertTrue(is_valid_hash(valid_sha256))

        invalid_hashes = [
            "not-a-hash",
            "12345",
            "xyz" * 15,
            "",
            None,
            "d41d8cd98f00b204e9800998ecf8427z"  # invalid hex char 'z'
        ]
        for inv in invalid_hashes:
            self.assertFalse(is_valid_hash(inv))

    def test_get_hash_reputation_invalid_syntax(self):
        """Verify invalid hash strings are rejected before any network request."""
        result = get_hash_reputation("invalid_hash_string")
        self.assertFalse(result["success"])
        self.assertIn("Invalid hash format", result["error"])

    def test_get_hash_reputation_missing_key(self):
        """Verify graceful error when VIRUSTOTAL_API_KEY is not configured."""
        with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": ""}):
            result = get_hash_reputation("d41d8cd98f00b204e9800998ecf8427e")
            self.assertFalse(result["success"])
            self.assertIn("VIRUSTOTAL_API_KEY not configured", result["error"])

    def test_get_hash_reputation_success_200(self):
        """Verify parsing of a valid 200 OK VirusTotal response."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 14,
                        "suspicious": 2,
                        "harmless": 45,
                        "undetected": 10,
                        "timeout": 0
                    },
                    "reputation": -25,
                    "type_description": "Win32 EXE",
                    "size": 102400,
                    "meaningful_name": "malicious_sample.exe",
                    "tags": ["trojan", "peexe"]
                }
            }
        }

        test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "mock_test_key"}):
            with patch("requests.get", return_value=mock_resp):
                result = get_hash_reputation(test_hash)

                self.assertTrue(result["success"])
                self.assertTrue(result["found"])
                self.assertEqual(result["malicious"], 14)
                self.assertEqual(result["suspicious"], 2)
                self.assertEqual(result["harmless"], 45)
                self.assertEqual(result["file_type"], "Win32 EXE")
                self.assertIn("trojan", result["tags"])

    def test_get_hash_reputation_not_found_404(self):
        """Verify 404 is treated as 'Unknown Status' without crashing."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "mock_test_key"}):
            with patch("requests.get", return_value=mock_resp):
                result = get_hash_reputation(test_hash)

                self.assertTrue(result["success"])
                self.assertFalse(result["found"])
                self.assertIn("Unknown Status", result["message"])

    def test_get_hash_reputation_network_exception(self):
        """Verify network errors / rate limits do not crash the module."""
        test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "mock_test_key"}):
            with patch("requests.get", side_effect=requests.RequestException("Rate limit exceeded")):
                result = get_hash_reputation(test_hash)

                self.assertFalse(result["success"])
                self.assertIn("Rate limit exceeded", result["error"])


if __name__ == "__main__":
    unittest.main()
