"""
Tests for SSRF prevention, IP blocklisting, and DNS rebinding protections
in src/features/safe_fetcher.py and src/features/redirect_analyzer.py.
"""

import unittest
from unittest.mock import patch, MagicMock
import requests

from src.features.safe_fetcher import (
    is_private_or_unsafe_ip,
    is_forbidden_hostname,
    validate_url,
    safe_get,
    safe_fetch_chain,
    MAX_RESPONSE_SIZE,
    PinnedSessionContext
)
from src.features.redirect_analyzer import analyze_redirect_chain


class TestSafeFetcher(unittest.TestCase):
    """
    Test suite verifying that SSRF defenses, private IP blocklists,
    cloud metadata blocklists, and size/timeout limits function properly.
    """

    def test_localhost_blocking(self):
        """Verify localhost and loopback IPv4/IPv6 addresses are blocked."""
        loopback_ips = [
            "127.0.0.1",
            "127.0.0.2",
            "127.1.2.3",
            "::1",
            "0.0.0.0",
            "::"
        ]
        for ip in loopback_ips:
            self.assertTrue(
                is_private_or_unsafe_ip(ip),
                f"Expected loopback IP {ip} to be blocked"
            )

        loopback_urls = [
            "http://localhost",
            "http://localhost:8000/admin",
            "http://sub.localhost/test",
            "http://127.0.0.1:8000",
            "http://127.0.0.5:9000",
            "http://[::1]:8080"
        ]
        for url in loopback_urls:
            validation = validate_url(url)
            self.assertFalse(
                validation["safe"],
                f"Expected URL {url} to be flagged unsafe"
            )
            result = safe_get(url)
            self.assertTrue(
                result.get("blocked", False),
                f"Expected safe_get on {url} to be blocked"
            )

    def test_private_ip_blocking(self):
        """Verify RFC 1918 and IPv6 private addresses are blocked."""
        private_ips = [
            "10.0.0.1",
            "10.255.255.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.0.1",
            "192.168.1.100",
            "fc00::1",
            "fd12:3456:789a::1"
        ]
        for ip in private_ips:
            self.assertTrue(
                is_private_or_unsafe_ip(ip),
                f"Expected private IP {ip} to be blocked"
            )

        private_urls = [
            "http://10.0.0.1/status",
            "http://172.16.0.1:8080",
            "http://192.168.1.1/router"
        ]
        for url in private_urls:
            validation = validate_url(url)
            self.assertFalse(validation["safe"])
            result = safe_get(url)
            self.assertTrue(result.get("blocked", False))

    def test_cloud_metadata_blocking(self):
        """Verify AWS, GCP, Azure, and Alibaba cloud metadata endpoints are blocked."""
        metadata_ips = [
            "169.254.169.254",  # AWS/GCP/Azure/OpenStack metadata
            "169.254.1.1",      # General link-local
            "100.100.100.200",  # Alibaba Cloud metadata
            "fd00:ec2::254"     # AWS IPv6 metadata
        ]
        for ip in metadata_ips:
            self.assertTrue(
                is_private_or_unsafe_ip(ip),
                f"Expected cloud metadata IP {ip} to be blocked"
            )

        metadata_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://instance-data/latest/meta-data/"
        ]
        for url in metadata_urls:
            validation = validate_url(url)
            self.assertFalse(
                validation["safe"],
                f"Expected cloud metadata URL {url} to be blocked"
            )
            result = safe_get(url)
            self.assertTrue(result.get("blocked", False))

    def test_forbidden_schemes(self):
        """Verify only HTTP and HTTPS are allowed."""
        unsafe_schemes = [
            "file:///etc/passwd",
            "gopher://127.0.0.1:25",
            "ftp://example.com/file",
            "data:text/html,<html>alert(1)</html>"
        ]
        for url in unsafe_schemes:
            validation = validate_url(url)
            self.assertFalse(validation["safe"])

    def test_response_size_limits(self):
        """Verify responses exceeding MAX_RESPONSE_SIZE are rejected."""
        oversized_data = b"X" * (MAX_RESPONSE_SIZE + 500)

        # Mock requests.get returning oversized data
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Length": str(len(oversized_data))}
        mock_response.raw.read.return_value = oversized_data

        with patch("src.features.safe_fetcher.validate_url") as mock_val:
            mock_val.return_value = {
                "safe": True,
                "hostname": "example.com",
                "primary_ip": "93.184.216.34"
            }
            with patch("requests.get", return_value=mock_response):
                result = safe_get("https://example.com/huge-file")
                self.assertFalse(result["success"])
                self.assertTrue(result["blocked"])
                self.assertIn("exceeds size limit", result["reason"].lower())

    def test_timeout_handling(self):
        """Verify request timeouts are caught cleanly without crashing."""
        with patch("src.features.safe_fetcher.validate_url") as mock_val:
            mock_val.return_value = {
                "safe": True,
                "hostname": "example.com",
                "primary_ip": "93.184.216.34"
            }
            with patch("requests.get", side_effect=requests.exceptions.Timeout("Connection timed out")):
                result = safe_get("https://example.com/slow", timeout=1)
                self.assertFalse(result["success"])
                self.assertTrue(result.get("is_timeout", False))
                self.assertIn("timed out", result["error"])

    def test_redirect_to_private_ip_blocked(self):
        """Verify redirects targeting private IP addresses are halted and flagged."""
        # 1st hop: 302 redirecting to http://127.0.0.1/admin
        mock_hop1 = {
            "success": True,
            "blocked": False,
            "status_code": 302,
            "headers": {"Location": "http://127.0.0.1/admin"},
            "content": b"",
            "text": "",
            "url": "https://public-site.com"
        }
        # 2nd hop: safe_get blocks 127.0.0.1
        mock_hop2 = {
            "success": False,
            "blocked": True,
            "reason": "Destination resolves to a restricted or private IP address"
        }

        with patch("src.features.redirect_analyzer.safe_get", side_effect=[mock_hop1, mock_hop2]):
            result = analyze_redirect_chain("https://public-site.com")
            self.assertFalse(result["success"])
            self.assertTrue(result["blocked"])
            self.assertIn("restricted", result["error"].lower())

    def test_dns_rebinding_pinning_context(self):
        """Verify PinnedSessionContext properly configures the thread-local IP map."""
        from src.features.safe_fetcher import _tls
        with PinnedSessionContext("attacker-domain.test", "93.184.216.34"):
            self.assertIsNotNone(_tls.pinned_map)
            self.assertEqual(
                _tls.pinned_map.get("attacker-domain.test"),
                "93.184.216.34"
            )
        # Verify cleanup on exit
        self.assertIsNone(_tls.pinned_map)


if __name__ == "__main__":
    unittest.main()
