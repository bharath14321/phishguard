"""
Tests for the Phase 8A evidence correlator.

All tests use deterministic, mocked analysis dictionaries.
No network calls are made.
"""

import pytest
from src.analysis.evidence_correlator import correlate_evidence


# ------------------------------------------------------------------ #
#  Helpers                                                            #
# ------------------------------------------------------------------ #

def _url_details(**overrides):
    """Build a minimal url_analyzer-style result dict."""
    base = {
        "url": "https://example.com",
        "url_features": {},
        "domain_intelligence": {},
        "brand_intelligence": {},
        "ip_intelligence": {},
        "virustotal": {},
        "redirect_analysis": {},
        "webpage_analysis": {},
        "errors": [],
    }
    base.update(overrides)
    return base


def _email_data(**overrides):
    """Build a minimal email_analyzer-style result dict."""
    base = {
        "headers": {
            "from": "Sender <sender@example.com>",
            "reply_to": "",
            "from_email": "sender@example.com",
            "reply_to_email": "",
            "from_domain": "example.com",
            "reply_to_domain": "",
            "reply_to_domain_mismatch": False,
            "display_name_analysis": {
                "display_name": "Sender",
                "email_address": "sender@example.com",
                "possible_mismatch": False,
            },
        },
        "body": {"plain_text": "", "html": ""},
    }
    base.update(overrides)
    return base


# ================================================================== #
#  1.  Brand + unrelated domain                                      #
# ================================================================== #

class TestBrandDomainCorrelation:

    def test_brand_mismatch_creates_correlation(self):
        """When brand_domain_mismatch is True, a brand-impersonation
        correlation should be created."""
        data = {
            "url_details": _url_details(
                brand_intelligence={
                    "brand_domain_mismatch": True,
                    "detected_brands": ["paypal"],
                    "registrable_domain": "evil.com",
                },
            ),
        }
        result = correlate_evidence(data)
        corr_names = [c["name"] for c in result["correlations"]]
        assert "brand_impersonation" in corr_names

    def test_no_mismatch_no_correlation(self):
        data = {
            "url_details": _url_details(
                brand_intelligence={
                    "brand_domain_mismatch": False,
                    "detected_brands": ["paypal"],
                },
            ),
        }
        result = correlate_evidence(data)
        corr_names = [c["name"] for c in result["correlations"]]
        assert "brand_impersonation" not in corr_names


# ================================================================== #
#  2.  Suspicious URL + password form                                 #
# ================================================================== #

class TestUrlPasswordCorrelation:

    def test_suspicious_url_and_password_form(self):
        data = {
            "url_details": _url_details(
                url_features={"suspicious_keyword_count": 3},
                webpage_analysis={"password_field_count": 1},
            ),
        }
        result = correlate_evidence(data)
        corr_names = [c["name"] for c in result["correlations"]]
        assert "suspicious_url_credential_collection" in corr_names

    def test_suspicious_url_no_password(self):
        data = {
            "url_details": _url_details(
                url_features={"suspicious_keyword_count": 3},
                webpage_analysis={"password_field_count": 0},
            ),
        }
        result = correlate_evidence(data)
        corr_names = [c["name"] for c in result["correlations"]]
        assert "suspicious_url_credential_collection" not in corr_names


# ================================================================== #
#  3.  Redirect + suspicious destination                              #
# ================================================================== #

class TestRedirectCorrelation:

    def test_redirects_to_suspicious_destination(self):
        data = {
            "url_details": _url_details(
                redirect_analysis={"redirect_count": 5},
                domain_intelligence={"is_ip_address": True},
            ),
        }
        result = correlate_evidence(data)
        corr_names = [c["name"] for c in result["correlations"]]
        assert "redirect_to_suspicious_destination" in corr_names

    def test_redirects_to_clean_destination(self):
        data = {
            "url_details": _url_details(
                redirect_analysis={"redirect_count": 5},
            ),
        }
        result = correlate_evidence(data)
        corr_names = [c["name"] for c in result["correlations"]]
        assert "redirect_to_suspicious_destination" not in corr_names


# ================================================================== #
#  4.  Display-name + Reply-To mismatch                               #
# ================================================================== #

class TestEmailIdentityCorrelation:

    def test_both_mismatches(self):
        headers = {
            "from": "PayPal <scam@evil.com>",
            "reply_to_domain_mismatch": True,
            "display_name_analysis": {
                "display_name": "PayPal",
                "email_address": "scam@evil.com",
                "possible_mismatch": True,
            },
        }
        data = {"email_data": {"headers": headers, "body": {}}}
        result = correlate_evidence(data)
        corr_names = [c["name"] for c in result["correlations"]]
        assert "sender_identity_deception" in corr_names

    def test_only_display_name_no_correlation(self):
        """A display-name mismatch alone should create evidence but
        NOT the combined identity-deception correlation."""
        headers = {
            "from": "PayPal <scam@evil.com>",
            "reply_to_domain_mismatch": False,
            "display_name_analysis": {
                "display_name": "PayPal",
                "email_address": "scam@evil.com",
                "possible_mismatch": True,
            },
        }
        data = {"email_data": {"headers": headers, "body": {}}}
        result = correlate_evidence(data)
        corr_names = [c["name"] for c in result["correlations"]]
        assert "sender_identity_deception" not in corr_names


# ================================================================== #
#  5.  Authentication failure + sender evidence                       #
# ================================================================== #

class TestAuthSenderCorrelation:

    def test_auth_failure_plus_identity_mismatch(self):
        headers = {
            "reply_to_domain_mismatch": True,
            "display_name_analysis": {
                "possible_mismatch": True,
            },
        }
        auth = {
            "status": {"spf": "fail", "dkim": "fail", "dmarc": "fail"},
            "signals": {"spf_fail": True, "dkim_fail": True, "dmarc_fail": True,
                        "spf_pass": False, "dkim_pass": False, "dmarc_pass": False},
        }
        data = {
            "email_data": {"headers": headers, "body": {}},
            "authentication": auth,
        }
        result = correlate_evidence(data)
        corr_names = [c["name"] for c in result["correlations"]]
        assert "auth_failure_plus_sender" in corr_names

    def test_single_auth_failure_alone_no_sender_correlation(self):
        """A single auth failure without sender anomalies should NOT
        produce the combined correlation."""
        headers = {
            "reply_to_domain_mismatch": False,
            "display_name_analysis": {"possible_mismatch": False},
        }
        auth = {
            "status": {"spf": "fail", "dkim": "pass", "dmarc": "pass"},
            "signals": {"spf_fail": True, "dkim_fail": False, "dmarc_fail": False,
                        "spf_pass": False, "dkim_pass": True, "dmarc_pass": True},
        }
        data = {
            "email_data": {"headers": headers, "body": {}},
            "authentication": auth,
        }
        result = correlate_evidence(data)
        corr_names = [c["name"] for c in result["correlations"]]
        assert "auth_failure_plus_sender" not in corr_names


# ================================================================== #
#  6.  Urgency + credential request                                   #
# ================================================================== #

class TestSocialEngineeringCorrelation:

    def test_urgency_plus_credential(self):
        nlp = {"urgency_count": 3, "credential_count": 2,
               "financial_count": 0, "bec_count": 0}
        data = {"nlp": nlp}
        result = correlate_evidence(data)
        corr_names = [c["name"] for c in result["correlations"]]
        assert "social_engineering" in corr_names

    def test_urgency_alone_no_correlation(self):
        nlp = {"urgency_count": 3, "credential_count": 0,
               "financial_count": 0, "bec_count": 0}
        data = {"nlp": nlp}
        result = correlate_evidence(data)
        corr_names = [c["name"] for c in result["correlations"]]
        assert "social_engineering" not in corr_names


# ================================================================== #
#  7.  Suspicious attachment + embedded URL                           #
# ================================================================== #

class TestAttachmentUrlCorrelation:

    def test_suspicious_attachment_with_urls(self):
        data = {
            "attachment": {"suspicious_extension": True, "extension": ".exe"},
            "embedded_url_analyses": [{"url": "http://evil.com"}],
        }
        result = correlate_evidence(data)
        corr_names = [c["name"] for c in result["correlations"]]
        assert "suspicious_attachment_with_urls" in corr_names

    def test_clean_attachment_no_correlation(self):
        data = {
            "attachment": {"suspicious_extension": False, "extension": ".pdf"},
            "embedded_url_analyses": [{"url": "http://evil.com"}],
        }
        result = correlate_evidence(data)
        corr_names = [c["name"] for c in result["correlations"]]
        assert "suspicious_attachment_with_urls" not in corr_names


# ================================================================== #
#  8.  Static malware + attachment                                    #
# ================================================================== #

class TestMalwareAttachmentCorrelation:

    def test_malware_plus_suspicious_attachment(self):
        data = {
            "attachment": {"suspicious_extension": True, "extension": ".exe"},
            "malware_static": {"suspicious_strings": True},
        }
        result = correlate_evidence(data)
        corr_names = [c["name"] for c in result["correlations"]]
        assert "malware_plus_attachment" in corr_names

    def test_malware_no_suspicious_attachment(self):
        data = {
            "attachment": {"suspicious_extension": False},
            "malware_static": {"suspicious_strings": True},
        }
        result = correlate_evidence(data)
        corr_names = [c["name"] for c in result["correlations"]]
        assert "malware_plus_attachment" not in corr_names


# ================================================================== #
#  9.  Reputation + independent evidence                              #
# ================================================================== #

class TestReputationCorrelation:

    def test_vt_malicious_plus_independent(self):
        data = {
            "url_details": _url_details(
                url_features={"suspicious_keyword_count": 3},
                virustotal={"success": True, "found": True, "malicious": 5},
            ),
        }
        result = correlate_evidence(data)
        corr_names = [c["name"] for c in result["correlations"]]
        assert "reputation_corroborated" in corr_names

    def test_vt_malicious_alone_no_independent(self):
        """VirusTotal must NOT be the sole verdict."""
        data = {
            "url_details": _url_details(
                virustotal={"success": True, "found": True, "malicious": 5},
            ),
        }
        result = correlate_evidence(data)
        corr_names = [c["name"] for c in result["correlations"]]
        assert "reputation_corroborated" not in corr_names


# ================================================================== #
#  10.  Unknown evidence                                              #
# ================================================================== #

class TestUnknownEvidence:

    def test_unknown_items_exist(self):
        data = {
            "url_details": _url_details(
                domain_intelligence={"dns_error": True},
                webpage_analysis={"fetch_error": True},
                virustotal={"success": False, "error": "no key"},
            ),
            "ml": {"model_available": False},
        }
        result = correlate_evidence(data)
        assert len(result["unknown_evidence"]) >= 3
        for item in result["unknown_evidence"]:
            assert item["category"] == "unknown"


# ================================================================== #
#  11.  DNS failure is not malicious                                  #
# ================================================================== #

class TestDnsFailureNotMalicious:

    def test_dns_failure_is_unknown(self):
        data = {
            "url_details": _url_details(
                domain_intelligence={"dns_error": True},
            ),
        }
        result = correlate_evidence(data)
        dns_items = [e for e in result["evidence"]["domain"]
                     if e["signal"] == "dns_failure"]
        assert len(dns_items) == 1
        assert dns_items[0]["category"] == "unknown"
        # Must NOT appear in positive evidence.
        pos_signals = [e["signal"] for e in result["positive_evidence"]]
        assert "dns_failure" not in pos_signals


# ================================================================== #
#  12.  HTTPS alone is not malicious                                  #
# ================================================================== #

class TestHttpsNotMalicious:

    def test_https_is_neutral(self):
        data = {
            "url_details": _url_details(url="https://legit.com"),
        }
        # Patch url field.
        data["url_details"]["url"] = "https://legit.com"
        result = correlate_evidence(data)
        https_items = [e for e in result["evidence"]["url"]
                       if e["signal"] == "https_present"]
        assert len(https_items) == 1
        assert https_items[0]["category"] == "neutral"
        pos_signals = [e["signal"] for e in result["positive_evidence"]]
        assert "https_present" not in pos_signals


# ================================================================== #
#  13.  Tracking pixel alone is not phishing                          #
# ================================================================== #

class TestTrackingPixelNeutral:

    def test_tracking_pixel_is_neutral(self):
        data = {
            "url_details": _url_details(
                webpage_analysis={
                    "tracking_pixel": True,
                    "password_field_count": 0,
                },
            ),
        }
        result = correlate_evidence(data)
        pixel_items = [e for e in result["evidence"]["webpage"]
                       if e["signal"] == "tracking_pixel"]
        assert len(pixel_items) == 1
        assert pixel_items[0]["category"] == "neutral"
        pos_signals = [e["signal"] for e in result["positive_evidence"]]
        assert "tracking_pixel" not in pos_signals


# ================================================================== #
#  14.  Duplicate signals not double-counted                          #
# ================================================================== #

class TestNoDuplicateDoubleCount:

    def test_brand_signals_grouped(self):
        """brand_domain_mismatch should produce ONE brand evidence
        item, not separate items for detected brand, hostname match,
        and domain mismatch."""
        data = {
            "url_details": _url_details(
                brand_intelligence={
                    "brand_domain_mismatch": True,
                    "detected_brands": ["paypal"],
                    "hostname": "paypal.evil.com",
                    "registrable_domain": "evil.com",
                },
            ),
        }
        result = correlate_evidence(data)
        brand_items = result["evidence"]["brand"]
        assert len(brand_items) == 1
        assert brand_items[0]["signal"] == "brand_domain_mismatch"

    def test_email_identity_grouped(self):
        """Display-name mismatch + reply-to mismatch should produce
        ONE combined evidence item, not two separate items."""
        headers = {
            "reply_to_domain_mismatch": True,
            "display_name_analysis": {"possible_mismatch": True},
        }
        data = {"email_data": {"headers": headers, "body": {}}}
        result = correlate_evidence(data)
        email_items = result["evidence"]["email"]
        identity_items = [e for e in email_items
                          if "mismatch" in e["signal"]]
        assert len(identity_items) == 1
        assert identity_items[0]["signal"] == "sender_identity_mismatch"


# ================================================================== #
#  15.  Existing unified analyzer artifact types remain supported      #
# ================================================================== #

class TestUnifiedAnalyzerArtifactTypes:

    def test_correlate_empty_data(self):
        """Calling correlate_evidence with empty data should succeed
        and return the correct structure — no crashes."""
        result = correlate_evidence({})
        assert "evidence" in result
        assert "correlations" in result
        assert "positive_evidence" in result
        assert "negative_evidence" in result
        assert "unknown_evidence" in result
        assert "summary" in result

    def test_url_artifact_structure(self):
        """URL-style data should produce valid evidence."""
        data = {"url_details": _url_details()}
        result = correlate_evidence(data)
        assert isinstance(result["evidence"], dict)
        assert isinstance(result["correlations"], list)

    def test_email_artifact_structure(self):
        """Email-style data should produce valid evidence."""
        data = {"email_data": _email_data()}
        result = correlate_evidence(data)
        assert isinstance(result["evidence"], dict)

    def test_file_artifact_structure(self):
        """File-style data (with attachment + VT) should work."""
        data = {
            "url_details": {"virustotal": {}},
            "attachment": {"suspicious_extension": False},
        }
        result = correlate_evidence(data)
        assert isinstance(result["evidence"], dict)

    def test_qr_artifact_structure(self):
        """QR artifact data is just URL data — should work."""
        data = {"url_details": _url_details()}
        result = correlate_evidence(data)
        assert isinstance(result["correlations"], list)
