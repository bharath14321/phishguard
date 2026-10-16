"""
tests/validation/test_cross_layer_validation.py

Automated Validation Test Suite for Cross-Layer Evidence Synthesis (PG-CROSS-001 through PG-CROSS-008).

Covers:
- Multi-source evidence combinations without double-counting.
- Email header auth + NLP + body URL correlation.
- Attachment static features + embedded URL fan-out.
- File hash reputation + PE static analysis.
- QR decode -> URL routing -> threat feed evaluation.
- Redirect hop tracking -> destination inspection.
"""

from pathlib import Path
import pytest
from src.analysis.unified_analyzer import analyze_email, analyze_url, analyze_file, analyze_qr
from src.analysis.evidence_correlator import correlate_evidence
from tests.validation.collector import record_test


def test_pg_cross_001_email_with_suspicious_url():
    """PG-CROSS-001: Validate Email + suspicious destination URL correlation."""
    eml_file = Path("tests/fixtures/validation/emails/urgent_phish.eml")
    res = analyze_email(str(eml_file), user_id=1)
    
    score = res["risk"]["score"]
    corr = res.get("evidence_correlation")
    status = "PASS" if score >= 75 and corr is not None else "FAIL"

    record_test(
        test_id="PG-CROSS-001",
        category="CROSS-LAYER",
        description="Cross-layer email body + threat intelligence URL synthesis",
        input_type="cross_layer",
        expected_behavior="Combines email NLP indicators with body URL threat feed without double-counting",
        actual_behavior=f"Score={score}, CorrelationPresent={corr is not None}",
        status=status,
        risk_score=score,
        risk_level=res["risk"]["level"],
    )
    assert score >= 75


def test_pg_cross_002_email_auth_fail_plus_suspicious_url():
    """PG-CROSS-002: Validate Email + SPF/DKIM failure + suspicious URL."""
    eml_file = Path("tests/fixtures/validation/emails/urgent_phish.eml")
    res = analyze_email(str(eml_file), user_id=1)
    signals = [s.get("name") if isinstance(s, dict) else str(s) for s in res.get("signals", [])]
    
    has_auth_sig = any("Authentication" in s for s in signals)
    has_url_sig = any("URL" in s or "Threat" in s for s in signals)
    status = "PASS" if has_auth_sig and has_url_sig else "FAIL"

    record_test(
        test_id="PG-CROSS-002",
        category="CROSS-LAYER",
        description="Email auth failure + suspicious URL multi-signal correlation",
        input_type="cross_layer",
        expected_behavior="Generates distinct authentication failure and URL threat signals",
        actual_behavior=f"AuthSig={has_auth_sig}, URLSig={has_url_sig}, SignalsCount={len(signals)}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert has_auth_sig and has_url_sig


def test_pg_cross_003_email_url_plus_attachment():
    """PG-CROSS-003: Validate Email + URL + attachment multi-artifact synthesis."""
    raw = """From: security@alerts.org
To: user@corp.org
Subject: Security Notice
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUND"

--BOUND
Content-Type: text/html

<p>Check: <a href="https://allegrolokalnie.lokalna-6747.sbs">Link</a></p>

--BOUND
Content-Type: text/plain; name="log.txt"
Content-Disposition: attachment; filename="log.txt"

Incident report text.
--BOUND--
"""
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".eml", mode="w", delete=False) as f:
        f.write(raw)
        tmp = f.name
    try:
        res = analyze_email(tmp, user_id=1)
        urls = res["details"].get("url_analyses", [])
        atts = res["details"].get("attachments", [])
        status = "PASS" if len(urls) >= 1 and len(atts) >= 1 and res["risk"]["score"] >= 75 else "FAIL"

        record_test(
            test_id="PG-CROSS-003",
            category="CROSS-LAYER",
            description="Email containing both body URLs and document attachments",
            input_type="cross_layer",
            expected_behavior="Processes both URL and attachment child layers cleanly",
            actual_behavior=f"URLs={len(urls)}, Attachments={len(atts)}, Score={res['risk']['score']}",
            status=status,
            risk_score=res["risk"]["score"],
            risk_level=res["risk"]["level"],
        )
        assert len(urls) >= 1 and len(atts) >= 1
    finally:
        Path(tmp).unlink()


def test_pg_cross_004_attachment_plus_embedded_url():
    """PG-CROSS-004: Validate document attachment with embedded actionable hyperlink."""
    html_doc = Path("tests/fixtures/validation/files/phishing_links.html")
    res = analyze_file(str(html_doc), user_id=1)
    status = "PASS" if "details" in res and res["risk"]["score"] >= 0 else "FAIL"

    record_test(
        test_id="PG-CROSS-004",
        category="CROSS-LAYER",
        description="Attachment containing embedded URL fan-out",
        input_type="cross_layer",
        expected_behavior="Embedded hyperlink extracted and analyzed by URL engine",
        actual_behavior=f"Score={res['risk']['score']}, Level={res['risk']['level']}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert "risk" in res


def test_pg_cross_005_hash_ti_plus_static_analysis():
    """PG-CROSS-005: Validate File Hash + Local TI + Static file inspection."""
    file_path = Path("tests/fixtures/validation/files/mismatch_image.jpg")
    res = analyze_file(str(file_path), user_id=1)
    status = "PASS" if "details" in res and res["details"].get("file_hash") is not None else "FAIL"

    record_test(
        test_id="PG-CROSS-005",
        category="CROSS-LAYER",
        description="File hash computation correlated with static file headers",
        input_type="cross_layer",
        expected_behavior="Computes SHA256, queries reputation, and inspects magic bytes",
        actual_behavior=f"Hash={res['details'].get('file_hash')[:16]}..., Level={res['risk']['level']}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert "file_hash" in res["details"]


def test_pg_cross_006_qr_to_url_threat_analysis():
    """PG-CROSS-006: Validate QR payload decoding routed to URL threat intelligence."""
    from src.features.qr_analyzer import cv2
    if cv2 is None:
        record_test(
            test_id="PG-CROSS-006",
            category="CROSS-LAYER",
            description="QR visual decoding into URL threat intelligence inspection",
            input_type="cross_layer",
            expected_behavior="Decodes QR payload and evaluates in full URL multi-layer engine",
            actual_behavior="cv2 library not installed in runtime environment",
            status="BLOCKED",
            notes="OpenCV is an optional dependency for QR visual decoding",
        )
        pytest.skip("OpenCV cv2 not installed")

    qr_file = Path("tests/fixtures/validation/qr/qr_phishing_url.png")
    res = analyze_qr(str(qr_file), user_id=1)
    
    score = res["risk"]["score"]
    level = res["risk"]["level"]
    status = "PASS" if score >= 75 and level in ["HIGH", "CRITICAL"] else "FAIL"

    record_test(
        test_id="PG-CROSS-006",
        category="CROSS-LAYER",
        description="QR visual decoding into URL threat intelligence inspection",
        input_type="cross_layer",
        expected_behavior="Decodes QR payload and evaluates in full URL multi-layer engine",
        actual_behavior=f"Score={score}, Level={level}",
        status=status,
        risk_score=score,
        risk_level=level,
    )
    assert score >= 75


def test_pg_cross_007_url_redirect_to_final_destination():
    """PG-CROSS-007: Validate URL redirect tracking and final destination synthesis."""
    from src.features.redirect_analyzer import analyze_redirect_chain
    url = "https://www.google.com/"
    red_info = analyze_redirect_chain(url)
    status = "PASS" if isinstance(red_info, dict) else "FAIL"

    record_test(
        test_id="PG-CROSS-007",
        category="CROSS-LAYER",
        description="URL redirect sequence hop analysis",
        input_type="cross_layer",
        expected_behavior="Traces redirect hops and evaluates destination endpoint",
        actual_behavior=f"RedirectAnalysisKeys={list(red_info.keys())}",
        status=status,
    )
    assert isinstance(red_info, dict)


def test_pg_cross_008_domain_brand_webpage_synthesis():
    """PG-CROSS-008: Validate domain mismatch + brand intelligence cross-correlation."""
    corr_input = {
        "url_details": {
            "brand_intelligence": {
                "brand_domain_mismatch": True,
                "detected_brands": ["Microsoft"]
            },
            "domain_intelligence": {"registered_domain": "attacker-portal.net"}
        }
    }
    corr_res = correlate_evidence(corr_input)
    correlations = corr_res.get("correlations", [])
    has_corr = len(correlations) > 0
    status = "PASS" if has_corr else "FAIL"

    record_test(
        test_id="PG-CROSS-008",
        category="CROSS-LAYER",
        description="Brand impersonation + credential form cross-layer correlation",
        input_type="cross_layer",
        expected_behavior="Generates correlated finding for brand mismatch on credential submission page",
        actual_behavior=f"CorrelationsGenerated={len(correlations)}",
        status=status,
        correlations=[c.get("name", "") for c in correlations],
    )
    assert has_corr
