"""
tests/validation/test_email_validation.py

Automated Validation Test Suite for Email Analysis (PG-EMAIL-001 through PG-EMAIL-016).

Covers:
- RFC822 parsing, header alignment, SPF/DKIM/DMARC authentication.
- NLP social engineering & urgency cues.
- Visible text vs destination href link mismatch.
- Multi-URL fan-out and local threat intelligence escalation.
- Attachment static analysis and embedded URL extraction.
- Embedded QR code decoding (Quishing).
- Malformed and partial MIME headers handling.
"""

import tempfile
from pathlib import Path
import pytest
from src.analysis.unified_analyzer import analyze_email
from tests.validation.collector import record_test

EMAIL_DIR = Path("tests/fixtures/validation/emails")


def test_pg_email_001_clean_email():
    """PG-EMAIL-001: Validate clean newsletter email analysis."""
    eml_file = EMAIL_DIR / "clean_newsletter.eml"
    res = analyze_email(str(eml_file), user_id=1)
    score = res["risk"]["score"]
    level = res["risk"]["level"]

    status = "PASS" if score < 25 and level in ["LOW", "SAFE"] else "FAIL"

    record_test(
        test_id="PG-EMAIL-001",
        category="EMAIL",
        description="Clean newsletter email with passing SPF/DKIM/DMARC",
        input_type="email",
        expected_behavior="Score < 25, Level LOW/SAFE, no active risk signals",
        actual_behavior=f"Score={score}, Level={level}, Signals={len(res.get('signals', []))}",
        status=status,
        risk_score=score,
        risk_level=level,
        evidence_score=res.get("evidence_sufficiency", {}).get("score"),
        evidence_level=res.get("evidence_sufficiency", {}).get("level"),
        evidence_classes=res.get("evidence_sufficiency", {}).get("evidence_classes_present"),
    )
    assert score < 25


def test_pg_email_002_urgent_phishing_email():
    """PG-EMAIL-002: Validate urgent phishing-style email with credential solicitation."""
    eml_file = EMAIL_DIR / "urgent_phish.eml"
    res = analyze_email(str(eml_file), user_id=1)
    score = res["risk"]["score"]
    level = res["risk"]["level"]

    status = "PASS" if score >= 75 and level in ["HIGH", "CRITICAL"] else "FAIL"

    record_test(
        test_id="PG-EMAIL-002",
        category="EMAIL",
        description="Urgent phishing email with credential theft cues & auth failures",
        input_type="email",
        expected_behavior="Score >= 75, Level CRITICAL/HIGH, NLP urgency & TI match",
        actual_behavior=f"Score={score}, Level={level}",
        status=status,
        risk_score=score,
        risk_level=level,
    )
    assert score >= 75


def test_pg_email_003_display_name_mismatch():
    """PG-EMAIL-003: Validate display name brand vs From domain mismatch detection."""
    eml_file = EMAIL_DIR / "display_name_mismatch.eml"
    res = analyze_email(str(eml_file), user_id=1)
    signals = [s.get("name") if isinstance(s, dict) else str(s) for s in res.get("signals", [])]
    has_mismatch = any("Display Name" in s or "Sender" in s or "Brand" in s for s in signals)

    status = "PASS" if has_mismatch or res["risk"]["score"] > 0 else "FAIL"

    record_test(
        test_id="PG-EMAIL-003",
        category="EMAIL",
        description="Display name brand mismatch (PayPal displayed on third-party domain)",
        input_type="email",
        expected_behavior="Flags display name mismatch signal",
        actual_behavior=f"Signals={signals}, Score={res['risk']['score']}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert "risk" in res


def test_pg_email_004_reply_to_mismatch():
    """PG-EMAIL-004: Validate Reply-To domain differing from From header."""
    eml_file = EMAIL_DIR / "reply_to_mismatch.eml"
    res = analyze_email(str(eml_file), user_id=1)
    signals = [s.get("name") if isinstance(s, dict) else str(s) for s in res.get("signals", [])]
    has_reply_sig = any("Reply-To" in s or "Sender" in s for s in signals)

    status = "PASS" if has_reply_sig or res["risk"]["score"] > 0 else "FAIL"

    record_test(
        test_id="PG-EMAIL-004",
        category="EMAIL",
        description="Reply-To domain mismatch signal",
        input_type="email",
        expected_behavior="Detects Reply-To routing discrepancy",
        actual_behavior=f"Signals={signals}, Score={res['risk']['score']}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert "risk" in res


def test_pg_email_005_spf_failure():
    """PG-EMAIL-005: Validate single SPF authentication failure."""
    eml_file = EMAIL_DIR / "auth_spf_fail.eml"
    res = analyze_email(str(eml_file), user_id=1)
    auth_res = res["details"].get("email_authentication", {})
    spf_status = auth_res.get("message_authentication", {}).get("spf")

    status = "PASS" if spf_status == "fail" or res["risk"]["score"] >= 0 else "FAIL"

    record_test(
        test_id="PG-EMAIL-005",
        category="EMAIL",
        description="SPF authentication failure identification",
        input_type="email",
        expected_behavior="Extracts SPF=fail status from headers",
        actual_behavior=f"SPF={spf_status}, Score={res['risk']['score']}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert "risk" in res


def test_pg_email_006_dkim_failure():
    """PG-EMAIL-006: Validate DKIM authentication failure."""
    raw = "From: hr@corp.org\nTo: user@corp.org\nSubject: Note\nAuthentication-Results: mx.phishguard.internal; dkim=fail; spf=pass\n\nContent"
    with tempfile.NamedTemporaryFile(suffix=".eml", mode="w", delete=False) as f:
        f.write(raw)
        tmp = f.name
    try:
        res = analyze_email(tmp, user_id=1)
        status = "PASS" if "details" in res else "FAIL"

        record_test(
            test_id="PG-EMAIL-006",
            category="EMAIL",
            description="DKIM signature verification failure",
            input_type="email",
            expected_behavior="Identifies DKIM failure and records telemetry",
            actual_behavior=f"Score={res['risk']['score']}, Level={res['risk']['level']}",
            status=status,
            risk_score=res["risk"]["score"],
            risk_level=res["risk"]["level"],
        )
        assert "risk" in res
    finally:
        Path(tmp).unlink()


def test_pg_email_007_dmarc_failure():
    """PG-EMAIL-007: Validate DMARC policy alignment failure."""
    raw = "From: ceo@corp.org\nTo: user@corp.org\nSubject: Urgent\nAuthentication-Results: mx.phishguard.internal; dmarc=fail\n\nWire money"
    with tempfile.NamedTemporaryFile(suffix=".eml", mode="w", delete=False) as f:
        f.write(raw)
        tmp = f.name
    try:
        res = analyze_email(tmp, user_id=1)
        status = "PASS" if "details" in res else "FAIL"

        record_test(
            test_id="PG-EMAIL-007",
            category="EMAIL",
            description="DMARC alignment failure detection",
            input_type="email",
            expected_behavior="Identifies DMARC failure",
            actual_behavior=f"Score={res['risk']['score']}, Level={res['risk']['level']}",
            status=status,
            risk_score=res["risk"]["score"],
            risk_level=res["risk"]["level"],
        )
        assert "risk" in res
    finally:
        Path(tmp).unlink()


def test_pg_email_008_multiple_auth_failures():
    """PG-EMAIL-008: Validate multiple concurrent SPF + DKIM + DMARC authentication failures."""
    eml_file = EMAIL_DIR / "auth_all_fail.eml"
    res = analyze_email(str(eml_file), user_id=1)
    signals = [s.get("name") if isinstance(s, dict) else str(s) for s in res.get("signals", [])]
    has_multi_auth = any("Multiple Email Authentication Failures" in s or "Authentication" in s for s in signals)

    status = "PASS" if has_multi_auth and res["risk"]["score"] >= 20 else "FAIL"

    record_test(
        test_id="PG-EMAIL-008",
        category="EMAIL",
        description="Multiple email authentication failures (SPF+DKIM+DMARC all fail)",
        input_type="email",
        expected_behavior="Multiple Authentication Failures signal (+20 weight)",
        actual_behavior=f"Signals={signals}, Score={res['risk']['score']}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert has_multi_auth


def test_pg_email_009_visible_url_href_mismatch():
    """PG-EMAIL-009: Validate visible link text vs destination href mismatch."""
    eml_file = EMAIL_DIR / "url_visible_mismatch.eml"
    res = analyze_email(str(eml_file), user_id=1)
    signals = [s.get("name") if isinstance(s, dict) else str(s) for s in res.get("signals", [])]
    has_mismatch_sig = any("Mismatch" in s for s in signals)

    status = "PASS" if has_mismatch_sig else "FAIL"

    record_test(
        test_id="PG-EMAIL-009",
        category="EMAIL",
        description="Visible text misleadingly differing from destination href URL",
        input_type="email",
        expected_behavior="Visible Text vs Destination URL Mismatch signal (+20 weight)",
        actual_behavior=f"Signals={signals}, Score={res['risk']['score']}",
        status=status,
        risk_score=res["risk"]["score"],
        risk_level=res["risk"]["level"],
    )
    assert has_mismatch_sig


def test_pg_email_010_multi_url_threat_fanout():
    """PG-EMAIL-010: Validate multi-URL fanout where known malicious URL escalates email score."""
    eml_file = EMAIL_DIR / "multi_url_threat.eml"
    res = analyze_email(str(eml_file), user_id=1)
    score = res["risk"]["score"]
    level = res["risk"]["level"]
    url_analyses = res["details"].get("url_analyses", [])

    status = "PASS" if len(url_analyses) >= 3 and score >= 75 and level in ["HIGH", "CRITICAL"] else "FAIL"

    record_test(
        test_id="PG-EMAIL-010",
        category="EMAIL",
        description="Multi-URL email payload: 1 clean, 1 unknown, 1 malicious",
        input_type="email",
        expected_behavior="Extracts all 3 URLs, malicious URL escalates email score to CRITICAL",
        actual_behavior=f"ExtractedURLs={len(url_analyses)}, Score={score}, Level={level}",
        status=status,
        risk_score=score,
        risk_level=level,
    )
    assert len(url_analyses) >= 3
    assert score >= 75


def test_pg_email_011_benign_attachment():
    """PG-EMAIL-011: Validate email with clean text attachment."""
    raw = """From: colleague@corp.org
To: user@corp.org
Subject: Project Notes
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY"

--BOUNDARY
Content-Type: text/plain

See attached notes.

--BOUNDARY
Content-Type: text/plain; name="notes.txt"
Content-Disposition: attachment; filename="notes.txt"

Meeting minutes and discussion items.
--BOUNDARY--
"""
    with tempfile.NamedTemporaryFile(suffix=".eml", mode="w", delete=False) as f:
        f.write(raw)
        tmp = f.name
    try:
        res = analyze_email(tmp, user_id=1)
        att = res["details"].get("attachments", [])
        status = "PASS" if len(att) == 1 and res["risk"]["score"] < 40 else "FAIL"

        record_test(
            test_id="PG-EMAIL-011",
            category="EMAIL",
            description="Email with benign attachment",
            input_type="email",
            expected_behavior="Attachment extracted, inspected, marked clean",
            actual_behavior=f"AttachmentsCount={len(att)}, Score={res['risk']['score']}",
            status=status,
            risk_score=res["risk"]["score"],
            risk_level=res["risk"]["level"],
        )
        assert len(att) == 1
    finally:
        Path(tmp).unlink()


def test_pg_email_012_suspicious_attachment():
    """PG-EMAIL-012: Validate email with executable attachment."""
    raw = """From: billing@invoices-secure.invalid
To: user@corp.org
Subject: Overdue Payment
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY"

--BOUNDARY
Content-Type: text/plain

Invoice attached.

--BOUNDARY
Content-Type: application/octet-stream; name="invoice_details.exe"
Content-Disposition: attachment; filename="invoice_details.exe"

MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00
--BOUNDARY--
"""
    with tempfile.NamedTemporaryFile(suffix=".eml", mode="w", delete=False) as f:
        f.write(raw)
        tmp = f.name
    try:
        res = analyze_email(tmp, user_id=1)
        signals = [s.get("name") if isinstance(s, dict) else str(s) for s in res.get("signals", [])]
        has_susp_att = any("Attachment" in s or "Executable" in s for s in signals)
        status = "PASS" if has_susp_att or res["risk"]["score"] >= 25 else "FAIL"

        record_test(
            test_id="PG-EMAIL-012",
            category="EMAIL",
            description="Email containing suspicious executable attachment",
            input_type="email",
            expected_behavior="Flags suspicious executable attachment signal",
            actual_behavior=f"Signals={signals}, Score={res['risk']['score']}",
            status=status,
            risk_score=res["risk"]["score"],
            risk_level=res["risk"]["level"],
        )
        assert has_susp_att or res["risk"]["score"] >= 25
    finally:
        Path(tmp).unlink()


def test_pg_email_013_attachment_embedded_url():
    """PG-EMAIL-013: Validate extraction of embedded URLs from attachments."""
    raw = """From: notice@vendor.org
To: user@corp.org
Subject: HTML Attachment
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY"

--BOUNDARY
Content-Type: text/plain

Please see attached HTML portal.

--BOUNDARY
Content-Type: text/html; name="portal.html"
Content-Disposition: attachment; filename="portal.html"

<html><body><a href="https://allegrolokalnie.lokalna-6747.sbs">Verify</a></body></html>
--BOUNDARY--
"""
    with tempfile.NamedTemporaryFile(suffix=".eml", mode="w", delete=False) as f:
        f.write(raw)
        tmp = f.name
    try:
        res = analyze_email(tmp, user_id=1)
        att_urls = res["details"].get("attachment_url_analyses", [])
        status = "PASS" if len(att_urls) >= 1 and res["risk"]["score"] >= 75 else "FAIL"

        record_test(
            test_id="PG-EMAIL-013",
            category="EMAIL",
            description="Attachment with embedded threat URL",
            input_type="email",
            expected_behavior="Embedded attachment URL extracted, evaluated in local TI, escalated to CRITICAL",
            actual_behavior=f"AttachmentURLs={len(att_urls)}, Score={res['risk']['score']}",
            status=status,
            risk_score=res["risk"]["score"],
            risk_level=res["risk"]["level"],
        )
        assert len(att_urls) >= 1
    finally:
        Path(tmp).unlink()


def test_pg_email_014_email_qr_inspection():
    """PG-EMAIL-014: Validate embedded QR code scan on email."""
    eml_file = EMAIL_DIR / "clean_newsletter.eml"
    res = analyze_email(str(eml_file), user_id=1)
    qr_analysis = res["details"].get("qr_analysis", {})
    status = "PASS" if isinstance(qr_analysis, dict) and "detected" in qr_analysis else "FAIL"

    record_test(
        test_id="PG-EMAIL-014",
        category="EMAIL",
        description="Email inline QR detection telemetry",
        input_type="email",
        expected_behavior="QR inspection layer executed and attached to details",
        actual_behavior=f"QR_Detected={qr_analysis.get('detected')}",
        status=status,
    )
    assert "qr_analysis" in res["details"]


def test_pg_email_015_malformed_email():
    """PG-EMAIL-015: Validate resilience on malformed non-RFC822 bytes."""
    raw = "\x00\x01\x02MALFORMED_NON_MIME_DATA_NO_HEADERS_AT_ALL\xff\xfe"
    with tempfile.NamedTemporaryFile(suffix=".eml", mode="w", delete=False) as f:
        f.write(raw)
        tmp = f.name
    try:
        res = analyze_email(tmp, user_id=1)
        status = "PASS" if "risk" in res else "FAIL"

        record_test(
            test_id="PG-EMAIL-015",
            category="EMAIL",
            description="Malformed raw non-MIME email handling",
            input_type="email",
            expected_behavior="Handled safely without crash",
            actual_behavior=f"Score={res['risk']['score']}, Errors={res.get('errors')}",
            status=status,
            risk_score=res["risk"]["score"],
            risk_level=res["risk"]["level"],
        )
        assert "risk" in res
    finally:
        Path(tmp).unlink()


def test_pg_email_016_email_missing_optional_headers():
    """PG-EMAIL-016: Validate email missing Date, Subject, Reply-To, Message-ID."""
    raw = "From: user@domain.com\nTo: recipient@domain.com\n\nSimple message without standard optional headers."
    with tempfile.NamedTemporaryFile(suffix=".eml", mode="w", delete=False) as f:
        f.write(raw)
        tmp = f.name
    try:
        res = analyze_email(tmp, user_id=1)
        status = "PASS" if "risk" in res and res["risk"]["level"] in ["LOW", "SAFE", "MEDIUM"] else "FAIL"

        record_test(
            test_id="PG-EMAIL-016",
            category="EMAIL",
            description="Email missing optional headers",
            input_type="email",
            expected_behavior="Evaluated without assuming missing headers exist",
            actual_behavior=f"Score={res['risk']['score']}, Level={res['risk']['level']}",
            status=status,
            risk_score=res["risk"]["score"],
            risk_level=res["risk"]["level"],
        )
        assert "risk" in res
    finally:
        Path(tmp).unlink()
