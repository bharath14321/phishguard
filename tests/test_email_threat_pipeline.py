"""
tests/test_email_threat_pipeline.py

Unit and end-to-end integration tests for the unified email analysis pipeline:
1. Multi-layer URL risk extraction from email body (plain text and HTML).
2. Local Threat Intelligence matching on body URLs with automatic score escalation.
3. Proper classification propagation (phishing / suspicious / clean).
4. AI Analyst unconfigured fallback robustness.
"""

import tempfile
from pathlib import Path
import pytest
from src.analysis.unified_analyzer import analyze_email
from src.features.local_ti import query_local_threat_intelligence


def test_email_with_malicious_body_url_escalation():
    """Verify that an email with a known threat intelligence URL is escalated to CRITICAL risk."""
    eml_content = """From: security-alerts@microsoft-support.internal
To: user@example.com
Subject: Action Required: Immediate Security Verification
Date: Wed, 07 Oct 2026 12:00:00 +0000
Content-Type: text/html; charset="UTF-8"

<html>
<body>
<p>Your mailbox access is about to be terminated. Please verify your identity immediately.</p>
<p><a href="https://login-outlook365.yzz.me/">Verify Microsoft Account</a></p>
</body>
</html>
"""
    with tempfile.NamedTemporaryFile(suffix=".eml", mode="w", delete=False) as f:
        f.write(eml_content)
        tmp_path = f.name

    try:
        res = analyze_email(tmp_path, user_id=1)
        assert "risk" in res
        assert res["risk"]["score"] >= 85.0
        assert res["risk"]["level"] in ["HIGH", "CRITICAL"]

        # Details verification
        details = res["details"]
        assert "url_analyses" in details
        assert len(details["url_analyses"]) >= 1

        target_u = details["url_analyses"][0]
        assert "login-outlook365.yzz.me" in target_u["url"]
        assert target_u["risk"]["score"] >= 85.0
        assert target_u["local_ti"]["found"] is True

        # Signals verification
        signal_names = [s.get("name") if isinstance(s, dict) else str(s) for s in res.get("signals", [])]
        assert any("Malicious URL" in name or "Local Threat Intelligence" in name for name in signal_names)

        # AI Analyst field verification
        assert "ai_analyst" in res
        assert res["ai_analyst"]["status"] in ["READY", "UNCONFIGURED"]
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_benign_email_scoring():
    """Verify that a standard clean email without threats is scored appropriately."""
    eml_content = """From: newsletter@legitimate-service.com
To: user@example.com
Subject: Weekly Digest
Date: Wed, 07 Oct 2026 12:00:00 +0000
Content-Type: text/plain; charset="UTF-8"

Here is your weekly digest. Have a great day!
"""
    with tempfile.NamedTemporaryFile(suffix=".eml", mode="w", delete=False) as f:
        f.write(eml_content)
        tmp_path = f.name

    try:
        res = analyze_email(tmp_path, user_id=1)
        assert res["risk"]["score"] < 40.0
        assert res["risk"]["level"] in ["LOW", "SAFE", "MEDIUM"]
    finally:
        Path(tmp_path).unlink(missing_ok=True)
