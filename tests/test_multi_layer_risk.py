import pytest

from src.analysis.multi_layer_risk import aggregate_multi_layer_risk


def test_aggregate_preserves_all_evidence_and_supplied_results():
    # Simulate a full analysis output where risk and correlation are already computed.
    mock_risk = type("RiskResult", (), {"score": 42, "level": "MEDIUM", "signals": []})()
    mock_correlation = {"correlations": [], "summary": "none"}
    analysis = {
        "ml": {"model_available": True, "probability": 0.85, "features": {"len": 10}},
        "url_details": {
            "domain_intelligence": {"is_ip_address": False, "registrar": "example"},
            "webpage_analysis": {"title": "Test Page", "meta": {"description": "example"}},
        },
        "email": {"headers": {"From": "phisher@example.com"}, "body": "Click here"},
        "attachment": {"files": [{"name": "doc.pdf", "type": "pdf"}]},
        "virustotal": {"malicious": False, "positives": 0},
        "final_risk": mock_risk,
        "correlated_evidence": mock_correlation,
        "explanation": {"summary": "test explanation"},
    }

    result = aggregate_multi_layer_risk(analysis)

    # Evidence pieces are passed through unchanged.
    assert result["ml_evidence"] == analysis["ml"]
    assert result["domain_evidence"] == analysis["url_details"]["domain_intelligence"]
    assert result["web_evidence"] == analysis["url_details"]["webpage_analysis"]
    assert result["email_evidence"] == analysis["email"]
    assert result["attachment_evidence"] == analysis["attachment"]
    assert result["threat_intel_evidence"] == analysis["virustotal"]
    # Supplied correlation and risk are preserved.
    assert result["correlated_evidence"] is mock_correlation
    assert result["final_risk"] is mock_risk
    # Explanation is also preserved.
    assert result["explanation"] == analysis["explanation"]


def test_aggregate_handles_missing_fields_gracefully():
    # Empty analysis dict – all optional fields should be None or empty defaults.
    analysis = {}
    result = aggregate_multi_layer_risk(analysis)

    assert result["ml_evidence"] is None
    assert result["domain_evidence"] is None
    assert result["web_evidence"] is None
    assert result["email_evidence"] is None
    assert result["attachment_evidence"] is None
    assert result["threat_intel_evidence"] is None
    # Correlated evidence defaults to empty dict when not supplied.
    assert result["correlated_evidence"] == {}
    # Final risk defaults to None.
    assert result["final_risk"] is None
    # Explanation defaults to empty dict.
    assert result["explanation"] == {}

