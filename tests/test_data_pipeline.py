"""
tests/test_data_pipeline.py

Comprehensive test suite for the automated data acquisition, threat intelligence,
evidence sufficiency, conditional VirusTotal escalation, and candidate training pipeline.
"""

import os
import json
import sqlite3
import pytest
from pathlib import Path
import pandas as pd

from src.analysis.evidence_sufficiency import (
    compute_evidence_sufficiency,
    should_query_virustotal,
    SufficiencyLevel,
    EvidenceClass,
    ti_cache
)
from scripts.data_pipeline.build_ti_database import init_db, query_local_ti
from scripts.data_pipeline.leakage_check import check_dataset_leakage, normalize_url
from scripts.data_pipeline.download_sources import load_sources_config


# ---------------------------------------------------------------------------
# 1. Evidence Sufficiency & Independent Class Tests
# ---------------------------------------------------------------------------

def test_evidence_sufficiency_empty_analysis():
    """Empty or None analysis returns score 0 and INSUFFICIENT level."""
    res = compute_evidence_sufficiency({})
    assert res.score == 0.0
    assert res.level == SufficiencyLevel.INSUFFICIENT
    assert res.evidence_classes_present == []


def test_evidence_sufficiency_multi_layer_strong():
    """Multi-layer evidence produces a STRONG or VERY_STRONG sufficiency score."""
    analysis = {
        "ml": {"model_available": True, "probability": 0.92},
        "domain_intelligence": {"domain": "phish-test.xyz", "creation_date": "2026-09-01", "is_ip_address": False},
        "brand_intelligence": {"impersonated_brand": "Microsoft"},
        "local_ti": {"found": True, "source": "phishtank"},
    }
    res = compute_evidence_sufficiency(analysis)
    assert res.score >= 60.0
    assert res.level in (SufficiencyLevel.STRONG, SufficiencyLevel.VERY_STRONG)
    assert EvidenceClass.MODEL.value in res.evidence_classes_present
    assert EvidenceClass.DOMAIN.value in res.evidence_classes_present
    assert EvidenceClass.CONTENT.value in res.evidence_classes_present
    assert EvidenceClass.LOCAL_TI.value in res.evidence_classes_present


def test_conditional_virustotal_local_ti_match():
    """If local TI has a match, external VirusTotal query is skipped."""
    analysis = {
        "local_ti": {"found": True, "source": "phishtank", "classification": "phishing"}
    }
    should_query, reason = should_query_virustotal(analysis, has_api_key=True)
    assert should_query is False
    assert "local threat intelligence" in reason.lower()


def test_conditional_virustotal_high_sufficiency_skip():
    """When native evidence is sufficient (>=70) with multiple classes, VT is skipped."""
    analysis = {
        "ml": {"model_available": True, "probability": 0.98},
        "domain_intelligence": {"domain": "login-secure-verify.xyz", "domain_age_days": 2},
        "webpage_analysis": {"status_code": 200, "has_password_input": True},
        "brand_intelligence": {"impersonated_brand": "Google"},
    }
    should_query, reason = should_query_virustotal(analysis, has_api_key=True)
    assert should_query is False
    assert "native evidence is sufficient" in reason.lower()


def test_conditional_virustotal_insufficient_escalate():
    """When native evidence is sparse or insufficient (<70), escalate to VirusTotal."""
    analysis = {
        "url_features": {"url_length": 35}, # Only sparse feature
    }
    should_query, reason = should_query_virustotal(analysis, has_api_key=True)
    assert should_query is True
    assert "escalating to virustotal" in reason.lower()


# ---------------------------------------------------------------------------
# 2. Threat Intel Cache Tests
# ---------------------------------------------------------------------------

def test_threat_intel_cache_lifecycle():
    """Verify TI cache stores and retrieves entries before expiration."""
    ti_cache.clear()
    assert ti_cache.get("url", "https://example.com") is None

    ti_cache.set("url", "https://example.com", "virustotal", {"positives": 5}, ttl=60)
    cached = ti_cache.get("url", "https://example.com")
    assert cached is not None
    assert cached["positives"] == 5


# ---------------------------------------------------------------------------
# 3. Local TI Database Lookup Tests
# ---------------------------------------------------------------------------

def test_local_ti_db_query(tmp_path):
    """Test SQLite TI database creation and fast indicator indexing."""
    db_file = tmp_path / "test_ti.db"
    conn = init_db(db_file)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO local_indicators (indicator, indicator_type, source, classification, family, tags, confidence, first_seen, last_seen, ingested_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, ("http://malicious-test.com/login", "url", "phishtank", "phishing", "generic", "verified:true", 95, "2026-10-01", "2026-10-01", "2026-10-01T00:00:00"))
    conn.commit()
    conn.close()

    result = query_local_ti("http://malicious-test.com/login", indicator_type="url", db_path=db_file)
    assert result is not None
    assert result["found"] is True
    assert result["source"] == "phishtank"
    assert result["classification"] == "phishing"


# ---------------------------------------------------------------------------
# 4. Leakage & Overlap Audit Tests
# ---------------------------------------------------------------------------

def test_leakage_detection_exact_duplicates():
    """Audits flag exact URL duplicates and calculate correct report status."""
    df_train = pd.DataFrame({
        "url": ["http://a.com", "http://b.com", "http://a.com", "http://c.com"],
        "label": [1, 0, 1, 0]
    })
    report = check_dataset_leakage(df_train)
    assert report["exact_duplicates"] == 2
    assert report["label_conflicts"] == 0


def test_leakage_detection_train_test_overlap():
    """Audits detect contamination between train and test splits."""
    df_train = pd.DataFrame({
        "url": ["http://site1.com/p", "http://site2.com/p"],
        "label": [1, 0]
    })
    df_test = pd.DataFrame({
        "url": ["http://site1.com/p", "http://clean.com"],
        "label": [1, 0]
    })
    report = check_dataset_leakage(df_train, test_df=df_test)
    assert report["train_test_overlap"] == 1


# ---------------------------------------------------------------------------
# 5. Sources Configuration Tests
# ---------------------------------------------------------------------------

def test_sources_configuration_loading():
    """Verify configured sources can be loaded with mandatory properties."""
    sources = load_sources_config()
    assert len(sources) >= 5
    source_names = [s["name"] for s in sources]
    assert "malicious_phish" in source_names
    assert "phishtank" in source_names
    assert "openphish" in source_names
    assert "urlhaus" in source_names
    assert "malwarebazaar" in source_names


# ---------------------------------------------------------------------------
# 6. Domain, IP, Email Auth & Risk Boundary Tests
# ---------------------------------------------------------------------------

def test_domain_intelligence_idn_and_evidence():
    """Domain intelligence detects IDN/Punycode and builds domain evidence summary."""
    from src.features.domain_intelligence import analyze_domain
    res_puny = analyze_domain("http://xn--pple-43d.com/login")
    assert res_puny["is_punycode"] is True
    assert res_puny["is_idn"] is True
    assert any("Punycode" in item for item in res_puny["domain_evidence_summary"])


def test_ip_intelligence_direct_and_evidence():
    """IP intelligence accurately categorizes direct IP hosts and private status."""
    from src.features.ip_intelligence import analyze_url_ip
    res_ip = analyze_url_ip("http://192.168.1.50/admin")
    assert res_ip["is_ip_address"] is True
    assert any("Private" in item for item in res_ip["ip_evidence_summary"])


def test_email_authentication_separation():
    """Email authentication separates header results from published DNS policy."""
    from src.features.email_authentication import analyze_email_authentication

    class MockMsg:
        def get_all(self, header, default):
            return ["spf=pass; dkim=pass; dmarc=pass"]
        def get(self, header, default=""):
            return "security@paypal.com"

    auth_res = analyze_email_authentication(MockMsg())
    assert auth_res["message_authentication"]["spf"] == "pass"
    assert auth_res["message_authentication"]["dkim"] == "pass"
    assert auth_res["published_dns_policy"]["published_spf"] == "unknown"


def test_risk_level_boundaries():
    """Verify exact engineering thresholds: 0-24 LOW, 25-49 MEDIUM, 50-74 HIGH, 75-100 CRITICAL."""
    from src.analysis.risk_engine import determine_risk_level
    assert determine_risk_level(0) == "LOW"
    assert determine_risk_level(24.9) == "LOW"
    assert determine_risk_level(25) == "MEDIUM"
    assert determine_risk_level(49.9) == "MEDIUM"
    assert determine_risk_level(50) == "HIGH"
    assert determine_risk_level(74.9) == "HIGH"
    assert determine_risk_level(75) == "CRITICAL"
    assert determine_risk_level(100) == "CRITICAL"


def test_unified_analyzer_sufficiency_integration():
    """Unified analyzer attaches evidence_sufficiency and vt_escalation metadata."""
    from src.analysis.unified_analyzer import analyze_url
    resp = analyze_url("http://example.com", user_id=1)
    assert "evidence_sufficiency" in resp
    suff = resp["evidence_sufficiency"]
    assert "score" in suff
    assert "level" in suff
    assert "vt_escalation" in suff
    assert "should_query" in suff["vt_escalation"]

