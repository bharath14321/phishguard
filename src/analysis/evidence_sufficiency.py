"""
src/analysis/evidence_sufficiency.py

Evidence Sufficiency and Independent Evidence Class Evaluation Engine.

Provides:
1. Evidence Sufficiency Score (0-100) and Level (INSUFFICIENT, LIMITED, STRONG, VERY_STRONG)
2. Evaluation of Independent Evidence Classes to prevent double-counting
3. VirusTotal Escalation Policy Evaluation (Native First -> Conditional VT)
4. Threat Intelligence Multi-Layer Cache
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class SufficiencyLevel(str, Enum):
    """Evidence sufficiency category."""
    INSUFFICIENT = "INSUFFICIENT"  # 0-39
    LIMITED = "LIMITED"            # 40-59
    STRONG = "STRONG"              # 60-79
    VERY_STRONG = "VERY_STRONG"    # 80-100


class EvidenceClass(str, Enum):
    """Independent classes of security evidence."""
    MODEL = "MODEL"                # Machine Learning inference predictions
    DOMAIN = "DOMAIN"              # DNS, WHOIS, Age, TLD, Punycode, Typosquatting
    IP = "IP"                      # ASN, geolocation, raw IP usage
    EMAIL_AUTH = "EMAIL_AUTH"      # SPF, DKIM, DMARC validation
    CONTENT = "CONTENT"            # Natural language processing, urgency, brand impersonation
    WEBPAGE = "WEBPAGE"            # DOM structure, form action, login inputs, scripts
    FILE_STATIC = "FILE_STATIC"    # Entropy, PE headers, macros, magic bytes, strings
    LOCAL_TI = "LOCAL_TI"          # Local Threat Intelligence (PhishTank, URLhaus, MalwareBazaar)
    BEHAVIORAL = "BEHAVIORAL"      # Isolated Sandbox execution telemetry (network, process, file mutations)
    EXTERNAL_TI = "EXTERNAL_TI"    # Third-party intelligence providers (e.g. VirusTotal)


@dataclass
class SufficiencyResult:
    """Structured assessment of evidence quantity and quality."""
    score: float
    level: SufficiencyLevel
    evidence_classes_present: List[str] = field(default_factory=list)
    signals_count: int = 0
    contradictions: List[str] = field(default_factory=list)
    has_contradiction: bool = False
    details: Dict[str, Any] = field(default_factory=dict)


def compute_evidence_sufficiency(analysis_data: Dict[str, Any]) -> SufficiencyResult:
    """
    Calculate evidence sufficiency independently from the risk score.

    Rules:
    - Measures how much solid empirical information was gathered (breadth & depth)
    - Awards points for distinct independent evidence classes
    - Subtracts or flags major contradictions between observed layers

    Returns:
        SufficiencyResult containing score (0-100), level, classes present, and details.
    """
    if not analysis_data or not isinstance(analysis_data, dict):
        return SufficiencyResult(score=0.0, level=SufficiencyLevel.INSUFFICIENT)

    classes_present: Set[EvidenceClass] = set()
    class_weights: Dict[str, float] = {}
    contradictions: List[str] = []

    # 1. Check ML Model Evidence
    ml_data = analysis_data.get("ml") or analysis_data.get("url_features", {}).get("ml")
    if ml_data and isinstance(ml_data, dict) and ml_data.get("model_available"):
        prob = ml_data.get("probability")
        if prob is not None:
            classes_present.add(EvidenceClass.MODEL)
            # High confidence ML counts more than borderline 0.5
            confidence_dist = abs(float(prob) - 0.5) * 2.0  # 0.0 to 1.0
            class_weights["MODEL"] = 15.0 + (10.0 * confidence_dist)

    # 2. Check Domain Intelligence Evidence
    domain_info = analysis_data.get("domain_intelligence") or analysis_data.get("details", {}).get("domain_intelligence") or analysis_data.get("details", {}).get("domain")
    email_headers = analysis_data.get("email_headers") or analysis_data.get("details", {}).get("email_headers")
    url_val = analysis_data.get("url") or analysis_data.get("details", {}).get("url")
    if (domain_info and isinstance(domain_info, dict) and domain_info.get("domain")) or \
       (email_headers and isinstance(email_headers, dict) and email_headers.get("from_domain")) or \
       (url_val and isinstance(url_val, str) and len(url_val) > 0):
        classes_present.add(EvidenceClass.DOMAIN)
        has_age = domain_info and isinstance(domain_info, dict) and ("creation_date" in domain_info or "domain_age_days" in domain_info)
        class_weights["DOMAIN"] = 20.0 if has_age else 15.0

    # 3. Check IP Evidence
    if domain_info and isinstance(domain_info, dict):
        if domain_info.get("ip_addresses") or domain_info.get("is_ip_address"):
            classes_present.add(EvidenceClass.IP)
            class_weights["IP"] = 10.0

    # 4. Check Email Authentication Evidence
    email_auth = analysis_data.get("email_authentication") or analysis_data.get("details", {}).get("email_authentication")
    if email_auth and isinstance(email_auth, dict) and (
        any(k in email_auth for k in ("spf", "dkim", "dmarc")) or
        "message_authentication" in email_auth or
        "status" in email_auth or
        "signals" in email_auth
    ):
        classes_present.add(EvidenceClass.EMAIL_AUTH)
        class_weights["EMAIL_AUTH"] = 20.0

    # 5. Check Content / NLP Evidence
    email_nlp = analysis_data.get("email_nlp") or analysis_data.get("details", {}).get("email_nlp")
    brand_intel = analysis_data.get("brand_intelligence") or analysis_data.get("details", {}).get("brand_intelligence")
    if (email_nlp and isinstance(email_nlp, dict) and (
        email_nlp.get("intent") or
        email_nlp.get("matched_categories") or
        email_nlp.get("urgency_count", 0) > 0 or
        email_nlp.get("credential_count", 0) > 0
    )) or (brand_intel and isinstance(brand_intel, dict) and brand_intel.get("impersonated_brand")):
        classes_present.add(EvidenceClass.CONTENT)
        class_weights["CONTENT"] = 15.0

    # 6. Check Webpage / DOM Evidence
    webpage = analysis_data.get("webpage_analysis") or analysis_data.get("details", {}).get("webpage_analysis")
    if webpage and isinstance(webpage, dict) and webpage.get("status_code"):
        classes_present.add(EvidenceClass.WEBPAGE)
        class_weights["WEBPAGE"] = 20.0

    # 7. Check Static File Evidence
    file_static = analysis_data.get("file_analysis") or analysis_data.get("details", {}).get("file_analysis") or \
                  analysis_data.get("attachment_analysis") or analysis_data.get("details", {}).get("attachment_analysis") or \
                  analysis_data.get("attachments") or analysis_data.get("details", {}).get("attachments")
    if file_static:
        if isinstance(file_static, list) and len(file_static) > 0:
            classes_present.add(EvidenceClass.FILE_STATIC)
            class_weights["FILE_STATIC"] = 20.0
        elif isinstance(file_static, dict) and (file_static.get("entropy") is not None or file_static.get("magic") or file_static.get("magic_bytes") or file_static.get("sha256")):
            classes_present.add(EvidenceClass.FILE_STATIC)
            class_weights["FILE_STATIC"] = 20.0

    # 8. Check Local Threat Intelligence
    local_ti = analysis_data.get("local_ti") or analysis_data.get("details", {}).get("local_ti")
    if local_ti and isinstance(local_ti, dict) and local_ti.get("found"):
        classes_present.add(EvidenceClass.LOCAL_TI)
        class_weights["LOCAL_TI"] = 30.0

    # 9. Check Behavioral / Sandbox Telemetry
    sandbox = analysis_data.get("sandbox_telemetry") or analysis_data.get("details", {}).get("sandbox_telemetry")
    if sandbox and isinstance(sandbox, dict) and sandbox.get("executed"):
        classes_present.add(EvidenceClass.BEHAVIORAL)
        class_weights["BEHAVIORAL"] = 30.0

    # 10. Check External TI (e.g. VirusTotal)
    vt_info = analysis_data.get("virustotal") or analysis_data.get("details", {}).get("virustotal")
    if vt_info and isinstance(vt_info, dict) and vt_info.get("status") == "SUCCESS":
        classes_present.add(EvidenceClass.EXTERNAL_TI)
        class_weights["EXTERNAL_TI"] = 20.0

    # Contradiction Detection (e.g. Model says High Risk 0.95, but Verified Clean Domain with 15+ years age and zero TI)
    if "MODEL" in class_weights and ml_data:
        prob = ml_data.get("probability", 0.5)
        if prob and float(prob) > 0.85 and local_ti and not local_ti.get("found") and domain_info and domain_info.get("is_tranco_top_1k"):
            contradictions.append("Model indicates high phishing probability on an authoritative top-1k Alexa/Tranco domain.")

    # Calculate raw score with calibrated diversity bonus
    raw_score = sum(class_weights.values())
    diversity_multiplier = 1.0 + (max(0, len(classes_present) - 1) * 0.08)
    computed_score = raw_score * diversity_multiplier

    # Cap purely static/heuristic analysis without confirmed TI, external verification, or sandbox detonation
    has_authoritative_anchor = (
        EvidenceClass.LOCAL_TI in classes_present or
        EvidenceClass.EXTERNAL_TI in classes_present or
        EvidenceClass.BEHAVIORAL in classes_present
    )
    if not has_authoritative_anchor:
        # Without authoritative ground-truth feeds or sandbox detonation, sufficiency reflects empirical limits (capped at 75.0 STRONG)
        final_score = min(75.0, computed_score)
    else:
        final_score = min(100.0, computed_score)

    # Determine Sufficiency Level
    if final_score < 40.0:
        level = SufficiencyLevel.INSUFFICIENT
    elif final_score < 60.0:
        level = SufficiencyLevel.LIMITED
    elif final_score < 80.0:
        level = SufficiencyLevel.STRONG
    else:
        level = SufficiencyLevel.VERY_STRONG

    signals = analysis_data.get("signals") or analysis_data.get("risk", {}).get("signals") or []

    return SufficiencyResult(
        score=round(final_score, 1),
        level=level,
        evidence_classes_present=[c.value for c in classes_present],
        signals_count=len(signals) if isinstance(signals, list) else 0,
        contradictions=contradictions,
        has_contradiction=len(contradictions) > 0,
        details={"class_weights": class_weights, "diversity_multiplier": round(diversity_multiplier, 2)}
    )


def should_query_virustotal(
    analysis_data: Dict[str, Any],
    has_api_key: bool = True
) -> Tuple[bool, str]:
    """
    Evaluate Conditional VirusTotal Escalation Policy.

    Policy:
    1. If no API key configured -> SKIP (UNAVAILABLE)
    2. Check local TI first -> If definitive match found in local TI -> SKIP (Local TI sufficient)
    3. Evaluate Evidence Sufficiency:
       If evidence sufficiency >= 70 AND at least 2 independent evidence classes AND no major contradiction
       -> SKIP (Native evidence sufficient; saves quota & prevents external leakage)
    4. Otherwise -> ESCALATE (Query VT due to insufficient or contradictory native evidence)

    Args:
        analysis_data: The assembled analysis details so far.
        has_api_key: Whether VIRUSTOTAL_API_KEY is available.

    Returns:
        Tuple of (should_query: bool, reason: str)
    """
    if not has_api_key:
        return False, "VirusTotal API key not configured."

    # 1. Check local threat intelligence match
    local_ti = analysis_data.get("local_ti") or analysis_data.get("details", {}).get("local_ti")
    if local_ti and isinstance(local_ti, dict) and local_ti.get("found"):
        source = local_ti.get("source", "Local TI")
        return False, f"Definitive indicator match found in local threat intelligence ({source}); external lookup skipped."

    # 2. Check sufficiency
    sufficiency = compute_evidence_sufficiency(analysis_data)

    if sufficiency.has_contradiction:
        return True, f"Native evidence contains contradictions ({'; '.join(sufficiency.contradictions)}); escalating to external VT."

    if sufficiency.score >= 70.0 and len(sufficiency.evidence_classes_present) >= 2:
        classes_str = ", ".join(sufficiency.evidence_classes_present)
        return False, f"Native evidence is sufficient (score={sufficiency.score}, classes=[{classes_str}]); external VT query skipped."

    # 3. Insufficient evidence -> Escalate
    classes_count = len(sufficiency.evidence_classes_present)
    return True, f"Native evidence insufficient (score={sufficiency.score}/100, {classes_count} classes); escalating to VirusTotal for enrichment."


class ThreatIntelCache:
    """
    In-memory / SQLite Threat Intelligence Cache with TTL.
    Prevents redundant network calls for identical indicators.
    """

    def __init__(self, default_ttl_seconds: int = 86400):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self.default_ttl = default_ttl_seconds

    def _make_key(self, indicator_type: str, indicator: str) -> str:
        return f"{indicator_type.lower()}:{indicator.strip().lower()}"

    def get(self, indicator_type: str, indicator: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached result if not expired."""
        key = self._make_key(indicator_type, indicator)
        entry = self._cache.get(key)
        if not entry:
            return None
        if time.time() > entry.get("expires_at", 0):
            del self._cache[key]
            return None
        return entry.get("data")

    def set(self, indicator_type: str, indicator: str, provider: str, data: Dict[str, Any], ttl: Optional[int] = None):
        """Store result with expiration timestamp."""
        key = self._make_key(indicator_type, indicator)
        duration = ttl if ttl is not None else self.default_ttl
        self._cache[key] = {
            "provider": provider,
            "indicator": indicator,
            "data": data,
            "cached_at": time.time(),
            "expires_at": time.time() + duration,
        }

    def clear(self):
        """Clear all cached entries."""
        self._cache.clear()


# Global in-memory cache instance
ti_cache = ThreatIntelCache()
