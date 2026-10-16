"""
Central multi-layer risk engine.

This module combines evidence from multiple security layers.

IMPORTANT:
The score is an engineering risk score, not a probability
unless it has been statistically calibrated.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RiskSignal:
    """
    Represents one security signal.

    name:
        Name of the signal.

    weight:
        Contribution to the risk score.

    reason:
        Human-readable explanation.

    source:
        Module that generated the signal.
    """

    name: str
    weight: float
    reason: str
    source: str
    finding: Optional[str] = None
    severity: Optional[str] = None
    explanation: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert RiskSignal to a canonical dictionary for serialization and UI rendering."""
        sev = self.severity or ("CRITICAL" if self.weight >= 75 else "HIGH" if self.weight >= 40 else "MEDIUM" if self.weight >= 20 else "LOW")
        finding_txt = self.finding or self.name
        explanation_txt = self.explanation or self.reason
        return {
            "name": self.name,
            "weight": float(self.weight),
            "reason": self.reason,
            "source": self.source,
            "finding": finding_txt,
            "explanation": explanation_txt,
            "severity": sev,
        }


@dataclass
class RiskResult:
    """
    Final risk assessment.
    """

    score: float
    level: str
    signals: list = field(default_factory=list)


def clamp_score(score):
    """
    Keep the score between 0 and 100.
    """

    return max(0.0, min(100.0, score))


def determine_risk_level(score):
    """
    Convert the numerical score into a risk category.

    These thresholds are initial engineering thresholds.
    They should later be calibrated using validation data.
    """

    if score < 25:
        return "LOW"

    if score < 50:
        return "MEDIUM"

    if score < 75:
        return "HIGH"

    return "CRITICAL"


def add_signal(signals, name, weight, reason, source):
    """
    Add a risk signal to the list.
    """

    signals.append(
        RiskSignal(
            name=name,
            weight=weight,
            reason=reason,
            source=source
        )
    )


def analyze_url_risk(analysis):
    """
    Generate a risk assessment from URL analysis.

    This is intentionally evidence-based rather than
    using one single indicator as the final verdict.
    """

    signals = []

    url_features = analysis.get(
        "url_features",
        {}
    )

    domain = analysis.get(
        "domain_intelligence",
        {}
    )

    brand = analysis.get(
        "brand_intelligence",
        {}
    )

    reputation = analysis.get(
        "virustotal",
        {}
    )

    redirects = analysis.get(
        "redirect_analysis",
        {}
    )

    webpage = analysis.get(
        "webpage_analysis",
        {}
    )

    local_ti = analysis.get(
        "local_ti",
        {}
    )

    ml = analysis.get(
        "ml",
        {}
    )

    # ---------------------------------------------------------
    # Local Threat Intelligence (Deterministic Match)
    # ---------------------------------------------------------
    if local_ti.get("found"):
        source_name = local_ti.get("source", "Local TI")
        threat_type = local_ti.get("threat_type") or "malicious phishing"
        add_signal(
            signals,
            "local_threat_intelligence_match",
            85,
            f"Confirmed match in {source_name} threat intelligence feed ({threat_type}).",
            "local_threat_intelligence"
        )

    # ---------------------------------------------------------
    # Supervised Machine Learning Model Assessment
    # ---------------------------------------------------------
    if ml.get("model_available"):
        phish_prob = ml.get("phishing_probability")
        if phish_prob is None:
            phish_prob = ml.get("probability")

        if phish_prob is not None:
            try:
                p_val = float(phish_prob)
                if p_val >= 0.8:
                    add_signal(
                        signals,
                        "ml_high_confidence_phishing",
                        20,
                        f"Machine learning URL model predicts phishing with {p_val:.1%} probability (lexical heuristic).",
                        "url_model_inference"
                    )
                elif p_val >= 0.5:
                    add_signal(
                        signals,
                        "ml_moderate_confidence_phishing",
                        10,
                        f"Machine learning URL model indicates potential phishing risk ({p_val:.1%} probability).",
                        "url_model_inference"
                    )
            except (ValueError, TypeError):
                pass

    # ---------------------------------------------------------
    # Direct IP address
    # ---------------------------------------------------------

    if domain.get("is_ip_address"):

        add_signal(
            signals,
            "direct_ip_address",
            15,
            "URL uses a direct IP address instead of a hostname.",
            "domain_intelligence"
        )

    # ---------------------------------------------------------
    # Brand-domain mismatch
    # ---------------------------------------------------------

    if brand.get("brand_domain_mismatch"):

        add_signal(
            signals,
            "brand_domain_mismatch",
            20,
            "A known brand appears inconsistent with the registrable domain.",
            "brand_intelligence"
        )

    # ---------------------------------------------------------
    # Redirect chain
    # ---------------------------------------------------------

    redirect_count = redirects.get(
        "redirect_count",
        0
    )

    if redirect_count >= 3:

        add_signal(
            signals,
            "multiple_redirects",
            10,
            f"URL produced {redirect_count} redirects.",
            "redirect_analyzer"
        )

    # ---------------------------------------------------------
    # VirusTotal reputation
    # ---------------------------------------------------------

    malicious = reputation.get(
        "malicious",
        0
    )

    if malicious:

        add_signal(
            signals,
            "threat_intelligence_detection",
            25,
            f"Threat intelligence reported {malicious} malicious detections.",
            "virustotal"
        )

    # ---------------------------------------------------------
    # Webpage form & password collection
    # ---------------------------------------------------------

    if webpage.get("has_cross_domain_submission") or webpage.get("cross_domain_forms"):
        add_signal(
            signals,
            "cross_domain_form_submission",
            25,
            "Webpage contains a form that submits data across domain boundaries.",
            "webpage_analyzer"
        )
    elif webpage.get("has_password_field") or webpage.get("password_field_count", 0) > 0:
        add_signal(
            signals,
            "password_collection",
            10,
            "The webpage contains password input fields.",
            "webpage_analyzer"
        )

    # ---------------------------------------------------------
    # Iframe usage
    # ---------------------------------------------------------

    iframe_count = webpage.get(
        "iframe_count",
        0
    )

    if iframe_count > 2:

        add_signal(
            signals,
            "multiple_iframes",
            5,
            "The webpage contains multiple iframes.",
            "webpage_analyzer"
        )

    # ---------------------------------------------------------
    # Suspicious HTML patterns
    # ---------------------------------------------------------

    patterns = webpage.get(
        "suspicious_html_patterns",
        []
    )

    if patterns:

        add_signal(
            signals,
            "suspicious_html_patterns",
            10,
            f"Detected {len(patterns)} suspicious HTML patterns.",
            "webpage_analyzer"
        )

    # ---------------------------------------------------------
    # Suspicious URL keywords
    # ---------------------------------------------------------

    keyword_count = url_features.get(
        "suspicious_keyword_count",
        0
    )

    if keyword_count >= 2:

        add_signal(
            signals,
            "suspicious_url_keywords",
            5,
            f"URL contains {keyword_count} suspicious keywords.",
            "url_features"
        )

    # ---------------------------------------------------------
    # Calculate score
    # ---------------------------------------------------------

    score = sum(
        signal.weight
        for signal in signals
    )

    score = clamp_score(score)

    level = determine_risk_level(score)

    return RiskResult(
        score=score,
        level=level,
        signals=signals
    )


def risk_result_to_dict(result):
    """
    Convert RiskResult into JSON-friendly data.
    """

    return {
        "risk_score": result.score,
        "risk_level": result.level,
        "signals": [
            {
                "name": signal.name,
                "weight": signal.weight,
                "reason": signal.reason,
                "source": signal.source
            }
            for signal in result.signals
        ]
    }


if __name__ == "__main__":

    # Synthetic example for testing.

    example = {
        "url_features": {
            "suspicious_keyword_count": 3
        },

        "domain_intelligence": {
            "is_ip_address": True
        },

        "brand_intelligence": {
            "brand_domain_mismatch": True
        },

        "virustotal": {
            "malicious": 2
        },

        "redirect_analysis": {
            "redirect_count": 4
        },

        "webpage_analysis": {
            "password_field_count": 1,
            "iframe_count": 3,
            "suspicious_html_patterns": [
                {"category": "credential_language"}
            ]
        }
    }

    result = analyze_url_risk(example)

    print("\n" + "=" * 60)
    print("RISK ENGINE TEST")
    print("=" * 60)

    print("\nRisk score:", result.score)
    print("Risk level:", result.level)

    print("\nSignals:")

    for signal in result.signals:
        print(
            f"  [{signal.weight}] "
            f"{signal.name}: "
            f"{signal.reason}"
        )

    print("=" * 60)
