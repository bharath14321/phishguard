"""Multi-layer risk aggregation module.

This module aggregates evidence from the different analysis stages (ML inference,
URL details, email data, attachment information, threat intel) together with
any already‑computed risk result and correlated evidence supplied by the
caller. It does **not** perform any new risk calculation or evidence
correlation – it simply forwards the inputs unchanged, filling missing pieces
with ``None`` or empty structures.

The design ensures that the aggregator can be safely used in pipelines where
risk and correlation have already been determined (e.g., by a previous
analysis step) without inadvertently altering the security posture.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

# No imports from risk_engine or evidence_correlator – the aggregator is a thin
# pass‑through layer. Any needed data must be provided by the caller.


def aggregate_multi_layer_risk(analysis_outputs: Dict[str, Any]) -> Dict[str, Any]:
    """Aggregate evidence and already‑computed results into a single dict.

    Parameters
    ----------
    analysis_outputs: dict
        Expected keys (all optional):

        - ``ml`` – output of the lightweight ML model.
        - ``url_details`` – dict containing URL analysis (may include
          ``domain_intelligence`` and ``webpage_analysis`` sub‑sections).
        - ``email`` – email‑analysis dict.
        - ``attachment`` – attachment‑analysis dict.
        - ``virustotal`` – threat‑intel information.
        - ``final_risk`` – a pre‑computed risk result object (e.g., ``RiskResult``).
        - ``correlated_evidence`` – result from ``correlate_evidence`` if already
          computed.
        - ``explanation`` – optional human‑readable explanation.

    Returns
    -------
    dict
        A mapping with the following keys (preserving ``None``/empty values
        when inputs are missing):

        - ``ml_evidence``
        - ``domain_evidence`` – ``domain_intelligence`` from ``url_details``.
        - ``web_evidence`` – ``webpage_analysis`` from ``url_details``.
        - ``email_evidence``
        - ``attachment_evidence``
        - ``threat_intel_evidence``
        - ``correlated_evidence`` – passed through unchanged or empty dict.
        - ``final_risk`` – passed through unchanged.
        - ``explanation`` – passed through unchanged or empty dict.
    """

    # ---------------------------------------------------------------------
    # 1. Extract evidence pieces; use ``None`` when a piece is absent.
    # ---------------------------------------------------------------------
    ml_evidence: Optional[Any] = analysis_outputs.get("ml")
    url_details: Dict[str, Any] = analysis_outputs.get("url_details", {})
    email_evidence: Optional[Any] = analysis_outputs.get("email")
    attachment_evidence: Optional[Any] = analysis_outputs.get("attachment")
    threat_intel: Optional[Any] = analysis_outputs.get("virustotal")

    # ---------------------------------------------------------------------
    # 2. Preserve already‑computed correlated evidence and final risk.
    #    If not supplied, provide safe defaults (empty dict / None).
    # ---------------------------------------------------------------------
    correlated_evidence: Any = analysis_outputs.get("correlated_evidence", {})
    final_risk: Any = analysis_outputs.get("final_risk")
    explanation: Any = analysis_outputs.get("explanation", {})

    # ---------------------------------------------------------------------
    # 3. Assemble and return the aggregated structure.
    # ---------------------------------------------------------------------
    return {
        "ml_evidence": ml_evidence,
        "domain_evidence": url_details.get("domain_intelligence"),
        "web_evidence": url_details.get("webpage_analysis"),
        "email_evidence": email_evidence,
        "attachment_evidence": attachment_evidence,
        "threat_intel_evidence": threat_intel,
        "correlated_evidence": correlated_evidence,
        "final_risk": final_risk,
        "explanation": explanation,
    }
