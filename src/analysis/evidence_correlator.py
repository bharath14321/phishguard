"""
Evidence Correlator — Phase 8A

Consumes the structured outputs that already exist from the URL, email,
attachment, and reputation analysis modules and identifies cross-layer
security correlations.

Design decisions:
    - This module does NOT rerun any analysis.  It receives the *already
      computed* analysis dicts and correlates them.
    - Unknown / unavailable evidence is never treated as malicious.
    - Related signals (e.g., brand mismatch + hostname detection +
      domain mismatch) are grouped into a single correlation to avoid
      double-counting.
    - The existing risk engine is NOT modified; this module only produces
      structured evidence.
"""

from typing import Dict, Any, List


# ------------------------------------------------------------------ #
#  Evidence item builder                                              #
# ------------------------------------------------------------------ #

def _evidence_item(source: str, signal: str, description: str,
                   category: str) -> Dict[str, Any]:
    """Build a single evidence item.

    Every evidence item has exactly four fields:
      source     – which module produced the signal
      signal     – short machine-readable identifier
      description – human-readable sentence
      category   – one of the classification constants below

    Valid categories:
        strong_positive, moderate_positive, weak_positive,
        neutral, negative, unknown
    """
    return {
        "source": source,
        "signal": signal,
        "description": description,
        "category": category,
    }


# ------------------------------------------------------------------ #
#  Correlation builder                                                #
# ------------------------------------------------------------------ #

def _correlation(name: str, description: str, sources: List[str],
                 severity: str) -> Dict[str, Any]:
    """Build one cross-layer correlation entry.

    severity is one of: high, medium, low, informational.
    """
    return {
        "name": name,
        "description": description,
        "sources": sources,
        "severity": severity,
    }


# ------------------------------------------------------------------ #
#  Evidence extractors (one per analysis layer)                       #
# ------------------------------------------------------------------ #

def _extract_url_evidence(url_details: dict) -> List[Dict[str, Any]]:
    """Pull evidence from the url_analyzer output.

    Reads url_features (suspicious keywords, IP usage, length)
    without re-running the analysis.
    """
    items: List[Dict[str, Any]] = []
    url_features = url_details.get("url_features", {})

    kw_count = url_features.get("suspicious_keyword_count", 0)
    if kw_count >= 2:
        items.append(_evidence_item(
            "url_features", "suspicious_keywords",
            f"URL contains {kw_count} suspicious keywords.",
            "moderate_positive",
        ))

    if url_features.get("has_ip_address"):
        items.append(_evidence_item(
            "url_features", "ip_in_url",
            "URL contains an IP address instead of a domain name.",
            "moderate_positive",
        ))

    if url_features.get("url_length", 0) > 200:
        items.append(_evidence_item(
            "url_features", "long_url",
            "URL is unusually long.",
            "weak_positive",
        ))

    # HTTPS alone is neutral — it does NOT indicate safety.
    scheme = url_details.get("url", "")
    if scheme.startswith("https://"):
        items.append(_evidence_item(
            "url_features", "https_present",
            "URL uses HTTPS (does not imply safety by itself).",
            "neutral",
        ))

    return items


def _extract_domain_evidence(url_details: dict) -> List[Dict[str, Any]]:
    """Pull evidence from domain_intelligence."""
    items: List[Dict[str, Any]] = []
    domain = url_details.get("domain_intelligence", {})

    if domain.get("is_ip_address"):
        items.append(_evidence_item(
            "domain_intelligence", "direct_ip",
            "URL resolves to a direct IP address.",
            "moderate_positive",
        ))

    # DNS failure is UNKNOWN, not malicious.
    if domain.get("dns_error"):
        items.append(_evidence_item(
            "domain_intelligence", "dns_failure",
            "DNS resolution failed — result is unknown.",
            "unknown",
        ))

    return items


def _extract_brand_evidence(url_details: dict) -> List[Dict[str, Any]]:
    """Pull evidence from brand_intelligence.

    Brand mismatch, detected brands, and hostname detection are
    conceptually a single observation so we emit one item rather
    than three to prevent double-counting.
    """
    items: List[Dict[str, Any]] = []
    brand = url_details.get("brand_intelligence", {})

    if brand.get("brand_domain_mismatch"):
        detected = brand.get("detected_brands", [])
        brand_names = ", ".join(detected) if detected else "a known brand"
        items.append(_evidence_item(
            "brand_intelligence", "brand_domain_mismatch",
            f"Possible brand impersonation: {brand_names} detected in "
            f"hostname but registrable domain does not match.",
            "strong_positive",
        ))
    elif brand.get("detected_brands"):
        items.append(_evidence_item(
            "brand_intelligence", "brand_present_no_mismatch",
            "Known brand detected; domain appears consistent.",
            "negative",
        ))

    return items


def _extract_ip_evidence(url_details: dict) -> List[Dict[str, Any]]:
    """Pull evidence from ip_intelligence."""
    items: List[Dict[str, Any]] = []
    ip_info = url_details.get("ip_intelligence", {})
    if not ip_info:
        return items

    if ip_info.get("is_private"):
        items.append(_evidence_item(
            "ip_intelligence", "private_ip",
            "URL points to a private/internal IP address.",
            "moderate_positive",
        ))

    return items


def _extract_redirect_evidence(url_details: dict) -> List[Dict[str, Any]]:
    """Pull evidence from redirect_analysis."""
    items: List[Dict[str, Any]] = []
    redirects = url_details.get("redirect_analysis", {})

    count = redirects.get("redirect_count", 0)
    if count >= 3:
        items.append(_evidence_item(
            "redirect_analysis", "multiple_redirects",
            f"URL produced {count} redirects before reaching the final page.",
            "moderate_positive",
        ))
    elif count > 0:
        items.append(_evidence_item(
            "redirect_analysis", "few_redirects",
            f"URL produced {count} redirect(s).",
            "weak_positive",
        ))

    return items


def _extract_webpage_evidence(url_details: dict) -> List[Dict[str, Any]]:
    """Pull evidence from webpage_analysis."""
    items: List[Dict[str, Any]] = []
    webpage = url_details.get("webpage_analysis", {})

    if not webpage:
        return items

    pw = webpage.get("password_field_count", 0)
    if pw > 0:
        items.append(_evidence_item(
            "webpage_analysis", "password_form",
            "The landing page contains a password/login form.",
            "moderate_positive",
        ))

    if webpage.get("suspicious_html_patterns"):
        items.append(_evidence_item(
            "webpage_analysis", "suspicious_html",
            "The page contains suspicious HTML patterns.",
            "moderate_positive",
        ))

    # Tracking pixel alone is neutral.
    if webpage.get("tracking_pixel") and pw == 0:
        items.append(_evidence_item(
            "webpage_analysis", "tracking_pixel",
            "Page contains a tracking pixel (common in marketing emails).",
            "neutral",
        ))

    # Fetch failure is unknown, not malicious.
    if webpage.get("fetch_error"):
        items.append(_evidence_item(
            "webpage_analysis", "fetch_failure",
            "Webpage could not be fetched — result is unknown.",
            "unknown",
        ))

    return items


def _extract_reputation_evidence(url_details: dict) -> List[Dict[str, Any]]:
    """Pull evidence from virustotal / reputation lookup.

    VirusTotal unavailability → unknown (never malicious).
    """
    items: List[Dict[str, Any]] = []
    vt = url_details.get("virustotal", {})

    if not vt:
        return items

    if not vt.get("success", True):
        # API failure or key not configured.
        items.append(_evidence_item(
            "virustotal", "vt_unavailable",
            "VirusTotal lookup was unavailable — cannot determine reputation.",
            "unknown",
        ))
        return items

    malicious = vt.get("malicious", 0)
    suspicious = vt.get("suspicious", 0)

    if malicious and malicious > 0:
        items.append(_evidence_item(
            "virustotal", "vt_malicious",
            f"VirusTotal: {malicious} vendor(s) flagged as malicious.",
            "strong_positive",
        ))
    elif suspicious and suspicious > 0:
        items.append(_evidence_item(
            "virustotal", "vt_suspicious",
            f"VirusTotal: {suspicious} vendor(s) flagged as suspicious.",
            "moderate_positive",
        ))
    elif vt.get("found") is True:
        items.append(_evidence_item(
            "virustotal", "vt_clean",
            "VirusTotal: no vendors flagged this as malicious.",
            "negative",
        ))

    return items


def _extract_ml_evidence(ml_data: dict) -> List[Dict[str, Any]]:
    """Pull evidence from the optional ML inference layer (Phase 7).

    The ML probability is NOT presented as calibrated confidence.
    """
    items: List[Dict[str, Any]] = []
    if not ml_data or not ml_data.get("model_available"):
        items.append(_evidence_item(
            "ml_model", "ml_unavailable",
            "ML model is not available for this artifact.",
            "unknown",
        ))
        return items

    prob = ml_data.get("probability")
    if prob is not None:
        if prob >= 0.8:
            cat = "strong_positive"
            desc = f"ML model output: {prob:.2f} (high suspicion)."
        elif prob >= 0.5:
            cat = "moderate_positive"
            desc = f"ML model output: {prob:.2f} (moderate suspicion)."
        elif prob >= 0.3:
            cat = "weak_positive"
            desc = f"ML model output: {prob:.2f} (slight suspicion)."
        else:
            cat = "negative"
            desc = f"ML model output: {prob:.2f} (low suspicion)."
        items.append(_evidence_item("ml_model", "ml_prediction", desc, cat))

    return items


# ---- Email-specific evidence extractors ---- #

def _extract_email_header_evidence(
        email_data: dict) -> List[Dict[str, Any]]:
    """Pull identity-related evidence from email headers.

    Groups display-name mismatch and reply-to mismatch into a
    single identity evidence item when both occur, to avoid
    double-counting.
    """
    items: List[Dict[str, Any]] = []
    headers = email_data.get("headers", {})

    display_mismatch = False
    display_analysis = headers.get("display_name_analysis", {})
    if display_analysis.get("possible_mismatch"):
        display_mismatch = True

    reply_mismatch = headers.get("reply_to_domain_mismatch", False)

    # Group the two identity signals.
    if display_mismatch and reply_mismatch:
        items.append(_evidence_item(
            "email_headers", "sender_identity_mismatch",
            "Both display-name and Reply-To domain differ from the From "
            "address — potential sender impersonation.",
            "strong_positive",
        ))
    elif display_mismatch:
        items.append(_evidence_item(
            "email_headers", "display_name_mismatch",
            "Display name suggests a known brand but the email domain "
            "does not match.",
            "moderate_positive",
        ))
    elif reply_mismatch:
        items.append(_evidence_item(
            "email_headers", "reply_to_mismatch",
            "Reply-To domain is different from the From domain.",
            "weak_positive",
        ))

    # BCC alone is neutral.
    if headers.get("bcc") and not display_mismatch and not reply_mismatch:
        items.append(_evidence_item(
            "email_headers", "bcc_present",
            "Email uses BCC (common and not inherently suspicious).",
            "neutral",
        ))

    return items


def _extract_authentication_evidence(
        auth_data: dict) -> List[Dict[str, Any]]:
    """Pull evidence from email authentication analysis.

    A single SPF/DKIM/DMARC failure alone does NOT mean phishing.
    """
    items: List[Dict[str, Any]] = []
    if not auth_data:
        return items

    signals = auth_data.get("signals", {})
    status = auth_data.get("status", {})

    fail_count = sum(1 for k in ("spf_fail", "dkim_fail", "dmarc_fail")
                     if signals.get(k))
    pass_count = sum(1 for k in ("spf_pass", "dkim_pass", "dmarc_pass")
                     if signals.get(k))

    if fail_count >= 2:
        items.append(_evidence_item(
            "email_authentication", "multiple_auth_failures",
            f"Multiple authentication checks failed "
            f"(SPF={status.get('spf','?')}, DKIM={status.get('dkim','?')}, "
            f"DMARC={status.get('dmarc','?')}).",
            "strong_positive",
        ))
    elif fail_count == 1:
        items.append(_evidence_item(
            "email_authentication", "single_auth_failure",
            f"One authentication check failed "
            f"(SPF={status.get('spf','?')}, DKIM={status.get('dkim','?')}, "
            f"DMARC={status.get('dmarc','?')}). "
            f"A single failure is not conclusive by itself.",
            "weak_positive",
        ))
    elif pass_count == 3:
        items.append(_evidence_item(
            "email_authentication", "all_auth_pass",
            "All SPF, DKIM, and DMARC checks passed.",
            "negative",
        ))

    return items


def _extract_nlp_evidence(nlp_data: dict) -> List[Dict[str, Any]]:
    """Pull evidence from email NLP analysis."""
    items: List[Dict[str, Any]] = []
    if not nlp_data:
        return items

    urgency = nlp_data.get("urgency_count", 0)
    credential = nlp_data.get("credential_count", 0)
    financial = nlp_data.get("financial_count", 0)
    bec = nlp_data.get("bec_count", 0)

    if urgency >= 2:
        items.append(_evidence_item(
            "email_nlp", "high_urgency",
            f"Email body contains {urgency} urgency indicators.",
            "moderate_positive",
        ))
    elif urgency == 1:
        items.append(_evidence_item(
            "email_nlp", "low_urgency",
            "Email body contains minor urgency language.",
            "weak_positive",
        ))

    if credential >= 1:
        items.append(_evidence_item(
            "email_nlp", "credential_request",
            f"Email body contains {credential} credential-related term(s).",
            "moderate_positive",
        ))

    if financial >= 2:
        items.append(_evidence_item(
            "email_nlp", "financial_language",
            f"Email body contains {financial} financial/payment references.",
            "moderate_positive",
        ))

    if bec >= 2:
        items.append(_evidence_item(
            "email_nlp", "bec_language",
            f"Email body contains {bec} BEC-related phrases.",
            "moderate_positive",
        ))

    return items


def _extract_attachment_evidence(
        attachment_data: dict) -> List[Dict[str, Any]]:
    """Pull evidence from attachment analysis."""
    items: List[Dict[str, Any]] = []
    if not attachment_data:
        return items

    if attachment_data.get("suspicious_extension"):
        items.append(_evidence_item(
            "attachment_analysis", "suspicious_extension",
            f"Attachment has a suspicious extension: "
            f"{attachment_data.get('extension', '?')}.",
            "strong_positive",
        ))

    if attachment_data.get("macro_enabled"):
        items.append(_evidence_item(
            "attachment_analysis", "macro_enabled",
            "Attachment is a macro-enabled Office document.",
            "strong_positive",
        ))

    return items


def _extract_malware_static_evidence(
        static_data: dict) -> List[Dict[str, Any]]:
    """Pull evidence from static malware analysis."""
    items: List[Dict[str, Any]] = []
    if not static_data:
        return items

    if static_data.get("suspicious_strings"):
        items.append(_evidence_item(
            "malware_static", "suspicious_strings",
            "Static analysis found suspicious strings in the file.",
            "strong_positive",
        ))

    if static_data.get("suspicious_imports"):
        items.append(_evidence_item(
            "malware_static", "suspicious_imports",
            "Static analysis found suspicious API imports.",
            "moderate_positive",
        ))

    return items


def _extract_qr_evidence(qr_data: dict) -> List[Dict[str, Any]]:
    """Pull evidence from embedded QR analysis in emails or QR artifacts."""
    items: List[Dict[str, Any]] = []
    if not qr_data or not qr_data.get("detected"):
        return items

    qr_count = qr_data.get("qr_count", 0)
    findings = qr_data.get("findings", [])
    url_count = sum(1 for f in findings if f.get("is_url"))

    if url_count > 0:
        items.append(_evidence_item(
            "qr_analysis", "embedded_qr_url",
            f"Email contains {qr_count} embedded QR code(s) directing to external URL(s).",
            "moderate_positive",
        ))
    else:
        items.append(_evidence_item(
            "qr_analysis", "embedded_qr_text",
            f"Email contains {qr_count} embedded QR code(s) with text payload.",
            "neutral",
        ))

    return items


# ------------------------------------------------------------------ #
#  Cross-layer correlations                                           #
# ------------------------------------------------------------------ #

def _detect_correlations(evidence: Dict[str, List],
                         analysis_data: dict) -> List[Dict[str, Any]]:
    """Detect cross-layer correlations between independent evidence.

    Implements the nine required deterministic correlation checks.
    Each correlation links signals from at least two different
    analysis sources.

    Security decision: correlations are descriptive — they do NOT
    automatically change the risk score.
    """
    correlations: List[Dict[str, Any]] = []
    url_details = analysis_data.get("url_details", {})
    email_data = analysis_data.get("email_data", {})
    auth_data = analysis_data.get("authentication", {})
    nlp_data = analysis_data.get("nlp", {})
    attachment_data = analysis_data.get("attachment", {})
    malware_data = analysis_data.get("malware_static", {})

    # Helpers: collect signal names for fast lookup.
    def _has(layer: str, signal: str) -> bool:
        return any(e["signal"] == signal for e in evidence.get(layer, []))

    # -------- 1. BRAND + DOMAIN -------- #
    # Brand appears in hostname but registrable domain doesn't match.
    brand = url_details.get("brand_intelligence", {})
    domain = url_details.get("domain_intelligence", {})
    if brand.get("brand_domain_mismatch"):
        correlations.append(_correlation(
            "brand_impersonation",
            "A known brand appears in the hostname but the registrable "
            "domain does not belong to that brand — possible brand "
            "impersonation.",
            ["brand_intelligence", "domain_intelligence"],
            "high",
        ))

    # -------- 2. SUSPICIOUS URL + PASSWORD FORM -------- #
    has_url_suspicion = (
        _has("url", "suspicious_keywords")
        or _has("url", "ip_in_url")
        or _has("domain", "direct_ip")
    )
    has_password = _has("webpage", "password_form")
    if has_url_suspicion and has_password:
        correlations.append(_correlation(
            "suspicious_url_credential_collection",
            "Suspicious URL indicators combined with a password/login "
            "form on the landing page suggest credential collection.",
            ["url_features", "webpage_analysis"],
            "high",
        ))

    # -------- 3. REDIRECT + SUSPICIOUS DESTINATION -------- #
    has_redirects = _has("redirect", "multiple_redirects")
    has_domain_suspicion = (
        _has("domain", "direct_ip")
        or _has("brand", "brand_domain_mismatch")
    )
    if has_redirects and has_domain_suspicion:
        correlations.append(_correlation(
            "redirect_to_suspicious_destination",
            "Multiple redirects end at a destination with suspicious "
            "domain indicators.",
            ["redirect_analysis", "domain_intelligence"],
            "high",
        ))

    # -------- 4. EMAIL IDENTITY (display-name + reply-to) -------- #
    if _has("email", "sender_identity_mismatch"):
        correlations.append(_correlation(
            "sender_identity_deception",
            "Both display-name and Reply-To domain differ from the "
            "sender's From address, suggesting impersonation.",
            ["email_headers"],
            "high",
        ))

    # -------- 5. AUTHENTICATION + SENDER EVIDENCE -------- #
    has_auth_problem = (
        _has("authentication", "multiple_auth_failures")
        or _has("authentication", "single_auth_failure")
    )
    has_sender_suspicion = (
        _has("email", "sender_identity_mismatch")
        or _has("email", "display_name_mismatch")
        or _has("email", "reply_to_mismatch")
    )
    if has_auth_problem and has_sender_suspicion:
        correlations.append(_correlation(
            "auth_failure_plus_sender",
            "Email authentication failures combined with sender "
            "identity anomalies increase suspicion.",
            ["email_authentication", "email_headers"],
            "high",
        ))

    # -------- 6. NLP: URGENCY + CREDENTIAL REQUEST -------- #
    has_urgency = (
        _has("nlp", "high_urgency") or _has("nlp", "low_urgency")
    )
    has_credential = _has("nlp", "credential_request")
    if has_urgency and has_credential:
        correlations.append(_correlation(
            "social_engineering",
            "Urgency language combined with credential-request "
            "language is a common social-engineering tactic.",
            ["email_nlp"],
            "high",
        ))

    # -------- 7. SUSPICIOUS ATTACHMENT + EMBEDDED URL -------- #
    has_sus_attachment = (
        _has("attachment", "suspicious_extension")
        or _has("attachment", "macro_enabled")
    )
    # Embedded URLs are stored in the unified analyzer under
    # details -> embedded_url_analyses.
    embedded_urls = analysis_data.get("embedded_url_analyses", [])
    if has_sus_attachment and embedded_urls:
        correlations.append(_correlation(
            "suspicious_attachment_with_urls",
            "A suspicious attachment also contains embedded URLs.",
            ["attachment_analysis", "url_features"],
            "high",
        ))

    # -------- 8. STATIC MALWARE + ATTACHMENT -------- #
    has_malware_signal = (
        _has("malware_static", "suspicious_strings")
        or _has("malware_static", "suspicious_imports")
    )
    if has_malware_signal and has_sus_attachment:
        correlations.append(_correlation(
            "malware_plus_attachment",
            "Static malware indicators combined with suspicious "
            "attachment metadata suggest a potentially malicious file.",
            ["malware_static", "attachment_analysis"],
            "high",
        ))

    # -------- 9. REPUTATION + INDEPENDENT EVIDENCE -------- #
    # VirusTotal must NOT be the sole verdict.
    has_vt_malicious = _has("reputation", "vt_malicious")
    has_independent = (
        has_url_suspicion
        or has_password
        or has_sus_attachment
        or has_sender_suspicion
        or _has("brand", "brand_domain_mismatch")
    )
    if has_vt_malicious and has_independent:
        correlations.append(_correlation(
            "reputation_corroborated",
            "VirusTotal detection is corroborated by at least one "
            "independent suspicious signal.",
            ["virustotal", "multi_layer"],
            "high",
        ))

    return correlations


# ------------------------------------------------------------------ #
#  Summary generator                                                  #
# ------------------------------------------------------------------ #

def _generate_summary(positive: list, negative: list, unknown: list,
                      correlations: list) -> str:
    """Create a one-sentence human-readable summary.

    Uses only factual language — does not claim certainty.
    """
    parts = []
    if correlations:
        parts.append(
            f"{len(correlations)} cross-layer correlation(s) detected")
    if positive:
        parts.append(f"{len(positive)} suspicious signal(s)")
    if negative:
        parts.append(f"{len(negative)} benign indicator(s)")
    if unknown:
        parts.append(f"{len(unknown)} unknown/unavailable result(s)")

    if not parts:
        return "No evidence signals collected."
    return "Evidence summary: " + "; ".join(parts) + "."


# ------------------------------------------------------------------ #
#  Main public API                                                    #
# ------------------------------------------------------------------ #

def correlate_evidence(analysis_data: Dict[str, Any]) -> Dict[str, Any]:
    """Correlate evidence across multiple analysis layers.

    Parameters
    ----------
    analysis_data : dict
        Combined dictionary holding the outputs of existing analyzers.
        Expected keys (all optional — missing layers are skipped):

        - ``url_details``      : from url_analyzer.analyze_url()
        - ``ml``               : from url_model_inference.predict_url()
        - ``email_data``       : from email_analyzer.analyze_email()
        - ``authentication``   : from email_authentication module
        - ``nlp``              : from email_nlp module
        - ``attachment``       : from attachment_analyzer.analyze_attachment()
        - ``malware_static``   : (if available) static malware analysis dict
        - ``embedded_url_analyses`` : list of embedded URL dicts (file analysis)

    Returns
    -------
    dict with:
        evidence        – per-layer lists of evidence items
        correlations    – detected cross-layer correlations
        positive_evidence  – all items with category ending in ``_positive``
        negative_evidence  – all items with category ``negative``
        unknown_evidence   – all items with category ``unknown``
        summary         – human-readable summary string
    """

    url_details = analysis_data.get("url_details", {})
    ml_data = analysis_data.get("ml", {})
    email_data = analysis_data.get("email_data", {})
    auth_data = analysis_data.get("authentication", {})
    nlp_data = analysis_data.get("nlp", {})
    attachment_data = analysis_data.get("attachment", {})
    malware_data = analysis_data.get("malware_static", {})

    # --- Collect per-layer evidence --- #
    evidence: Dict[str, List] = {
        "url": _extract_url_evidence(url_details),
        "ml": _extract_ml_evidence(ml_data),
        "domain": _extract_domain_evidence(url_details),
        "brand": _extract_brand_evidence(url_details),
        "ip": _extract_ip_evidence(url_details),
        "redirect": _extract_redirect_evidence(url_details),
        "webpage": _extract_webpage_evidence(url_details),
        "email": _extract_email_header_evidence(email_data),
        "authentication": _extract_authentication_evidence(auth_data),
        "nlp": _extract_nlp_evidence(nlp_data),
        "attachment": _extract_attachment_evidence(attachment_data),
        "malware_static": _extract_malware_static_evidence(malware_data),
        "reputation": _extract_reputation_evidence(url_details),
        "qr": _extract_qr_evidence(analysis_data.get("qr_analysis") or analysis_data.get("qr", {})),
    }

    # --- Run cross-layer correlations --- #
    correlations = _detect_correlations(evidence, analysis_data)

    # --- Classify evidence --- #
    positive: List[Dict[str, Any]] = []
    negative: List[Dict[str, Any]] = []
    unknown: List[Dict[str, Any]] = []

    for layer_items in evidence.values():
        for item in layer_items:
            cat = item.get("category", "")
            if cat.endswith("_positive"):
                positive.append(item)
            elif cat == "negative":
                negative.append(item)
            elif cat == "unknown":
                unknown.append(item)
            # neutral items are intentionally excluded from both.

    summary = _generate_summary(positive, negative, unknown, correlations)

    return {
        "evidence": evidence,
        "correlations": correlations,
        "positive_evidence": positive,
        "negative_evidence": negative,
        "unknown_evidence": unknown,
        "summary": summary,
    }
