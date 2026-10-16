'''email_ai_features.py

Utility functions for extracting AI‑ready feature vectors from the email analysis
output produced by :func:`src.features.email_analyzer.analyze_email`.
These features can later be fed to a trained ML model (if one exists) or used
by a deterministic fallback scorer.
'''\n\nfrom typing import Dict, Any\n\ndef extract_email_ai_features(email_data: Dict[str, Any]) -> Dict[str, Any]:\n    """Map the raw email analysis dict into structured AI feature groups.
\n    The original email analyzer returns a dict with various keys (e.g., ``"urls"``,
    ``"headers"``, ``"attachments"``).  This helper extracts the most relevant
    signals and organizes them into five high‑level categories required by the
    specification:
\n    * ``IDENTITY`` – sender/receiver verification signals.
    * ``AUTHENTICATION`` – DKIM/SPF/DMARC results.
    * ``LANGUAGE`` – language detection and suspicious vocab.
    * ``URL`` – count and risk of embedded URLs.
    * ``ATTACHMENT`` – number of attachments and any suspicious file types.
\n    The function is deliberately defensive: missing keys yield ``0`` or empty
    structures so that downstream code can safely compute scores.
\n    Parameters\n    ----------\n    email_data: dict\n        Output of ``email_analyzer``.
\n    Returns\n    -------\n    dict\n        Mapping of the five feature groups to their extracted values.
    """\n    # Helper to safely fetch nested values.
    def _get(key: str, default=None):\n        return email_data.get(key, default)
\n    # 1. IDENTITY – simple presence checks.
    identity = {\n        "has_sender": bool(_get("sender")),\n        "has_recipient": bool(_get("recipients")),\n        "sender_is_known": bool(_get("sender", {}).get("is_known", False)),\n    }\n\n    # 2. AUTHENTICATION – DKIM, SPF, DMARC results (if present).
    auth = {\n        "dkim_pass": bool(_get("authentication", {}).get("dkim_pass")),\n        "spf_pass": bool(_get("authentication", {}).get("spf_pass")),\n        "dmarc_pass": bool(_get("authentication", {}).get("dmarc_pass")),\n    }\n\n    # 3. LANGUAGE – naive heuristics (placeholder for real NLP).
    language = {\n        "language": _get("language", "unknown"),\n        "suspicious_words": len(_get("suspicious_words", [])),\n    }\n\n    # 4. URL – count of URLs and simple risk flags.
    urls = _get("urls", [])\n    url_features = {\n        "url_count": len(urls),\n        "has_malicious_url": any(u.get("risk", {}).get("level") == "HIGH" for u in urls),\n    }\n\n    # 5. ATTACHMENT – attachment count and any dangerous types.
    attachments = _get("attachments", [])\n    attachment_features = {\n        "attachment_count": len(attachments),\n        "has_executable": any(att.get("type") in {"exe", "js", "vbs"} for att in attachments),\n    }\n\n    return {\n        "IDENTITY": identity,\n        "AUTHENTICATION": auth,\n        "LANGUAGE": language,\n        "URL": url_features,\n        "ATTACHMENT": attachment_features,\n    }\n
