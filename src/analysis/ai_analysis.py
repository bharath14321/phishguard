'''ai_analysis.py

Hybrid AI analysis utilities that combine deterministic analyzers with optional
ML inference for URLs and emails.
'''\n\nfrom typing import Dict, Any\n\n# Deterministic analyzers (already existing)\nfrom src.features.url_analyzer import analyze_url as url_analyzer\nfrom src.features.email_analyzer import analyze_email as email_analyzer\n\n# Optional ML inference modules – they handle missing model artifacts themselves.\ntry:\n    from src.models.url_model_inference import predict_url\nexcept Exception:\n    def predict_url(url: str) -> Dict[str, Any]:\n        return {"model_available": False, "probability": None, "features": {}}\n\ntry:\n    from src.features.email_ai_features import extract_email_ai_features\nexcept Exception:\n    def extract_email_ai_features(email_data: Dict[str, Any]) -> Dict[str, Any]:\n        return {}\n\ndef analyze_url_with_ai(url: str, user_id: int) -> Dict[str, Any]:\n    """Run the full URL analysis pipeline and augment with ML results.
\n    Returns a dictionary with three top‑level sections: ``rules`` (the original
    deterministic result), ``ml`` (probability from the trained model, if any),
    and ``combined`` which merges risk scores.
    """\n    # Deterministic analysis (same as unified_analyzer.analyze_url).\n    deterministic_result = url_analyzer(url)\n    # ML inference – may be unavailable.
    ml_result = predict_url(url)\n    # Merge risk scores: simple heuristic – if ML probability > 0.5 treat as high.
    combined_risk = deterministic_result.get("risk", {})\n    if ml_result.get("model_available") and ml_result.get("probability") is not None:\n        prob = ml_result["probability"]\n        combined_risk["ml_probability"] = prob\n        combined_risk["ml_score"] = 1 if prob >= 0.5 else 0\n    return {\n        "rules": deterministic_result,\n        "ml": ml_result,\n        "combined": combined_risk,\n    }\n\ndef analyze_email_with_ai(file_path: str, user_id: int) -> Dict[str, Any]:\n    """Run deterministic email analysis and add AI feature extraction.
\n    A full ML model for email is not provided; this function currently returns the
    extracted feature vector and a placeholder ``model_available`` flag.
    """\n    deterministic_result = email_analyzer(file_path)\n    # Extract AI‑ready features from the deterministic result.
    email_features = extract_email_ai_features(deterministic_result)\n    ml_placeholder = {\n        "model_available": False,\n        "features": email_features,\n    }\n    return {\n        "rules": deterministic_result,\n        "ml": ml_placeholder,\n    }\n
