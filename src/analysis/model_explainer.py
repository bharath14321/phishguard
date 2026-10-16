"""
model_explainer.py

Provides an optional explainability layer for the URL Random Forest model.
All functions contain detailed comments describing purpose, steps, and
security considerations.
"""

import os
import sys
from typing import Any, Dict, List

# Feature extraction – re‑use the existing lexical extractor.
try:
    from src.features.url_features import extract_url_features
except ImportError as e:
    raise ImportError("URL feature extractor is required for model explanation") from e

# Optional joblib import for deserialising the model artifact.
try:
    import joblib  # type: ignore
except Exception:
    joblib = None  # type: ignore

# Path to the trained Random Forest model artifact (same location used in inference).
_MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "url_random_forest.joblib")


def _load_model() -> Any:
    """Load the Random Forest model if the artifact exists.

    Returns:
        The deserialized model object, or ``None`` if the artifact is missing
        or cannot be loaded.  This function deliberately swallows any
        deserialization errors to avoid exposing stack traces to callers.
    """
    if joblib is None:
        return None
    if not os.path.isfile(_MODEL_PATH):
        return None
    try:
        return joblib.load(_MODEL_PATH)
    except Exception:
        # Corrupted or incompatible model – treat as unavailable.
        return None


def _detect_malicious_class_index(model: Any) -> int:
    """Determine which class index corresponds to the *malicious* label.

    The Random Forest was trained with a binary target where ``1`` denotes
    malicious URLs.  Scikit‑learn stores the class labels in ``model.classes_``.
    If the attribute is missing or does not contain ``1``, we fall back to the
    last index (``-1``) which is a safe default for ``predict_proba``.
    """
    try:
        # ``classes_`` may be strings ("malicious") or integers (1).
        classes = list(model.classes_)
        if 1 in classes:
            return classes.index(1)
        if "malicious" in classes:
            return classes.index("malicious")
    except Exception:
        pass
    # Default to the second column (index 1) – common for binary classifiers.
    return 1


def explain_url_model(url: str) -> Dict[str, Any]:
    """Generate an explainability payload for a URL using the Random Forest.

    The function follows a *best‑effort* approach:

    1. Extract the 14 lexical features used during training.
    2. Load the persisted model artifact (if present).
    3. Compute the phishing probability via ``predict_proba`` when supported.
    4. Attempt SHAP‑based per‑prediction explanations – optional.
    5. If SHAP is unavailable, fall back to the model's ``feature_importances_``.
    6. Return a structured dictionary that callers can merge into the API
       response.

    Security considerations:
    * No external network calls are performed.
    * All failures are caught and reported via ``available: False`` with a
      concise ``reason`` string – no stack‑traces are leaked.
    * The function never mutates global state.
    """
    # ------------------------------------------------------------------
    # 1. Feature extraction – must match training order exactly.
    # ------------------------------------------------------------------
    try:
        features = extract_url_features(url)
    except Exception as exc:
        return {
            "available": False,
            "reason": f"feature extraction failed: {exc}",
        }

    # ------------------------------------------------------------------
    # 2. Load the model artifact.
    # ------------------------------------------------------------------
    model = _load_model()
    if model is None:
        return {
            "available": False,
            "reason": "model artifact not found or could not be loaded",
        }

    # ------------------------------------------------------------------
    # 3. Prepare the ordered feature vector expected by the model.
    # ------------------------------------------------------------------
    feature_order = [
        "url_length",
        "hostname_length",
        "path_length",
        "query_length",
        "dot_count",
        "hyphen_count",
        "digit_count",
        "special_char_count",
        "subdomain_count",
        "contains_ip",
        "uses_https",
        "contains_at",
        "contains_double_slash",
        "suspicious_keyword_count",
    ]
    vector = [float(features.get(k, 0)) for k in feature_order]

    # ------------------------------------------------------------------
    # 4. Compute the probability (if supported) and the raw prediction.
    # ------------------------------------------------------------------
    probability = None
    try:
        # ``predict_proba`` returns an array of shape (n_samples, n_classes).
        probas = model.predict_proba([vector])
        mal_idx = _detect_malicious_class_index(model)
        probability = float(probas[0][mal_idx])
    except Exception:
        # Fallback to ``predict`` – may return class label directly.
        try:
            pred = model.predict([vector])[0]
            # If the prediction is already a probability (e.g., regression), use it.
            probability = float(pred)
        except Exception:
            probability = None

    # ------------------------------------------------------------------
    # 5. Attempt SHAP – optional and may not be installed.
    # ------------------------------------------------------------------
    shap_available = False
    shap_values: List[float] = []
    direction: List[str] = []
    try:
        import shap  # type: ignore
        # Use the generic TreeExplainer for scikit‑learn models.
        explainer = shap.TreeExplainer(model)
        shap_res = explainer(vector)
        # ``shap_res.values`` is an array aligned with the feature order.
        shap_vals = list(map(float, shap_res.values))
        # Determine direction relative to the malicious class.
        for val in shap_vals:
            if val > 0:
                direction.append("increases_risk")
            elif val < 0:
                direction.append("decreases_risk")
            else:
                direction.append("neutral")
        shap_values = shap_vals
        shap_available = True
    except Exception:
        shap_available = False

    # ------------------------------------------------------------------
    # 5. Model-wide Global Feature Importances
    # ------------------------------------------------------------------
    global_importances: List[Dict[str, Any]] = []
    try:
        raw_importances = list(map(float, getattr(model, "feature_importances_", [])))
        if raw_importances:
            imp_indices = sorted(range(len(raw_importances)), key=lambda i: raw_importances[i], reverse=True)
            for i in imp_indices[:7]:
                global_importances.append({
                    "feature": feature_order[i],
                    "global_importance": round(raw_importances[i], 4),
                    "description": f"Model-wide split purity contribution across all training trees.",
                })
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 6. Local Tree Decision Path Analysis (native Random Forest explainability)
    # ------------------------------------------------------------------
    local_influential_features: List[Dict[str, Any]] = []
    tree_votes = {"phishing": 0, "benign": 0, "total": 0}
    try:
        if hasattr(model, "estimators_"):
            tree_votes["total"] = len(model.estimators_)
            split_counts: Dict[str, int] = {f: 0 for f in feature_order}
            for tree in model.estimators_:
                t_pred = tree.predict([vector])[0]
                if t_pred == 1:
                    tree_votes["phishing"] += 1
                else:
                    tree_votes["benign"] += 1
                # Inspect decision path
                dp = tree.decision_path([vector])
                for node_id in dp.indices[dp.indptr[0]:dp.indptr[1]]:
                    f_idx = tree.tree_.feature[node_id]
                    if 0 <= f_idx < len(feature_order):
                        split_counts[feature_order[f_idx]] += 1

            # Rank by local active split participation
            ranked_local = sorted(
                [{"feature": k, "active_splits": v, "value": vector[feature_order.index(k)]}
                 for k, v in split_counts.items() if v > 0],
                key=lambda x: x["active_splits"],
                reverse=True
            )
            local_influential_features = ranked_local[:5]
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 7. Assembled Explainability Contract
    # ------------------------------------------------------------------
    phish_prob = probability if probability is not None else 0.0
    is_phishing = bool(probability is not None and probability >= 0.5)

    # Local feature values dictionary
    local_feature_values = {k: features.get(k, 0) for k in feature_order}

    # Backward-compatible top_features with explicit role distinction
    top_features: List[Dict[str, Any]] = []
    if shap_available:
        for i, f_name in enumerate(feature_order):
            s_val = shap_values[i] if i < len(shap_values) else 0.0
            top_features.append({
                "feature": f_name,
                "value": vector[i],
                "shap_value": s_val,
                "direction": direction[i] if i < len(direction) else "neutral",
                "importance": abs(s_val),
                "scope": "shap_local_attribution",
            })
        top_features.sort(key=lambda item: abs(item.get("shap_value", 0)), reverse=True)
    elif local_influential_features:
        for item in local_influential_features:
            top_features.append({
                "feature": item["feature"],
                "value": item["value"],
                "importance": round(item["active_splits"] / max(1, tree_votes["total"]), 4),
                "active_splits": item["active_splits"],
                "scope": "local_decision_path",
            })
    elif global_importances:
        for item in global_importances[:5]:
            f_name = item["feature"]
            top_features.append({
                "feature": f_name,
                "value": local_feature_values.get(f_name, 0),
                "importance": item["global_importance"],
                "scope": "global_model_importance",
            })

    explanation_method = "SHAP" if shap_available else ("model_feature_importance" if global_importances or local_influential_features else "none")

    result: Dict[str, Any] = {
        "available": True,
        "model": "URL Random Forest Classifier",
        "model_version": "1.0.0",
        "prediction": "malicious" if is_phishing else "benign",
        "verdict": "phishing" if is_phishing else "benign",
        "predicted_class": 1 if is_phishing else 0,
        "probability": probability,
        "phishing_probability": probability,
        "benign_probability": 1.0 - phish_prob if probability is not None else None,
        "classification_threshold": 0.5,
        "explanation_method": explanation_method,
        "local_explanation_method": "tree_decision_path_analysis",
        "tree_ensemble_votes": tree_votes,
        "local_influential_features": local_influential_features,
        "global_feature_importances": global_importances,
        "local_feature_values": local_feature_values,
        "top_features": top_features,
        "scope_distinction": {
            "global_explanation": "Model-wide feature importance measures overall split purity (Gini impurity) reduction across the training dataset.",
            "local_explanation": "Local decision path evaluation shows the exact feature values extracted for this URL and the decision splits traversed in the forest.",
        },
        "limitations_and_caveats": [
            "Lexical Scope: The model evaluates URL string composition only, with no inspection of live webpage content or external reputation.",
            "Dataset Artifacts: Benign URLs using HTTPS (uses_https=1) or deep paths may trigger elevated phishing likelihood if similar structures were overrepresented in malicious training samples.",
            "Independence: ML probability is an empirical heuristic and must be corroborated by threat intelligence or deterministic signals before establishing confirmed risk."
        ],
    }

    return result


# Public alias for model explanation
explain_prediction = explain_url_model
