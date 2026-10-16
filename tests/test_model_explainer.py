"""
tests/test_model_explainer.py

Tests for the optional model explanation layer.
All tests avoid external dependencies and network calls.
"""

import builtins
import types
from unittest import mock

from src.analysis.model_explainer import explain_url_model

# Helper to construct a minimal mock Random Forest model
def make_mock_model(predict_proba=True, shap=True, feature_importances=True):
    mock_model = mock.Mock()
    # Classes – assume binary {0,1}
    mock_model.classes_ = [0, 1]
    # Predict_proba returns a fixed probability 0.85 for class 1
    if predict_proba:
        mock_model.predict_proba.return_value = [[0.15, 0.85]]
    else:
        mock_model.predict_proba.side_effect = AttributeError("no predict_proba")
        mock_model.predict.return_value = [1]
    # Feature importances – simple deterministic list
    if feature_importances:
        mock_model.feature_importances_ = [0.1] * 14
    else:
        del mock_model.feature_importances_
    # Attach a dummy TreeExplainer if shap is requested
    mock_model._shap_available = shap
    return mock_model

# Patch the internal _load_model to return our mock model.
@mock.patch("src.analysis.model_explainer._load_model")
def test_explain_with_shap_available(mock_load):
    mock_load.return_value = make_mock_model()
    # Patch shap import inside the function
    with mock.patch.dict("sys.modules", {"shap": types.SimpleNamespace(TreeExplainer=lambda m: types.SimpleNamespace(__call__=lambda x: types.SimpleNamespace(values=[0.2]*14)))}):
        result = explain_url_model("https://example.com")
    assert result["available"] is True
    assert result["explanation_method"] in ["SHAP", "model_feature_importance"]
    assert isinstance(result["top_features"], list)
    assert result["probability"] == 0.85

@mock.patch("src.analysis.model_explainer._load_model")
def test_fallback_to_feature_importance(mock_load):
    # Model with no SHAP (shap import will fail) but has feature_importances_
    mock_load.return_value = make_mock_model(shap=False)
    # Ensure shap import raises ImportError
    with mock.patch.dict("sys.modules", {"shap": None}):
        result = explain_url_model("https://example.com")
    assert result["available"] is True
    assert result["explanation_method"] == "model_feature_importance"
    assert isinstance(result["top_features"], list)
    # Probability should still be present via predict_proba
    assert result["probability"] == 0.85

@mock.patch("src.analysis.model_explainer._load_model")
def test_model_missing(mock_load):
    mock_load.return_value = None
    result = explain_url_model("https://example.com")
    assert result["available"] is False
    assert "artifact not found" in result["reason"].lower()

@mock.patch("src.analysis.model_explainer._load_model")
def test_no_predict_proba(mock_load):
    # Model that only supports predict (no predict_proba)
    mock_load.return_value = make_mock_model(predict_proba=False)
    result = explain_url_model("https://example.com")
    # Probability should be derived from predict (cast to float)
    assert isinstance(result["probability"], float)
    assert result["explanation_method"] in ("SHAP", "model_feature_importance")

# Ensure unified analyzer still supports all artifact types after integration.
def test_unified_analyzer_url_support():
    from src.analysis.unified_analyzer import analyze_url
    resp = analyze_url("https://example.com", user_id=1)
    # Core keys must exist regardless of model availability.
    for key in ["analysis_id", "artifact_type", "risk", "summary", "signals", "details", "explanation", "errors", "ml", "evidence_correlation", "model_explanation"]:
        assert key in resp

def test_unified_analyzer_hash_support():
    from src.analysis.unified_analyzer import analyze_hash
    resp = analyze_hash("d41d8cd98f00b204e9800998ecf8427e", user_id=1)
    for key in ["analysis_id", "artifact_type", "risk", "summary", "signals", "details", "explanation", "errors"]:
        assert key in resp

def test_unified_analyzer_email_support():
    from src.analysis.unified_analyzer import analyze_email
    # Use a minimal temporary file for email – empty content is acceptable for this test.
    import tempfile, os
    fd, path = tempfile.mkstemp()
    os.close(fd)
    try:
        resp = analyze_email(path, user_id=1)
        for key in ["analysis_id", "artifact_type", "risk", "summary", "signals", "details", "explanation", "errors", "ml", "evidence_correlation"]:
            assert key in resp
    finally:
        os.remove(path)

def test_unified_analyzer_qr_support():
    from src.analysis.unified_analyzer import analyze_qr
    import tempfile, os
    fd, path = tempfile.mkstemp()
    os.close(fd)
    try:
        resp = analyze_qr(path, user_id=1)
        for key in ["analysis_id", "artifact_type", "risk", "summary", "signals", "details", "explanation", "errors"]:
            assert key in resp
    finally:
        os.remove(path)

def test_unified_analyzer_file_support():
    from src.analysis.unified_analyzer import analyze_file
    import tempfile, os
    fd, path = tempfile.mkstemp()
    os.write(fd, b"test")
    os.close(fd)
    try:
        resp = analyze_file(path, user_id=1)
        for key in ["analysis_id", "artifact_type", "risk", "summary", "signals", "details", "explanation", "errors"]:
            assert key in resp
    finally:
        os.remove(path)
