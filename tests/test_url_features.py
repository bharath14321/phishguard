from src.features.url_features import extract_url_features, normalize_url
from src.features.url_analyzer import analyze_url
from src.models.url_model_inference import predict_url


def test_basic_extraction():

    url = "https://example.com/login"

    features = extract_url_features(url)

    assert features["url_length"] > 0
    assert features["uses_https"] == 1


def test_ip_detection():

    url = "http://192.0.2.10/login"

    features = extract_url_features(url)

    assert features["contains_ip"] == 1


def test_keyword_detection():

    url = "https://example.com/login/verify"

    features = extract_url_features(url)

    assert features["suspicious_keyword_count"] >= 2


def test_scheme_normalization_cases():
    """Verify that normalize_url handles lowercase, uppercase, and schemeless URLs properly."""
    assert normalize_url("example.com/login") == "http://example.com/login"
    assert normalize_url("http://example.com/login") == "http://example.com/login"
    assert normalize_url("https://example.com/login") == "https://example.com/login"
    assert normalize_url("HTTP://example.com/login") == "http://example.com/login"
    assert normalize_url("HTTPS://example.com/login") == "https://example.com/login"
    assert normalize_url("  HTTPS://EXAMPLE.COM/Path  ") == "https://example.com/path"
    assert normalize_url("") == ""


def test_uses_https_derivation():
    """Verify uses_https is 1 only when HTTPS is explicitly specified in the URL (case-insensitive)."""
    f_schemeless = extract_url_features("example.com/login")
    assert f_schemeless["uses_https"] == 0
    assert f_schemeless["hostname_length"] == 11

    f_http = extract_url_features("http://example.com/login")
    assert f_http["uses_https"] == 0

    f_https = extract_url_features("https://example.com/login")
    assert f_https["uses_https"] == 1

    f_http_upper = extract_url_features("HTTP://example.com/login")
    assert f_http_upper["uses_https"] == 0
    assert f_http_upper["contains_double_slash"] == 0

    f_https_upper = extract_url_features("HTTPS://example.com/login")
    assert f_https_upper["uses_https"] == 1
    assert f_https_upper["hostname_length"] == 11
    assert f_https_upper["contains_double_slash"] == 0


def test_training_vs_runtime_feature_consistency():
    """Verify exact parity across extract_url_features, analyze_url, and predict_url."""
    test_urls = [
        "example.com/login",
        "http://example.com/login",
        "https://example.com/login",
        "HTTP://example.com/login",
        "HTTPS://example.com/login",
        "https://sub.domain.co.uk/path/to/page?user=test#sec",
        "http://192.168.1.1/admin/login.php",
    ]

    for url in test_urls:
        f_train = extract_url_features(url)
        f_analyzer = analyze_url(url)["url_features"]
        f_predict = predict_url(url)["features"]

        assert f_train == f_analyzer, f"Analyzer feature mismatch for {url}"
        assert f_train == f_predict, f"Predict feature mismatch for {url}"
