import re
import ipaddress
from urllib.parse import urlparse

import tldextract


SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "bank",
    "wallet",
    "billing",
    "payment",
    "authenticate",
]
def normalize_url(url):
    """
    Normalize a URL before extracting features.

    Purpose:
        URLs are case-insensitive in their scheme and hostname.
        Lowercasing and stripping whitespace prevents the ML feature extractor
        from treating simple capitalization or leading/trailing whitespace
        as distinct inputs.

    Scheme Handling:
        - If the URL explicitly starts with http:// or https:// (case-insensitively),
          the scheme is preserved in lowercase.
        - If the URL does not contain an explicit scheme (schemeless), a parsing scheme
          ('http://') is prepended solely to enable RFC-compliant URL component parsing
          (hostname, path, query).
        - The original URL string should be preserved separately for forensics and auditing.
    """

    # Convert the input to a string and remove surrounding spaces.
    url = str(url).strip()

    # Return an empty string if no URL was provided.
    if not url:
        return ""

    # Convert to lowercase to ensure case-insensitive scheme and domain handling.
    url = url.lower()

    # Add a parsing scheme when the dataset/input does not contain one.
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    return url
def is_ip_address(hostname):
    if not hostname:
        return 0

    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


# Module-level offline TLDExtract instance to prevent live network calls during feature extraction
_tld_extractor = tldextract.TLDExtract(suffix_list_urls=None)


def extract_url_features(url):
    """
    Extract 14 lexical and structural features from a URL for machine learning inference.

    Features extracted:
    - 4 length features: url_length, hostname_length, path_length, query_length
    - 4 character counts: dot_count, hyphen_count, digit_count, special_char_count
    - 5 structural flags: subdomain_count, contains_ip, uses_https, contains_at, contains_double_slash
    - 1 keyword count: suspicious_keyword_count

    Parameters:
        url: Raw URL string to extract features from.

    Returns:
        dict: Mapping of exact 14 feature names to numeric values.
    """
    # Step 1: Normalize URL (ensure scheme is present, lowercase, strip whitespace)
    url = normalize_url(url)

    # Step 2: Parse URL components with urllib
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # Step 3: Extract domain and subdomain components using offline TLDExtract
    extracted = _tld_extractor(url)
    subdomain = extracted.subdomain

    features = {}

    # Basic lengths
    features["url_length"] = len(url)
    features["hostname_length"] = len(hostname)
    features["path_length"] = len(path)
    features["query_length"] = len(query)

    # Character counts
    features["dot_count"] = url.count(".")
    features["hyphen_count"] = url.count("-")
    features["digit_count"] = sum(c.isdigit() for c in url)

    features["special_char_count"] = sum(
        not c.isalnum() for c in url
    )

    # Structure
    features["subdomain_count"] = (
        len(subdomain.split("."))
        if subdomain
        else 0
    )

    features["contains_ip"] = is_ip_address(hostname)

    features["uses_https"] = int(
        parsed.scheme.lower() == "https"
    )

    features["contains_at"] = int("@" in url)

    features["contains_double_slash"] = int(
        "//" in parsed.path
    )

    # Suspicious keywords
    url_lower = url.lower()

    features["suspicious_keyword_count"] = sum(
        keyword in url_lower
        for keyword in SUSPICIOUS_KEYWORDS
    )

    return features


if __name__ == "__main__":

    test_url = "https://www.google.com"

    result = extract_url_features(test_url)

    for key, value in result.items():
      print(f"{key}: {value}")
