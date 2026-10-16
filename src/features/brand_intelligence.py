"""
Brand Intelligence Module

Purpose:
    Detect whether a known brand name appears in a URL but the
    actual registrable domain belongs to a different domain.

Example:

    paypal.com
        -> legitimate-looking domain relationship

    paypal.com.example.net
        -> "paypal" appears in the hostname, but the actual
           registrable domain is example.net.

This is a supporting security signal, NOT a final phishing verdict.
"""

import re

import tldextract


# ================================================================
# Known brands
# ================================================================

# Initial controlled brand list.
#
# Later this can be expanded and eventually replaced or supplemented
# with a configurable brand database.
KNOWN_BRANDS = [
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "facebook",
    "instagram",
    "netflix",
    "linkedin",
    "github",
    "dropbox",
    "adobe",
    "steam",
    "linkedin",
]


# ================================================================
# URL hostname extraction
# ================================================================

def extract_hostname(url):
    """
    Extract the hostname from a URL.

    Example:
        https://login.paypal.com/account
        ->
        login.paypal.com
    """

    # Add a scheme when the URL does not already have one.
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # Remove the scheme.
    hostname = url.split("://", 1)[1].split("/", 1)[0]

    # Remove a port if one exists.
    hostname = hostname.split(":", 1)[0]

    return hostname.lower()


# ================================================================
# Domain extraction
# ================================================================

def extract_domain_parts(hostname):
    """
    Extract the registrable domain and subdomain.

    Example:
        login.paypal.example.com

    Returns:
        subdomain = login.paypal
        domain    = example
        suffix    = com
    """

    extracted = tldextract.extract(hostname)

    return {
        "subdomain": extracted.subdomain,
        "domain": extracted.domain,
        "suffix": extracted.suffix,
        "registrable_domain": (
            f"{extracted.domain}.{extracted.suffix}"
            if extracted.domain and extracted.suffix
            else extracted.domain
        )
    }


# ================================================================
# Brand detection
# ================================================================

def detect_brands(hostname, path=""):
    """
    Detect known brand names appearing in the hostname or URL path.

    Returns:
        List of detected brand names.

    We search the hostname and path separately because a brand can
    appear in either location.
    """

    # Convert everything to lowercase so detection is
    # case-insensitive.
    searchable_text = (
        hostname + "/" + path
    ).lower()

    detected_brands = []

    for brand in KNOWN_BRANDS:

        # Match the brand as a meaningful hostname/path token.
        #
        # This avoids some accidental substring matches.
        pattern = rf"(?<![a-z0-9]){re.escape(brand)}(?![a-z0-9])"

        if re.search(pattern, searchable_text):
            detected_brands.append(brand)

    return detected_brands


# ================================================================
# Brand/domain relationship
# ================================================================

def analyze_brand_domain_relationship(
    hostname,
    registrable_domain,
    detected_brands
):
    """
    Determine whether detected brands are related to the
    registrable domain.

    Example:

        hostname:
            paypal.com.example.net

        registrable domain:
            example.net

        detected brand:
            paypal

        Result:
            brand_domain_mismatch = True
    """

    registrable_domain_lower = registrable_domain.lower()

    results = []

    for brand in detected_brands:

        # Check whether the brand is part of the actual
        # registrable domain.
        brand_matches_domain = (
            brand in registrable_domain_lower
        )

        # Check whether the brand occurs in the subdomain/hostname.
        brand_in_hostname = (
            brand in hostname.lower()
        )

        # A mismatch exists when a brand appears in the hostname
        # but the actual registrable domain does not represent it.
        mismatch = (
            brand_in_hostname
            and not brand_matches_domain
        )

        results.append({
            "brand": brand,
            "brand_in_hostname": brand_in_hostname,
            "brand_matches_registrable_domain":
                brand_matches_domain,
            "brand_domain_mismatch": mismatch
        })

    return results


# ================================================================
# Complete brand analysis
# ================================================================

def analyze_brand(url):
    """
    Perform complete brand/domain analysis for a URL.

    Returns:
        Dictionary containing detected brands and their
        relationship with the actual registrable domain.
    """

    # Extract hostname.
    hostname = extract_hostname(url)

    # Extract everything after the hostname so we can also
    # inspect the path for brand references.
    remainder = ""

    if "://" in url:
        remainder = url.split("://", 1)[1]

    if "/" in remainder:
        path = remainder.split("/", 1)[1]
    else:
        path = ""

    # Extract domain components.
    domain_parts = extract_domain_parts(hostname)

    registrable_domain = domain_parts[
        "registrable_domain"
    ]

    # Detect known brands.
    detected_brands = detect_brands(
        hostname,
        path
    )

    # Analyze relationship between each brand and domain.
    relationships = analyze_brand_domain_relationship(
        hostname,
        registrable_domain,
        detected_brands
    )

    # Determine whether at least one mismatch exists.
    mismatch_detected = any(
        item["brand_domain_mismatch"]
        for item in relationships
    )

    return {
        "url": url,
        "hostname": hostname,
        "registrable_domain": registrable_domain,
        "detected_brands": detected_brands,
        "brand_relationships": relationships,
        "brand_domain_mismatch": mismatch_detected
    }


# ================================================================
# Testing
# ================================================================

def main():
    """
    Test brand intelligence against controlled examples.
    """

    test_urls = [
        "https://paypal.com/login",

        "https://login.paypal.com/account",

        "https://paypal.com.example.net/login",

        "https://secure.microsoft.com/login",

        "https://microsoft.login.example.net/account",

        "https://example.com/paypal/login",
    ]

    print("=" * 70)
    print("BRAND INTELLIGENCE TEST")
    print("=" * 70)

    for url in test_urls:

        print("\nURL:")
        print(url)

        result = analyze_brand(url)

        print("\nResult:")

        for key, value in result.items():
            print(f"{key}: {value}")

        print("-" * 70)


# ================================================================
# Program entry point
# ================================================================

if __name__ == "__main__":
    main()
