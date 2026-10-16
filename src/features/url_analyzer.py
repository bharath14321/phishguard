"""
Central URL analysis pipeline.

Every URL entering the phishing-detection platform should
eventually pass through this central analyzer.

Analysis layers:

    URL
     |
     +--> Lexical URL features
     |
     +--> Domain intelligence
     |
     +--> Brand intelligence
     |
     +--> IP intelligence
     |
     +--> VirusTotal reputation
     |
     +--> Redirect analysis
     |
     +--> Webpage analysis
     |
     +--> Final structured result

Each layer is isolated so that a failure in one module does
not stop the remaining analysis.
"""


# -------------------------------------------------------------
# IMPORT ANALYSIS MODULES
# -------------------------------------------------------------

from src.features.url_features import extract_url_features
from src.features.domain_intelligence import analyze_domain
from src.features.brand_intelligence import analyze_brand
from src.features.ip_intelligence import analyze_url_ip
from src.features.reputation import get_url_reputation
from src.features.redirect_analyzer import analyze_redirect_chain
from src.features.webpage_analyzer import analyze_webpage


# -------------------------------------------------------------
# MAIN URL ANALYZER
# -------------------------------------------------------------


def analyze_url(url: str, check_vt: bool = True) -> dict:
    """
    Run all URL-analysis layers.

    Parameters
    ----------
    url : str
        URL to analyze.
    check_vt : bool
        Whether to query VirusTotal during initial extraction (default True).
        Can be set to False if caller manages conditional Threat Intelligence escalation.

    Returns
    -------
    dict
        Structured results from all analysis modules.

    Every module has its own error handler. Therefore, if
    VirusTotal is unavailable, for example, the URL/domain/
    webpage analysis can still continue.
    """

    # Create the central result object.
    result = {
        "url": url,

        "url_features": {},
        "domain_intelligence": {},
        "brand_intelligence": {},
        "ip_intelligence": {},
        "virustotal": {},
        "redirect_analysis": {},
        "webpage_analysis": {},

        "errors": []
    }

    # ---------------------------------------------------------
    # 1. URL LEXICAL FEATURES
    # ---------------------------------------------------------

    try:

        result["url_features"] = (
            extract_url_features(url)
        )

    except Exception as error:

        result["errors"].append({
            "module": "url_features",
            "error": str(error)
        })

    # ---------------------------------------------------------
    # 2. DOMAIN INTELLIGENCE
    # ---------------------------------------------------------

    try:

        result["domain_intelligence"] = (
            analyze_domain(url)
        )

    except Exception as error:

        result["errors"].append({
            "module": "domain_intelligence",
            "error": str(error)
        })

    # ---------------------------------------------------------
    # 3. BRAND INTELLIGENCE
    # ---------------------------------------------------------

    try:

        result["brand_intelligence"] = (
            analyze_brand(url)
        )

    except Exception as error:

        result["errors"].append({
            "module": "brand_intelligence",
            "error": str(error)
        })

    # ---------------------------------------------------------
    # 4. IP INTELLIGENCE
    # ---------------------------------------------------------

    try:

        result["ip_intelligence"] = (
            analyze_url_ip(url)
        )

    except Exception as error:

        result["errors"].append({
            "module": "ip_intelligence",
            "error": str(error)
        })

    # ---------------------------------------------------------
    # 5. VIRUSTOTAL REPUTATION
    # ---------------------------------------------------------

    if check_vt:
        try:
            from src.features.reputation import normalize_vt_result
            result["virustotal"] = normalize_vt_result(get_url_reputation(url), url)
        except Exception as error:
            result["virustotal"] = {
                "status": "ERROR",
                "source": "virustotal",
                "provider": "VirusTotal",
                "malicious": 0,
                "total": 0,
                "is_clean": False,
                "is_unknown": True,
                "error": str(error),
                "message": "VirusTotal lookup encountered an error",
            }
            result["errors"].append({
                "module": "virustotal",
                "error": str(error)
            })
    else:
        result["virustotal"] = {
            "status": "NOT_REQUIRED",
            "source": "virustotal",
            "provider": "VirusTotal",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total": 0,
            "reputation": None,
            "is_clean": False,
            "is_unknown": False,
            "message": "External threat intelligence not required in initial extraction",
        }

    # ---------------------------------------------------------
    # 6. REDIRECT ANALYSIS
    # ---------------------------------------------------------

    try:

        result["redirect_analysis"] = (
            analyze_redirect_chain(url)
        )

    except Exception as error:

        result["errors"].append({
            "module": "redirect_analyzer",
            "error": str(error)
        })

    # ---------------------------------------------------------
    # 7. WEBPAGE ANALYSIS
    # ---------------------------------------------------------

    try:

        result["webpage_analysis"] = (
            analyze_webpage(url)
        )

    except Exception as error:

        result["errors"].append({
            "module": "webpage_analyzer",
            "error": str(error)
        })

    # Return the complete analysis.
    return result


# -------------------------------------------------------------
# TERMINAL OUTPUT HELPER
# -------------------------------------------------------------


def print_section(title):
    """
    Print a formatted section heading.
    """

    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


# -------------------------------------------------------------
# PRINT COMPLETE RESULT
# -------------------------------------------------------------


def print_url_analysis(result):
    """
    Print the complete URL-analysis result in a readable
    terminal format.

    Large structures such as all HTML links are summarized
    instead of dumping everything to the terminal.
    """

    # ---------------------------------------------------------
    # MAIN HEADER
    # ---------------------------------------------------------

    print_section(
        "CENTRAL URL ANALYSIS"
    )

    print("\nURL:")
    print(
        result.get(
            "url",
            "Unknown"
        )
    )

    # ---------------------------------------------------------
    # URL FEATURES
    # ---------------------------------------------------------

    print_section(
        "URL FEATURES"
    )

    url_features = result.get(
        "url_features",
        {}
    )

    if url_features:

        for key, value in url_features.items():

            print(
                f"{key}: {value}"
            )

    else:

        print(
            "No URL features available."
        )

    # ---------------------------------------------------------
    # DOMAIN INTELLIGENCE
    # ---------------------------------------------------------

    print_section(
        "DOMAIN INTELLIGENCE"
    )

    domain = result.get(
        "domain_intelligence",
        {}
    )

    if domain:

        for key, value in domain.items():

            print(
                f"{key}: {value}"
            )

    else:

        print(
            "No domain intelligence available."
        )

    # ---------------------------------------------------------
    # BRAND INTELLIGENCE
    # ---------------------------------------------------------

    print_section(
        "BRAND INTELLIGENCE"
    )

    brand = result.get(
        "brand_intelligence",
        {}
    )

    if brand:

        for key, value in brand.items():

            print(
                f"{key}: {value}"
            )

    else:

        print(
            "No brand intelligence available."
        )

    # ---------------------------------------------------------
    # IP INTELLIGENCE
    # ---------------------------------------------------------

    print_section(
        "IP INTELLIGENCE"
    )

    ip_info = result.get(
        "ip_intelligence",
        {}
    )

    if ip_info:

        for key, value in ip_info.items():

            print(
                f"{key}: {value}"
            )

    else:

        print(
            "No IP intelligence available."
        )

    # ---------------------------------------------------------
    # VIRUSTOTAL
    # ---------------------------------------------------------

    print_section(
        "VIRUSTOTAL"
    )

    virustotal = result.get(
        "virustotal",
        {}
    )

    if virustotal:

        for key, value in virustotal.items():

            print(
                f"{key}: {value}"
            )

    else:

        print(
            "No VirusTotal result available."
        )

    # ---------------------------------------------------------
    # REDIRECT ANALYSIS
    # ---------------------------------------------------------

    print_section(
        "REDIRECT ANALYSIS"
    )

    redirects = result.get(
        "redirect_analysis",
        {}
    )

    if redirects:

        # Print the most important redirect information.
        for key in [
            "redirect_count",
            "final_url",
            "status_codes"
        ]:

            if key in redirects:

                print(
                    f"{key}: "
                    f"{redirects[key]}"
                )

        # Print the complete redirect chain.
        chain = redirects.get(
            "redirect_chain",
            []
        )

        if chain:

            print(
                "\nRedirect chain:"
            )

            for item in chain:

                print(
                    f"  {item}"
                )

    else:

        print(
            "No redirect information available."
        )

    # ---------------------------------------------------------
    # WEBPAGE ANALYSIS
    # ---------------------------------------------------------

    print_section(
        "WEBPAGE ANALYSIS"
    )

    webpage = result.get(
        "webpage_analysis",
        {}
    )

    if webpage:

        # Print important webpage fields.
        webpage_fields = [
            "fetch_success",
            "is_html",
            "status_code",
            "content_type",
            "title",
            "page_size",
            "form_count",
            "password_field_count",
            "link_count",
            "resource_count",
            "external_resource_count",
            "iframe_count",
            "script_count"
        ]

        for key in webpage_fields:

            if key in webpage:

                print(
                    f"{key}: "
                    f"{webpage[key]}"
                )

        # Print suspicious HTML patterns.
        suspicious_patterns = webpage.get(
            "suspicious_html_patterns",
            []
        )

        if suspicious_patterns:

            print(
                "\nSuspicious HTML patterns:"
            )

            for pattern in suspicious_patterns:

                print(
                    f"  {pattern}"
                )

        # Print webpage errors if the analyzer generated one.
        if "error" in webpage:

            print(
                "\nWebpage error:"
            )

            print(
                webpage["error"]
            )

    else:

        print(
            "No webpage analysis available."
        )

    # ---------------------------------------------------------
    # MODULE ERRORS
    # ---------------------------------------------------------

    print_section(
        "ANALYSIS ERRORS"
    )

    errors = result.get(
        "errors",
        []
    )

    if errors:

        for error in errors:

            print(
                f"{error['module']}: "
                f"{error['error']}"
            )

    else:

        print(
            "No module errors."
        )

    # ---------------------------------------------------------
    # COMPLETE
    # ---------------------------------------------------------

    print(
        "\n" + "=" * 60
    )

    print(
        "URL ANALYSIS COMPLETE"
    )

    print(
        "=" * 60
    )


# -------------------------------------------------------------
# DIRECT TEST
# -------------------------------------------------------------


if __name__ == "__main__":

    # Use a harmless URL for testing.
    TEST_URL = "https://example.com"

    print(
        f"\nAnalyzing URL: {TEST_URL}"
    )

    # Run the complete pipeline.
    result = analyze_url(
        TEST_URL
    )

    # Display the result.
    print_url_analysis(
        result
    )
