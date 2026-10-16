"""
Redirect Chain Analyzer

This module follows HTTP redirects and records every URL
visited before reaching the final destination.

Example:

URL A
  ↓ 301
URL B
  ↓ 302
URL C
  ↓ 301
URL D

The complete chain can later become a feature for our
phishing risk engine.

SSRF Security:
Uses safe_fetcher to validate destination IP and prevent DNS rebinding
at every redirect hop.
"""

from urllib.parse import urljoin
from src.features.domain_intelligence import normalize_url
from src.features.safe_fetcher import safe_get, REQUEST_TIMEOUT, MAX_REDIRECTS_DEFAULT

MAX_REDIRECTS = MAX_REDIRECTS_DEFAULT


def analyze_redirect_chain(url: str, max_redirects: int = MAX_REDIRECTS, timeout: int = REQUEST_TIMEOUT) -> dict:
    """Follow redirects safely and return detailed hops and security telemetry.

    SSRF Protection:
    Every hop destination is validated via safe_get before navigating, preventing
    private network, loopback, or cloud metadata SSRF exploitation.

    Parameters
    ----------
    url: str
        The initial target URL.
    timeout: int
        HTTP socket timeout per hop.

    Returns
    -------
    dict
        Standardized redirect contract containing:
        - status: COMPLETED | NO_REDIRECT | BLOCKED | TIMEOUT | ERROR | NOT_EVALUATED
        - original_url: Initial requested URL
        - final_url: Destination URL reached
        - redirect_count: Number of redirect hops
        - hops: List of hop records {from_url, status_code, location, to_url}
        - error_reason: Error message if failed, else None
        - redirect_chain: List of traversed URLs (backward compatibility)
        - status_codes: List of observed HTTP status codes
    """
    if not url or not str(url).strip():
        return {
            "status": "NOT_EVALUATED",
            "original_url": url or "",
            "final_url": url or "",
            "redirect_count": 0,
            "hops": [],
            "error_reason": "No target URL provided for redirect inspection.",
            "redirect_chain": [],
            "status_codes": [],
            "success": False,
            "blocked": False,
        }

    # Normalize the URL before initiating safe requests
    norm_url = normalize_url(url)
    redirect_chain = []
    status_codes = []
    hops = []
    current_url = norm_url

    try:
        for _ in range(max_redirects):
            fetch_result = safe_get(current_url, timeout=timeout)
            redirect_chain.append(current_url)

            if not fetch_result.get("success"):
                is_blocked = fetch_result.get("blocked", False)
                raw_err = fetch_result.get("reason") or fetch_result.get("error", "Request failed")
                # Classify failure status accurately
                if is_blocked:
                    status_val = "BLOCKED"
                elif "timeout" in str(raw_err).lower() or "timed out" in str(raw_err).lower():
                    status_val = "TIMEOUT"
                else:
                    status_val = "ERROR"

                return {
                    "status": status_val,
                    "original_url": norm_url,
                    "final_url": current_url,
                    "redirect_count": max(0, len(hops)),
                    "hops": hops,
                    "error_reason": raw_err,
                    "redirect_chain": redirect_chain,
                    "status_codes": status_codes,
                    "success": False,
                    "blocked": is_blocked,
                    "max_redirects_reached": False,
                }

            status_code = fetch_result.get("status_code", 0)
            status_codes.append(status_code)

            # Not a redirect status code (e.g. 200 OK, 404, etc.)
            if status_code not in (301, 302, 303, 307, 308):
                status_val = "NO_REDIRECT" if len(hops) == 0 else "COMPLETED"
                return {
                    "status": status_val,
                    "original_url": norm_url,
                    "final_url": current_url,
                    "redirect_count": len(hops),
                    "hops": hops,
                    "error_reason": None,
                    "redirect_chain": redirect_chain,
                    "status_codes": status_codes,
                    "success": True,
                    "blocked": False,
                    "max_redirects_reached": False,
                }

            # Response is a redirect: extract Location header
            headers = fetch_result.get("headers", {})
            location_val = headers.get("Location") or headers.get("location")

            if not location_val:
                # Redirect status without Location header
                return {
                    "status": "COMPLETED" if len(hops) > 0 else "ERROR",
                    "original_url": norm_url,
                    "final_url": current_url,
                    "redirect_count": len(hops),
                    "hops": hops,
                    "error_reason": "Redirect status code returned without Location header." if len(hops) == 0 else None,
                    "redirect_chain": redirect_chain,
                    "status_codes": status_codes,
                    "success": len(hops) > 0,
                    "blocked": False,
                    "max_redirects_reached": False,
                }

            # Resolve relative destination URLs
            destination_url = urljoin(current_url, location_val)

            # Record this observable hop
            hops.append({
                "from_url": current_url,
                "status_code": status_code,
                "location": location_val,
                "to_url": destination_url,
            })

            # Detect redirect loop
            if destination_url in redirect_chain:
                redirect_chain.append(destination_url)
                return {
                    "status": "COMPLETED",
                    "original_url": norm_url,
                    "final_url": destination_url,
                    "redirect_count": len(hops),
                    "hops": hops,
                    "error_reason": f"Redirect loop detected: {destination_url} previously traversed.",
                    "redirect_chain": redirect_chain,
                    "status_codes": status_codes,
                    "success": True,
                    "blocked": False,
                    "loop_detected": True,
                    "max_redirects_reached": False,
                }

            current_url = destination_url

        # Exceeded maximum allowable redirect hops
        return {
            "status": "BLOCKED",
            "original_url": norm_url,
            "final_url": current_url,
            "redirect_count": len(hops),
            "hops": hops,
            "error_reason": f"Exceeded maximum allowable redirect limit of {MAX_REDIRECTS} hops.",
            "redirect_chain": redirect_chain,
            "status_codes": status_codes,
            "success": False,
            "blocked": True,
            "max_redirects_reached": True,
        }

    except Exception as error:
        err_str = str(error)
        status_val = "TIMEOUT" if "timeout" in err_str.lower() else "ERROR"
        return {
            "status": status_val,
            "original_url": norm_url,
            "final_url": current_url,
            "redirect_count": len(hops),
            "hops": hops,
            "error_reason": err_str,
            "redirect_chain": redirect_chain,
            "status_codes": status_codes,
            "success": False,
            "blocked": False,
            "max_redirects_reached": False,
        }

# Public alias for redirect tracing
trace_redirect_chain = analyze_redirect_chain


def main():
    """
    Test the redirect analyzer.
    """
    test_urls = [
        "http://google.com",
        "https://example.com"
    ]

    for test_url in test_urls:
        print("\n" + "=" * 60)
        print("Testing:", test_url)
        result = analyze_redirect_chain(test_url)
        print("\nOriginal URL:", result.get("original_url"))
        print("Final URL:", result.get("final_url"))
        print("Redirect count:", result.get("redirect_count"))
        print("Status codes:", result.get("status_codes"))
        print("Chain:", result.get("redirect_chain"))


if __name__ == "__main__":
    main()
