"""
Webpage analysis module.

This module fetches a webpage and extracts security-relevant
HTML characteristics.

IMPORTANT:
This is analysis only. It does not submit credentials,
interact with forms, or execute page JavaScript.

SSRF Security:
Uses safe_fetcher to validate destination IP, prevent DNS rebinding,
and enforce response size/timeout limits.
"""

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from src.features.safe_fetcher import safe_get, REQUEST_TIMEOUT, MAX_RESPONSE_SIZE


class SafeWebpageResponse:
    """
    Lightweight response wrapper maintaining backward compatibility
    with the previous requests.Response interface.
    """

    def __init__(self, status_code: int, headers: dict, text: str, content: bytes):
        self.status_code = status_code
        self.headers = headers
        self.text = text
        self.content = content


def fetch_webpage_detailed(url: str, timeout: int = REQUEST_TIMEOUT) -> tuple[Optional[SafeWebpageResponse], Dict[str, Any]]:
    """Fetch a webpage using SSRF-safe HTTP request, capturing detailed network/security telemetry.

    Security & Safety:
    - Enforces SSRF destination IP verification (blocking internal CIDRs, loopbacks, metadata IPs).
    - Pins connection socket to verified IP to block DNS rebinding.
    - Capped to 2 MB maximum response buffer to avoid memory exhaustion.
    - Strict network timeout applied.

    Returns:
        tuple (SafeWebpageResponse or None, metadata_dict)
    """
    try:
        result = safe_get(url, timeout=timeout)
        if not result.get("success"):
            reason = result.get("reason") or "Network fetch failed"
            is_blocked = result.get("blocked", False)
            return None, {
                "success": False,
                "blocked": is_blocked,
                "reason": reason,
                "validation": result.get("validation", {}),
            }

        resp = SafeWebpageResponse(
            status_code=result.get("status_code", 200),
            headers=result.get("headers", {}),
            text=result.get("text", ""),
            content=result.get("content", b"")
        )
        return resp, {
            "success": True,
            "blocked": False,
            "status_code": result.get("status_code", 200),
            "headers": result.get("headers", {}),
            "pinned_ip": result.get("pinned_ip"),
            "final_url": result.get("url", url),
        }
    except Exception as exc:
        err_msg = str(exc)
        return None, {
            "success": False,
            "blocked": False,
            "reason": f"Fetch error: {err_msg}",
        }


def fetch_webpage(url: str, timeout: int = REQUEST_TIMEOUT):
    """Backward-compatible helper returning SafeWebpageResponse or None."""
    resp, _ = fetch_webpage_detailed(url, timeout=timeout)
    return resp


def extract_forms(soup):
    """
    Extract HTML form information.
    Forms are important because phishing pages commonly request credentials.
    """
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            inputs.append({
                "type": input_tag.get("type", "text").lower(),
                "name": input_tag.get("name"),
            })
        forms.append({
            "action": action,
            "method": method,
            "inputs": inputs,
        })
    return forms


def count_password_fields(soup):
    """
    Count password input fields on the webpage.
    """
    count = 0
    for input_tag in soup.find_all("input"):
        input_type = input_tag.get("type", "").lower()
        if input_type == "password":
            count += 1
    return count


def extract_links(soup, base_url):
    """
    Extract links from the webpage with absolute URLs.
    """
    links = []
    for anchor in soup.find_all("a", href=True):
        href = anchor.get("href")
        absolute_url = urljoin(base_url, href)
        links.append({
            "text": anchor.get_text(" ", strip=True),
            "url": absolute_url,
        })
    return links


def extract_external_resources(soup, base_url):
    """
    Identify external resources such as scripts, stylesheets, images, iframes.
    """
    base_hostname = urlparse(base_url).hostname if base_url else ""
    resources = []

    for script in soup.find_all("script", src=True):
        url = urljoin(base_url, script["src"])
        resources.append({
            "type": "script",
            "url": url,
            "external": urlparse(url).hostname != base_hostname if base_hostname else False,
        })

    for link in soup.find_all("link", href=True):
        rel = link.get("rel", [])
        if "stylesheet" in rel:
            url = urljoin(base_url, link["href"])
            resources.append({
                "type": "stylesheet",
                "url": url,
                "external": urlparse(url).hostname != base_hostname if base_hostname else False,
            })

    for image in soup.find_all("img", src=True):
        url = urljoin(base_url, image["src"])
        resources.append({
            "type": "image",
            "url": url,
            "external": urlparse(url).hostname != base_hostname if base_hostname else False,
        })

    for iframe in soup.find_all("iframe", src=True):
        url = urljoin(base_url, iframe["src"])
        resources.append({
            "type": "iframe",
            "url": url,
            "external": urlparse(url).hostname != base_hostname if base_hostname else False,
        })

    return resources


def detect_suspicious_html_patterns(html):
    """
    Look for common suspicious HTML patterns like obfuscation or credential collection prompts.
    """
    patterns = {
        "javascript_obfuscation": [
            r"eval\s*\(",
            r"atob\s*\(",
            r"fromCharCode\s*\(",
        ],
        "credential_language": [
            r"verify\s+your\s+account",
            r"confirm\s+your\s+identity",
            r"enter\s+your\s+password",
            r"sign\s+in",
            r"login",
        ],
    }
    matches = []
    html_lower = (html or "").lower()
    for category, expressions in patterns.items():
        for expression in expressions:
            if re.search(expression, html_lower):
                matches.append({
                    "category": category,
                    "pattern": expression,
                })
    return matches


def analyze_html_content(html: str, base_url: str = "") -> dict:
    """
    Statically inspect HTML string for forms, password fields, resources,
    and cross-domain submission destinations.
    """
    soup = BeautifulSoup(html or "", "html.parser")
    page_hostname = urlparse(base_url).hostname or "" if base_url else ""

    forms = extract_forms(soup)
    password_fields = count_password_fields(soup)
    links = extract_links(soup, base_url) if base_url else []
    resources = extract_external_resources(soup, base_url) if base_url else []
    suspicious_patterns = detect_suspicious_html_patterns(html or "")

    # Detailed form and login inspection
    cross_domain_forms = []
    has_login_form = False
    for f in forms:
        action = f.get("action", "")
        method = f.get("method", "get")
        has_pwd = any(inp.get("type") == "password" for inp in f.get("inputs", []))
        if has_pwd or any("pass" in str(inp.get("name", "")).lower() for inp in f.get("inputs", [])):
            has_login_form = True

        if action and base_url:
            abs_action = urljoin(base_url, action)
            act_host = urlparse(abs_action).hostname or ""
            if act_host and page_hostname and act_host.lower() != page_hostname.lower():
                cross_domain_forms.append({
                    "action_url": abs_action,
                    "target_hostname": act_host,
                    "method": method,
                    "inputs_count": len(f.get("inputs", [])),
                    "has_password": has_pwd,
                })

    # Scripts and images
    scripts = [r["url"] for r in resources if r.get("type") == "script"]
    external_images = [r["url"] for r in resources if r.get("type") == "image" and r.get("external")]

    return {
        "title": soup.title.get_text(strip=True) if soup.title else None,
        "page_size": len(html or ""),
        "form_count": len(forms),
        "password_field_count": password_fields,
        "has_login_form": has_login_form,
        "has_password_field": password_fields > 0,
        "cross_domain_forms": cross_domain_forms,
        "has_cross_domain_submission": len(cross_domain_forms) > 0,
        "forms": forms,
        "link_count": len(links),
        "links": links[:50],  # capped for memory safety
        "resource_count": len(resources),
        "external_resource_count": sum(1 for r in resources if r.get("external")),
        "scripts": scripts[:30],
        "script_count": len(scripts),
        "external_images": external_images[:30],
        "iframe_count": len(soup.find_all("iframe")),
        "suspicious_html_patterns": suspicious_patterns,
        "login_assessment": (
            "A login form alone is not proof of phishing. Authentication safety depends on "
            "domain registration legitimacy, TLS certificate alignment, and absence of deceptive redirection."
        ),
        "limitations": "Passive static HTML inspection only. JavaScript rendering, form submission, and session cookies are not executed.",
    }


def analyze_webpage(url: str) -> dict:
    """Perform comprehensive, explainable webpage inspection on a given destination.

    Analyzes HTML structures, forms, password collection inputs, external resources,
    and cross-domain submission destinations without executing scripts or submitting data.
    """
    if not url or not str(url).strip():
        return {
            "url": url or "",
            "fetch_success": False,
            "status": "NOT_EVALUATED",
            "error": "No URL supplied for webpage analysis.",
            "error_reason": "URL absent.",
        }

    response, meta = fetch_webpage_detailed(url)

    if response is None:
        raw_reason = meta.get("reason", "Unable to safely fetch webpage.")
        # Categorize fetch failure reason
        reason_lower = raw_reason.lower()
        if "timeout" in reason_lower or "timed out" in reason_lower:
            failure_category = "network_timeout"
        elif "could not be resolved" in reason_lower or "dns" in reason_lower:
            failure_category = "dns_resolution_failure"
        elif "restricted or private ip" in reason_lower or meta.get("blocked"):
            failure_category = "blocked_by_ssrf_policy"
        elif "tls" in reason_lower or "certificate" in reason_lower or "ssl" in reason_lower:
            failure_category = "tls_validation_failure"
        elif "size limit" in reason_lower or "exceeded" in reason_lower:
            failure_category = "response_too_large"
        else:
            failure_category = "external_service_unavailable"

        return {
            "url": url,
            "fetch_success": False,
            "status": "FETCH_FAILED",
            "failure_category": failure_category,
            "error": raw_reason,
            "error_reason": raw_reason,
            "is_html": False,
            "form_count": 0,
            "password_field_count": 0,
            "forms": [],
            "links": [],
            "resources": [],
            "suspicious_html_patterns": [],
            "limitations": "Webpage content could not be retrieved; passive heuristic and threat-feed evidence relied upon.",
        }

    content_type = response.headers.get("Content-Type", "").lower()

    # Parse non-HTML responses
    if "html" not in content_type:
        return {
            "url": url,
            "fetch_success": True,
            "status": "NON_HTML_CONTENT",
            "is_html": False,
            "status_code": response.status_code,
            "content_type": content_type,
            "page_size": len(response.text),
            "response_size_bytes": len(response.content),
            "form_count": 0,
            "password_field_count": 0,
            "forms": [],
            "links": [],
            "resources": [],
            "suspicious_html_patterns": [],
            "limitations": f"Response content-type '{content_type}' is not HTML.",
        }

    html_analysis = analyze_html_content(response.text, base_url=url)

    res = {
        "url": url,
        "fetch_success": True,
        "status": "SUCCESS",
        "is_html": True,
        "status_code": response.status_code,
        "content_type": content_type,
        "response_size_bytes": len(response.content),
    }
    res.update(html_analysis)
    return res


def print_webpage_analysis(result):
    """
    Print webpage analysis in a readable format.
    """
    print("\n" + "=" * 60)
    print("WEBPAGE ANALYSIS")
    print("=" * 60)

    for key, value in result.items():
        if key in {"links", "forms"}:
            print(f"\n{key}: {len(value)} item(s)")
        else:
            print(f"\n{key}: {value}")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    TEST_URL = "https://example.com"
    result = analyze_webpage(TEST_URL)
    print_webpage_analysis(result)
