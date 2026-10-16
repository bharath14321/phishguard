"""
Email Authentication Analysis

Analyzes authentication results found inside an email's headers.

Checks:
- SPF
- DKIM
- DMARC

Important:
These results are signals, not final phishing decisions.
"""

import re


def extract_authentication_results(message):
    """
    Extract Authentication-Results and related authentication headers.

    Returns a dict with:
        authentication_results: list of Authentication-Results header strings
        received_spf: list of Received-SPF header strings
    """
    if not hasattr(message, "get_all"):
        return {"authentication_results": [], "received_spf": []}

    auth_results = message.get_all("Authentication-Results", []) or []
    received_spf = message.get_all("Received-SPF", []) or []

    return {
        "authentication_results": [str(h) for h in auth_results],
        "received_spf": [str(h) for h in received_spf]
    }


def extract_auth_status(authentication_headers, received_spf_headers=None):
    """
    Extract SPF, DKIM and DMARC status from Authentication-Results and Received-SPF.

    Strictly differentiates between:
        - pass / passed
        - fail / failed
        - softfail
        - neutral
        - none
        - temperror
        - permerror
        - absent (when the header or specific check is not present)
        - unknown

    SECURITY RULE: An absent header is NEVER inferred as a failure.
    """
    if received_spf_headers is None:
        received_spf_headers = []

    # If no authentication headers are present at all
    if not authentication_headers and not received_spf_headers:
        return {
            "spf": "absent",
            "dkim": "absent",
            "dmarc": "absent",
            "header_present": False,
        }

    combined_headers = " ".join(
        str(header) for header in authentication_headers
    ).lower()

    result = {
        "spf": "absent",
        "dkim": "absent",
        "dmarc": "absent",
        "header_present": bool(authentication_headers or received_spf_headers),
    }

    # Search for SPF result in Authentication-Results
    spf_match = re.search(r"\bspf\s*=\s*([a-z]+)", combined_headers)
    if spf_match:
        val = spf_match.group(1).lower()
        result["spf"] = "pass" if val == "pass" else val
    elif received_spf_headers:
        # Fallback to Received-SPF header
        spf_combined = " ".join(str(h) for h in received_spf_headers).lower()
        r_spf_match = re.search(r"^(pass|fail|softfail|neutral|none|temperror|permerror)\b", spf_combined.strip())
        if r_spf_match:
            result["spf"] = r_spf_match.group(1)
        elif "pass" in spf_combined:
            result["spf"] = "pass"
        elif "fail" in spf_combined:
            result["spf"] = "fail"

    # Search for DKIM result
    dkim_match = re.search(r"\bdkim\s*=\s*([a-z]+)", combined_headers)
    if dkim_match:
        val = dkim_match.group(1).lower()
        result["dkim"] = "pass" if val == "pass" else val

    # Search for DMARC result
    dmarc_match = re.search(r"\bdmarc\s*=\s*([a-z]+)", combined_headers)
    if dmarc_match:
        val = dmarc_match.group(1).lower()
        result["dmarc"] = "pass" if val == "pass" else val

    return result


def calculate_authentication_signals(auth_status):
    """
    Convert authentication results into clean risk signals.
    'absent' or 'unknown' status is NOT treated as a failure.
    """
    spf_val = auth_status.get("spf", "absent").lower()
    dkim_val = auth_status.get("dkim", "absent").lower()
    dmarc_val = auth_status.get("dmarc", "absent").lower()

    return {
        "spf_pass": spf_val in ("pass", "passed"),
        "dkim_pass": dkim_val in ("pass", "passed"),
        "dmarc_pass": dmarc_val in ("pass", "passed"),

        "spf_fail": spf_val in ("fail", "failed", "softfail"),
        "dkim_fail": dkim_val in ("fail", "failed"),
        "dmarc_fail": dmarc_val in ("fail", "failed"),

        "spf_absent": spf_val in ("absent", "unknown", "not_evaluated"),
        "dkim_absent": dkim_val in ("absent", "unknown", "not_evaluated"),
        "dmarc_absent": dmarc_val in ("absent", "unknown", "not_evaluated"),
    }


def check_published_dns_policy(domain: str) -> dict:
    """
    Query published DNS authentication policies (SPF, DMARC) for a domain.
    Missing/failed DNS lookups evaluate to 'absent' or 'unknown' (never automatically malicious).
    """
    import subprocess
    import shutil

    dns_policy = {
        "published_spf": "absent",
        "published_dmarc": "absent",
        "dns_lookup_success": False,
    }
    if not domain or not isinstance(domain, str) or not re.match(r"^[a-zA-Z0-9.\-]+$", domain):
        return dns_policy

    if not shutil.which("dig"):
        return dns_policy

    try:
        # Check SPF TXT record
        spf_proc = subprocess.run(
            ["dig", "+short", "+time=2", "+tries=1", "TXT", domain],
            capture_output=True,
            text=True,
            timeout=3.0,
        )
        if spf_proc.returncode == 0 and spf_proc.stdout:
            txt_lines = spf_proc.stdout.splitlines()
            for line in txt_lines:
                clean_l = line.strip().strip('"')
                if "v=spf1" in clean_l:
                    dns_policy["published_spf"] = clean_l
                    dns_policy["dns_lookup_success"] = True
                    break

        # Check DMARC TXT record
        dmarc_proc = subprocess.run(
            ["dig", "+short", "+time=2", "+tries=1", "TXT", f"_dmarc.{domain}"],
            capture_output=True,
            text=True,
            timeout=3.0,
        )
        if dmarc_proc.returncode == 0 and dmarc_proc.stdout:
            txt_lines = dmarc_proc.stdout.splitlines()
            for line in txt_lines:
                clean_l = line.strip().strip('"')
                if "v=DMARC1" in clean_l or "v=dmarc1" in clean_l:
                    dns_policy["published_dmarc"] = clean_l
                    dns_policy["dns_lookup_success"] = True
                    break

        if dns_policy["published_spf"] != "absent" or dns_policy["published_dmarc"] != "absent":
            dns_policy["dns_lookup_success"] = True
    except Exception:
        # Safe fallback on network failure / offline mode
        dns_policy["dns_lookup_success"] = False

    return dns_policy


def analyze_email_authentication(message):
    """
    Perform complete email authentication analysis, strictly separating:
    1. Message Authentication (headers: SPF, DKIM, DMARC from Authentication-Results and Received-SPF)
    2. Published DNS Policy (DNS TXT records for SPF/DMARC)

    Includes an explicit verification disclaimer for uploaded artifact contexts.
    """
    raw_headers = extract_authentication_results(message)
    auth_headers = raw_headers["authentication_results"]
    received_spf = raw_headers["received_spf"]

    status = extract_auth_status(auth_headers, received_spf)
    signals = calculate_authentication_signals(status)

    from_header = str(message.get("From", "")) if hasattr(message, "get") else ""
    from_domain = from_header.split("@")[-1].rstrip(">").strip().lower() if "@" in from_header else ""
    published_policy = check_published_dns_policy(from_domain)

    # Verification disclaimer for offline / uploaded email inspection
    verification_caveat = (
        "Headers reflect values in the uploaded email artifact and have not been "
        "cryptographically re-verified against the authoritative mail transfer agent in this offline context."
    )

    return {
        "authentication_headers": auth_headers,
        "received_spf_headers": received_spf,
        "message_authentication": status,
        "status": status,
        "published_dns_policy": published_policy,
        "signals": signals,
        "verification_caveat": verification_caveat,
    }


def main():
    """
    Simple standalone test.

    This creates a simulated Authentication-Results
    header so the module can be tested without
    contacting an external mail server.
    """

    test_headers = [
        "mx.example.com; "
        "spf=pass smtp.mailfrom=example.com; "
        "dkim=pass header.d=example.com; "
        "dmarc=fail header.from=example.com"
    ]

    class FakeMessage:
        """
        Small fake email object used for testing.
        """

        def get_all(self, header_name, default):
            return test_headers

    message = FakeMessage()

    result = analyze_email_authentication(
        message
    )

    print("\nAuthentication Results:")

    for key, value in result.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
