"""
Domain Intelligence Module

Purpose:
    Extract domain-level intelligence from a URL.

Current capabilities:
    1. Extract hostname
    2. Extract registrable domain
    3. Extract subdomain
    4. Extract TLD
    5. Detect whether hostname is an IP address
    6. Resolve DNS records to IP addresses
    7. Identify IPv4 / IPv6 addresses
    8. Calculate basic domain characteristics

This module is intentionally passive.
It does NOT perform:
    - Port scanning
    - Vulnerability scanning
    - Exploitation
    - Brute forcing
"""


import socket
import ipaddress
from urllib.parse import urlparse

import tldextract


# ================================================================
# Configuration
# ================================================================

# Number of DNS addresses to retain in the result.
MAX_DNS_RESULTS = 20


# ================================================================
# URL normalization
# ================================================================

def normalize_url(url):
    """
    Normalize a URL before parsing.

    Why:
        Many URLs in our dataset do not contain http:// or https://.

    Example:
        example.com/login
        ->
        http://example.com/login
    """

    # Convert input to string and remove surrounding whitespace.
    url = str(url).strip()

    # Return empty string if no URL was supplied.
    if not url:
        return ""

    # Add a default scheme when one is missing.
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    return url


# ================================================================
# Hostname extraction
# ================================================================

def extract_hostname(url):
    """
    Extract the hostname from a URL.

    Example:
        https://login.example.com/account
        ->
        login.example.com
    """

    # Normalize the URL before parsing.
    normalized_url = normalize_url(url)

    # Parse the URL.
    parsed = urlparse(normalized_url)

    # Return hostname in lowercase.
    return (parsed.hostname or "").lower()


# ================================================================
# IP address detection
# ================================================================

def detect_ip_address(hostname):
    """
    Determine whether a hostname is an IPv4 or IPv6 address.

    Returns:
        Tuple:
            (is_ip, ip_version)

    Examples:
        192.168.1.1 -> (True, 4)
        2001:db8::1 -> (True, 6)
        example.com -> (False, None)
    """

    try:
        # Try to interpret the hostname as an IP address.
        ip = ipaddress.ip_address(hostname)

        # Return the IP version.
        return True, ip.version

    except ValueError:
        # Hostname is not an IP address.
        return False, None


# ================================================================
# Domain parsing
# ================================================================

def parse_domain(hostname):
    """
    Extract subdomain, registrable domain, and TLD.

    Example:
        login.secure.example.com

        subdomain:
            login.secure

        registrable domain:
            example.com

        TLD:
            com
    """

    # tldextract separates:
    #   subdomain
    #   domain
    #   suffix
    extracted = tldextract.extract(hostname)

    subdomain = extracted.subdomain
    domain = extracted.domain
    suffix = extracted.suffix

    # Construct the registrable domain.
    if domain and suffix:
        registrable_domain = f"{domain}.{suffix}"
    else:
        registrable_domain = domain

    return {
        "subdomain": subdomain,
        "domain": domain,
        "tld": suffix,
        "registrable_domain": registrable_domain
    }


# ================================================================
# DNS resolution
# ================================================================

# ================================================================
# DNS resolution
# ================================================================

import subprocess
from datetime import datetime, timezone

def resolve_dns(hostname):
    """Resolve a hostname to comprehensive DNS records (A, AAAA, MX, NS, TXT, CNAME).

    Security:
    - Avoids leaking private infrastructure.
    - Accurately distinguishes SUCCESS with records, NO_RECORDS (NODATA), NXDOMAIN,
      TIMEOUT, RESOLVER_FAILURE, BLOCKED, and NOT_EVALUATED.
    - Does NOT infer domain legitimacy solely from successful resolution.

    Returns:
        Dictionary containing structured DNS records and status categorization.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    records = {t: [] for t in record_types}

    if not hostname or not str(hostname).strip():
        return {
            "status": "NOT_EVALUATED",
            "domain": hostname or "",
            "timestamp": now_iso,
            "records": records,
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "cname_records": [],
            "ipv4_addresses": [],
            "ipv6_addresses": [],
            "dns_resolution_success": False,
            "record_count": 0,
            "error_reason": "No hostname provided for DNS lookup.",
        }

    clean_host = hostname.strip().lower()

    # Block direct IP or loopback/private resolution attempts
    if clean_host in ("localhost", "127.0.0.1", "::1") or clean_host.endswith(".local") or clean_host.endswith(".internal"):
        return {
            "status": "BLOCKED",
            "domain": clean_host,
            "timestamp": now_iso,
            "records": records,
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "cname_records": [],
            "ipv4_addresses": [],
            "ipv6_addresses": [],
            "dns_resolution_success": False,
            "record_count": 0,
            "error_reason": "Resolution blocked for internal/private hostname.",
        }

    status = "RESOLVER_FAILURE"
    error_reason = None
    queried_successfully = False

    # 1. Attempt lookup using system dig utility
    try:
        for rtype in record_types:
            cmd = ["dig", "+noall", "+answer", "+comments", "+time=2", "+tries=1", clean_host, rtype]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            out = proc.stdout
            if "status: NXDOMAIN" in out:
                status = "NXDOMAIN"
                error_reason = f"Domain {clean_host} does not exist (NXDOMAIN)."
                break
            if "timed out" in out.lower() or "connection timed out" in out.lower():
                status = "TIMEOUT"
                error_reason = "DNS query timed out waiting for resolver."
            elif "network unreachable" in out.lower() or "no servers could be reached" in out.lower():
                status = "RESOLVER_FAILURE"
                error_reason = "Upstream DNS resolvers unreachable."

            for line in out.splitlines():
                if line.startswith(";;") or not line.strip():
                    continue
                parts = line.strip().split()
                if len(parts) >= 5:
                    item_type = parts[3].upper()
                    item_val = " ".join(parts[4:]).strip('"')
                    if item_type == rtype and item_val not in records[rtype]:
                        records[rtype].append(item_val)
                        queried_successfully = True

    except Exception as exc:
        error_reason = str(exc)

    # 2. Fallback to socket.getaddrinfo for basic A and AAAA addresses
    if not queried_successfully and status not in ("NXDOMAIN",):
        try:
            results = socket.getaddrinfo(clean_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for res in results:
                family = res[0]
                addr = res[4][0]
                if family == socket.AF_INET and addr not in records["A"]:
                    records["A"].append(addr)
                elif family == socket.AF_INET6 and addr not in records["AAAA"]:
                    records["AAAA"].append(addr)
            if records["A"] or records["AAAA"]:
                queried_successfully = True
                status = "SUCCESS"
                error_reason = None
        except socket.gaierror as gai_err:
            if gai_err.errno == socket.EAI_NONAME:
                status = "NXDOMAIN"
                error_reason = f"Hostname {clean_host} not found (NXDOMAIN)."
            elif "timed out" in str(gai_err).lower():
                status = "TIMEOUT"
                error_reason = "Resolver timed out."
            else:
                if status == "RESOLVER_FAILURE" and not error_reason:
                    error_reason = f"Resolver error: {gai_err}"

    # Determine final status
    total_records = sum(len(v) for v in records.values())
    if total_records > 0:
        status = "SUCCESS"
        error_reason = None
    elif status not in ("NXDOMAIN", "TIMEOUT", "RESOLVER_FAILURE", "BLOCKED"):
        status = "NO_RECORDS"
        error_reason = f"Query succeeded but returned no {record_types} resource records."

    ipv4_list = sorted(records["A"])[:MAX_DNS_RESULTS]
    ipv6_list = sorted(records["AAAA"])[:MAX_DNS_RESULTS]

    return {
        "status": status,
        "domain": clean_host,
        "timestamp": now_iso,
        "records": records,
        "a_records": ipv4_list,
        "aaaa_records": ipv6_list,
        "mx_records": records["MX"][:MAX_DNS_RESULTS],
        "ns_records": records["NS"][:MAX_DNS_RESULTS],
        "txt_records": records["TXT"][:MAX_DNS_RESULTS],
        "cname_records": records["CNAME"][:MAX_DNS_RESULTS],
        "ipv4_addresses": ipv4_list,
        "ipv6_addresses": ipv6_list,
        "dns_resolution_success": (status == "SUCCESS"),
        "record_count": total_records,
        "error_reason": error_reason,
    }


# ================================================================
# Basic domain characteristics
# ================================================================

def calculate_domain_characteristics(
    hostname,
    registrable_domain,
    subdomain
):
    """
    Calculate basic structural characteristics of a domain.

    These features can later be supplied to our ML/risk engine.
    """

    # Count the number of dots in the hostname.
    dot_count = hostname.count(".")

    # Count hostname characters.
    hostname_length = len(hostname)

    # Count subdomain labels.
    if subdomain:
        subdomain_count = len(
            subdomain.split(".")
        )
    else:
        subdomain_count = 0

    # Count hyphens in the hostname.
    hyphen_count = hostname.count("-")

    # Count numeric characters.
    digit_count = sum(
        character.isdigit()
        for character in hostname
    )

    # Determine whether the hostname contains
    # suspiciously long subdomain structure.
    long_subdomain = len(subdomain) >= 30

    # Determine whether the registrable domain
    # itself contains a hyphen.
    domain_has_hyphen = "-" in registrable_domain

    return {
        "hostname_length": hostname_length,
        "hostname_dot_count": dot_count,
        "subdomain_count": subdomain_count,
        "hostname_hyphen_count": hyphen_count,
        "hostname_digit_count": digit_count,
        "long_subdomain": long_subdomain,
        "domain_has_hyphen": domain_has_hyphen
    }


# ================================================================
# Main domain intelligence function
# ================================================================

def analyze_domain(url, check_tls=True):
    """
    Perform complete domain intelligence analysis for one URL.

    Parameters:
        url: The URL or domain to evaluate.
        check_tls: Whether to passively inspect TLS certificates for HTTPS destinations.

    Returns:
        Dictionary containing all extracted domain intelligence.
    """

    # Extract hostname from URL.
    hostname = extract_hostname(url)

    # Detect whether hostname itself is an IP address.
    is_ip, ip_version = detect_ip_address(hostname)

    # If hostname is a normal domain, parse its domain structure.
    if not is_ip:
        domain_info = parse_domain(hostname)

        subdomain = domain_info["subdomain"]
        registrable_domain = domain_info["registrable_domain"]
        tld = domain_info["tld"]
        domain = domain_info["domain"]

        # Calculate structural characteristics.
        characteristics = calculate_domain_characteristics(
            hostname,
            registrable_domain,
            subdomain
        )

        # Perform DNS resolution.
        dns_info = resolve_dns(hostname)

    else:
        # IP-based URL does not have normal domain components.
        domain = ""
        tld = ""
        subdomain = ""
        registrable_domain = ""

        characteristics = {
            "hostname_length": len(hostname),
            "hostname_dot_count": hostname.count("."),
            "subdomain_count": 0,
            "hostname_hyphen_count": hostname.count("-"),
            "hostname_digit_count": sum(
                character.isdigit()
                for character in hostname
            ),
            "long_subdomain": False,
            "domain_has_hyphen": False
        }

        # The hostname is already an IP address,
        # so DNS resolution is unnecessary.
        dns_info = {
            "ipv4_addresses": [hostname]
            if ip_version == 4 else [],
            "ipv6_addresses": [hostname]
            if ip_version == 6 else [],
            "dns_resolution_success": True
        }

    # Detect IDN (Internationalized Domain Name) / Punycode (e.g. xn--)
    is_idn = False
    is_punycode = False
    try:
        if "xn--" in hostname.lower():
            is_punycode = True
            is_idn = True
        elif any(ord(char) > 127 for char in hostname):
            is_idn = True
    except Exception:
        pass

    # Check Local Threat Intelligence for domain
    local_ti_match = None
    try:
        from scripts.data_pipeline.build_ti_database import query_local_ti
        if registrable_domain:
            local_ti_match = query_local_ti(registrable_domain, indicator_type="domain") or query_local_ti(hostname, indicator_type="domain")
    except Exception:
        local_ti_match = None

    # Combine all intelligence into one dictionary.
    result = {
        "url": url,
        "hostname": hostname,
        "is_ip_address": is_ip,
        "ip_version": ip_version,
        "domain": domain,
        "registrable_domain": registrable_domain,
        "subdomain": subdomain,
        "tld": tld,
        "is_idn": is_idn,
        "is_punycode": is_punycode,
        "local_ti_match": local_ti_match,
        "domain_age": "UNKNOWN",
        "registrar": "UNAVAILABLE",
        "nameservers": "UNAVAILABLE",
        "asn": "UNAVAILABLE",
        "country": "UNAVAILABLE",
    }

    # Private / Loopback Destination Status
    is_loopback = False
    is_private = False
    if is_ip:
        try:
            ip_obj = ipaddress.ip_address(hostname)
            is_loopback = ip_obj.is_loopback
            is_private = ip_obj.is_private
        except Exception:
            pass
    result["is_loopback"] = is_loopback
    result["is_private"] = is_private

    # Add structural characteristics.
    result.update(characteristics)

    # Add DNS information.
    result.update(dns_info)

    # Optional TLS Certificate Inspection
    if check_tls:
        try:
            from src.features.tls_analyzer import analyze_tls_certificate
            target_for_tls = url if "://" in url else f"https://{hostname}"
            tls_res = analyze_tls_certificate(target_for_tls)
            result["tls"] = tls_res
            result["https_supported"] = tls_res.get("connection_successful", False)
            result["tls_status"] = tls_res.get("status", "UNAVAILABLE")
        except Exception as exc:
            result["tls"] = {"status": "UNAVAILABLE", "error": str(exc)}
            result["https_supported"] = False
            result["tls_status"] = "UNAVAILABLE"

    # Domain Evidence Summary
    evidence_items = []
    if is_ip:
        evidence_items.append("Direct IP address used instead of hostname")
    if is_punycode or is_idn:
        evidence_items.append("Internationalized domain name (Punycode) detected")
    if characteristics.get("subdomain_count", 0) >= 3:
        evidence_items.append(f"Deep subdomain nesting ({characteristics.get('subdomain_count')} levels)")
    if characteristics.get("long_subdomain"):
        evidence_items.append("Unusually long subdomain string")
    if local_ti_match and local_ti_match.get("found"):
        evidence_items.append(f"Domain flagged in local threat intelligence ({local_ti_match.get('source')})")

    result["domain_evidence_summary"] = evidence_items
    return result



# ================================================================
# Command-line testing
# ================================================================

def main():
    """
    Test the domain intelligence module using sample URLs.

    This allows us to verify the module before integrating it
    into the larger phishing detection pipeline.
    """

    test_urls = [
        "https://www.google.com",
        "https://login.example.com/account",
        "http://paypal.com.example.net/login",
        "http://192.168.1.10/login",
        "https://login.secure.account.example.co.uk",
    ]

    print("=" * 70)
    print("DOMAIN INTELLIGENCE TEST")
    print("=" * 70)

    # Analyze every test URL.
    for url in test_urls:

        print("\nURL:")
        print(url)

        result = analyze_domain(url)

        print("\nDomain intelligence:")

        for key, value in result.items():
            print(f"{key}: {value}")

        print("-" * 70)


# ================================================================
# Program entry point
# ================================================================

if __name__ == "__main__":
    main()
