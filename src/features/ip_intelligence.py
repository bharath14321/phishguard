"""
IP Intelligence Module

This module extracts IP-related intelligence from a URL.

It checks:
1. Whether the hostname is an IP address.
2. IPv4 / IPv6 version.
3. Private, loopback, reserved, or public IP.
4. DNS resolution for domain names.
5. Resolved IP addresses.

ASN / geolocation enrichment can be added later through
external APIs such as VirusTotal or other threat-intelligence services.
"""

import ipaddress
import socket
from urllib.parse import urlparse

from src.features.domain_intelligence import normalize_url


def get_ip_information(ip):
    """
    Analyze a single IP address.

    Returns information such as:
    - IP version
    - private/public status
    - loopback status
    - reserved status
    """
    try:
        ip_obj = ipaddress.ip_address(ip)

        return {
            "ip": ip,
            "version": ip_obj.version,
            "is_private": ip_obj.is_private,
            "is_global": ip_obj.is_global,
            "is_loopback": ip_obj.is_loopback,
            "is_reserved": ip_obj.is_reserved,
        }

    except ValueError:
        # Return None when the supplied value is not a valid IP.
        return None


def resolve_hostname(hostname):
    """
    Resolve a hostname into IP addresses using the local DNS resolver.

    Returns:
        A list of unique IP addresses.
    """

    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            proto=socket.IPPROTO_TCP
        )

        # Extract IP addresses from DNS results.
        addresses = {result[4][0] for result in results}

        return sorted(addresses)

    except (socket.gaierror, socket.timeout, OSError):
        # DNS resolution can fail for many legitimate reasons.
        return []


def analyze_url_ip(url):
    """
    Perform IP intelligence analysis on a URL.

    The function:
    1. Normalizes the URL.
    2. Extracts the hostname.
    3. Determines whether hostname is already an IP.
    4. If it is a domain, performs DNS resolution.
    5. Classifies the resulting IP addresses.
    """

    # Normalize URL before parsing.
    url = normalize_url(url)

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return {
            "url": url,
            "hostname": None,
            "is_ip_address": False,
            "ip_information": [],
            "dns_resolved_ips": [],
        }

    # Check whether hostname itself is an IP address
    direct_ip_info = get_ip_information(hostname)

    # If hostname is a domain, resolve it through DNS
    resolved_ips = []
    ip_information = []
    if direct_ip_info:
        resolved_ips = [hostname]
        ip_information = [direct_ip_info]
    else:
        resolved_ips = resolve_hostname(hostname)
        for ip in resolved_ips:
            info = get_ip_information(ip)
            if info:
                ip_information.append(info)

    # Check local TI for resolved or direct IPs
    local_ti_matches = []
    try:
        from scripts.data_pipeline.build_ti_database import query_local_ti
        check_ips = [hostname] if direct_ip_info else resolved_ips
        for ip_addr in check_ips:
            ti_res = query_local_ti(ip_addr, indicator_type="ip")
            if ti_res and ti_res.get("found"):
                local_ti_matches.append(ti_res)
    except Exception:
        local_ti_matches = []

    # IP Evidence Summary
    evidence_items = []
    if direct_ip_info:
        evidence_items.append("Direct IP address used as URL host")
        if direct_ip_info.get("is_private"):
            evidence_items.append("Private RFC 1918 IP address")
        elif direct_ip_info.get("is_reserved"):
            evidence_items.append("Reserved/Special-use IP address")
        elif direct_ip_info.get("is_loopback"):
            evidence_items.append("Loopback IP address")
    if local_ti_matches:
        evidence_items.append(f"IP address matched local threat intelligence ({local_ti_matches[0].get('source')})")

    return {
        "url": url,
        "hostname": hostname,
        "is_ip_address": bool(direct_ip_info),
        "ip_information": ip_information,
        "dns_resolved_ips": resolved_ips,
        "local_ti_matches": local_ti_matches,
        "ip_evidence_summary": evidence_items,
    }


def main():
    """
    Run a few examples to verify the IP intelligence module.
    """

    test_urls = [
        "http://192.168.1.10/login",
        "https://example.com",
        "https://8.8.8.8/test",
    ]

    for url in test_urls:

        print("\n" + "=" * 60)
        print("URL:", url)

        result = analyze_url_ip(url)

        for key, value in result.items():
            print(f"{key}: {value}")


if __name__ == "__main__":
    main()
