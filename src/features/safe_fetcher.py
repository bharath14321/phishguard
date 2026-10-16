"""
SSRF-Safe HTTP Fetching Utilities.

This module validates destination IP addresses and hostnames before making
HTTP requests to prevent Server-Side Request Forgery (SSRF).

It blocks:
- Loopback addresses (127.0.0.0/8, ::1)
- Private network addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
- Link-local and cloud metadata addresses (169.254.0.0/16, fe80::/10, fd00:ec2::254)
- Specific metadata IPs (169.254.169.254, 100.100.100.200)
- Carrier-Grade NAT (100.64.0.0/10)
- Multicast and broadcast (224.0.0.0/4, ff00::/8, 255.255.255.255)
- Reserved and unspecified addresses (0.0.0.0/8, 240.0.0.0/4, ::)
- Localhost and internal metadata domain names
- DNS rebinding attacks via socket IP pinning
"""

import ipaddress
import socket
import threading
from urllib.parse import urlparse, urljoin
import requests
from urllib3.util import connection

# Default timeout and response size limits
REQUEST_TIMEOUT = 10
MAX_RESPONSE_SIZE = 2 * 1024 * 1024  # 2 MB
MAX_REDIRECTS_DEFAULT = 10

# Cloud metadata and internal domains to block outright
FORBIDDEN_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
    "metadata.aws",
}

# Specific cloud metadata IP networks/addresses
CLOUD_METADATA_NETWORKS = [
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba Cloud
    ipaddress.ip_network("fd00:ec2::254/128"),   # AWS IPv6 metadata
]

CARRIER_GRADE_NAT = ipaddress.ip_network("100.64.0.0/10")

# -------------------------------------------------------------
# THREAD-LOCAL IP PINNING FOR DNS REBINDING PROTECTION
# -------------------------------------------------------------

_tls = threading.local()
_real_create_connection = connection.create_connection


def _safe_pinned_create_connection(address, *args, **kwargs):
    """
    Hook urllib3's create_connection to pin the connection to the verified IP.
    
    This guarantees that even if a remote DNS server attempts DNS rebinding
    between validation and socket creation, the connection is forced to connect
    to the pre-validated IP address.
    """
    host, port = address
    pinned_map = getattr(_tls, "pinned_map", None)
    if pinned_map and host in pinned_map:
        target_ip = pinned_map[host]
        return _real_create_connection((target_ip, port), *args, **kwargs)
    return _real_create_connection(address, *args, **kwargs)


# Install the connection hook once at module import
if connection.create_connection != _safe_pinned_create_connection:
    connection.create_connection = _safe_pinned_create_connection


class PinnedSessionContext:
    """
    Context manager that pins a hostname to a validated IP for the current thread.
    """

    def __init__(self, host: str, ip: str):
        self.host = host
        self.ip = ip

    def __enter__(self):
        if not hasattr(_tls, "pinned_map") or _tls.pinned_map is None:
            _tls.pinned_map = {}
        _tls.pinned_map[self.host] = self.ip
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(_tls, "pinned_map") and _tls.pinned_map:
            _tls.pinned_map.pop(self.host, None)
            if not _tls.pinned_map:
                _tls.pinned_map = None


# -------------------------------------------------------------
# IP & HOSTNAME VALIDATION
# -------------------------------------------------------------


def is_cloud_metadata_ip(address_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """
    Check if an IP address belongs to known cloud metadata services.
    """
    for network in CLOUD_METADATA_NETWORKS:
        if address_obj in network:
            return True
    return False


def is_private_or_unsafe_ip(ip: str) -> bool:
    """
    Determine whether an IP address string should not be accessed.

    Blocks:
    - private addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
    - loopback (127.0.0.0/8, ::1)
    - link-local (169.254.0.0/16, fe80::/10)
    - multicast (224.0.0.0/4, ff00::/8)
    - reserved (240.0.0.0/4)
    - unspecified (0.0.0.0, ::)
    - carrier-grade NAT (100.64.0.0/10)
    - cloud metadata services
    """
    try:
        address = ipaddress.ip_address(ip)

        # Handle IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped

        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
            or address in CARRIER_GRADE_NAT
            or is_cloud_metadata_ip(address)
        ):
            return True

        return False

    except ValueError:
        # Invalid IP address syntax is considered unsafe
        return True


def is_forbidden_hostname(hostname: str) -> bool:
    """
    Check if a hostname is an explicit local, internal, or cloud-metadata domain.
    """
    host = hostname.lower().strip().rstrip(".")
    if host in FORBIDDEN_HOSTNAMES:
        return True

    # Block subdomains of forbidden hosts or local TLDs
    if (
        host.endswith(".localhost")
        or host.endswith(".local")
        or host.endswith(".internal")
        or host.endswith(".localdomain")
        or host.endswith(".arpa")
    ):
        return True

    return False


def resolve_hostname(hostname: str) -> list[str]:
    """
    Resolve a hostname into all its IPv4 and IPv6 addresses.
    """
    addresses = set()
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for result in results:
            ip = result[4][0]
            addresses.add(ip)
    except socket.gaierror:
        return []

    return sorted(addresses)


def validate_url(url: str) -> dict:
    """
    Validate a URL before making a network request.

    Returns a dictionary describing whether the destination is safe:
    {
        "safe": bool,
        "reason": str,
        "hostname": str,
        "resolved_ips": list[str],
        "blocked_ips": list[str],
        "primary_ip": str
    }
    """
    try:
        parsed = urlparse(url)
    except Exception as err:
        return {"safe": False, "reason": f"Malformed URL: {err}"}

    if parsed.scheme.lower() not in {"http", "https"}:
        return {
            "safe": False,
            "reason": "Only HTTP and HTTPS protocols are allowed"
        }

    if not parsed.hostname:
        return {
            "safe": False,
            "reason": "Missing or empty hostname in URL"
        }

    hostname = parsed.hostname.lower().strip()

    if is_forbidden_hostname(hostname):
        return {
            "safe": False,
            "reason": f"Destination hostname '{hostname}' is restricted",
            "hostname": hostname
        }

    addresses = resolve_hostname(hostname)
    if not addresses:
        return {
            "safe": False,
            "reason": f"Hostname '{hostname}' could not be resolved",
            "hostname": hostname
        }

    unsafe_addresses = []
    safe_addresses = []

    for ip in addresses:
        if is_private_or_unsafe_ip(ip):
            unsafe_addresses.append(ip)
        else:
            safe_addresses.append(ip)

    if unsafe_addresses:
        return {
            "safe": False,
            "reason": "Destination resolves to a restricted or private IP address",
            "hostname": hostname,
            "resolved_ips": addresses,
            "blocked_ips": unsafe_addresses
        }

    return {
        "safe": True,
        "hostname": hostname,
        "resolved_ips": addresses,
        "primary_ip": safe_addresses[0] if safe_addresses else None
    }


# -------------------------------------------------------------
# SSRF-SAFE HTTP FETCHING
# -------------------------------------------------------------


def safe_get(url: str, timeout: int = REQUEST_TIMEOUT, headers: dict = None) -> dict:
    """
    Perform an HTTP GET request with SSRF and DNS rebinding protections.

    - Validates scheme and hostname.
    - Resolves and verifies destination IPs against private/cloud CIDRs.
    - Pins socket connection to the validated IP to prevent DNS rebinding.
    - Disables automatic redirects to prevent redirection to private IPs.
    - Caps downloaded response body to MAX_RESPONSE_SIZE bytes.
    """
    validation = validate_url(url)
    if not validation.get("safe"):
        return {
            "success": False,
            "blocked": True,
            "reason": validation.get("reason", "Validation failed"),
            "validation": validation
        }

    hostname = validation["hostname"]
    pinned_ip = validation["primary_ip"]

    request_headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36 AI-Phishing-Detection-Analyzer/1.0"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    if headers:
        request_headers.update(headers)

    try:
        with PinnedSessionContext(hostname, pinned_ip):
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=False,
                headers=request_headers,
                stream=True
            )

            # Check declared Content-Length header if provided
            content_length = response.headers.get("Content-Length")
            if content_length:
                try:
                    if int(content_length) > MAX_RESPONSE_SIZE:
                        response.close()
                        return {
                            "success": False,
                            "blocked": True,
                            "reason": f"Response Content-Length ({content_length}) exceeds size limit ({MAX_RESPONSE_SIZE} bytes)"
                        }
                except ValueError:
                    pass

            # Read up to MAX_RESPONSE_SIZE + 1 bytes safely
            content = response.raw.read(MAX_RESPONSE_SIZE + 1)
            if len(content) > MAX_RESPONSE_SIZE:
                response.close()
                return {
                    "success": False,
                    "blocked": True,
                    "reason": f"Response body exceeded maximum allowed size of {MAX_RESPONSE_SIZE} bytes"
                }

            response._content = content
            response.close()

            # Decode text safely
            encoding = response.encoding or "utf-8"
            try:
                text_content = content.decode(encoding, errors="replace")
            except Exception:
                text_content = content.decode("utf-8", errors="replace")

            return {
                "success": True,
                "blocked": False,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content": content,
                "text": text_content,
                "url": url,
                "pinned_ip": pinned_ip,
                "validation": validation
            }

    except requests.exceptions.Timeout:
        return {
            "success": False,
            "blocked": False,
            "error": f"Request timed out after {timeout} seconds",
            "is_timeout": True
        }
    except requests.RequestException as error:
        return {
            "success": False,
            "blocked": False,
            "error": str(error)
        }


def safe_fetch_chain(
    url: str,
    max_redirects: int = MAX_REDIRECTS_DEFAULT,
    timeout: int = REQUEST_TIMEOUT
) -> dict:
    """
    Safely follow HTTP redirect chains by validating each hop independently.

    Prevents:
    - Infinite redirect loops
    - Redirecting from public IP to internal/metadata IPs (SSRF via redirect)
    - Protocol switching to non-HTTP/HTTPS schemes
    """
    redirect_chain = []
    status_codes = []
    current_url = url

    for _ in range(max_redirects + 1):
        redirect_chain.append(current_url)

        res = safe_get(current_url, timeout=timeout)
        if not res["success"]:
            return {
                "success": False,
                "blocked": res.get("blocked", False),
                "error": res.get("error") or res.get("reason"),
                "original_url": url,
                "final_url": current_url,
                "redirect_count": len(redirect_chain) - 1,
                "redirect_chain": redirect_chain,
                "status_codes": status_codes,
            }

        status_code = res["status_code"]
        status_codes.append(status_code)

        # Check for HTTP redirect response
        if status_code in (301, 302, 303, 307, 308):
            location = res["headers"].get("Location") or res["headers"].get("location")
            if not location:
                # Redirect header missing, terminate
                break

            # Resolve relative URLs
            next_url = urljoin(current_url, location)

            # Prevent immediate loop
            if next_url in redirect_chain:
                return {
                    "success": True,
                    "original_url": url,
                    "final_url": current_url,
                    "redirect_count": len(redirect_chain) - 1,
                    "redirect_chain": redirect_chain,
                    "status_codes": status_codes,
                    "loop_detected": True,
                    "last_response": res
                }

            current_url = next_url
        else:
            # Reached terminal destination
            return {
                "success": True,
                "original_url": url,
                "final_url": current_url,
                "redirect_count": len(redirect_chain) - 1,
                "redirect_chain": redirect_chain,
                "status_codes": status_codes,
                "last_response": res
            }

    # Exceeded max redirects
    return {
        "success": False,
        "blocked": True,
        "reason": f"Exceeded maximum redirect limit of {max_redirects}",
        "original_url": url,
        "final_url": current_url,
        "redirect_count": len(redirect_chain) - 1,
        "redirect_chain": redirect_chain,
        "status_codes": status_codes,
    }
