"""
VirusTotal Threat Intelligence Module & Provider Adapter

Supports:
1. URL reputation lookup
2. File hash reputation lookup (MD5, SHA-1, SHA-256)
3. Local file hash reputation lookup

Status semantics:
- SUCCESS: Found in VT with analysis stats
- NOT_FOUND: 404 from VT (Unknown in VT, NOT necessarily clean)
- UNAVAILABLE: API key missing or service unconfigured
- RATE_LIMITED: 429 from VT
- ERROR: Network timeout or communication failure

CRITICAL SECURITY & FIDELITY RULES:
- UNKNOWN / UNAVAILABLE / NOT_FOUND are NOT clean or safe.
- VirusTotal is an external enrichment source, NOT the sole verdict.
- VIRUSTOTAL_API_KEY must never be sent to the client/browser.
"""

import base64
import hashlib
import os
import re
from typing import Any, Dict, Optional
import requests
from dotenv import load_dotenv

# Load variables from .env
load_dotenv()

# VirusTotal API base URL
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Hash validation regexes
MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")


def get_headers() -> Dict[str, str]:
    """
    Create HTTP headers required by VirusTotal API v3.
    """
    return {
        "x-apikey": os.getenv("VIRUSTOTAL_API_KEY", "")
    }


def is_valid_hash(hash_value: str) -> bool:
    """
    Validate that an input string is an MD5, SHA-1, or SHA-256 hash.
    """
    if not isinstance(hash_value, str):
        return False
    cleaned = hash_value.strip()
    return bool(
        MD5_REGEX.match(cleaned)
        or SHA1_REGEX.match(cleaned)
        or SHA256_REGEX.match(cleaned)
    )


def encode_url_for_virustotal(url: str) -> str:
    """
    Convert a URL into VirusTotal's URL identifier.
    VirusTotal uses URL-safe Base64 without '=' padding.
    """
    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8")
    return encoded.rstrip("=")


def extract_vt_threat_label(attributes: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract and normalize threat label, malware family, and category from VirusTotal attributes.
    Never invents or hallucinates labels if none are provided.
    """
    if not attributes or not isinstance(attributes, dict):
        return {
            "threat_label": "Unknown / not provided",
            "threat_category": "Unknown",
            "threat_family": "Unknown",
            "popular_threat_classification": {},
        }

    pop_class = attributes.get("popular_threat_classification") or {}
    suggested_label = pop_class.get("suggested_threat_label")
    
    pop_category_list = pop_class.get("popular_threat_category") or []
    pop_category = pop_category_list[0].get("value") if pop_category_list and isinstance(pop_category_list, list) and isinstance(pop_category_list[0], dict) else None
    
    pop_name_list = pop_class.get("popular_threat_name") or []
    pop_name = pop_name_list[0].get("value") if pop_name_list and isinstance(pop_name_list, list) and isinstance(pop_name_list[0], dict) else None

    # Categories dictionary from vendors
    categories_dict = attributes.get("categories") or {}
    
    # Fallback vendor consensus from last_analysis_results if suggested_label not present
    vendor_results = attributes.get("last_analysis_results") or {}
    malicious_results = []
    if isinstance(vendor_results, dict):
        for engine, res in vendor_results.items():
            if isinstance(res, dict) and res.get("category") == "malicious" and res.get("result"):
                malicious_results.append(str(res.get("result")))
    
    # Determine the primary threat_label
    threat_label = suggested_label or pop_name or pop_category
    
    if not threat_label and malicious_results:
        cleaned_results = [r.strip() for r in malicious_results if r.strip().lower() not in ["clean", "unrated", "malicious", "threat", "phishing"]]
        if cleaned_results:
            from collections import Counter
            counts = Counter(cleaned_results)
            threat_label = counts.most_common(1)[0][0]

    if not threat_label and categories_dict and isinstance(categories_dict, dict):
        cat_values = [v.strip() for v in categories_dict.values() if isinstance(v, str) and v.strip()]
        if cat_values:
            from collections import Counter
            cat_counts = Counter(cat_values)
            threat_label = cat_counts.most_common(1)[0][0]

    if not threat_label:
        threat_label = "Unknown / not provided"
        
    return {
        "threat_label": threat_label,
        "threat_category": pop_category or "Unknown",
        "threat_family": pop_name or "Unknown",
        "popular_threat_classification": pop_class,
    }


def get_url_reputation(url: str) -> Dict[str, Any]:
    """
    Look up a URL in VirusTotal.
    Returns normalized vendor analysis statistics with explicit status semantics.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return {
            "success": False,
            "found": False,
            "status": "UNAVAILABLE",
            "provider": "VirusTotal",
            "type": "url",
            "url": url,
            "is_clean": False,
            "is_unknown": True,
            "threat_label": "Unknown / not provided",
            "threat_category": "Unknown",
            "threat_family": "Unknown",
            "error": "VIRUSTOTAL_API_KEY not configured",
            "message": "VirusTotal intelligence unavailable (API key not configured)",
        }

    url_id = encode_url_for_virustotal(url)
    endpoint = f"{VT_BASE_URL}/urls/{url_id}"

    try:
        response = requests.get(
            endpoint,
            headers=get_headers(),
            timeout=15,
        )

        # 404 indicates VirusTotal has no existing record for this URL
        if response.status_code == 404:
            return {
                "success": True,
                "found": False,
                "status": "NOT_FOUND",
                "provider": "VirusTotal",
                "type": "url",
                "url": url,
                "is_clean": False,
                "is_unknown": True,
                "threat_label": "Unknown / not provided",
                "threat_category": "Unknown",
                "threat_family": "Unknown",
                "message": "URL not observed in VirusTotal database (Unknown)",
            }

        # 429 Rate Limit
        if response.status_code == 429:
            return {
                "success": False,
                "found": False,
                "status": "RATE_LIMITED",
                "provider": "VirusTotal",
                "type": "url",
                "url": url,
                "is_clean": False,
                "is_unknown": True,
                "threat_label": "Unknown / not provided",
                "threat_category": "Unknown",
                "threat_family": "Unknown",
                "error": "VirusTotal API rate limit reached",
                "message": "VirusTotal intelligence unavailable (Rate limited)",
            }

        response.raise_for_status()
        data = response.json()

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        timeout_count = stats.get("timeout", 0)

        # Clean is strictly when malicious and suspicious are zero in a found scan
        is_clean = (malicious == 0 and suspicious == 0)

        total_count = malicious + suspicious + harmless + undetected
        threat_info = extract_vt_threat_label(attributes)

        return {
            "success": True,
            "found": True,
            "status": "SUCCESS",
            "source": "virustotal",
            "provider": "VirusTotal",
            "type": "url",
            "url": url,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total": total_count,
            "timeout": timeout_count,
            "reputation": attributes.get("reputation", 0),
            "categories": attributes.get("categories", {}),
            "threat_label": threat_info["threat_label"],
            "threat_category": threat_info["threat_category"],
            "threat_family": threat_info["threat_family"],
            "popular_threat_classification": threat_info["popular_threat_classification"],
            "last_analysis_date": attributes.get("last_analysis_date"),
            "is_clean": is_clean,
            "is_unknown": False,
            "message": f"Threat intelligence detections: {malicious} malicious, {suspicious} suspicious across {total_count} engines",
        }

    except requests.Timeout:
        return {
            "success": False,
            "found": False,
            "status": "ERROR",
            "provider": "VirusTotal",
            "type": "url",
            "url": url,
            "is_clean": False,
            "is_unknown": True,
            "error": "VirusTotal query timed out",
            "message": "VirusTotal intelligence query timed out",
        }
    except requests.RequestException as error:
        return {
            "success": False,
            "found": False,
            "status": "ERROR",
            "provider": "VirusTotal",
            "type": "url",
            "url": url,
            "is_clean": False,
            "is_unknown": True,
            "error": str(error),
            "message": "VirusTotal intelligence lookup failed",
        }


def get_hash_reputation(hash_value: str) -> Dict[str, Any]:
    """
    Query VirusTotal directly by cryptographic hash (MD5, SHA-1, or SHA-256).

    IMPORTANT:
    Does NOT upload files. Only performs threat intelligence lookup on the hash.
    A hash not found in VirusTotal must NOT automatically be considered clean.
    """
    if not isinstance(hash_value, str):
        return {
            "success": False,
            "found": False,
            "status": "ERROR",
            "provider": "VirusTotal",
            "type": "hash",
            "is_clean": False,
            "is_unknown": True,
            "error": "Hash value must be a string",
        }

    cleaned_hash = hash_value.strip().lower()

    if not is_valid_hash(cleaned_hash):
        return {
            "success": False,
            "found": False,
            "status": "ERROR",
            "provider": "VirusTotal",
            "type": "hash",
            "hash": cleaned_hash,
            "is_clean": False,
            "is_unknown": True,
            "error": "Invalid hash format (must be MD5, SHA-1, or SHA-256 hexadecimal)",
        }

    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return {
            "success": False,
            "found": False,
            "status": "UNAVAILABLE",
            "provider": "VirusTotal",
            "type": "hash",
            "hash": cleaned_hash,
            "is_clean": False,
            "is_unknown": True,
            "error": "VIRUSTOTAL_API_KEY not configured",
            "message": "VirusTotal hash intelligence unavailable (API key not configured)",
        }

    endpoint = f"{VT_BASE_URL}/files/{cleaned_hash}"

    try:
        response = requests.get(
            endpoint,
            headers=get_headers(),
            timeout=15,
        )

        if response.status_code == 404:
            return {
                "success": True,
                "found": False,
                "status": "NOT_FOUND",
                "provider": "VirusTotal",
                "type": "hash",
                "hash": cleaned_hash,
                "is_clean": False,
                "is_unknown": True,
                "message": "Hash not observed in VirusTotal threat feed (Unknown Status)",
            }

        if response.status_code == 429:
            return {
                "success": False,
                "found": False,
                "status": "RATE_LIMITED",
                "provider": "VirusTotal",
                "type": "hash",
                "hash": cleaned_hash,
                "is_clean": False,
                "is_unknown": True,
                "error": "VirusTotal API rate limit reached",
                "message": "VirusTotal intelligence unavailable (Rate limited)",
            }

        response.raise_for_status()
        data = response.json()

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        timeout_count = stats.get("timeout", 0)

        is_clean = (malicious == 0 and suspicious == 0)

        total_count = malicious + suspicious + harmless + undetected
        threat_info = extract_vt_threat_label(attributes)

        return {
            "success": True,
            "found": True,
            "status": "SUCCESS",
            "source": "virustotal",
            "provider": "VirusTotal",
            "type": "hash",
            "hash": cleaned_hash,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total": total_count,
            "timeout": timeout_count,
            "reputation": attributes.get("reputation", 0),
            "threat_label": threat_info["threat_label"],
            "threat_category": threat_info["threat_category"],
            "threat_family": threat_info["threat_family"],
            "popular_threat_classification": threat_info["popular_threat_classification"],
            "file_type": attributes.get("type_description"),
            "file_size": attributes.get("size"),
            "meaningful_name": attributes.get("meaningful_name"),
            "tags": attributes.get("tags", []),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "is_clean": is_clean,
            "is_unknown": False,
            "message": f"Threat intelligence detections: {malicious} malicious, {suspicious} suspicious across {total_count} engines",
        }

    except requests.Timeout:
        return {
            "success": False,
            "found": False,
            "status": "ERROR",
            "source": "virustotal",
            "provider": "VirusTotal",
            "type": "hash",
            "hash": cleaned_hash,
            "is_clean": False,
            "is_unknown": True,
            "threat_label": "Unknown / not provided",
            "threat_category": "Unknown",
            "threat_family": "Unknown",
            "error": "VirusTotal query timed out",
            "message": "VirusTotal intelligence query timed out",
        }
    except requests.RequestException as error:
        return {
            "success": False,
            "found": False,
            "status": "ERROR",
            "source": "virustotal",
            "provider": "VirusTotal",
            "type": "hash",
            "hash": cleaned_hash,
            "is_clean": False,
            "is_unknown": True,
            "threat_label": "Unknown / not provided",
            "threat_category": "Unknown",
            "threat_family": "Unknown",
            "error": str(error),
            "message": "VirusTotal intelligence lookup failed",
        }


def calculate_sha256(file_path: str) -> str:
    """
    Calculate SHA-256 for a file in chunks to minimize memory consumption.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(1024 * 1024)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


def get_file_reputation(file_path: str) -> Dict[str, Any]:
    """
    Calculate a local file's SHA-256 hash and query VirusTotal for an existing analysis.

    IMPORTANT:
    Does NOT upload the file. Searches VirusTotal strictly by SHA-256 hash.
    """
    if not os.path.exists(file_path):
        return {
            "success": False,
            "found": False,
            "status": "ERROR",
            "source": "virustotal",
            "provider": "VirusTotal",
            "type": "file",
            "is_clean": False,
            "is_unknown": True,
            "threat_label": "Unknown / not provided",
            "threat_category": "Unknown",
            "threat_family": "Unknown",
            "error": f"File not found: {file_path}",
        }

    sha256 = calculate_sha256(file_path)
    result = get_hash_reputation(sha256)

    result["type"] = "file"
    result["sha256"] = sha256
    result["file_path"] = file_path
    return result


def normalize_vt_result(raw_vt: Optional[Dict[str, Any]], url_or_hash: str = "") -> Dict[str, Any]:
    """
    Canonical normalizer for VirusTotal / Threat Intelligence results across all pipelines.

    Guarantees consistent schema, explicit status semantics, and non-conflated default values:
    - Never defaults NOT_REQUIRED, UNAVAILABLE, NOT_FOUND, or ERROR to '0/70 clean'.
    - Canonical fields: status, source, provider, malicious, suspicious, harmless, undetected, total, reputation, message, threat_label.
    """
    if not raw_vt or not isinstance(raw_vt, dict):
        return {
            "status": "NOT_QUERIED",
            "source": "virustotal",
            "provider": "VirusTotal",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total": 0,
            "reputation": None,
            "categories": {},
            "threat_label": "Unknown / not provided",
            "threat_category": "Unknown",
            "threat_family": "Unknown",
            "popular_threat_classification": {},
            "queried_at": None,
            "is_clean": False,
            "is_unknown": True,
            "message": "Threat intelligence was not queried for this scan.",
            "error": None,
        }

    status_val = str(raw_vt.get("status", "SUCCESS")).upper()
    malicious = int(raw_vt.get("malicious", raw_vt.get("malicious_count", raw_vt.get("positives", 0))) or 0)
    suspicious = int(raw_vt.get("suspicious", raw_vt.get("suspicious_count", 0)) or 0)
    harmless = int(raw_vt.get("harmless", raw_vt.get("harmless_count", 0)) or 0)
    undetected = int(raw_vt.get("undetected", raw_vt.get("undetected_count", 0)) or 0)
    total = int(raw_vt.get("total", raw_vt.get("total_engines", malicious + suspicious + harmless + undetected)) or 0)

    # Clean only when found in VT with 0 malicious and 0 suspicious detections
    is_clean = bool(raw_vt.get("is_clean", (status_val == "SUCCESS" and malicious == 0 and suspicious == 0 and total > 0)))
    is_unknown = bool(raw_vt.get("is_unknown", status_val in ["NOT_FOUND", "UNAVAILABLE", "RATE_LIMITED", "ERROR", "NOT_QUERIED"]))

    # Extract or propagate threat label info
    threat_label = raw_vt.get("threat_label")
    threat_category = raw_vt.get("threat_category", "Unknown")
    threat_family = raw_vt.get("threat_family", "Unknown")
    pop_class = raw_vt.get("popular_threat_classification", {})

    if not threat_label or threat_label == "Unknown / not provided":
        if "attributes" in raw_vt and isinstance(raw_vt["attributes"], dict):
            extracted = extract_vt_threat_label(raw_vt["attributes"])
            threat_label = extracted["threat_label"]
            threat_category = extracted["threat_category"]
            threat_family = extracted["threat_family"]
            pop_class = extracted["popular_threat_classification"]
        elif raw_vt.get("categories") and isinstance(raw_vt.get("categories"), dict):
            extracted = extract_vt_threat_label({"categories": raw_vt.get("categories")})
            threat_label = extracted["threat_label"]
        elif status_val == "SUCCESS" and malicious > 0:
            threat_label = "Malicious detection"
        else:
            threat_label = "Unknown / not provided"

    msg = raw_vt.get("message")
    if not msg:
        if status_val == "SUCCESS" and total > 0:
            msg = f"Multi-vendor detections: {malicious} malicious, {suspicious} suspicious across {total} engines."
        elif status_val == "NOT_REQUIRED":
            msg = "Threat intelligence lookup not required for this scan."
        elif status_val == "UNAVAILABLE":
            msg = "Threat intelligence service unavailable or unconfigured."
        elif status_val == "NOT_FOUND":
            msg = "Indicator not observed in threat intelligence database (Unknown)."
        else:
            msg = "Threat intelligence evaluation completed."

    return {
        "status": status_val,
        "source": "virustotal",
        "provider": "VirusTotal",
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total": total,
        "reputation": raw_vt.get("reputation"),
        "categories": raw_vt.get("categories", {}),
        "threat_label": threat_label,
        "threat_category": threat_category,
        "threat_family": threat_family,
        "popular_threat_classification": pop_class,
        "last_analysis_date": raw_vt.get("last_analysis_date"),
        "queried_at": raw_vt.get("queried_at"),
        "is_clean": is_clean,
        "is_unknown": is_unknown,
        "message": msg,
        "error": raw_vt.get("error"),
    }

