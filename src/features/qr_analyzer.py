"""
src/features/qr_analyzer.py

QR Phishing & Payload Analyzer.
Decodes QR codes using robust multi-decoder architecture (OpenCV / pyzbar / pure-Python ISO/IEC 18004 fallback).
Classifies extracted payloads (URL, EMAIL, PHONE, WIFI, TEXT, OTHER) and routes
URL payloads safely into the central analysis pipeline.
"""

from __future__ import annotations

import re
from typing import Dict, Any, Optional
from urllib.parse import urlparse

from src.features.qr_decoder import decode_qr_image

try:
    import cv2
except ImportError:
    cv2 = None


def classify_qr_payload(data: str) -> str:
    """
    Classify a decoded QR string into a semantic payload type:
    - URL: Web addresses starting with http://, https://, or domain-like formats
    - EMAIL: mailto: links or direct email addresses
    - PHONE: tel: links, smsto: links, or phone number strings
    - WIFI: Wi-Fi network configuration strings (WIFI:...)
    - TEXT: Plain readable text
    - OTHER: Binary / custom application URIs
    """
    if not data or not isinstance(data, str):
        return "OTHER"

    data_trimmed = data.strip()
    data_lower = data_trimmed.lower()

    # 1. URL checks
    if data_lower.startswith(("http://", "https://", "ftp://", "ftps://")):
        return "URL"

    # 2. Email checks
    if data_lower.startswith("mailto:"):
        return "EMAIL"
    if re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", data_trimmed):
        return "EMAIL"

    # 3. Phone checks
    if data_lower.startswith(("tel:", "sms:", "smsto:")):
        return "PHONE"
    if re.match(r"^\+?[0-9\s\-()]{7,20}$", data_trimmed):
        return "PHONE"

    # 4. Wi-Fi configuration checks
    if data_trimmed.startswith("WIFI:"):
        return "WIFI"

    # 5. Generic domain check (e.g. "www.example.com/login")
    if re.match(r"^(www\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$", data_trimmed, re.IGNORECASE):
        return "URL"

    # 6. Default to TEXT or OTHER
    if all(ord(c) >= 32 or c in "\r\n\t" for c in data_trimmed):
        return "TEXT"

    return "OTHER"


def decode_qr_code(image_path: str) -> Optional[str]:
    """
    Read an image and attempt to decode a QR code.
    Returns decoded QR content string or None.
    """
    return decode_qr_image(image_path)


def analyze_qr_code(image_path: str) -> Dict[str, Any]:
    """
    Decode a QR code and classify the extracted payload.
    """
    data = decode_qr_code(image_path)

    if not data:
        return {
            "success": False,
            "decode_status": "FAILED",
            "decoded_data": None,
            "decoded_payload": None,
            "payload_type": None,
            "is_url": False,
            "message": "No QR code payload extracted.",
        }

    payload_type = classify_qr_payload(data)
    is_url = (payload_type == "URL")

    # Normalize protocol if domain string without scheme was parsed as URL
    normalized_url = data
    if is_url and not data.lower().startswith(("http://", "https://", "ftp://")):
        normalized_url = f"https://{data}"

    return {
        "success": True,
        "decode_status": "SUCCESS",
        "decoded_data": normalized_url if is_url else data,
        "decoded_payload": normalized_url if is_url else data,
        "raw_payload": data,
        "payload_type": payload_type,
        "is_url": is_url,
    }


def main():
    """Test QR decoding on sample image."""
    image_path = "tests/fixtures/validation/qr/qr_benign_url.png"
    result = analyze_qr_code(image_path)
    print("\n========== QR ANALYSIS ==========")
    for key, value in result.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
