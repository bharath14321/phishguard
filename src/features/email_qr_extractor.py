"""
Email Embedded QR Code Extractor and Analyzer

Extracts candidate image MIME parts (inline and attachments) from an .eml email file
and passes them safely to the central QR analyzer (src/features/qr_analyzer.py).
When a decoded QR payload contains an HTTP/HTTPS URL, the URL is automatically routed
through the central URL analysis pipeline (src/features/url_analyzer.py).

Security & Hygiene Controls:
- Safe bounded iteration over MIME parts (max images limit).
- Strict per-image byte size enforcement (max size limit).
- Randomized, isolated temporary files with guaranteed cleanup in finally blocks.
- No execution of file content; no trust placed in external MIME filenames.
- Content hash deduplication to avoid redundant QR decoding of repeated assets.
- URL deduplication to avoid redundant downstream URL pipeline execution.
"""

import os
import re
import hashlib
import tempfile
from email import policy
from email.parser import BytesParser
from typing import Dict, Any, List, Optional, Set

from src.features.qr_analyzer import analyze_qr_code
from src.features.url_analyzer import analyze_url
from src.analysis.risk_engine import analyze_url_risk


# Maximum number of image MIME parts inspected per email to prevent DoS
MAX_CANDIDATE_IMAGES = 15

# Maximum allowed size for an individual image MIME payload (10 MB)
MAX_IMAGE_BYTES = 10 * 1024 * 1024

# Supported image MIME types that OpenCV / QR detector can decode
SUPPORTED_IMAGE_MIMETYPES = {
    "image/png",
    "image/jpeg",
    "image/jpg",
    "image/bmp",
    "image/webp",
    "image/gif",
    "image/tiff",
}

# Image file extension pattern for attachment fallback identification
IMAGE_EXT_PATTERN = re.compile(
    r"\.(png|jpe?g|bmp|webp|gif|tiff)$",
    re.IGNORECASE,
)


def _determine_image_suffix(content_type: str, filename: Optional[str]) -> str:
    """
    Determine a safe, sanitized file extension suffix for temporary image file creation.
    """
    ct = (content_type or "").lower().strip()
    if "png" in ct:
        return ".png"
    if "jpeg" in ct or "jpg" in ct:
        return ".jpg"
    if "bmp" in ct:
        return ".bmp"
    if "webp" in ct:
        return ".webp"
    if "gif" in ct:
        return ".gif"
    if "tiff" in ct:
        return ".tiff"

    if filename:
        match = IMAGE_EXT_PATTERN.search(filename)
        if match:
            return f".{match.group(1).lower()}"

    return ".png"


def extract_candidate_images_from_email(
    file_path: str,
    max_images: int = MAX_CANDIDATE_IMAGES,
    max_bytes: int = MAX_IMAGE_BYTES,
) -> List[Dict[str, Any]]:
    """
    Parse an .eml email file and extract candidate image MIME parts.

    Parameters
    ----------
    file_path : str
        Path to the .eml file on disk.
    max_images : int
        Maximum number of image parts to extract (DoS protection).
    max_bytes : int
        Maximum allowed byte size per image part.

    Returns
    -------
    List[Dict[str, Any]]
        List of candidate image dictionaries containing safe metadata and raw bytes.
    """
    candidates: List[Dict[str, Any]] = []

    try:
        with open(file_path, "rb") as f:
            message = BytesParser(policy=policy.default).parse(f)
    except Exception:
        return candidates

    image_counter = 0

    # Walk through all MIME parts in the email message
    for part in message.walk():
        if image_counter >= max_images:
            break

        # Check if part is an image MIME type or has image extension
        content_type = (part.get_content_type() or "").lower()
        content_maintype = (part.get_content_maintype() or "").lower()
        raw_filename = part.get_filename() or ""
        content_id = part.get("Content-ID") or ""

        is_image_mime = (
            content_maintype == "image"
            or content_type in SUPPORTED_IMAGE_MIMETYPES
        )
        is_image_ext = bool(IMAGE_EXT_PATTERN.search(raw_filename))

        if not (is_image_mime or is_image_ext):
            continue

        try:
            payload_bytes = part.get_payload(decode=True)
        except Exception:
            continue

        if not payload_bytes or len(payload_bytes) == 0:
            continue

        # Enforce image size limits to prevent memory exhaustion
        if len(payload_bytes) > max_bytes:
            continue

        image_counter += 1
        source_label = (
            raw_filename.strip()
            if raw_filename.strip()
            else (content_id.strip() if content_id.strip() else f"inline_image_{image_counter}")
        )

        candidates.append({
            "part_index": image_counter,
            "source_name": source_label,
            "content_type": content_type,
            "size_bytes": len(payload_bytes),
            "bytes": payload_bytes,
            "suffix": _determine_image_suffix(content_type, raw_filename),
        })

    return candidates


def extract_qr_from_email(
    file_path: str,
    max_images: int = MAX_CANDIDATE_IMAGES,
    max_bytes: int = MAX_IMAGE_BYTES,
) -> Dict[str, Any]:
    """
    Inspect all candidate images in an email for QR codes and analyze any decoded URLs.

    Security & Reliability Flow:
    1. Extract image MIME parts up to bounded maximums.
    2. Deduplicate repeated images by SHA-256 hash.
    3. Write each candidate to an isolated temporary file on disk.
    4. Pass temporary file to existing qr_analyzer (analyze_qr_code).
    5. Clean up temporary files in guaranteed finally blocks.
    6. For detected QR codes with HTTP/HTTPS URLs, invoke the central url_analyzer.
    7. Deduplicate URL analyses when identical URLs appear across multiple QR images.

    Parameters
    ----------
    file_path : str
        Path to the email file (.eml).
    max_images : int
        Maximum images to inspect.
    max_bytes : int
        Maximum byte size per image.

    Returns
    -------
    Dict[str, Any]
        Structured QR analysis result dictionary for the email.
    """
    errors: List[str] = []
    findings: List[Dict[str, Any]] = []
    seen_image_hashes: Set[str] = set()
    analyzed_urls_cache: Dict[str, Dict[str, Any]] = {}

    try:
        candidates = extract_candidate_images_from_email(
            file_path,
            max_images=max_images,
            max_bytes=max_bytes,
        )
    except Exception as exc:
        return {
            "detected": False,
            "image_count": 0,
            "qr_count": 0,
            "findings": [],
            "errors": [str(exc)],
        }

    total_images_inspected = len(candidates)

    for item in candidates:
        img_bytes = item["bytes"]
        img_hash = hashlib.sha256(img_bytes).hexdigest()

        # Skip duplicate identical images in the same email (e.g. repeated logo)
        if img_hash in seen_image_hashes:
            continue
        seen_image_hashes.add(img_hash)

        temp_path = None
        try:
            # Create a safe, randomized temporary file for OpenCV to read
            with tempfile.NamedTemporaryFile(
                prefix="phishguard_qr_email_",
                suffix=item["suffix"],
                delete=False,
            ) as tmp_file:
                tmp_file.write(img_bytes)
                temp_path = tmp_file.name

            # Run existing QR decoder on the temporary image file
            qr_res = analyze_qr_code(temp_path)

            if qr_res.get("success") and qr_res.get("decoded_data"):
                decoded_data = str(qr_res["decoded_data"]).strip()
                is_url = bool(qr_res.get("is_url", False))

                finding_entry: Dict[str, Any] = {
                    "source_part": item["source_name"],
                    "decoded_data": decoded_data,
                    "is_url": is_url,
                }

                # If the QR code payload is a URL, route it through the central URL pipeline
                if is_url and decoded_data:
                    if decoded_data in analyzed_urls_cache:
                        cached = analyzed_urls_cache[decoded_data]
                        finding_entry["url_analysis"] = cached["analysis"]
                        finding_entry["url_risk"] = cached["risk"]
                    else:
                        try:
                            url_analysis = analyze_url(decoded_data)
                            risk_result = analyze_url_risk(url_analysis)
                            url_risk_dict = {
                                "score": getattr(risk_result, "score", 0),
                                "level": getattr(risk_result, "level", "UNKNOWN"),
                                "signals": getattr(risk_result, "signals", []),
                            }
                            finding_entry["url_analysis"] = url_analysis
                            finding_entry["url_risk"] = url_risk_dict
                            analyzed_urls_cache[decoded_data] = {
                                "analysis": url_analysis,
                                "risk": url_risk_dict,
                            }
                        except Exception as url_err:
                            errors.append(f"Failed URL analysis for decoded QR '{decoded_data}': {url_err}")
                            finding_entry["url_analysis"] = None
                            finding_entry["url_risk"] = None

                findings.append(finding_entry)

        except Exception as proc_err:
            errors.append(f"Error analyzing image part {item.get('source_name')}: {proc_err}")
        finally:
            # Guarantee temporary file removal
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except Exception:
                    pass

    return {
        "detected": len(findings) > 0,
        "image_count": total_images_inspected,
        "qr_count": len(findings),
        "findings": findings,
        "errors": errors,
    }
