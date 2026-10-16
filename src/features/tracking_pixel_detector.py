"""
src/features/tracking_pixel_detector.py

Passive Email HTML Resource & Tracking-Pixel Detection Engine.
Inspects HTML structure, image tags, sources, and styles for privacy-invasive
tracking pixels and remote external web beacons.

Guarantees:
1. Does NOT download arbitrary remote images or make external web requests.
2. Performs passive metadata analysis using parsed HTML attributes.
3. Distinguishes MIME image attachments from remote HTML external resources.
4. Classifies suspect images with heuristic confidence ('Tracking pixel suspected').
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup

logger = logging.getLogger("phishguard.tracking_pixel_detector")

# Keywords in URL paths, filenames, or domains that strongly suggest tracking/analytics beacons
TRACKING_KEYWORD_PATTERN = re.compile(
    r"(pixel|beacon|spacer|transparent|track|tracking|tracker|open|trk|ping|1x1|blank|dot|clear|spacer\.gif|pixel\.gif|open\.php|track\.php)",
    re.IGNORECASE,
)

# Common URL query parameters used to track recipient opens/identities
TRACKING_QUERY_PARAMS = {
    "id", "uid", "user", "userid", "email", "e", "u", "token", "cid", "mid",
    "recipient", "recip", "msg", "msgid", "campaign", "c", "trk", "open",
}


def _parse_dimension(val: Any) -> Optional[int]:
    """Parse dimension string or number (e.g. '1', '1px', 1) into an integer."""
    if val is None:
        return None
    val_str = str(val).strip().lower()
    if val_str.endswith("px"):
        val_str = val_str[:-2].strip()
    try:
        return int(float(val_str))
    except (ValueError, TypeError):
        return None


def detect_tracking_pixels(
    html_content: str,
    mime_image_count: int = 0,
) -> Dict[str, Any]:
    """
    Inspect HTML email body for remote images, web beacons, and tracking pixels.

    Parameters:
        html_content: Raw HTML text of the email message.
        mime_image_count: Count of MIME image attachments present in the RFC822 message.

    Returns:
        Structured tracking intelligence report:
        {
            "detected": bool,
            "status": "SUSPECTED" | "NOT_DETECTED",
            "html_image_resources_count": int,
            "mime_image_count": int,
            "tracking_pixels_count": int,
            "resources": list[dict],
            "suspected_tracking_pixels": list[dict],
            "reasons": list[str]
        }
    """
    if not html_content or not isinstance(html_content, str):
        return {
            "detected": False,
            "status": "NOT_DETECTED",
            "html_image_resources_count": 0,
            "mime_image_count": mime_image_count,
            "tracking_pixels_count": 0,
            "resources": [],
            "suspected_tracking_pixels": [],
            "reasons": [],
        }

    soup = BeautifulSoup(html_content, "html.parser")
    resources: List[Dict[str, Any]] = []
    suspected_pixels: List[Dict[str, Any]] = []
    reasons: List[str] = []

    # 1. Inspect all <img> elements
    for img in soup.find_all("img"):
        src = (img.get("src") or "").strip()
        if not src:
            continue

        alt = img.get("alt")
        width_raw = img.get("width")
        height_raw = img.get("height")
        style = (img.get("style") or "").lower()

        # Parse CSS inline dimensions if not specified in HTML attributes
        width = _parse_dimension(width_raw)
        height = _parse_dimension(height_raw)
        if width is None and "width" in style:
            w_match = re.search(r"width\s*:\s*([0-9]+)\s*(?:px)?", style)
            if w_match:
                width = _parse_dimension(w_match.group(1))
        if height is None and "height" in style:
            h_match = re.search(r"height\s*:\s*([0-9]+)\s*(?:px)?", style)
            if h_match:
                height = _parse_dimension(h_match.group(1))

        # Check inline Content-ID vs Remote Web Resource
        is_cid = src.lower().startswith("cid:")
        content_id = src[4:].strip("<>") if is_cid else None
        is_remote = src.lower().startswith(("http://", "https://"))
        same_origin_or_external = "inline_cid" if is_cid else ("external" if is_remote else "relative")

        # Evaluate Tracking Indicators
        tracking_indicators = []
        score = 0.0

        # Dimension indicator (1x1 or 0x0)
        is_dim_small = False
        if width is not None and width <= 1 and height is not None and height <= 1:
            is_dim_small = True
            tracking_indicators.append("dimension_1x1_or_smaller")
            score += 0.45
        elif (width is not None and width <= 1) or (height is not None and height <= 1):
            tracking_indicators.append("single_dimension_1px")
            score += 0.20

        # Empty or missing alt text
        if alt == "" or alt is None:
            tracking_indicators.append("empty_or_omitted_alt_text")
            score += 0.15

        # Remote external resource
        if is_remote:
            tracking_indicators.append("remote_external_image")
            score += 0.15

        # CSS Hiding
        if any(h in style for h in ["display:none", "display: none", "visibility:hidden", "visibility: hidden", "opacity:0", "opacity: 0"]):
            tracking_indicators.append("hidden_via_css_style")
            score += 0.30

        # Explicit visual dimensions (images with width or height > 1 are visual content, not 1x1 tracking pixels)
        has_visual_size = (width is not None and width > 1) or (height is not None and height > 1)
        is_css_hidden = any(h in style for h in ["display:none", "display: none", "visibility:hidden", "visibility: hidden", "opacity:0", "opacity: 0"])

        # URL path / filename pattern match
        parsed_url = urlparse(src) if is_remote else None
        host = parsed_url.hostname if parsed_url else ""
        path = parsed_url.path if parsed_url else src
        if TRACKING_KEYWORD_PATTERN.search(path):
            tracking_indicators.append("tracking_keyword_in_image_url")
            score += 0.25

        # Query parameter check
        matched_q = set()
        if parsed_url and parsed_url.query:
            q_params = {k.lower() for k in parse_qs(parsed_url.query).keys()}
            matched_q = q_params.intersection(TRACKING_QUERY_PARAMS)
            if matched_q:
                tracking_indicators.append(f"tracking_query_params:{','.join(matched_q)}")
                score += 0.25

        score = min(1.0, score)

        # A tracking pixel requires small dimensions (<= 1x1), or CSS hidden styling,
        # or explicit tracking query parameters. Normal visual content images are never suspected.
        if has_visual_size and not is_css_hidden:
            is_suspected = False
        else:
            is_suspected = (is_dim_small or is_css_hidden or bool(matched_q)) and (score >= 0.45)

        res_record = {
            "resource_type": "image",
            "source": "html",
            "url": src,
            "src": src,
            "host": host,
            "width": width,
            "height": height,
            "alt": alt if alt is not None else "",
            "content_id": content_id,
            "is_remote": is_remote,
            "same_origin_or_external": same_origin_or_external,
            "tracking_pixel_score": round(score, 2),
            "tracking_indicators": tracking_indicators,
            "is_suspected": is_suspected,
            "is_suspected_tracking_pixel": is_suspected,
        }
        resources.append(res_record)

        if is_suspected:
            suspected_pixels.append(res_record)
            if is_dim_small and (alt == "" or alt is None) and is_remote:
                reason = "Remote 1×1 image with empty alt text; pattern is consistent with an email tracking pixel."
            elif is_dim_small and is_remote:
                reason = "Remote 1×1 external image loaded over HTTPS/HTTP without visual dimensions."
            else:
                reason = f"Remote image resource matches heuristic tracking patterns (score: {round(score, 2)})."
            if reason not in reasons:
                reasons.append(reason)

    # 2. Inspect <source> tags with srcset
    for source_tag in soup.find_all("source"):
        src = (source_tag.get("src") or source_tag.get("srcset") or "").strip()
        if not src or not src.lower().startswith(("http://", "https://")):
            continue
        parsed_url = urlparse(src)
        host = parsed_url.hostname or ""
        path = parsed_url.path or src
        is_keyword = bool(TRACKING_KEYWORD_PATTERN.search(path))
        res_record = {
            "resource_type": "source",
            "source": "html",
            "url": src,
            "host": host,
            "width": None,
            "height": None,
            "alt": "",
            "content_id": None,
            "is_remote": True,
            "same_origin_or_external": "external",
            "tracking_pixel_score": 0.4 if is_keyword else 0.1,
            "tracking_indicators": ["source_tag", "remote_external_image"] + (["tracking_keyword"] if is_keyword else []),
            "is_suspected_tracking_pixel": False,
        }
        resources.append(res_record)

    has_suspected = len(suspected_pixels) > 0
    return {
        "detected": has_suspected,
        "status": "SUSPECTED" if has_suspected else "NOT_DETECTED",
        "html_image_resources_count": len(resources),
        "mime_image_count": mime_image_count,
        "tracking_pixels_count": len(suspected_pixels),
        "resources": resources,
        "suspected_tracking_pixels": suspected_pixels,
        "reasons": reasons,
    }
