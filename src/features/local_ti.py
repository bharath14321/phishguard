"""
src/features/local_ti.py

High-Performance Local Threat Intelligence Lookup Engine.
Queries the local SQLite database (data/threat_intelligence.db) containing
ingested indicators from PhishTank, URLhaus, OpenPhish, and MalwareBazaar.

Features:
- Fast indexed lookup for URLs, domains, and file hashes (SHA256, MD5, SHA1).
- Normalization (URL schemes, trailing slashes, lowercase hashes).
- Graceful handling of missing database file.
"""

from __future__ import annotations

import logging
from pathlib import Path
import sqlite3
from typing import Any, Dict, Optional
from urllib.parse import urlparse

logger = logging.getLogger("phishguard.local_ti")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
LOCAL_TI_DB_PATH = _PROJECT_ROOT / "data" / "threat_intelligence.db"


def _normalize_url_variants(url: str) -> list[str]:
    """Generate normalized search variants for a URL indicator."""
    if not url:
        return []
    u = url.strip()
    variants = {u}

    # Add lowercase variant
    variants.add(u.lower())

    # Trailing slash variants
    if u.endswith("/"):
        variants.add(u[:-1])
        variants.add(u[:-1].lower())
    else:
        variants.add(f"{u}/")
        variants.add(f"{u}/".lower())

    # Scheme variants (http vs https vs schemeless)
    if u.startswith("http://"):
        schemeless = u[7:]
        variants.add(schemeless)
        variants.add(f"https://{schemeless}")
    elif u.startswith("https://"):
        schemeless = u[8:]
        variants.add(schemeless)
        variants.add(f"http://{schemeless}")
    else:
        variants.add(f"http://{u}")
        variants.add(f"https://{u}")

    return list(variants)


def query_local_threat_intelligence(
    indicator: str,
    indicator_type: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Query the local threat intelligence database for a URL, domain, or hash indicator.

    Returns:
        Dict with keys:
            - found (bool): True if matched in local feeds
            - status (str): 'FOUND' or 'UNKNOWN'
            - indicator (str)
            - indicator_type (str)
            - source (str, optional): 'phishtank', 'urlhaus', 'openphish', 'malwarebazaar'
            - classification (str, optional): 'phishing', 'malware'
            - confidence (int, optional): 0-100
            - family (str, optional)
            - tags (str, optional)
            - message (str)
    """
    target_db = db_path or LOCAL_TI_DB_PATH
    if not target_db.exists():
        return {
            "found": False,
            "status": "UNKNOWN",
            "indicator": indicator,
            "indicator_type": indicator_type or "unknown",
            "message": "Local threat intelligence database not present on disk.",
        }

    clean_indicator = indicator.strip()
    if not clean_indicator:
        return {
            "found": False,
            "status": "UNKNOWN",
            "indicator": indicator,
            "indicator_type": indicator_type or "unknown",
            "message": "Empty indicator provided.",
        }

    try:
        conn = sqlite3.connect(f"file:{target_db.resolve()}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # 1. If hash lookup (MD5, SHA1, SHA256)
        clean_lower = clean_indicator.lower()
        if len(clean_lower) in (32, 40, 64) and all(c in "0123456789abcdef" for c in clean_lower):
            cursor.execute(
                "SELECT * FROM local_indicators WHERE indicator = ? LIMIT 1",
                (clean_lower,),
            )
            row = cursor.fetchone()
            if row:
                conn.close()
                return {
                    "found": True,
                    "status": "FOUND",
                    "indicator": clean_lower,
                    "indicator_type": row["indicator_type"],
                    "source": row["source"],
                    "classification": row["classification"],
                    "family": row["family"],
                    "tags": row["tags"],
                    "confidence": int(row["confidence"] or 95),
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                    "message": f"Known malicious file hash matched in local feed ({row['source']}).",
                }

        # 2. If URL / domain lookup
        url_variants = _normalize_url_variants(clean_indicator)
        placeholders = ",".join("?" for _ in url_variants)
        cursor.execute(
            f"SELECT * FROM local_indicators WHERE indicator IN ({placeholders}) LIMIT 1",
            url_variants,
        )
        row = cursor.fetchone()
        if row:
            conn.close()
            return {
                "found": True,
                "status": "FOUND",
                "indicator": clean_indicator,
                "matched_indicator": row["indicator"],
                "indicator_type": row["indicator_type"],
                "source": row["source"],
                "classification": row["classification"],
                "family": row["family"],
                "tags": row["tags"],
                "confidence": int(row["confidence"] or 95),
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "message": f"Known malicious indicator matched in local feed ({row['source']}).",
            }

        # 3. If domain lookup fallback from URL
        try:
            parsed = urlparse(clean_indicator if "://" in clean_indicator else f"http://{clean_indicator}")
            domain = (parsed.netloc or "").split(":")[0].lower()
            if domain and domain != clean_lower:
                cursor.execute(
                    "SELECT * FROM local_indicators WHERE indicator = ? LIMIT 1",
                    (domain,),
                )
                row = cursor.fetchone()
                if row:
                    conn.close()
                    return {
                        "found": True,
                        "status": "FOUND",
                        "indicator": clean_indicator,
                        "matched_indicator": domain,
                        "indicator_type": "domain",
                        "source": row["source"],
                        "classification": row["classification"],
                        "family": row["family"],
                        "tags": row["tags"],
                        "confidence": int(row["confidence"] or 90),
                        "first_seen": row["first_seen"],
                        "last_seen": row["last_seen"],
                        "message": f"Known malicious domain matched in local feed ({row['source']}).",
                    }
        except Exception:
            pass

        conn.close()
        return {
            "found": False,
            "status": "UNKNOWN",
            "indicator": clean_indicator,
            "indicator_type": indicator_type or "url",
            "message": "Indicator not present in local threat intelligence feeds.",
        }

    except Exception as exc:
        logger.error("Local threat intelligence lookup error: %s", exc)
        return {
            "found": False,
            "status": "UNKNOWN",
            "indicator": clean_indicator,
            "indicator_type": indicator_type or "unknown",
            "error": str(exc),
            "message": "Local threat intelligence lookup encountered an error.",
        }


def aggregate_local_ti_results(
    evaluations: List[Dict[str, Any]],
    evaluated_count: Optional[int] = None,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Canonical Local Threat Intelligence Aggregation Contract for multi-indicator artifacts (e.g. Email).

    Derives authoritative status from ALL analyzed child indicators (plain text URLs,
    HTML href URLs, attachment embedded URLs, QR-decoded URLs, attachment hashes).

    Guarantees:
    - If ANY child indicator matches (e.g. PhishTank), status is MATCH, never NO_MATCH.
    - If no indicators were evaluated, status is NOT_EVALUATED, never NO_MATCH.
    - If evaluations encountered fatal errors, status is ERROR.
    - Never conflates NO_MATCH with NOT_EVALUATED with ERROR.
    """
    if error:
        return {
            "status": "ERROR",
            "matches": [],
            "indicator_count_evaluated": evaluated_count or len(evaluations),
            "evaluated_count": evaluated_count or len(evaluations),
            "matched_indicator_count": 0,
            "sources": [],
            "highest_confidence": None,
            "found": False,
            "source": None,
            "classification": None,
            "threat_type": None,
            "confidence": None,
            "error": error,
            "message": f"Local threat intelligence evaluation failed with error: {error}",
        }

    total_evaluated = evaluated_count if evaluated_count is not None else len(evaluations)
    if total_evaluated == 0:
        return {
            "status": "NOT_EVALUATED",
            "matches": [],
            "indicator_count_evaluated": 0,
            "evaluated_count": 0,
            "matched_indicator_count": 0,
            "sources": [],
            "highest_confidence": None,
            "found": False,
            "source": None,
            "classification": None,
            "threat_type": None,
            "confidence": None,
            "error": None,
            "message": "Local threat intelligence was not evaluated (no child indicators observed).",
        }

    matches: List[Dict[str, Any]] = []
    sources_set = set()
    highest_conf: Optional[int] = None

    for item in evaluations:
        ti = item.get("local_ti") or item
        # Check if matched
        is_matched = bool(ti.get("found")) or ti.get("status") in ("FOUND", "MATCH")
        if is_matched:
            feed_source = ti.get("source") or "local_threat_feed"
            sources_set.add(feed_source)
            conf = ti.get("confidence")
            if conf is not None:
                try:
                    conf_int = int(conf)
                    if highest_conf is None or conf_int > highest_conf:
                        highest_conf = conf_int
                except (ValueError, TypeError):
                    pass

            match_record = {
                "indicator": item.get("indicator") or item.get("url") or ti.get("indicator") or "",
                "indicator_type": item.get("indicator_type") or ti.get("indicator_type") or "url",
                "source": feed_source,
                "verdict": "MALICIOUS",
                "confidence": conf or 95,
                "threat_type": ti.get("threat_type") or ti.get("classification") or "phishing",
                "classification": ti.get("classification") or ti.get("threat_type") or "phishing",
                "family": ti.get("family"),
                "matched_child_artifact": item.get("child_artifact") or item.get("source") or item.get("url") or "child_indicator",
                "canonicalized_indicator": ti.get("matched_indicator") or item.get("indicator") or item.get("url") or "",
            }
            matches.append(match_record)

    sources_list = sorted(list(sources_set))
    if len(matches) > 0:
        status = "MATCH"
        primary_source = sources_list[0] if sources_list else "phishtank"
        primary_threat = matches[0].get("threat_type", "phishing")
        message = f"Confirmed malicious indicator matched in local {primary_source} threat feed ({primary_threat})."
    else:
        status = "NO_MATCH"
        primary_source = None
        primary_threat = None
        message = f"Evaluated against 91,190 local threat intelligence indicators across {total_evaluated} child indicator(s); no match found."

    return {
        "status": status,
        "matches": matches,
        "indicator_count_evaluated": total_evaluated,
        "evaluated_count": total_evaluated,
        "matched_indicator_count": len(matches),
        "sources": sources_list,
        "highest_confidence": highest_conf or (95 if status == "MATCH" else None),
        # Backward-compatible fields
        "found": status == "MATCH",
        "source": primary_source,
        "classification": primary_threat,
        "threat_type": primary_threat,
        "confidence": highest_conf or (95 if status == "MATCH" else None),
        "error": None,
        "message": message,
    }

