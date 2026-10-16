"""
scripts/data_pipeline/download_sources.py

Automated Dataset & Threat Intelligence Feed Ingestion.

Supports:
- PhishTank, OpenPhish, URLhaus, MalwareBazaar (Local Threat Intelligence)
- Malicious Phish (Local training set)
- Handling of Authenticated/Restricted datasets (Graceful manual action pause)
- SHA-256 calculation and metadata verification
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
try:
    import yaml
except ImportError:
    yaml = None
import requests

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s - %(message)s")
logger = logging.getLogger("phishguard.data_pipeline")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
RAW_DATA_DIR = BASE_DIR / "data" / "raw"
PROCESSED_DATA_DIR = BASE_DIR / "data" / "processed"
CONFIG_PATH_YAML = BASE_DIR / "data" / "sources.yaml"
CONFIG_PATH_JSON = BASE_DIR / "data" / "sources.json"


def compute_file_sha256(filepath: Path) -> str:
    """Calculate the cryptographic SHA-256 checksum of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(65536), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def load_sources_config(config_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Load sources definition from YAML or JSON fallback."""
    target_json = CONFIG_PATH_JSON
    target_yaml = CONFIG_PATH_YAML

    if target_json.exists():
        with open(target_json, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("sources", [])

    if target_yaml.exists() and yaml is not None:
        with open(target_yaml, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data.get("sources", [])

    logger.error("Sources config file not found.")
    return []


def download_http_source(
    source: Dict[str, Any],
    dest_dir: Path = RAW_DATA_DIR,
    timeout: int = 30
) -> Dict[str, Any]:
    """
    Download a single HTTP/HTTPS dataset or feed.
    Saves to destination directory and calculates metadata.
    """
    name = source.get("name", "unknown")
    url = source.get("url")
    expected_format = source.get("expected_format", "csv")
    dest_file = dest_dir / f"{name}.{expected_format}"

    result = {
        "name": name,
        "status": "FAILED",
        "purpose": source.get("purpose"),
        "destination": str(dest_file),
        "sha256": None,
        "bytes_downloaded": 0,
        "manual_action_required": False,
        "message": "",
    }

    # Check if manual action is required
    if source.get("manual_action_required") or source.get("authentication_required"):
        result["status"] = "PENDING_MANUAL_ACTION"
        result["manual_action_required"] = True
        result["message"] = source.get("manual_instructions", "Authentication or registration required.")
        logger.warning(f"Source '{name}' requires manual action: {result['message']}")
        return result

    if not source.get("enabled", True):
        result["status"] = "DISABLED"
        result["message"] = "Source is disabled in configuration."
        return result

    # Local file check
    if source.get("download_method") == "local_file":
        local_path = BASE_DIR / url if not Path(url).is_absolute() else Path(url)
        if local_path.exists():
            result["status"] = "SUCCESS"
            result["destination"] = str(local_path)
            result["sha256"] = compute_file_sha256(local_path)
            result["bytes_downloaded"] = local_path.stat().st_size
            result["message"] = "Existing local dataset verified."
            logger.info(f"Verified local source '{name}' ({result['bytes_downloaded']:,} bytes)")
            return result
        else:
            result["status"] = "MISSING_LOCAL_FILE"
            result["message"] = f"Expected local file not found at {local_path}"
            return result

    # HTTP Download
    logger.info(f"Downloading source '{name}' from {url}...")
    headers = {"User-Agent": "PHISHGUARD-Threat-Intel-Pipeline/2.0"}

    try:
        response = requests.get(url, headers=headers, timeout=timeout, stream=True, allow_redirects=True)
        if response.status_code == 200:
            dest_dir.mkdir(parents=True, exist_ok=True)
            temp_file = dest_file.with_suffix(".tmp")
            
            with open(temp_file, "wb") as f:
                for chunk in response.iter_content(chunk_size=65536):
                    if chunk:
                        f.write(chunk)
            
            # Atomic rename
            temp_file.replace(dest_file)
            result["status"] = "SUCCESS"
            result["sha256"] = compute_file_sha256(dest_file)
            result["bytes_downloaded"] = dest_file.stat().st_size
            result["message"] = "Downloaded successfully."
            logger.info(f"Successfully downloaded '{name}' ({result['bytes_downloaded']:,} bytes, sha256={result['sha256'][:8]}...)")
        else:
            result["status"] = f"HTTP_{response.status_code}"
            result["message"] = f"HTTP error {response.status_code}: {response.reason}"
            logger.error(f"Failed to download '{name}': {result['message']}")
    except Exception as exc:
        result["status"] = "ERROR"
        result["message"] = f"Network exception: {type(exc).__name__} - {str(exc)}"
        logger.error(f"Exception downloading '{name}': {exc}")

    return result


def download_all_sources(config_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """
    Execute downloading for all configured sources.
    Returns list of source execution results.
    """
    sources = load_sources_config(config_path)
    results = []
    logger.info(f"Starting acquisition for {len(sources)} configured sources...")

    for source in sources:
        res = download_http_source(source)
        results.append(res)

    return results


if __name__ == "__main__":
    download_all_sources()
