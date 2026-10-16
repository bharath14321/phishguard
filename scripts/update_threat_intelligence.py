#!/usr/bin/env python3
"""
scripts/update_threat_intelligence.py

CLI Management Script for PHISHGUARD Local Threat Intelligence Updates.

Usage:
  python scripts/update_threat_intelligence.py --status
  python scripts/update_threat_intelligence.py --check-only
  python scripts/update_threat_intelligence.py --rollback
  python scripts/update_threat_intelligence.py --ingest-file <path> --source phishtank
"""

import argparse
import json
import sys
from pathlib import Path

# Add project root to path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.features.threat_intelligence_updater import (
    ThreatIntelligenceUpdater,
    get_threat_intelligence_status,
)


def main():
    parser = argparse.ArgumentParser(description="PHISHGUARD Local Threat Intelligence CLI")
    parser.add_argument("--status", action="store_true", help="Print live threat intelligence status and exit")
    parser.add_argument("--check-only", action="store_true", help="Check database health and status")
    parser.add_argument("--rollback", action="store_true", help="Roll back to previous backup snapshot")
    parser.add_argument("--ingest-file", type=str, help="Ingest a custom indicators file (JSON or CSV)")
    parser.add_argument("--source", type=str, default="custom_feed", help="Feed source name (e.g., phishtank, urlhaus)")
    parser.add_argument("--db-path", type=str, help="Custom database path")

    args = parser.parse_args()
    db_path = Path(args.db_path) if args.db_path else None

    if args.status or args.check_only:
        status_info = get_threat_intelligence_status(db_path)
        print(json.dumps(status_info, indent=2))
        sys.exit(0 if status_info["status"] == "ACTIVE" else 1)

    updater = ThreatIntelligenceUpdater(db_path=db_path)

    if args.rollback:
        print("Initiating rollback to previous snapshot...")
        updater.acquire_lock()
        try:
            success = updater.rollback_to_snapshot()
            if success:
                print("Rollback completed successfully.")
            else:
                print("No backup snapshot found or rollback failed.")
                sys.exit(1)
        finally:
            updater.release_lock()
        sys.exit(0)

    if args.ingest_file:
        file_path = Path(args.ingest_file)
        if not file_path.exists():
            print(f"Error: File not found: {file_path}")
            sys.exit(1)

        print(f"Acquiring update lock and creating backup snapshot...")
        updater.acquire_lock()
        try:
            updater.create_backup_snapshot()
            conn = updater.init_staging_db(copy_existing=True)

            raw_bytes = file_path.read_bytes()
            records = []
            if file_path.suffix.lower() == ".json":
                parsed = json.loads(raw_bytes.decode("utf-8", errors="replace"))
                if isinstance(parsed, list):
                    for item in parsed:
                        if isinstance(item, dict):
                            records.append({
                                "indicator": item.get("url") or item.get("indicator", ""),
                                "indicator_type": item.get("type", "url"),
                                "classification": item.get("classification", "phishing"),
                                "confidence": item.get("confidence", 95),
                            })
                        elif isinstance(item, str):
                            records.append({"indicator": item, "indicator_type": "url"})
            else:
                lines = raw_bytes.decode("utf-8", errors="replace").splitlines()
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        records.append({"indicator": line, "indicator_type": "url"})

            print(f"Ingesting {len(records)} records for source '{args.source}'...")
            inserted = updater.ingest_records(conn, args.source, records, raw_bytes)
            print(f"Inserted/updated {inserted} records. Verifying integrity and swapping...")
            updater.verify_and_swap(conn)
            print("Threat intelligence update completed successfully.")
        finally:
            updater.release_lock()
        sys.exit(0)

    # Default: print status
    status_info = get_threat_intelligence_status(db_path)
    print(json.dumps(status_info, indent=2))


if __name__ == "__main__":
    main()
