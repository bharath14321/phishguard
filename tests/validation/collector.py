"""
tests/validation/collector.py

Central validation results collector and reporter for the PHISHGUARD automated validation campaign.

Provides:
1. ValidationRecord dataclass capturing machine-readable test case schema.
2. ValidationCollector singleton managing execution state and result aggregation.
3. Multi-format report export (JSON, CSV, Markdown, HTML).
"""

from __future__ import annotations

import csv
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ValidationRecord:
    """
    Standardized machine-readable record for every validation test case.
    """
    test_id: str
    category: str
    description: str
    input_type: str
    expected_behavior: str
    actual_behavior: str
    status: str  # PASS | FAIL | BLOCKED | MANUAL
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    evidence_score: Optional[float] = None
    evidence_level: Optional[str] = None
    evidence_classes: List[str] = field(default_factory=list)
    correlations: List[str] = field(default_factory=list)
    vt_decision: Optional[str] = None
    vt_result: Optional[str] = None
    ai_status: Optional[str] = None
    analysis_id: Optional[int] = None
    error: Optional[str] = None
    notes: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ValidationCollector:
    """
    Singleton repository of validation test execution outcomes.
    """
    _instance: Optional[ValidationCollector] = None

    def __init__(self):
        self.records: Dict[str, ValidationRecord] = {}

    @classmethod
    def get_instance(cls) -> ValidationCollector:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        cls._instance = cls()

    def record(
        self,
        test_id: str,
        category: str,
        description: str,
        input_type: str,
        expected_behavior: str,
        actual_behavior: str,
        status: str,
        risk_score: Optional[float] = None,
        risk_level: Optional[str] = None,
        evidence_score: Optional[float] = None,
        evidence_level: Optional[str] = None,
        evidence_classes: Optional[List[str]] = None,
        correlations: Optional[List[str]] = None,
        vt_decision: Optional[str] = None,
        vt_result: Optional[str] = None,
        ai_status: Optional[str] = None,
        analysis_id: Optional[int] = None,
        error: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> ValidationRecord:
        """Record or update a validation test case execution."""
        status_norm = status.strip().upper()
        if status_norm not in ("PASS", "FAIL", "BLOCKED", "MANUAL"):
            status_norm = "FAIL"

        rec = ValidationRecord(
            test_id=test_id,
            category=category.upper(),
            description=description,
            input_type=input_type,
            expected_behavior=expected_behavior,
            actual_behavior=actual_behavior,
            status=status_norm,
            risk_score=risk_score,
            risk_level=risk_level,
            evidence_score=evidence_score,
            evidence_level=evidence_level,
            evidence_classes=evidence_classes or [],
            correlations=correlations or [],
            vt_decision=vt_decision,
            vt_result=vt_result,
            ai_status=ai_status,
            analysis_id=analysis_id,
            error=error,
            notes=notes,
        )
        self.records[test_id] = rec
        return rec

    def record_result(
        self,
        test_id: str,
        category: str,
        description: str,
        status: str = "PASS",
        duration_ms: float = 0.0,
        evidence: Optional[Dict[str, Any]] = None,
        expected_behavior: str = "As specified in validation test definition",
        actual_behavior: str = "Validated correctly against current implementation",
        **kwargs: Any,
    ) -> ValidationRecord:
        """Convenience recorder accepting evidence dict and duration."""
        ev = evidence or {}
        risk_score = ev.get("score") if "score" in ev else ev.get("risk_score")
        risk_level = ev.get("level") if "level" in ev else ev.get("risk_level")
        return self.record(
            test_id=test_id,
            category=category,
            description=description,
            input_type=kwargs.get("input_type", "structured"),
            expected_behavior=expected_behavior,
            actual_behavior=actual_behavior,
            status=status,
            risk_score=risk_score,
            risk_level=risk_level,
            notes=json.dumps(ev, default=str) if ev else None,
            **kwargs,
        )

    def get_records(self) -> List[ValidationRecord]:
        """Return sorted list of all recorded validation test cases."""
        return sorted(self.records.values(), key=lambda r: r.test_id)

    def summary(self) -> Dict[str, Any]:
        """Aggregate test execution metrics."""
        records = self.get_records()
        total = len(records)
        passed = sum(1 for r in records if r.status == "PASS")
        failed = sum(1 for r in records if r.status == "FAIL")
        blocked = sum(1 for r in records if r.status == "BLOCKED")
        manual = sum(1 for r in records if r.status == "MANUAL")

        categories: Dict[str, Dict[str, int]] = {}
        for r in records:
            cat = r.category
            if cat not in categories:
                categories[cat] = {"total": 0, "pass": 0, "fail": 0, "blocked": 0, "manual": 0}
            categories[cat]["total"] += 1
            categories[cat][r.status.lower()] += 1

        return {
            "total": total,
            "pass": passed,
            "fail": failed,
            "blocked": blocked,
            "manual": manual,
            "pass_rate": round((passed / total * 100), 2) if total > 0 else 0.0,
            "categories": categories,
        }

    def export_all(self, report_dir: Path | str = "reports/validation") -> Dict[str, str]:
        """Export latest.json, latest.csv, latest.md, latest.html and timestamped variants."""
        r_dir = Path(report_dir)
        r_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        summary_data = self.summary()
        records_data = [r.to_dict() for r in self.get_records()]
        full_payload = {
            "metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "campaign": "PHISHGUARD Automated Comprehensive Validation Campaign",
                "version": "2.0.0",
            },
            "summary": summary_data,
            "records": records_data,
        }

        json_latest = r_dir / "latest.json"
        csv_latest = r_dir / "latest.csv"
        md_latest = r_dir / "latest.md"
        html_latest = r_dir / "latest.html"

        try:
            # 1. JSON Export
            json_content = json.dumps(full_payload, indent=2)
            json_ts = r_dir / f"validation_{ts}.json"
            json_ts.write_text(json_content)
            json_latest.write_text(json_content)

            # 2. CSV Export
            csv_rows = []
            headers = [
                "test_id", "category", "status", "description", "input_type",
                "expected_behavior", "actual_behavior", "risk_score", "risk_level",
                "evidence_score", "evidence_level", "evidence_classes", "correlations",
                "vt_decision", "vt_result", "ai_status", "analysis_id", "error", "notes", "timestamp"
            ]
            csv_ts = r_dir / f"validation_{ts}.csv"
            with open(csv_ts, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                for r in records_data:
                    row = dict(r)
                    row["evidence_classes"] = "; ".join(row.get("evidence_classes") or [])
                    row["correlations"] = "; ".join(row.get("correlations") or [])
                    writer.writerow(row)
            csv_latest.write_text(csv_ts.read_text(encoding="utf-8"))

            # 3. Markdown Export
            md_content = self._generate_markdown(full_payload)
            md_ts = r_dir / f"validation_{ts}.md"
            md_latest = r_dir / "latest.md"
            md_ts.write_text(md_content)
            md_latest.write_text(md_content)

            # 4. HTML Export
            html_content = self._generate_html(full_payload)
            html_ts = r_dir / f"validation_{ts}.html"
            html_latest = r_dir / "latest.html"
            html_ts.write_text(html_content)
            html_latest.write_text(html_content)
        except OSError as e:
            print(f"[ValidationCollector] Notice: Report export skipped due to filesystem constraint ({e})")

        return {
            "json": str(json_latest),
            "csv": str(csv_latest),
            "md": str(md_latest),
            "html": str(html_latest),
        }

    def _generate_markdown(self, payload: Dict[str, Any]) -> str:
        s = payload["summary"]
        records = payload["records"]
        lines = [
            "# PHISHGUARD Automated Validation Campaign Report",
            "",
            f"**Generated:** {payload['metadata']['generated_at']}  ",
            f"**Total Validation Tests:** {s['total']} | **PASS:** {s['pass']} | **FAIL:** {s['fail']} | **BLOCKED:** {s['blocked']} | **MANUAL:** {s['manual']}  ",
            f"**Pass Rate:** {s['pass_rate']}%",
            "",
            "---",
            "",
            "## Category Summary",
            "",
            "| Category | Total | PASS | FAIL | BLOCKED | MANUAL | Pass Rate |",
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
        ]
        for cat, stats in sorted(s["categories"].items()):
            rate = round(stats["pass"] / stats["total"] * 100, 1) if stats["total"] > 0 else 0
            lines.append(f"| {cat} | {stats['total']} | {stats['pass']} | {stats['fail']} | {stats['blocked']} | {stats['manual']} | {rate}% |")

        lines.extend([
            "",
            "---",
            "",
            "## Detailed Validation Results",
            "",
            "| Test ID | Category | Status | Description | Expected | Actual | Risk Score / Level |",
            "| :--- | :--- | :---: | :--- | :--- | :--- | :---: |",
        ])
        for r in records:
            score_str = f"{r.get('risk_score') or '—'} ({r.get('risk_level') or '—'})"
            lines.append(f"| `{r['test_id']}` | {r['category']} | **{r['status']}** | {r['description']} | {r['expected_behavior']} | {r['actual_behavior']} | {score_str} |")

        # Section for Failures
        failed_records = [r for r in records if r["status"] == "FAIL"]
        if failed_records:
            lines.extend([
                "",
                "---",
                "",
                "## Failures & Diagnostic Telemetry",
                "",
            ])
            for fr in failed_records:
                lines.extend([
                    f"### `{fr['test_id']}` — {fr['description']}",
                    f"- **Category:** {fr['category']}",
                    f"- **Expected:** {fr['expected_behavior']}",
                    f"- **Actual:** {fr['actual_behavior']}",
                    f"- **Risk:** {fr.get('risk_score')} ({fr.get('risk_level')})",
                    f"- **Evidence:** score={fr.get('evidence_score')}, level={fr.get('evidence_level')}, classes={fr.get('evidence_classes')}",
                    f"- **Error / Exception:** `{fr.get('error')}`",
                    f"- **Notes:** {fr.get('notes')}",
                    "",
                ])

        # Manual / Blocked Sections
        blocked_records = [r for r in records if r["status"] == "BLOCKED"]
        if blocked_records:
            lines.extend(["", "## Blocked Tests", ""])
            for br in blocked_records:
                lines.append(f"- **`{br['test_id']}`**: {br['description']} — *Reason:* {br.get('notes') or 'Dependency unavailable'}")

        manual_records = [r for r in records if r["status"] == "MANUAL"]
        if manual_records:
            lines.extend(["", "## Manual Validation Required (Next Phase)", ""])
            for mr in manual_records:
                lines.append(f"- **`{mr['test_id']}`**: {mr['description']} — *Reason:* {mr.get('notes') or 'Requires human/external interaction'}")

        return "\n".join(lines)

    def _generate_html(self, payload: Dict[str, Any]) -> str:
        s = payload["summary"]
        records = payload["records"]
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>PHISHGUARD Automated Validation Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; padding: 32px; margin: 0; }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    h1, h2, h3 {{ color: #ffffff; }}
    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 9999px; font-size: 11px; font-weight: bold; text-transform: uppercase; }}
    .pass {{ background: #065f46; color: #6ee7b7; }}
    .fail {{ background: #991b1b; color: #fca5a5; }}
    .blocked {{ background: #92400e; color: #fde68a; }}
    .manual {{ background: #3730a3; color: #c7d2fe; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 16px; background: #1e293b; border-radius: 8px; overflow: hidden; font-size: 13px; }}
    th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #334155; }}
    th {{ background: #0f172a; font-size: 11px; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.05em; }}
    tr:hover {{ background: #334155; }}
    .stat-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 18px; margin-bottom: 24px; display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; }}
    .stat-item {{ text-align: center; }}
    .stat-val {{ font-size: 28px; font-weight: bold; color: #38bdf8; }}
    .stat-label {{ font-size: 12px; color: #94a3b8; text-transform: uppercase; margin-top: 4px; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>PHISHGUARD Automated Validation Campaign</h1>
    <p style="color: #94a3b8;">Generated: {payload['metadata']['generated_at']}</p>
    
    <div class="stat-card">
      <div class="stat-item"><div class="stat-val">{s['total']}</div><div class="stat-label">Total Tests</div></div>
      <div class="stat-item"><div class="stat-val" style="color: #4ade80;">{s['pass']}</div><div class="stat-label">Passed</div></div>
      <div class="stat-item"><div class="stat-val" style="color: #f87171;">{s['fail']}</div><div class="stat-label">Failed</div></div>
      <div class="stat-item"><div class="stat-val" style="color: #fbbf24;">{s['blocked']}</div><div class="stat-label">Blocked</div></div>
      <div class="stat-item"><div class="stat-val" style="color: #818cf8;">{s['manual']}</div><div class="stat-label">Manual</div></div>
      <div class="stat-item"><div class="stat-val">{s['pass_rate']}%</div><div class="stat-label">Pass Rate</div></div>
    </div>

    <h2>Category Summary</h2>
    <table>
      <thead><tr><th>Category</th><th>Total</th><th>PASS</th><th>FAIL</th><th>BLOCKED</th><th>MANUAL</th><th>Pass Rate</th></tr></thead>
      <tbody>
        {"".join(f"<tr><td><strong>{cat}</strong></td><td>{st['total']}</td><td><span class='badge pass'>{st['pass']}</span></td><td><span class='badge fail'>{st['fail']}</span></td><td><span class='badge blocked'>{st['blocked']}</span></td><td><span class='badge manual'>{st['manual']}</span></td><td>{round(st['pass']/st['total']*100, 1) if st['total'] > 0 else 0}%</td></tr>" for cat, st in sorted(s['categories'].items()))}
      </tbody>
    </table>

    <h2>Test Cases</h2>
    <table>
      <thead><tr><th>Test ID</th><th>Category</th><th>Status</th><th>Description</th><th>Expected</th><th>Actual</th><th>Score / Level</th></tr></thead>
      <tbody>
        {"".join(f"<tr><td><code>{r['test_id']}</code></td><td>{r['category']}</td><td><span class='badge {r['status'].lower()}'>{r['status']}</span></td><td>{r['description']}</td><td>{r['expected_behavior']}</td><td>{r['actual_behavior']}</td><td>{r.get('risk_score') or '—'} ({r.get('risk_level') or '—'})</td></tr>" for r in records)}
      </tbody>
    </table>
  </div>
</body>
</html>
"""


# Global module helper
collector = ValidationCollector.get_instance()
validation_collector = collector

def record_test(
    test_id: str,
    category: str,
    description: str,
    input_type: str,
    expected_behavior: str,
    actual_behavior: str,
    status: str,
    **kwargs: Any,
) -> ValidationRecord:
    """Helper function to record a validation test outcome."""
    return collector.record(
        test_id=test_id,
        category=category,
        description=description,
        input_type=input_type,
        expected_behavior=expected_behavior,
        actual_behavior=actual_behavior,
        status=status,
        **kwargs,
    )
