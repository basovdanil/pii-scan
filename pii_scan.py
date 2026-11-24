#!/usr/bin/env python3
"""Scan a CSV export for personal data before it leaves the company.

Finds e-mail addresses, phone numbers, Russian passport series/number pairs and
SNILS, reports them per column with masked examples, and returns a non-zero code
so it can gate a pipeline.

Usage:
  python pii_scan.py export.csv
  python pii_scan.py export.csv --json

Exit codes: 0 — nothing found; 2 — bad arguments; 3 — file cannot be read;
4 — personal data found.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE = re.compile(r"(?<!\d)(?:\+7|8)[\s\-()]*\d{3}[\s\-()]*\d{3}[\s\-]*\d{2}[\s\-]*\d{2}(?!\d)")
PASSPORT = re.compile(r"(?<!\d)\d{4}\s?\d{6}(?!\d)")
SNILS = re.compile(r"(?<!\d)\d{3}-\d{3}-\d{3}[ ]?\d{2}(?!\d)")

RULES = (
    ("email", EMAIL, "e-mail address"),
    ("phone", PHONE, "phone number"),
    ("passport", PASSPORT, "passport series and number"),
    ("snils", SNILS, "SNILS"),
)


def mask(value: str, kind: str) -> str:
    """Return a masked example so the report itself carries no personal data."""
    if kind == "email":
        local, _, domain = value.partition("@")
        return f"{local[:1]}***@{domain}"
    digits = re.sub(r"\D", "", value)
    if len(digits) <= 2:
        return "***"
    return f"***{digits[-2:]}"


def scan(path: Path, delimiter: str = ",", encoding: str = "utf-8-sig") -> dict:
    with path.open(encoding=encoding, newline="") as handle:
        reader = csv.DictReader(handle, delimiter=delimiter)
        if not reader.fieldnames:
            raise ValueError("no header row")
        columns = {name: {"count": 0, "kinds": {}, "examples": []} for name in reader.fieldnames}
        rows = 0
        for row in reader:
            rows += 1
            for column, value in row.items():
                if not value or column not in columns:
                    continue
                for kind, pattern, _label in RULES:
                    for match in pattern.finditer(value):
                        entry = columns[column]
                        entry["count"] += 1
                        entry["kinds"][kind] = entry["kinds"].get(kind, 0) + 1
                        if len(entry["examples"]) < 3:
                            entry["examples"].append(mask(match.group(0), kind))
    findings = {name: data for name, data in columns.items() if data["count"]}
    totals: dict[str, int] = {}
    for data in findings.values():
        for kind, count in data["kinds"].items():
            totals[kind] = totals.get(kind, 0) + count
    return {"file": str(path), "rows": rows, "columns": list(columns),
            "findings": findings, "totals": totals}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan a CSV export for personal data.")
    parser.add_argument("file", help="CSV file to scan")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--delimiter", default=",", help="field delimiter, default ','")
    args = parser.parse_args(argv)

    path = Path(args.file)
    if not path.exists():
        print(f"error: no such file: {path}", file=sys.stderr)
        return 3
    try:
        report = scan(path, delimiter=args.delimiter)
    except (UnicodeDecodeError, ValueError, csv.Error) as exc:
        print(f"error: cannot read {path}: {exc}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=1))
    else:
        total = sum(col["count"] for col in report["findings"].values())
        print(f"{report['file']}: {report['rows']} rows, {len(report['findings'])} columns with findings, {total} matches")
        for name, data in report["findings"].items():
            kinds = ", ".join(f"{kind}={count}" for kind, count in sorted(data["kinds"].items()))
            print(f"  {name}: {data['count']} ({kinds}); examples: {', '.join(data['examples'])}")
        if not report["findings"]:
            print("  nothing found")

    return 4 if report["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
