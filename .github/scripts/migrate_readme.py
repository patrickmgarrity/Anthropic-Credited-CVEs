#!/usr/bin/env python3
"""
One-shot migration: parse README.md's CVE table into cves.yaml.

Run this ONCE to seed cves.yaml from the existing tracked entries:

    python .github/scripts/migrate_readme.py README.md cves.yaml

After migration, cves.yaml becomes the source of truth and README.md is
regenerated from it by render_readme.py.

Handles the quirks of the existing README:
  - CVE column may be plain text or a markdown link: [CVE-...](url)
  - Date may be 'Reserved' (no date)
  - CVSS may be missing
  - Trailing notes like 'NOT IN CVE TABLE' get pulled into the notes field
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML not installed. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(2)


# Matches a CVE ID, optionally wrapped in a markdown link
CVE_LINK_RE = re.compile(
    r"^\s*(?:\[(?P<id_linked>CVE-\d{4}-\d+)\]\((?P<url>[^)]+)\)|(?P<id_plain>CVE-\d{4}-\d+))\s*$"
)
NOT_IN_TABLE_RE = re.compile(r"\s*NOT IN CVE TABLE\s*", re.IGNORECASE)


def parse_cve_cell(cell: str) -> tuple[str, str | None]:
    """Return (cve_id, optional_url). Raises ValueError if not parseable."""
    m = CVE_LINK_RE.match(cell.strip())
    if not m:
        raise ValueError(f"Could not parse CVE cell: {cell!r}")
    return (m.group("id_linked") or m.group("id_plain"), m.group("url"))


def parse_date(cell: str) -> tuple[str | None, str]:
    """Return (iso_date_or_None, status). 'Reserved' -> (None, 'reserved')."""
    s = cell.strip()
    if s.lower() == "reserved":
        return (None, "reserved")
    # Some dates in the existing README are typos like '2016-05-26' instead of '2026-05-26'
    # -- preserve them as-is; user can fix.
    return (s, "published")


def parse_cvss(cell: str) -> float | None:
    s = cell.strip()
    if not s:
        return None
    try:
        return float(s)
    except ValueError:
        return None


def parse_credit(cell: str) -> tuple[str, str | None]:
    """Return (credit_text, notes). Strips 'NOT IN CVE TABLE' into notes."""
    s = cell.strip()
    notes = None
    m = NOT_IN_TABLE_RE.search(s)
    if m:
        notes = "NOT IN CVE TABLE"
        s = NOT_IN_TABLE_RE.sub("", s).strip()
    return (s, notes)


def split_row(line: str) -> list[str]:
    """Split a markdown table row into cells."""
    # Strip leading/trailing pipes, split on pipe
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    return [c.strip() for c in line.split("|")]


def is_data_row(line: str) -> bool:
    """Heuristic: a data row contains a CVE ID."""
    return "CVE-" in line and line.lstrip().startswith("|")


def parse_readme(readme_text: str) -> list[dict]:
    entries: list[dict] = []
    skipped: list[tuple[int, str, str]] = []

    for lineno, raw in enumerate(readme_text.splitlines(), 1):
        if not is_data_row(raw):
            continue
        cells = split_row(raw)
        # Expected: CVE | Date | Vendor | Product | CVSS | Credit  -> 6 cells
        if len(cells) < 6:
            skipped.append((lineno, "too few cells", raw))
            continue
        cve_cell, date_cell, vendor_cell, product_cell, cvss_cell, credit_cell = cells[:6]
        # If a credit has stray pipes, rejoin extra cells back into credit
        if len(cells) > 6:
            credit_cell = " | ".join(cells[5:])
        try:
            cve_id, cve_link = parse_cve_cell(cve_cell)
        except ValueError as e:
            skipped.append((lineno, str(e), raw))
            continue

        date, status = parse_date(date_cell)
        cvss = parse_cvss(cvss_cell)
        credit, notes = parse_credit(credit_cell)

        entry = {
            "cve": cve_id,
            "date": date,
            "vendor": vendor_cell.strip(),
            "product": product_cell.strip(),
            "cvss": cvss,
            "credit": credit,
            "status": status,
            "cve_link": cve_link,
            "notes": notes,
            "auto_discovered": False,
        }
        entries.append(entry)

    if skipped:
        print(f"Skipped {len(skipped)} row(s):", file=sys.stderr)
        for lineno, reason, raw in skipped:
            print(f"  line {lineno}: {reason}\n    {raw}", file=sys.stderr)

    return entries


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} README.md cves.yaml", file=sys.stderr)
        return 2

    readme_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    entries = parse_readme(readme_path.read_text(encoding="utf-8"))
    print(f"Parsed {len(entries)} entries from {readme_path}")

    # Sort by CVE ID descending so newest first
    def sort_key(e: dict) -> tuple[int, int]:
        m = re.match(r"CVE-(\d+)-(\d+)", e["cve"])
        if not m:
            return (0, 0)
        return (int(m.group(1)), int(m.group(2)))

    entries.sort(key=sort_key, reverse=True)

    # Write YAML. Use a clean style: block format, keep key order, no anchors.
    class _Dumper(yaml.SafeDumper):
        pass

    def _str_repr(dumper, data):
        if "\n" in data or len(data) > 80:
            return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=">")
        return dumper.represent_scalar("tag:yaml.org,2002:str", data)

    _Dumper.add_representer(str, _str_repr)

    out_path.write_text(
        yaml.dump(entries, Dumper=_Dumper, sort_keys=False, allow_unicode=True, width=100),
        encoding="utf-8",
    )
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
