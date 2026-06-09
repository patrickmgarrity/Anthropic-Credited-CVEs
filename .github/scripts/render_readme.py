#!/usr/bin/env python3
"""
Generate README.md from cves.yaml.

Reads:  cves.yaml
Reads:  .github/templates/README.template.md (preamble/postamble)
Writes: README.md

The template file contains everything in the README *except* the CVE table.
It must contain the marker line:

    <!-- BEGIN_CVE_TABLE -->
    <!-- END_CVE_TABLE -->

The renderer replaces everything between those markers with the freshly
generated table.

If no template exists, a default one is used (preserves the look of the
current README).
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


DEFAULT_TEMPLATE = """\
# ANTHROPIC CVE TRACKER

## Overview
Tracking vulnerabilities that credit the Anthropic research team and are possibly discovered by [Project Glasswing](https://www.anthropic.com/glasswing).

**CURRENT CVE COUNT: {count}**

## Initial Research
[Tracking CVEs Attributed to Anthropic Researchers and Project Glasswing](https://www.vulncheck.com/blog/anthropic-glasswing-cves)

## Add a Vulnerability
If you find an Anthropic credited vulnerability, please open a Pull Request or Send me a message on linkedin or in the [Extended Vulnerability Community Discord](https://discord.gg/yTRXwepK).

## Considerations

This project is maintained on a best effort basis.

## The List

<!-- BEGIN_CVE_TABLE -->
<!-- END_CVE_TABLE -->
"""

MARKER_BEGIN = "<!-- BEGIN_CVE_TABLE -->"
MARKER_END = "<!-- END_CVE_TABLE -->"


def render_cve_cell(entry: dict) -> str:
    """Render the ID column.

    Prefer the CVE ID when present; otherwise fall back to the GHSA ID. The
    cell is linked when a corresponding *_link is set.
    """
    cve = entry.get("cve")
    if cve:
        link = entry.get("cve_link")
        return f"[{cve}]({link})" if link else cve
    ghsa = entry.get("ghsa")
    if ghsa:
        link = entry.get("ghsa_link") or f"https://github.com/advisories/{ghsa}"
        return f"[{ghsa}]({link})"
    return "—"


def render_date_cell(entry: dict) -> str:
    if entry.get("status") == "reserved" or not entry.get("date"):
        return "Reserved"
    return str(entry["date"])


def render_cvss_cell(entry: dict) -> str:
    v = entry.get("cvss")
    if v is None:
        return ""
    # Always show one decimal place (CVSS convention): 9.8, 8.0, 4.0
    return f"{v:.1f}"


def render_credit_cell(entry: dict) -> str:
    credit = (entry.get("credit") or "").strip()
    note = (entry.get("notes") or "").strip()
    if note:
        return f"{credit} {note}".strip()
    return credit


def sort_key(entry: dict):
    """Newest first by date, then by CVE number (or GHSA ID when no CVE).
    Reserved entries float to the top of their CVE-number bucket."""
    date = entry.get("date") or ""
    ident = entry.get("cve") or entry.get("ghsa") or ""
    m = re.match(r"CVE-(\d+)-(\d+)", ident)
    cve_year = int(m.group(1)) if m else 0
    cve_seq = int(m.group(2)) if m else 0
    # Sort by (date desc, year desc, seq desc)
    return (date, cve_year, cve_seq)


def dedupe_entries(entries: list[dict]) -> list[dict]:
    """Collapse entries that share a CVE/GHSA identifier, keeping the most
    complete record (most non-empty fields; `published` wins ties). Since
    cves.yaml is union-merged (see .gitattributes), a parallel merge could in
    theory leave two rows for the same CVE; this keeps the table and count
    correct. First-seen order is otherwise preserved."""
    def completeness(e: dict) -> tuple[int, int]:
        nonnull = sum(1 for v in e.values() if v not in (None, "", "null"))
        return (nonnull, 1 if e.get("status") == "published" else 0)

    best: dict[str, dict] = {}
    order: list[str] = []
    for e in entries:
        ident = e.get("cve") or e.get("ghsa")
        if not ident:
            ident = id(e)  # keep identifier-less rows as-is
        if ident not in best:
            best[ident] = e
            order.append(ident)
        elif completeness(e) > completeness(best[ident]):
            best[ident] = e
    return [best[i] for i in order]


def render_table(entries: list[dict]) -> str:
    header = "| CVE | Date | Vendor | Product | CVSS | Credit |\n"
    header += "| --- | --- | --- | --- | --- | --- |\n"
    rows = []
    for e in sorted(entries, key=sort_key, reverse=True):
        cells = [
            render_cve_cell(e),
            render_date_cell(e),
            (e.get("vendor") or "").strip(),
            (e.get("product") or "").strip(),
            render_cvss_cell(e),
            render_credit_cell(e),
        ]
        rows.append("| " + " | ".join(cells) + " |")
    return header + "\n".join(rows) + "\n"


def render_readme(template: str, entries: list[dict]) -> str:
    count = len(entries)
    table = render_table(entries)
    body_block = f"{MARKER_BEGIN}\n{table}{MARKER_END}"
    template = template.replace("{count}", str(count))

    if MARKER_BEGIN in template and MARKER_END in template:
        pattern = re.compile(
            re.escape(MARKER_BEGIN) + r".*?" + re.escape(MARKER_END),
            re.DOTALL,
        )
        return pattern.sub(body_block, template)

    # No markers in template -> append
    return template.rstrip() + "\n\n" + body_block + "\n"


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    cves_path = repo_root / "cves.yaml"
    readme_path = repo_root / "README.md"
    template_path = repo_root / ".github" / "templates" / "README.template.md"

    if not cves_path.exists():
        print(f"missing {cves_path}", file=sys.stderr)
        return 1

    entries = yaml.safe_load(cves_path.read_text(encoding="utf-8")) or []
    entries = dedupe_entries(entries)

    if template_path.exists():
        template = template_path.read_text(encoding="utf-8")
    else:
        template = DEFAULT_TEMPLATE

    rendered = render_readme(template, entries)
    readme_path.write_text(rendered, encoding="utf-8")
    print(f"Rendered {readme_path} from {len(entries)} entries.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
