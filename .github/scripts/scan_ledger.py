#!/usr/bin/env python3
"""
Sync CVEs from Anthropic's public disclosure ledger into cves/.

Source of truth for this scanner:
    https://red.anthropic.com/2026/cvd/data/ledger.json

The ledger is Anthropic's own authoritative record of vulnerabilities their
research team disclosed. Every *revealed* row exposes an `ant_id` and the
CVE/GHSA identifiers assigned to that finding, and each revealed finding has a
public page at:

    https://red.anthropic.com/2026/cvd/findings/<ant_id>

Because the ledger is authoritative (no keyword false positives, unlike
scan_cves.py / scan_ghsas.py, which is why *those* gate on human-reviewed PRs),
this scanner writes directly to cves/ and lets the workflow commit to main.
For every revealed CVE on the ledger it ensures:

  1. a record exists at cves/<CVE>.yaml (creating it, enriched from MITRE when
     the CVE is published, otherwise stubbed from ledger data), and
  2. the record carries the current `ledger_link` pointing at the finding page.

The pass is declarative and idempotent: re-running rewrites byte-identical files
for anything already in sync (no git churn), so no state file is needed. It also
naturally handles CVEs added to a finding later — they simply appear as new
records on the next run. Manual edits to other fields are preserved; only
`ledger_link` is (re)written on an otherwise-existing record.

This script performs NO git or PR operations. The caller (a workflow step, or a
human running it locally for a one-time backfill) commits the resulting changes.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

# Reuse helpers from the sibling scanners (same dir).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scan_cves import (  # noqa: E402
    CVES_DIR,
    cve_file_path,
    extract_summary,
    http_get_json,
    write_cve_entry,
)
from recheck_reserved import fetch_record  # noqa: E402  (MITRE cveawg lookup)

LEDGER_JSON_URL = "https://red.anthropic.com/2026/cvd/data/ledger.json"
FINDINGS_URL_TMPL = "https://red.anthropic.com/2026/cvd/findings/{ant_id}"
MITRE_SLEEP_SECONDS = 0.3  # be polite to cveawg between record fetches

# Canonical field order for a written entry. Keeps auto-created and
# link-patched files consistent with the rest of cves/.
FIELD_ORDER = (
    "cve", "ghsa", "date", "vendor", "product", "cvss", "credit",
    "status", "cve_link", "ghsa_link", "ledger_link", "notes",
    "auto_discovered",
)


def normalize(entry: dict) -> dict:
    """Return the entry with keys in FIELD_ORDER; any extra keys keep their
    relative order at the end so nothing is ever dropped."""
    ordered = {k: entry[k] for k in FIELD_ORDER if k in entry}
    for k, v in entry.items():
        if k not in ordered:
            ordered[k] = v
    return ordered


def ledger_link_for(ant_id: str) -> str:
    return FINDINGS_URL_TMPL.format(ant_id=ant_id)


def revealed_cve_map(ledger: list[dict]) -> dict[str, str]:
    """Map every current CVE id on a *revealed* ledger row to its ant_id.

    Uses `cve_ids` only (the identifiers currently assigned to the finding);
    `corrected_cve_ids` are intentionally ignored — the ledger keeps those
    struck through as "published in error", so we must not track them.
    A finding can carry several CVEs; each maps to that finding's ant_id.
    """
    out: dict[str, str] = {}
    for row in ledger:
        if row.get("reveal_tier") != "revealed":
            continue
        ant_id = row.get("ant_id")
        if not ant_id:
            continue
        for cve in (row.get("cve_ids") or []):
            out.setdefault(cve, ant_id)
    return out


def _split_project(project: str) -> tuple[str, str]:
    """Best-effort vendor/product from a ledger project like "libexpat/libexpat"
    or a bare "htslib". Used only for CVEs MITRE hasn't published yet."""
    project = (project or "").strip()
    if "/" in project:
        org, _, repo = project.partition("/")
        return org, repo
    return "", project


def stub_from_ledger(cve_id: str, row: dict) -> dict:
    """Build a minimal entry from ledger data alone, for a CVE that MITRE has
    not published yet (cveawg 404). CVSS is left null; backfill_cvss.py fills it
    once a score is available."""
    vendor, product = _split_project(row.get("project", ""))
    return {
        "cve": cve_id,
        "ghsa": None,
        "date": row.get("discovered_on") or row.get("committed_at"),
        "vendor": vendor,
        "product": product,
        "cvss": None,
        "credit": "Anthropic",
        "status": "reserved",
        "cve_link": f"https://www.cve.org/CVERecord?id={cve_id}",
        "ghsa_link": None,
        "notes": None,
        "auto_discovered": True,
    }


def build_new_entry(cve_id: str, ant_id: str, row: dict) -> dict:
    """Create a full record for a CVE new to the repo. Enrich from MITRE when
    the CVE is published; otherwise fall back to a ledger-only stub."""
    record = None
    try:
        record = fetch_record(cve_id)  # None on 404 (still reserved)
    except RuntimeError as exc:
        print(f"  {cve_id}: MITRE fetch failed ({exc}); using ledger stub",
              file=sys.stderr)
    if record is not None:
        s = extract_summary(record)
        entry = {k: s[k] for k in (
            "cve", "ghsa", "date", "vendor", "product", "cvss", "credit",
            "status", "cve_link", "ghsa_link", "notes", "auto_discovered")}
        # The CVE record's own metadata sometimes omits credits entirely. The
        # ledger is authoritative that this was an Anthropic disclosure, so fall
        # back to a minimal attribution rather than leaving the column blank.
        if not (entry.get("credit") or "").strip():
            entry["credit"] = "Anthropic"
    else:
        entry = stub_from_ledger(cve_id, row)
    entry["ledger_link"] = ledger_link_for(ant_id)
    return normalize(entry)


def load_entry(path: Path):
    import yaml
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    return doc if isinstance(doc, dict) else None


def main() -> int:
    print(f"Fetching ledger: {LEDGER_JSON_URL}")
    ledger = http_get_json(LEDGER_JSON_URL)
    if not isinstance(ledger, list):
        print("ledger.json is not a list; aborting", file=sys.stderr)
        return 1

    cve_map = revealed_cve_map(ledger)
    print(f"  {len(cve_map)} revealed CVE(s) with a finding on the ledger")

    added = 0
    linked = 0
    unchanged = 0

    for cve_id, ant_id in sorted(cve_map.items()):
        link = ledger_link_for(ant_id)
        path = cve_file_path(cve_id)

        if not path.exists():
            row = next((r for r in ledger if r.get("ant_id") == ant_id), {})
            entry = build_new_entry(cve_id, ant_id, row)
            write_cve_entry(entry)
            added += 1
            print(f"  + added {cve_id} (status={entry['status']}) -> {ant_id}")
            time.sleep(MITRE_SLEEP_SECONDS)
            continue

        entry = load_entry(path)
        if entry is None:
            print(f"  ! {cve_id}: unreadable YAML, skipping", file=sys.stderr)
            continue
        if entry.get("ledger_link") == link:
            unchanged += 1
            continue
        entry["ledger_link"] = link
        write_cve_entry(normalize(entry))
        linked += 1
        print(f"  ~ linked {cve_id} -> {ant_id}")

    print(f"Done. {added} added, {linked} link(s) attached, "
          f"{unchanged} already in sync.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
