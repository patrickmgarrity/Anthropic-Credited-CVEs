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

A second pass does the same for GHSA ids on revealed findings (`ghsa_ids`):

  - a GHSA on a finding that also has a CVE is attached to that CVE's record
    (`ghsa`, plus `ghsa_link` when the advisory is public);
  - a GHSA-only finding gets its own GHSA-keyed record (cves/GHSA-....yaml),
    unless GitHub's advisory database already maps it to a CVE, in which case
    it is filed under that CVE instead. Many of these GHSAs are private
    repository advisories (404 on GitHub), so `ghsa_link` is left empty and
    the README links the ID to the ledger finding page instead;
  - when the ledger later assigns a CVE to a GHSA-only finding, the GHSA-keyed
    record is renamed to the CVE rather than duplicated.

Withdrawn and merged findings are skipped by the GHSA pass.

The pass is declarative and idempotent: re-running rewrites byte-identical files
for anything already in sync (no git churn), so no state file is needed. It also
naturally handles CVEs added to a finding later — they simply appear as new
records on the next run. Manual edits to other fields are preserved; only
`ledger_link` is (re)written on an otherwise-existing record.

This script performs NO git or PR operations. The caller (a workflow step, or a
human running it locally for a one-time backfill) commits the resulting changes.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# Reuse helpers from the sibling scanners (same dir).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scan_cves import (  # noqa: E402
    CVES_DIR,
    USER_AGENT,
    cve_file_path,
    extract_summary,
    http_get_json,
    write_cve_entry,
)
from recheck_reserved import fetch_record  # noqa: E402  (MITRE cveawg lookup)

LEDGER_JSON_URL = "https://red.anthropic.com/2026/cvd/data/ledger.json"
STATS_PATH = Path("state/ledger_stats.json")
FINDINGS_URL_TMPL = "https://red.anthropic.com/2026/cvd/findings/{ant_id}"
MITRE_SLEEP_SECONDS = 0.3  # be polite to cveawg between record fetches
GHSA_API_URL = "https://api.github.com/advisories/{ghsa_id}"
GHSA_PUBLIC_URL = "https://github.com/advisories/{ghsa_id}"
SKIP_GHSA_STATUSES = {"withdrawn", "merged"}

# Canonical field order for a written entry. Keeps auto-created and
# link-patched files consistent with the rest of cves/.
FIELD_ORDER = (
    "cve", "ghsa", "date", "vendor", "product", "cvss", "credit",
    "status", "cve_link", "ghsa_link", "ledger_link",
    "vulncheck_kev", "kev_date_added", "notes",
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


def fetch_global_advisory(ghsa_id: str, retries: int = 3) -> dict | None:
    """GitHub global advisory for `ghsa_id`, or None if it isn't in the global
    database (private/unpublished repository advisories return 404)."""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    last_err: Exception | None = None
    for attempt in range(retries):
        try:
            req = Request(GHSA_API_URL.format(ghsa_id=ghsa_id), headers=headers)
            with urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except HTTPError as e:
            if e.code == 404:
                return None
            last_err = e
        except (URLError, TimeoutError, json.JSONDecodeError) as e:
            last_err = e
        time.sleep(2 ** attempt)
    raise RuntimeError(f"Failed to fetch {ghsa_id}: {last_err}")


def load_all_entries() -> dict[Path, dict]:
    out: dict[Path, dict] = {}
    for path in sorted(CVES_DIR.glob("*.yaml")):
        entry = load_entry(path)
        if entry is not None:
            out[path] = entry
    return out


def upgrade_ghsa_entry(cve_id: str, row: dict) -> bool:
    """If one of the finding's GHSAs already has a GHSA-keyed record, move it
    under `cve_id` (set cve/cve_link, rename the file) instead of creating a
    duplicate CVE record. Returns True if an upgrade happened."""
    for ghsa_id in row.get("ghsa_ids") or []:
        old_path = cve_file_path(ghsa_id)
        if not old_path.exists():
            continue
        entry = load_entry(old_path)
        if entry is None:
            continue
        entry["cve"] = cve_id
        entry["cve_link"] = f"https://www.cve.org/CVERecord?id={cve_id}"
        write_cve_entry(normalize(entry))
        old_path.unlink()
        print(f"  ^ upgraded {ghsa_id} -> {cve_id}")
        return True
    return False


def ghsa_only_entry(ghsa_id: str, ant_id: str, row: dict,
                    advisory: dict | None) -> dict:
    """GHSA-keyed record for a finding with no CVE. Uses the public advisory's
    data when GitHub has it; otherwise ledger data alone."""
    vendor, product = _split_project(row.get("project", ""))
    cvss = None
    date = row.get("revealed_at") or row.get("patched_at") or row.get("committed_at")
    if advisory:
        score = (advisory.get("cvss") or {}).get("score")
        cvss = float(score) if score else None
        date = (advisory.get("published_at") or "")[:10] or date
    return normalize({
        "cve": None,
        "ghsa": ghsa_id,
        "date": date or None,
        "vendor": vendor,
        "product": product,
        "cvss": cvss,
        "credit": "Anthropic",
        "status": "published",
        "cve_link": None,
        "ghsa_link": GHSA_PUBLIC_URL.format(ghsa_id=ghsa_id) if advisory else None,
        "ledger_link": ledger_link_for(ant_id),
        "notes": None,
        "auto_discovered": True,
    })


def sync_ghsas(ledger: list[dict]) -> tuple[int, int]:
    """GHSA pass (see module docstring). Returns (added, attached)."""
    entries = load_all_entries()
    by_ghsa = {e.get("ghsa"): p for p, e in entries.items() if e.get("ghsa")}
    added = attached = 0

    class _LookupFailed(Exception):
        pass

    def lookup(ghsa_id: str) -> dict | None:
        try:
            return fetch_global_advisory(ghsa_id)
        except RuntimeError as exc:
            # Rate limit / network blip: skip this GHSA for this run rather than
            # aborting the whole sync (which would also skip the commit step).
            print(f"  ! {ghsa_id}: lookup failed ({exc}); will retry next run",
                  file=sys.stderr)
            raise _LookupFailed from exc

    def attach(cve_id: str, ghsa_id: str, advisory: dict | None) -> bool:
        path = cve_file_path(cve_id)
        entry = load_entry(path) if path.exists() else None
        if entry is None or entry.get("ghsa"):
            return False  # missing, or already carries a (possibly other) GHSA
        entry["ghsa"] = ghsa_id
        if advisory is not None and not entry.get("ghsa_link"):
            entry["ghsa_link"] = GHSA_PUBLIC_URL.format(ghsa_id=ghsa_id)
        write_cve_entry(normalize(entry))
        by_ghsa[ghsa_id] = path
        print(f"  ~ attached {ghsa_id} to {cve_id}")
        return True

    for row in ledger:
        if row.get("reveal_tier") != "revealed" or not row.get("ant_id"):
            continue
        if row.get("status") in SKIP_GHSA_STATUSES or row.get("withdrawn"):
            continue
        ant_id = row["ant_id"]
        row_cves = row.get("cve_ids") or []
        for ghsa_id in row.get("ghsa_ids") or []:
            if ghsa_id in by_ghsa:
                continue  # already tracked somewhere

            if len(row_cves) == 1:
                # Unambiguous: the finding's only CVE. Check the record first so
                # GHSAs that can't be attached (CVE record missing, or it already
                # carries another GHSA) don't cost an API call every run; the
                # lookup only decides whether ghsa_link is public.
                target = cve_file_path(row_cves[0])
                current = load_entry(target) if target.exists() else None
                if current is None or current.get("ghsa"):
                    continue
                try:
                    attached += attach(row_cves[0], ghsa_id, lookup(ghsa_id))
                except _LookupFailed:
                    pass
                continue

            try:
                advisory = lookup(ghsa_id)
            except _LookupFailed:
                continue
            adv_cve = (advisory or {}).get("cve_id")
            if row_cves:
                # Several CVEs: only attach when GitHub says which one.
                if adv_cve in row_cves:
                    attached += attach(adv_cve, ghsa_id, advisory)
                continue

            # GHSA-only finding.
            if adv_cve:
                if not cve_file_path(adv_cve).exists():
                    entry = build_new_entry(adv_cve, ant_id, row)
                    write_cve_entry(entry)
                    added += 1
                    print(f"  + added {adv_cve} (via {ghsa_id}) -> {ant_id}")
                attached += attach(adv_cve, ghsa_id, advisory)
                continue
            entry = ghsa_only_entry(ghsa_id, ant_id, row, advisory)
            path = write_cve_entry(entry)
            by_ghsa[ghsa_id] = path
            added += 1
            note = "" if advisory else " (private advisory)"
            print(f"  + added {ghsa_id}{note} -> {ant_id}")
    return added, attached


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

    # Stats for the README header:
    #  - fixed findings the ledger marks "fixed" that carry no CVE ("fixed" only
    #    appears on revealed rows, so it's a verifiable count), and
    #  - findings Anthropic has withdrawn (the explicit `withdrawn` flag).
    fixed_no_cve = sum(1 for r in ledger
                       if r.get("status") == "fixed" and not r.get("cve_ids"))
    withdrawn = sum(1 for r in ledger if r.get("withdrawn") is True)
    # Revealed findings with neither a CVE nor a GHSA (README "Advisories w/o
    # GHSA/CVE"); withdrawn and merged findings are excluded.
    no_id = sum(1 for r in ledger
                if r.get("reveal_tier") == "revealed" and r.get("ant_id")
                and r.get("status") not in SKIP_GHSA_STATUSES
                and not r.get("withdrawn")
                and not r.get("cve_ids") and not r.get("ghsa_ids"))
    STATS_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATS_PATH.write_text(json.dumps({
        "fixed_findings_without_cve": fixed_no_cve,
        "findings_withdrawn": withdrawn,
        "findings_without_cve_or_ghsa": no_id,
    }, indent=2) + "\n")
    print(f"  {no_id} revealed finding(s) without a CVE or GHSA, "
          f"{fixed_no_cve} fixed finding(s) without a CVE, "
          f"{withdrawn} withdrawn (wrote {STATS_PATH})")

    added = 0
    linked = 0
    unchanged = 0

    for cve_id, ant_id in sorted(cve_map.items()):
        link = ledger_link_for(ant_id)
        path = cve_file_path(cve_id)

        if not path.exists():
            row = next((r for r in ledger if r.get("ant_id") == ant_id), {})
            if upgrade_ghsa_entry(cve_id, row):
                # fall through to the link check below on the renamed file
                pass
            else:
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

    print("GHSA pass:")
    g_added, g_attached = sync_ghsas(ledger)

    print(f"Done. CVEs: {added} added, {linked} link(s) attached, "
          f"{unchanged} already in sync. GHSAs: {g_added} record(s) added, "
          f"{g_attached} attached to existing CVEs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
