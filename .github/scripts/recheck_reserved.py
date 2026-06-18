#!/usr/bin/env python3
"""
Re-check reserved CVEs in cves.yaml against MITRE's CVE API.

For every entry with status == "reserved", fetch the current CVE record. If
the state has flipped to PUBLISHED, diff the fresh metadata against the
stored entry and open a PR proposing the update (date, vendor, product,
CVSS, credit, description, status).

The script never commits to main directly; each update goes through a PR
the operator reviews, matching the scanner's workflow.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# Reuse helpers from scan_cves.py (same dir).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scan_cves import (  # noqa: E402
    RENDER_SCRIPT,
    USER_AGENT,
    extract_summary,
    load_cves_yaml,
    run,
    save_cves_yaml,
    write_cve_entry,
)

MITRE_API = "https://cveawg.mitre.org/api/cve/{cve_id}"


def fetch_record(cve_id: str) -> dict | None:
    """Fetch a CVE record from MITRE.

    Returns the parsed JSON on success, None on 404 (MITRE returns 404 for
    reserved CVEs — only published records are served by this endpoint, so
    a 404 means the CVE is still reserved or has been rejected).
    Raises RuntimeError for any other persistent failure.
    """
    url = MITRE_API.format(cve_id=cve_id)
    last_err: Exception | None = None
    for attempt in range(3):
        try:
            req = Request(url, headers={"User-Agent": USER_AGENT})
            with urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except HTTPError as e:
            if e.code == 404:
                return None
            last_err = e
        except (URLError, TimeoutError, json.JSONDecodeError) as e:
            last_err = e
        time.sleep(2 ** attempt)
    raise RuntimeError(f"Failed to fetch {url}: {last_err}")

# Fields we'll propagate from a freshly-published record into the stored entry.
# `cve_link` is intentionally excluded — it's already set when the entry was created.
UPDATABLE_FIELDS = ("date", "vendor", "product", "cvss", "credit", "status")


def diff_updates(current: dict, fresh: dict) -> dict:
    """Return the subset of fresh fields that differ from current.

    Only counts a field as an update when fresh has a non-empty value; this
    prevents wiping out manual edits if MITRE temporarily drops a field.
    """
    updates: dict = {}
    for key in UPDATABLE_FIELDS:
        new_val = fresh.get(key)
        if new_val in (None, "", []):
            continue
        if new_val != current.get(key):
            updates[key] = new_val
    return updates


def existing_update_pr(cve_id: str, repo: str) -> str | None:
    """Return URL of an already-open update PR for this CVE, if any."""
    result = run(
        ["gh", "pr", "list", "--repo", repo, "--state", "open",
         "--search", f"\"[update] {cve_id}\" in:title",
         "--json", "url,title", "--limit", "10"],
        check=False,
    )
    if result.returncode != 0:
        print(f"  warn: gh pr list failed: {result.stderr.strip()}", file=sys.stderr)
        return None
    try:
        prs = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        return None
    for pr in prs:
        title = pr.get("title", "")
        if cve_id in title and "[update]" in title:
            return pr.get("url")
    return None


def render_update_body(cve_id: str, current: dict, fresh: dict,
                       updates: dict) -> str:
    lines = [
        f"## Auto-detected update: {cve_id}",
        "",
        f"`{cve_id}` was previously tracked as **reserved**. MITRE's record now "
        f"shows it as **{fresh.get('status', '?')}**, with new metadata.",
        "",
        "### Field changes",
        "",
        "| Field | Before | After |",
        "| --- | --- | --- |",
    ]
    for k in UPDATABLE_FIELDS:
        if k not in updates:
            continue
        before = current.get(k)
        after = updates[k]
        before_s = "(empty)" if before in (None, "", []) else str(before)
        after_s = str(after)
        lines.append(f"| `{k}` | {before_s} | {after_s} |")

    description = fresh.get("description") or "_no description provided_"
    lines += [
        "",
        "### Description (from current record)",
        description,
        "",
        "### Links",
        f"- CVE.org: https://www.cve.org/CVERecord?id={cve_id}",
        f"- NVD: https://nvd.nist.gov/vuln/detail/{cve_id}",
        f"- MITRE API: https://cveawg.mitre.org/api/cve/{cve_id}",
        "",
        "---",
        "**To accept:** merge this PR. `README.md` and the `cves.yaml` aggregate "
        "regenerate on merge.",
        "**To reject:** close this PR. The entry stays as-is; the recheck will "
        "propose again on the next run if MITRE keeps the new state.",
        "**To tweak:** edit the YAML on this branch before merging.",
        "",
        "_Surfaced automatically by `.github/scripts/recheck_reserved.py`._",
    ]
    return "\n".join(lines) + "\n"


def create_update_pr(repo: str, cve_id: str, current: dict, fresh: dict,
                     updates: dict) -> bool:
    branch = f"auto-update/{cve_id.lower()}"
    base_branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()

    run(["git", "fetch", "origin", base_branch], check=False)
    run(["git", "branch", "-D", branch], check=False)
    run(["git", "checkout", "-b", branch])

    try:
        target = next((e for e in load_cves_yaml() if e.get("cve") == cve_id), None)
        if target is None:
            print(f"  {cve_id} no longer tracked; skipping", file=sys.stderr)
            return False
        target.update(updates)
        path = write_cve_entry(target)  # rewrite only this entry's file

        run(["git", "add", str(path)])
        field_summary = ", ".join(updates.keys())
        commit_msg = f"auto: update {cve_id} ({field_summary})"
        run(["git", "commit", "-m", commit_msg])
        run(["git", "push", "-u", "origin", branch])

        body = render_update_body(cve_id, current, fresh, updates)
        title = f"[update] {cve_id} — reserved → published"
        create_result = run(
            ["gh", "pr", "create", "--repo", repo, "--base", base_branch,
             "--head", branch, "--title", title, "--body", body,
             "--label", "cve-candidate"],
            check=False,
        )
        if create_result.returncode != 0 and "label" in create_result.stderr.lower():
            create_result = run(
                ["gh", "pr", "create", "--repo", repo, "--base", base_branch,
                 "--head", branch, "--title", title, "--body", body],
                check=False,
            )
        if create_result.returncode != 0:
            print(f"  pr create failed: {create_result.stderr.strip()}", file=sys.stderr)
            return False
        print(f"  opened update PR for {cve_id}: {create_result.stdout.strip()}")
        return True

    finally:
        run(["git", "checkout", base_branch], check=False)
        run(["git", "reset", "--hard", f"origin/{base_branch}"], check=False)


def main() -> int:
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        print("GITHUB_REPOSITORY not set", file=sys.stderr)
        return 2

    entries = load_cves_yaml()
    reserved = [e for e in entries if e.get("status") == "reserved"]
    print(f"Found {len(reserved)} reserved entry/entries to check.")

    if not reserved:
        return 0

    updates_opened = 0
    for entry in reserved:
        cve_id = entry.get("cve")
        if not cve_id:
            continue

        try:
            record = fetch_record(cve_id)
        except RuntimeError as e:
            print(f"  {cve_id}: fetch failed: {e}", file=sys.stderr)
            continue

        if record is None:
            print(f"  {cve_id}: still reserved (404 from MITRE)")
            continue

        state = record.get("cveMetadata", {}).get("state")
        if state != "PUBLISHED":
            print(f"  {cve_id}: unexpected state '{state or 'unknown'}', skipping")
            continue

        fresh = extract_summary(record)
        updates = diff_updates(entry, fresh)
        if not updates:
            print(f"  {cve_id}: published but no field changes detected")
            continue

        already_open = existing_update_pr(cve_id, repo)
        if already_open:
            print(f"  {cve_id}: update PR already open ({already_open})")
            continue

        print(f"  {cve_id}: published with changes in {list(updates.keys())}")
        if create_update_pr(repo, cve_id, entry, fresh, updates):
            updates_opened += 1

    print(f"Done. Opened {updates_opened} update PR(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
