#!/usr/bin/env python3
"""
Scan the cvelistV5 delta feed for CVEs that mention Anthropic, anywhere
in the record, and open one PR per candidate proposing an addition to
cves.yaml + regenerated README.md.

Strategy:
  1. Fetch cves/delta.json from cvelistV5 main; it lists changed records
     with direct githubLinks to each record's JSON.
  2. For each changed record, fetch the JSON and search the entire
     serialized record for "anthropic" (case-insensitive).
  3. For each hit:
       - skip if the CVE is already in cves.yaml
       - skip if there is already an open PR for it
       - otherwise create a new branch, append a YAML entry, re-render
         README.md, push the branch, and open a PR
  4. Persist:
       state/seen.json -> last_fetch_timestamp + set of CVEs we've
       already opened PRs for, so re-runs don't open duplicate PRs.

This script intentionally does NOT merge anything; the user reviews each
PR and clicks Merge to publish.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

import yaml


KEYWORDS_PATH = Path("keywords.yaml")
DELTA_LOG_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
STATE_PATH = Path("state/seen.json")
CVES_YAML_PATH = Path("cves.yaml")  # generated aggregate (rendered on main)
CVES_DIR = Path("cves")             # source of truth: one file per CVE/GHSA
USER_AGENT = "anthropic-cve-tracker (+github actions)"
FETCH_SLEEP_SECONDS = 0.1
RENDER_SCRIPT = Path(".github/scripts/render_readme.py")
# Hard cap on records we'll fetch in a single run. Protects against pathological
# catch-up runs (e.g. first run on a brand-new repo would otherwise try to fetch
# ~tens of thousands of CVEs). Tunable.
MAX_RECORDS_PER_RUN = 2000


def load_keywords() -> list[str]:
    """Read keywords.yaml. Returns a list of non-empty, lowercased strings."""
    if not KEYWORDS_PATH.exists():
        # Sensible default if file is missing
        return ["anthropic"]
    raw = yaml.safe_load(KEYWORDS_PATH.read_text(encoding="utf-8")) or {}
    kws = raw.get("keywords") if isinstance(raw, dict) else raw
    if not isinstance(kws, list):
        return ["anthropic"]
    return [str(k).strip().lower() for k in kws if str(k).strip()]


# ---------- HTTP ----------

def http_get_json(url: str, retries: int = 3) -> dict:
    last_err: Exception | None = None
    for attempt in range(retries):
        try:
            req = Request(url, headers={"User-Agent": USER_AGENT})
            with urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as e:
            last_err = e
            time.sleep(2 ** attempt)
    raise RuntimeError(f"Failed to fetch {url}: {last_err}")


# ---------- State ----------

def load_state() -> dict:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text())
        except json.JSONDecodeError:
            pass
    return {"last_fetch_timestamp": None, "seen_cve_ids": []}


def save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")


# ---------- Matching ----------

def record_matches(record: dict, keywords: list[str]) -> dict[str, list[str]]:
    """
    Search the entire serialized record for any of the keywords.
    Returns a dict mapping location -> list of keywords found there.
    Empty dict means no match.

    Example return:
      {
        "credits": ["anthropic", "nicholas carlini"],
        "references": ["anthropic.com"],
      }
    """
    cna = record.get("containers", {}).get("cna", {}) or {}

    # Build (location_name, joined_lowercase_blob) pairs
    locations: list[tuple[str, str]] = []

    def add(name: str, items: list[str]) -> None:
        blob = " ".join(s for s in items if s).lower()
        if blob:
            locations.append((name, blob))

    add("credits", [c.get("value", "") for c in (cna.get("credits") or [])])
    add("descriptions", [d.get("value", "") for d in (cna.get("descriptions") or [])])
    add("references", [
        (r.get("url", "") or "") + " " + (r.get("name") or "")
        for r in (cna.get("references") or [])
    ])
    add("affected", [
        f"{a.get('vendor', '')} {a.get('product', '')}"
        for a in (cna.get("affected") or [])
    ])
    add("solutions", [s.get("value", "") for s in (cna.get("solutions") or [])])
    add("workarounds", [w.get("value", "") for w in (cna.get("workarounds") or [])])
    add("x_generator", [json.dumps(cna.get("x_generator", ""))])

    adp = record.get("containers", {}).get("adp") or []
    if adp:
        add("adp", [json.dumps(adp)])

    matches: dict[str, list[str]] = {}
    for loc_name, blob in locations:
        for kw in keywords:
            if kw in blob:
                matches.setdefault(loc_name, []).append(kw)

    # Catch-all: keyword somewhere we didn't categorize
    if not matches:
        full = json.dumps(record).lower()
        for kw in keywords:
            if kw in full:
                matches.setdefault("other", []).append(kw)

    return matches


# ---------- Record summary ----------

def extract_summary(record: dict) -> dict:
    meta = record.get("cveMetadata", {})
    cna = record.get("containers", {}).get("cna", {}) or {}

    descriptions = cna.get("descriptions", []) or []
    description = ""
    for d in descriptions:
        if d.get("lang", "").lower().startswith("en"):
            description = d.get("value", "")
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "")

    affected_list = cna.get("affected", []) or []
    vendor = affected_list[0].get("vendor") if affected_list else None
    product = affected_list[0].get("product") if affected_list else None

    # Try to find a CVSS v3.x or v4 base score from metrics
    cvss: float | None = None
    for metric in cna.get("metrics") or []:
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
            if key in metric:
                try:
                    cvss = float(metric[key].get("baseScore"))
                except (TypeError, ValueError):
                    pass
                if cvss is not None:
                    break
        if cvss is not None:
            break

    credit_strings = [c.get("value", "").strip()
                      for c in (cna.get("credits") or []) if c.get("value")]
    credit_joined = " | ".join(credit_strings) if credit_strings else ""

    date_published = meta.get("datePublished") or ""
    date_only = date_published[:10] if date_published else None

    cve_id = meta.get("cveId", "UNKNOWN")
    return {
        "cve": cve_id,
        "ghsa": None,
        "date": date_only,
        "vendor": vendor or "",
        "product": product or "",
        "cvss": cvss,
        "credit": credit_joined,
        "status": "published" if meta.get("state") == "PUBLISHED" else "reserved",
        "description": description,
        "cve_link": f"https://www.cve.org/CVERecord?id={cve_id}",
        "ghsa_link": None,
        "notes": None,
        "auto_discovered": True,
    }


# ---------- cves.yaml manipulation ----------

class _YamlDumper(yaml.SafeDumper):
    pass


def _str_repr(dumper, data):
    if "\n" in data or len(data) > 80:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=">")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_YamlDumper.add_representer(str, _str_repr)


def entry_ident(entry: dict) -> str:
    """Stable identifier used as the per-entry filename: CVE id when present,
    otherwise the GHSA id (for advisories that have no CVE assigned yet)."""
    return entry.get("cve") or entry.get("ghsa") or ""


def cve_file_path(ident: str) -> Path:
    return CVES_DIR / f"{ident}.yaml"


def write_cve_entry(entry: dict) -> Path:
    """Write a single entry to cves/<id>.yaml. This is what auto-PRs touch — one
    file per PR, so independent additions never collide. README.md and the flat
    cves.yaml aggregate are regenerated from cves/ on main by render_readme.py."""
    CVES_DIR.mkdir(exist_ok=True)
    path = cve_file_path(entry_ident(entry))
    path.write_text(
        yaml.dump(entry, Dumper=_YamlDumper, sort_keys=False,
                  allow_unicode=True, width=100),
        encoding="utf-8",
    )
    return path


def load_cves_yaml() -> list[dict]:
    """Load every entry from cves/. Falls back to the legacy flat cves.yaml if
    the directory does not exist (e.g. before migration)."""
    if CVES_DIR.is_dir():
        out = []
        for path in sorted(CVES_DIR.glob("*.yaml")):
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            if isinstance(doc, dict):
                out.append(doc)
        return out
    if CVES_YAML_PATH.exists():
        return yaml.safe_load(CVES_YAML_PATH.read_text(encoding="utf-8")) or []
    return []


def save_cves_yaml(entries: list[dict]) -> None:
    """Write each entry to its own file under cves/. Unchanged entries produce
    byte-identical files (no git churn). Single-entry callers should prefer
    write_cve_entry() so a PR touches exactly one file."""
    for entry in entries:
        write_cve_entry(entry)


# ---------- Git / PR ----------

def run(cmd: list[str], check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check, **kwargs)


def existing_pr_for_cve(cve_id: str, repo: str) -> str | None:
    """Open PRs only — if one exists, we already proposed this CVE and shouldn't duplicate."""
    result = run(
        ["gh", "pr", "list", "--repo", repo, "--state", "open",
         "--search", f"\"{cve_id}\" in:title",
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
        if cve_id in pr.get("title", ""):
            return pr.get("url")
    return None


def render_pr_body(entry: dict, summary: dict, matches: dict[str, list[str]],
                   record_url: str) -> str:
    description = summary.get("description") or "_no description provided_"
    cvss_str = f"{entry['cvss']:.1f}" if entry.get("cvss") is not None else "(not in record)"

    # Render the match table: location -> keywords
    if matches:
        match_lines = []
        for loc, kws in matches.items():
            # dedupe while preserving order
            seen_local = set()
            uniq_kws = []
            for k in kws:
                if k not in seen_local:
                    uniq_kws.append(k)
                    seen_local.add(k)
            kw_str = ", ".join(f"`{k}`" for k in uniq_kws)
            match_lines.append(f"- **{loc}:** {kw_str}")
        match_block = "\n".join(match_lines)
    else:
        match_block = "_unknown_"

    return f"""## Auto-detected: {entry['cve']}

This PR proposes adding `{entry['cve']}` as `cves/{entry['cve']}.yaml`. `README.md` and the `cves.yaml` aggregate regenerate automatically on merge.

### Where the match came from
{match_block}

**Vendor / Product:** {entry.get('vendor', '?')} / {entry.get('product', '?')}
**Date:** {entry.get('date') or 'Reserved'}
**CVSS:** {cvss_str}
**Status:** {entry.get('status', '?')}

### Credit field (from record)
```
{entry.get('credit') or '(empty — match was in another field)'}
```

### Description
{description}

### Links
- CVE record JSON: {record_url}
- CVE.org: https://www.cve.org/CVERecord?id={entry['cve']}
- NVD: https://nvd.nist.gov/vuln/detail/{entry['cve']}

---
**To accept:** merge this PR. `README.md` and the `cves.yaml` aggregate regenerate on merge.
**To reject:** close this PR. The CVE will be remembered as "seen" and not re-proposed.
**To tweak before merging:** edit the YAML in the PR; README re-renders on merge.

_Surfaced automatically by `.github/workflows/scan-cves.yml`._
"""


def create_pr_for_entry(repo: str, entry: dict, summary: dict,
                        matches: dict[str, list[str]],
                        record_url: str) -> bool:
    cve_id = entry["cve"]
    branch = f"auto/{cve_id.lower()}"

    # Get current branch to come back to it
    base_branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()

    # Make sure we're starting clean from base
    run(["git", "fetch", "origin", base_branch], check=False)

    # If the branch already exists remotely, gh pr list above should have caught it,
    # but be defensive: delete any local copy.
    run(["git", "branch", "-D", branch], check=False)
    run(["git", "checkout", "-b", branch])

    try:
        # One file per CVE: the PR adds exactly cves/<cve_id>.yaml. README.md and
        # the flat cves.yaml aggregate are regenerated from cves/ on main, so the
        # PR carries no shared file and never conflicts with other auto-PRs.
        if cve_file_path(cve_id).exists():
            print(f"  {cve_id} already in cves/; skipping PR")
            return False
        path = write_cve_entry(entry)

        run(["git", "add", str(path)])
        # Build a short commit message describing the match
        match_summary = ", ".join(sorted(matches.keys())) or "record"
        commit_msg = f"auto: add {cve_id} (matched in {match_summary})"
        run(["git", "commit", "-m", commit_msg])
        run(["git", "push", "-u", "origin", branch])

        body = render_pr_body(entry, summary, matches, record_url)
        title = f"[candidate] {cve_id} — keyword match"
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
        print(f"  opened PR for {cve_id}: {create_result.stdout.strip()}")
        return True

    finally:
        run(["git", "checkout", base_branch], check=False)
        run(["git", "reset", "--hard", f"origin/{base_branch}"], check=False)


# ---------- main ----------

def main() -> int:
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        print("GITHUB_REPOSITORY not set", file=sys.stderr)
        return 2

    keywords = load_keywords()
    print(f"Loaded {len(keywords)} keyword(s) from {KEYWORDS_PATH}")

    print(f"Fetching deltaLog: {DELTA_LOG_URL}")
    delta_log = http_get_json(DELTA_LOG_URL)
    if not isinstance(delta_log, list):
        print("deltaLog.json is not a list; aborting", file=sys.stderr)
        return 1

    state = load_state()
    seen: set[str] = set(state.get("seen_cve_ids", []))
    last_ts = state.get("last_fetch_timestamp")
    print(f"  loaded state: last_fetch_timestamp={last_ts}, {len(seen)} CVEs already seen")

    # deltaLog entries are ordered newest first. Walk them and keep only those
    # whose fetchTime is strictly greater than our last_fetch_timestamp.
    # On first run (last_ts is None), the operator can set FIRST_RUN_BATCHES to
    # backfill more than the most-recent batch. Default = 1 to keep first runs cheap.
    if last_ts is None:
        try:
            first_run_batches = int(os.environ.get("FIRST_RUN_BATCHES", "1"))
        except ValueError:
            first_run_batches = 1
        new_batches = delta_log[:max(1, first_run_batches)]
        print(f"  first run: processing the {len(new_batches)} most recent batch(es) "
              f"(set FIRST_RUN_BATCHES to backfill more)")
    else:
        new_batches = [b for b in delta_log if (b.get("fetchTime") or "") > last_ts]
        print(f"  {len(new_batches)} batch(es) newer than last run")

    if not new_batches:
        print("No new batches; nothing to do.")
        return 0

    # Process batches oldest-first. We dedup CVE IDs across batches WITHIN this run.
    # If we hit MAX_RECORDS_PER_RUN, we stop adding stubs and only advance the
    # timestamp to the last fully-processed batch — so the next run resumes correctly.
    stubs_by_cve: dict[str, dict] = {}
    last_fully_processed_batch_ts: str | None = None
    capped = False

    for batch in reversed(new_batches):  # oldest first
        # Snapshot how many stubs this batch would add
        batch_stubs: list[tuple[str, dict]] = []
        for key in ("new", "updated"):
            for s in batch.get(key) or []:
                cve = s.get("cveId")
                if cve and cve not in stubs_by_cve:
                    batch_stubs.append((cve, s))

        if len(stubs_by_cve) + len(batch_stubs) > MAX_RECORDS_PER_RUN:
            # Stop here. The PREVIOUS batch was the last fully processed.
            print(f"  WARNING: hit MAX_RECORDS_PER_RUN={MAX_RECORDS_PER_RUN} at "
                  f"batch fetchTime={batch.get('fetchTime')}; "
                  f"will resume from there next run")
            capped = True
            break

        for cve, s in batch_stubs:
            stubs_by_cve[cve] = s
        last_fully_processed_batch_ts = batch.get("fetchTime")

    print(f"  {len(stubs_by_cve)} unique CVE(s) to consider")

    existing_yaml_ids = {e.get("cve") for e in load_cves_yaml()}

    matches_found = 0
    prs_opened = 0

    for cve_id, stub in stubs_by_cve.items():
        record_url = stub.get("githubLink")
        if not record_url:
            continue
        if cve_id in seen:
            continue
        if cve_id in existing_yaml_ids:
            seen.add(cve_id)
            continue

        try:
            record = http_get_json(record_url)
        except RuntimeError as e:
            print(f"  skip {cve_id}: {e}", file=sys.stderr)
            continue

        matches = record_matches(record, keywords)
        if not matches:
            time.sleep(FETCH_SLEEP_SECONDS)
            continue

        matches_found += 1
        log_parts = []
        for loc, kws in matches.items():
            uniq = list(dict.fromkeys(kws))
            log_parts.append(f"{loc}: {','.join(uniq)}")
        print(f"  match: {cve_id} -> " + "; ".join(log_parts))

        existing_pr = existing_pr_for_cve(cve_id, repo)
        if existing_pr:
            print(f"    PR already open: {existing_pr}")
            seen.add(cve_id)
            time.sleep(FETCH_SLEEP_SECONDS)
            continue

        summary = extract_summary(record)
        entry = {k: summary[k] for k in
                 ("cve", "ghsa", "date", "vendor", "product", "cvss",
                  "credit", "status", "cve_link", "ghsa_link",
                  "notes", "auto_discovered")}

        ok = create_pr_for_entry(repo, entry, summary, matches, record_url)
        if ok:
            prs_opened += 1
        seen.add(cve_id)
        time.sleep(FETCH_SLEEP_SECONDS)

    # Advance last_fetch_timestamp only to the boundary of fully-processed batches.
    if last_fully_processed_batch_ts:
        new_last_ts = last_fully_processed_batch_ts
    else:
        # We didn't fully process any batch this run -- keep state unchanged
        new_last_ts = last_ts

    state["last_fetch_timestamp"] = new_last_ts
    state["seen_cve_ids"] = sorted(seen)
    save_state(state)

    print(f"Done. {matches_found} matches, {prs_opened} PR(s) opened, {len(seen)} CVEs tracked total.")
    print(f"  advanced last_fetch_timestamp to: {new_last_ts}{' (capped)' if capped else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
