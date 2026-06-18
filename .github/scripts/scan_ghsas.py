#!/usr/bin/env python3
"""
Scan GitHub's global security advisory database for Anthropic-credited
advisories and also recheck any GHSA-only entries in cves.yaml to see if
they have since been assigned a CVE.

Two passes:

1. Forward scan: GET /advisories?modified=>=<since>, paginate. For each
   advisory, match `keywords` against the whole JSON blob and match
   `github_usernames` against credits[*].user.login. If an advisory hits:
     - already in cves.yaml by CVE or GHSA  -> open enrichment PR if there
       are usable new fields, otherwise skip silently
     - new                                  -> open candidate PR with a
       fresh entry (CVE-keyed if the GHSA has a CVE, GHSA-keyed otherwise)

2. CVE-assignment recheck: walk cves.yaml entries where `cve` is null and
   `ghsa` is set. Refetch /advisories/<ghsa>; if `cve_id` is now populated,
   open a PR moving the entry under that CVE.

Like the other scanners, no merges happen automatically -- humans review
the PRs.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

# Reuse helpers from scan_cves.py (same dir).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scan_cves import (  # noqa: E402
    KEYWORDS_PATH,
    RENDER_SCRIPT,
    STATE_PATH,
    USER_AGENT,
    cve_file_path,
    entry_ident,
    load_cves_yaml,
    run,
    save_cves_yaml,
    write_cve_entry,
)
import yaml  # noqa: E402

ADVISORIES_LIST_URL = "https://api.github.com/advisories"
ADVISORY_URL = "https://api.github.com/advisories/{ghsa_id}"
GH_HEADERS_BASE = {
    "User-Agent": USER_AGENT,
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}
MAX_PAGES_PER_RUN = 10  # 10 * 100 = 1000 advisories max per run
FIRST_RUN_DAYS_DEFAULT = 7


# ---------- Keywords ----------

def load_keyword_config() -> tuple[list[str], list[str]]:
    """Returns (text_keywords, github_usernames), both lowercased."""
    if not KEYWORDS_PATH.exists():
        return (["anthropic"], [])
    raw = yaml.safe_load(KEYWORDS_PATH.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        return (["anthropic"], [])
    kws = raw.get("keywords") or []
    unames = raw.get("github_usernames") or []
    kws = [str(k).strip().lower() for k in kws if str(k).strip()]
    unames = [str(u).strip().lower() for u in unames if str(u).strip()]
    return (kws, unames)


# ---------- HTTP ----------

def gh_headers() -> dict:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    h = dict(GH_HEADERS_BASE)
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def http_get(url: str, retries: int = 3) -> tuple[dict | list | None, dict]:
    """GET a JSON URL with retries; returns (parsed_body_or_None_on_404, headers).

    None body for 404 lets callers distinguish 'not found' (e.g. withdrawn or
    nonexistent GHSA) from a hard failure.
    """
    last_err: Exception | None = None
    for attempt in range(retries):
        try:
            req = Request(url, headers=gh_headers())
            with urlopen(req, timeout=30) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                # Convert headers to a flat dict for downstream Link parsing
                return body, dict(resp.headers.items())
        except HTTPError as e:
            if e.code == 404:
                return None, dict(e.headers.items()) if e.headers else {}
            last_err = e
        except (URLError, TimeoutError, json.JSONDecodeError) as e:
            last_err = e
        time.sleep(2 ** attempt)
    raise RuntimeError(f"Failed to fetch {url}: {last_err}")


def parse_next_link(link_header: str | None) -> str | None:
    """Parse RFC5988 Link: header for rel=next URL."""
    if not link_header:
        return None
    for part in link_header.split(","):
        section = part.strip().split(";")
        if len(section) < 2:
            continue
        url = section[0].strip().lstrip("<").rstrip(">")
        rel = ""
        for attr in section[1:]:
            attr = attr.strip()
            if attr.startswith("rel="):
                rel = attr[4:].strip().strip('"')
        if rel == "next":
            return url
    return None


# ---------- Matching ----------

def advisory_matches(advisory: dict, keywords: list[str],
                     usernames: list[str]) -> dict[str, list[str]]:
    """Locate keyword/username hits in an advisory.

    Returns a {location: [keywords]} dict; empty dict means no match.
    """
    matches: dict[str, list[str]] = {}

    def add_text(loc: str, blob: str) -> None:
        if not blob:
            return
        lower = blob.lower()
        for kw in keywords:
            if kw in lower:
                matches.setdefault(loc, []).append(kw)

    add_text("summary", advisory.get("summary") or "")
    add_text("description", advisory.get("description") or "")

    refs = advisory.get("references") or []
    add_text("references", " ".join(refs))

    # Vulnerabilities packages (vendor/product strings)
    vulns = advisory.get("vulnerabilities") or []
    pkg_blob_parts: list[str] = []
    for v in vulns:
        pkg = v.get("package") or {}
        pkg_blob_parts.append(f"{pkg.get('ecosystem','')} {pkg.get('name','')}")
    add_text("packages", " ".join(pkg_blob_parts))

    # Structured credits: usernames
    if usernames:
        credits = advisory.get("credits") or []
        for c in credits:
            user = c.get("user") or {}
            login = (user.get("login") or "").lower()
            if login and login in usernames:
                matches.setdefault("credits.user.login", []).append(login)

    # Catch-all on the whole serialized advisory if nothing matched yet --
    # this catches anything we didn't categorize (e.g. CWE descriptions).
    if not matches:
        full = json.dumps(advisory).lower()
        for kw in keywords:
            if kw in full:
                matches.setdefault("other", []).append(kw)

    return matches


# ---------- Entry construction ----------

def extract_ghsa_summary(advisory: dict) -> dict:
    """Build a cves.yaml-compatible entry from a GHSA advisory."""
    ghsa_id = advisory.get("ghsa_id", "UNKNOWN")
    cve_id = advisory.get("cve_id")

    # Date: published_at is the GHSA publish date (close enough to vuln date)
    published_at = advisory.get("published_at") or ""
    date_only = published_at[:10] if published_at else None

    # CVSS: prefer the structured score; fall back to severity tier mapping
    cvss = None
    cvss_field = advisory.get("cvss") or {}
    score = cvss_field.get("score")
    if score is not None:
        try:
            cvss = float(score)
        except (TypeError, ValueError):
            pass

    vulns = advisory.get("vulnerabilities") or []
    pkg = (vulns[0].get("package") or {}) if vulns else {}
    pkg_name = pkg.get("name") or ""
    # Composer-style "vendor/product" splits cleanly; otherwise use ecosystem as vendor
    if "/" in pkg_name:
        vendor, product = pkg_name.split("/", 1)
    else:
        vendor = pkg.get("ecosystem") or ""
        product = pkg_name

    credit_parts: list[str] = []
    for c in advisory.get("credits") or []:
        user = c.get("user") or {}
        login = user.get("login")
        ctype = c.get("type") or ""
        if login:
            credit_parts.append(f"@{login} ({ctype})" if ctype else f"@{login}")
    credit_joined = " | ".join(credit_parts)

    status = "withdrawn" if advisory.get("withdrawn_at") else "published"

    return {
        "cve": cve_id,
        "ghsa": ghsa_id,
        "date": date_only,
        "vendor": vendor,
        "product": product,
        "cvss": cvss,
        "credit": credit_joined,
        "status": status,
        "cve_link": f"https://www.cve.org/CVERecord?id={cve_id}" if cve_id else None,
        "ghsa_link": f"https://github.com/advisories/{ghsa_id}",
        "notes": None,
        "auto_discovered": True,
    }


# ---------- State ----------

def load_state() -> dict:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text())
        except json.JSONDecodeError:
            pass
    return {}


def save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")


# ---------- PR helpers ----------

def existing_pr_with_id(cve_or_ghsa: str, repo: str) -> str | None:
    result = run(
        ["gh", "pr", "list", "--repo", repo, "--state", "open",
         "--search", f"\"{cve_or_ghsa}\" in:title",
         "--json", "url,title", "--limit", "10"],
        check=False,
    )
    if result.returncode != 0:
        return None
    try:
        prs = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        return None
    for pr in prs:
        if cve_or_ghsa in pr.get("title", ""):
            return pr.get("url")
    return None


def open_pr(branch: str, title: str, body: str, repo: str) -> bool:
    base_branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()
    run(["git", "push", "-u", "origin", branch])
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
    print(f"  opened PR: {create_result.stdout.strip()}")
    return True


def commit_branch(branch_name: str, files: list[str], commit_msg: str) -> str:
    """Create a fresh branch off main, stage changes, commit. Returns base branch."""
    base_branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()
    run(["git", "fetch", "origin", base_branch], check=False)
    run(["git", "branch", "-D", branch_name], check=False)
    run(["git", "checkout", "-b", branch_name])
    run(["git", "add", *files])
    run(["git", "commit", "-m", commit_msg])
    return base_branch


def reset_to_base(base_branch: str) -> None:
    run(["git", "checkout", base_branch], check=False)
    run(["git", "reset", "--hard", f"origin/{base_branch}"], check=False)


# ---------- New-entry PR ----------

def render_candidate_body(entry: dict, advisory: dict,
                          matches: dict[str, list[str]]) -> str:
    if matches:
        match_lines = []
        for loc, kws in matches.items():
            uniq = list(dict.fromkeys(kws))
            match_lines.append(f"- **{loc}:** " + ", ".join(f"`{k}`" for k in uniq))
        match_block = "\n".join(match_lines)
    else:
        match_block = "_unknown_"

    cve_id = entry.get("cve") or "(none yet)"
    ghsa_id = entry.get("ghsa") or "(none)"
    description = advisory.get("description") or "_no description provided_"
    cvss_str = f"{entry['cvss']:.1f}" if entry.get("cvss") is not None else "(not in advisory)"

    return f"""## Auto-detected (via GHSA): {ghsa_id}

This PR proposes adding a new entry as a file under `cves/`. `README.md` and the `cves.yaml` aggregate regenerate automatically on merge.

**CVE:** {cve_id}
**GHSA:** {ghsa_id}
**Package:** {entry.get('vendor','?')} / {entry.get('product','?')}
**Date:** {entry.get('date') or 'Unknown'}
**CVSS:** {cvss_str}
**Severity:** {advisory.get('severity','?')}
**Status:** {entry.get('status','?')}

### Where the match came from
{match_block}

### Credits field (from advisory)
```
{entry.get('credit') or '(empty -- match came from prose or another field)'}
```

### Description
{description}

### Links
- GHSA: https://github.com/advisories/{ghsa_id}
{"- CVE.org: https://www.cve.org/CVERecord?id=" + cve_id if entry.get("cve") else ""}
- Source API: {ADVISORY_URL.format(ghsa_id=ghsa_id)}

---
**To accept:** merge this PR. `README.md` and the `cves.yaml` aggregate regenerate on merge.
**To reject:** close this PR. The GHSA is recorded as seen and won't be re-proposed.
**To tweak:** edit the YAML on this branch before merging.

_Surfaced automatically by `.github/scripts/scan_ghsas.py`._
"""


def create_candidate_pr(repo: str, entry: dict, advisory: dict,
                        matches: dict[str, list[str]]) -> bool:
    ghsa_id = entry.get("ghsa") or "UNKNOWN"
    cve_id = entry.get("cve")
    branch = f"auto-ghsa/{ghsa_id.lower()}"
    try:
        run(["git", "fetch", "origin",
             run(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()],
            check=False)
        run(["git", "branch", "-D", branch], check=False)
        run(["git", "checkout", "-b", branch])

        # Defensive dedup -- recheck within the working tree
        for e in load_cves_yaml():
            if (cve_id and e.get("cve") == cve_id) or e.get("ghsa") == ghsa_id:
                print(f"  {ghsa_id}: already tracked at PR-creation time; skipping")
                return False
        path = write_cve_entry(entry)  # one file per entry; no shared-file conflict

        run(["git", "add", str(path)])
        commit_msg = (
            f"auto: add {cve_id} (via {ghsa_id})" if cve_id
            else f"auto: add {ghsa_id} (no CVE assigned yet)"
        )
        run(["git", "commit", "-m", commit_msg])

        title = (f"[candidate] {cve_id} (via {ghsa_id})" if cve_id
                 else f"[candidate] {ghsa_id} - no CVE yet")
        body = render_candidate_body(entry, advisory, matches)
        return open_pr(branch, title, body, repo)
    finally:
        reset_to_base(run(["git", "rev-parse", "--abbrev-ref", "main"],
                          check=False).stdout.strip() or "main")


# ---------- Enrichment PR (GHSA found for existing CVE entry) ----------

# Fields that GHSA data may fill in if the current entry leaves them blank.
ENRICHABLE = ("vendor", "product", "cvss", "credit", "date")


def compute_enrichments(current: dict, fresh: dict) -> dict:
    """Return fields to set on the existing entry, only filling blanks.

    `ghsa` and `ghsa_link` are added unconditionally if missing.
    """
    updates: dict = {}
    if not current.get("ghsa") and fresh.get("ghsa"):
        updates["ghsa"] = fresh["ghsa"]
    if not current.get("ghsa_link") and fresh.get("ghsa_link"):
        updates["ghsa_link"] = fresh["ghsa_link"]
    for k in ENRICHABLE:
        if fresh.get(k) in (None, "", []):
            continue
        if current.get(k) in (None, "", []):
            updates[k] = fresh[k]
    return updates


def render_enrichment_body(cve_id: str, ghsa_id: str,
                           current: dict, updates: dict,
                           advisory: dict,
                           matches: dict[str, list[str]]) -> str:
    lines = [
        f"## GHSA enrichment for {cve_id}",
        "",
        f"GitHub's advisory database has `{ghsa_id}` linked to `{cve_id}`. "
        "This PR adds the GHSA reference and fills in any fields the current "
        "entry had left blank.",
        "",
        "### Field changes",
        "",
        "| Field | Before | After |",
        "| --- | --- | --- |",
    ]
    for k in sorted(updates.keys()):
        before = current.get(k)
        before_s = "(empty)" if before in (None, "", []) else str(before)
        lines.append(f"| `{k}` | {before_s} | {updates[k]} |")

    if matches:
        match_lines = []
        for loc, kws in matches.items():
            uniq = list(dict.fromkeys(kws))
            match_lines.append(f"- **{loc}:** " + ", ".join(f"`{k}`" for k in uniq))
        match_block = "\n".join(match_lines)
    else:
        match_block = "_unknown_"

    lines += [
        "",
        "### Where the match came from",
        match_block,
        "",
        "### Links",
        f"- GHSA: https://github.com/advisories/{ghsa_id}",
        f"- CVE.org: https://www.cve.org/CVERecord?id={cve_id}",
        "",
        "---",
        "**To accept:** merge this PR.",
        "**To reject:** close this PR. The GHSA is recorded as seen.",
        "",
        "_Surfaced automatically by `.github/scripts/scan_ghsas.py`._",
    ]
    return "\n".join(lines) + "\n"


def create_enrichment_pr(repo: str, cve_id: str, ghsa_id: str,
                         current: dict, updates: dict, advisory: dict,
                         matches: dict[str, list[str]]) -> bool:
    branch = f"auto-ghsa-enrich/{ghsa_id.lower()}"
    base_branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()
    run(["git", "fetch", "origin", base_branch], check=False)
    run(["git", "branch", "-D", branch], check=False)
    run(["git", "checkout", "-b", branch])
    try:
        target = next((e for e in load_cves_yaml() if e.get("cve") == cve_id), None)
        if target is None:
            print(f"  {cve_id} not found at PR-creation time; skipping", file=sys.stderr)
            return False
        target.update(updates)
        path = write_cve_entry(target)  # rewrite only this entry's file

        run(["git", "add", str(path)])
        run(["git", "commit", "-m", f"auto: enrich {cve_id} from {ghsa_id}"])

        title = f"[update] {cve_id} - GHSA enrichment ({ghsa_id})"
        body = render_enrichment_body(cve_id, ghsa_id, current, updates,
                                      advisory, matches)
        return open_pr(branch, title, body, repo)
    finally:
        reset_to_base(base_branch)


# ---------- CVE-assignment recheck ----------

def render_assignment_body(ghsa_id: str, cve_id: str, current: dict,
                           advisory: dict) -> str:
    desc = advisory.get("description") or "_no description provided_"
    return f"""## CVE assigned to tracked GHSA: {ghsa_id} -> {cve_id}

GitHub's advisory database now links `{ghsa_id}` to `{cve_id}`. This PR
updates the entry in `cves.yaml` to set the CVE ID and its `cve_link`.

### Description
{desc}

### Links
- GHSA: https://github.com/advisories/{ghsa_id}
- CVE.org: https://www.cve.org/CVERecord?id={cve_id}

---
**To accept:** merge this PR.
**To reject:** close this PR; the entry stays as GHSA-only.

_Surfaced automatically by `.github/scripts/scan_ghsas.py`._
"""


def create_assignment_pr(repo: str, ghsa_id: str, cve_id: str,
                         current: dict, advisory: dict) -> bool:
    branch = f"auto-ghsa-cve/{ghsa_id.lower()}"
    base_branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()
    run(["git", "fetch", "origin", base_branch], check=False)
    run(["git", "branch", "-D", branch], check=False)
    run(["git", "checkout", "-b", branch])
    try:
        target = next((e for e in load_cves_yaml() if e.get("ghsa") == ghsa_id), None)
        if target is None:
            print(f"  {ghsa_id} not found at PR-creation time; skipping", file=sys.stderr)
            return False
        old_path = cve_file_path(entry_ident(target))  # was GHSA-named
        target["cve"] = cve_id
        target["cve_link"] = f"https://www.cve.org/CVERecord?id={cve_id}"
        new_path = write_cve_entry(target)  # now CVE-named
        if old_path != new_path and old_path.exists():
            run(["git", "rm", "-q", str(old_path)], check=False)
        run(["git", "add", str(new_path)])
        run(["git", "commit", "-m", f"auto: assign {cve_id} to {ghsa_id}"])

        title = f"[update] {ghsa_id} -> {cve_id} (CVE assigned)"
        body = render_assignment_body(ghsa_id, cve_id, current, advisory)
        return open_pr(branch, title, body, repo)
    finally:
        reset_to_base(base_branch)


# ---------- Main passes ----------

def iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def forward_scan(repo: str, keywords: list[str], usernames: list[str],
                 state: dict, existing_yaml: list[dict]) -> int:
    """Returns number of PRs opened."""
    by_cve = {e["cve"]: e for e in existing_yaml if e.get("cve")}
    by_ghsa = {e["ghsa"]: e for e in existing_yaml if e.get("ghsa")}

    last_ghsa_modified = state.get("last_ghsa_modified")
    seen_ghsa_ids: set[str] = set(state.get("seen_ghsa_ids") or [])

    if not last_ghsa_modified:
        days = int(os.environ.get("FIRST_RUN_GHSA_DAYS",
                                  str(FIRST_RUN_DAYS_DEFAULT)))
        cutoff = (dt.datetime.now(dt.timezone.utc)
                  - dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"  first GHSA run: looking back {days} day(s) (from {cutoff})")
    else:
        cutoff = last_ghsa_modified
        print(f"  GHSA scan: looking for advisories modified >= {cutoff}")

    query = urlencode({
        "modified": f">={cutoff}",
        "sort": "updated",
        "direction": "asc",
        "per_page": "100",
    })
    url: str | None = f"{ADVISORIES_LIST_URL}?{query}"

    advisories: list[dict] = []
    pages = 0
    while url and pages < MAX_PAGES_PER_RUN:
        body, headers = http_get(url)
        if not isinstance(body, list):
            print(f"  unexpected list response: {type(body).__name__}", file=sys.stderr)
            break
        advisories.extend(body)
        url = parse_next_link(headers.get("Link"))
        pages += 1
    if pages == MAX_PAGES_PER_RUN and url:
        print(f"  WARNING: hit MAX_PAGES_PER_RUN={MAX_PAGES_PER_RUN}; "
              f"some advisories may roll into the next run")

    print(f"  fetched {len(advisories)} advisory record(s) across {pages} page(s)")

    prs_opened = 0
    max_modified_seen = cutoff

    for advisory in advisories:
        ghsa_id = advisory.get("ghsa_id")
        if not ghsa_id:
            continue
        updated_at = advisory.get("updated_at") or ""
        if updated_at > max_modified_seen:
            max_modified_seen = updated_at

        if ghsa_id in seen_ghsa_ids:
            continue
        if advisory.get("withdrawn_at"):
            continue

        matches = advisory_matches(advisory, keywords, usernames)
        if not matches:
            continue

        cve_id = advisory.get("cve_id")
        print(f"  match: {ghsa_id} (cve={cve_id}) -> "
              + "; ".join(f"{loc}: {','.join(dict.fromkeys(kws))}"
                          for loc, kws in matches.items()))

        # Case 1: CVE already tracked -> enrichment
        if cve_id and cve_id in by_cve:
            current = by_cve[cve_id]
            fresh = extract_ghsa_summary(advisory)
            updates = compute_enrichments(current, fresh)
            if not updates:
                print(f"    nothing to enrich on {cve_id}; marking seen")
                seen_ghsa_ids.add(ghsa_id)
                continue
            if existing_pr_with_id(ghsa_id, repo) or existing_pr_with_id(cve_id, repo):
                print(f"    open PR already exists for {cve_id} or {ghsa_id}; skipping")
                seen_ghsa_ids.add(ghsa_id)
                continue
            if create_enrichment_pr(repo, cve_id, ghsa_id, current,
                                    updates, advisory, matches):
                prs_opened += 1
            seen_ghsa_ids.add(ghsa_id)
            continue

        # Case 1b: GHSA already tracked but referenced by ghsa not cve -> skip
        if ghsa_id in by_ghsa:
            seen_ghsa_ids.add(ghsa_id)
            continue

        # Case 2 / 3: new entry (CVE-keyed or GHSA-only)
        identifier = cve_id or ghsa_id
        if existing_pr_with_id(identifier, repo):
            print(f"    open PR already exists for {identifier}; skipping")
            seen_ghsa_ids.add(ghsa_id)
            continue

        entry = extract_ghsa_summary(advisory)
        if create_candidate_pr(repo, entry, advisory, matches):
            prs_opened += 1
        seen_ghsa_ids.add(ghsa_id)

    state["last_ghsa_modified"] = max_modified_seen
    state["seen_ghsa_ids"] = sorted(seen_ghsa_ids)
    return prs_opened


def cve_assignment_recheck(repo: str, existing_yaml: list[dict]) -> int:
    ghsa_only = [e for e in existing_yaml
                 if not e.get("cve") and e.get("ghsa")]
    print(f"CVE-assignment recheck: {len(ghsa_only)} GHSA-only entry/entries")

    prs_opened = 0
    for entry in ghsa_only:
        ghsa_id = entry["ghsa"]
        try:
            body, _ = http_get(ADVISORY_URL.format(ghsa_id=ghsa_id))
        except RuntimeError as e:
            print(f"  {ghsa_id}: fetch failed: {e}", file=sys.stderr)
            continue
        if body is None:
            print(f"  {ghsa_id}: 404 (withdrawn or removed); skipping")
            continue
        cve_id = body.get("cve_id")
        if not cve_id:
            print(f"  {ghsa_id}: still no CVE assigned")
            continue
        if existing_pr_with_id(ghsa_id, repo) or existing_pr_with_id(cve_id, repo):
            print(f"  {ghsa_id}: open PR already exists; skipping")
            continue
        print(f"  {ghsa_id}: CVE assigned -> {cve_id}")
        if create_assignment_pr(repo, ghsa_id, cve_id, entry, body):
            prs_opened += 1
    return prs_opened


def main() -> int:
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        print("GITHUB_REPOSITORY not set", file=sys.stderr)
        return 2

    keywords, usernames = load_keyword_config()
    print(f"Loaded {len(keywords)} text keyword(s) and "
          f"{len(usernames)} github username(s)")

    state = load_state()
    existing_yaml = load_cves_yaml()

    print("=== Forward scan ===")
    forward_prs = forward_scan(repo, keywords, usernames, state, existing_yaml)

    # Reload after forward scan in case it added entries via PRs (PRs sit on
    # branches, but main is unchanged; load again to be safe in case future
    # passes mutate the working tree differently).
    existing_yaml = load_cves_yaml()

    print("=== CVE-assignment recheck ===")
    recheck_prs = cve_assignment_recheck(repo, existing_yaml)

    save_state(state)

    print(f"Done. Opened {forward_prs} candidate/enrichment PR(s) and "
          f"{recheck_prs} CVE-assignment PR(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
