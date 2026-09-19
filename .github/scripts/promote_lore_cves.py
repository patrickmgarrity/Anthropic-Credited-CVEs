#!/usr/bin/env python3
"""
Promote kernel-lore issues to tracked CVEs once a CVE is assigned.

Background
----------
`scan_lore.py` opens one GitHub issue per Linux mailing-list patch that credits
an Anthropic-affiliated researcher in an attribution trailer. Those issues are
filed *before* any CVE exists: the kernel CNA assigns CVEs later and strips the
reporter credit from the CVE record entirely. So the credit lives only in the
issue (its attribution trailers), and the CVE — when it lands — lives only on the
Linux CVE announcement list.

This script joins the two. For each open `kernel-lore-candidate` issue it:

  1. reads the full patch subject + attribution trailers from the issue body,
  2. searches lore.kernel.org/linux-cve-announce for that subject (the Linux CVE
     project titles every announcement `CVE-YYYY-NNNNN: <fix subject>`),
  3. requires an EXACT normalized-subject match to a `CVE-...` entry — a fuzzy
     hit is skipped and logged, never guessed, so no wrong CVE is ever stapled
     to an issue,
  4. on a match, opens a "promotion" PR adding cves/<CVE>.yaml, with metadata
     enriched from MITRE but `credit` taken from the issue's trailers (the credit
     the kernel CNA dropped), and labels the issue `has-cve` so re-runs skip it.

If the matched CVE is already tracked, no PR is opened — the script just labels
and comments on the issue (and closes it) so the loop stays clean.

Like the keyword scanners, this NEVER commits to main directly; every promotion
is a PR the operator reviews. Set DRY_RUN=1 to print matches without touching
GitHub (issue listing still requires an authenticated `gh`).

Env:
  GITHUB_REPOSITORY      required unless DRY_RUN
  GH_TOKEN/GITHUB_TOKEN  used by `gh`
  DRY_RUN=1              print what it would do; open no PRs, apply no labels
  MAX_PROMOTIONS_PER_RUN guardrail (default 20)
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import quote
import xml.etree.ElementTree as ET

# Reuse the proven helpers from the sibling scanners (same dir).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scan_cves import (  # noqa: E402
    cve_file_path,
    existing_pr_for_cve,
    extract_summary,
    load_cves_yaml,
    run,
    write_cve_entry,
)
from scan_lore import (  # noqa: E402
    ATOM_NS,
    TRAILER_RE,
    canonical_key,
    curl,
    load_match_terms,
    strip_subject_tags,
)
from scan_ledger import normalize  # noqa: E402  (canonical field order)
from recheck_reserved import fetch_record  # noqa: E402  (MITRE cveawg lookup)

ANNOUNCE_BASE = "https://lore.kernel.org/linux-cve-announce/"
LORE_ISSUE_LABEL = "kernel-lore-candidate"
HAS_CVE_LABEL = "has-cve"
CVE_TITLE_RE = re.compile(r"^(CVE-\d{4}-\d{4,7}):\s*(.+)$")
DRY_RUN = os.environ.get("DRY_RUN") in ("1", "true", "True")


# ---------- issue parsing ----------

LORE_TITLE_PREFIX = "[kernel-lore]"


def list_lore_issues(repo: str) -> list[dict]:
    """Open kernel-lore issues that don't already carry the has-cve label.

    Selected by the `[kernel-lore]` title prefix rather than a label:
    scan_lore.py drops its `kernel-lore-candidate` label when the label doesn't
    exist in the repo (it never was created here), so a label filter would match
    nothing. The title prefix is written unconditionally, so it's reliable.
    """
    res = run(
        ["gh", "issue", "list", "--repo", repo, "--state", "open", "--json",
         "number,title,body,labels", "--limit", "500"],
        check=False,
    )
    if res.returncode != 0:
        print(f"  gh issue list failed: {res.stderr.strip()}", file=sys.stderr)
        return []
    try:
        issues = json.loads(res.stdout or "[]")
    except json.JSONDecodeError:
        return []
    out = []
    for iss in issues:
        if not (iss.get("title") or "").startswith(LORE_TITLE_PREFIX):
            continue
        labels = {l.get("name") for l in (iss.get("labels") or [])}
        if HAS_CVE_LABEL in labels:
            continue
        out.append(iss)
    return out


def parse_issue(issue: dict, terms: list[str]) -> dict:
    """Pull the full subject and the Anthropic-matched attribution trailers out
    of an issue body written by scan_lore.render_issue_body. Falls back to the
    (possibly truncated) title for the subject if the body lacks the line."""
    body = issue.get("body") or ""
    subject = ""
    lore_link = ""
    for line in body.splitlines():
        ls = line.strip()
        if not subject and ls.startswith("**Subject:**"):
            subject = ls[len("**Subject:**"):].strip()
        if not lore_link and ls.startswith("https://lore.kernel.org/"):
            lore_link = ls
    if not subject:
        title = issue.get("title", "")
        subject = re.sub(r"^\[kernel-lore\]\s*", "", title).strip()

    trailers: list[str] = []
    for line in body.splitlines():
        ls = line.strip()
        if TRAILER_RE.match(ls):
            low = ls.lower()
            if "noreply@anthropic.com" in low:
                continue  # AI-assist credit, not a human researcher
            if any(t in low for t in terms):
                trailers.append(ls)
    trailers = list(dict.fromkeys(trailers))  # dedupe, keep order
    return {"subject": subject, "trailers": trailers, "lore_link": lore_link}


def credit_from_trailers(trailers: list[str]) -> str:
    """Join the matched attribution trailers verbatim — the repo already stores
    kernel credit as the raw trailer line (see existing Linux entries)."""
    return " | ".join(trailers)


# ---------- linux-cve-announce lookup ----------

def announce_entries(subject: str, retries: int = 3) -> list[tuple[str, str]]:
    """Search linux-cve-announce for a subject; return [(cve_id, fix_subject)].

    Reuses the Anubis-aware curl + Atom handling from scan_lore. A zero-result
    query returns an HTML "search results" page (not XML) — treated as empty.
    """
    # Strip [PATCH 6.18 920/957] / [PATCH net] tags first: their tokens (version
    # numbers, "PATCH") pollute the full-text query and tank recall on the CVE
    # announcement. Match precision still comes from the exact canonical_key
    # comparison in match_cve().
    q = re.sub(r"[^A-Za-z0-9]+", " ", strip_subject_tags(subject)).strip()
    if not q:
        return []
    url = f"{ANNOUNCE_BASE}?q={quote(q)}&x=A"
    root = None
    for attempt in range(retries):
        resp = curl(url)
        stripped = resp.lstrip()
        if stripped.startswith("<?xml"):
            try:
                root = ET.fromstring(resp)
                break
            except ET.ParseError:
                time.sleep(1.5 * (attempt + 1))
                continue
        if "search results" in stripped[:400].lower():
            return []
        time.sleep(1.5 * (attempt + 1))
    if root is None:
        print(f"  warn: no Atom from announce for {subject!r} (transient)",
              file=sys.stderr)
        return []
    out = []
    for e in root.findall(f"{ATOM_NS}entry"):
        title = (e.findtext(f"{ATOM_NS}title") or "").strip()
        m = CVE_TITLE_RE.match(title)
        if m:
            out.append((m.group(1), m.group(2).strip()))
    return out


def match_cve(issue_subject: str) -> str | None:
    """Return the CVE whose announced fix-subject exactly matches this issue's
    (normalized) subject, or None. Exact-only: recall from the search query,
    precision from this equality check."""
    want = canonical_key(issue_subject)
    if not want:
        return None
    for cve_id, fix_subject in announce_entries(issue_subject):
        if canonical_key(fix_subject) == want:
            return cve_id
    return None


# ---------- entry building ----------

def build_entry(cve_id: str, credit: str) -> dict:
    """Full record for a newly-assigned kernel CVE. Metadata from MITRE; credit
    forced from the issue trailers (kernel CNA records carry none)."""
    record = None
    try:
        record = fetch_record(cve_id)
    except RuntimeError as exc:
        print(f"  {cve_id}: MITRE fetch failed ({exc})", file=sys.stderr)
    if record is not None:
        s = extract_summary(record)
        entry = {k: s[k] for k in (
            "cve", "ghsa", "date", "vendor", "product", "cvss", "credit",
            "status", "cve_link", "ghsa_link", "notes", "auto_discovered")}
    else:
        entry = {
            "cve": cve_id, "ghsa": None, "date": None,
            "vendor": "Linux", "product": "Linux", "cvss": None,
            "credit": "", "status": "reserved",
            "cve_link": f"https://www.cve.org/CVERecord?id={cve_id}",
            "ghsa_link": None, "notes": None, "auto_discovered": True,
        }
    entry["credit"] = credit or entry.get("credit") or "Anthropic"
    return normalize(entry)


# ---------- GitHub mutations ----------

def ensure_label(repo: str) -> None:
    run(["gh", "label", "create", HAS_CVE_LABEL, "--repo", repo,
         "--color", "0E8A16", "--description", "A CVE has been assigned",
         "--force"], check=False)


def label_and_comment(repo: str, issue_no: int, comment: str) -> None:
    run(["gh", "issue", "edit", str(issue_no), "--repo", repo,
         "--add-label", HAS_CVE_LABEL], check=False)
    run(["gh", "issue", "comment", str(issue_no), "--repo", repo,
         "--body", comment], check=False)


def render_pr_body(cve_id: str, issue_no: int, parsed: dict, entry: dict) -> str:
    trailers = "\n".join(f"    {t}" for t in parsed["trailers"]) or "    (none)"
    cvss = f"{entry['cvss']:.1f}" if entry.get("cvss") is not None else "(none yet)"
    return f"""## Promote {cve_id} from kernel-lore #{issue_no}

`{cve_id}` was assigned to a Linux kernel fix first surfaced as a researcher
credit in #{issue_no}. The kernel CNA strips reporter credit from its CVE
record, so `credit` here comes from the issue's attribution trailer(s) rather
than the CVE record.

**Subject:** {parsed['subject']}
**Vendor / Product:** {entry.get('vendor')} / {entry.get('product')}
**Date:** {entry.get('date') or 'Reserved'}
**CVSS:** {cvss}
**Status:** {entry.get('status')}

### Credit (from issue trailers)
```
{trailers}
```

### Links
- Source issue: #{issue_no}
- LKML message: {parsed.get('lore_link') or '(see issue)'}
- linux-cve-announce: {ANNOUNCE_BASE}?q={quote(cve_id)}&x=A
- CVE.org: https://www.cve.org/CVERecord?id={cve_id}

---
**To accept:** merge this PR — `README.md` + the `cves.yaml` aggregate regenerate
on merge, and #{issue_no} closes automatically.
**To reject:** close this PR; the issue keeps its `{HAS_CVE_LABEL}` label and
won't be re-proposed.

_Surfaced automatically by `.github/scripts/promote_lore_cves.py`._

Closes #{issue_no}
"""


def open_promotion_pr(repo: str, cve_id: str, issue_no: int,
                      parsed: dict, entry: dict) -> bool:
    branch = f"auto-lore/{cve_id.lower()}"
    base_branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()
    run(["git", "fetch", "origin", base_branch], check=False)
    run(["git", "branch", "-D", branch], check=False)
    run(["git", "checkout", "-b", branch])
    try:
        if cve_file_path(cve_id).exists():
            print(f"  {cve_id} already in cves/; skipping PR")
            return False
        path = write_cve_entry(entry)
        run(["git", "add", str(path)])
        run(["git", "commit", "-m",
             f"auto: promote {cve_id} from kernel-lore #{issue_no}"])
        run(["git", "push", "-u", "origin", branch])

        body = render_pr_body(cve_id, issue_no, parsed, entry)
        title = f"[promote] {cve_id} — from kernel-lore #{issue_no}"
        res = run(["gh", "pr", "create", "--repo", repo, "--base", base_branch,
                   "--head", branch, "--title", title, "--body", body,
                   "--label", "cve-candidate"], check=False)
        if res.returncode != 0 and "label" in res.stderr.lower():
            res = run(["gh", "pr", "create", "--repo", repo, "--base",
                       base_branch, "--head", branch, "--title", title,
                       "--body", body], check=False)
        if res.returncode != 0:
            print(f"  pr create failed: {res.stderr.strip()}", file=sys.stderr)
            return False
        print(f"  opened promotion PR for {cve_id}: {res.stdout.strip()}")
        return True
    finally:
        run(["git", "checkout", base_branch], check=False)
        run(["git", "reset", "--hard", f"origin/{base_branch}"], check=False)


# ---------- main ----------

def main() -> int:
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo and not DRY_RUN:
        print("GITHUB_REPOSITORY not set (and not DRY_RUN)", file=sys.stderr)
        return 2
    try:
        max_promotions = int(os.environ.get("MAX_PROMOTIONS_PER_RUN", "20"))
    except ValueError:
        max_promotions = 20

    terms = load_match_terms()
    issues = list_lore_issues(repo) if repo else []
    print(f"{len(issues)} open {LORE_ISSUE_LABEL} issue(s) without {HAS_CVE_LABEL}")

    tracked = {e.get("cve") for e in load_cves_yaml()}
    if not DRY_RUN and repo:
        ensure_label(repo)

    promoted = 0
    for issue in issues:
        no = issue["number"]
        parsed = parse_issue(issue, terms)
        cve_id = match_cve(parsed["subject"])
        if not cve_id:
            print(f"  #{no}: no assigned CVE yet — {parsed['subject'][:70]!r}")
            time.sleep(0.3)
            continue

        credit = credit_from_trailers(parsed["trailers"])
        print(f"  #{no}: matched {cve_id}  (credit: {credit or 'n/a'})")

        if DRY_RUN:
            print(f"    [DRY_RUN] would promote {cve_id} and label #{no}")
            continue

        # Already tracked → just close the loop on the issue.
        if cve_id in tracked or cve_file_path(cve_id).exists():
            label_and_comment(
                repo, no,
                f"Assigned **{cve_id}** — already tracked in `cves/`. "
                f"Closing; marked `{HAS_CVE_LABEL}`.")
            run(["gh", "issue", "close", str(no), "--repo", repo], check=False)
            print(f"    {cve_id} already tracked; labelled + closed #{no}")
            continue

        if existing_pr_for_cve(cve_id, repo):
            label_and_comment(repo, no,
                              f"Assigned **{cve_id}** — a PR is already open.")
            print(f"    {cve_id}: PR already open; labelled #{no}")
            continue

        if promoted >= max_promotions:
            print(f"  hit MAX_PROMOTIONS_PER_RUN={max_promotions}; deferring rest")
            break

        entry = build_entry(cve_id, credit)
        if open_promotion_pr(repo, cve_id, no, parsed, entry):
            promoted += 1
            label_and_comment(
                repo, no,
                f"Assigned **{cve_id}** — opened a promotion PR "
                f"(`credit` taken from this issue's trailers). "
                f"Marked `{HAS_CVE_LABEL}`.")
        time.sleep(0.3)

    print(f"Done. {promoted} promotion PR(s) opened.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
