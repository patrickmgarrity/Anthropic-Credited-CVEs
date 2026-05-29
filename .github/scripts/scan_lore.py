#!/usr/bin/env python3
"""
Incrementally scan lore.kernel.org (the LKML public-inbox archive) for kernel
patches/discussions that credit Anthropic-affiliated people in an attribution
trailer, and open one GitHub issue per *new* finding.

Why this exists
---------------
The Linux kernel CNA strips reporter/author attribution from its CVE records
(see CVE-2026-43185: the JSON has no `credits` field, only git commit links).
The credit lives only in the commit message trailers
(`Reported-by:`, `Signed-off-by:`, `Co-developed-by:`, ...), which `scan_cves.py`
never sees. Many of these fixes also land *without* a CVE, or get one much later.

So we watch the source where the credit actually exists: the mailing list.

Strategy (mirrors scan_cves.py's incremental model)
---------------------------------------------------
  1. Build match terms from keywords.yaml: email domains (e.g. anthropic.com,
     doyensec.com) + multi-word researcher names. The domain alone catches every
     @anthropic.com address (npc@, srxzr@, bmorris@, noreply@ ...); the names
     catch people committing under personal emails (e.g. nicholas@carlini.com).
  2. For each term, query the public-inbox search Atom feed, restricted to
     messages received since our last run (`rt:<YYYYMMDD>..`).
  3. For each result we haven't seen before (by message URL), fetch the raw
     message and keep it only if a match term appears in an *attribution trailer*
     line. That trailer filter is what separates real credits from the (large)
     volume of LKML threads merely discussing Anthropic/AI.
  4. Collapse stable-tree backports of the same fix to a single "finding" so we
     don't open 11 issues for one patch.
  5. Open one GitHub issue per new finding (unless DRY_RUN). Persist state so
     re-runs never re-open the same finding.

State: state/lore_seen.json
  {
    "last_run_date": "YYYYMMDD",          # advanced each successful run
    "seen_message_ids": [...],            # message URLs already processed
    "opened_finding_keys": [...]          # canonical fix keys we've filed issues for
  }

Env:
  GITHUB_REPOSITORY   required unless DRY_RUN (e.g. "owner/repo")
  GH_TOKEN/GITHUB_TOKEN  used by `gh` for issue creation
  DRY_RUN=1           print findings instead of creating issues (local testing)
  FIRST_RUN_DAYS      backfill window on the very first run (default 14)
  MAX_ISSUES_PER_RUN  guardrail against flooding (default 30)
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote
import xml.etree.ElementTree as ET

import yaml

ATOM_NS = "{http://www.w3.org/2005/Atom}"
KEYWORDS_PATH = Path("keywords.yaml")
STATE_PATH = Path("state/lore_seen.json")
LORE_BASE = "https://lore.kernel.org/all/"
USER_AGENT = "anthropic-cve-tracker (+github actions)"  # non-Mozilla UA passes Anubis

# Attribution trailers only. `Link:`/`Closes:` are deliberately excluded — they
# carry reference URLs (blog posts, patch.msgid.link), not credits, and produced
# false positives (e.g. `Link: https://blog.calif.io/...`).
TRAILER_RE = re.compile(
    r"^(Reported-by|Signed-off-by|Co-developed-by|Co-authored-by|Suggested-by|"
    r"Tested-by|Acked-by|Reviewed-by|Found-by|Reported-and-tested-by):",
    re.IGNORECASE,
)

# Administrative / non-finding messages that carry a credit trailer but aren't
# original work: stable-tree bounce notices and maintainer-file changes. Applied
# to the subject *after* stripping Re:/Fwd: and [..] tags.
NOISE_SUBJECT_RE = re.compile(
    r"(?i)^(failed\b|patch\b.*\bhas been added\b|maintainers:)",
)


def strip_subject_tags(subject: str) -> str:
    s = re.sub(r"(?i)^(re:|fwd:)\s*", "", subject).strip()
    s = re.sub(r"^(\[[^\]]*\]\s*)+", "", s)  # leading [PATCH ...] / [tip: ...] tags
    return s.strip().strip('"')

DRY_RUN = os.environ.get("DRY_RUN") in ("1", "true", "True")


# ---------- keywords ----------

def load_match_terms() -> list[str]:
    """Email domains + multi-word names from keywords.yaml, lowercased.

    Bare single-word org names (e.g. "Anthropic") are intentionally excluded:
    the domain `anthropic.com` already catches their addresses inside trailers,
    and the bare word produces noise.
    """
    raw = yaml.safe_load(KEYWORDS_PATH.read_text(encoding="utf-8")) or {}
    kws = raw.get("keywords", []) if isinstance(raw, dict) else (raw or [])
    terms: list[str] = []
    for k in kws:
        k = str(k).strip()
        if not k:
            continue
        is_domain = ("." in k) and (" " not in k)
        is_name = " " in k
        if is_domain or is_name:
            terms.append(k.lower())
    return sorted(set(terms))


# ---------- state ----------

def load_state() -> dict:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text())
        except json.JSONDecodeError:
            pass
    return {"last_run_date": None, "seen_message_ids": [], "opened_finding_keys": []}


def save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Keep the seen list bounded; these terms are low-volume so this is generous.
    state["seen_message_ids"] = sorted(set(state["seen_message_ids"]))[-5000:]
    state["opened_finding_keys"] = sorted(set(state["opened_finding_keys"]))[-5000:]
    STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")


# ---------- http ----------

def curl(url: str, timeout: int = 45) -> str:
    proc = subprocess.run(
        ["curl", "-s", "-A", USER_AGENT, "--max-time", str(timeout), url],
        capture_output=True,
    )
    return proc.stdout.decode("utf-8", errors="replace")


def feed_entries(term: str, since: str, retries: int = 3) -> list[dict]:
    """Return [{title, link, updated}] for a term restricted to rt:<since>..

    lore is fronted by Anubis, which intermittently serves an HTML challenge
    instead of the Atom feed. Detect a non-XML response and retry.
    """
    # public-inbox uses space as implicit AND; the literal word "AND" is a
    # search token, not an operator. Date filter is `d:` (the Date header).
    q = f'"{term}"' if " " in term else term
    if since:
        q = f"{q} d:{since}.."
    url = f"{LORE_BASE}?q={quote(q)}&x=A"
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
        # public-inbox returns an HTML "search results" page (ignoring x=A) when
        # there are zero matches. That's a valid empty result, not an error.
        if "search results" in stripped[:400].lower():
            return []
        # Anything else (empty body, Anubis challenge) is transient: back off & retry.
        time.sleep(1.5 * (attempt + 1))
    if root is None:
        print(f"  warn: no Atom for {term!r} after {retries} tries (transient)", file=sys.stderr)
        return []
    out = []
    for e in root.findall(f"{ATOM_NS}entry"):
        link_el = e.find(f"{ATOM_NS}link")
        href = link_el.get("href") if link_el is not None else None
        if not href:
            continue
        out.append({
            "title": (e.findtext(f"{ATOM_NS}title") or "").strip(),
            "link": href.rstrip("/"),
            "updated": (e.findtext(f"{ATOM_NS}updated") or "")[:10],
        })
    return out


# ---------- raw message parsing ----------

def parse_raw(raw: str, terms: list[str]) -> dict | None:
    """If a term appears in an attribution trailer, return finding metadata."""
    subject = date = frm = ""
    matched: list[str] = []
    for line in raw.splitlines():
        ls = line.strip()
        if not subject and line.lower().startswith("subject:"):
            subject = line[8:].strip()
        elif not date and line.lower().startswith("date:"):
            date = line[5:].strip()
        elif not frm and line.lower().startswith("from:"):
            frm = line[5:].strip()
        if TRAILER_RE.match(ls):
            low = ls.lower()
            # Skip Claude/AI-assist credits (Co-authored-by/Reviewed-by Claude
            # <noreply@anthropic.com>). We only track human researcher credits.
            if "noreply@anthropic.com" in low:
                continue
            if any(t in low for t in terms):
                matched.append(ls)
    if not matched:
        return None
    if NOISE_SUBJECT_RE.match(strip_subject_tags(subject)):
        return None  # stable bounce / "has been added" / MAINTAINERS change
    return {
        "subject": subject,
        "date": date,
        "from": frm,
        "trailers": list(dict.fromkeys(matched)),  # dedupe, keep order
    }


def canonical_key(subject: str) -> str:
    """Collapse stable-backport variants of one fix to a single key."""
    s = strip_subject_tags(subject)
    s = re.sub(r"(?i)\s+(failed to apply|has been added).*$", "", s)
    s = re.sub(r"\s+", " ", s).strip().lower()
    return s


# ---------- issue creation ----------

def issue_exists(repo: str, finding_key: str) -> bool:
    """Defensive check in addition to state: is there already an issue for this fix?"""
    res = subprocess.run(
        ["gh", "issue", "list", "--repo", repo, "--state", "all",
         "--search", finding_key, "--json", "title", "--limit", "5"],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        return False
    try:
        items = json.loads(res.stdout or "[]")
    except json.JSONDecodeError:
        return False
    return bool(items)


def render_issue_body(f: dict, link: str, terms_hit: set[str]) -> str:
    trailers = "\n".join(f"    {t}" for t in f["trailers"])
    hit = ", ".join(f"`{t}`" for t in sorted(terms_hit))
    return f"""## Kernel attribution match — researcher-credited

A Linux kernel mailing-list message credits an Anthropic-affiliated party in an
attribution trailer. The kernel CNA strips this from CVE records, so it would
not be caught by `scan_cves.py`.

**Subject:** {f['subject']}
**From:** {f['from']}
**Date:** {f['date']}
**Matched term(s):** {hit}

### Attribution trailer(s)
```
{trailers}
```

### Link
{link}

---
### Triage checklist
- [ ] Is this a security fix (vs. tooling/maintainer/AI-assist contribution)?
- [ ] Does it already have a CVE? (check `git.kernel.org` commit → kernel CNA)
- [ ] If yes and not yet tracked: add to `cves.yaml` and re-render.
- [ ] If no CVE: keep for monitoring / close if out of scope.

_Surfaced automatically by `.github/workflows/scan-lore.yml`._
"""


def create_issue(repo: str, f: dict, link: str, terms_hit: set[str]) -> bool:
    title = f"[kernel-lore] {f['subject'][:120]}"
    body = render_issue_body(f, link, terms_hit)
    args = ["gh", "issue", "create", "--repo", repo, "--title", title, "--body", body,
            "--label", "kernel-lore-candidate"]
    res = subprocess.run(args, capture_output=True, text=True)
    if res.returncode != 0 and "label" in res.stderr.lower():
        # label may not exist yet; retry without it
        res = subprocess.run(args[:-2], capture_output=True, text=True)
    if res.returncode != 0:
        print(f"  issue create failed: {res.stderr.strip()}", file=sys.stderr)
        return False
    print(f"  opened issue: {res.stdout.strip()}")
    return True


# ---------- main ----------

def main() -> int:
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo and not DRY_RUN:
        print("GITHUB_REPOSITORY not set (and not DRY_RUN)", file=sys.stderr)
        return 2

    try:
        first_run_days = int(os.environ.get("FIRST_RUN_DAYS", "14"))
    except ValueError:
        first_run_days = 14
    try:
        max_issues = int(os.environ.get("MAX_ISSUES_PER_RUN", "30"))
    except ValueError:
        max_issues = 30

    terms = load_match_terms()
    print(f"Loaded {len(terms)} match term(s): {', '.join(terms)}")

    state = load_state()
    seen = set(state.get("seen_message_ids", []))
    opened_keys = set(state.get("opened_finding_keys", []))

    now = datetime.now(timezone.utc)
    if state.get("last_run_date"):
        # Re-query from the last run date (inclusive) — seen_message_ids dedupes
        # the boundary overlap.
        since = state["last_run_date"]
    else:
        since = (now - timedelta(days=first_run_days)).strftime("%Y%m%d")
        print(f"  first run: backfilling {first_run_days} day(s) from {since}")

    # 1. Gather candidate messages across all terms.
    candidates: dict[str, set[str]] = {}  # link -> terms that surfaced it
    for term in terms:
        for entry in feed_entries(term, since):
            candidates.setdefault(entry["link"], set()).add(term)
        time.sleep(0.3)
    print(f"  {len(candidates)} candidate message(s) since {since}")

    # 2. Fetch + trailer-filter the ones we haven't processed.
    findings: dict[str, dict] = {}  # finding_key -> {finding, link, terms_hit}
    new_seen: list[str] = []
    for link, surfaced_terms in candidates.items():
        if link in seen:
            continue
        new_seen.append(link)
        raw = curl(link + "/raw")
        time.sleep(0.2)
        if not raw:
            continue
        f = parse_raw(raw, terms)
        if not f:
            continue
        # Confirm which terms actually landed in a trailer (for reporting).
        joined = " ".join(f["trailers"]).lower()
        terms_hit = {t for t in terms if t in joined} or surfaced_terms
        key = canonical_key(f["subject"])
        # Keep the representative with the cleanest subject (no version numbers / FAILED).
        if key not in findings or not re.search(r"(?i)failed|\d+/\d+|has been added", f["subject"]):
            findings[key] = {"finding": f, "link": link, "terms_hit": terms_hit}

    print(f"  {len(findings)} distinct new finding(s) after trailer filter")

    # 3. Open issues for findings we haven't filed before.
    issues_opened = 0
    for key, data in findings.items():
        if key in opened_keys:
            continue
        f = data["finding"]
        if DRY_RUN:
            print(f"\n[DRY_RUN] would open issue:")
            print(f"  subject : {f['subject']}")
            print(f"  date    : {f['date']}")
            print(f"  link    : {data['link']}")
            for t in f["trailers"]:
                print(f"    >> {t}")
            opened_keys.add(key)
            continue
        if issues_opened >= max_issues:
            print(f"  hit MAX_ISSUES_PER_RUN={max_issues}; deferring the rest to next run")
            # Don't mark these seen/opened so they're picked up next run.
            break
        if key in opened_keys or issue_exists(repo, key):
            opened_keys.add(key)
            continue
        if create_issue(repo, f, data["link"], data["terms_hit"]):
            issues_opened += 1
            opened_keys.add(key)

    # 4. Persist state.
    state["seen_message_ids"] = sorted(seen | set(new_seen))
    state["opened_finding_keys"] = sorted(opened_keys)
    state["last_run_date"] = now.strftime("%Y%m%d")
    if not DRY_RUN:
        save_state(state)
        print(f"Done. {issues_opened} issue(s) opened. State advanced to {state['last_run_date']}.")
    else:
        print(f"\n[DRY_RUN] {len(findings)} finding(s); state NOT written.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
