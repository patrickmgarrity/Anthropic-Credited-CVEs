#!/usr/bin/env python3
"""
Local, read-only report: where do Anthropic finding IDs (ANT-2026-...) show up
in GitHub issues and PRs, and which of them does this tracker not know about?

Nothing is written to GitHub and nothing in the repo is modified; output goes to
--out (default: ./ant_github_report/).

How it works
------------
1. GitHub search (issues + PRs, all public repos except this one) for
   "ANT-2026", sliced by creation date. Search returns at most 1,000 results
   per query, so any slice over the cap is split in half until it fits.
2. GitHub tokenizes "ANT-2026" into the words ANT and 2026, so raw hits are
   noisy (Ant Design, "ant" ...). Each hit is kept only if its title/body has a
   real finding id: ANT-2026-<4-10 alnum>.
3. Hits are split into bot dependency bumps (Renovate/Dependabot quoting an
   advisory) and everything else (maintainer issues/PRs).
4. Each distinct id is classified against Anthropic's ledger and cves/:
     tracked          - the finding is already in cves/
     GAP              - on the ledger WITH a CVE/GHSA, but not in cves/
     ledger-no-id     - on the ledger, no CVE/GHSA (the README's
                        "Advisories w/o GHSA/CVE")
     not-on-ledger    - unknown to the public ledger: not yet revealed, or a
                        numeric Security Team id (ANT-2026-22436 style), which
                        the ledger doesn't use
   CVE/GHSA ids quoted next to the ANT id in the issue/PR text (Renovate and
   Dependabot PRs usually quote the advisory) also count: any of them in
   cves/ -> tracked; quoted but none tracked -> GAP.

Usage (from the repo root):
    python3 .github/scripts/report_ant_github.py --since 2026-10-01
    GITHUB_TOKEN=... python3 .github/scripts/report_ant_github.py   # 3x faster

Rate limits: search allows 10 requests/min anonymously, 30/min with a token.
The script paces itself to stay under the limit; a 30-day run is a few hundred
requests (roughly 20 min anonymous, 7 min with a token).
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import re
import sys
import time
from collections import defaultdict
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import yaml

SEARCH_URL = "https://api.github.com/search/issues"
LEDGER_URL = "https://red.anthropic.com/2026/cvd/data/ledger.json"
OWN_REPO = "patrickmgarrity/Anthropic-Credited-CVEs"
SEARCH_CAP = 1000
ANT_RE = re.compile(r"\bANT-2026-[A-Z0-9]{4,10}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
GHSA_RE = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b")
BOT_LOGINS = {"renovate[bot]", "dependabot[bot]", "renovate-bot", "mend-for-github-com[bot]",
              "red-hat-konflux[bot]", "github-actions[bot]"}
BOT_TITLE_RE = re.compile(
    r"(?i)\b(update dependency|bump\b|chore\(deps\)|deps(-dev)?:|\[security\]|lock file maintenance)")
UA = "anthropic-cve-tracker-local-report"


# ---------- HTTP ----------

class Searcher:
    def __init__(self) -> None:
        self.token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        self.interval = 2.1 if self.token else 6.2  # 30/min vs 10/min
        self.last = 0.0
        self.requests = 0

    def get(self, params: dict) -> dict:
        headers = {"User-Agent": UA, "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        url = f"{SEARCH_URL}?{urlencode(params)}"
        for attempt in range(6):
            wait = self.interval - (time.time() - self.last)
            if wait > 0:
                time.sleep(wait)
            self.last = time.time()
            self.requests += 1
            try:
                with urlopen(Request(url, headers=headers), timeout=60) as r:
                    return json.loads(r.read().decode("utf-8"))
            except HTTPError as e:
                if e.code in (403, 429):  # rate limited: wait for the reset
                    reset = e.headers.get("x-ratelimit-reset")
                    retry = e.headers.get("retry-after")
                    sleep = (int(retry) if retry else
                             max(5, int(reset) - int(time.time()) + 2) if reset else 60)
                    print(f"    rate limited; sleeping {sleep}s", file=sys.stderr)
                    time.sleep(min(sleep, 120))
                    continue
                if e.code == 422:  # e.g. page past the 1,000 cap
                    return {"total_count": 0, "items": []}
                raise
            except (URLError, TimeoutError):
                time.sleep(5 * (attempt + 1))
        raise RuntimeError(f"search failed repeatedly: {url}")


def fmt(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def search_range(s: Searcher, kind: str, start: dt.datetime, end: dt.datetime,
                 out: list[dict]) -> None:
    """Collect every hit created in [start, end), splitting until under the cap."""
    q = (f'"ANT-2026" is:{kind} -repo:{OWN_REPO} '
         f"created:{fmt(start)}..{fmt(end - dt.timedelta(seconds=1))}")
    first = s.get({"q": q, "per_page": 100, "page": 1})
    total = first.get("total_count", 0)
    if total > SEARCH_CAP and end - start > dt.timedelta(minutes=10):
        mid = start + (end - start) / 2
        search_range(s, kind, start, mid, out)
        search_range(s, kind, mid, end, out)
        return
    out.extend(first.get("items", []))
    pages = min(SEARCH_CAP, total) // 100 + (1 if min(SEARCH_CAP, total) % 100 else 0)
    for page in range(2, pages + 1):
        out.extend(s.get({"q": q, "per_page": 100, "page": page}).get("items", []))


# ---------- reference data ----------

def load_ledger() -> dict[str, dict]:
    req = Request(LEDGER_URL, headers={"User-Agent": UA})
    with urlopen(req, timeout=120) as r:
        rows = json.loads(r.read().decode("utf-8"))
    return {r["ant_id"]: r for r in rows if r.get("ant_id")}


def load_tracked(repo_root: Path) -> tuple[set[str], set[str], set[str]]:
    """(ant ids, cve ids, ghsa ids) present in cves/."""
    ants, cves, ghsas = set(), set(), set()
    for p in (repo_root / "cves").glob("*.yaml"):
        e = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if e.get("cve"):
            cves.add(e["cve"])
        if e.get("ghsa"):
            ghsas.add(e["ghsa"])
        blob = " ".join(str(e.get(k) or "") for k in ("ledger_link", "credit", "notes"))
        ants.update(ANT_RE.findall(blob))
        ants.update(re.findall(r"findings/(ANT-2026-[A-Z0-9]+)", blob))
    return ants, cves, ghsas


def classify(ant: str, ledger: dict, tracked: tuple[set, set, set],
             quoted_cves: set[str], quoted_ghsas: set[str]) -> str:
    t_ants, t_cves, t_ghsas = tracked
    row = ledger.get(ant)
    if ant in t_ants:
        return "tracked"
    if row or quoted_cves or quoted_ghsas:
        ids_c = set(row.get("cve_ids") or []) | quoted_cves if row else set(quoted_cves)
        ids_g = set(row.get("ghsa_ids") or []) | quoted_ghsas if row else set(quoted_ghsas)
        if any(c in t_cves for c in ids_c) or any(g in t_ghsas for g in ids_g):
            return "tracked"
        if ids_c or ids_g:
            return "GAP"
        return "ledger-no-id"
    return "not-on-ledger"  # no ledger row and no CVE/GHSA quoted alongside



# ---------- issues for reserved CVEs ----------

_MITRE_CACHE: dict[str, tuple[str, str]] = {}


def mitre_info(cve_id: str) -> tuple[str, str]:
    """(state, datePublished YYYY-MM-DD or "") from MITRE's CVE API.
    State is PUBLISHED / REJECTED / RESERVED; the API 404s for ids that are
    reserved but not yet published."""
    if cve_id in _MITRE_CACHE:
        return _MITRE_CACHE[cve_id]
    req = Request(f"https://cveawg.mitre.org/api/cve/{cve_id}", headers={"User-Agent": UA})
    try:
        with urlopen(req, timeout=30) as r:
            meta = json.loads(r.read().decode("utf-8"))["cveMetadata"]
            info = (meta["state"], (meta.get("datePublished") or "")[:10])
    except HTTPError as e:
        info = ("RESERVED", "") if e.code == 404 else (f"error {e.code}", "")
    except (URLError, TimeoutError, KeyError, json.JSONDecodeError) as e:
        info = (f"error {e}", "")
    _MITRE_CACHE[cve_id] = info
    time.sleep(0.2)
    return info


# ANT-2026 findings can't have a CVE published before 2026: an older CVE quoted
# next to an ANT id is a reference ("variant of CVE-2022-27781"), not the
# finding's own CVE.
FINDING_EPOCH = "2026-01-01"


def predates_findings(cve_id: str) -> bool:
    state, published = mitre_info(cve_id)
    return state == "PUBLISHED" and bool(published) and published < FINDING_EPOCH


def gh_api(method: str, path: str, token: str, body: dict | None = None):
    headers = {"User-Agent": UA, "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28", "Authorization": f"Bearer {token}"}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = Request(f"https://api.github.com{path}", data=data, headers=headers, method=method)
    with urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode("utf-8") or "null")


def existing_issue_titles(token: str | None) -> list[str]:
    """Titles of all issues (open and closed) in OWN_REPO, for de-duping."""
    titles, page = [], 1
    while True:
        path = f"/repos/{OWN_REPO}/issues?state=all&per_page=100&page={page}"
        if token:
            batch = gh_api("GET", path, token)
        else:
            with urlopen(Request(f"https://api.github.com{path}",
                                 headers={"User-Agent": UA}), timeout=60) as r:
                batch = json.loads(r.read().decode("utf-8"))
        titles += [i["title"] for i in batch if "pull_request" not in i]
        if len(batch) < 100:
            return titles
        page += 1


def cve_issues(rows: list[dict], by_id: dict) -> list[dict]:
    """One issue draft per (GAP finding, linked CVE), whatever the CVE's state."""
    drafts = []
    for r in rows:
        if r["class"] != "GAP" or not r["cve_ids"]:
            continue
        for cve in r["cve_ids"].split():
            state, _ = mitre_info(cve)
            rec = by_id[r["ant_id"]]
            links = [h["url"] for h in rec["human"]][:10]
            # Name the repo with the most maintainer activity (the likely
            # upstream), not whichever repo sorts first alphabetically.
            counts = defaultdict(int)
            for h in rec["human"]:
                counts[h["repo"]] += 1
            all_repos = r["repos"].split()
            repo = max(counts, key=counts.get) if counts else all_repos[0]
            shown = ", ".join(all_repos[:5]) + (
                f" and {len(all_repos) - 5} more" if len(all_repos) > 5 else "")
            title = f"[ant-github] {cve} ({state.lower()}) — {r['ant_id']} in {repo}"
            body = "\n".join([
                f"An Anthropic finding id was seen on GitHub next to a CVE "
                f"that this tracker doesn't have yet.",
                "",
                f"- **CVE:** [{cve}](https://www.cve.org/CVERecord?id={cve}) "
                f"({state} at MITRE as of {dt.date.today()})",
                f"- **Finding:** {r['ant_id']}",
                f"- **Upstream (most maintainer activity):** {repo}",
                f"- **Seen in {len(all_repos)} repo(s):** {shown}",
                f"- **GHSA(s) quoted:** {r['ghsa_ids'] or 'none'}",
                f"- **First seen:** {r['first_seen']}",
                "",
                "**Where it was seen:**",
                *[f"- {u}" for u in links],
                "",
                "Add it to `cves/` if the CVE is this finding's (as a reserved entry if it "
                "isn't published yet). Close this issue if the CVE is only referenced, "
                "e.g. an older, similar bug the finding is a variant or regression of.",
                "",
                "_Surfaced by `.github/scripts/report_ant_github.py`._",
            ])
            drafts.append({"cve": cve, "ant": r["ant_id"], "title": title, "body": body})
    return drafts

# ---------- main ----------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--since", default=(dt.date.today() - dt.timedelta(days=30)).isoformat(),
                    help="first creation date to search (YYYY-MM-DD; default 30 days ago)")
    ap.add_argument("--until", default=dt.date.today().isoformat(),
                    help="last creation date to search, inclusive (default today)")
    ap.add_argument("--out", default="ant_github_report", help="output directory")
    ap.add_argument("--issues", action="store_true",
                    help="draft one issue in this repo per GAP finding with a linked CVE, "
                         "any state (dry run: prints only)")
    ap.add_argument("--create", action="store_true",
                    help="with --issues: actually open the issues (token needs "
                         "Issues: read/write on this repo)")
    ap.add_argument("--reuse", action="store_true",
                    help="skip searching; rebuild the report from <out>/hits.json")
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    start = dt.datetime.fromisoformat(args.since).replace(tzinfo=dt.timezone.utc)
    stop = (dt.datetime.fromisoformat(args.until).replace(tzinfo=dt.timezone.utc)
            + dt.timedelta(days=1))
    s = Searcher()
    raw: list[dict] = []
    if args.reuse:
        hits = json.loads((Path(args.out) / "hits.json").read_text(encoding="utf-8"))
        print(f"Reusing {len(hits)} hit(s) from {args.out}/hits.json (no search)")
        day = stop  # skip the search loop
    else:
        print(f"Searching {args.since}..{args.until} "
              f"({'token' if s.token else 'anonymous, slower'})")
    day = stop if args.reuse else start
    while day < stop:
        nxt = min(day + dt.timedelta(days=1), stop)
        before = len(raw)
        for kind in ("pr", "issue"):
            search_range(s, kind, day, nxt, raw)
        print(f"  {day.date()}: {len(raw) - before} raw hit(s)")
        day = nxt

    # de-dupe and keep only real finding ids
    seen: set[str] = set()
    if not args.reuse:
        hits = []
    for it in raw:
        if it["html_url"] in seen:
            continue
        seen.add(it["html_url"])
        text = f"{it.get('title') or ''}\n{it.get('body') or ''}"
        ids = sorted(set(ANT_RE.findall(text)))
        if not ids:
            continue
        login = ((it.get("user") or {}).get("login") or "").lower()
        is_bot = login in BOT_LOGINS or login.endswith("[bot]") or bool(
            BOT_TITLE_RE.search(it.get("title") or ""))
        hits.append({
            "ids": ids,
            "cves": sorted(set(CVE_RE.findall(text))),
            "ghsas": sorted(set(GHSA_RE.findall(text))),
            "repo": it["repository_url"].split("/repos/")[1],
            "kind": "PR" if "pull_request" in it else "issue",
            "state": it["state"],
            "created": it["created_at"][:10],
            "author": login,
            "bot": is_bot,
            "title": (it.get("title") or "").strip(),
            "url": it["html_url"],
        })

    print("Loading ledger and cves/ ...")
    ledger = load_ledger()
    tracked = load_tracked(repo_root)

    by_id: dict[str, dict] = defaultdict(
        lambda: {"repos": set(), "human": [], "bot": 0, "cves": set(), "ghsas": set()})
    for h in hits:
        for a in h["ids"]:
            rec = by_id[a]
            rec["repos"].add(h["repo"])
            # Only attribute quoted CVE/GHSA ids when the text is about a single
            # advisory: one ANT id and at most one CVE + one GHSA. Grouped
            # Dependabot PRs ("Bump the python group ... 12 updates") quote many
            # unrelated advisories next to one ANT id.
            if len(h["ids"]) == 1 and len(h["cves"]) <= 1 and len(h["ghsas"]) <= 1:
                rec["cves"].update(h["cves"])
                rec["ghsas"].update(h["ghsas"])
            if h["bot"]:
                rec["bot"] += 1
            else:
                rec["human"].append(h)

    quoted = sorted({c for rec in by_id.values() for c in rec["cves"]})
    if quoted:
        print(f"Checking {len(quoted)} quoted CVE(s) at MITRE (dropping pre-{FINDING_EPOCH[:4]} references) ...")
        old = {c for c in quoted if predates_findings(c)}
        for rec in by_id.values():
            rec["cves"] -= old
        print(f"  dropped {len(old)} CVE(s) published before {FINDING_EPOCH}")

    rows = []
    for a, rec in by_id.items():
        row = ledger.get(a) or {}
        rows.append({
            "ant_id": a,
            "class": classify(a, ledger, tracked, rec["cves"], rec["ghsas"]),
            "ledger_status": row.get("status") or "",
            "project": row.get("project") or "",
            "cve_ids": " ".join(sorted(set(row.get("cve_ids") or []) | rec["cves"])),
            "ghsa_ids": " ".join(sorted(set(row.get("ghsa_ids") or []) | rec["ghsas"])),
            "repos": " ".join(sorted(rec["repos"])),
            "human_hits": len(rec["human"]),
            "bot_hits": rec["bot"],
            "first_seen": min((h["created"] for h in rec["human"]), default=""),
            "example": rec["human"][0]["url"] if rec["human"] else "",
        })
    order = {"GAP": 0, "not-on-ledger": 1, "ledger-no-id": 2, "tracked": 3}
    rows.sort(key=lambda r: (order[r["class"]], -r["human_hits"], r["ant_id"]))

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "ant_ids.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["ant_id"])
        w.writeheader()
        w.writerows(rows)
    with open(out / "hits.json", "w", encoding="utf-8") as f:
        json.dump(hits, f, indent=1)

    counts = defaultdict(int)
    for r in rows:
        counts[r["class"]] += 1
    human_hits = [h for h in hits if not h["bot"]]
    lines = [
        f"# ANT-2026 IDs on GitHub ({args.since} to {args.until})",
        "",
        f"- Raw search results: {len(raw) if not args.reuse else 'n/a (reused)'} → with a real finding id: {len(hits)} "
        f"({len(human_hits)} maintainer/other, {len(hits) - len(human_hits)} bot dependency bumps)",
        f"- Distinct finding ids: {len(rows)}",
        f"- **GAP** (has a CVE/GHSA via ledger or quoted on GitHub, not in cves/): {counts['GAP']}",
        f"- **not-on-ledger** (no ledger row, no CVE/GHSA quoted): {counts['not-on-ledger']}",
        f"- ledger-no-id (on ledger, no CVE/GHSA): {counts['ledger-no-id']}",
        f"- tracked: {counts['tracked']}",
        "",
    ]
    for cls, heading in (("GAP", "GAP: should probably be tracked"),
                         ("not-on-ledger", "No CVE/GHSA anywhere (not on ledger, none quoted)"),
                         ("ledger-no-id", "On the ledger without a CVE/GHSA")):
        sel = [r for r in rows if r["class"] == cls]
        if not sel:
            continue
        lines += [f"## {heading} ({len(sel)})", "",
                  "| ANT id | Project / repos | CVE / GHSA | Maintainer hits | Bot hits | First seen | Example |",
                  "|---|---|---|---|---|---|---|"]
        for r in sel:
            ids = " ".join(x for x in (r["cve_ids"], r["ghsa_ids"]) if x) or "—"
            proj = r["project"] or r["repos"][:60]
            ex = f"[link]({r['example']})" if r["example"] else ""
            lines.append(f"| {r['ant_id']} | {proj} | {ids} | {r['human_hits']} | "
                         f"{r['bot_hits']} | {r['first_seen']} | {ex} |")
        lines.append("")
    (out / "report.md").write_text("\n".join(lines), encoding="utf-8")

    if args.issues:
        print("\nChecking linked CVEs at MITRE ...")
        drafts = cve_issues(rows, by_id)
        existing = existing_issue_titles(s.token)
        for d in drafts:
            if any(d["cve"] in t and d["ant"] in t for t in existing):
                print(f"  skip {d['cve']} / {d['ant']}: issue already exists")
                continue
            if args.create:
                if not s.token:
                    print("  --create needs GITHUB_TOKEN with Issues: read/write", file=sys.stderr)
                    break
                res = gh_api("POST", f"/repos/{OWN_REPO}/issues", s.token,
                             {"title": d["title"], "body": d["body"]})
                print(f"  opened {res['html_url']}")
                existing.append(d["title"])
            else:
                print(f"\n  [dry run] would open: {d['title']}\n" +
                      "\n".join("    " + ln for ln in d["body"].splitlines()))
        if not drafts:
            print("  no GAP findings with a linked CVE")

    print(f"\nDone in {s.requests} search request(s).")
    print("\n".join(lines[2:9]))
    print(f"\nWrote {out}/report.md, {out}/ant_ids.csv, {out}/hits.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
