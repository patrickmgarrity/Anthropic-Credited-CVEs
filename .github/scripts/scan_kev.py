#!/usr/bin/env python3
"""
Mark tracked CVEs that appear in VulnCheck KEV (Known Exploited Vulnerabilities).

Pulls the full vulncheck-kev index once (paginated) via the VulnCheck SDK, then
cross-references it against cves/. For every tracked CVE that is in KEV it sets:

    vulncheck_kev: true
    kev_date_added: 'YYYY-MM-DD'   # date VulnCheck added it to KEV

and it removes those fields from any record no longer in KEV, so the marker
stays accurate. Pulling the whole index once is far cheaper than one API call
per tracked CVE (mirrors the pagination pattern used elsewhere at VulnCheck).

Authoritative data enrichment of existing records — like backfill_cvss.py and
the ledger sync, it writes straight to cves/ and lets the workflow commit to
main. Declarative and idempotent: unchanged records are rewritten byte-identical
(no churn), so no state file is needed.

Auth: the API token is read from the VULNCHECK_API_TOKEN environment variable
(set it as a repository secret and pass it through in the workflow). If the
variable is unset the script no-ops with a message, so runs without the secret
(forks, PRs) don't fail.

Env:
  VULNCHECK_API_TOKEN   required to do anything; absent -> skip
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scan_cves import CVES_DIR, write_cve_entry  # noqa: E402
from scan_ledger import normalize  # noqa: E402  (canonical field order)

VULNCHECK_HOST = "https://api.vulncheck.com"
VULNCHECK_API = VULNCHECK_HOST + "/v3"
PAGE_LIMIT = 2000
KEV_FIELDS = ("vulncheck_kev", "kev_date_added")


def load_kev_index(token: str) -> dict[str, dict]:
    """Return {cve_id: {"date_added": 'YYYY-MM-DD'|None}} for all of VulnCheck
    KEV, walking the cursor-paginated index. Uses the official vulncheck_sdk,
    matching the standard VulnCheck client pattern."""
    import vulncheck_sdk  # imported lazily so the module only needs it at runtime

    cfg = vulncheck_sdk.Configuration(host=VULNCHECK_API)
    cfg.api_key["Bearer"] = token

    kev: dict[str, dict] = {}

    def ingest(resp) -> None:
        for entry in resp.data:
            date_added = (entry.date_added or "")[:10] or None
            for cve in (entry.cve or []):
                kev[cve] = {"date_added": date_added}

    with vulncheck_sdk.ApiClient(cfg) as api_client:
        api = vulncheck_sdk.IndicesApi(api_client)
        resp = api.index_vulncheck_kev_get(start_cursor="true", limit=PAGE_LIMIT)
        ingest(resp)
        while resp.meta.next_cursor is not None:
            resp = api.index_vulncheck_kev_get(
                cursor=resp.meta.next_cursor, limit=PAGE_LIMIT)
            ingest(resp)
    return kev


def apply_kev(entry: dict, info: dict | None) -> dict | None:
    """Return the entry with KEV fields set/cleared to reflect `info`, or None
    if nothing changed (so callers can skip a byte-identical rewrite)."""
    if info:
        if (entry.get("vulncheck_kev") is True
                and entry.get("kev_date_added") == info["date_added"]):
            return None
        updated = dict(entry)
        updated["vulncheck_kev"] = True
        updated["kev_date_added"] = info["date_added"]
        return normalize(updated)
    # not in KEV: strip any stale marker
    if any(k in entry for k in KEV_FIELDS):
        return normalize({k: v for k, v in entry.items() if k not in KEV_FIELDS})
    return None


def main() -> int:
    token = os.environ.get("VULNCHECK_API_TOKEN")
    if not token:
        print("VULNCHECK_API_TOKEN not set; skipping VulnCheck KEV sync.")
        return 0

    try:
        kev = load_kev_index(token)
    except ImportError:
        print("vulncheck-sdk not installed (pip install vulncheck-sdk); "
              "skipping.", file=sys.stderr)
        return 0
    print(f"Pulled {len(kev)} CVE(s) from VulnCheck KEV.")

    marked = cleared = 0
    for path in sorted(CVES_DIR.glob("*.yaml")):
        entry = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(entry, dict):
            continue
        result = apply_kev(entry, kev.get(entry.get("cve")))
        if result is None:
            continue
        write_cve_entry(result)
        if result.get("vulncheck_kev"):
            marked += 1
            print(f"  🛑 {entry['cve']} in KEV (added {result['kev_date_added']})")
        else:
            cleared += 1
            print(f"  cleared stale KEV marker on {entry['cve']}")

    print(f"Done. {marked} KEV marker(s) set/updated, {cleared} cleared.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
