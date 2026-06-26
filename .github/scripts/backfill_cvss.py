#!/usr/bin/env python3
"""Backfill missing CVSS base scores from NVD.

Walks every published entry under cves/ whose `cvss` is null and looks the score
up in NVD (NIST). NVD routinely enriches records the CNA left blank, and often
adds a score days after a CVE is first published — so running this periodically
(see scan-cves.yml) self-heals entries the scanner couldn't score at creation.

Reserved entries are skipped (NVD has no score for them yet). Best-effort:
requests are spaced to respect NVD's anonymous rate limit, and any lookup that
fails or returns no score leaves the entry unchanged.

Run from the repo root:  python .github/scripts/backfill_cvss.py
"""
from __future__ import annotations

import sys
import time

from scan_cves import (
    NVD_SLEEP_SECONDS,
    fetch_nvd_cvss,
    load_cves_yaml,
    write_cve_entry,
)


def main() -> int:
    missing = [e for e in load_cves_yaml()
               if e.get("cvss") is None and e.get("status") != "reserved"]
    if not missing:
        print("No published entries are missing CVSS.")
        return 0

    print(f"{len(missing)} published entr{'y' if len(missing) == 1 else 'ies'} "
          f"missing CVSS; querying NVD...")
    updated = 0
    for i, entry in enumerate(missing):
        cve_id = entry["cve"]
        score = fetch_nvd_cvss(cve_id)
        if score is not None:
            entry["cvss"] = score
            write_cve_entry(entry)
            updated += 1
            print(f"  {cve_id}: set cvss = {score}")
        else:
            print(f"  {cve_id}: no CVSS in NVD (left null)")
        if i < len(missing) - 1:
            time.sleep(NVD_SLEEP_SECONDS)  # respect NVD rate limit

    print(f"\nBackfilled {updated}/{len(missing)} entries. "
          f"README.md and cves.yaml regenerate on merge (or run render_readme.py).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
