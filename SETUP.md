# Anthropic CVE Tracker — Setup & Operation

End-to-end automation for tracking CVEs that credit Anthropic, Anthropic researchers, or known Anthropic collaborators, using only GitHub Actions (no external infrastructure).

---

## What this does

1. **Every 2 hours**, scans the official CVE feed (`CVEProject/cvelistV5`) for any new or updated CVE record that mentions a keyword you care about (Anthropic, researcher names, etc.).
2. For each match, opens a **Pull Request** that adds a structured YAML entry to `cves.yaml` and regenerates `README.md`.
3. You **merge** the PR to publish the entry, or **close** it to mark the CVE as "reviewed and skipped" forever.
4. You can also edit `cves.yaml` directly (or add/remove keywords in `keywords.yaml`) — README re-renders automatically.

The scanner uses `cves/deltaLog.json` (a 30-day history), so even multi-day outages catch up cleanly with no missed CVEs.

---

## File layout

Drop everything from this bundle into your repo, preserving paths exactly:

```
your-repo/
├── cves.yaml                                    # source-of-truth data (pre-seeded with your 80 entries)
├── keywords.yaml                                # what to look for (edit anytime)
├── state/
│   └── seen.json                                # bookkeeping (auto-maintained)
└── .github/
    ├── workflows/
    │   ├── scan-cves.yml                        # scheduled scanner
    │   └── render-readme.yml                    # README regenerator
    └── scripts/
        ├── scan_cves.py                         # the scanner
        ├── render_readme.py                     # YAML → README
        └── migrate_readme.py                    # one-shot README → YAML (already run)
```

Your existing `README.md` stays in place. The first time `render-readme.yml` runs, it will regenerate the README from `cves.yaml` and overwrite it. The content will be identical except for some minor whitespace normalization.

---

## Deployment (10 minutes)

### 1. Add the files to your repo

Either commit them via git, or upload them through the GitHub web UI. Make sure paths match the layout above.

### 2. Enable workflow permissions

GitHub Actions need permission to create branches, open PRs, and commit. In your repo:

**Settings → Actions → General → Workflow permissions**
- Select **"Read and write permissions"**
- Check **"Allow GitHub Actions to create and approve pull requests"**
- Click **Save**

### 3. (Optional) Create a label

The scanner labels its PRs `cve-candidate`. Create the label so filtering works nicely:

**Issues → Labels → New label** → name: `cve-candidate`, any color.

(If you skip this, the scanner falls back to creating PRs without the label — still works.)

### 4. Verify the renderer first

In the **Actions** tab, find **"Render README from cves.yaml"** and click **Run workflow**.

This regenerates `README.md` from the pre-seeded `cves.yaml`. Open the resulting commit and confirm the README looks right. If something's off, fix it before the scanner starts opening PRs.

### 5. Run the scanner

In the **Actions** tab, find **"Scan cvelistV5 for Anthropic-mentioned CVEs"** and click **Run workflow**.

The first run only processes the most-recent batch (typically 3-15 CVEs, ~5 seconds). It will:
- Update `state/seen.json` with the timestamp
- Open a PR if it finds any matches (unlikely on first run unless one of those few CVEs happens to mention Anthropic)

After that, it runs automatically every 2 hours.

---

## Daily operation

### When the scanner finds a match
A PR titled `[candidate] CVE-XXXX-XXXX — keyword match` appears in your repo. The PR body shows:
- Which keywords matched in which fields (e.g. "credits: anthropic, nicholas carlini")
- Vendor, product, date, CVSS (if available)
- The full credit string from the record
- The description
- Links to CVE.org, NVD, and the raw record

**To accept:** click **Merge**. The entry lands in `cves.yaml`. The `render-readme.yml` workflow regenerates `README.md` and commits it within a minute.

**To reject:** click **Close**. The CVE is recorded in `state/seen.json` and won't be proposed again.

**To tweak before merging:** edit `cves.yaml` directly in the PR's "Files changed" tab (CVSS, vendor name, notes, etc.), commit on the branch, then merge.

### Adding a CVE you found independently
Edit `cves.yaml` directly. Two ways:

**On github.com:** open the file → pencil icon ✏️ → paste a new entry at the top → commit (directly to main, or via PR).

**Locally:**
```bash
git pull
$EDITOR cves.yaml          # add an entry, copy the format from an existing one
git add cves.yaml
git commit -m "add CVE-XXXX-XXXX (manual)"
git push
```

Either way, the `render-readme.yml` workflow fires automatically and updates `README.md`. You don't touch README directly.

Entry format:
```yaml
- cve: CVE-2026-XXXXX
  date: 2026-01-15           # or null for reserved
  vendor: Vendor Name
  product: Product Name
  cvss: 9.8                  # or null if unknown
  credit: >-
    Researcher Name from Anthropic
  status: published          # published | reserved
  cve_link: null             # optional override URL for the CVE column
  notes: null                # e.g. "NOT IN CVE TABLE"
  auto_discovered: false
```

### Editing the keyword list
Open `keywords.yaml` on github.com, edit, commit. The next scheduled scan uses the new list. No deploy step needed.

The current list includes Anthropic, Calif.io, anthropic.com, and 8 researcher names. Add more whenever you discover a new researcher who should trigger the alarm.

### Changing the schedule
Edit `.github/workflows/scan-cves.yml`. The cron line is:

```yaml
- cron: "17 */2 * * *"   # every 2 hours at :17
```

Common alternatives:
- Hourly: `"17 * * * *"`
- Every 30 min: `"*/30 * * * *"` (fine, the script is cheap)
- Daily 8am UTC: `"0 8 * * *"`

---

## Backfill on first deploy

By default, the first scanner run only processes the most-recent batch (~3-15 CVEs). If you want to backfill more history on the first run — say, the past 24 hours — set the `FIRST_RUN_BATCHES` environment variable.

To do this once, edit `.github/workflows/scan-cves.yml` and temporarily add it under the scanner step:

```yaml
- name: Run scanner
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    GITHUB_REPOSITORY: ${{ github.repository }}
    FIRST_RUN_BATCHES: "100"     # ← add this; remove after first run
  run: python .github/scripts/scan_cves.py
```

Each batch is one cvelistV5 commit, ~3-30 CVEs. `100` batches typically covers ~6-12 hours of activity. Remove the variable after the first run completes so subsequent runs use the resume-from-state behavior.

---

## Troubleshooting

### "The scanner ran but no PR was opened, even though I expected one"
Check the Actions log. Common reasons:
- The CVE record genuinely has no keyword in its JSON (this is the Linux-kernel / Ghost-CMS scenario discussed earlier — those credits live outside cvelistV5).
- The CVE is already in `cves.yaml` (it's skipped silently as "already curated").
- A PR was already opened previously and closed; the CVE is now in `state/seen.json`.

### "I closed a PR and now I want it back"
Edit `state/seen.json` and remove the CVE ID from `seen_cve_ids`. Then run the scanner manually (set `FIRST_RUN_BATCHES` high if needed, or re-set `last_fetch_timestamp` to `null` to redo from scratch).

### "The README looks wrong / I want to change the prose around the table"
The renderer uses a built-in default template. To override, create `.github/templates/README.template.md` containing your preferred prose with these two markers somewhere in it:

```
<!-- BEGIN_CVE_TABLE -->
<!-- END_CVE_TABLE -->
```

The renderer replaces everything between the markers with the generated table. Use `{count}` anywhere in the template to inject the current entry count.

### "I want to re-migrate from the current README"
Don't — `cves.yaml` is now the source of truth. If you really need to, the migration script is in `.github/scripts/migrate_readme.py` and can be re-run, but it'll overwrite any structured edits you've made.

### "I'm getting Linux kernel CVEs missed"
Confirmed limitation — those credits live in kernel.org's `linux-cve-announce` feed, not cvelistV5. The scanner cannot find them in the source it has. Adding a second-source ingestor is a clean extension if you want it later.

---

## Known coverage gaps (recap)

The scanner sees only what's in the cvelistV5 record JSON. It will catch:
- Anything where the CNA put credit info in the record (most vendors)
- Anything mentioning Anthropic / known researchers / Calif.io / anthropic.com in description, references, etc.

It will miss:
- Linux kernel CVEs (credit lives in upstream commits, not the CVE record)
- Vendor advisories not yet assigned a CVE
- GHSA advisories that haven't been pushed upstream to MITRE

For these, manual addition via `cves.yaml` edit (see above) remains the fallback.
