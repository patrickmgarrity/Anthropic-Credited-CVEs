#!/usr/bin/env python3
"""
Generate README.md from cves.yaml.

Reads:  cves.yaml
Reads:  .github/templates/README.template.md (preamble/postamble)
Writes: README.md

The template file contains everything in the README *except* the CVE table.
It must contain the marker line:

    <!-- BEGIN_CVE_TABLE -->
    <!-- END_CVE_TABLE -->

The renderer replaces everything between those markers with the freshly
generated table.

If no template exists, a default one is used (preserves the look of the
current README).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML not installed. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(2)


DEFAULT_TEMPLATE = """\
# ANTHROPIC CVE TRACKER

## Overview
Tracking vulnerabilities that credit the Anthropic research team and are possibly discovered by [Project Glasswing](https://www.anthropic.com/glasswing).

**CURRENT CVE COUNT: {count}**

**Fixed Anthropic Findings w/o CVE: {fixed_no_cve}**

**Findings Withdrawn by Anthropic: {withdrawn}**

## Distributions

<table>
  <tr>
    <td>
      <picture>
        <source media="(prefers-color-scheme: dark)" srcset="assets/cvss-severity-dark.svg">
        <img alt="CVSS severity distribution" src="assets/cvss-severity.svg" width="440">
      </picture>
    </td>
    <td>
      <picture>
        <source media="(prefers-color-scheme: dark)" srcset="assets/kev-exploited-dark.svg">
        <img alt="Exploited in the wild (VulnCheck KEV)" src="assets/kev-exploited.svg" width="440">
      </picture>
    </td>
  </tr>
  <tr>
    <td colspan="2">
      <picture>
        <source media="(prefers-color-scheme: dark)" srcset="assets/monthly-additions-dark.svg">
        <img alt="CVEs added per month" src="assets/monthly-additions.svg" width="880">
      </picture>
    </td>
  </tr>
</table>

## Anthropic Research

- [Tracking CVEs Attributed to Anthropic Researchers and Project Glasswing](https://www.vulncheck.com/blog/anthropic-glasswing-cves)
- [Observations on Anthropic’s Vulnerability Disclosure Ledger](https://www.vulncheck.com/blog/anthropic-ledger)
- [Has Anthropic Glasswing Lived Up to the Hype it brought this year?](https://www.vulncheck.com/blog/state-of-exploitation-1h-2026#has-anthropic-glasswing-lived-up-to-the-hype-it-brought-this-year)
- [The Anthropic Glasswing Receipts Are Starting to Trickle In](https://www.vulncheck.com/blog/anthropic-glasswing-receipts)

## Add a Vulnerability
If you find an Anthropic credited vulnerability, please open a Pull Request or Send me a message on linkedin or in the [Extended Vulnerability Community Discord](https://discord.gg/yTRXwepK).

## Considerations

This project is maintained on a best effort basis.

## The List

<!-- BEGIN_CVE_TABLE -->
<!-- END_CVE_TABLE -->
"""

MARKER_BEGIN = "<!-- BEGIN_CVE_TABLE -->"
MARKER_END = "<!-- END_CVE_TABLE -->"

# CVSS v3.x / v4.0 qualitative severity bands and their chart colors.
# Order matters: it sets the pie slice and legend order.
SEVERITY_BANDS = [
    ("Critical", 9.0, "#d32f2f"),  # red
    ("High",     7.0, "#f57c00"),  # orange
    ("Medium",   4.0, "#f9c80e"),  # yellow
    ("Low",      0.1, "#2e7d32"),  # green
]
UNSCORED_LABEL = "Unscored"
UNSCORED_COLOR = "#9e9e9e"  # gray — entries with no CVSS (or 0.0)


def severity_of(score):
    """Map a CVSS base score to its qualitative band, or None if unscored."""
    if score is None:
        return None
    try:
        score = float(score)
    except (TypeError, ValueError):
        return None
    for name, floor, _ in SEVERITY_BANDS:
        if score >= floor:
            return name
    return None  # 0.0 / negative -> no severity


def severity_counts(entries: list[dict]) -> dict[str, int]:
    counts = {name: 0 for name, _, _ in SEVERITY_BANDS}
    for e in entries:
        band = severity_of(e.get("cvss"))
        if band:
            counts[band] += 1
    return counts


def _arc_point(cx: float, cy: float, r: float, angle_deg: float) -> tuple[float, float]:
    import math
    a = math.radians(angle_deg)
    return cx + r * math.cos(a), cy + r * math.sin(a)


# Text/stroke palettes per color scheme. Slice fills are shared (they read well
# on both backgrounds); only text and the inter-slice stroke change.
CHART_THEMES = {
    "light": {"text": "#24292f", "muted": "#57606a", "stroke": "#ffffff"},
    "dark":  {"text": "#e6edf3", "muted": "#8b949e", "stroke": "#0d1117"},
}


# Exploited-in-the-wild (VulnCheck KEV) pie colors.
KEV_EXPLOITED_COLOR = "#d32f2f"  # red — known exploited (in vcKEV)
KEV_NOT_COLOR = "#9e9e9e"        # gray — not known to be exploited


def _pie_svg(title: str, segments: list[tuple[str, int, str]],
             theme: str = "light", subtitle: str | None = None) -> str:
    """Build a standalone SVG pie from ordered (label, count, color) segments.
    Colors are pinned per category (unlike Mermaid, which assigns palette colors
    by slice size). `theme` selects text/separator colors for light or dark pages.
    Layout: title band on top, pie centered below, caption beneath, legend right."""
    pal = CHART_THEMES[theme]
    total = sum(n for _, n, _ in segments)

    cx, cy, r = 140.0, 170.0, 105.0
    slices = []
    angle = -90.0  # start at 12 o'clock
    for _, n, color in segments:
        if n == 0:
            continue
        sweep = 360.0 * n / total if total else 0.0
        if n == total:  # single full-circle slice: <path> arc would degenerate
            slices.append(
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{color}" '
                f'stroke="{pal["stroke"]}" stroke-width="2"/>')
        else:
            x1, y1 = _arc_point(cx, cy, r, angle)
            x2, y2 = _arc_point(cx, cy, r, angle + sweep)
            large = 1 if sweep > 180 else 0
            slices.append(
                f'<path d="M{cx:.2f},{cy:.2f} L{x1:.2f},{y1:.2f} '
                f'A{r},{r} 0 {large} 1 {x2:.2f},{y2:.2f} Z" fill="{color}" '
                f'stroke="{pal["stroke"]}" stroke-width="2"/>')
        angle += sweep

    # legend (one row per category, vertically centered next to the pie)
    lx = 300.0
    ly = cy - (len(segments) * 30) / 2 + 8
    legend = []
    for i, (name, n, color) in enumerate(segments):
        pct = (100.0 * n / total) if total else 0.0
        # Two decimals so a tiny non-zero share (e.g. 1 of 225 = 0.44%) doesn't
        # round down to "0%" and read as "none".
        pct_str = f"{pct:.2f}%"
        y = ly + i * 30
        legend.append(
            f'<rect x="{lx}" y="{y}" width="16" height="16" rx="3" fill="{color}"/>'
            f'<text x="{lx + 24}" y="{y + 13}" font-size="14" fill="{pal["text"]}">'
            f'{name}: {n} ({pct_str})</text>')

    subtitle_line = (
        f'  <text x="{cx}" y="52" font-size="12" text-anchor="middle" '
        f'fill="{pal["muted"]}">{subtitle}</text>\n'
    ) if subtitle else ""
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="500" height="320" '
        'viewBox="0 0 500 320" font-family="-apple-system,Segoe UI,Helvetica,Arial,sans-serif">\n'
        f'  <text x="{cx}" y="34" font-size="17" font-weight="600" '
        f'text-anchor="middle" fill="{pal["text"]}">{title}</text>\n'
        + subtitle_line +
        '  ' + '\n  '.join(slices) + '\n'
        f'  <text x="{cx}" y="305" font-size="12" text-anchor="middle" '
        f'fill="{pal["muted"]}">{total} CVEs</text>\n'
        '  ' + '\n  '.join(legend) + '\n'
        '</svg>\n'
    )


def render_severity_svg(entries: list[dict], theme: str = "light") -> str:
    """SVG pie of the CVSS severity distribution (red/orange/yellow/green, plus
    gray for unscored)."""
    counts = severity_counts(entries)
    unscored = len(entries) - sum(counts.values())  # null or 0.0 CVSS
    segments = [(name, counts[name], color) for name, _, color in SEVERITY_BANDS]
    if unscored:
        segments.append((UNSCORED_LABEL, unscored, UNSCORED_COLOR))
    return _pie_svg("CVSS Severity", segments, theme)


def render_kev_svg(entries: list[dict], theme: str = "light") -> str:
    """SVG pie of exploited-in-the-wild status: red for CVEs in VulnCheck KEV,
    gray for the rest."""
    exploited = sum(1 for e in entries if e.get("vulncheck_kev"))
    segments = [
        ("Exploited", exploited, KEV_EXPLOITED_COLOR),
        ("Not exploited", len(entries) - exploited, KEV_NOT_COLOR),
    ]
    return _pie_svg("Exploited in the Wild", segments, theme,
                    subtitle="Source: VulnCheck KEV")


MONTHLY_BAR_COLOR = {"light": "#0969da", "dark": "#4493f8"}
MONTHLY_GRID_COLOR = {"light": "#d0d7de", "dark": "#30363d"}
_MONTH_ABBR = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def monthly_counts(entries: list[dict]) -> list[tuple[int, int, int]]:
    """[(year, month, count)] from each entry's `date`, oldest first, with
    empty months between the first and last filled in as zero."""
    counts: dict[tuple[int, int], int] = {}
    for e in entries:
        d = str(e.get("date") or "")
        if len(d) >= 7 and d[4] == "-":
            try:
                key = (int(d[:4]), int(d[5:7]))
            except ValueError:
                continue
            if 1 <= key[1] <= 12:
                counts[key] = counts.get(key, 0) + 1
    if not counts:
        return []
    (y, m), last = min(counts), max(counts)
    out = []
    while (y, m) <= last:
        out.append((y, m, counts.get((y, m), 0)))
        y, m = (y + 1, 1) if m == 12 else (y, m + 1)
    return out


def _nice_step(max_val: int, target_lines: int = 4) -> int:
    raw = max(1, max_val / target_lines)
    for mult in (1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000):
        if mult >= raw:
            return mult
    return int(raw)


def render_monthly_svg(entries: list[dict], theme: str = "light") -> str:
    """SVG bar chart of entries per month (by the entry's `date`). The current
    month is drawn lighter and starred because it is still in progress."""
    import datetime as _dt
    import math

    pal = CHART_THEMES[theme]
    bar_color = MONTHLY_BAR_COLOR[theme]
    grid_color = MONTHLY_GRID_COLOR[theme]
    months = monthly_counts(entries)
    today = _dt.date.today()

    W, H = 900, 320
    left, right, top, bottom = 48, 16, 64, 262  # plot area
    plot_w, plot_h = W - left - right, bottom - top
    n = max(1, len(months))
    peak = max((c for _, _, c in months), default=0)
    step = _nice_step(peak)
    y_max = max(step, math.ceil(peak / step) * step)

    def y_of(v: float) -> float:
        return bottom - plot_h * v / y_max

    parts: list[str] = []
    # horizontal gridlines + y tick labels
    v = 0
    while v <= y_max:
        y = y_of(v)
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="{W - right}" y2="{y:.1f}" '
                     f'stroke="{grid_color}" stroke-width="1"/>')
        parts.append(f'<text x="{left - 8}" y="{y + 4:.1f}" font-size="11" '
                     f'text-anchor="end" fill="{pal["muted"]}">{v}</text>')
        v += step

    slot = plot_w / n
    bar_w = min(56.0, slot * 0.7)
    label_every = max(1, math.ceil(n / 18))  # keep month labels legible
    partial_note = False
    for i, (yr, mo, c) in enumerate(months):
        cx = left + slot * (i + 0.5)
        partial = (yr, mo) == (today.year, today.month)
        partial_note |= partial
        opacity = ' fill-opacity="0.5"' if partial else ""
        if c:
            y = y_of(c)
            parts.append(f'<rect x="{cx - bar_w / 2:.1f}" y="{y:.1f}" width="{bar_w:.1f}" '
                         f'height="{bottom - y:.1f}" rx="3" fill="{bar_color}"{opacity}/>')
        parts.append(f'<text x="{cx:.1f}" y="{y_of(c) - 6:.1f}" font-size="12" '
                     f'font-weight="600" text-anchor="middle" fill="{pal["text"]}">'
                     f'{c}{"*" if partial else ""}</text>')
        if i % label_every == 0 or partial:
            parts.append(f'<text x="{cx:.1f}" y="{bottom + 18}" font-size="12" '
                         f'text-anchor="middle" fill="{pal["text"]}">{_MONTH_ABBR[mo - 1]}</text>')
            if i == 0 or mo == 1:
                parts.append(f'<text x="{cx:.1f}" y="{bottom + 34}" font-size="11" '
                             f'text-anchor="middle" fill="{pal["muted"]}">{yr}</text>')

    total = sum(c for _, _, c in months)
    caption = f"{total} CVEs by month of publication"
    if partial_note:
        caption += " · * current month to date"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'viewBox="0 0 {W} {H}" font-family="-apple-system,Segoe UI,Helvetica,Arial,sans-serif">\n'
        f'  <text x="{W / 2}" y="34" font-size="17" font-weight="600" '
        f'text-anchor="middle" fill="{pal["text"]}">Monthly Additions</text>\n'
        '  ' + '\n  '.join(parts) + '\n'
        f'  <text x="{W / 2}" y="{H - 10}" font-size="12" text-anchor="middle" '
        f'fill="{pal["muted"]}">{caption}</text>\n'
        '</svg>\n'
    )


def render_cve_cell(entry: dict) -> str:
    """Render the ID column.

    Prefer the CVE ID when present; otherwise fall back to the GHSA ID. The
    cell is linked when a corresponding *_link is set.
    """
    cve = entry.get("cve")
    if cve:
        link = entry.get("cve_link")
        return f"[{cve}]({link})" if link else cve
    ghsa = entry.get("ghsa")
    if ghsa:
        link = entry.get("ghsa_link") or f"https://github.com/advisories/{ghsa}"
        return f"[{ghsa}]({link})"
    return "—"


def render_date_cell(entry: dict) -> str:
    if entry.get("status") == "reserved" or not entry.get("date"):
        return "Reserved"
    return str(entry["date"])


def render_cvss_cell(entry: dict) -> str:
    v = entry.get("cvss")
    if v is None:
        return ""
    # Always show one decimal place (CVSS convention): 9.8, 8.0, 4.0
    return f"{v:.1f}"


def render_ledger_cell(entry: dict) -> str:
    """Link to the finding's page on Anthropic's disclosure ledger, when the
    CVE appears there. Rendered as a compact icon to keep the column narrow;
    empty when the entry has no ledger_link."""
    link = (entry.get("ledger_link") or "").strip()
    return f"[🔗]({link})" if link else ""


def render_kev_cell(entry: dict) -> str:
    """Mark CVEs known to be exploited (present in VulnCheck KEV). Compact icon
    to keep the column narrow; empty when the CVE isn't in KEV."""
    return "✅" if entry.get("vulncheck_kev") else ""


def render_credit_cell(entry: dict) -> str:
    credit = (entry.get("credit") or "").strip()
    note = (entry.get("notes") or "").strip()
    if note:
        return f"{credit} {note}".strip()
    return credit


def sort_key(entry: dict):
    """Newest first by date, then by CVE number (or GHSA ID when no CVE).
    Reserved entries float to the top of their CVE-number bucket."""
    date = entry.get("date") or ""
    ident = entry.get("cve") or entry.get("ghsa") or ""
    m = re.match(r"CVE-(\d+)-(\d+)", ident)
    cve_year = int(m.group(1)) if m else 0
    cve_seq = int(m.group(2)) if m else 0
    # Sort by (date desc, year desc, seq desc)
    return (date, cve_year, cve_seq)


def dedupe_entries(entries: list[dict]) -> list[dict]:
    """Collapse entries that share a CVE/GHSA identifier, keeping the most
    complete record (most non-empty fields; `published` wins ties). Since
    cves.yaml is union-merged (see .gitattributes), a parallel merge could in
    theory leave two rows for the same CVE; this keeps the table and count
    correct. First-seen order is otherwise preserved."""
    def completeness(e: dict) -> tuple[int, int]:
        nonnull = sum(1 for v in e.values() if v not in (None, "", "null"))
        return (nonnull, 1 if e.get("status") == "published" else 0)

    best: dict[str, dict] = {}
    order: list[str] = []
    for e in entries:
        ident = e.get("cve") or e.get("ghsa")
        if not ident:
            ident = id(e)  # keep identifier-less rows as-is
        if ident not in best:
            best[ident] = e
            order.append(ident)
        elif completeness(e) > completeness(best[ident]):
            best[ident] = e
    return [best[i] for i in order]


def _cell(value: str) -> str:
    """Make a string safe to drop into a Markdown table cell. An unescaped `|`
    starts a new column, so a multi-credit value like "A | B | C" would spill
    past the Credit column and the extra parts get dropped by the renderer.
    Escape pipes and flatten any newlines so the whole value stays in one cell."""
    return value.replace("|", "\\|").replace("\r", " ").replace("\n", " ").strip()


def render_table(entries: list[dict]) -> str:
    header = "| CVE | Date | Vendor | Product | CVSS | Ledger | vcKEV | Credit |\n"
    header += "| --- | --- | --- | --- | --- | --- | --- | --- |\n"
    rows = []
    for e in sorted(entries, key=sort_key, reverse=True):
        cells = [
            render_cve_cell(e),
            render_date_cell(e),
            (e.get("vendor") or "").strip(),
            (e.get("product") or "").strip(),
            render_cvss_cell(e),
            render_ledger_cell(e),
            render_kev_cell(e),
            render_credit_cell(e),
        ]
        rows.append("| " + " | ".join(_cell(c) for c in cells) + " |")
    return header + "\n".join(rows) + "\n"


def load_ledger_stats(repo_root: Path) -> dict:
    """Ledger-derived counts for the README header, written by scan_ledger.py to
    state/ledger_stats.json. Returns {} if the file is missing/unreadable."""
    path = repo_root / "state" / "ledger_stats.json"
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8")) or {}
        except (ValueError, OSError):
            pass
    return {}


def _stat(stats: dict, key: str) -> str:
    """Display a ledger stat, or 'n/a' if it hasn't been computed yet."""
    val = stats.get(key)
    return str(val) if val is not None else "n/a"


def render_readme(template: str, entries: list[dict],
                  stats: dict | None = None) -> str:
    stats = stats or {}
    count = len(entries)
    table = render_table(entries)
    body_block = f"{MARKER_BEGIN}\n{table}{MARKER_END}"
    template = template.replace("{count}", str(count))
    template = template.replace(
        "{fixed_no_cve}", _stat(stats, "fixed_findings_without_cve"))
    template = template.replace(
        "{withdrawn}", _stat(stats, "findings_withdrawn"))

    if MARKER_BEGIN in template and MARKER_END in template:
        pattern = re.compile(
            re.escape(MARKER_BEGIN) + r".*?" + re.escape(MARKER_END),
            re.DOTALL,
        )
        return pattern.sub(body_block, template)

    # No markers in template -> append
    return template.rstrip() + "\n\n" + body_block + "\n"


class _YamlDumper(yaml.SafeDumper):
    pass


def _str_repr(dumper, data):
    if "\n" in data or len(data) > 80:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=">")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_YamlDumper.add_representer(str, _str_repr)


def load_entries(repo_root: Path) -> list[dict]:
    """Entries live one-per-file under cves/. Each file is a single mapping.
    Falls back to the legacy single cves.yaml list if the directory is absent."""
    cves_dir = repo_root / "cves"
    if cves_dir.is_dir():
        out = []
        for path in sorted(cves_dir.glob("*.yaml")):
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            if isinstance(doc, dict):
                out.append(doc)
            elif isinstance(doc, list):  # tolerate a multi-entry file
                out.extend(d for d in doc if isinstance(d, dict))
        return out
    legacy = repo_root / "cves.yaml"
    if legacy.exists():
        return yaml.safe_load(legacy.read_text(encoding="utf-8")) or []
    return []


def write_aggregate(repo_root: Path, entries: list[dict]) -> None:
    """Regenerate the flat cves.yaml aggregate from the per-CVE files, so any
    external consumer of the single file keeps working. This file is generated
    on main (like README.md) and must not be hand-edited in contributor PRs."""
    ordered = sorted(entries, key=sort_key, reverse=True)
    (repo_root / "cves.yaml").write_text(
        yaml.dump(ordered, Dumper=_YamlDumper, sort_keys=False,
                  allow_unicode=True, width=100),
        encoding="utf-8",
    )


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    readme_path = repo_root / "README.md"
    template_path = repo_root / ".github" / "templates" / "README.template.md"

    entries = dedupe_entries(load_entries(repo_root))
    if not entries:
        print("no CVE entries found (cves/ or cves.yaml)", file=sys.stderr)
        return 1

    if template_path.exists():
        template = template_path.read_text(encoding="utf-8")
    else:
        template = DEFAULT_TEMPLATE

    rendered = render_readme(template, entries, load_ledger_stats(repo_root))
    readme_path.write_text(rendered, encoding="utf-8")
    write_aggregate(repo_root, entries)

    assets_dir = repo_root / "assets"
    assets_dir.mkdir(exist_ok=True)
    # Light is the default (cvss-severity.svg); dark is swapped in via <picture>.
    (assets_dir / "cvss-severity.svg").write_text(
        render_severity_svg(entries, "light"), encoding="utf-8")
    (assets_dir / "cvss-severity-dark.svg").write_text(
        render_severity_svg(entries, "dark"), encoding="utf-8")
    # Exploited-in-the-wild (VulnCheck KEV) pie, light + dark.
    (assets_dir / "kev-exploited.svg").write_text(
        render_kev_svg(entries, "light"), encoding="utf-8")
    (assets_dir / "kev-exploited-dark.svg").write_text(
        render_kev_svg(entries, "dark"), encoding="utf-8")
    # Monthly additions bar chart (by entry `date`), light + dark.
    (assets_dir / "monthly-additions.svg").write_text(
        render_monthly_svg(entries, "light"), encoding="utf-8")
    (assets_dir / "monthly-additions-dark.svg").write_text(
        render_monthly_svg(entries, "dark"), encoding="utf-8")

    print(f"Rendered {readme_path}, cves.yaml and severity charts "
          f"from {len(entries)} entries.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
