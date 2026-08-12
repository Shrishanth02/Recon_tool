"""Generate a self-contained, printable HTML engagement report.

The HTML is styled for both screen and print (Ctrl/Cmd+P → Save as PDF), so it
doubles as the client deliverable without pulling in a heavy PDF dependency.
"""

import html
from datetime import datetime, timezone

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_COLOR = {
    "critical": "#b91c1c",
    "high": "#dc2626",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#64748b",
}

# A coarse engagement risk rating from the highest-severity findings present.
def _risk_rating(counts: dict) -> str:
    if counts.get("critical"):
        return "Critical"
    if counts.get("high"):
        return "High"
    if counts.get("medium"):
        return "Medium"
    if counts.get("low"):
        return "Low"
    return "Informational"


def _esc(v) -> str:
    return html.escape(str(v if v is not None else ""))


def generate(
    project: dict,
    findings: list,
    scans: list,
    branding: dict | None = None,
) -> str:
    """Render the engagement report, optionally white-labelled.

    ``branding`` is an optional dict with any of ``brand_name``,
    ``brand_primary_color``, ``brand_logo_url`` and ``report_footer``. When it is
    ``None`` (or empty) the output is byte-for-byte identical to the original
    unbranded RECON-X report, so every existing caller is unaffected. When
    provided, ``brand_name`` drives the header/title, ``brand_primary_color`` the
    accent color, ``brand_logo_url`` an optional header logo, and
    ``report_footer`` an extra note appended to the disclaimer area.
    """
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    real = [f for f in findings if f["severity"] != "info"]
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rating = _risk_rating(counts)

    # --- Branding (all optional; absent -> byte-compatible defaults) -------- #
    branding = branding or {}
    brand_name = (branding.get("brand_name") or "").strip()
    accent = (branding.get("brand_primary_color") or "").strip() or "#0d9488"
    logo_url = (branding.get("brand_logo_url") or "").strip()
    footer_note = (branding.get("report_footer") or "").strip()

    # Document <title> prefix and the header brand block.
    title_brand = _esc(brand_name) if brand_name else "RECON-X"
    if brand_name:
        logo_html = (
            f'<img src="{_esc(logo_url)}" alt="" '
            f'style="height:40px;vertical-align:middle;margin-right:10px">'
            if logo_url
            else ""
        )
        brand_inner = f"{logo_html}{_esc(brand_name)}"
    else:
        brand_inner = "RECON<span>-X</span>"
    footer_html = (
        f'\n    <div style="margin-top:10px">{_esc(footer_note)}</div>'
        if footer_note
        else ""
    )

    scope = project.get("scope") or []
    scope_html = (
        ", ".join(_esc(s) for s in scope) if scope else "<em>No scope defined</em>"
    )

    # Severity summary chips
    chips = "".join(
        f'<span class="chip" style="background:{SEV_COLOR[s]}">{counts[s]} {s}</span>'
        for s in SEV_ORDER
        if counts.get(s)
    ) or '<span class="chip" style="background:#16a34a">No findings</span>'

    # Findings
    finding_rows = []
    for i, f in enumerate(findings, 1):
        sev = f["severity"]
        refs = []
        for c in f.get("cve") or []:
            refs.append(f'<span class="tag cve">{_esc(c).upper()}</span>')
        for c in f.get("cwe") or []:
            refs.append(f'<span class="tag">{_esc(c).upper()}</span>')
        cvss = f'<span class="cvss">CVSS {_esc(f["cvss"])}</span>' if f.get("cvss") is not None else ""
        finding_rows.append(f"""
        <div class="finding">
          <div class="f-head">
            <span class="sev" style="background:{SEV_COLOR.get(sev,'#64748b')}">{_esc(sev).upper()}</span>
            <span class="f-name">{i}. {_esc(f['name'])}</span>
            <span class="f-src">{_esc(f.get('source',''))}</span>
            {cvss}
          </div>
          <div class="f-loc">{_esc(f.get('location',''))}</div>
          {'<div class="f-tags">'+''.join(refs)+'</div>' if refs else ''}
          {'<div class="f-desc">'+_esc(f.get('description',''))+'</div>' if f.get('description') else ''}
        </div>""")
    findings_html = "".join(finding_rows) or "<p class='muted'>No findings recorded.</p>"

    # Scan activity
    scan_rows = "".join(
        f"<tr><td>#{s['id']}</td><td>{_esc(s['tool'])}</td><td>{_esc(s['target'])}</td>"
        f"<td>{_esc(s['status'])}</td><td>{_esc(round(s.get('duration',0),1))}s</td>"
        f"<td>{_esc(s.get('started_at',''))}</td></tr>"
        for s in scans
    ) or "<tr><td colspan='6' class='muted'>No scans recorded.</td></tr>"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{title_brand} Report — {_esc(project['name'])}</title>
<style>
  :root {{ --ink:#0f172a; --muted:#64748b; --line:#e2e8f0; --accent:{accent}; }}
  * {{ box-sizing:border-box; }}
  body {{ font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; color:var(--ink);
          margin:0; background:#f1f5f9; }}
  .page {{ max-width:920px; margin:0 auto; background:#fff; padding:48px 56px; }}
  .top {{ display:flex; justify-content:space-between; align-items:flex-start; border-bottom:3px solid var(--accent); padding-bottom:18px; }}
  .brand {{ font-size:24px; font-weight:800; letter-spacing:.08em; }}
  .brand span {{ color:var(--accent); }}
  .muted {{ color:var(--muted); }}
  h1 {{ font-size:22px; margin:28px 0 4px; }}
  h2 {{ font-size:15px; text-transform:uppercase; letter-spacing:.08em; color:var(--accent);
        border-bottom:1px solid var(--line); padding-bottom:6px; margin:34px 0 14px; }}
  .meta {{ font-size:13px; color:var(--muted); line-height:1.7; }}
  .summary {{ display:flex; gap:24px; margin:18px 0; flex-wrap:wrap; }}
  .stat {{ background:#f8fafc; border:1px solid var(--line); border-radius:10px; padding:14px 20px; min-width:130px; }}
  .stat .n {{ font-size:28px; font-weight:800; }}
  .stat .l {{ font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.05em; }}
  .rating {{ display:inline-block; padding:4px 14px; border-radius:20px; color:#fff; font-weight:700; }}
  .chips {{ display:flex; gap:8px; flex-wrap:wrap; margin:8px 0 4px; }}
  .chip {{ color:#fff; font-size:12px; font-weight:700; padding:4px 12px; border-radius:20px; text-transform:capitalize; }}
  .finding {{ border:1px solid var(--line); border-left:4px solid var(--line); border-radius:8px; padding:12px 16px; margin:10px 0; page-break-inside:avoid; }}
  .f-head {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
  .sev {{ color:#fff; font-size:11px; font-weight:700; padding:2px 9px; border-radius:5px; }}
  .f-name {{ font-weight:700; }}
  .f-src {{ font-size:11px; text-transform:uppercase; color:var(--muted); border:1px solid var(--line); padding:1px 6px; border-radius:5px; }}
  .cvss {{ margin-left:auto; font-size:12px; color:#d97706; font-weight:700; }}
  .f-loc {{ font-family:ui-monospace,monospace; font-size:12px; color:var(--accent); margin-top:6px; word-break:break-all; }}
  .f-tags {{ margin-top:8px; display:flex; gap:6px; flex-wrap:wrap; }}
  .tag {{ font-size:11px; background:#f1f5f9; border:1px solid var(--line); padding:1px 7px; border-radius:5px; }}
  .tag.cve {{ color:#b91c1c; border-color:#fecaca; }}
  .f-desc {{ margin-top:8px; font-size:13px; color:#334155; line-height:1.55; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th,td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); }}
  th {{ font-size:11px; text-transform:uppercase; color:var(--muted); letter-spacing:.05em; }}
  .disclaimer {{ margin-top:36px; padding:14px 16px; background:#fffbeb; border:1px solid #fde68a; border-radius:8px; font-size:12px; color:#92400e; }}
  .print-btn {{ position:fixed; top:20px; right:20px; background:var(--accent); color:#fff; border:0; padding:10px 18px; border-radius:8px; font-weight:700; cursor:pointer; }}
  @media print {{ body {{ background:#fff; }} .page {{ padding:0; }} .print-btn {{ display:none; }} }}
</style></head>
<body>
<button class="print-btn" onclick="window.print()">Save as PDF</button>
<div class="page">
  <div class="top">
    <div><div class="brand">{brand_inner}</div><div class="muted">Security Assessment Report</div></div>
    <div class="meta" style="text-align:right">Generated {generated}<br>Report v1.0</div>
  </div>

  <h1>{_esc(project['name'])}</h1>
  <div class="meta">{_esc(project.get('description',''))}</div>

  <h2>Engagement Overview</h2>
  <div class="meta"><b>Scope:</b> {scope_html}<br><b>Overall risk rating:</b>
    <span class="rating" style="background:{SEV_COLOR.get(rating.lower(), '#16a34a')}">{rating}</span></div>

  <h2>Executive Summary</h2>
  <div class="summary">
    <div class="stat"><div class="n">{len(scans)}</div><div class="l">Scans run</div></div>
    <div class="stat"><div class="n">{len(real)}</div><div class="l">Vulnerabilities</div></div>
    <div class="stat"><div class="n">{counts.get('critical',0)+counts.get('high',0)}</div><div class="l">High / Critical</div></div>
    <div class="stat"><div class="n">{len(findings)}</div><div class="l">Total findings</div></div>
  </div>
  <div class="chips">{chips}</div>

  <h2>Findings</h2>
  {findings_html}

  <h2>Scan Activity</h2>
  <table>
    <thead><tr><th>ID</th><th>Module</th><th>Target</th><th>Status</th><th>Duration</th><th>Started (UTC)</th></tr></thead>
    <tbody>{scan_rows}</tbody>
  </table>

  <div class="disclaimer">
    <b>Authorized testing notice.</b> This report documents reconnaissance and
    automated detection performed with RECON-X against the scope listed above.
    Findings are detection-based and should be manually validated. Conduct testing
    only against systems you are explicitly authorized to assess.{footer_html}
  </div>
</div>
</body></html>"""
