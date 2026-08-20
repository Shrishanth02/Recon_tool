"""Generate a self-contained, printable HTML engagement report.

The HTML is styled for both screen and print (Ctrl/Cmd+P → Save as PDF), so it
doubles as the client deliverable without pulling in a heavy PDF dependency.
"""

import html
from datetime import datetime, timezone

from .branding import safe_color, safe_logo_url
from .severity import normalize_severity

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
    # P0-7: normalize every finding's severity up front so one malformed value
    # (e.g. "unknown") renders under a real severity bucket instead of being
    # dropped from the grouped body — and can never break report rendering.
    findings = [{**f, "severity": normalize_severity(f.get("severity"))} for f in findings]
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    real = [f for f in findings if f["severity"] != "info"]
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rating = _risk_rating(counts)

    # --- Branding (all optional; absent -> byte-compatible defaults) -------- #
    branding = branding or {}
    brand_name = (branding.get("brand_name") or "").strip()
    # P0-5: brand color/logo are untrusted (org-controlled) and rendered into the
    # report's <style>/HTML. Validate strictly and fall back to a safe default so
    # a malicious stored value can never escape the CSS property or the <img src>.
    accent = safe_color(branding.get("brand_primary_color"), "#0d9488")
    logo_url = safe_logo_url(branding.get("brand_logo_url"))
    footer_note = (branding.get("report_footer") or "").strip()

    # Document <title> prefix and the header brand block.
    title_brand = _esc(brand_name) if brand_name else "RedOpsX"
    if brand_name:
        logo_html = (
            f'<img src="{_esc(logo_url)}" alt="" '
            f'style="height:40px;vertical-align:middle;margin-right:10px">'
            if logo_url
            else ""
        )
        brand_inner = f"{logo_html}{_esc(brand_name)}"
    else:
        brand_inner = "Red<span>OpsX</span>"
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
    automated detection performed with RedOpsX against the scope listed above.
    Findings are detection-based and should be manually validated. Conduct testing
    only against systems you are explicitly authorized to assess.{footer_html}
  </div>
</div>
</body></html>"""


# --------------------------------------------------------------------------- #
# Purple-Team P5: purple-team report (recon + ATT&CK coverage + AI triage).
# --------------------------------------------------------------------------- #
#: Verdict colors for the ATT&CK coverage matrix cells.
_COVERAGE_COLORS = {
    "detected": "#16a34a",      # green  — validated and caught by the SIEM/EDR
    "missed": "#dc2626",        # red    — emulated but not detected (a gap)
    "not_validated": "#94a3b8",  # grey   — emulated but never validated
}


def _coverage_cell(detected) -> tuple[str, str]:
    """Map a technique ``detected`` verdict to a ``(label, color)`` pair."""
    if detected is True:
        return "Detected", _COVERAGE_COLORS["detected"]
    if detected is False:
        return "Missed", _COVERAGE_COLORS["missed"]
    return "Not validated", _COVERAGE_COLORS["not_validated"]


def generate_purple(
    project: dict,
    findings: list,
    scans: list,
    coverage: dict,
    triage: dict | None = None,
    branding: dict | None = None,
) -> str:
    """Render a self-contained purple-team HTML report.

    Extends the recon report with the continuous-purple posture: an ATT&CK
    coverage matrix, detection gaps, a coverage trend, and (when available) the AI
    triage's prioritized actions. Every dynamic value is escaped with :func:`_esc`,
    so the output is byte-safe HTML with inline CSS. :func:`generate` is left
    untouched.

    Parameters
    ----------
    project, findings, scans:
        As for :func:`generate` — the engagement, its findings, and scan activity.
    coverage:
        The :func:`app.crud.coverage_dashboard` payload (``summary``/``techniques``/
        ``tactics``/``trend``/``gaps``).
    triage:
        An optional triage summary — either the compact
        :func:`app.purple.chain_triage` dict (``enabled``/``count``/``top``) or a
        persisted ``TriageResult.data`` payload. When ``None`` or disabled a
        "triage unavailable" note is shown.
    branding:
        Optional white-label dict (same keys as :func:`generate`).
    """
    coverage = coverage or {}
    branding = branding or {}
    brand_name = (branding.get("brand_name") or "").strip()
    # P0-5: see generate() — untrusted branding is validated + safely defaulted.
    accent = safe_color(branding.get("brand_primary_color"), "#7c3aed")
    logo_url = safe_logo_url(branding.get("brand_logo_url"))
    footer_note = (branding.get("report_footer") or "").strip()

    # P0-7: normalize every finding's severity up front so one malformed value
    # (e.g. "unknown") renders under a real severity bucket instead of being
    # dropped from the grouped body — and can never break report rendering.
    findings = [{**f, "severity": normalize_severity(f.get("severity"))} for f in findings]
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    real = [f for f in findings if f["severity"] != "info"]
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rating = _risk_rating(counts)

    title_brand = _esc(brand_name) if brand_name else "RedOpsX"
    if brand_name:
        logo_html = (
            f'<img src="{_esc(logo_url)}" alt="" '
            f'style="height:40px;vertical-align:middle;margin-right:10px">'
            if logo_url
            else ""
        )
        brand_inner = f"{logo_html}{_esc(brand_name)}"
    else:
        brand_inner = "Red<span>OpsX</span> Purple"
    footer_html = (
        f'\n    <div style="margin-top:10px">{_esc(footer_note)}</div>'
        if footer_note
        else ""
    )

    scope = project.get("scope") or []
    scope_html = (
        ", ".join(_esc(s) for s in scope) if scope else "<em>No scope defined</em>"
    )

    cov_summary = coverage.get("summary") or {}
    coverage_pct = cov_summary.get("coverage_pct")
    coverage_pct_html = f"{_esc(coverage_pct)}%" if coverage_pct is not None else "n/a"

    # --- (2) ATT&CK Coverage Matrix: tactics -> techniques. ---------------- #
    techs_by_tactic: dict[str, list] = {}
    for t in coverage.get("techniques") or []:
        techs_by_tactic.setdefault(t.get("tactic") or "", []).append(t)

    tactic_blocks = []
    for tac in coverage.get("tactics") or []:
        tid = tac.get("tactic") or ""
        techs = techs_by_tactic.get(tid, [])
        cells = []
        for t in techs:
            label, color = _coverage_cell(t.get("detected"))
            cells.append(
                f'<span class="tcell" style="border-color:{color};color:{color}">'
                f'<b>{_esc(t.get("technique_id",""))}</b> '
                f'{_esc(t.get("name",""))} — {label}</span>'
            )
        cells_html = "".join(cells) or '<span class="muted">no techniques</span>'
        tactic_blocks.append(
            f'<div class="tactic-row"><div class="tactic-name">'
            f'{_esc(tac.get("name") or tid)}'
            f'<span class="tactic-meta">{_esc(tac.get("detected",0))} detected / '
            f'{_esc(tac.get("missed",0))} missed / {_esc(tac.get("total",0))} total</span>'
            f'</div><div class="tcells">{cells_html}</div></div>'
        )
    matrix_html = "".join(tactic_blocks) or (
        "<p class='muted'>No emulated techniques yet — run a purple loop to "
        "populate the coverage matrix.</p>"
    )

    # --- (3) Detection gaps table. ----------------------------------------- #
    gap_rows = "".join(
        f"<tr><td>{_esc(g.get('technique_id',''))}</td>"
        f"<td>{_esc(g.get('name',''))}</td><td>{_esc(g.get('tactic',''))}</td></tr>"
        for g in (coverage.get("gaps") or [])
    ) or "<tr><td colspan='3' class='muted'>No outstanding detection gaps.</td></tr>"

    # --- (4) Coverage trend note. ------------------------------------------ #
    trend = coverage.get("trend") or []
    if trend:
        first_pct = trend[0].get("coverage_pct")
        last_pct = trend[-1].get("coverage_pct")
        direction = "stable"
        if first_pct is not None and last_pct is not None:
            if last_pct > first_pct:
                direction = "improving"
            elif last_pct < first_pct:
                direction = "regressing"
        trend_html = (
            f"Across {len(trend)} validated run(s), detection coverage moved from "
            f"<b>{_esc(first_pct)}%</b> to <b>{_esc(last_pct)}%</b> "
            f"(<b>{direction}</b>)."
        )
    else:
        trend_html = (
            "<span class='muted'>No validated runs yet — coverage trend will "
            "appear once emulations are validated against a detection connector.</span>"
        )

    # --- (5) AI triage prioritized actions. -------------------------------- #
    triage = triage or {}
    triage_enabled = bool(triage.get("enabled"))
    if triage_enabled:
        # Accept either the compact chain_triage `top` list or a full triage
        # payload's `findings`/`items` list.
        rows = triage.get("top") or triage.get("findings") or triage.get("items") or []
        item_rows = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            rid = r.get("id", r.get("finding_id"))
            sev = r.get("severity") or r.get("suggested_severity") or ""
            action = (
                r.get("recommendation")
                or r.get("remediation")
                or r.get("rationale")
                or ""
            )
            item_rows.append(
                f"<tr><td>#{_esc(rid)}</td>"
                f"<td>{_esc(r.get('name',''))}</td>"
                f"<td><span class='sev' style='background:"
                f"{SEV_COLOR.get(str(sev).lower(),'#64748b')}'>"
                f"{_esc(str(sev).upper())}</span></td>"
                f"<td>{_esc(r.get('priority',''))}</td>"
                f"<td>{_esc(action)}</td></tr>"
            )
        headline = triage.get("summary") or triage.get("risk_narrative") or ""
        headline_html = (
            f"<div class='meta' style='margin-bottom:10px'>{_esc(headline)}</div>"
            if headline
            else ""
        )
        body_rows = "".join(item_rows) or (
            "<tr><td colspan='5' class='muted'>Triage returned no prioritized "
            "items.</td></tr>"
        )
        triage_html = (
            f"{headline_html}"
            "<table><thead><tr><th>Finding</th><th>Name</th><th>Severity</th>"
            "<th>Priority</th><th>Recommended action</th></tr></thead>"
            f"<tbody>{body_rows}</tbody></table>"
        )
    else:
        reason = _esc(triage.get("reason") or "AI triage not enabled")
        triage_html = (
            f"<div class='note'><b>AI triage unavailable.</b> {reason}. Findings "
            "below are prioritized by scanner severity only.</div>"
        )

    # --- (6) Findings, grouped by severity (Critical first). --------------- #
    _SEV_LABEL = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Informational",
    }
    _GENERIC_REMEDIATION = {
        "critical": (
            "Treat as an emergency. Apply the vendor patch or remove the exposed "
            "service immediately, rotate any credentials that may have been "
            "exposed, and hunt for prior exploitation before returning the asset "
            "to service."
        ),
        "high": (
            "Prioritise remediation in the current sprint. Patch or reconfigure "
            "the affected component, restrict network exposure, and add "
            "compensating detection until the fix is deployed."
        ),
        "medium": (
            "Schedule remediation as part of routine maintenance. Harden the "
            "configuration, apply available updates, and validate the fix in a "
            "follow-up scan."
        ),
        "low": (
            "Address opportunistically. Apply configuration hardening and track "
            "the item to closure in the vulnerability-management backlog."
        ),
        "info": (
            "No direct action required. Retain for context and situational "
            "awareness; reassess if the surrounding attack surface changes."
        ),
    }

    def _finding_card(idx: int, f: dict) -> str:
        sev = f["severity"]
        refs = []
        for c in f.get("cve") or []:
            refs.append(f'<span class="tag cve">{_esc(c).upper()}</span>')
        for c in f.get("cwe") or []:
            refs.append(f'<span class="tag">{_esc(c).upper()}</span>')
        cvss = (
            f'<span class="cvss">CVSS {_esc(f["cvss"])}</span>'
            if f.get("cvss") is not None
            else ""
        )
        attck = ""
        if f.get("technique_id"):
            attck = (
                f'<span class="tag attck">ATT&amp;CK {_esc(f.get("technique_id"))}'
                + (f' · {_esc(f.get("tactic"))}' if f.get("tactic") else "")
                + "</span>"
            )
        tags = "".join(refs) + attck
        remediation = f.get("remediation") or _GENERIC_REMEDIATION.get(
            sev, _GENERIC_REMEDIATION["info"]
        )
        loc = f.get("location", "")
        return f"""
        <div class="finding sev-{_esc(sev)}">
          <div class="f-head">
            <span class="sev" style="background:{SEV_COLOR.get(sev,'#64748b')}">{_esc(sev).upper()}</span>
            <span class="f-name">{idx}. {_esc(f['name'])}</span>
            <span class="f-src">{_esc(f.get('source',''))}</span>
            {cvss}
          </div>
          {'<div class="f-asset"><span class="f-lbl">Affected asset</span><span class="f-loc">'+_esc(loc)+'</span></div>' if loc else ''}
          {'<div class="f-tags">'+tags+'</div>' if tags else ''}
          {'<div class="f-desc">'+_esc(f.get('description',''))+'</div>' if f.get('description') else ''}
          <div class="f-remed"><span class="f-lbl">Remediation</span> {_esc(remediation)}</div>
        </div>"""

    grouped = []
    idx = 0
    for s in SEV_ORDER:
        bucket = [f for f in findings if f["severity"] == s]
        if not bucket:
            continue
        cards = []
        for f in bucket:
            idx += 1
            cards.append(_finding_card(idx, f))
        grouped.append(
            f'<h3 class="sev-group"><span class="sev-dot" '
            f'style="background:{SEV_COLOR[s]}"></span>{_SEV_LABEL.get(s, s.title())} '
            f'severity <span class="sev-group-n">({len(bucket)})</span></h3>'
            + "".join(cards)
        )
    findings_html = "".join(grouped) or "<p class='muted'>No findings recorded.</p>"

    # Severity-count badge row (all severities shown, including zero).
    chips = "".join(
        f'<span class="chip" style="background:{SEV_COLOR[s]}">'
        f'<b>{counts.get(s, 0)}</b> {_SEV_LABEL.get(s, s.title())}</span>'
        for s in SEV_ORDER
    )

    # Severity summary table for the executive section.
    sev_table_rows = "".join(
        f'<tr><td><span class="sev" style="background:{SEV_COLOR[s]}">'
        f'{s.upper()}</span></td><td class="num">{counts.get(s, 0)}</td></tr>'
        for s in SEV_ORDER
    )

    # Executive narrative, derived from the finding profile and coverage.
    total_real = len(real)
    hi_crit = counts.get("critical", 0) + counts.get("high", 0)
    if hi_crit:
        posture = (
            f"The assessment identified {hi_crit} high-impact "
            f"(Critical/High) finding(s) that materially increase the "
            f"organisation's exposure and warrant prompt remediation."
        )
    elif total_real:
        posture = (
            f"The assessment identified {total_real} finding(s) of moderate or "
            f"lower severity; no Critical or High issues were confirmed."
        )
    else:
        posture = (
            "No exploitable vulnerabilities were confirmed within the tested "
            "scope during this engagement."
        )
    if coverage_pct is not None:
        cov_sentence = (
            f" Detection coverage across emulated ATT&amp;CK techniques stands at "
            f"<b>{coverage_pct_html}</b>, and the outstanding detection gaps are "
            f"enumerated in the coverage section below."
        )
    else:
        cov_sentence = (
            " Detection coverage was not measured for this engagement; run a "
            "purple-team emulation loop to populate the ATT&amp;CK matrix."
        )
    narrative_html = (
        f"RedOpsX performed an authorized purple-team assessment of "
        f"<b>{_esc(project.get('name',''))}</b>. {posture}"
        f" The overall engagement risk is rated <b>{rating}</b>.{cov_sentence}"
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title_brand} Penetration Test Report — {_esc(project['name'])}</title>
<style>
  :root {{ --ink:#0f172a; --body:#334155; --muted:#64748b; --line:#e2e8f0;
           --soft:#f8fafc; --accent:{accent}; }}
  * {{ box-sizing:border-box; }}
  html {{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
          color:var(--ink); margin:0; background:#e2e8f0; line-height:1.55; }}
  .page {{ max-width:940px; margin:24px auto; background:#fff; padding:56px 64px;
           box-shadow:0 1px 3px rgba(15,23,42,.12); }}
  a {{ color:var(--accent); }}

  /* Cover */
  .cover {{ min-height:78vh; display:flex; flex-direction:column; page-break-after:always; }}
  .cover-brand {{ display:flex; justify-content:space-between; align-items:flex-start;
                  border-bottom:3px solid var(--accent); padding-bottom:20px; }}
  .brand {{ font-size:26px; font-weight:800; letter-spacing:.06em; }}
  .brand span {{ color:var(--accent); }}
  .cover-mid {{ flex:1; display:flex; flex-direction:column; justify-content:center;
                padding:48px 0; }}
  .doc-kicker {{ font-size:13px; text-transform:uppercase; letter-spacing:.22em;
                 color:var(--accent); font-weight:700; }}
  .doc-title {{ font-size:44px; font-weight:800; line-height:1.1; margin:12px 0 8px; }}
  .doc-sub {{ font-size:19px; color:var(--muted); font-weight:600; }}
  .engagement {{ font-size:24px; font-weight:700; margin-top:34px; }}
  .cover-meta {{ margin-top:28px; border-top:1px solid var(--line);
                 display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
                 gap:2px 24px; }}
  .cover-meta div {{ padding:12px 0; border-bottom:1px solid var(--line); }}
  .cover-meta .k {{ font-size:11px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); }}
  .cover-meta .v {{ font-size:15px; font-weight:600; margin-top:2px; }}
  .confidential {{ margin-top:auto; background:#fef2f2; border:1px solid #fecaca;
                   color:#991b1b; border-radius:8px; padding:12px 16px; font-size:12.5px; }}
  .confidential b {{ letter-spacing:.06em; }}

  .muted {{ color:var(--muted); }}
  h2 {{ font-size:15px; text-transform:uppercase; letter-spacing:.09em; color:var(--accent);
        border-bottom:2px solid var(--line); padding-bottom:7px; margin:40px 0 16px;
        page-break-after:avoid; }}
  h3.sev-group {{ font-size:14px; margin:22px 0 8px; display:flex; align-items:center;
                  gap:8px; page-break-after:avoid; }}
  .sev-dot {{ width:12px; height:12px; border-radius:3px; display:inline-block; }}
  .sev-group-n {{ color:var(--muted); font-weight:600; }}
  p, .prose {{ font-size:14px; color:var(--body); }}
  .meta {{ font-size:13.5px; color:var(--body); line-height:1.7; }}

  .toc {{ font-size:14px; }}
  .toc ol {{ margin:0; padding-left:20px; }}
  .toc li {{ padding:3px 0; }}

  .grid {{ display:grid; grid-template-columns:2fr 1fr; gap:28px; align-items:start; }}
  .summary {{ display:flex; gap:16px; margin:18px 0; flex-wrap:wrap; }}
  .stat {{ background:var(--soft); border:1px solid var(--line); border-radius:10px;
           padding:14px 20px; min-width:120px; flex:1; }}
  .stat .n {{ font-size:26px; font-weight:800; }}
  .stat .l {{ font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.05em; }}
  .rating {{ display:inline-block; padding:4px 14px; border-radius:6px; color:#fff; font-weight:700; }}
  .chips {{ display:flex; gap:8px; flex-wrap:wrap; margin:12px 0 4px; }}
  .chip {{ color:#fff; font-size:12px; font-weight:600; padding:5px 12px; border-radius:6px; }}
  .chip b {{ font-weight:800; }}

  .callout {{ background:var(--soft); border:1px solid var(--line); border-left:4px solid var(--accent);
              border-radius:8px; padding:14px 18px; margin:14px 0; font-size:14px; color:var(--body); }}
  ol.phases {{ font-size:14px; color:var(--body); padding-left:20px; }}
  ol.phases li {{ margin:6px 0; }}
  ol.phases b {{ color:var(--ink); }}

  .tactic-row {{ border:1px solid var(--line); border-radius:8px; padding:12px 16px;
                 margin:10px 0; page-break-inside:avoid; }}
  .tactic-name {{ font-weight:700; font-size:14px; display:flex; justify-content:space-between;
                  align-items:baseline; flex-wrap:wrap; gap:8px; }}
  .tactic-meta {{ font-size:11px; font-weight:600; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }}
  .tcells {{ display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; }}
  .tcell {{ font-size:12px; border:1.5px solid; border-radius:6px; padding:4px 10px; background:#fff; }}
  .legend {{ display:flex; gap:16px; flex-wrap:wrap; font-size:12px; margin:8px 0 4px; }}
  .legend span {{ display:inline-flex; align-items:center; gap:6px; color:var(--body); }}
  .dot {{ width:11px; height:11px; border-radius:3px; display:inline-block; }}

  .finding {{ border:1px solid var(--line); border-left:5px solid var(--line); border-radius:8px;
              padding:14px 18px; margin:10px 0; page-break-inside:avoid; }}
  .finding.sev-critical {{ border-left-color:#b91c1c; }}
  .finding.sev-high {{ border-left-color:#dc2626; }}
  .finding.sev-medium {{ border-left-color:#d97706; }}
  .finding.sev-low {{ border-left-color:#2563eb; }}
  .finding.sev-info {{ border-left-color:#64748b; }}
  .f-head {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
  .sev {{ color:#fff; font-size:11px; font-weight:700; padding:2px 9px; border-radius:5px;
          letter-spacing:.03em; }}
  .f-name {{ font-weight:700; font-size:15px; }}
  .f-src {{ font-size:11px; text-transform:uppercase; color:var(--muted); border:1px solid var(--line);
            padding:1px 6px; border-radius:5px; }}
  .cvss {{ margin-left:auto; font-size:12px; color:#b45309; font-weight:700; }}
  .f-asset {{ margin-top:8px; }}
  .f-lbl {{ display:inline-block; font-size:10.5px; text-transform:uppercase; letter-spacing:.06em;
            color:var(--muted); font-weight:700; margin-right:6px; }}
  .f-loc {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12.5px;
            color:var(--accent); word-break:break-all; }}
  .f-tags {{ margin-top:8px; display:flex; gap:6px; flex-wrap:wrap; }}
  .tag {{ font-size:11px; background:var(--soft); border:1px solid var(--line); padding:2px 8px; border-radius:5px; }}
  .tag.cve {{ color:#b91c1c; border-color:#fecaca; }}
  .tag.attck {{ color:#6d28d9; border-color:#ddd6fe; }}
  .f-desc {{ margin-top:9px; font-size:13.5px; color:var(--body); line-height:1.6; }}
  .f-remed {{ margin-top:10px; padding-top:10px; border-top:1px dashed var(--line);
              font-size:13px; color:var(--body); }}

  table {{ width:100%; border-collapse:collapse; font-size:13px; margin:6px 0; }}
  th,td {{ text-align:left; padding:9px 11px; border:1px solid var(--line); vertical-align:top; }}
  th {{ font-size:11px; text-transform:uppercase; color:var(--muted); letter-spacing:.05em;
        background:var(--soft); }}
  td.num {{ text-align:right; font-variant-numeric:tabular-nums; font-weight:700; }}
  .sev-table {{ max-width:280px; }}

  .note {{ padding:13px 16px; background:var(--soft); border:1px solid var(--line);
           border-radius:8px; font-size:13.5px; color:var(--body); }}
  .note.warn {{ background:#fffbeb; border-color:#fde68a; color:#92400e; }}
  .disclaimer {{ margin-top:20px; padding:16px 18px; background:#fffbeb; border:1px solid #fde68a;
                 border-radius:8px; font-size:12.5px; color:#92400e; page-break-inside:avoid; }}
  .footer {{ margin-top:34px; padding-top:16px; border-top:1px solid var(--line);
             font-size:11.5px; color:var(--muted); display:flex; justify-content:space-between;
             flex-wrap:wrap; gap:8px; }}

  .print-btn {{ position:fixed; top:20px; right:20px; background:var(--accent); color:#fff;
                border:0; padding:10px 18px; border-radius:8px; font-weight:700; cursor:pointer;
                box-shadow:0 2px 8px rgba(15,23,42,.2); z-index:10; }}
  @media (max-width:720px) {{ .page {{ padding:32px 22px; }} .grid {{ grid-template-columns:1fr; }} }}
  @media print {{
    body {{ background:#fff; }}
    .page {{ margin:0; padding:0; max-width:none; box-shadow:none; }}
    .print-btn {{ display:none; }}
    h2, h3 {{ page-break-after:avoid; }}
    .finding, .tactic-row, table {{ page-break-inside:avoid; }}
  }}
</style></head>
<body>
<button class="print-btn" onclick="window.print()">⭳ Save as PDF</button>
<div class="page">

  <!-- ============================ COVER ============================ -->
  <section class="cover">
    <div class="cover-brand">
      <div><div class="brand">{brand_inner}</div>
           <div class="muted" style="margin-top:4px;font-size:13px">Offensive Security &amp; Detection Engineering</div></div>
      <div class="meta" style="text-align:right">Report v1.0<br>Generated {generated}</div>
    </div>
    <div class="cover-mid">
      <div class="doc-kicker">Penetration Test Report</div>
      <div class="doc-title">Purple-Team<br>Assessment Report</div>
      <div class="doc-sub">Adversary emulation, vulnerability validation &amp; detection coverage</div>
      <div class="engagement">{_esc(project['name'])}</div>
      <div class="cover-meta">
        <div><div class="k">Engagement</div><div class="v">{_esc(project['name'])}</div></div>
        <div><div class="k">Date issued</div><div class="v">{generated}</div></div>
        <div><div class="k">Overall risk</div><div class="v"><span class="rating" style="background:{SEV_COLOR.get(rating.lower(), '#16a34a')}">{rating}</span></div></div>
        <div><div class="k">Prepared by</div><div class="v">{title_brand} Purple Team</div></div>
      </div>
    </div>
    <div class="confidential">
      <b>CONFIDENTIAL.</b> This document contains sensitive security information about
      {_esc(project['name'])} and is intended solely for authorized recipients. Do not
      distribute, reproduce, or disclose its contents without written permission.
    </div>
  </section>

  <!-- ======================= TABLE OF CONTENTS ===================== -->
  <h2>Contents</h2>
  <div class="toc"><ol>
    <li>Executive Summary</li>
    <li>Scope &amp; Engagement Details</li>
    <li>Methodology</li>
    <li>Findings</li>
    <li>ATT&amp;CK Coverage Matrix &amp; Detection Gaps</li>
    <li>AI Triage — Prioritized Actions</li>
    <li>Appendix — Authorization &amp; Safety Statement</li>
  </ol></div>

  <!-- ======================= 1. EXECUTIVE SUMMARY =================== -->
  <h2>1. Executive Summary</h2>
  <div class="grid">
    <div>
      <p class="prose">{narrative_html}</p>
      <div class="callout"><b>Overall engagement risk rating:</b>
        <span class="rating" style="background:{SEV_COLOR.get(rating.lower(), '#16a34a')}">{rating}</span></div>
      <div class="chips">{chips}</div>
    </div>
    <div>
      <table class="sev-table">
        <thead><tr><th>Severity</th><th class="num">Count</th></tr></thead>
        <tbody>{sev_table_rows}</tbody>
      </table>
    </div>
  </div>
  <div class="summary">
    <div class="stat"><div class="n">{len(scans)}</div><div class="l">Scans run</div></div>
    <div class="stat"><div class="n">{len(real)}</div><div class="l">Vulnerabilities</div></div>
    <div class="stat"><div class="n">{counts.get('critical',0)+counts.get('high',0)}</div><div class="l">High / Critical</div></div>
    <div class="stat"><div class="n">{coverage_pct_html}</div><div class="l">Detection coverage</div></div>
  </div>

  <!-- ======================= 2. SCOPE ============================== -->
  <h2>2. Scope &amp; Engagement Details</h2>
  <div class="meta"><b>Engagement:</b> {_esc(project['name'])}</div>
  {'<div class="meta"><b>Description:</b> '+_esc(project.get('description',''))+'</div>' if project.get('description') else ''}
  <div class="meta"><b>In-scope targets:</b> {scope_html}</div>
  <div class="note" style="margin-top:12px">Testing was conducted only against the assets
    enumerated above, under written authorization from the asset owner. Systems outside
    this scope were explicitly excluded from all active testing.</div>

  <!-- ======================= 3. METHODOLOGY ======================== -->
  <h2>3. Methodology</h2>
  <p class="prose">This assessment followed a PTES-aligned, purple-team methodology that
    pairs offensive validation with defensive detection measurement. All testing was
    <b>authorized</b>, and any exploitation activity is <b>human-gated</b> and
    strictly <b>non-destructive</b>.</p>
  <ol class="phases">
    <li><b>Reconnaissance</b> — passive and active discovery of the in-scope attack surface.</li>
    <li><b>Enumeration</b> — service, technology, and asset fingerprinting to map exposure.</li>
    <li><b>Vulnerability Assessment</b> — automated and manual identification of weaknesses,
        mapped to CVE/CWE and CVSS where applicable.</li>
    <li><b>Validation</b> — confirmation of exploitability using benign, marker-bearing probes;
        no exploit payloads, data exfiltration, or state changes are performed.</li>
    <li><b>Detection Coverage</b> — ATT&amp;CK-mapped adversary emulation validated against the
        organization's SIEM/EDR to measure detection and expose gaps.</li>
    <li><b>Human-Gated Exploitation</b> — any deeper exploitation is proposed automatically but
        executes only after explicit human approval, and remains read-only and non-destructive.</li>
  </ol>

  <!-- ======================= 4. FINDINGS =========================== -->
  <h2>4. Findings</h2>
  <p class="prose">Findings are grouped by severity, highest impact first. Each entry lists the
    affected asset, applicable CVE/CWE/CVSS references, a technical description, and recommended
    remediation.</p>
  {findings_html}

  <!-- =============== 5. ATT&CK COVERAGE MATRIX ===================== -->
  <h2>5. ATT&amp;CK Coverage Matrix</h2>
  <div class="meta">Detection coverage across validated ATT&amp;CK techniques:
    <b>{coverage_pct_html}</b>
    ({_esc(cov_summary.get('detected',0))} detected,
     {_esc(cov_summary.get('missed',0))} missed,
     {_esc(cov_summary.get('not_validated',0))} not validated of
     {_esc(cov_summary.get('techniques_emulated',0))} emulated).</div>
  <div class="legend">
    <span><span class="dot" style="background:{_COVERAGE_COLORS['detected']}"></span>Detected</span>
    <span><span class="dot" style="background:{_COVERAGE_COLORS['missed']}"></span>Missed (gap)</span>
    <span><span class="dot" style="background:{_COVERAGE_COLORS['not_validated']}"></span>Not validated</span>
  </div>
  {matrix_html}

  <h3 class="sev-group" style="margin-top:24px">Detection Gaps</h3>
  <p class="prose">The following emulated techniques were <b>not detected</b> and represent
    priority detection-engineering work.</p>
  <table>
    <thead><tr><th>ATT&amp;CK ID</th><th>Technique</th><th>Tactic</th></tr></thead>
    <tbody>{gap_rows}</tbody>
  </table>
  <div class="note" style="margin-top:14px"><b>Coverage trend.</b> {trend_html}</div>

  <!-- ======================= 6. AI TRIAGE ========================== -->
  <h2>6. AI Triage — Prioritized Actions</h2>
  {triage_html}

  <!-- ======================= 7. APPENDIX =========================== -->
  <h2>7. Appendix — Authorization &amp; Safety Statement</h2>
  <div class="disclaimer">
    <b>Authorization, methodology &amp; safety.</b> This purple-team assessment combined
    authorized reconnaissance with SAFE, ATT&amp;CK-mapped emulation and detection validation.
    All emulation and validation actions were <b>non-destructive</b> — benign HTTP/TCP probes
    carrying identifying markers, with no exploit payloads, data exfiltration, or state changes.
    Any "exploitation" capability in RedOpsX is <b>human-gated and sandboxed</b>: reachability is
    proposed and validated automatically, but a validation probe runs only after explicit human
    approval and is itself read-only and non-destructive. Findings are detection-based and should
    be manually validated by the receiving team. Conduct testing only against systems you are
    explicitly authorized to assess.{footer_html}
  </div>

  <div class="footer">
    <span>{title_brand} · Purple-Team Assessment Report — CONFIDENTIAL</span>
    <span>{_esc(project['name'])} · Generated {generated}</span>
  </div>
</div>
</body></html>"""
