"""Generate a self-contained, printable HTML security-assessment report (V2).

The HTML is styled for both screen and print (Ctrl/Cmd+P -> Save as PDF), so it
doubles as the client deliverable without a heavy PDF dependency.

V2 reporting principle (see :mod:`app.report_model`):
    SEVERITY  !=  STATUS  !=  CONFIDENCE
A ``vuln`` finding at ``detection_tier="signal"`` (e.g. "Possible IDOR") is a
POTENTIAL finding, never a Confirmed vulnerability, whatever its severity. The
Executive Summary counts Confirmed / Potential / Hardening / Informational /
Not-Tested separately, the overall risk is derived from CONFIRMED findings only,
ATT&CK and AI sections render only when that data actually exists, and a coverage
matrix distinguishes "tested, no finding" from "not tested". Nothing is fabricated.
"""

import html
from datetime import datetime, timezone

from . import report_model as rm
from .branding import safe_color, safe_logo_url

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_COLOR = {
    "critical": "#b91c1c",
    "high": "#dc2626",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#64748b",
}
_SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium",
              "low": "Low", "info": "Informational"}

# Status -> badge color (independent of severity color).
_STATUS_COLOR = {
    "Confirmed": "#b91c1c",
    "Likely": "#c2410c",
    "Potential": "#a16207",
    "Inconclusive": "#6b7280",
    "Hardening": "#0e7490",
    "Informational": "#64748b",
}
_COV_COLOR = {"TESTED": "#16a34a", "PARTIAL": "#d97706",
              "NOT TESTED": "#6b7280", "NOT APPLICABLE": "#94a3b8", "INCONCLUSIVE": "#a16207"}

_COVERAGE_COLORS = {"detected": "#16a34a", "missed": "#dc2626", "not_validated": "#94a3b8"}


def _esc(v) -> str:
    return html.escape(str(v if v is not None else ""))


def _coverage_cell(detected) -> tuple[str, str]:
    if detected is True:
        return "Detected", _COVERAGE_COLORS["detected"]
    if detected is False:
        return "Missed", _COVERAGE_COLORS["missed"]
    return "Not validated", _COVERAGE_COLORS["not_validated"]


def _risk_color(rating: str) -> str:
    return {"Critical": "#b91c1c", "High": "#dc2626", "Medium": "#d97706",
            "Low": "#2563eb"}.get(rating, "#16a34a")


def _brand_bits(branding: dict, default_accent: str, suffix: str = ""):
    brand_name = (branding.get("brand_name") or "").strip()
    accent = safe_color(branding.get("brand_primary_color"), default_accent)
    logo_url = safe_logo_url(branding.get("brand_logo_url"))
    footer_note = (branding.get("report_footer") or "").strip()
    if brand_name:
        logo_html = (f'<img src="{_esc(logo_url)}" alt="" '
                     f'style="height:40px;vertical-align:middle;margin-right:10px">' if logo_url else "")
        brand_inner = f"{logo_html}{_esc(brand_name)}"
        title_brand = _esc(brand_name)
    else:
        brand_inner = f"Red<span>OpsX</span>{(' ' + suffix) if suffix else ''}"
        title_brand = "RedOpsX"
    footer_html = (f'\n    <div style="margin-top:10px">{_esc(footer_note)}</div>' if footer_note else "")
    return brand_name, accent, brand_inner, title_brand, footer_html


_CSS = """
  :root {{ --ink:#0f172a; --muted:#64748b; --line:#e2e8f0; --soft:#f8fafc; --accent:{accent}; }}
  * {{ box-sizing:border-box; }}
  body {{ font-family:"Segoe UI",-apple-system,BlinkMacSystemFont,Roboto,Helvetica,Arial,sans-serif;
          color:var(--ink); margin:0; background:#f1f5f9; font-size:14px; line-height:1.55; }}
  .page {{ max-width:940px; margin:0 auto; background:#fff; padding:44px 56px; }}
  .top {{ display:flex; justify-content:space-between; align-items:flex-start; border-bottom:3px solid var(--accent); padding-bottom:16px; }}
  .brand {{ font-size:24px; font-weight:800; letter-spacing:.06em; }}
  .brand span {{ color:var(--accent); }}
  .muted {{ color:var(--muted); }}
  h1 {{ font-size:22px; margin:26px 0 4px; }}
  h2 {{ font-size:14px; text-transform:uppercase; letter-spacing:.07em; color:var(--accent);
        border-bottom:1px solid var(--line); padding-bottom:6px; margin:32px 0 14px; }}
  h3 {{ font-size:15px; margin:20px 0 8px; }}
  .meta {{ font-size:13px; color:var(--muted); line-height:1.8; }}
  .grid {{ display:flex; gap:16px; flex-wrap:wrap; margin:16px 0; }}
  .stat {{ background:var(--soft); border:1px solid var(--line); border-radius:10px; padding:12px 18px; min-width:120px; }}
  .stat .n {{ font-size:26px; font-weight:800; }}
  .stat .l {{ font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.05em; }}
  .rating {{ display:inline-block; padding:4px 14px; border-radius:20px; color:#fff; font-weight:700; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; margin:6px 0; }}
  th,td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }}
  th {{ font-size:11px; text-transform:uppercase; color:var(--muted); letter-spacing:.05em; }}
  td.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
  .badge {{ color:#fff; font-size:11px; font-weight:700; padding:2px 9px; border-radius:5px; white-space:nowrap; }}
  .pill {{ font-size:11px; font-weight:600; padding:2px 9px; border-radius:20px; border:1px solid var(--line); white-space:nowrap; }}
  .finding {{ border:1px solid var(--line); border-left:4px solid var(--line); border-radius:8px; padding:14px 16px; margin:12px 0; page-break-inside:avoid; }}
  .f-head {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
  .f-id {{ font-family:ui-monospace,Consolas,monospace; font-weight:700; color:var(--muted); }}
  .f-name {{ font-weight:700; font-size:15px; }}
  .f-meta {{ display:flex; gap:8px; flex-wrap:wrap; margin:10px 0; }}
  .kv {{ font-size:12px; }} .kv b {{ color:var(--muted); font-weight:600; }}
  .sec {{ margin-top:10px; }} .sec .lbl {{ font-size:11px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); font-weight:700; }}
  .loc {{ font-family:ui-monospace,Consolas,monospace; font-size:12px; color:var(--accent); word-break:break-all; }}
  pre.ev {{ background:#0f1620; color:#d6e2ef; padding:10px 12px; border-radius:6px; overflow-x:auto; font-size:12px;
            font-family:ui-monospace,Consolas,monospace; white-space:pre-wrap; word-break:break-word; max-height:320px; }}
  .tag {{ font-size:11px; background:var(--soft); border:1px solid var(--line); padding:1px 7px; border-radius:5px; }}
  .note {{ background:var(--soft); border:1px solid var(--line); border-radius:8px; padding:12px 14px; font-size:13px; margin:10px 0; }}
  .qc {{ background:#fef2f2; border:1px solid #fecaca; color:#991b1b; border-radius:8px; padding:12px 14px; font-size:12.5px; margin:10px 0; }}
  .disclaimer {{ margin-top:34px; padding:14px 16px; background:#fffbeb; border:1px solid #fde68a; border-radius:8px; font-size:12px; color:#92400e; }}
  .legend {{ font-size:11.5px; color:var(--muted); margin:6px 0 0; }}
  .print-btn {{ position:fixed; top:20px; right:20px; background:var(--accent); color:#fff; border:0; padding:10px 18px; border-radius:8px; font-weight:700; cursor:pointer; }}
  .appx {{ font-size:12.5px; }}
  @media print {{ body {{ background:#fff; }} .page {{ padding:0; max-width:none; }} .print-btn {{ display:none; }}
    h2 {{ page-break-after:avoid; }} .finding {{ page-break-inside:avoid; }} }}
"""


def _cover(model, project, generated, doc_type):
    p = project
    rows = [
        ("Report ID", p.get("report_id") or f"RX-{generated[:10].replace('-','')}"),
        ("Client / Organization", p.get("client") or p.get("org_name") or "Not provided"),
        ("Engagement", p.get("name") or "Not provided"),
        ("Assessment type", doc_type),
        ("Report date", generated),
        ("Report version", "1.0"),
        ("Prepared by", p.get("prepared_by") or "Not provided"),
        ("Reviewed by", p.get("reviewed_by") or "Not provided"),
        ("Classification", p.get("classification") or "Confidential"),
    ]
    body = "".join(f"<tr><td style='width:210px'><b>{_esc(k)}</b></td><td>{_esc(v)}</td></tr>" for k, v in rows)
    return f"<h2>Document control</h2><table>{body}</table>"


def _dashboard(model):
    c = model["counts"]
    r = model["overall_risk"]
    tiles = [
        (r, "Overall risk (confirmed)", _risk_color(r)),
        (c["confirmed_total"], "Confirmed", None),
        (c["potential_total"], "Potential", None),
        (c["hardening_total"], "Hardening", None),
        (c["informational_total"], "Informational", None),
        (c["not_tested_total"], "Not tested", None),
        (c["assets"], "Assets", None),
        (c["scans"], "Scans run", None),
    ]
    cells = []
    for val, lab, col in tiles:
        style = f' style="color:{col}"' if col else ""
        cells.append(f'<div class="stat"><div class="n"{style}>{_esc(val)}</div><div class="l">{_esc(lab)}</div></div>')
    return f'<h2>Executive dashboard</h2><div class="grid">{"".join(cells)}</div>'


def _risk_table(model):
    conf, pot = model["counts"]["confirmed"], model["counts"]["potential"]
    rows = []
    for s in SEV_ORDER:
        if not (conf.get(s) or pot.get(s)):
            continue
        rows.append(
            f'<tr><td><span class="badge" style="background:{SEV_COLOR[s]}">{s.upper()}</span></td>'
            f'<td class="num">{conf.get(s,0)}</td><td class="num">{pot.get(s,0)}</td></tr>'
        )
    body = "".join(rows) or "<tr><td colspan='3' class='muted'>No confirmed or potential findings.</td></tr>"
    return (f'<h2>Risk summary</h2><table><thead><tr><th>Severity</th>'
            f'<th class="num">Confirmed</th><th class="num">Potential</th></tr></thead><tbody>{body}</tbody></table>'
            f'<p class="legend">Overall risk is derived from CONFIRMED findings only (scanner-derived rating). '
            f'Potential findings are unconfirmed signals requiring validation and do not raise the rating.</p>')


def _coverage_table(model):
    rows = []
    for r in model["coverage_matrix"]:
        rows.append(
            f'<tr><td>{_esc(r["area"])}</td>'
            f'<td><span class="pill" style="color:{_COV_COLOR.get(r["status"],"#64748b")};'
            f'border-color:{_COV_COLOR.get(r["status"],"#64748b")}">{_esc(r["status"])}</span></td>'
            f'<td>{_esc(r["result"])}</td><td class="muted">{_esc(r["limitation"])}</td></tr>'
        )
    return (f'<h2>Testing coverage</h2><table><thead><tr><th>Test area</th><th>Status</th>'
            f'<th>Result</th><th>Limitation</th></tr></thead><tbody>{"".join(rows)}</tbody></table>'
            f'<p class="legend">"Tested / No finding" means the area was exercised and nothing was found. '
            f'"Not tested" means the area was NOT exercised (e.g. required tool unavailable) — absence of a finding '
            f'is not evidence of absence of the issue.</p>')


def _evidence_html(f):
    ev = rm.redact(f.get("evidence") or {})
    if not ev:
        return ('<div class="sec"><span class="lbl">Evidence</span>'
                '<div class="muted">Evidence unavailable — finding remains unconfirmed.</div></div>'
                if f.get("_status") in rm._UNCONFIRMED else "")
    lines = []
    for k, v in (ev.items() if isinstance(ev, dict) else []):
        if isinstance(v, (dict, list)):
            import json
            v = json.dumps(v, default=str)[:1500]
        lines.append(f"{k}: {v}")
    txt = "\n".join(lines)[:4000] if lines else str(ev)[:4000]
    return f'<div class="sec"><span class="lbl">Evidence</span><pre class="ev">{_esc(txt)}</pre></div>'


def _finding_card(fid, f, show_validation_hint=False):
    sev = f["severity"]
    status = f.get("_status", rm.classify(f))
    conf = f.get("confidence")
    conf_lbl = "High" if (conf or 0) >= 70 else "Medium" if (conf or 0) >= 40 else "Low"
    cvss = f'CVSS {_esc(f["cvss"])}' if isinstance(f.get("cvss"), (int, float)) else "CVSS: Not Scored"
    cwes = ", ".join(_esc(str(c).upper()) for c in (f.get("cwe") or [])) or "Not determined"
    cves = " ".join(f'<span class="tag" style="color:#b91c1c">{_esc(str(c).upper())}</span>' for c in (f.get("cve") or []))
    loc = f.get("location", "")
    desc = f.get("description", "")
    remed = rm.remediation_for(f)
    attck = ""
    if f.get("technique_id"):
        attck = (f' <span class="tag">ATT&amp;CK {_esc(f.get("technique_id"))}'
                 + (f' / {_esc(f.get("tactic"))}' if f.get("tactic") else "") + "</span>")
    valid = ""
    if show_validation_hint:
        valid = ('<div class="sec"><span class="lbl">Validation</span>'
                 '<div class="muted">Unconfirmed signal — validate before treating as exploitable '
                 '(e.g. provide a second authorized identity for access-control findings, or an OAST '
                 'collaborator for blind SSRF).</div></div>')
    return f"""
    <div class="finding sev-{_esc(sev)}" style="border-left-color:{SEV_COLOR.get(sev,'#64748b')}">
      <div class="f-head">
        <span class="f-id">{_esc(fid)}</span>
        <span class="f-name">{_esc(f.get('name',''))}</span>
      </div>
      <div class="f-meta">
        <span class="badge" style="background:{SEV_COLOR.get(sev,'#64748b')}">{_esc(sev).upper()}</span>
        <span class="badge" style="background:{_STATUS_COLOR.get(status,'#64748b')}">{_esc(status)}</span>
        <span class="pill">Confidence: {_esc(conf_lbl)}</span>
        <span class="pill">{_esc(cvss)}</span>
        <span class="pill">CWE: {cwes}</span>
        {('<span class="pill">Source: '+_esc(f.get('source',''))+'</span>') if f.get('source') else ''}
        {cves}{attck}
      </div>
      {('<div class="sec"><span class="lbl">Affected asset</span> <span class="loc">'+_esc(loc)+'</span></div>') if loc else ''}
      {('<div class="sec"><span class="lbl">Description</span><div>'+_esc(desc)+'</div></div>') if desc else ''}
      {_evidence_html(f)}
      {valid}
      <div class="sec"><span class="lbl">Remediation</span><div>{_esc(remed)}</div></div>
    </div>"""


def _findings_summary_table(model):
    rows = []
    n = 0
    for f in model["confirmed"] + model["potential"]:
        n += 1
        fid = f.get("_fid") or f"RX-{n:03d}"
        f["_fid"] = fid
        rows.append(
            f'<tr><td class="f-id">{_esc(fid)}</td>'
            f'<td><span class="badge" style="background:{SEV_COLOR.get(f["severity"],"#64748b")}">{_esc(f["severity"]).upper()}</span></td>'
            f'<td><span class="badge" style="background:{_STATUS_COLOR.get(f.get("_status"),"#64748b")}">{_esc(f.get("_status"))}</span></td>'
            f'<td>{_esc(f.get("name",""))}</td><td class="loc">{_esc(rm._asset(f.get("location")))}</td></tr>'
        )
    if not rows:
        return '<h2>Findings summary</h2><p class="muted">No confirmed or potential findings.</p>'
    return (f'<h2>Findings summary</h2><table><thead><tr><th>ID</th><th>Severity</th><th>Status</th>'
            f'<th>Finding</th><th>Asset</th></tr></thead><tbody>{"".join(rows)}</tbody></table>')


def _hardening_section(model):
    if not model["hardening"]:
        return ""
    rows = "".join(
        f'<tr><td><span class="badge" style="background:{SEV_COLOR.get(h["severity"],"#64748b")}">{_esc(h["severity"]).upper()}</span></td>'
        f'<td>{_esc(h["name"])}</td><td class="loc">{_esc(h["asset"])}</td>'
        f'<td class="muted">{_esc(h["remediation"])[:200]}</td></tr>'
        for h in model["hardening"]
    )
    return (f'<h2>Hardening observations</h2>'
            f'<p class="legend">Best-practice gaps (not exploitable vulnerabilities), aggregated per asset.</p>'
            f'<table><thead><tr><th>Severity</th><th>Observation</th><th>Asset</th><th>Remediation</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>')


def _appendix_informational(model):
    if not model["informational"]:
        return ""
    rows = "".join(
        f'<tr><td>{_esc(i["name"])}</td><td class="loc">{_esc(i["asset"])}</td><td class="num">{_esc(i["count"])}</td></tr>'
        for i in model["informational"][:400]
    )
    more = ""
    if len(model["informational"]) > 400:
        more = f'<p class="muted">… and {len(model["informational"]) - 400} more (truncated).</p>'
    return (f'<h2>Appendix A — Attack surface &amp; reconnaissance</h2>'
            f'<p class="legend">Informational reconnaissance (hosts, ports, discovered endpoints, technologies), '
            f'aggregated. These are context, not vulnerabilities.</p>'
            f'<table class="appx"><thead><tr><th>Observation</th><th>Asset</th><th class="num">Count</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>{more}')


def _scope_section(model):
    scope = model["scope"]
    if scope:
        in_scope = ", ".join(_esc(s) for s in scope)
        authz = "Scope explicitly defined for this engagement."
    else:
        in_scope = "Not provided"
        authz = ("Scope not explicitly defined for this engagement. Only assess systems you are explicitly "
                 "authorized to test.")
    return (f'<h2>Scope &amp; rules of engagement</h2>'
            f'<table><tr><td style="width:210px"><b>In scope</b></td><td>{in_scope}</td></tr>'
            f'<tr><td><b>Out of scope</b></td><td>Not provided</td></tr>'
            f'<tr><td><b>Testing type</b></td><td>Automated, non-destructive detection (safe by construction)</td></tr>'
            f'<tr><td><b>Authentication context</b></td><td>Unauthenticated unless identities were supplied</td></tr>'
            f'<tr><td><b>Excluded techniques</b></td><td>Destructive exploitation (human-gated; not performed automatically)</td></tr>'
            f'<tr><td><b>Authorization status</b></td><td>{_esc(authz)}</td></tr></table>')


def _qc_banner(model):
    if not model["qc_issues"]:
        return ""
    items = "".join(f"<li>{_esc(q)}</li>" for q in model["qc_issues"][:10])
    return f'<div class="qc"><b>Report quality checks flagged {len(model["qc_issues"])} item(s):</b><ul>{items}</ul></div>'


def _exec_summary(model):
    c = model["counts"]
    ct, pt = c["confirmed_total"], c["potential_total"]
    if c["confirmed"]["critical"] or c["confirmed"]["high"]:
        narrative = (f"The assessment confirmed {c['confirmed']['critical']+c['confirmed']['high']} high-impact "
                     f"(Critical/High) vulnerability(ies) requiring prompt remediation.")
    elif ct:
        narrative = f"The assessment confirmed {ct} vulnerability(ies), none Critical or High."
    else:
        narrative = "No vulnerabilities were confirmed within the tested scope."
    if pt:
        narrative += (f" A further {pt} potential finding(s) were detected as unconfirmed signals and require "
                      f"validation before they can be treated as vulnerabilities.")
    if c["not_tested_total"]:
        narrative += (f" {c['not_tested_total']} test area(s) were not exercised (see Testing coverage) — "
                      f"their absence from the findings is not evidence the issue is absent.")
    return (f'<h2>Executive summary</h2><div class="note">{_esc(narrative)}</div>')


def _render_findings_detail(model):
    n = 0
    conf_cards, pot_cards = [], []
    for f in model["confirmed"]:
        n += 1
        f.setdefault("_fid", f"RX-{n:03d}")
        conf_cards.append(_finding_card(f["_fid"], f))
    for f in model["potential"]:
        n += 1
        f.setdefault("_fid", f"RX-{n:03d}")
        pot_cards.append(_finding_card(f["_fid"], f, show_validation_hint=True))
    out = ""
    if conf_cards:
        out += "<h2>Confirmed findings</h2>" + "".join(conf_cards)
    if pot_cards:
        out += ('<h2>Potential findings (unconfirmed)</h2>'
                '<p class="legend">Detected as signals but not validated. Do not treat as confirmed vulnerabilities '
                'until verified.</p>' + "".join(pot_cards))
    if not conf_cards and not pot_cards:
        out = "<h2>Findings</h2><p class='muted'>No confirmed or potential findings recorded.</p>"
    return out


def _attck_section(coverage):
    """Render the ATT&CK matrix + gaps + trend (only called when techniques exist)."""
    cov = coverage or {}
    cov_summary = cov.get("summary") or {}
    coverage_pct = cov_summary.get("coverage_pct")
    coverage_pct_html = f"{_esc(coverage_pct)}%" if coverage_pct is not None else "n/a"
    techs_by_tactic: dict = {}
    for t in cov.get("techniques") or []:
        techs_by_tactic.setdefault(t.get("tactic") or "", []).append(t)
    blocks = []
    for tac in cov.get("tactics") or []:
        tid = tac.get("tactic") or ""
        cells = []
        for t in techs_by_tactic.get(tid, []):
            label, color = _coverage_cell(t.get("detected"))
            cells.append(f'<span class="tag" style="border-color:{color};color:{color}">'
                         f'<b>{_esc(t.get("technique_id",""))}</b> {_esc(t.get("name",""))} — {label}</span>')
        cells_html = " ".join(cells) or '<span class="muted">no techniques</span>'
        blocks.append(f'<div class="sec"><b>{_esc(tac.get("name") or tid)}</b> '
                      f'<span class="muted">({_esc(tac.get("detected",0))} detected / {_esc(tac.get("missed",0))} missed '
                      f'/ {_esc(tac.get("total",0))} total)</span><div class="f-meta">{cells_html}</div></div>')
    gap_rows = "".join(
        f"<tr><td>{_esc(g.get('technique_id',''))}</td><td>{_esc(g.get('name',''))}</td>"
        f"<td>{_esc(g.get('tactic',''))}</td></tr>" for g in (cov.get("gaps") or [])
    ) or "<tr><td colspan='3' class='muted'>No outstanding detection gaps.</td></tr>"
    return (f'<h2>ATT&amp;CK Coverage Matrix</h2>'
            f'<div class="note">Detection coverage across emulated techniques: <b>{coverage_pct_html}</b>.</div>'
            f'{"".join(blocks)}'
            f'<h3>Detection Gaps</h3><table><thead><tr><th>Technique</th><th>Name</th><th>Tactic</th></tr></thead>'
            f'<tbody>{gap_rows}</tbody></table>')


def _ai_section(triage):
    """Render AI remediation priorities (only called when triage enabled)."""
    tri = triage or {}
    rows = tri.get("top") or tri.get("findings") or tri.get("items") or []
    item_rows = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        rid = r.get("id", r.get("finding_id"))
        name = r.get("name") or (f"Finding #{rid}" if rid is not None else "")
        ref = f"#{_esc(rid)} " if rid is not None else ""
        sev = str(r.get("severity") or r.get("suggested_severity") or "").lower()
        sev_badge = (f'<span class="badge" style="background:{SEV_COLOR.get(sev,"#64748b")}">{_esc(sev.upper())}</span>'
                     if sev else "")
        action = r.get("recommendation") or r.get("remediation") or r.get("rationale") or ""
        item_rows.append(
            f"<tr><td>{_esc(r.get('priority',''))}</td><td class='f-id'>{ref}</td>"
            f"<td>{_esc(name)}</td><td>{sev_badge}</td><td>{_esc(action)}</td></tr>"
        )
    headline = tri.get("summary") or tri.get("risk_narrative") or ""
    hl = f'<div class="note">{_esc(headline)}</div>' if headline else ""
    body = "".join(item_rows) or "<tr><td colspan='5' class='muted'>No prioritized items.</td></tr>"
    return (f'<h2>Remediation priorities (AI-assisted)</h2>{hl}'
            f'<p class="legend">AI-generated prioritization of the findings above. It does not alter the factual '
            f'evidence and introduces no new findings.</p>'
            f'<table><thead><tr><th>Priority</th><th>Ref</th><th>Finding</th><th>Severity</th>'
            f'<th>Recommended action</th></tr></thead><tbody>{body}</tbody></table>')


def _assemble(title_brand, brand_inner, accent, doc_type, sections, footer_html):
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{title_brand} Security Assessment Report</title>
<style>{_CSS.format(accent=accent)}</style></head>
<body>
<button class="print-btn" onclick="window.print()">Save as PDF</button>
<div class="page">
  <div class="top">
    <div><div class="brand">{brand_inner}</div><div class="muted">{_esc(doc_type)}</div></div>
    <div class="meta" style="text-align:right">Generated {generated}<br>Report v1.0</div>
  </div>
  {sections}
  <div class="disclaimer">
    <b>Authorized testing notice.</b> This report documents automated, non-destructive
    reconnaissance and detection performed with RedOpsX. Findings are detection-based:
    Confirmed items were validated by the tooling, Potential items are unconfirmed signals
    requiring manual validation, and Not-Tested areas were not exercised. Any exploitation
    capability is human-gated and non-destructive. Conduct testing only against systems you
    are explicitly authorized to assess.{footer_html}
  </div>
</div>
</body></html>"""


def generate(project: dict, findings: list, scans: list, branding: dict | None = None,
             tools: dict | None = None) -> str:
    """Render the standard security-assessment report (V2)."""
    branding = branding or {}
    brand_name, accent, brand_inner, title_brand, footer_html = _brand_bits(branding, "#0d9488")
    model = rm.build_model(project, findings, scans, tools=tools)
    sections = "".join([
        f'<h1>{_esc(project.get("name",""))}</h1><div class="meta">{_esc(project.get("description",""))}</div>',
        _qc_banner(model),
        _cover(model, project, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "Security Assessment Report"),
        _dashboard(model),
        _exec_summary(model),
        _scope_section(model),
        _risk_table(model),
        _coverage_table(model),
        _findings_summary_table(model),
        _render_findings_detail(model),
        _hardening_section(model),
        _appendix_informational(model),
    ])
    return _assemble(title_brand, brand_inner, accent, "Security Assessment Report", sections, footer_html)


def generate_purple(project: dict, findings: list, scans: list, coverage: dict,
                    triage: dict | None = None, branding: dict | None = None,
                    tools: dict | None = None) -> str:
    """Render the purple-team report (V2): standard report + conditional ATT&CK + AI."""
    branding = branding or {}
    brand_name, accent, brand_inner, title_brand, footer_html = _brand_bits(branding, "#7c3aed", suffix="Purple")
    model = rm.build_model(project, findings, scans, tools=tools, coverage=coverage, triage=triage)

    attck = _attck_section(coverage) if model["attck_present"] else (
        '<h2>Purple-team detection validation</h2>'
        '<div class="note">Purple-team detection validation was not performed for this engagement '
        '(no ATT&amp;CK techniques were emulated).</div>')
    ai = _ai_section(triage) if model["triage_present"] else ""

    sections = "".join([
        f'<h1>{_esc(project.get("name",""))}</h1><div class="meta">{_esc(project.get("description",""))}</div>',
        _qc_banner(model),
        _cover(model, project, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "Purple-Team Assessment Report"),
        _dashboard(model),
        _exec_summary(model),
        _scope_section(model),
        _risk_table(model),
        _coverage_table(model),
        _findings_summary_table(model),
        _render_findings_detail(model),
        _hardening_section(model),
        attck,
        ai,
        _appendix_informational(model),
    ])
    return _assemble(title_brand, brand_inner, accent, "Purple-Team Assessment Report", sections, footer_html)
