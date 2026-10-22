"""Reporter: turns a campaign result into decisions.

Executive view first (what falls, what to fix first), technical detail
second (every step, every proof, the evidence ids). Two formats:
Markdown, and a self-contained dark HTML dashboard with the attack
path rendered as an SVG diagram — no external assets, opens anywhere.
"""

from __future__ import annotations

import html

from .graph import Graph

_FIXES = [
    ("sql injection", "Parameterize every query; least-privilege DB user "
                      "(the web app must not be able to read the users table)."),
    ("credential reuse", "Unique credentials per service, stored in a vault; "
                         "rotate the leaked service password everywhere."),
    ("password reused", "Unique credentials per service, stored in a vault; "
                        "rotate the leaked service password everywhere."),
    ("path traversal", "Canonicalize paths and whitelist downloadable files; "
                       "never let user input address the filesystem directly."),
    ("token", "Short-lived, narrowly-scoped API tokens; store outside the "
              "file shares the app can serve."),
    ("reach", "Reduce the public attack surface; put internal apps behind "
              "the VPN/SSO boundary."),
]


def fix_for(technique: str) -> str:
    t = technique.lower()
    for key, fix in _FIXES:
        if key in t:
            return fix
    return "Harden or remove this step; re-run the campaign to verify."


def _choke_and_blast(graph: Graph, plan: dict) -> tuple[list, dict]:
    entry, goal = plan["entry"], plan["goal"]
    chokes = graph.choke_points(entry, goal) if plan["reachable"] else []
    blast = graph.blast_radius(entry) if plan["reachable"] else {}
    return chokes, blast


def build_markdown(result: dict, graph: Graph, org: str = "") -> str:
    plan = result["plan"]
    chokes, blast = _choke_and_blast(graph, plan)
    lines = [f"# LEVIATHAN Campaign Report — {result['campaign']}", ""]
    if org:
        lines.append(f"**Organisation:** {org}  ")
    lines += [f"**Goal:** {plan['goal']}  ",
              f"**Path proven end-to-end:** {'YES' if result['proven'] else 'NO'}  ",
              f"**Risk:** impact {plan['risk']['impact']} × likelihood "
              f"{plan['risk']['likelihood']} = **{plan['risk']['score']}**", ""]
    if plan["reachable"]:
        lines += ["## The attack path", "",
                  " → ".join(plan["best_path"]["assets"]), ""]
    lines += ["## Steps and proof", "",
              "| # | From → To | Technique | Proof |",
              "|---|---|---|---|"]
    for s in result["steps"]:
        lines.append(f"| {s['step']} | {s['from']} → {s['to']} | "
                     f"{s['technique']} | **{s['proof']}** |")
    lines += ["", "## Fix first (choke points)", ""]
    if chokes:
        for c in chokes:
            lines.append(f"- **{c['asset']}** — lies on {c['paths_through']} of "
                         f"{c['of_total']} paths"
                         + (" — hardening it breaks EVERY known path."
                            if c["breaks_all_paths"] else "."))
    else:
        lines.append("- No choke points identified.")
    lines += ["", "## Remediation per step", ""]
    for s in result["steps"]:
        lines.append(f"{s['step']}. **{s['technique']}** — {fix_for(s['technique'])}")
    if blast.get("crown_jewels_at_risk"):
        lines += ["", "## Blast radius from the entry point", "",
                  f"From `{plan['entry']}` an attacker can reach: "
                  f"{', '.join(blast['reachable'])}. "
                  f"Crown jewels at risk: {', '.join(blast['crown_jewels_at_risk'])} "
                  f"(value {blast['value_at_risk']})."]
    lines += ["", "---", "Proof standard: CONFIRMED = canary evidence captured · "
              "LIKELY = observed posture · THEORETICAL = graph inference · "
              "FAILED = step did not work. Evidence is hash-chained in the vault."]
    return "\n".join(lines) + "\n"


def _svg_path(plan: dict) -> str:
    assets = plan["best_path"]["assets"] if plan["reachable"] else []
    if not assets:
        return ""
    w = max(640, 190 * len(assets))
    parts = [f'<svg viewBox="0 0 {w} 110" xmlns="http://www.w3.org/2000/svg">']
    for i, a in enumerate(assets):
        x = 20 + i * 185
        fill = "#7f1d1d" if a == plan["goal"] else "#1e293b"
        parts.append(f'<rect x="{x}" y="30" width="150" height="46" rx="8" '
                     f'fill="{fill}" stroke="#38bdf8"/>')
        parts.append(f'<text x="{x + 75}" y="58" fill="#e2e8f0" '
                     f'text-anchor="middle" font-size="13">{html.escape(a)}</text>')
        if i < len(assets) - 1:
            parts.append(f'<line x1="{x + 150}" y1="53" x2="{x + 185}" y2="53" '
                         f'stroke="#f43f5e" stroke-width="2"/>')
            parts.append(f'<polygon points="{x + 185},53 {x + 177},49 {x + 177},57" '
                         f'fill="#f43f5e"/>')
    parts.append("</svg>")
    return "".join(parts)


def build_html(result: dict, graph: Graph, org: str = "") -> str:
    plan = result["plan"]
    chokes, _ = _choke_and_blast(graph, plan)
    badge = {"CONFIRMED": "#22c55e", "LIKELY": "#eab308",
             "THEORETICAL": "#64748b", "FAILED": "#ef4444"}
    steps_html = "".join(
        f'<div class="step"><b>Step {s["step"]}</b> '
        f'{html.escape(s["from"])} → {html.escape(s["to"])}<br>'
        f'<i>{html.escape(s["technique"])}</i><br>'
        f'<span class="badge" style="background:{badge.get(s["proof"], "#666")}">'
        f'{s["proof"]}</span> {html.escape(s["detail"])}<br>'
        f'<small>Fix: {html.escape(fix_for(s["technique"]))}</small></div>'
        for s in result["steps"])
    choke_html = "".join(
        f'<li><b>{html.escape(c["asset"])}</b> — {c["paths_through"]}/'
        f'{c["of_total"]} paths'
        + (" · breaks ALL paths" if c["breaks_all_paths"] else "") + "</li>"
        for c in chokes) or "<li>none identified</li>"
    verdict = "PATH PROVEN" if result["proven"] else "NOT FULLY PROVEN"
    vcolor = "#22c55e" if result["proven"] else "#ef4444"
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>LEVIATHAN — {html.escape(result['campaign'])}</title>
<style>body{{background:#020617;color:#e2e8f0;font-family:ui-monospace,Menlo,monospace;margin:2rem}}
h1{{color:#38bdf8}} .step{{background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:1rem;margin:.6rem 0}}
.badge{{color:#020617;border-radius:4px;padding:.1rem .45rem;font-weight:700}}
.verdict{{font-size:1.3rem;color:{vcolor};font-weight:700}}</style></head>
<body><h1>🐉 LEVIATHAN — Campaign {html.escape(result['campaign'])}</h1>
<p>{html.escape(org)} · Goal: <b>{html.escape(plan['goal'])}</b> · Risk score:
<b>{plan['risk']['score']}</b> (impact {plan['risk']['impact']} × likelihood {plan['risk']['likelihood']})</p>
<p class="verdict">{verdict}</p>
<h2>Attack path</h2>{_svg_path(plan)}
<h2>Steps &amp; proof</h2>{steps_html}
<h2>Fix first — choke points</h2><ul>{choke_html}</ul>
<p><small>Canary proof standard: no destructive payloads were used. All evidence is hash-chained in the vault.</small></p>
</body></html>"""
