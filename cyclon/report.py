"""HTML report generation."""

import html
from pathlib import Path


def write_html_report(result, path: Path, agents: list[str] | None = None):
    findings = result.findings
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings_sorted = sorted(findings, key=lambda f: (sev_order.get(f.severity, 5), f.file, f.line or 0))

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    agents = agents or []
    agent_counts = {}
    for f in findings:
        for a in [x.strip() for x in (f.agent or "").split(",") if x.strip()]:
            agent_counts[a] = agent_counts.get(a, 0) + 1

    def esc(x):
        return html.escape(str(x)) if x is not None else ""

    sev_color = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308",
                 "low": "#3b82f6", "info": "#6b7280"}

    # Group findings by file for readability
    by_file = {}
    for f in findings_sorted:
        by_file.setdefault(f.file, []).append(f)

    file_sections = []
    for fname, fs in by_file.items():
        cards = []
        for f in fs:
            color = sev_color.get(f.severity, "#6b7280")
            loc = esc(fname)
            if f.line:
                loc += f":{f.line}"
            agents_str = esc(f.agent) if f.agent else "—"
            cards.append(f"""
            <article class="finding" data-sev="{esc(f.severity)}" data-agent="{esc(f.agent)}">
              <header class="fhead">
                <span class="badge sev" style="background:{color}">{esc(f.severity.upper())}</span>
                <span class="loc">{loc}</span>
                <h3 class="title">{esc(f.title)}</h3>
              </header>
              <div class="meta">
                <span><strong>Category:</strong> {esc(f.category)}</span>
                <span><strong>Agents:</strong> {agents_str}</span>
              </div>
              <p class="desc">{esc(f.description)}</p>
              {('<details class="sugg"><summary>Suggested fix</summary><pre><code>' + esc(f.suggestion) + '</code></pre></details>') if f.suggestion else ''}
            </article>
            """)
        file_sections.append(f"""
        <section class="filegroup">
          <h2 class="filetitle">📄 {esc(fname)} <span class="filecount">({len(fs)} issue{'s' if len(fs)!=1 else ''})</span></h2>
          {''.join(cards)}
        </section>
        """)

    counts_html = "".join(
        f'<button class="filter" data-filter="sev:{esc(k)}">{esc(k)} <span>{v}</span></button>'
        for k, v in sorted(counts.items(), key=lambda kv: sev_order.get(kv[0], 9))
    )
    agents_html = "".join(
        f'<button class="filter" data-filter="agent:{esc(a)}">{esc(a)} <span>{n}</span></button>'
        for a, n in sorted(agent_counts.items())
    )

    errors_html = ""
    if result.errors:
        errors_html = (
            "<section class='errors'><h2>⚠ Errors</h2><ul>"
            + "".join(f"<li>{esc(e)}</li>" for e in result.errors)
            + "</ul></section>"
        )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>cyclon report</title>
<style>
  :root {{
    --bg:#0b1220; --panel:#111a2e; --card:#16203a; --border:#24304d;
    --text:#e6edf7; --muted:#94a3b8; --accent:#38bdf8; --accent2:#a78bfa;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
         background:var(--bg); color:var(--text); line-height:1.5; }}
  header.top {{ padding:28px 32px; background:linear-gradient(135deg,#0f172a,#1e1b4b); border-bottom:1px solid var(--border); }}
  header.top h1 {{ margin:0 0 6px; font-size:28px; color:var(--accent); }}
  header.top .sub {{ color:var(--muted); font-size:14px; }}
  .summary {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; padding:20px 32px; }}
  .stat {{ background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:14px 16px; }}
  .stat .label {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.05em; }}
  .stat .value {{ font-size:24px; font-weight:700; margin-top:4px; }}
  .toolbar {{ padding:12px 32px; display:flex; flex-wrap:wrap; gap:8px; align-items:center; border-bottom:1px solid var(--border); background:var(--panel); position:sticky; top:0; z-index:5; }}
  .toolbar input {{ padding:8px 12px; border-radius:8px; border:1px solid var(--border); background:var(--bg); color:var(--text); min-width:220px; }}
  .filter {{ background:var(--bg); color:var(--text); border:1px solid var(--border); border-radius:999px; padding:6px 12px; cursor:pointer; font-size:13px; }}
  .filter span {{ background:var(--border); border-radius:999px; padding:0 6px; margin-left:6px; font-size:11px; }}
  .filter.active {{ background:var(--accent); color:#0b1220; border-color:var(--accent); }}
  .filter.active span {{ background:rgba(0,0,0,.2); color:#0b1220; }}
  .content {{ padding:20px 32px 60px; max-width:1200px; margin:0 auto; }}
  .filegroup {{ margin-bottom:24px; }}
  .filetitle {{ font-size:16px; color:var(--accent2); border-bottom:1px solid var(--border); padding-bottom:6px; }}
  .filecount {{ color:var(--muted); font-size:13px; font-weight:400; }}
  .finding {{ background:var(--card); border:1px solid var(--border); border-radius:12px; padding:14px 16px; margin:10px 0; transition:transform .1s; }}
  .finding:hover {{ transform:translateY(-1px); }}
  .finding.hidden {{ display:none; }}
  .fhead {{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; }}
  .badge.sev {{ color:#fff; padding:3px 9px; border-radius:6px; font-size:11px; font-weight:700; }}
  .loc {{ font-family:ui-monospace, SFMono-Regular, Menlo, monospace; color:var(--muted); font-size:13px; }}
  .title {{ margin:0; font-size:15px; font-weight:600; flex:1; min-width:200px; }}
  .meta {{ color:var(--muted); font-size:12px; margin:8px 0; display:flex; gap:16px; flex-wrap:wrap; }}
  .desc {{ margin:8px 0; white-space:pre-wrap; }}
  details.sugg {{ background:var(--bg); border:1px solid var(--border); border-radius:8px; padding:8px 12px; }}
  details.sugg summary {{ cursor:pointer; color:var(--accent); font-weight:600; }}
  details.sugg pre {{ margin:8px 0 0; overflow:auto; }}
  code {{ font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:13px; }}
  .errors {{ background:#2a1215; border:1px solid #7f1d1d; border-radius:12px; padding:14px 16px; margin-top:20px; }}
  .errors h2 {{ color:#fca5a5; margin-top:0; }}
  footer {{ text-align:center; color:var(--muted); font-size:12px; padding:20px; }}
  @media (max-width:600px) {{ .content,.summary,.toolbar {{ padding-left:16px; padding-right:16px; }} }}
</style>
</head>
<body>
<header class="top">
  <h1>🛡️ cyclon scan report</h1>
  <div class="sub">Multi-agent code analysis · {len(agents)} agent{'s' if len(agents)!=1 else ''}</div>
</header>

<div class="summary">
  <div class="stat"><div class="label">Root</div><div class="value" style="font-size:14px;word-break:break-all">{esc(result.root)}</div></div>
  <div class="stat"><div class="label">Files scanned</div><div class="value">{result.files_scanned}</div></div>
  <div class="stat"><div class="label">Issues found</div><div class="value">{len(findings)}</div></div>
  <div class="stat"><div class="label">Agents</div><div class="value" style="font-size:14px">{esc(", ".join(agents)) if agents else "—"}</div></div>
</div>

<div class="toolbar">
  <input id="search" type="search" placeholder="Search title, file, description…">
  <button class="filter active" data-filter="all">All <span>{len(findings)}</span></button>
  {counts_html}
  {agents_html}
</div>

<div class="content">
  {''.join(file_sections) if file_sections else '<p style="color:var(--muted)">No issues found. 🎉</p>'}
  {errors_html}
</div>

<footer>Generated by cyclon · {len(findings)} issue{'s' if len(findings)!=1 else ''}</footer>

<script>
  const search = document.getElementById('search');
  const filters = document.querySelectorAll('.filter');
  let activeFilter = 'all';
  function apply() {{
    const q = (search.value || '').toLowerCase();
    document.querySelectorAll('.finding').forEach(el => {{
      const text = el.innerText.toLowerCase();
      const sev = el.dataset.sev;
      const agent = el.dataset.agent || '';
      let show = true;
      if (activeFilter.startsWith('sev:')) show = sev === activeFilter.slice(4);
      else if (activeFilter.startsWith('agent:')) show = agent.includes(activeFilter.slice(6));
      if (q && !text.includes(q)) show = false;
      el.classList.toggle('hidden', !show);
    }});
    // hide empty file groups
    document.querySelectorAll('.filegroup').forEach(g => {{
      const visible = g.querySelectorAll('.finding:not(.hidden)').length;
      g.style.display = visible ? '' : 'none';
    }});
  }}
  filters.forEach(b => b.addEventListener('click', () => {{
    filters.forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    activeFilter = b.dataset.filter;
    apply();
  }}));
  search.addEventListener('input', apply);
</script>
</body>
</html>
"""
    path.write_text(doc, encoding="utf-8")
    return path
