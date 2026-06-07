"""
Threat Intelligence Aggregator — Web Dashboard
Run: python3 dashboard.py
Open: http://localhost:5000
"""

import os
import sys
import json
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from flask import Flask, render_template_string, jsonify, request, redirect, url_for
except ImportError:
    print("[ERROR] Flask not installed. Run:  pip3 install flask")
    sys.exit(1)

from modules.parser        import load_all_feeds
from modules.normalizer    import normalize_all
from modules.correlator    import correlate
from modules.blocklist_gen import generate_blocklists
from modules.reporter      import generate_report

BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
FEEDS_DIR     = os.path.join(BASE_DIR, "feeds")
OUTPUT_DIR    = os.path.join(BASE_DIR, "output")
BLOCKLIST_DIR = os.path.join(OUTPUT_DIR, "blocklists")
REPORT_DIR    = os.path.join(OUTPUT_DIR, "reports")

app  = Flask(__name__)
DATA = {}   # holds last pipeline result in memory

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TI Aggregator Dashboard</title>
<style>
  :root{--bg:#0d1117;--card:#161b22;--border:#30363d;--accent:#58a6ff;
        --green:#3fb950;--red:#f85149;--yellow:#d29922;--text:#e6edf3;--sub:#8b949e}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:'Segoe UI',sans-serif;min-height:100vh}
  header{background:var(--card);border-bottom:1px solid var(--border);
         padding:16px 32px;display:flex;align-items:center;justify-content:space-between}
  header h1{font-size:1.3rem;color:var(--accent)}
  header span{font-size:.8rem;color:var(--sub)}
  .container{padding:28px 32px;max-width:1400px;margin:auto}
  .run-btn{background:var(--accent);color:#000;border:none;padding:10px 26px;
           border-radius:6px;font-size:.95rem;font-weight:700;cursor:pointer;
           text-decoration:none;display:inline-block;margin-bottom:24px}
  .run-btn:hover{opacity:.85}
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:28px}
  .stat{background:var(--card);border:1px solid var(--border);border-radius:8px;
        padding:20px;text-align:center}
  .stat .num{font-size:2rem;font-weight:700}
  .stat .lbl{font-size:.8rem;color:var(--sub);margin-top:4px}
  .high{color:var(--red)} .medium{color:var(--yellow)} .low{color:var(--green)}
  .accent{color:var(--accent)}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:28px}
  @media(max-width:900px){.grid2{grid-template-columns:1fr}}
  .card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:20px}
  .card h3{font-size:1rem;margin-bottom:14px;color:var(--accent)}
  table{width:100%;border-collapse:collapse;font-size:.85rem}
  th{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);color:var(--sub);font-weight:600}
  td{padding:8px 10px;border-bottom:1px solid var(--border)}
  tr:last-child td{border-bottom:none}
  .badge{padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:700}
  .badge.HIGH{background:#f8514933;color:var(--red)}
  .badge.MEDIUM{background:#d2992233;color:var(--yellow)}
  .badge.LOW{background:#3fb95033;color:var(--green)}
  .search-bar{width:100%;padding:10px 14px;background:var(--card);border:1px solid var(--border);
              border-radius:6px;color:var(--text);font-size:.9rem;margin-bottom:16px}
  .search-bar:focus{outline:none;border-color:var(--accent)}
  .no-data{color:var(--sub);text-align:center;padding:40px;font-size:.95rem}
  .bar-wrap{display:flex;align-items:center;gap:10px;margin:6px 0}
  .bar-label{width:80px;font-size:.8rem;color:var(--sub);text-align:right}
  .bar{height:16px;border-radius:4px;background:var(--accent);opacity:.8}
  .bar-val{font-size:.8rem;color:var(--sub)}
  .filter-row{display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap}
  .filter-btn{padding:5px 14px;border-radius:5px;border:1px solid var(--border);
              background:transparent;color:var(--text);cursor:pointer;font-size:.82rem}
  .filter-btn.active,.filter-btn:hover{background:var(--accent);color:#000;border-color:var(--accent)}
  .empty{display:flex;flex-direction:column;align-items:center;justify-content:center;
         min-height:60vh;gap:16px;color:var(--sub)}
  .empty h2{color:var(--text);font-size:1.4rem}
</style>
</head>
<body>
<header>
  <h1>&#x1F6E1; Threat Intelligence Aggregator</h1>
  <span>{{ generated }}</span>
</header>
<div class="container">

{% if not has_data %}
<div class="empty">
  <div style="font-size:3rem">&#x1F4CB;</div>
  <h2>No Analysis Run Yet</h2>
  <p>Click the button below to parse your feeds and generate results.</p>
  <form method="POST" action="/run">
    <button class="run-btn" type="submit">&#9654; Run Analysis Now</button>
  </form>
</div>

{% else %}
<form method="POST" action="/run" style="display:inline">
  <button class="run-btn" type="submit">&#9654; Re-Run Analysis</button>
</form>

<!-- STAT CARDS -->
<div class="stats">
  <div class="stat"><div class="num accent">{{ stats.total }}</div><div class="lbl">Total Unique IOCs</div></div>
  <div class="stat"><div class="num high">{{ stats.high }}</div><div class="lbl">HIGH Severity</div></div>
  <div class="stat"><div class="num medium">{{ stats.medium }}</div><div class="lbl">MEDIUM Severity</div></div>
  <div class="stat"><div class="num low">{{ stats.low }}</div><div class="lbl">LOW Severity</div></div>
  <div class="stat"><div class="num accent">{{ stats.correlated }}</div><div class="lbl">Cross-Feed Hits</div></div>
  <div class="stat"><div class="num">{{ stats.feeds }}</div><div class="lbl">Feeds Processed</div></div>
</div>

<!-- CHARTS ROW -->
<div class="grid2">
  <!-- IOC by Type -->
  <div class="card">
    <h3>&#x1F4CA; IOC Distribution by Type</h3>
    {% set max_v = type_counts.values()|list|max %}
    {% for t, c in type_counts.items() %}
    <div class="bar-wrap">
      <div class="bar-label">{{ t }}</div>
      <div class="bar" style="width:{{ (c/max_v*200)|int }}px"></div>
      <div class="bar-val">{{ c }}</div>
    </div>
    {% endfor %}
  </div>

  <!-- Blocklist Summary -->
  <div class="card">
    <h3>&#x1F512; Blocklist Output Summary</h3>
    <table>
      <tr><th>Blocklist</th><th>Entries</th></tr>
      {% for bl, cnt in blocklist_summary.items() %}
      <tr><td>{{ bl.replace('_',' ').title() }}</td><td>{{ cnt }}</td></tr>
      {% endfor %}
    </table>
  </div>
</div>

<!-- IOC TABLE -->
<div class="card">
  <h3>&#x1F50D; All IOC Indicators</h3>
  <input class="search-bar" id="searchBox" type="text" placeholder="Search IOCs, types, sources..." oninput="filterTable()">
  <div class="filter-row">
    <button class="filter-btn active" onclick="filterSev(this,'ALL')">All</button>
    <button class="filter-btn" onclick="filterSev(this,'HIGH')">&#x1F534; HIGH</button>
    <button class="filter-btn" onclick="filterSev(this,'MEDIUM')">&#x1F7E1; MEDIUM</button>
    <button class="filter-btn" onclick="filterSev(this,'LOW')">&#x1F7E2; LOW</button>
    <button class="filter-btn" onclick="filterSev(this,'CORR')">&#x1F517; Correlated</button>
  </div>
  <table id="iocTable">
    <thead>
      <tr>
        <th>Severity</th><th>Type</th><th>Risk Score</th>
        <th>Feeds</th><th>Indicator</th><th>Sources</th>
      </tr>
    </thead>
    <tbody>
    {% for ioc in all_iocs %}
    <tr data-sev="{{ ioc.final_severity }}" data-corr="{{ ioc.is_correlated }}">
      <td><span class="badge {{ ioc.final_severity }}">{{ ioc.final_severity }}</span></td>
      <td>{{ ioc.type }}</td>
      <td>{{ ioc.risk_score }}</td>
      <td>{{ ioc.feed_count }}</td>
      <td style="font-family:monospace;word-break:break-all">{{ ioc.value }}</td>
      <td style="font-size:.78rem;color:var(--sub)">{{ ioc.sources|join(', ') }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% endif %}

</div>
<script>
let currentSev = 'ALL';
function filterTable(){
  const q = document.getElementById('searchBox').value.toLowerCase();
  document.querySelectorAll('#iocTable tbody tr').forEach(row => {
    const txt = row.innerText.toLowerCase();
    const sevOk = currentSev === 'ALL'
      || (currentSev === 'CORR' && row.dataset.corr === 'True')
      || row.dataset.sev === currentSev;
    row.style.display = (txt.includes(q) && sevOk) ? '' : 'none';
  });
}
function filterSev(btn, sev){
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  currentSev = sev;
  filterTable();
}
</script>
</body>
</html>
"""


def run_pipeline():
    raw        = load_all_feeds(FEEDS_DIR)
    normalized = normalize_all(raw)
    correlated = correlate(normalized)
    bl_summary = generate_blocklists(correlated, BLOCKLIST_DIR)
    generate_report(correlated, bl_summary, FEEDS_DIR, REPORT_DIR)

    type_counts = {}
    for ioc in correlated:
        type_counts[ioc["type"]] = type_counts.get(ioc["type"], 0) + 1

    DATA["all_iocs"]         = correlated
    DATA["type_counts"]      = dict(sorted(type_counts.items(), key=lambda x: -x[1]))
    DATA["blocklist_summary"] = bl_summary
    DATA["stats"] = {
        "total":      len(correlated),
        "high":       sum(1 for i in correlated if i["final_severity"] == "HIGH"),
        "medium":     sum(1 for i in correlated if i["final_severity"] == "MEDIUM"),
        "low":        sum(1 for i in correlated if i["final_severity"] == "LOW"),
        "correlated": sum(1 for i in correlated if i["is_correlated"]),
        "feeds":      len([f for f in os.listdir(FEEDS_DIR) if os.path.isfile(os.path.join(FEEDS_DIR, f))]),
    }
    DATA["generated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


@app.route("/")
def index():
    has_data = bool(DATA)
    return render_template_string(
        HTML,
        has_data       = has_data,
        stats          = DATA.get("stats", {}),
        type_counts    = DATA.get("type_counts", {}),
        blocklist_summary = DATA.get("blocklist_summary", {}),
        all_iocs       = DATA.get("all_iocs", []),
        generated      = DATA.get("generated", ""),
    )


@app.route("/run", methods=["POST"])
def run():
    run_pipeline()
    return redirect(url_for("index"))


@app.route("/api/iocs")
def api_iocs():
    return jsonify(DATA.get("all_iocs", []))


@app.route("/api/stats")
def api_stats():
    return jsonify(DATA.get("stats", {}))


if __name__ == "__main__":
    print("\n  TI Aggregator Dashboard")
    print("  Open http://localhost:5000 in your browser\n")
    app.run(debug=False, host="0.0.0.0", port=5000)
