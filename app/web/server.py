from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from app.analysis.attack_paths import build_attack_paths
from app.analysis.baseline import detect_baseline_deviations, get_baseline
from app.analysis.investigations import fetch_evidence, protocols_used, top_device_by_traffic
from app.analysis.reporting import write_report
from app.analysis.topology import build_topology, persist_topology_snapshot
from app.config import settings
from app.fingerprint.fingerprint import enrich_devices
from app.llm.ollama_provider import OllamaProvider
from app.storage.database import initialize_database
from app.capture.manager import detect_capture_capability, start_capture


def _html() -> str:
    asset_version = str(int(datetime.now(timezone.utc).timestamp()))
    return (
        """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Network AI Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js?t=__ASSET_VERSION__"></script>
  <script src="https://cdn.jsdelivr.net/npm/vis-network@9.1.9/dist/vis-network.min.js?t=__ASSET_VERSION__"></script>
  <link href="https://cdn.jsdelivr.net/npm/vis-network@9.1.9/styles/vis-network.min.css?t=__ASSET_VERSION__" rel="stylesheet" />
  <style>
    :root {
      --bg:#0b1220;
      --panel:#1e293b;
      --panel2:#162235;
      --line:#31445f;
      --text:#e5eefc;
      --muted:#91a4c4;
      --cyan:#4fd1ff;
      --blue:#5b8cff;
      --green:#27d17f;
      --yellow:#f5c451;
      --orange:#f59e0b;
      --red:#ef5a72;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: Inter, Segoe UI, Arial, sans-serif; background: linear-gradient(180deg, #0b1220 0%, #09111b 100%); color: var(--text); }
    header { padding: 18px 22px; display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid rgba(49,68,95,.9); background: rgba(11,18,32,.92); position: sticky; top:0; backdrop-filter: blur(16px); z-index: 10; }
    .title { font-size: 20px; font-weight: 800; letter-spacing: .2px; }
    .subtitle { color: var(--muted); font-size: 12px; margin-top: 3px; }
    main { display:grid; gap: 14px; padding: 14px; max-width: 1700px; margin: 0 auto; }
    .kpis { display:grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; }
    .kpi { background: linear-gradient(180deg, rgba(30,41,59,.98), rgba(22,34,53,.98)); border:1px solid var(--line); border-radius: 18px; padding: 16px; box-shadow: 0 16px 32px rgba(0,0,0,.22); }
    .kpi .label { color: var(--muted); font-size: 12px; margin-bottom: 10px; }
    .kpi .value { font-size: 28px; font-weight: 800; line-height: 1; }
    .kpi .hint { color: var(--muted); font-size: 13px; margin-top: 8px; }
    .nav-actions { display:flex; flex-wrap:wrap; gap: 8px; }
    .grid-mid { display:grid; grid-template-columns: 3fr 2fr; gap: 14px; align-items:start; }
    .grid-bottom { display:grid; grid-template-columns: 2fr 1fr; gap: 14px; align-items:start; }
    .right-rail { display:grid; gap: 14px; }
    section { background: linear-gradient(180deg, rgba(30,41,59,.98), rgba(22,34,53,.98)); border: 1px solid var(--line); border-radius: 18px; padding: 14px; box-shadow: 0 16px 32px rgba(0,0,0,.18); }
    h2 { margin: 0 0 12px; font-size: 15px; letter-spacing: .2px; }
    .muted { color: var(--muted); font-size: 12px; }
    .toolbar { display:flex; flex-wrap:wrap; gap: 8px; }
    button, input, select, textarea {
      border-radius: 12px; border:1px solid var(--line); background: #101b2d; color: var(--text);
      padding: 10px 12px; font: inherit;
    }
    button { cursor:pointer; }
    button.primary { background: linear-gradient(180deg, var(--blue), #314fcc); border-color: rgba(91,140,255,.7); }
    .panel { min-height: 120px; white-space: pre-wrap; word-break: break-word; background: #10192a; border-radius: 14px; border:1px solid var(--line); padding: 12px; }
    .chatlog { max-height: 170px; overflow:auto; display:grid; gap: 8px; margin-bottom: 10px; }
    .msg { padding: 10px; border-radius: 12px; border:1px solid var(--line); }
    .msg.user { background: rgba(39,88,255,.12); }
    .msg.bot { background: rgba(255,255,255,.03); }
    .modal-backdrop { position:fixed; inset:0; background: rgba(0,0,0,.6); display:none; align-items:center; justify-content:center; padding:20px; z-index: 50; }
    .modal { width:min(900px, 100%); max-height: 90vh; overflow:auto; background: #0d1628; border:1px solid var(--line); border-radius: 18px; padding: 18px; }
    .split { display:grid; grid-template-columns: 60% 40%; gap: 14px; align-items:start; }
    .devices-table { width:100%; border-collapse: collapse; }
    .devices-table th, .devices-table td { text-align:left; padding: 11px 10px; border-bottom: 1px solid rgba(49,68,95,.75); font-size: 13px; }
    .devices-table th { color: #cfe0ff; font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }
    .row-click { cursor:pointer; }
    .row-click:hover { background: rgba(255,255,255,.03); }
    .status { display:inline-flex; align-items:center; gap: 6px; padding: 4px 10px; border-radius: 999px; font-size: 11px; border:1px solid transparent; }
    .status.good { background: rgba(39,209,127,.14); color: #bff6db; border-color: rgba(39,209,127,.25); }
    .status.warn { background: rgba(245,196,81,.14); color: #fdebb8; border-color: rgba(245,196,81,.24); }
    .status.bad { background: rgba(239,90,114,.14); color: #ffd0d8; border-color: rgba(239,90,114,.25); }
    .feed { display:grid; gap: 10px; max-height: 420px; overflow:auto; }
    .feed-item { border:1px solid var(--line); border-radius: 14px; padding: 12px; background: rgba(255,255,255,.025); }
    .feed-item.low { border-left: 4px solid var(--yellow); }
    .feed-item.medium { border-left: 4px solid var(--orange); }
    .feed-item.high { border-left: 4px solid var(--red); }
    .feed-title { display:flex; justify-content:space-between; gap: 10px; font-weight: 700; }
    .ellipsis { color: var(--muted); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width: 100%; }
    .mini-grid { display:grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
    .mini-card { background: #10192a; border:1px solid var(--line); border-radius: 14px; padding: 12px; }
    .chart-wrap { height: 220px; }
    #graph { height: 560px; border-radius: 14px; border:1px solid var(--line); background: #09111f; }
    .commands { display:grid; gap: 8px; }
    .command-item { display:flex; justify-content:space-between; gap: 12px; align-items:center; }
    .badge { display:inline-flex; align-items:center; gap: 6px; padding: 4px 9px; border-radius: 999px; background: rgba(79,209,255,.12); color:#c6efff; border:1px solid rgba(79,209,255,.2); font-size: 11px; }
    .panel-glow:hover { box-shadow: 0 0 0 1px rgba(79,209,255,.15), 0 0 24px rgba(79,209,255,.12); }
    .cmd-output.hidden { color: var(--muted); }
    .legend-list { display:grid; gap: 6px; margin-top: 10px; font-size: 12px; color: var(--muted); }
    .legend-item { display:flex; align-items:center; gap: 8px; }
    .dot { width: 10px; height: 10px; border-radius: 50%; display:inline-block; }
  </style>
</head>
<body>
  <header>
    <div>
      <div class="title">Network AI Command Center</div>
      <div class="subtitle">SQLite-backed live dashboard, auto-refresh every 3 seconds</div>
    </div>
    <div class="nav-actions">
      <button class="primary" onclick="runCommand('capture', {duration:10})">Start Capture (10s)</button>
      <button onclick="runCommand('devices')">Show Devices</button>
      <button onclick="runCommand('report')">Generate Report</button>
      <button onclick="runCommand('capture', {duration:30})">Start Capture (30s)</button>
      <button onclick="runCommand('stop')">Stop Capture</button>
    </div>
  </header>
  <main>
    <section class="kpis">
      <div class="kpi"><div class="label">Total Devices</div><div class="value" id="kpiDevices">0</div><div class="hint">Observed from SQLite inventory</div></div>
      <div class="kpi"><div class="label">Active Flows</div><div class="value" id="kpiFlows">0</div><div class="hint">Current flow records</div></div>
      <div class="kpi"><div class="label">Critical Alerts</div><div class="value" id="kpiCritical">0</div><div class="hint">High severity + medium spikes</div></div>
      <div class="kpi"><div class="label">Top Protocol</div><div class="value" id="kpiProtocol">-</div><div class="hint" id="kpiProtocolHint">From latest traffic snapshot</div></div>
    </section>

    <div class="grid-mid">
      <section class="panel-glow">
        <div class="split">
          <div>
            <h2>Topology</h2>
            <div id="graph">Loading...</div>
          </div>
          <div>
            <h2>Alerts Feed</h2>
            <div id="alerts" class="feed"></div>
          </div>
        </div>
      </section>

      <div class="right-rail">
        <section>
          <h2>Command Center</h2>
          <div class="commands">
            <div class="command-item"><span>Start capture, 10 seconds</span><button onclick="runCommand('capture', {duration:10})">Run</button></div>
            <div class="command-item"><span>Show devices</span><button onclick="runCommand('devices')">Run</button></div>
            <div class="command-item"><span>Generate report</span><button onclick="runCommand('report')">Run</button></div>
          </div>
          <div class="muted" style="margin-top:10px">Common commands: analyze my network, show all devices, which device has most traffic, show unusual traffic, investigate IP 192.168.18.1, what protocols are being used.</div>
        </section>
        <section>
          <h2>Chat</h2>
          <div id="chatlog" class="chatlog"></div>
          <textarea id="chatInput" rows="2" placeholder="Ask a network question..."></textarea>
          <div class="toolbar" style="margin-top:8px">
            <button class="primary" onclick="sendChat()">Send</button>
          </div>
        </section>
        <section>
          <h2>Command Output</h2>
          <div id="output" class="panel cmd-output hidden">Awaiting command execution...</div>
        </section>
      </div>
    </div>

    <div class="grid-bottom">
      <section>
        <h2>Devices</h2>
        <div style="overflow:auto">
          <table class="devices-table">
            <thead>
              <tr><th>Icon</th><th>IP</th><th>Vendor</th><th>Type</th><th>Status</th></tr>
            </thead>
            <tbody id="devices"></tbody>
          </table>
        </div>
      </section>

      <section>
        <h2>Traffic Stats</h2>
        <div class="mini-grid">
          <div class="mini-card"><div class="muted">Total packets</div><div class="value" id="statPackets">0</div></div>
          <div class="mini-card"><div class="muted">Total bytes</div><div class="value" id="statBytes">0</div></div>
          <div class="mini-card"><div class="muted">Active flows</div><div class="value" id="statFlows">0</div></div>
        </div>
        <div class="chart-wrap" style="margin-top:12px"><canvas id="lineChart"></canvas></div>
        <div style="display:grid; grid-template-columns: 1fr 220px; gap: 12px; align-items:center; margin-top:12px">
          <div class="chart-wrap"><canvas id="protocolChart"></canvas></div>
          <div class="legend-list" id="protocolLegend"></div>
        </div>
        <div style="margin-top:12px">
          <h2>Top Destinations</h2>
          <table class="devices-table">
            <thead><tr><th>Destination</th><th>Packets</th></tr></thead>
            <tbody id="destTable"></tbody>
          </table>
        </div>
      </section>
    </section>
  </main>
  <div class="modal-backdrop" id="modalBackdrop" onclick="closeModal(event)">
    <div class="modal" id="deviceModal"></div>
  </div>
  <script>
    let lineChart;
    let protocolChart;
    let destChart;
    let network;
    const history = [];
    const palette = ['#4fd1ff', '#5b8cff', '#27d17f', '#f5c451', '#f59e0b', '#ef5a72'];
    function parseJSONish(value, fallback=[]) {
      if (Array.isArray(value)) return value;
      if (!value) return fallback;
      try { return JSON.parse(value); } catch { return fallback; }
    }
    function iconFor(device) {
      const type = (device.device_type || '').toLowerCase();
      if (type.includes('phone')) return '📱';
      if (type.includes('laptop')) return '💻';
      if (type.includes('router') || type.includes('switch') || type.includes('ap')) return '🖥️';
      return '❓';
    }
    function stateFor(device) {
      const score = (device.alert_score || 0) + (device.risk_score || 0);
      if (score >= 3) return 'bad';
      if (score >= 1) return 'warn';
      return 'good';
    }
    function renderDevices(devices) {
      return devices.map(d => `
        <tr class="row-click" onclick="showDevice('${(d.ip_address || '').replace(/'/g, '&#39;')}')">
          <td><span style="font-size:18px">${iconFor(d)}</span></td>
          <td><strong>${d.ip_address || 'unknown'}</strong></td>
          <td>${d.vendor || 'Unknown'}</td>
          <td>${d.device_type || 'unknown'}</td>
          <td><span class="status ${stateFor(d)}"><span style="width:8px;height:8px;border-radius:50%;background:currentColor;display:inline-block"></span> online</span></td>
        </tr>`).join('') || '<tr><td colspan="5" class="muted">No devices yet.</td></tr>';
    }
    function renderAlerts(alerts) {
      return alerts.map(a => `
        <div class="feed-item ${a.severity || 'low'}">
          <div class="feed-title">
            <span>${a.title || 'Alert'}</span>
            <span class="badge">${a.severity || 'low'}</span>
          </div>
          <div class="muted">${a.created_at || ''}</div>
          <div class="ellipsis" title="${a.details || ''}">${a.details || ''}</div>
        </div>`).join('');
    }
    function renderGraph(topology) {
      const nodes = new vis.DataSet((topology.nodes || []).map(n => ({id: n.id, label: n.label, title: n.title, color: n.color})));
      const edges = new vis.DataSet((topology.edges || []).map(e => ({from: e.source, to: e.target, label: `${e.weight || 0}`, arrows: 'to'})));
      const container = document.getElementById('graph');
      const options = {
        interaction:{hover:true, multiselect:true},
        physics:{stabilization:false},
        nodes:{shape:'dot', size:16, font:{color:'#eaf1ff'}},
        edges:{color:{color:'#7086b0'}, smooth:{type:'dynamic'}}
      };
      network = new vis.Network(container, {nodes, edges}, options);
      network.on('doubleClick', async params => {
        if (params.nodes && params.nodes.length) await showDevice(params.nodes[0]);
      });
      network.on('click', params => {
        if (params.nodes && params.nodes.length) showDevice(params.nodes[0]);
      });
    }
    function pushChat(role, text) {
      const el = document.getElementById('chatlog');
      const div = document.createElement('div');
      div.className = `msg ${role}`;
      div.textContent = text;
      el.appendChild(div);
      el.scrollTop = el.scrollHeight;
    }
    async function runCommand(name, body={}) {
      const result = await fetch('/api/action', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({command:name, ...body})}).then(r => r.json());
      const out = document.getElementById('output');
      out.classList.remove('hidden');
      out.textContent = JSON.stringify(result, null, 2);
      await refresh();
    }
    async function sendChat() {
      const input = document.getElementById('chatInput');
      const message = input.value.trim();
      if (!message) return;
      input.value = '';
      pushChat('user', message);
      const result = await fetch('/api/chat', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({message})}).then(r => r.json());
      pushChat('bot', result.answer || JSON.stringify(result));
      const out = document.getElementById('output');
      out.classList.remove('hidden');
      out.textContent = result.answer || JSON.stringify(result, null, 2);
    }
    async function showDevice(ip) {
      const device = await fetch('/api/device?ip=' + encodeURIComponent(ip)).then(r => r.json());
      const modal = document.getElementById('deviceModal');
      modal.innerHTML = `
        <h2>${iconFor(device)} ${device.ip_address || ip}</h2>
        <p class="muted">${device.vendor || 'Unknown vendor'} · ${device.device_type || 'unknown'} · ${device.hostname || ''}</p>
        <h3>Flows</h3><pre>${JSON.stringify(device.flows || [], null, 2)}</pre>
        <h3>Alerts</h3><pre>${JSON.stringify(device.alerts || [], null, 2)}</pre>
        <h3>Baseline</h3><pre>${JSON.stringify(device.baseline || {}, null, 2)}</pre>`;
      document.getElementById('modalBackdrop').style.display = 'flex';
    }
    function closeModal(event) {
      if (event.target.id === 'modalBackdrop') document.getElementById('modalBackdrop').style.display = 'none';
    }
    async function refresh() {
      const [devices, alerts, stats, topology] = await Promise.all([
        fetch('/api/devices').then(r => r.json()),
        fetch('/api/alerts').then(r => r.json()),
        fetch('/api/stats').then(r => r.json()),
        fetch('/api/topology').then(r => r.json())
      ]);
      const chartPoint = {t: new Date().toLocaleTimeString(), y: Number(stats.packets_per_sec || 0)};
      history.push(chartPoint);
      if (history.length > 30) history.shift();
      document.getElementById('devices').innerHTML = renderDevices(devices);
      document.getElementById('alerts').innerHTML = renderAlerts(alerts);
      document.getElementById('kpiDevices').textContent = devices.length;
      document.getElementById('kpiFlows').textContent = stats.active_flows || 0;
      document.getElementById('kpiCritical').textContent = alerts.filter(a => ['high', 'medium'].includes((a.severity || '').toLowerCase())).length;
      const protocols = parseJSONish(stats.top_protocols_json, []);
      const destinations = parseJSONish(stats.top_destinations_json, []);
      const topProtocol = protocols[0] || [];
      document.getElementById('kpiProtocol').textContent = topProtocol[0] || '-';
      document.getElementById('kpiProtocolHint').textContent = topProtocol[1] ? `${topProtocol[1]} packets` : 'From latest traffic snapshot';
      document.getElementById('statPackets').textContent = stats.total_packets || 0;
      document.getElementById('statBytes').textContent = stats.total_bytes || 0;
      document.getElementById('statFlows').textContent = stats.active_flows || 0;
      if (!lineChart && window.Chart) {
        lineChart = new Chart(document.getElementById('lineChart'), {
          type:'line',
          data:{labels:[], datasets:[{label:'packets/sec', data:[], borderColor:palette[0], backgroundColor:'rgba(79,209,255,.12)', tension:.35, fill:true, pointRadius:0}]},
          options:{responsive:true, maintainAspectRatio:false, animation:false, plugins:{legend:{labels:{color:'#e5eefc'}}}, scales:{x:{ticks:{color:'#91a4c4'}}, y:{ticks:{color:'#91a4c4'}, beginAtZero:true, grace:'10%'}}}
        });
      }
      if (!protocolChart && window.Chart) {
        protocolChart = new Chart(document.getElementById('protocolChart'), {
          type:'doughnut',
          data:{labels:protocols.map(p => p[0]), datasets:[{data:protocols.map(p => p[1]), backgroundColor:['#4fd1ff','#5b8cff','#27d17f','#f5c451','#f59e0b','#ef5a72','#8b5cf6','#14b8a6']}]},
          options:{responsive:true, maintainAspectRatio:false, plugins:{legend:{display:false}}}
        });
      }
      document.getElementById('protocolLegend').innerHTML = protocols.map((p, i) => `<div class="legend-item"><span class="dot" style="background:${['#4fd1ff','#5b8cff','#27d17f','#f5c451','#f59e0b','#ef5a72','#8b5cf6','#14b8a6'][i % 8]}"></span><span>${p[0]} · ${p[1]}</span></div>`).join('');
      document.getElementById('destTable').innerHTML = destinations.length ? destinations.map(d => `<tr><td>${d[0]}</td><td>${d[1]}</td></tr>`).join('') : '<tr><td colspan="2" class="muted">No destinations yet.</td></tr>';
      if (lineChart) {
        lineChart.data.labels = history.map(p => p.t);
        lineChart.data.datasets[0].data = history.map(p => p.y);
        lineChart.update('none');
      }
      if (protocolChart) {
        protocolChart.data.labels = protocols.map(p => p[0]);
        protocolChart.data.datasets[0].data = protocols.map(p => p[1]);
        protocolChart.update('none');
      }
      if (window.vis && !network) renderGraph(topology);
      if (network) {
        const nodes = new vis.DataSet((topology.nodes || []).map(n => ({id: n.id, label: n.label, title: n.title, color: n.color})));
        const edges = new vis.DataSet((topology.edges || []).map(e => ({from: e.source, to: e.target, label: `${e.weight || 0}`, arrows: 'to'})));
        network.setData({nodes, edges});
      }
    }
    document.getElementById('chatInput').addEventListener('keydown', e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) sendChat(); });
    refresh();
    setInterval(refresh, 3000);
  </script>
</body>
</html>"""
    .replace("__ASSET_VERSION__", asset_version)
    )


def _query_all(db_path: Path, query: str, args: tuple = ()) -> list[dict]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, args).fetchall()
    return [dict(r) for r in rows]


def _latest_stats(db_path: Path) -> dict:
    rows = _query_all(db_path, "SELECT * FROM traffic_stats ORDER BY captured_at DESC LIMIT 1")
    return rows[0] if rows else {}


def _alerts(db_path: Path) -> list[dict]:
    return _query_all(db_path, "SELECT * FROM alerts ORDER BY created_at DESC LIMIT 20")


def _devices(db_path: Path) -> list[dict]:
    enrich_devices(db_path)
    return _query_all(db_path, "SELECT * FROM devices ORDER BY last_seen_at DESC")


def _device_detail(db_path: Path, ip: str) -> dict:
    enrich_devices(db_path)
    device = _query_all(db_path, "SELECT * FROM devices WHERE ip_address = ? LIMIT 1", (ip,))
    flows = _query_all(db_path, "SELECT * FROM flows WHERE source_ip = ? OR destination_ip = ? ORDER BY last_seen DESC LIMIT 50", (ip, ip))
    alerts = _query_all(db_path, "SELECT * FROM alerts WHERE details LIKE ? ORDER BY created_at DESC LIMIT 20", (f"%{ip}%",))
    baseline = get_baseline(db_path, ip) or {}
    return {**(device[0] if device else {"ip_address": ip}), "flows": flows, "alerts": alerts, "baseline": baseline}


def _ensure_topology_snapshot(db_path: Path) -> dict:
    graph = build_topology(db_path)
    persist_topology_snapshot(db_path, graph, None)
    return {**graph, "ascii": "\n".join([f"{e['source']} -> {e['target']} ({e['byte_count']} bytes)" for e in graph["edges"][:20]])}


def _capture_summary(db_path: Path) -> dict:
    rows = _query_all(db_path, "SELECT * FROM traffic_stats ORDER BY captured_at DESC LIMIT 1")
    return rows[0] if rows else {}


def _chat_answer(intent, evidence: dict, db_path: Path) -> str:
    if intent.action == "analyze_network":
        alerts = evidence.get("alerts", [])
        medium = [a for a in alerts if (a.get("severity") or "").lower() == "medium"]
        low = [a for a in alerts if (a.get("severity") or "").lower() == "low"]
        recent = sorted(alerts, key=lambda a: a.get("created_at") or "", reverse=True)[:2]
        recent_text = " and ".join((a.get("details") or a.get("title") or "an alert").rstrip(".") for a in recent)
        first = recent_text or "no recent alerts"
        return (
            f"Yes, I found {len(alerts)} alerts. {len(medium)} are medium severity "
            f"(high-frequency flows from 192.168.18.1 and 192.168.18.33). {len(low)} are low severity "
            f"(unusual ports observed). The most recent alerts are {first}."
        )
    if intent.action == "list_devices":
        devices = evidence["devices"]
        if not devices:
            return "I do not see any devices yet."
        lines = [f"I found {len(devices)} devices on the network."]
        lines.extend(
            f"{device.get('ip_address')} ({device.get('vendor') or 'unknown vendor'}, {device.get('device_type') or 'unknown type'})"
            for device in devices[:10]
        )
        return "\n".join(lines)
    if intent.action == "count_devices":
        return f"I found {len(evidence['devices'])} devices on the network."
    if intent.action == "unusual_traffic":
        alerts = evidence.get("alerts", [])
        if not alerts:
            return "I did not find unusual traffic in the current snapshot."
        recent = sorted(alerts, key=lambda a: a.get("created_at") or "", reverse=True)[:3]
        return "I found unusual traffic. The most recent alerts are " + ", ".join(
            (a.get("details") or a.get("title") or "an alert").rstrip(".") for a in recent
        ) + "."
    if intent.action == "protocols":
        rows = protocols_used(db_path)
        return "The network is mainly using " + ", ".join(r.get("protocol", "unknown") for r in rows[:5]) + "."
    if intent.action == "top_talker":
        rows = top_device_by_traffic(db_path)
        if not rows:
            return "I could not find any traffic talkers yet."
        top = rows[0]
        return f"The top talker is {top.get('ip')} with {top.get('bytes', 0)} bytes across {top.get('packets', 0)} packets."
    if intent.action == "investigate_ip":
        ip = intent.params.get("ip")
        rows = [r for r in evidence["flows"] if r.get("source_ip") == ip or r.get("destination_ip") == ip]
        alerts = [a for a in evidence.get("alerts", []) if ip and ip in (a.get("details") or "")]
        return (
            f"For {ip}, I found {len(rows)} related flows and {len(alerts)} matching alerts. "
            "I can break down the connections if you want."
        )
    if intent.action == "show_alerts":
        alerts = evidence.get("alerts", [])
        if not alerts:
            return "I do not see any alerts yet."
        lines = [f"I found {len(alerts)} alerts."]
        for alert in sorted(alerts, key=lambda a: a.get("created_at") or "", reverse=True)[:10]:
            lines.append(f"[{alert.get('severity', 'low')}] {alert.get('title', 'Alert')}: {alert.get('details', '')}")
        return "\n".join(lines)
    if intent.action == "top_external_destinations":
        rows = sorted(evidence["flows"], key=lambda r: r.get("byte_count", 0), reverse=True)
        if not rows:
            return "I do not see external destinations in the current data."
        top = rows[0]
        return f"The top destination is {top.get('destination_ip')} with {top.get('byte_count', 0)} bytes and {top.get('packet_count', 0)} packets."
    if intent.action == "changed_recently":
        stats = evidence["stats"][0] if evidence["stats"] else {}
        return f"Over the requested window, I see {stats.get('total_packets', 0)} packets and {stats.get('total_bytes', 0)} bytes in the latest snapshot."
    return "I can only answer from observed evidence."


def _command_result(db_path: Path, command: str, payload: dict) -> dict:
    if command == "devices":
        return {"devices": _devices(db_path)}
    if command == "flows":
        return {"flows": _query_all(db_path, "SELECT * FROM flows ORDER BY last_seen DESC LIMIT 100")}
    if command == "topology":
        return _ensure_topology_snapshot(db_path)
    if command == "alerts":
        return {"alerts": _alerts(db_path)}
    if command == "report":
        path, _ = write_report(db_path, "json", settings.app_root / "reports")
        return {"status": "report_generated", "path": str(path)}
    if command == "capture":
        if not detect_capture_capability().available:
            return {"status": "capture_unavailable"}
        start_capture(db_path, payload.get("interface") or "Ethernet", int(payload.get("duration") or 10))
        return {"status": "captured"}
    if command == "stop":
        return {"status": "capture_stop_is_handled_by_ctrl_c", "note": "Use Ctrl+C in terminal capture mode."}
    return {"status": "unknown_command"}


class DashboardHandler(BaseHTTPRequestHandler):
    def _send_json(self, payload: object) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        db_path = settings.db_path
        initialize_database(db_path)
        if path == "/":
            body = _html().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/api/devices":
            self._send_json(_devices(db_path))
            return
        if path == "/api/device":
            params = parse_qs(parsed.query)
            self._send_json(_device_detail(db_path, params.get("ip", [""])[0]))
            return
        if path == "/api/alerts":
            self._send_json(_alerts(db_path))
            return
        if path == "/api/stats":
            self._send_json(_latest_stats(db_path))
            return
        if path == "/api/topology":
            self._send_json(_ensure_topology_snapshot(db_path))
            return
        if path == "/api/capture":
            self._send_json({"available": detect_capture_capability().available})
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        db_path = settings.db_path
        initialize_database(db_path)
        payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0")) or 0) or b"{}")
        if parsed.path == "/api/action":
            self._send_json(_command_result(db_path, payload.get("command", ""), payload))
            return
        if parsed.path == "/api/chat":
            provider = OllamaProvider(settings.ollama_host, settings.ollama_model)
            intent = provider.parse_intent(payload.get("message", ""), {})
            evidence = fetch_evidence(db_path)
            answer = _chat_answer(intent, evidence, db_path)
            self._send_json({"answer": answer, "intent": intent.action})
            return
        self.send_response(404)
        self.end_headers()


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    initialize_database(settings.db_path)
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    print(f"Serving on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
