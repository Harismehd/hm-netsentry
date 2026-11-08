from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from app.analysis.attack_paths import build_attack_paths
from app.analysis.baseline import detect_baseline_deviations
from app.analysis.investigations import protocols_used


def _query_all(db_path: Path, query: str, args: tuple = ()) -> list[dict]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, args).fetchall()
    return [dict(r) for r in rows]


def build_report(db_path: Path) -> dict:
    devices = _query_all(db_path, "SELECT ip_address, mac_address, vendor, device_type, hostname FROM devices ORDER BY last_seen_at DESC")
    flows = _query_all(db_path, "SELECT * FROM flows ORDER BY ended_at DESC")
    stats = _query_all(db_path, "SELECT * FROM traffic_stats ORDER BY captured_at DESC LIMIT 1")
    alerts = _query_all(db_path, "SELECT severity, title, details, created_at FROM alerts ORDER BY created_at DESC")
    attack_paths = build_attack_paths(db_path).get("paths", [])
    baselines = detect_baseline_deviations(db_path)
    top_talkers = _query_all(
        db_path,
        """
        SELECT source_ip AS ip, SUM(byte_count) AS bytes, SUM(packet_count) AS packets
        FROM flows
        GROUP BY source_ip
        ORDER BY bytes DESC
        LIMIT 10
        """,
    )
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "capture_summary": stats[0] if stats else {},
        "device_inventory": devices,
        "top_talkers": top_talkers,
        "protocols": protocols_used(db_path),
        "alerts": alerts,
        "attack_paths": attack_paths,
        "baseline_deviations": baselines,
        "flow_count": len(flows),
        "device_count": len(devices),
    }
    return report


def render_text(report: dict) -> str:
    lines = [
        f"Generated: {report['generated_at']}",
        f"Devices: {report['device_count']}",
        f"Flows: {report['flow_count']}",
        "",
        "Device Inventory",
    ]
    for device in report["device_inventory"]:
        lines.append(
            f"- {device.get('ip_address')} | {device.get('mac_address') or 'n/a'} | {device.get('vendor') or 'unknown'} | {device.get('device_type') or 'unknown'}"
        )
    lines.extend(["", "Top Talkers"])
    for row in report["top_talkers"]:
        lines.append(f"- {row.get('ip')}: {row.get('bytes', 0)} bytes, {row.get('packets', 0)} packets")
    lines.extend(["", "Protocols"])
    for row in report["protocols"]:
        lines.append(f"- {row.get('protocol')}: {row.get('bytes', 0)} bytes, {row.get('packets', 0)} packets")
    lines.extend(["", "Alerts"])
    for alert in report["alerts"]:
        lines.append(f"- {alert.get('severity')}: {alert.get('title')}")
    lines.extend(["", "Attack Paths"])
    for path in report["attack_paths"][:10]:
        lines.append(f"- {' -> '.join(path.get('path', []))} (risk {path.get('risk', 0)})")
    lines.extend(["", "Baseline Deviations"])
    for item in report["baseline_deviations"]:
        lines.append(f"- {item.get('device_ip')}: {item.get('metric')} {item.get('current')} > {item.get('baseline')}")
    return "\n".join(lines)


def render_html(report: dict) -> str:
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Network AI Report</title>
<style>body{{font-family:Arial,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px}} table{{border-collapse:collapse;width:100%}} td,th{{border:1px solid #ccc;padding:6px}} th{{background:#f4f4f4}} pre{{white-space:pre-wrap}}</style>
</head><body>
<h1>Network AI Report</h1>
<p>Generated: {report['generated_at']}</p>
<p>Devices: {report['device_count']} | Flows: {report['flow_count']}</p>
<h2>Device Inventory</h2>
<table><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Type</th></tr>
{''.join(f"<tr><td>{d.get('ip_address') or ''}</td><td>{d.get('mac_address') or ''}</td><td>{d.get('vendor') or ''}</td><td>{d.get('device_type') or ''}</td></tr>" for d in report['device_inventory'])}
</table>
<h2>Top Talkers</h2><pre>{json.dumps(report['top_talkers'], indent=2)}</pre>
<h2>Protocols</h2><pre>{json.dumps(report['protocols'], indent=2)}</pre>
<h2>Alerts</h2><pre>{json.dumps(report['alerts'], indent=2)}</pre>
<h2>Attack Paths</h2><pre>{json.dumps(report['attack_paths'], indent=2)}</pre>
<h2>Baseline Deviations</h2><pre>{json.dumps(report['baseline_deviations'], indent=2)}</pre>
</body></html>"""


def write_report(db_path: Path, fmt: str, output_dir: Path) -> tuple[Path, str]:
    report = build_report(db_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if fmt == "json":
        path = output_dir / f"report-{stamp}.json"
        content = json.dumps(report, indent=2)
    elif fmt == "html":
        path = output_dir / f"report-{stamp}.html"
        content = render_html(report)
    else:
        path = output_dir / f"report-{stamp}.txt"
        content = render_text(report)
    path.write_text(content, encoding="utf-8")
    return path, content
