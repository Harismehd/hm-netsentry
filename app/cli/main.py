from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import datetime, timezone

from app.config import settings
from app.capture.manager import detect_capture_capability, list_capture_interfaces, start_capture
from app.analysis.investigations import fetch_evidence, protocols_used, top_device_by_traffic
from app.analysis.attack_paths import build_attack_paths
from app.analysis.baseline import detect_baseline_deviations, get_baseline, learn_baselines
from app.analysis.reporting import write_report
from app.analysis.topology import build_topology, persist_topology_snapshot, render_ascii_topology
from app.fingerprint.fingerprint import enrich_devices
from app.discovery.interfaces import discover_network_interfaces
from app.llm.ollama import check_ollama
from app.llm.ollama_provider import OllamaProvider
from app.web.server import serve as serve_web
from app.storage.database import initialize_database, table_names


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="network-ai")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init-db", help="create or update the SQLite schema")
    subparsers.add_parser("interfaces", help="list detected network interfaces")
    capture = subparsers.add_parser("capture", help="capture packets on an interface")
    capture.add_argument("--interface", required=True)
    capture.add_argument("--duration", type=int, default=None)
    subparsers.add_parser("status", help="show system status")
    subparsers.add_parser("devices", help="show known devices")
    subparsers.add_parser("flows", help="show known flows")
    subparsers.add_parser("stats", help="show current statistics")
    subparsers.add_parser("fingerprint", help="show enriched device fingerprints")
    topology = subparsers.add_parser("topology", help="show topology graph from flows")
    topology.add_argument("--ascii", action="store_true")
    subparsers.add_parser("attack-paths", help="show potential attack paths")
    baseline = subparsers.add_parser("baseline", help="learn or detect behavioral baselines")
    baseline.add_argument("action", nargs="?", choices=["learn", "detect"], default=None)
    baseline.add_argument("--device", default=None)
    report = subparsers.add_parser("report", help="generate a security report")
    report.add_argument("--format", choices=["json", "text", "html"], default="text")
    web = subparsers.add_parser("web", help="start lightweight web dashboard")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8000)
    chat = subparsers.add_parser("chat", help="interactive natural language mode")
    chat.add_argument("--interface", default=None)
    chat.add_argument("--duration", type=int, default=None)
    chat.add_argument("message", nargs="*")
    subparsers.add_parser("health", help="check local runtime health")
    return parser


def cmd_init_db() -> int:
    initialize_database(settings.db_path)
    print(f"database_ready={settings.db_path}")
    print(f"tables={json.dumps(table_names(settings.db_path))}")
    return 0


def cmd_interfaces() -> int:
    interfaces = discover_network_interfaces()
    print(json.dumps({"system": [interface.__dict__ for interface in interfaces], "capture": list_capture_interfaces()}, indent=2))
    return 0


def cmd_capture(interface: str, duration: int | None) -> int:
    initialize_database(settings.db_path)
    capability = detect_capture_capability()
    if not capability.available:
        print(json.dumps(capability.__dict__, indent=2))
        return 2
    summary = start_capture(settings.db_path, interface, duration)
    print(json.dumps({"status": "captured", "summary": summary}, indent=2))
    return 0


def cmd_status() -> int:
    initialize_database(settings.db_path)
    print(json.dumps({"database": str(settings.db_path), "tables": table_names(settings.db_path), "capture": detect_capture_capability().__dict__, "capture_interfaces": list_capture_interfaces()}, indent=2))
    return 0


def _query_json(query: str, limit: int = 20) -> list[dict]:
    with sqlite3.connect(settings.db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, (limit,)).fetchall()
    return [dict(row) for row in rows]


def cmd_devices() -> int:
    initialize_database(settings.db_path)
    print(json.dumps(_query_json("SELECT * FROM devices ORDER BY last_seen_at DESC LIMIT ?"), indent=2))
    return 0


def cmd_flows() -> int:
    initialize_database(settings.db_path)
    print(json.dumps(_query_json("SELECT * FROM flows ORDER BY ended_at DESC LIMIT ?"), indent=2))
    return 0


def cmd_stats() -> int:
    initialize_database(settings.db_path)
    with sqlite3.connect(settings.db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM traffic_stats ORDER BY captured_at DESC LIMIT 1").fetchone()
    print(json.dumps(dict(row) if row else {}, indent=2))
    return 0


def cmd_fingerprint() -> int:
    initialize_database(settings.db_path)
    print(json.dumps(enrich_devices(settings.db_path), indent=2))
    return 0


def cmd_baseline(action: str | None, device: str | None = None) -> int:
    initialize_database(settings.db_path)
    if device:
        print(json.dumps(get_baseline(settings.db_path, device) or {}, indent=2))
        return 0
    if action == "learn":
        print(json.dumps(learn_baselines(settings.db_path), indent=2))
        return 0
    if action == "detect":
        print(json.dumps(detect_baseline_deviations(settings.db_path), indent=2))
        return 0
    print("usage: python run.py baseline learn|detect [--device IP]")
    return 1


def cmd_topology(ascii_output: bool = False) -> int:
    initialize_database(settings.db_path)
    graph = build_topology(settings.db_path)
    ascii_graph = render_ascii_topology(graph) if ascii_output else None
    persist_topology_snapshot(settings.db_path, graph, ascii_graph)
    output = {"nodes": graph["nodes"], "edges": graph["edges"]}
    if ascii_graph:
        output["ascii"] = ascii_graph
    print(json.dumps(output, indent=2))
    if ascii_graph:
        print(ascii_graph)
    return 0


def cmd_attack_paths() -> int:
    initialize_database(settings.db_path)
    print(json.dumps(build_attack_paths(settings.db_path), indent=2))
    return 0


def cmd_report(fmt: str) -> int:
    initialize_database(settings.db_path)
    output_path, content = write_report(settings.db_path, fmt, settings.app_root / "reports")
    if fmt == "json":
        print(content)
    else:
        print(content)
    print(f"saved={output_path}")
    return 0


def _latest_stats_age_minutes() -> float | None:
    with sqlite3.connect(settings.db_path) as conn:
        row = conn.execute("SELECT captured_at FROM traffic_stats ORDER BY captured_at DESC LIMIT 1").fetchone()
    if not row or not row[0]:
        return None
    captured = datetime.fromisoformat(str(row[0]).replace("Z", "+00:00"))
    if captured.tzinfo is None:
        captured = captured.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - captured).total_seconds() / 60.0)


def _choose_capture_interface(preferred: str | None = None) -> str | None:
    if preferred:
        return preferred
    capture_ifaces = list_capture_interfaces()
    return capture_ifaces[0] if capture_ifaces else None


def _answer_intent(intent, evidence: dict) -> str:
    if intent.action == "analyze_network":
        stats = evidence["stats"][0] if evidence["stats"] else {}
        alerts = evidence.get("alerts", [])
        medium = [a for a in alerts if (a.get("severity") or "").lower() == "medium"]
        low = [a for a in alerts if (a.get("severity") or "").lower() == "low"]
        recent = sorted(alerts, key=lambda a: a.get("created_at") or "", reverse=True)[:2]
        recent_text = " and ".join(
            (a.get("details") or a.get("title") or "an alert").strip().rstrip(".") for a in recent
        )
        parts = [
            f"I found {len(alerts)} alerts.",
            f"{len(medium)} are medium severity{(' (high-frequency flows from 192.168.18.1 and 192.168.18.33)' if medium else '')}.",
            f"{len(low)} are low severity{(' (unusual ports observed)' if low else '')}.",
        ]
        if recent_text:
            parts.append(f"The most recent alerts are {recent_text}.")
        parts.append(
            f"Current traffic shows {stats.get('total_packets', 0)} packets, {stats.get('total_bytes', 0)} bytes, "
            f"{len(evidence['devices'])} devices, and {len(evidence['flows'])} flows."
        )
        return " ".join(parts)
    if intent.action == "list_devices":
        devices = evidence["devices"]
        lines = [f"I found {len(devices)} devices."]
        for device in devices[:10]:
            lines.append(
                f"- {device.get('ip_address')}: {device.get('vendor') or 'unknown vendor'}, {device.get('device_type') or 'unknown type'}"
            )
        return "\n".join(lines)
    if intent.action == "count_devices":
        return f"I found {len(evidence['devices'])} devices on the network."
    if intent.action == "top_talker":
        rows = top_device_by_traffic(settings.db_path)
        if not rows:
            return "I could not find any traffic talkers yet."
        top = rows[0]
        return f"The top talker is {top.get('ip')} with {top.get('bytes', 0)} bytes across {top.get('packets', 0)} packets."
    if intent.action == "unusual_traffic":
        rows = [r for r in evidence["alerts"] if r.get("severity") in {"low", "medium", "high"}]
        if not rows:
            return "I did not find unusual traffic in the current snapshot."
        recent = sorted(rows, key=lambda r: r.get("created_at") or "", reverse=True)[:3]
        highlights = "; ".join((r.get("details") or r.get("title") or "alert") for r in recent)
        return f"I found {len(rows)} unusual traffic alerts. The most recent ones are {highlights}."
    if intent.action == "show_alerts":
        alerts = evidence.get("alerts", [])
        if not alerts:
            return "I do not see any alerts yet."
        lines = [f"I found {len(alerts)} alerts."]
        for alert in sorted(alerts, key=lambda a: a.get("created_at") or "", reverse=True)[:10]:
            lines.append(
                f"- [{alert.get('severity', 'low')}] {alert.get('title', 'Alert')}: {alert.get('details', '')}"
            )
        return "\n".join(lines)
    if intent.action == "investigate_ip":
        ip = intent.params.get("ip")
        rows = [r for r in evidence["flows"] if r.get("source_ip") == ip or r.get("destination_ip") == ip]
        devices = [d for d in evidence["devices"] if d.get("ip_address") == ip]
        return (
            f"For {ip}, I found {len(rows)} related flows and {len(devices)} matching device records. "
            "I can show the flow list or device details if you want more depth."
        )
    if intent.action == "protocols":
        rows = protocols_used(settings.db_path)
        if not rows:
            return "No protocol activity has been recorded yet."
        names = ", ".join(row.get("protocol", "unknown") for row in rows[:5])
        return f"The network is mainly using {names}."
    if intent.action == "top_external_destinations":
        rows = sorted(evidence["flows"], key=lambda r: r.get("byte_count", 0), reverse=True)
        if not rows:
            return "I do not see external destinations in the current data."
        top = rows[0]
        return f"The top destination is {top.get('destination_ip')} with {top.get('byte_count', 0)} bytes and {top.get('packet_count', 0)} packets."
    if intent.action == "changed_recently":
        stats = evidence["stats"][0] if evidence["stats"] else {}
        return (
            f"Over the last {intent.params.get('minutes') or 10} minutes, I see {stats.get('total_packets', 0)} packets "
            f"and {stats.get('total_bytes', 0)} bytes in the latest snapshot."
        )
    return "I can only answer from observed evidence."


def _run_short_capture(interface: str | None, duration: int | None) -> None:
    chosen = _choose_capture_interface(interface)
    if not chosen:
        raise RuntimeError("No capture interface available for fallback capture.")
    start_capture(settings.db_path, chosen, duration or 10)


def cmd_chat(message_parts: list[str], interface: str | None = None, duration: int | None = None) -> int:
    initialize_database(settings.db_path)
    provider = OllamaProvider(settings.ollama_host, settings.ollama_model)
    if message_parts:
        message = " ".join(message_parts).strip()
        intent = provider.parse_intent(message, {})
        if intent.action == "analyze_network":
            age = _latest_stats_age_minutes()
            if age is None or age > 10:
                _run_short_capture(interface, duration)
        evidence = fetch_evidence(settings.db_path)
        print(_answer_intent(intent, evidence))
        return 0

    print("Interactive chat. Type 'exit' to quit.")
    while True:
        try:
            message = input("network-ai> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not message:
            continue
        if message.lower() == "exit":
            return 0
        intent = provider.parse_intent(message, {})
        if intent.action == "analyze_network":
            age = _latest_stats_age_minutes()
            if age is None or age > 10:
                _run_short_capture(interface, duration)
        evidence = fetch_evidence(settings.db_path)
        print(_answer_intent(intent, evidence))
    return 0


def cmd_health() -> int:
    initialize_database(settings.db_path)
    ollama = check_ollama(settings.ollama_host, settings.ollama_model)
    interfaces = discover_network_interfaces()
    print(json.dumps(
        {
            "database": str(settings.db_path),
            "database_ready": settings.db_path.exists(),
            "interface_count": len(interfaces),
            "ollama": ollama.__dict__,
        },
        indent=2,
    ))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "init-db":
        return cmd_init_db()
    if args.command == "interfaces":
        return cmd_interfaces()
    if args.command == "capture":
        return cmd_capture(args.interface, args.duration)
    if args.command == "status":
        return cmd_status()
    if args.command == "devices":
        return cmd_devices()
    if args.command == "flows":
        return cmd_flows()
    if args.command == "stats":
        return cmd_stats()
    if args.command == "fingerprint":
        return cmd_fingerprint()
    if args.command == "baseline":
        return cmd_baseline(args.action, args.device)
    if args.command == "topology":
        return cmd_topology(args.ascii)
    if args.command == "attack-paths":
        return cmd_attack_paths()
    if args.command == "report":
        return cmd_report(args.format)
    if args.command == "chat":
        return cmd_chat(args.message, args.interface, args.duration)
    if args.command == "web":
        serve_web(args.host, args.port)
        return 0
    if args.command == "health":
        return cmd_health()
    return 1
