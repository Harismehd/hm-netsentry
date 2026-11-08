from __future__ import annotations

import json
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path

from app.storage.database import insert_alert, upsert_baseline_profile


def _is_external(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)
    except ValueError:
        return False


def _parse_ts(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def learn_baselines(db_path: Path) -> list[dict]:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=30)
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = [dict(r) for r in conn.execute("SELECT * FROM flows WHERE ended_at >= ?", (cutoff.isoformat(),)).fetchall()]
        devices = [dict(r) for r in conn.execute("SELECT ip_address, vendor, device_type FROM devices").fetchall()]
    device_meta = {d["ip_address"]: d for d in devices if d.get("ip_address")}
    by_device = defaultdict(list)
    for row in rows:
        if row.get("source_ip"):
            by_device[row["source_ip"]].append(row)
        if row.get("destination_ip"):
            by_device[row["destination_ip"]].append(row)

    learned = []
    for device_ip, flows in by_device.items():
        per_day_packets: Counter[str] = Counter()
        per_day_bytes: Counter[str] = Counter()
        per_day_conns: Counter[str] = Counter()
        destinations_per_day: defaultdict[str, set] = defaultdict(set)
        protocol_counts: Counter[str] = Counter()
        for flow in flows:
            day = _parse_ts(flow.get("ended_at")).date().isoformat()
            per_day_packets[day] += flow.get("packet_count", 0) or 0
            per_day_bytes[day] += flow.get("byte_count", 0) or 0
            per_day_conns[day] += 1
            other = flow.get("destination_ip") if flow.get("source_ip") == device_ip else flow.get("source_ip")
            if _is_external(other):
                destinations_per_day[day].add(other)
            if flow.get("protocol"):
                protocol_counts[flow["protocol"]] += flow.get("packet_count", 0) or 0
        days = max(1, len(per_day_packets))
        profile = {
            "device_ip": device_ip,
            "vendor": device_meta.get(device_ip, {}).get("vendor"),
            "device_type": device_meta.get(device_ip, {}).get("device_type"),
            "average_packets_per_hour": sum(per_day_packets.values()) / days,
            "average_bytes_per_hour": sum(per_day_bytes.values()) / days,
            "average_connections_per_hour": sum(per_day_conns.values()) / days,
            "unique_external_destinations_per_day": (sum(len(v) for v in destinations_per_day.values()) / days) if days else 0,
            "protocol_distribution": dict(protocol_counts),
        }
        upsert_baseline_profile(db_path, device_ip, json.dumps(profile))
        learned.append(profile)
    return learned


def get_baseline(db_path: Path, device_ip: str) -> dict | None:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM baseline_profiles WHERE device_ip = ?", (device_ip,)).fetchone()
    if not row:
        return None
    profile = json.loads(row["profile_json"])
    profile["learned_from"] = row["learned_from"]
    profile["updated_at"] = row["updated_at"]
    return profile


def detect_baseline_deviations(db_path: Path) -> list[dict]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current_flows = [dict(r) for r in conn.execute("SELECT * FROM flows").fetchall()]
        baselines = [dict(r) for r in conn.execute("SELECT * FROM baseline_profiles").fetchall()]
    current_by_device = defaultdict(lambda: {"packets": 0, "bytes": 0, "connections": 0, "destinations": set(), "protocols": Counter()})
    for flow in current_flows:
        for device_ip in (flow.get("source_ip"), flow.get("destination_ip")):
            if not device_ip:
                continue
            bucket = current_by_device[device_ip]
            bucket["packets"] += flow.get("packet_count", 0) or 0
            bucket["bytes"] += flow.get("byte_count", 0) or 0
            bucket["connections"] += 1
            other = flow.get("destination_ip") if flow.get("source_ip") == device_ip else flow.get("source_ip")
            if _is_external(other):
                bucket["destinations"].add(other)
            if flow.get("protocol"):
                bucket["protocols"][flow["protocol"]] += flow.get("packet_count", 0) or 0

    alerts = []
    for baseline_row in baselines:
        profile = json.loads(baseline_row["profile_json"])
        device_ip = baseline_row["device_ip"]
        current = current_by_device.get(device_ip)
        if not current:
            continue
        checks = (
            ("packets", current["packets"], profile.get("average_packets_per_hour", 0)),
            ("bytes", current["bytes"], profile.get("average_bytes_per_hour", 0)),
            ("connections", current["connections"], profile.get("average_connections_per_hour", 0)),
            ("external_destinations", len(current["destinations"]), profile.get("unique_external_destinations_per_day", 0)),
        )
        for name, value, baseline_value in checks:
            if baseline_value > 0 and value > 2 * baseline_value:
                alert = {
                    "device_ip": device_ip,
                    "metric": name,
                    "current": value,
                    "baseline": baseline_value,
                    "severity": "medium",
                }
                alerts.append(alert)
                insert_alert(db_path, "medium", f"Baseline deviation: {name}", json.dumps(alert))
    return alerts
