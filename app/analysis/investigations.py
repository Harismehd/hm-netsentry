from __future__ import annotations

import json
import sqlite3
from pathlib import Path


def fetch_evidence(db_path: Path, limit: int = 20) -> dict:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        devices = [dict(r) for r in conn.execute("SELECT * FROM devices ORDER BY last_seen_at DESC LIMIT ?", (limit,))]
        flows = [dict(r) for r in conn.execute("SELECT * FROM flows ORDER BY ended_at DESC LIMIT ?", (limit,))]
        stats = [dict(r) for r in conn.execute("SELECT * FROM traffic_stats ORDER BY captured_at DESC LIMIT 5")]
        alerts = [dict(r) for r in conn.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,))]
        dns = [dict(r) for r in conn.execute("SELECT * FROM dns_events ORDER BY observed_at DESC LIMIT ?", (limit,))]
    return {"devices": devices, "flows": flows, "stats": stats, "alerts": alerts, "dns_events": dns}


def top_device_by_traffic(db_path: Path) -> list[dict]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT source_ip AS ip, SUM(byte_count) AS bytes, SUM(packet_count) AS packets
            FROM flows
            GROUP BY source_ip
            ORDER BY bytes DESC
            LIMIT 5
            """
        ).fetchall()
    return [dict(r) for r in rows]


def list_devices(db_path: Path) -> list[dict]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM devices ORDER BY last_seen_at DESC").fetchall()
    return [dict(r) for r in rows]


def list_flows(db_path: Path) -> list[dict]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM flows ORDER BY ended_at DESC").fetchall()
    return [dict(r) for r in rows]


def protocols_used(db_path: Path) -> list[dict]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT protocol, SUM(packet_count) AS packets, SUM(byte_count) AS bytes FROM flows GROUP BY protocol ORDER BY bytes DESC").fetchall()
    return [dict(r) for r in rows]

