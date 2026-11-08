from __future__ import annotations

import sqlite3
from pathlib import Path

from app.fingerprint.device_type import infer_device_type
from app.fingerprint.oui import lookup_vendor


def enrich_devices(db_path: Path) -> list[dict]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        devices = [dict(row) for row in conn.execute("SELECT * FROM devices ORDER BY last_seen_at DESC").fetchall()]
        for device in devices:
            ip = device.get("ip_address")
            mac = device.get("mac_address")
            vendor = lookup_vendor(mac)
            protocol_rows = conn.execute(
                "SELECT protocol, destination_port, source_port FROM flows WHERE source_ip = ? OR destination_ip = ?",
                (ip, ip),
            ).fetchall()
            dns_rows = conn.execute(
                "SELECT queried_name, response_name FROM dns_events WHERE source_ip = ? OR destination_ip = ?",
                (ip, ip),
            ).fetchall()
            protocols = [r[0] for r in protocol_rows if r[0]]
            ports = [r[1] for r in protocol_rows if r[1] is not None] + [r[2] for r in protocol_rows if r[2] is not None]
            hostnames = []
            for row in dns_rows:
                hostnames.extend([v for v in row if v])
            device_type = infer_device_type(vendor=vendor, protocols=protocols, ports=ports, hostnames=hostnames)
            conn.execute(
                "UPDATE devices SET vendor = COALESCE(?, vendor), device_type = COALESCE(?, device_type) WHERE ip_address = ?",
                (vendor, device_type, ip),
            )
            device["vendor"] = vendor or device.get("vendor")
            device["device_type"] = device_type
        conn.commit()
    return devices
