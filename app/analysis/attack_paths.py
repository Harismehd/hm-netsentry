from __future__ import annotations

import json
import sqlite3
from ipaddress import ip_address
from pathlib import Path

from app.storage.database import insert_attack_paths


SERVICE_RISK = {
    22: 5,
    23: 5,
    25: 3,
    53: 2,
    80: 3,
    110: 3,
    139: 4,
    143: 3,
    443: 4,
    445: 5,
    3389: 5,
    5900: 4,
}


def _is_public_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        addr = ip_address(value)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)
    except ValueError:
        return False


def _service_risk(ports: list[int]) -> int:
    return max((SERVICE_RISK.get(port, 1) for port in ports), default=1)


def build_attack_paths(db_path: Path) -> dict:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        devices = [dict(r) for r in conn.execute("SELECT * FROM devices").fetchall()]
        flows = [dict(r) for r in conn.execute("SELECT * FROM flows").fetchall()]

    node_map = {d.get("ip_address"): d for d in devices if d.get("ip_address")}
    exposure: dict[str, set[str]] = {ip: set() for ip in node_map}
    services: dict[str, set[int]] = {ip: set() for ip in node_map}
    graph: dict[str, set[str]] = {ip: set() for ip in node_map}

    for flow in flows:
        src = flow.get("source_ip")
        dst = flow.get("destination_ip")
        if not src or not dst:
            continue
        node_map.setdefault(src, {"ip_address": src})
        node_map.setdefault(dst, {"ip_address": dst})
        graph.setdefault(src, set()).add(dst)
        graph.setdefault(dst, set())
        for ip, other in ((src, dst), (dst, src)):
            if _is_public_ip(other):
                exposure.setdefault(ip, set()).add(other)
        for ip, port in ((src, flow.get("source_port")), (dst, flow.get("destination_port"))):
            if port is not None:
                services.setdefault(ip, set()).add(int(port))

    paths = []
    external_nodes = [ip for ip in node_map if _is_public_ip(ip) or exposure.get(ip)]
    internal_targets = [ip for ip in node_map if not _is_public_ip(ip)]

    for ext in external_nodes:
        for hop1 in graph.get(ext, set()):
            if hop1 == ext:
                continue
            for hop2 in graph.get(hop1, set()):
                if hop2 in {ext, hop1}:
                    continue
                if hop2 in internal_targets:
                    path = [ext, hop1, hop2]
                    risk = len(exposure.get(hop1, set())) * 2 + _service_risk(sorted(list(services.get(hop1, set())))) + _service_risk(sorted(list(services.get(hop2, set()))))
                    paths.append(
                        {
                            "path": path,
                            "risk": risk,
                            "exposure": sorted(exposure.get(hop1, set())),
                            "open_services": {
                                hop1: sorted(services.get(hop1, set())),
                                hop2: sorted(services.get(hop2, set())),
                            },
                            "criticality": {
                                hop1: _service_risk(sorted(list(services.get(hop1, set())))),
                                hop2: _service_risk(sorted(list(services.get(hop2, set())))),
                            },
                        }
                    )

    paths.sort(key=lambda item: item["risk"], reverse=True)
    result = {
        "nodes": [
            {
                "id": ip,
                "vendor": node_map.get(ip, {}).get("vendor"),
                "device_type": node_map.get(ip, {}).get("device_type"),
                "exposure": sorted(exposure.get(ip, set())),
                "open_services": sorted(services.get(ip, set())),
            }
            for ip in sorted(node_map)
        ],
        "paths": paths,
    }
    insert_attack_paths(db_path, "attack_paths_snapshot", json.dumps(paths))
    return result
