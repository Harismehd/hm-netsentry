from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from app.storage.database import insert_topology_graph


def build_topology(db_path: Path) -> dict:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        devices = {row["ip_address"]: dict(row) for row in conn.execute("SELECT * FROM devices").fetchall() if row["ip_address"]}
        flows = [dict(row) for row in conn.execute("SELECT * FROM flows").fetchall()]

    nodes = []
    seen = set()
    for ip, device in devices.items():
        nodes.append(
            {
                "id": ip,
                "label": device.get("hostname") or ip,
                "vendor": device.get("vendor"),
                "device_type": device.get("device_type"),
            }
        )
        seen.add(ip)

    edges_map: dict[tuple[str, str], dict] = {}
    for flow in flows:
        src = flow.get("source_ip")
        dst = flow.get("destination_ip")
        if not src or not dst:
            continue
        if src not in seen:
            nodes.append({"id": src, "label": src, "vendor": None, "device_type": None})
            seen.add(src)
        if dst not in seen:
            nodes.append({"id": dst, "label": dst, "vendor": None, "device_type": None})
            seen.add(dst)
        key = (src, dst)
        edge = edges_map.setdefault(
            key,
            {"source": src, "target": dst, "packet_count": 0, "byte_count": 0, "protocols": set()},
        )
        edge["packet_count"] += flow.get("packet_count", 0) or 0
        edge["byte_count"] += flow.get("byte_count", 0) or 0
        if flow.get("protocol"):
            edge["protocols"].add(flow["protocol"])

    edges = [
        {
            "source": e["source"],
            "target": e["target"],
            "packet_count": e["packet_count"],
            "byte_count": e["byte_count"],
            "weight": e["byte_count"],
            "protocols": sorted(e["protocols"]),
        }
        for e in edges_map.values()
    ]
    edges.sort(key=lambda e: (e["byte_count"], e["packet_count"]), reverse=True)
    nodes.sort(key=lambda n: n["id"])
    return {"nodes": nodes, "edges": edges}


def render_ascii_topology(graph: dict, max_edges: int = 20) -> str:
    lines = ["Topology"]
    for edge in graph["edges"][:max_edges]:
        proto = ",".join(edge.get("protocols", []))
        lines.append(f"{edge['source']} -> {edge['target']}  packets={edge['packet_count']} bytes={edge['byte_count']} {proto}")
    if not graph["edges"]:
        lines.append("(no flows yet)")
    return "\n".join(lines)


def persist_topology_snapshot(db_path: Path, graph: dict, ascii_graph: str | None = None) -> None:
    insert_topology_graph(
        db_path,
        "topology_snapshot",
        json.dumps(graph["nodes"]),
        json.dumps(graph["edges"]),
        ascii_graph,
    )
