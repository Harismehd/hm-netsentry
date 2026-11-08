from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


SCHEMA_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS network_interfaces (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        mac_address TEXT,
        ipv4_address TEXT,
        ipv6_address TEXT,
        is_up INTEGER NOT NULL DEFAULT 0,
        discovered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT,
        mac_address TEXT,
        hostname TEXT,
        vendor TEXT,
        device_type TEXT,
        first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(ip_address)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS traffic_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        interface_name TEXT NOT NULL,
        captured_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        total_packets INTEGER NOT NULL DEFAULT 0,
        total_bytes INTEGER NOT NULL DEFAULT 0,
        packets_per_sec REAL NOT NULL DEFAULT 0,
        bytes_per_sec REAL NOT NULL DEFAULT 0,
        active_flows INTEGER NOT NULL DEFAULT 0,
        active_devices INTEGER NOT NULL DEFAULT 0,
        top_talkers_json TEXT NOT NULL DEFAULT '[]',
        top_destinations_json TEXT NOT NULL DEFAULT '[]',
        top_protocols_json TEXT NOT NULL DEFAULT '[]',
        top_ports_json TEXT NOT NULL DEFAULT '[]'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS capture_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        interface_name TEXT NOT NULL,
        started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        ended_at TEXT,
        status TEXT NOT NULL,
        summary_json TEXT NOT NULL DEFAULT '{}'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS flows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_ip TEXT,
        source_port INTEGER,
        destination_ip TEXT,
        destination_port INTEGER,
        protocol TEXT,
        interface_name TEXT,
        packet_count INTEGER NOT NULL DEFAULT 0,
        byte_count INTEGER NOT NULL DEFAULT 0,
        started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        ended_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        tcp_flags TEXT,
        direction TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS dns_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        queried_name TEXT,
        response_name TEXT,
        response_ip TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        observed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT,
        port INTEGER,
        protocol TEXT,
        service_name TEXT,
        discovered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        details TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS network_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        label TEXT NOT NULL,
        summary_json TEXT NOT NULL,
        captured_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS topology_graphs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        label TEXT NOT NULL,
        nodes_json TEXT NOT NULL,
        edges_json TEXT NOT NULL,
        ascii_graph TEXT,
        captured_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS baseline_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_ip TEXT NOT NULL UNIQUE,
        profile_json TEXT NOT NULL,
        learned_from TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS attack_paths (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        label TEXT NOT NULL,
        paths_json TEXT NOT NULL,
        captured_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS investigations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        query TEXT NOT NULL,
        result_json TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
)


def initialize_database(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        for statement in SCHEMA_STATEMENTS:
            conn.execute(statement)
        conn.execute(
            """
            DELETE FROM devices
            WHERE id NOT IN (
                SELECT MIN(id)
                FROM devices
                GROUP BY ip_address
            )
            """
        )
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address)")
        existing_columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(flows)").fetchall()
        }
        for column_name, column_def in (
            ("interface_name", "TEXT"),
            ("tcp_flags", "TEXT"),
            ("direction", "TEXT"),
        ):
            if column_name not in existing_columns:
                conn.execute(f"ALTER TABLE flows ADD COLUMN {column_name} {column_def}")
        device_columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(devices)").fetchall()
        }
        if "device_type" not in device_columns:
            conn.execute("ALTER TABLE devices ADD COLUMN device_type TEXT")
        baseline_columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(baseline_profiles)").fetchall()
        }
        if baseline_columns and "profile_json" not in baseline_columns:
            conn.execute("ALTER TABLE baseline_profiles ADD COLUMN profile_json TEXT")
        conn.commit()


def table_names(db_path: Path) -> list[str]:
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
    return [row[0] for row in rows]


def upsert_device(
    db_path: Path,
    ip_address: str | None,
    mac_address: str | None,
    hostname: str | None,
    vendor: str | None,
    device_type: str | None = None,
    observed_at: datetime | None = None,
) -> None:
    observed_at = observed_at or datetime.now(timezone.utc)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO devices (ip_address, mac_address, hostname, vendor, device_type, first_seen_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                mac_address=COALESCE(excluded.mac_address, devices.mac_address),
                hostname=COALESCE(excluded.hostname, devices.hostname),
                vendor=COALESCE(excluded.vendor, devices.vendor),
                device_type=COALESCE(excluded.device_type, devices.device_type),
                last_seen_at=excluded.last_seen_at
            """,
            (
                ip_address,
                mac_address,
                hostname,
                vendor,
                device_type,
                observed_at.isoformat(),
                observed_at.isoformat(),
            ),
        )
        conn.commit()


def upsert_flow(
    db_path: Path,
    source_ip: str | None,
    destination_ip: str | None,
    source_port: int | None,
    destination_port: int | None,
    protocol: str,
    interface_name: str,
    packet_count: int,
    byte_count: int,
    first_seen: str,
    last_seen: str,
    tcp_flags: str | None,
    direction: str | None,
) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO flows (
                source_ip, source_port, destination_ip, destination_port, protocol,
                packet_count, byte_count, started_at, ended_at, tcp_flags, direction, interface_name
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_ip,
                source_port,
                destination_ip,
                destination_port,
                protocol,
                packet_count,
                byte_count,
                first_seen,
                last_seen,
                tcp_flags,
                direction,
                interface_name,
            ),
        )
        conn.commit()


def persist_traffic_stats(db_path: Path, snapshot: dict) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO traffic_stats (
                interface_name, total_packets, total_bytes, packets_per_sec, bytes_per_sec,
                active_flows, active_devices, top_talkers_json, top_destinations_json,
                top_protocols_json, top_ports_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot["interface_name"],
                snapshot["total_packets"],
                snapshot["total_bytes"],
                snapshot["packets_per_sec"],
                snapshot["bytes_per_sec"],
                snapshot["active_flows"],
                snapshot["active_devices"],
                json.dumps(snapshot["top_talkers"]),
                json.dumps(snapshot["top_destinations"]),
                json.dumps(snapshot["top_protocols"]),
                json.dumps(snapshot["top_ports"]),
            ),
        )
        conn.commit()


def insert_dns_event(
    db_path: Path,
    queried_name: str | None,
    response_name: str | None,
    response_ip: str | None,
    source_ip: str | None,
    destination_ip: str | None,
    observed_at: str | None = None,
) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO dns_events (
                queried_name, response_name, response_ip, source_ip, destination_ip, observed_at
            ) VALUES (?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))
            """,
            (queried_name, response_name, response_ip, source_ip, destination_ip, observed_at),
        )
        conn.commit()


def insert_alert(db_path: Path, severity: str, title: str, details: str | None = None) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO alerts (severity, title, details) VALUES (?, ?, ?)",
            (severity, title, details),
        )
        conn.commit()


def insert_network_snapshot(db_path: Path, label: str, summary_json: str) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO network_snapshots (label, summary_json) VALUES (?, ?)",
            (label, summary_json),
        )
        conn.commit()


def insert_topology_graph(db_path: Path, label: str, nodes_json: str, edges_json: str, ascii_graph: str | None = None) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO topology_graphs (label, nodes_json, edges_json, ascii_graph) VALUES (?, ?, ?, ?)",
            (label, nodes_json, edges_json, ascii_graph),
        )
        conn.commit()


def upsert_baseline_profile(db_path: Path, device_ip: str, profile_json: str) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO baseline_profiles (device_ip, profile_json, learned_from, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT(device_ip) DO UPDATE SET
                profile_json=excluded.profile_json,
                updated_at=CURRENT_TIMESTAMP
            """,
            (device_ip, profile_json),
        )
        conn.commit()


def insert_attack_paths(db_path: Path, label: str, paths_json: str) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO attack_paths (label, paths_json) VALUES (?, ?)",
            (label, paths_json),
        )
        conn.commit()
