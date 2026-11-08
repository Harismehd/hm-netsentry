from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.analysis.attack_paths import build_attack_paths
from app.storage.database import initialize_database


class AttackPathTests(unittest.TestCase):
    def test_attack_paths_build(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        db_path = tmp / "attack.sqlite3"
        initialize_database(db_path)
        with sqlite3.connect(db_path) as conn:
            conn.execute("INSERT INTO devices (ip_address, mac_address, vendor, device_type) VALUES (?, ?, ?, ?)", ("8.8.8.8", None, None, None))
            conn.execute("INSERT INTO devices (ip_address, mac_address, vendor, device_type) VALUES (?, ?, ?, ?)", ("192.168.18.10", None, None, None))
            conn.execute("INSERT INTO devices (ip_address, mac_address, vendor, device_type) VALUES (?, ?, ?, ?)", ("192.168.18.20", None, None, None))
            conn.execute("INSERT INTO flows (source_ip, destination_ip, source_port, destination_port, protocol, interface_name, packet_count, byte_count, started_at, ended_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)", ("8.8.8.8", "192.168.18.10", 443, 3389, "TCP", "Ethernet", 5, 500))
            conn.execute("INSERT INTO flows (source_ip, destination_ip, source_port, destination_port, protocol, interface_name, packet_count, byte_count, started_at, ended_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)", ("192.168.18.10", "192.168.18.20", 3389, 445, "TCP", "Ethernet", 4, 400))
            conn.commit()
        result = build_attack_paths(db_path)
        self.assertTrue(result["paths"])
        self.assertEqual(result["paths"][0]["path"], ["8.8.8.8", "192.168.18.10", "192.168.18.20"])
        self.assertGreater(result["paths"][0]["risk"], 0)
