from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
import sqlite3

from app.analysis.baseline import detect_baseline_deviations, get_baseline, learn_baselines
from app.storage.database import initialize_database


class BaselineTests(unittest.TestCase):
    def test_learn_and_get_baseline(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        db_path = tmp / "baseline.sqlite3"
        initialize_database(db_path)
        with sqlite3.connect(db_path) as conn:
            conn.execute("INSERT INTO devices (ip_address, mac_address, vendor, device_type) VALUES (?, ?, ?, ?)", ("192.168.18.10", "14:65:6A:00:00:01", "Apple, Inc.", "phone"))
            conn.execute("INSERT INTO flows (source_ip, destination_ip, source_port, destination_port, protocol, interface_name, packet_count, byte_count, started_at, ended_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)", ("192.168.18.10", "8.8.8.8", 1234, 443, "TCP", "Ethernet", 20, 2000))
            conn.commit()
        learned = learn_baselines(db_path)
        self.assertTrue(learned)
        profile = get_baseline(db_path, "192.168.18.10")
        self.assertIsNotNone(profile)
        self.assertEqual(profile["vendor"], "Apple, Inc.")

    def test_detect_baseline_deviation(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        db_path = tmp / "baseline.sqlite3"
        initialize_database(db_path)
        with sqlite3.connect(db_path) as conn:
            conn.execute("INSERT INTO devices (ip_address, mac_address, vendor, device_type) VALUES (?, ?, ?, ?)", ("192.168.18.10", "14:65:6A:00:00:01", "Apple, Inc.", "phone"))
            conn.execute("INSERT INTO flows (source_ip, destination_ip, source_port, destination_port, protocol, interface_name, packet_count, byte_count, started_at, ended_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)", ("192.168.18.10", "8.8.8.8", 1234, 443, "TCP", "Ethernet", 5, 500))
            conn.execute("INSERT INTO baseline_profiles (device_ip, profile_json, learned_from, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)", ("192.168.18.10", json.dumps({
                "device_ip": "192.168.18.10",
                "average_packets_per_hour": 1,
                "average_bytes_per_hour": 100,
                "average_connections_per_hour": 1,
                "unique_external_destinations_per_day": 1,
                "protocol_distribution": {"TCP": 1},
            })))
            conn.commit()
        alerts = detect_baseline_deviations(db_path)
        self.assertTrue(alerts)

