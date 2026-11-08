from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.analysis.reporting import write_report
from app.storage.database import initialize_database


class ReportingTests(unittest.TestCase):
    def test_write_report_text(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        db_path = tmp / "report.sqlite3"
        initialize_database(db_path)
        with sqlite3.connect(db_path) as conn:
            conn.execute("INSERT INTO devices (ip_address, mac_address, vendor, device_type) VALUES (?, ?, ?, ?)", ("192.168.18.10", "14:65:6A:00:00:01", "Apple, Inc.", "phone"))
            conn.execute("INSERT INTO flows (source_ip, destination_ip, source_port, destination_port, protocol, interface_name, packet_count, byte_count, started_at, ended_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)", ("192.168.18.10", "8.8.8.8", 1234, 443, "TCP", "Ethernet", 2, 200))
            conn.commit()
        out_dir = tmp / "reports"
        path, content = write_report(db_path, "text", out_dir)
        self.assertTrue(path.exists())
        self.assertIn("Device Inventory", content)
