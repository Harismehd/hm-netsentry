from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
import sqlite3
from pathlib import Path

from app.analysis.telemetry import TelemetryEngine
from app.protocols.classifier import PacketView, classify_protocol
from app.storage.database import initialize_database, upsert_device
from app.fingerprint.oui import lookup_vendor
from app.fingerprint.device_type import infer_device_type
from app.fingerprint.fingerprint import enrich_devices
from app.analysis.topology import build_topology, render_ascii_topology


class Phase2Tests(unittest.TestCase):
    def test_protocol_classification(self) -> None:
        pkt = PacketView(protocol="UDP", src_port=5353, dst_port=5353, mdns=True, ip_version=4)
        protocols = classify_protocol(pkt)
        self.assertIn("UDP", protocols)
        self.assertIn("mDNS", protocols)

    def test_flow_and_device_tracking(self) -> None:
        engine = TelemetryEngine("Ethernet")
        pkt = PacketView(protocol="TCP", src_ip="192.168.1.10", dst_ip="1.1.1.1", src_port=51515, dst_port=443, tls=True, ip_version=4, payload_len=120)
        engine.observe_packet(pkt, datetime.now(timezone.utc))
        self.assertEqual(engine.total_packets, 1)
        self.assertEqual(engine.total_bytes, 120)
        self.assertEqual(len(engine.flows), 1)
        self.assertEqual(len(engine.devices), 2)

    def test_statistics_snapshot(self) -> None:
        engine = TelemetryEngine("Ethernet")
        engine.observe_packet(PacketView(protocol="UDP", src_ip="10.0.0.2", dst_ip="8.8.8.8", src_port=12345, dst_port=53, dns=True, ip_version=4, payload_len=60))
        snapshot = engine.snapshot()
        self.assertEqual(snapshot["total_packets"], 1)
        self.assertEqual(snapshot["active_flows"], 1)

    def test_database_persistence(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        db_path = tmp / "phase2.sqlite3"
        try:
            initialize_database(db_path)
            with sqlite3.connect(db_path) as conn:
                conn.execute(
                    "INSERT INTO traffic_stats (interface_name, total_packets, total_bytes, packets_per_sec, bytes_per_sec, active_flows, active_devices, top_talkers_json, top_destinations_json, top_protocols_json, top_ports_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    ("Ethernet", 1, 60, 1.0, 60.0, 1, 1, "[]", "[]", "[]", "[]"),
                )
                conn.commit()
                row = conn.execute("SELECT total_packets, total_bytes FROM traffic_stats LIMIT 1").fetchone()
            self.assertEqual(row, (1, 60))
        finally:
            pass

    def test_device_deduplication_by_ip(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        db_path = tmp / "devices.sqlite3"
        initialize_database(db_path)
        upsert_device(db_path, "192.168.18.1", "AA:BB:CC:DD:EE:FF", None, None)
        upsert_device(db_path, "192.168.18.1", "11:22:33:44:55:66", None, None)
        with sqlite3.connect(db_path) as conn:
            count = conn.execute("SELECT COUNT(*) FROM devices WHERE ip_address = ?", ("192.168.18.1",)).fetchone()[0]
            mac = conn.execute("SELECT mac_address FROM devices WHERE ip_address = ?", ("192.168.18.1",)).fetchone()[0]
        self.assertEqual(count, 1)
        self.assertEqual(mac, "11:22:33:44:55:66")

    def test_packet_mac_extraction(self) -> None:
        from app.capture.scapy_capture import to_packet_view
        from scapy.all import Ether, IP, TCP

        pkt = Ether(src="AA:BB:CC:DD:EE:FF", dst="11:22:33:44:55:66") / IP(src="192.168.18.1", dst="1.1.1.1") / TCP(sport=1234, dport=443)
        view = to_packet_view(pkt)
        self.assertEqual(view.src_mac, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(view.dst_mac, "11:22:33:44:55:66")

    def test_vendor_lookup_and_device_type(self) -> None:
        self.assertEqual(lookup_vendor("14:65:6a:00:00:01"), "Apple, Inc.")
        device_type = infer_device_type(vendor="Apple, Inc.", protocols=["TCP"], ports=[443], hostnames=["iphone.local"])
        self.assertEqual(device_type, "phone")

    def test_fingerprint_enrichment(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        db_path = tmp / "fingerprint.sqlite3"
        initialize_database(db_path)
        upsert_device(db_path, "192.168.18.99", "14:65:6A:AA:BB:CC", None, None, None)
        enriched = enrich_devices(db_path)
        row = next(item for item in enriched if item["ip_address"] == "192.168.18.99")
        self.assertEqual(row["vendor"], "Apple, Inc.")
        self.assertIn("device_type", row)

    def test_topology_build_and_ascii(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        db_path = tmp / "topology.sqlite3"
        initialize_database(db_path)
        with sqlite3.connect(db_path) as conn:
            conn.execute("INSERT INTO devices (ip_address, mac_address, first_seen_at, last_seen_at) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)", ("192.168.18.1", "14:65:6A:00:00:01"))
            conn.execute("INSERT INTO devices (ip_address, mac_address, first_seen_at, last_seen_at) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)", ("192.168.18.33", "FC:9D:05:00:00:01"))
            conn.execute("INSERT INTO flows (source_ip, destination_ip, source_port, destination_port, protocol, interface_name, packet_count, byte_count, started_at, ended_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)", ("192.168.18.1", "192.168.18.33", 1234, 443, "TCP", "Ethernet", 3, 300))
            conn.commit()
        graph = build_topology(db_path)
        ascii_graph = render_ascii_topology(graph)
        self.assertEqual(len(graph["nodes"]), 2)
        self.assertEqual(len(graph["edges"]), 1)
        self.assertIn("192.168.18.1 -> 192.168.18.33", ascii_graph)


class Phase3Tests(unittest.TestCase):
    def test_dns_and_alerts(self) -> None:
        engine = TelemetryEngine("Ethernet")
        for _ in range(3):
            engine.observe_packet(PacketView(protocol="UDP", src_ip="10.0.0.2", dst_ip="8.8.8.8", src_port=12345, dst_port=53, dns=True, dns_query="1234567890123456789012345678901234567890.bad.example.com", ip_version=4, payload_len=60))
        snap = engine.snapshot()
        self.assertGreaterEqual(len(snap["alerts"]), 1)

    def test_snapshot_shape(self) -> None:
        engine = TelemetryEngine("Ethernet")
        snap = engine.snapshot()
        self.assertIn("volume_windows", snap)
        self.assertIn("alerts", snap)


if __name__ == "__main__":
    unittest.main()
