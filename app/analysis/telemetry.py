from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path

from app.protocols.classifier import PacketView, classify_protocol
from app.storage.database import (
    insert_alert,
    insert_dns_event,
    insert_network_snapshot,
    persist_traffic_stats,
    upsert_device,
    upsert_flow,
)
from app.fingerprint.oui import lookup_vendor
from app.fingerprint.device_type import infer_device_type


@dataclass
class FlowRecord:
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str
    interface_name: str
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    packets: int = 0
    bytes: int = 0
    tcp_flags: str | None = None
    direction: str | None = None

    def observe(self, payload_bytes: int, observed_at: datetime, tcp_flags: str | None = None) -> None:
        self.last_seen = observed_at
        self.packets += 1
        self.bytes += payload_bytes
        if tcp_flags:
            self.tcp_flags = tcp_flags

    @property
    def duration(self) -> float:
        return max(0.0, (self.last_seen - self.first_seen).total_seconds())


@dataclass
class DeviceRecord:
    ip_address: str | None
    mac_address: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def touch(self, observed_at: datetime) -> None:
        self.last_seen = observed_at


@dataclass
class DnsRecord:
    queried_name: str | None
    response_name: str | None
    response_ip: str | None
    source_ip: str | None
    destination_ip: str | None
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class TelemetryEngine:
    def __init__(self, interface_name: str) -> None:
        self.interface_name = interface_name
        self.flows: dict[tuple, FlowRecord] = {}
        self.devices: dict[str, DeviceRecord] = {}
        self.protocol_counts: Counter[str] = Counter()
        self.port_counts: Counter[int] = Counter()
        self.talker_counts: Counter[str] = Counter()
        self.destination_counts: Counter[str] = Counter()
        self.flow_timestamps: Counter[str] = Counter()
        self.dns_queries: Counter[str] = Counter()
        self.dns_nxdomain_count = 0
        self.dns_records: list[DnsRecord] = []
        self.alerts: list[tuple[str, str, str | None]] = []
        self.total_packets = 0
        self.total_bytes = 0
        self.started_at = datetime.now(timezone.utc)
        self._db_path: Path | None = None

    def attach_database(self, db_path: Path) -> None:
        self._db_path = db_path

    def observe_packet(self, packet: PacketView, observed_at: datetime | None = None) -> None:
        observed_at = observed_at or datetime.now(timezone.utc)
        self.total_packets += 1
        self.total_bytes += packet.payload_len
        protocols = classify_protocol(packet)
        for proto in protocols:
            self.protocol_counts[proto] += 1
        for port in (packet.src_port, packet.dst_port):
            if port is not None:
                self.port_counts[port] += 1
        if packet.src_ip:
            self.talker_counts[packet.src_ip] += 1
            src_vendor = lookup_vendor(packet.src_mac)
            self.devices.setdefault(packet.src_ip, DeviceRecord(ip_address=packet.src_ip, mac_address=packet.src_mac, vendor=src_vendor)).touch(observed_at)
            if self._db_path:
                src_type = infer_device_type(vendor=src_vendor, protocols=protocols, ports=[p for p in (packet.src_port, packet.dst_port) if p is not None], hostnames=[])
                upsert_device(self._db_path, packet.src_ip, packet.src_mac, None, src_vendor, src_type, observed_at)
        if packet.dst_ip:
            self.destination_counts[packet.dst_ip] += 1
            dst_vendor = lookup_vendor(packet.dst_mac)
            self.devices.setdefault(packet.dst_ip, DeviceRecord(ip_address=packet.dst_ip, mac_address=packet.dst_mac, vendor=dst_vendor)).touch(observed_at)
            if self._db_path:
                dst_type = infer_device_type(vendor=dst_vendor, protocols=protocols, ports=[p for p in (packet.src_port, packet.dst_port) if p is not None], hostnames=[])
                upsert_device(self._db_path, packet.dst_ip, packet.dst_mac, None, dst_vendor, dst_type, observed_at)
        flow_key = (packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, packet.protocol or "UNKNOWN", self.interface_name)
        flow = self.flows.get(flow_key)
        if flow is None:
            flow = FlowRecord(packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, packet.protocol or "UNKNOWN", self.interface_name)
            self.flows[flow_key] = flow
        flow.observe(packet.payload_len, observed_at, packet.tcp_flags)
        self.flow_timestamps[flow.source_ip or "unknown"] += 1
        self._detect_anomalies(flow)
        if self._db_path:
            upsert_flow(
                self._db_path,
                flow.source_ip,
                flow.destination_ip,
                flow.source_port,
                flow.destination_port,
                flow.protocol,
                flow.interface_name,
                flow.packets,
                flow.bytes,
                flow.first_seen.isoformat(),
                flow.last_seen.isoformat(),
                flow.tcp_flags,
                flow.direction,
            )
        if packet.dns:
            self._handle_dns(packet, observed_at)

    def _handle_dns(self, packet: PacketView, observed_at: datetime) -> None:
        queried = getattr(packet, "dns_query", None)
        response = getattr(packet, "dns_response", None)
        response_ip = getattr(packet, "dns_response_ip", None)
        self.dns_records.append(DnsRecord(queried, response, response_ip, packet.src_ip, packet.dst_ip, observed_at))
        if queried:
            self.dns_queries[queried] += 1
            if self._looks_suspicious_domain(queried):
                self._raise_alert("medium", "Suspicious domain pattern", queried)
        if getattr(packet, "dns_nxdomain", False):
            self.dns_nxdomain_count += 1
            if self.dns_nxdomain_count >= 3:
                self._raise_alert("medium", "NXDOMAIN spike", f"{self.dns_nxdomain_count} NXDOMAIN responses observed")
        if self._db_path:
            insert_dns_event(
                self._db_path,
                queried,
                response,
                response_ip,
                packet.src_ip,
                packet.dst_ip,
                observed_at.isoformat(),
            )

    def _looks_suspicious_domain(self, domain: str) -> bool:
        parts = domain.split(".")
        if len(domain) > 80 or sum(1 for c in domain if c.isdigit()) > len(domain) // 2:
            return True
        if len(parts) > 5 or any(len(part) > 30 for part in parts):
            return True
        if "-" in domain and any(part.isdigit() for part in parts[0:1]):
            return True
        return False

    def _detect_anomalies(self, flow: FlowRecord) -> None:
        if flow.source_ip and self.flow_timestamps[flow.source_ip] >= 10:
            self._raise_alert("medium", "High-frequency flow source", flow.source_ip)
        if flow.protocol in {"TCP", "UDP"} and flow.destination_port is not None:
            if flow.protocol == "TCP" and flow.destination_port not in {20, 21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 1433, 3306, 3389}:
                self._raise_alert("low", "Unusual port observed", f"{flow.protocol} to {flow.destination_port}")
            if flow.protocol == "UDP" and flow.destination_port not in {53, 67, 68, 123, 137, 138, 161, 162, 443, 500, 5353, 1900}:
                self._raise_alert("low", "Unusual port observed", f"{flow.protocol} to {flow.destination_port}")

    def _raise_alert(self, severity: str, title: str, details: str | None = None) -> None:
        item = (severity, title, details)
        if item not in self.alerts:
            self.alerts.append(item)
            if self._db_path:
                insert_alert(self._db_path, severity, title, details)

    def snapshot(self) -> dict:
        elapsed = max(1.0, (datetime.now(timezone.utc) - self.started_at).total_seconds())
        volume_window = {
            "last_60s_packets": self.total_packets,
            "last_60s_bytes": self.total_bytes,
        }
        return {
            "interface_name": self.interface_name,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "packets_per_sec": self.total_packets / elapsed,
            "bytes_per_sec": self.total_bytes / elapsed,
            "active_flows": len(self.flows),
            "active_devices": len(self.devices),
            "top_talkers": self.talker_counts.most_common(5),
            "top_destinations": self.destination_counts.most_common(5),
            "top_protocols": self.protocol_counts.most_common(10),
            "top_ports": self.port_counts.most_common(10),
            "volume_windows": volume_window,
            "alerts": self.alerts,
        }

    def persist_summary(self) -> None:
        if self._db_path:
            for device in self.devices.values():
                upsert_device(
                    self._db_path,
                    device.ip_address,
                    device.mac_address,
                    device.hostname,
                    device.vendor,
                    device.last_seen,
                )
            for flow in self.flows.values():
                upsert_flow(
                    self._db_path,
                    flow.source_ip,
                    flow.destination_ip,
                    flow.source_port,
                    flow.destination_port,
                    flow.protocol,
                    flow.interface_name,
                    flow.packets,
                    flow.bytes,
                    flow.first_seen.isoformat(),
                    flow.last_seen.isoformat(),
                    flow.tcp_flags,
                    flow.direction,
                )
            for dns in self.dns_records:
                insert_dns_event(
                    self._db_path,
                    dns.queried_name,
                    dns.response_name,
                    dns.response_ip,
                    dns.source_ip,
                    dns.destination_ip,
                    dns.observed_at.isoformat(),
                )
            insert_network_snapshot(self._db_path, "telemetry_snapshot", json.dumps(self.snapshot(), default=str))
            persist_traffic_stats(self._db_path, self.snapshot())
