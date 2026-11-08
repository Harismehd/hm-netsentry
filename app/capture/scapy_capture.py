from __future__ import annotations

from datetime import datetime, timezone
import time
from pathlib import Path

from scapy.all import AsyncSniffer, get_if_list
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from app.analysis.telemetry import TelemetryEngine
from app.protocols.classifier import PacketView
from app.storage.database import initialize_database


def available_capture_interfaces() -> list[str]:
    return list(get_if_list())


def to_packet_view(pkt) -> PacketView:
    ethertype = int(pkt[Ether].type) if Ether in pkt else None
    src_mac = str(pkt[Ether].src) if Ether in pkt and getattr(pkt[Ether], "src", None) else None
    dst_mac = str(pkt[Ether].dst) if Ether in pkt and getattr(pkt[Ether], "dst", None) else None
    ip_version = None
    src_ip = dst_ip = None
    protocol = None
    src_port = dst_port = None
    tcp_flags = None
    ttl = None
    udp_length = None
    dns = dhcp = arp = http = tls = ssh = ftp = smb = mdns = ssdp = quic = False

    if IP in pkt:
        ip = pkt[IP]
        ip_version = 4
        src_ip = ip.src
        dst_ip = ip.dst
        ttl = int(ip.ttl)
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        ip_version = 6
        src_ip = ip6.src
        dst_ip = ip6.dst
        ttl = int(getattr(ip6, "hlim", 0) or 0)

    if ARP in pkt:
        arp = True
        protocol = "ARP"
        src_ip = getattr(pkt[ARP], "psrc", src_ip)
        dst_ip = getattr(pkt[ARP], "pdst", dst_ip)
    elif TCP in pkt:
        protocol = "TCP"
        src_port = int(pkt[TCP].sport)
        dst_port = int(pkt[TCP].dport)
        tcp_flags = str(pkt[TCP].flags)
        if src_port in {80, 8080} or dst_port in {80, 8080}:
            http = True
        if src_port == 443 or dst_port == 443:
            tls = True
        if src_port == 22 or dst_port == 22:
            ssh = True
        if src_port in {20, 21} or dst_port in {20, 21}:
            ftp = True
        if src_port in {139, 445} or dst_port in {139, 445}:
            smb = True
    elif UDP in pkt:
        protocol = "UDP"
        src_port = int(pkt[UDP].sport)
        dst_port = int(pkt[UDP].dport)
        udp_length = int(pkt[UDP].len) if getattr(pkt[UDP], "len", None) is not None else None
        if DNS in pkt:
            dns = True
            try:
                dns_layer = pkt[DNS]
                if getattr(dns_layer, "qr", 0) == 0 and getattr(dns_layer, "qd", None):
                    dns_query = dns_layer.qd.qname.decode(errors="ignore").rstrip(".")
                elif getattr(dns_layer, "qr", 0) == 1:
                    dns_response = getattr(getattr(dns_layer, "an", None), "rrname", None)
                    if dns_response:
                        dns_response = dns_response.decode(errors="ignore").rstrip(".")
                    if getattr(dns_layer, "rcode", 0) == 3:
                        dns_nxdomain = True
                    if getattr(dns_layer, "an", None) and getattr(dns_layer.an, "rdata", None):
                        dns_response_ip = str(dns_layer.an.rdata)
            except Exception:
                pass
        if {src_port, dst_port} & {53}:
            dns = True
        if DHCP in pkt or BOOTP in pkt or {src_port, dst_port} & {67, 68}:
            dhcp = True
        if {src_port, dst_port} & {5353}:
            mdns = True
        if {src_port, dst_port} & {1900}:
            ssdp = True
        if {src_port, dst_port} & {443}:
            quic = True
    elif ICMP in pkt:
        protocol = "ICMP"

    payload_len = len(bytes(pkt))
    if protocol is None:
        protocol = "IPv4" if ip_version == 4 else "IPv6" if ip_version == 6 else "UNKNOWN"

    return PacketView(
        ethertype=ethertype,
        ip_version=ip_version,
        protocol=protocol,
        src_mac=src_mac,
        dst_mac=dst_mac,
        src_port=src_port,
        dst_port=dst_port,
        src_ip=src_ip,
        dst_ip=dst_ip,
        tcp_flags=tcp_flags,
        payload_len=payload_len,
        ttl=ttl,
        udp_length=udp_length,
        dns=dns,
        dhcp=dhcp,
        arp=arp,
        http=http,
        tls=tls,
        ssh=ssh,
        ftp=ftp,
        smb=smb,
        mdns=mdns,
        ssdp=ssdp,
        quic=quic,
    )


def run_capture(db_path: Path, interface_name: str, duration: int | None = None) -> dict:
    initialize_database(db_path)
    engine = TelemetryEngine(interface_name)
    engine.attach_database(db_path)

    def on_packet(pkt) -> None:
        engine.observe_packet(to_packet_view(pkt), datetime.now(timezone.utc))

    sniffer = AsyncSniffer(iface=interface_name, prn=on_packet, store=False)
    sniffer.start()
    try:
        if duration is None:
            while True:
                time.sleep(0.5)
        else:
            time.sleep(duration)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass
        try:
            sniffer.join()
        except Exception:
            pass
    engine.persist_summary()
    return engine.snapshot()
