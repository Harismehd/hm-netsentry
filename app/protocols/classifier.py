from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PacketView:
    ethertype: int | None = None
    ip_version: int | None = None
    protocol: str | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    tcp_flags: str | None = None
    payload_len: int = 0
    ttl: int | None = None
    udp_length: int | None = None
    dns: bool = False
    dhcp: bool = False
    arp: bool = False
    http: bool = False
    tls: bool = False
    ssh: bool = False
    ftp: bool = False
    smb: bool = False
    mdns: bool = False
    ssdp: bool = False
    quic: bool = False
    dns_query: str | None = None
    dns_response: str | None = None
    dns_response_ip: str | None = None
    dns_nxdomain: bool = False


def classify_protocol(pkt: PacketView) -> list[str]:
    protocols: list[str] = []
    if pkt.arp or pkt.ethertype == 0x0806:
        protocols.append("ARP")
    if pkt.ip_version == 4:
        protocols.append("IPv4")
    if pkt.ip_version == 6:
        protocols.append("IPv6")
    if pkt.protocol == "TCP":
        protocols.append("TCP")
    if pkt.protocol == "UDP":
        protocols.append("UDP")
    if pkt.protocol == "ICMP":
        protocols.append("ICMP")
    if pkt.dns or pkt.src_port == 53 or pkt.dst_port == 53:
        protocols.append("DNS")
    if pkt.dhcp or {pkt.src_port, pkt.dst_port} & {67, 68}:
        protocols.append("DHCP")
    if pkt.http or {pkt.src_port, pkt.dst_port} & {80, 8080, 8000, 5000}:
        protocols.append("HTTP")
    if pkt.tls or {pkt.src_port, pkt.dst_port} & {443, 8443}:
        protocols.append("TLS/HTTPS")
    if pkt.ssh or {pkt.src_port, pkt.dst_port} & {22}:
        protocols.append("SSH")
    if pkt.ftp or {pkt.src_port, pkt.dst_port} & {20, 21}:
        protocols.append("FTP")
    if pkt.smb or {pkt.src_port, pkt.dst_port} & {445, 139}:
        protocols.append("SMB")
    if pkt.mdns or {pkt.src_port, pkt.dst_port} & {5353}:
        protocols.append("mDNS")
    if pkt.ssdp or {pkt.src_port, pkt.dst_port} & {1900}:
        protocols.append("SSDP")
    if pkt.quic or {pkt.src_port, pkt.dst_port} & {443, 80} and pkt.protocol == "UDP":
        protocols.append("QUIC")
    return list(dict.fromkeys(protocols))
