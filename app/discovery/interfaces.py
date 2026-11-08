from __future__ import annotations

import platform
import re
import socket
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class NetworkInterface:
    name: str
    description: str = ""
    ipv4_address: str | None = None
    mac_address: str | None = None
    is_up: bool = False


def _parse_windows_ipconfig() -> list[NetworkInterface]:
    result = subprocess.run(
        ["ipconfig", "/all"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        check=False,
    )
    text = result.stdout
    interfaces: list[NetworkInterface] = []
    current_name = None
    current_ipv4 = None
    current_mac = None
    current_up = False

    adapter_header = re.compile(r"^(Ethernet|Wireless LAN|Wi-Fi|Ethernet adapter|Wireless LAN adapter|Teredo|Local Area Connection).*$")
    mac_pattern = re.compile(r"Physical Address[.\s]*:[\s-]*([0-9A-Fa-f-]{11,17})")
    ipv4_pattern = re.compile(r"IPv4 Address[.\s]*:[\s]*([0-9.]+)")
    media_pattern = re.compile(r"Media State[.\s]*:[\s]*(.+)")

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.endswith(":") and "adapter" in stripped.lower():
            if current_name:
                interfaces.append(
                    NetworkInterface(
                        name=current_name,
                        ipv4_address=current_ipv4,
                        mac_address=current_mac,
                        is_up=current_up,
                    )
                )
            current_name = stripped[:-1]
            current_ipv4 = None
            current_mac = None
            current_up = True
            continue
        mac_match = mac_pattern.search(stripped)
        if mac_match:
            current_mac = mac_match.group(1).replace("-", ":")
        ipv4_match = ipv4_pattern.search(stripped)
        if ipv4_match:
            current_ipv4 = ipv4_match.group(1)
        media_match = media_pattern.search(stripped)
        if media_match and "disconnected" in media_match.group(1).lower():
            current_up = False

    if current_name:
        interfaces.append(
            NetworkInterface(
                name=current_name,
                ipv4_address=current_ipv4,
                mac_address=current_mac,
                is_up=current_up,
            )
        )
    return interfaces


def discover_network_interfaces() -> list[NetworkInterface]:
    if platform.system().lower() == "windows":
        return _parse_windows_ipconfig()
    hostname = socket.gethostname()
    return [NetworkInterface(name=hostname, description="local-host")]

