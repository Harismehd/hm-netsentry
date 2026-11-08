from __future__ import annotations

import platform
from dataclasses import dataclass

from scapy.all import get_if_list

from app.capture.scapy_capture import run_capture


@dataclass(frozen=True)
class CaptureCapability:
    available: bool
    method: str
    details: str


def detect_capture_capability() -> CaptureCapability:
    if platform.system().lower() != "windows":
        return CaptureCapability(False, "unsupported", "Phase 2 capture is Windows-oriented")
    interfaces = list(get_if_list())
    if interfaces:
        return CaptureCapability(True, "scapy", "Scapy capture interfaces available")
    return CaptureCapability(False, "missing", "Scapy could not see capture interfaces; Npcap may be missing")


def list_capture_interfaces() -> list[str]:
    cap = detect_capture_capability()
    if not cap.available:
        return []
    return list(get_if_list())


def start_capture(db_path, interface_name: str, duration: int | None = None) -> dict:
    cap = detect_capture_capability()
    if not cap.available:
        raise RuntimeError(cap.details)
    return run_capture(db_path, interface_name, duration)
