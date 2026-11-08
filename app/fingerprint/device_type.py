from __future__ import annotations


def infer_device_type(*, vendor: str | None, protocols: list[str], ports: list[int], hostnames: list[str]) -> str:
    hints = " ".join(hostnames).lower()
    protocol_set = {p.upper() for p in protocols}
    port_set = set(ports)

    if any(tag in hints for tag in ("iphone", "android", "ipad", "mobile")):
        return "phone"
    if any(tag in hints for tag in ("printer",)):
        return "printer"
    if any(tag in hints for tag in ("camera", "cam", "ring", "nest", "hue")) or 554 in port_set:
        return "iot"
    if vendor and any(tag in vendor.lower() for tag in ("apple", "samsung", "google")):
        return "phone"
    if {80, 443, 22, 445, 3389} & port_set or {"TCP"} & protocol_set:
        return "laptop"
    if 53 in port_set and 67 in port_set and len(port_set) <= 4:
        return "router"
    return "unknown"

