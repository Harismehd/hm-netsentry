from __future__ import annotations

from functools import lru_cache


LOCAL_OUI_PREFIXES: dict[str, str] = {
    "14:65:6A": "Apple, Inc.",
    "FC:9D:05": "ASUSTek COMPUTER INC.",
    "00:1A:7D": "Lite-On Technology Corporation",
    "B8:F2:CC": "Intel Corporate",
    "F4:B5:E4": "Samsung Electronics Co.,Ltd",
}


def _normalize_prefix(prefix: str) -> str:
    return prefix.replace("-", ":").upper()


@lru_cache(maxsize=512)
def lookup_vendor(mac_address: str | None) -> str | None:
    if not mac_address:
        return None
    prefix = ":".join(mac_address.replace("-", ":").upper().split(":")[:3])
    return LOCAL_OUI_PREFIXES.get(prefix)

