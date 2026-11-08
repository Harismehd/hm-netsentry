from __future__ import annotations

import json
import re
from dataclasses import dataclass

from app.llm.provider import LlmIntent


def _extract_minutes(text: str, default: int = 10) -> int:
    match = re.search(r"last\s+(\d+)\s+minutes?", text.lower())
    return int(match.group(1)) if match else default


def rule_intent(message: str) -> LlmIntent:
    text = message.lower().strip()
    if "analyze my network" in text:
        return LlmIntent("analyze_network", {})
    if "show all devices" in text or "show me all devices" in text or text == "devices":
        return LlmIntent("list_devices", {})
    if "how many devices" in text or "number of devices" in text or "device count" in text:
        return LlmIntent("count_devices", {})
    if "which device has most traffic" in text or "most traffic" in text or "top talker" in text:
        return LlmIntent("top_talker", {})
    if "show unusual traffic" in text or "abnormal behavior" in text or "abnormal behaviour" in text:
        return LlmIntent("unusual_traffic", {})
    if text.startswith("investigate ip ") or text.startswith("investigate "):
        ip = text.split("investigate", 1)[1].strip().replace("ip", "", 1).strip().split()[0]
        return LlmIntent("investigate_ip", {"ip": ip})
    if "what protocols are being used" in text:
        return LlmIntent("protocols", {})
    if "show alerts" in text or "show all alerts" in text or "alerts" == text:
        return LlmIntent("show_alerts", {})
    if "top external destinations" in text:
        return LlmIntent("top_external_destinations", {})
    if "what changed" in text:
        return LlmIntent("changed_recently", {"minutes": _extract_minutes(text)})
    return LlmIntent("unknown", {"message": message})
