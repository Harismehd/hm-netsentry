from __future__ import annotations

import json
import urllib.error
import urllib.request

from app.llm.provider import LlmIntent, LlmProvider
from app.llm.router import rule_intent


class OllamaProvider(LlmProvider):
    name = "ollama"

    def __init__(self, host: str, model: str) -> None:
        self.host = host.rstrip("/")
        self.model = model

    def parse_intent(self, message: str, context: dict) -> LlmIntent:
        local = rule_intent(message)
        if local.action != "unknown":
            return local
        prompt = (
            "You are a router for a network telemetry assistant. "
            "Return ONLY JSON with keys action and params. "
            "Allowed actions: analyze_network, list_devices, count_devices, top_talker, unusual_traffic, show_alerts, "
            "investigate_ip, protocols, top_external_destinations, changed_recently, unknown. "
            f"Question: {message}"
        )
        try:
            payload = json.dumps({"model": self.model, "prompt": prompt, "stream": False}).encode()
            req = urllib.request.Request(
                f"{self.host}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=20) as resp:
                body = json.loads(resp.read().decode("utf-8", errors="ignore"))
            raw = body.get("response", "").strip()
            parsed = json.loads(raw)
            action = parsed.get("action", "unknown")
            params = parsed.get("params", {})
            if isinstance(params, dict):
                return LlmIntent(action, params)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
            pass
        return local

    def summarize(self, prompt: str) -> str:
        payload = json.dumps({"model": self.model, "prompt": prompt, "stream": False}).encode()
        req = urllib.request.Request(
            f"{self.host}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode("utf-8", errors="ignore"))
        return body.get("response", "").strip()
