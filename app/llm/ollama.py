from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class OllamaStatus:
    reachable: bool
    model_available: bool
    details: str


def _http_get(url: str, timeout: float = 3.0) -> tuple[int, str]:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.status, response.read().decode("utf-8", errors="ignore")


def check_ollama(host: str, model: str) -> OllamaStatus:
    try:
        status_code, body = _http_get(f"{host.rstrip('/')}/api/tags")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return OllamaStatus(False, False, f"unreachable: {exc}")

    if status_code != 200:
        return OllamaStatus(True, False, f"unexpected status {status_code}")

    try:
        payload = json.loads(body)
        names = {item.get("name") for item in payload.get("models", [])}
    except Exception as exc:  # pragma: no cover - defensive
        return OllamaStatus(True, False, f"invalid response: {exc}")

    return OllamaStatus(True, model in names, "ok" if model in names else "model not found")

