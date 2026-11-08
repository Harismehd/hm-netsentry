from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LlmIntent:
    action: str
    params: dict


class LlmProvider:
    name = "base"

    def parse_intent(self, message: str, context: dict) -> LlmIntent:
        raise NotImplementedError

    def summarize(self, prompt: str) -> str:
        raise NotImplementedError

