"""Pluggable response engines.

Both engines implement the same two-method surface so the agent loop, the tool
layer and every guard behave identically no matter which one is driving:

    engine.name -> str
    engine.complete(system, messages, tools, hardened) -> EngineReply

`messages` uses Anthropic content-block shape, so the real provider passes it
straight through and the simulated engine reads the same structure.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field

_ids = itertools.count(1)


@dataclass
class ToolCall:
    name: str
    input: dict
    id: str = field(default_factory=lambda: f"toolu_lab_{next(_ids):04d}")


@dataclass
class EngineReply:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    note: str = ""          # why the engine did this, shown in the demo trace


def build(provider: str, cfg):
    if provider == "simulated":
        from chatbot.engines.simulated import SimulatedEngine
        return SimulatedEngine()
    if provider == "anthropic":
        from chatbot.engines.anthropic_engine import AnthropicEngine
        return AnthropicEngine(cfg)
    raise ValueError(f"unknown provider {provider!r} (use 'simulated' or 'anthropic')")
