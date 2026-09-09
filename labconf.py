"""Shared lab configuration.

Everything the demo needs to agree on lives here so the web app, the internal
service simulator and the exploit runner cannot drift apart.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Fictional target company. Nothing here maps to a real organisation; the
# .example TLD is reserved by RFC 2606 precisely for this purpose.
# ---------------------------------------------------------------------------
COMPANY = "Northwind Dynamics"
BOT_NAME = "Nora"
PUBLIC_DOMAIN = "northwind-dynamics.example"

# Canary planted in the vulnerable system prompt. If this string ever reaches a
# user-visible response, the system prompt leaked. Hardened mode blocks it.
SYSTEM_PROMPT_CANARY = "NWD-CANARY-7f3a91b2"

MODE_VULNERABLE = "vulnerable"
MODE_HARDENED = "hardened"

PUBLIC_HOST = os.environ.get("LAB_PUBLIC_HOST", "127.0.0.1")
PUBLIC_PORT = int(os.environ.get("LAB_PUBLIC_PORT", "8000"))

# The "internal" network the chatbot's server can reach and the attacker cannot.
# Bound to loopback on purpose: run the public app on 0.0.0.0 and attack it from
# a second machine and the isolation is real, not simulated.
INTERNAL_HOST = os.environ.get("LAB_INTERNAL_HOST", "127.0.0.1")
INTERNAL_PORT = int(os.environ.get("LAB_INTERNAL_PORT", "9001"))
INTERNAL_BASE = f"http://{INTERNAL_HOST}:{INTERNAL_PORT}"


@dataclass
class LabConfig:
    mode: str = os.environ.get("LAB_MODE", MODE_VULNERABLE)
    provider: str = os.environ.get("LAB_PROVIDER", "simulated")
    model: str = os.environ.get("LAB_MODEL", "claude-opus-5")
    effort: str = os.environ.get("LAB_EFFORT", "low")
    max_tool_steps: int = 6

    # Hardened-mode egress allowlist for the fetch_url tool.
    egress_allowlist: tuple = (PUBLIC_DOMAIN, f"www.{PUBLIC_DOMAIN}", f"docs.{PUBLIC_DOMAIN}")

    # Hardened-mode rate limits for the ticketing tool.
    max_tickets_per_session: int = 2

    def hardened(self) -> bool:
        return self.mode == MODE_HARDENED


CONFIG = LabConfig()
