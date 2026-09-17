#!/usr/bin/env python3
"""Scenario 1 lab launcher — external, public-facing chatbot.

    python3 lab.py                          # vulnerable, simulated engine
    python3 lab.py --mode hardened          # mitigations enforced
    python3 lab.py --provider anthropic     # drive a real model (needs a key)
    python3 lab.py --host 0.0.0.0           # attack it from another machine

Starts the simulated internal network (loopback only) alongside the public app
unless --no-internal is passed.
"""
from __future__ import annotations

import argparse
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from labconf import (CONFIG, INTERNAL_BASE, MODE_HARDENED, MODE_VULNERABLE,
                     PUBLIC_HOST, PUBLIC_PORT)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=[MODE_VULNERABLE, MODE_HARDENED],
                    default=CONFIG.mode, help="start vulnerable or hardened")
    ap.add_argument("--provider", choices=["simulated", "anthropic", "azure"],
                    default=CONFIG.provider,
                    help="deterministic rule engine, the real Claude API, or "
                         "Azure OpenAI")
    ap.add_argument("--model", default=CONFIG.model,
                    help="model id for --provider anthropic, or the deployment "
                         "name for --provider azure (or set AZURE_OPENAI_DEPLOYMENT)")
    ap.add_argument("--effort", default=CONFIG.effort,
                    choices=["low", "medium", "high", "xhigh", "max"])
    ap.add_argument("--host", default=PUBLIC_HOST)
    ap.add_argument("--port", type=int, default=PUBLIC_PORT)
    ap.add_argument("--no-internal", action="store_true",
                    help="do not start the simulated internal network")
    args = ap.parse_args()

    CONFIG.mode = args.mode
    CONFIG.provider = args.provider
    CONFIG.model = args.model
    CONFIG.effort = args.effort

    if not args.no_internal:
        from internal_services.server import main as internal_main
        threading.Thread(target=internal_main, daemon=True).start()
        print(f"[lab] internal network at {INTERNAL_BASE} (reachable by the bot only)")

    from chatbot.server import serve
    serve(args.host, args.port)


if __name__ == "__main__":
    main()
