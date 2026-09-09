"""The agent loop.

Order of operations per tool call, and the order is the whole point:

    engine asks for a tool
      -> guards.authorize_tool   (may this tool run at all?)
      -> tool-specific guard     (egress allowlist, rate limit, retrieval scope)
      -> execute
      -> guards.prepare_tool_result  (sanitise + label attacker-controlled text)
      -> back to the engine
    engine produces an answer
      -> guards.scan_output      (secrets and unauthorised commitments)
      -> user

Content from a first-party retrieval (kb_search) is trusted-but-scoped: the
control is *what it returns*, not how it is labelled. Content from a web page,
a page comment or an arbitrary HTTP response is attacker-controllable, so it
gets wrapped as data.
"""
from __future__ import annotations

import threading

from labconf import CONFIG, LabConfig
from chatbot import engines, guards, prompts, state, tools


class Agent:
    def __init__(self, cfg: LabConfig | None = None):
        self.cfg = cfg or CONFIG
        self.engine = engines.build(self.cfg.provider, self.cfg)
        self._history: dict[str, list[dict]] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    def history(self, session: str) -> list[dict]:
        with self._lock:
            return list(self._history.get(session, []))

    def clear(self, session: str) -> None:
        with self._lock:
            self._history.pop(session, None)

    # ------------------------------------------------------------------
    def respond(self, session: str, user_text: str) -> dict:
        cfg = self.cfg
        hardened = cfg.hardened()
        system = prompts.system_prompt(hardened)
        specs = tools.specs_for(cfg)

        state.trace(session, "user", user_text[:400], mode=cfg.mode)
        messages = [{"role": "user", "content": m["text"]} if m["role"] == "user"
                    else {"role": "assistant", "content": m["text"]}
                    for m in self.history(session)]
        messages.append({"role": "user", "content": user_text})

        steps = 0
        reply = None
        for steps in range(1, cfg.max_tool_steps + 1):
            reply = self.engine.complete(system, messages, specs, hardened)
            if reply.note:
                state.trace(session, "engine", reply.note, step=steps)

            if not reply.tool_calls:
                break

            assistant_blocks = []
            if reply.text:
                assistant_blocks.append({"type": "text", "text": reply.text})
            for tc in reply.tool_calls:
                assistant_blocks.append({"type": "tool_use", "id": tc.id,
                                         "name": tc.name, "input": tc.input})
            messages.append({"role": "assistant", "content": assistant_blocks})

            results = []
            for tc in reply.tool_calls:
                out = tools.execute(tc.name, tc.input, cfg, session)
                content = out.text
                if out.untrusted:
                    # Provenance is recorded in both modes. Vulnerable mode
                    # labels the source but grants it the same authority as
                    # everything else in the context window — which is the
                    # actual state of most deployments. Hardened mode wraps it
                    # in the markers the system prompt defines as data-only.
                    content = guards.prepare_tool_result(content, out.source,
                                                         cfg, session)
                    if not cfg.hardened():
                        content = f"[content from {out.source}]\n{content}"
                results.append({"type": "tool_result", "tool_use_id": tc.id,
                                "content": content})
            messages.append({"role": "user", "content": results})
        else:
            state.trace(session, "engine",
                        f"tool-step ceiling ({cfg.max_tool_steps}) reached", step=steps)

        raw = (reply.text if reply else "") or (
            "I wasn't able to finish that request.")
        final, findings = guards.scan_output(raw, cfg, session)

        with self._lock:
            hist = self._history.setdefault(session, [])
            hist.append({"role": "user", "text": user_text})
            hist.append({"role": "assistant", "text": final})

        state.trace(session, "assistant", final[:400],
                    findings=findings, mode=cfg.mode)
        return {
            "reply": final,
            "raw": raw,
            "findings": findings,
            "withheld": bool(findings) and hardened,
            "steps": steps,
            "mode": cfg.mode,
            "provider": self.engine.name,
        }
