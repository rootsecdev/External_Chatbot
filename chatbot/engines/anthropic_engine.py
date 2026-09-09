"""Real-model engine: drives the same prompts, tools and guards through the
Claude API.

Two things are worth pointing out during a demo:

1. Hardened mode changes nothing about this file. The mitigations live in the
   harness (chatbot/guards.py) and in the system prompt, which is exactly where
   they belong — you cannot patch a model into being safe, but you can refuse to
   execute what it asks for.
2. A current frontier model resists several of these attacks on its own, and
   the stronger the model the more it resists. That is a finding, not a
   disappointment: it shows which vectors survive a capable model (the ones the
   harness hands over on a plate — SSRF, over-broad retrieval, standing write
   access to CRM and mail) and which are mostly prompt-level.

A manual tool loop is used rather than the SDK's beta tool_runner because every
tool call has to pass through the guard layer before it executes, and the
result has to be sanitised before it goes back to the model.
"""
from __future__ import annotations

from chatbot.engines import EngineReply, ToolCall

MAX_TOKENS = 16000
# Server-side refusal fallbacks, on by default per Anthropic's guidance for
# claude-opus-5: if a safety classifier declines the request, the API routes it
# to a suitable fallback model instead of returning nothing usable.
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AnthropicEngine:
    name = "anthropic"

    def __init__(self, cfg):
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise SystemExit(
                "The anthropic package is required for --provider anthropic.\n"
                "  pip install anthropic\n"
                "Or run the lab offline with --provider simulated."
            ) from exc
        self._anthropic = anthropic
        # Zero-arg client: resolves ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN, or
        # an `ant auth login` profile, in that order.
        self.client = anthropic.Anthropic()
        self.cfg = cfg
        self._use_fallbacks = True

    def complete(self, system: str, messages: list[dict], tools: list[dict],
                 hardened: bool) -> EngineReply:
        anthropic = self._anthropic
        kwargs = dict(
            model=self.cfg.model,
            max_tokens=MAX_TOKENS,
            system=system,
            messages=messages,
            tools=tools,
            output_config={"effort": self.cfg.effort},
        )
        try:
            response = self._create(kwargs)
        except anthropic.NotFoundError as exc:
            return EngineReply(text=f"[model {self.cfg.model} not available: {exc}]",
                               note="api error")
        except anthropic.RateLimitError:
            return EngineReply(text="[rate limited — retry in a moment]",
                               note="api rate limit")
        except anthropic.APIStatusError as exc:
            return EngineReply(text=f"[API error {exc.status_code}: {exc.message}]",
                               note="api error")
        except anthropic.APIConnectionError as exc:
            return EngineReply(text=f"[cannot reach the API: {exc}]",
                               note="api connection error")

        # Always check stop_reason before touching content.
        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None) if details else None
            return EngineReply(
                text="[the model declined this request]",
                note=f"stop_reason=refusal category={category}")

        text_parts, calls = [], []
        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                calls.append(ToolCall(name=block.name, input=dict(block.input),
                                      id=block.id))
        return EngineReply(
            text="\n".join(text_parts).strip(),
            tool_calls=calls,
            note=f"{self.cfg.model} stop_reason={response.stop_reason} "
                 f"effort={self.cfg.effort}")

    def _create(self, kwargs: dict):
        """Prefer the refusal-fallback beta; fall back to the stable endpoint if
        this SDK or account does not accept it."""
        if self._use_fallbacks:
            try:
                return self.client.beta.messages.create(
                    betas=[FALLBACK_BETA], fallbacks="default", **kwargs)
            except (TypeError, self._anthropic.BadRequestError):
                # Older SDK, or the beta is not enabled for this account.
                self._use_fallbacks = False
        return self.client.messages.create(**kwargs)
