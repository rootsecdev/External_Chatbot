"""Real-model engine: drives the same prompts, tools and guards through Azure
OpenAI (the Chat Completions API).

Everything the demo relies on is identical to the other engines. The only real
work here is translation: the whole harness speaks the Anthropic content-block
shape (so the Anthropic engine can pass `messages` straight through and the
simulated engine can read the same structure), while Azure OpenAI speaks the
OpenAI Chat Completions shape. This file converts one to the other on the way
in and back again on the way out. The guard layer, the tool loop and the system
prompts never change.

The same two demo points hold as for the Anthropic engine:

1. Hardened mode changes nothing about this file. The mitigations live in the
   harness (chatbot/guards.py) and in the system prompt.
2. A capable model resists several of these attacks on its own — a finding, not
   a disappointment. Vectors 3, 4 and 6 (over-broad retrieval, SSRF, standing
   write access) survive it regardless, because the harness hands them over.

Azure's own content filter is the OpenAI analogue of Anthropic's server-side
refusal: when it declines a request the engine surfaces that plainly rather
than crashing, which is worth putting on screen for the same reason.

Configuration is read from the environment, matching Azure's own conventions:

    AZURE_OPENAI_ENDPOINT      https://<resource>.openai.azure.com   (required)
    AZURE_OPENAI_API_KEY       the resource key                      (or AD token)
    AZURE_OPENAI_AD_TOKEN      an Entra ID token, instead of a key   (optional)
    AZURE_OPENAI_API_VERSION   defaults to a recent GA version       (optional)
    AZURE_OPENAI_DEPLOYMENT    the deployment name to call           (or --model)

On Azure the model is addressed by *deployment name*, not model id, so set
AZURE_OPENAI_DEPLOYMENT or pass --model with the deployment name.
"""
from __future__ import annotations

import json
import os

from chatbot.engines import EngineReply, ToolCall

MAX_TOKENS = 16000
DEFAULT_API_VERSION = "2024-10-21"

# The lab's effort scale mapped onto OpenAI's reasoning_effort. Only reasoning
# models accept the parameter; a deployment that rejects it is retried without.
_EFFORT = {"low": "low", "medium": "medium", "high": "high",
           "xhigh": "high", "max": "high"}


def _to_openai_tools(tools: list[dict]) -> list[dict]:
    """Anthropic tool spec -> OpenAI function-tool spec."""
    return [{
        "type": "function",
        "function": {
            "name": t["name"],
            "description": t.get("description", ""),
            "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
        },
    } for t in tools]


def _to_openai_messages(system: str, messages: list[dict]) -> list[dict]:
    """Anthropic content-block messages -> OpenAI chat messages.

    A string content passes through. An assistant block list splits into text
    (the message content) and tool_use blocks (OpenAI tool_calls). A user block
    list is tool results, and each one becomes its own `tool` message keyed by
    the id the assistant used — which is why ids must round-trip unchanged.
    """
    out: list[dict] = [{"role": "system", "content": system}]
    for m in messages:
        role = m.get("role")
        content = m.get("content")

        if isinstance(content, str):
            out.append({"role": role, "content": content})
            continue

        if role == "assistant":
            text_parts, tool_calls = [], []
            for b in content or []:
                if not isinstance(b, dict):
                    continue
                if b.get("type") == "text":
                    text_parts.append(str(b.get("text", "")))
                elif b.get("type") == "tool_use":
                    tool_calls.append({
                        "id": b["id"],
                        "type": "function",
                        "function": {"name": b["name"],
                                     "arguments": json.dumps(b.get("input") or {})},
                    })
            msg: dict = {"role": "assistant", "content": "\n".join(text_parts) or None}
            if tool_calls:
                msg["tool_calls"] = tool_calls
            out.append(msg)
            continue

        # role == "user" with a block list: tool results (and, defensively, text)
        for b in content or []:
            if not isinstance(b, dict):
                continue
            if b.get("type") == "tool_result":
                out.append({"role": "tool",
                            "tool_call_id": b.get("tool_use_id"),
                            "content": str(b.get("content", ""))})
            elif b.get("type") == "text":
                out.append({"role": "user", "content": str(b.get("text", ""))})
    return out


class AzureOpenAIEngine:
    name = "azure"

    def __init__(self, cfg):
        try:
            import openai
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise SystemExit(
                "The openai package is required for --provider azure.\n"
                "  pip install openai\n"
                "Or run the lab offline with --provider simulated."
            ) from exc
        self._openai = openai
        self.cfg = cfg

        endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
        if not endpoint:
            raise SystemExit(
                "AZURE_OPENAI_ENDPOINT is required for --provider azure, e.g.\n"
                "  export AZURE_OPENAI_ENDPOINT=https://<resource>.openai.azure.com"
            )
        api_key = os.environ.get("AZURE_OPENAI_API_KEY")
        ad_token = os.environ.get("AZURE_OPENAI_AD_TOKEN")
        if not api_key and not ad_token:
            raise SystemExit(
                "Set AZURE_OPENAI_API_KEY (or AZURE_OPENAI_AD_TOKEN) for "
                "--provider azure."
            )
        api_version = os.environ.get("AZURE_OPENAI_API_VERSION", DEFAULT_API_VERSION)

        self.deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT") or cfg.model
        self.client = openai.AzureOpenAI(
            azure_endpoint=endpoint,
            api_version=api_version,
            api_key=api_key,
            azure_ad_token=ad_token,
        )
        self._effort = _EFFORT.get(cfg.effort, "medium")
        self._use_effort = True
        self._use_temperature = True
        self._token_param = "max_completion_tokens"

    def complete(self, system: str, messages: list[dict], tools: list[dict],
                 hardened: bool) -> EngineReply:
        openai = self._openai
        kwargs = dict(
            model=self.deployment,
            messages=_to_openai_messages(system, messages),
            tools=_to_openai_tools(tools),
            tool_choice="auto",
        )
        try:
            response = self._create(kwargs)
        except openai.NotFoundError as exc:
            return EngineReply(
                text=f"[deployment {self.deployment!r} not found: {exc}]",
                note="api error — check AZURE_OPENAI_DEPLOYMENT / --model")
        except openai.BadRequestError as exc:
            # Azure returns the content filter as a 400 with a content_filter code.
            if _is_content_filter(exc):
                return EngineReply(
                    text="[Azure content filter declined this request]",
                    note="stop_reason=content_filter (Azure)")
            return EngineReply(text=f"[bad request: {exc}]", note="api error")
        except openai.RateLimitError:
            return EngineReply(text="[rate limited — retry in a moment]",
                               note="api rate limit")
        except openai.APIStatusError as exc:
            return EngineReply(text=f"[API error {exc.status_code}: {exc.message}]",
                               note="api error")
        except openai.APIConnectionError as exc:
            return EngineReply(text=f"[cannot reach Azure OpenAI: {exc}]",
                               note="api connection error")

        choice = response.choices[0]
        finish = choice.finish_reason
        if finish == "content_filter":
            return EngineReply(text="[Azure content filter stopped the response]",
                               note="stop_reason=content_filter (Azure)")

        msg = choice.message
        text = msg.content or ""
        calls = []
        for tc in (msg.tool_calls or []):
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            if not isinstance(args, dict):
                args = {}
            calls.append(ToolCall(name=tc.function.name, input=args, id=tc.id))

        return EngineReply(
            text=text.strip(),
            tool_calls=calls,
            note=f"{self.deployment} finish_reason={finish} "
                 f"effort={self._effort if self._use_effort else 'n/a'}")

    def _create(self, base_kwargs: dict):
        """Send the request, recovering from a deployment that rejects an
        optional parameter. A fixed temperature is dropped first (reasoning
        models allow only the default), then reasoning_effort, then the newer
        max_completion_tokens is swapped for max_tokens if unsupported. Each
        fallback flips a flag permanently, so the retry converges."""
        kwargs = dict(base_kwargs)
        kwargs[self._token_param] = MAX_TOKENS
        if self._use_effort:
            kwargs["reasoning_effort"] = self._effort
        if self._use_temperature and self.cfg.temperature is not None:
            kwargs["temperature"] = self.cfg.temperature
        try:
            return self.client.chat.completions.create(**kwargs)
        except self._openai.BadRequestError as exc:
            if _is_content_filter(exc):
                raise
            blob = str(exc).lower()
            retry = False
            if self._use_temperature and "temperature" in blob:
                self._use_temperature = False
                retry = True
            elif self._use_effort and "reasoning_effort" in blob:
                self._use_effort = False
                retry = True
            elif (self._token_param == "max_completion_tokens"
                    and "max_completion_tokens" in blob):
                self._token_param = "max_tokens"
                retry = True
            if retry:
                return self._create(base_kwargs)
            raise


def _is_content_filter(exc) -> bool:
    code = getattr(exc, "code", None)
    if code == "content_filter":
        return True
    return "content_filter" in str(exc).lower()
