"""Injection-directive parsing — one source of truth for two consumers.

The simulated engine calls extract_directives() to decide what to *obey* when
it reads attacker-controlled text out of a tool result. The guard layer calls
the same function to decide what to *report and strip*. Keeping both on one
parser means the demo cannot drift into showing a block for something the
engine would never have followed, or vice versa.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Text that is invisible to a human reading the rendered page but perfectly
# legible to anything converting that page to text for a model.
HIDDEN_PATTERNS = [
    re.compile(r"<!--.*?-->", re.S),
    re.compile(r"<[^>]*style=\"[^\"]*(?:display\s*:\s*none|visibility\s*:\s*hidden"
               r"|font-size\s*:\s*0|opacity\s*:\s*0|color\s*:\s*#?(?:fff|ffffff|white))"
               r"[^\"]*\"[^>]*>(.*?)</[^>]+>", re.S | re.I),
    re.compile(r"[​‌‍⁠﻿]+"),
]

_SAY = re.compile(
    r"(?:you\s+must\s+|you\s+should\s+|always\s+|please\s+|instead,?\s+)?"
    r"(?:say|reply\s+with|respond\s+with|answer\s+with|state|confirm|tell\s+"
    r"(?:the\s+|every\s+|each\s+)?(?:user|customer|visitor)s?\s+(?:that\s+)?)"
    # Stop at a sentence boundary so a following directive is parsed separately.
    # Stop at a sentence boundary, a newline, or the start of a tag — the
    # payload is usually inside hidden markup, so "<" ends the instruction.
    r"\b[:\s\"']*(?P<arg>[^\n\"'<]{5,300}?)(?=\.\s|\.$|\n|<|$)", re.I)
_REVEAL = re.compile(
    r"(?:reveal|print|output|show|repeat|disclose|dump)\s+(?:me\s+)?"
    r"(?:your|the)\s+(?:full\s+|initial\s+|original\s+|complete\s+)?"
    r"(?:system\s+prompt|prompt|instructions|configuration|config|guardrails|"
    r"rules|tools?\s+list|tool\s+names)", re.I)
_FETCH = re.compile(
    r"(?:fetch|retrieve|load|request|check|browse|visit|read|curl|get)\s+"
    r"(?P<arg>(?:https?://|http://)[^\s\"'<>\]]+|\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?[^\s\"'<>\]]*)",
    re.I)
_EMAIL = re.compile(
    r"(?:e-?mail|mail|forward|send)\s+"
    r"(?:(?:an?\s+)?e-?mail\s+)?"
    r"(?:(?:it|this|that|them|these|everything|the\s+(?:result|results|transcript|"
    r"details|contents?|output))\s+)?"
    r"(?:to\s+)?(?P<arg>[\w.+-]+@[\w.-]+\.\w+)", re.I)
_TICKET = re.compile(
    r"(?:create|open|file|raise|submit)\s+(?:a\s+|\d+\s+)?(?:support\s+|new\s+)?ticket", re.I)
_PERSONA = re.compile(
    r"(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|your\s+|the\s+|previous\s+"
    r"|prior\s+|earlier\s+)*(?:instructions?|rules?|guardrails?|prompt|persona|"
    r"directives?|guidelines?)|you\s+are\s+now\s+(?:a\s+|an\s+)?\w+", re.I)


@dataclass
class Directive:
    kind: str          # say | reveal_prompt | fetch | email | ticket | persona
    arg: str
    raw: str

    def describe(self) -> str:
        return f"{self.kind}({self.arg[:80]})" if self.arg else self.kind


def strip_hidden(text: str) -> tuple[str, list[str]]:
    """Remove human-invisible content, returning (clean_text, removed_chunks)."""
    removed: list[str] = []
    out = text
    for pat in HIDDEN_PATTERNS:
        def _sub(m: re.Match) -> str:
            chunk = (m.group(1) if m.groups() else m.group(0)).strip()
            if chunk:
                removed.append(chunk)
            return " "
        out = pat.sub(_sub, out)
    return out, removed


def extract_directives(text: str, limit: int = 4) -> list[Directive]:
    """Find instruction-shaped text. Order matters: the more specific action
    verbs are matched before the generic 'say X' catch-all."""
    found: list[Directive] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, arg: str, raw: str) -> None:
        key = (kind, arg.strip().lower())
        if key not in seen:
            seen.add(key)
            found.append(Directive(kind, arg.strip(), raw.strip()))

    for m in _REVEAL.finditer(text):
        add("reveal_prompt", "", m.group(0))
    for m in _FETCH.finditer(text):
        add("fetch", m.group("arg").rstrip(".,);"), m.group(0))
    for m in _EMAIL.finditer(text):
        add("email", m.group("arg"), m.group(0))
    for m in _TICKET.finditer(text):
        add("ticket", "", m.group(0))
    for m in _PERSONA.finditer(text):
        add("persona", "", m.group(0))
    for m in _SAY.finditer(text):
        add("say", m.group("arg").rstrip(".,;"), m.group(0))
    return found[:limit]
