"""In-memory lab state: CMS comments, tickets, outbound mail, CRM, trace log.

Deliberately process-local and non-persistent — restarting the lab gives you a
clean slate between demo runs.
"""
from __future__ import annotations

import itertools
import threading
import time
from dataclasses import dataclass, field

_lock = threading.RLock()
_ids = itertools.count(1)


@dataclass
class Comment:
    slug: str
    author: str
    body: str
    id: int = field(default_factory=lambda: next(_ids))
    at: float = field(default_factory=time.time)


@dataclass
class Ticket:
    email: str
    subject: str
    body: str
    session: str
    id: int = field(default_factory=lambda: next(_ids))
    at: float = field(default_factory=time.time)


@dataclass
class Mail:
    to: str
    subject: str
    body: str
    session: str
    id: int = field(default_factory=lambda: next(_ids))
    at: float = field(default_factory=time.time)
    envelope_from: str = "support@northwind-dynamics.example"


COMMENTS: list[Comment] = []
TICKETS: list[Ticket] = []
OUTBOX: list[Mail] = []

# Fake CRM the public bot should never have been able to reach. Synthetic
# records; the .example domain is reserved for documentation use.
CRM: list[dict] = [
    {"name": "Cascade Aerospace", "contact": "j.okafor@cascade-aero.example",
     "plan": "Enterprise", "mrr": 41400, "seats": 450, "renewal": "2027-02-28",
     "notes": "HALIBUT design partner. Churn risk low."},
    {"name": "Halden Maritime", "contact": "erik.lund@halden-maritime.example",
     "plan": "Enterprise", "mrr": 27600, "seats": 300, "renewal": "2026-12-31",
     "notes": "Filed SLA credit claim for INC-4417 ($18,400)."},
    {"name": "Tessellate Labs", "contact": "billing@tessellate.example",
     "plan": "Pro", "mrr": 3870, "seats": 30, "renewal": "2026-10-15",
     "notes": "Card declined twice in August. Dunning stage 2."},
    {"name": "Vela Imaging", "contact": "ops@vela-imaging.example",
     "plan": "Starter", "mrr": 588, "seats": 12, "renewal": "2026-11-01",
     "notes": "Evaluating Meridian Telemetry as alternative."},
]

# Append-only demo trace: every tool call, retrieval and guard decision.
TRACE: list[dict] = []


def add_comment(slug: str, author: str, body: str) -> Comment:
    with _lock:
        c = Comment(slug=slug, author=author, body=body)
        COMMENTS.append(c)
        return c


def comments_for(slug: str) -> list[Comment]:
    with _lock:
        return [c for c in COMMENTS if c.slug == slug]


def add_ticket(email: str, subject: str, body: str, session: str) -> Ticket:
    with _lock:
        t = Ticket(email=email, subject=subject, body=body, session=session)
        TICKETS.append(t)
        return t


def tickets_for_session(session: str) -> list[Ticket]:
    with _lock:
        return [t for t in TICKETS if t.session == session]


def add_mail(to: str, subject: str, body: str, session: str) -> Mail:
    with _lock:
        m = Mail(to=to, subject=subject, body=body, session=session)
        OUTBOX.append(m)
        return m


def trace(session: str, kind: str, detail: str, **extra) -> dict:
    with _lock:
        entry = {"session": session, "kind": kind, "detail": detail,
                 "at": time.time(), **extra}
        TRACE.append(entry)
        return entry


def trace_for(session: str) -> list[dict]:
    with _lock:
        return [t for t in TRACE if t["session"] == session]


def reset() -> None:
    """Clear demo state between runs (used by the exploit runner and tests)."""
    with _lock:
        COMMENTS.clear()
        TICKETS.clear()
        OUTBOX.clear()
        TRACE.clear()
