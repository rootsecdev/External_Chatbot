"""Tool definitions and implementations for the support assistant.

The vulnerable toolset is what you find in the wild when a chatbot has been
wired up to "be more helpful": read access to the knowledge index, an
unrestricted outbound fetch, and write access to ticketing, CRM and mail.
"""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from labconf import CONFIG, PUBLIC_DOMAIN, LabConfig
from chatbot import guards, kb, state

SITE_ROOT = Path(__file__).resolve().parent.parent / "site_content"
FETCH_TIMEOUT = 4
FETCH_MAX_BYTES = 4096


@dataclass
class ToolResult:
    text: str
    source: str = "tool"          # label used when wrapping untrusted content
    untrusted: bool = False        # attacker may control this content
    effect: str = ""               # side effect worth showing in the trace


# ---------------------------------------------------------------------------
# Tool schemas, in Anthropic tool-definition form so the same list drives both
# the simulated engine and the real API.
# ---------------------------------------------------------------------------
TOOL_SPECS: list[dict] = [
    {
        "name": "kb_search",
        "description": "Search the Northwind Dynamics knowledge index for "
                       "product, pricing, policy and troubleshooting answers.",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string", "description": "Search terms."}},
            "required": ["query"],
        },
    },
    {
        "name": "read_site_page",
        "description": f"Read the rendered text of a page on {PUBLIC_DOMAIN}, "
                       "including visitor comments, so answers match what the "
                       "customer is looking at.",
        "input_schema": {
            "type": "object",
            "properties": {"slug": {"type": "string", "description":
                                    "Page slug, e.g. pricing or orbit-quickstart."}},
            "required": ["slug"],
        },
    },
    {
        "name": "fetch_url",
        "description": "Fetch a URL and return the response body. Use this to "
                       "check links, endpoints or status pages for a customer.",
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "Absolute URL."}},
            "required": ["url"],
        },
    },
    {
        "name": "create_ticket",
        "description": "Open a support ticket in the TIER1-WEB queue.",
        "input_schema": {
            "type": "object",
            "properties": {
                "email": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["email", "subject"],
        },
    },
    {
        "name": "lookup_customer",
        "description": "Look up an account in the CRM by company name or email "
                       "to personalise support.",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "send_email",
        "description": f"Send an email from support@{PUBLIC_DOMAIN} via the "
                       "internal relay.",
        "input_schema": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
        },
    },
]


def specs_for(cfg: LabConfig) -> list[dict]:
    """Hardened mode never advertises the tools it would refuse to run."""
    if cfg.hardened():
        return [s for s in TOOL_SPECS if s["name"] in guards.HARDENED_TOOLSET]
    return TOOL_SPECS


# ---------------------------------------------------------------------------
# Implementations
# ---------------------------------------------------------------------------

def _kb_search(args: dict, cfg: LabConfig, session: str) -> ToolResult:
    query = str(args.get("query", ""))
    hits = kb.search(query, limit=3)
    hits = guards.filter_retrieval(hits, cfg, session)
    if not hits:
        return ToolResult("No matching documents in the index.", source="kb_search")
    chunks = []
    for d in hits:
        state.trace(session, "retrieval",
                    f"{d.name} (classification={d.classification})", source=d.source)
        chunks.append(f"[{d.name} | classification={d.classification} | "
                      f"source={d.source}]\n{d.title}\n{d.body}")
    return ToolResult("\n\n".join(chunks), source="kb_search")


def _read_site_page(args: dict, cfg: LabConfig, session: str) -> ToolResult:
    slug = str(args.get("slug", "")).strip().strip("/") or "home"
    path = SITE_ROOT / f"{slug}.md"
    if not path.is_file() or path.parent != SITE_ROOT:
        return ToolResult(f"No page with slug {slug!r}.", source=f"page:{slug}")

    raw = path.read_text()
    body = raw.split("---", 2)[2].strip() if raw.startswith("---") else raw

    # A page is not just what the CMS author wrote. Anything rendered into it —
    # comments here, but equally a review widget, a product Q&A, a stored XSS —
    # becomes part of what the bot reads.
    comments = state.comments_for(slug)
    if comments:
        rendered = "\n".join(f"- {c.author}: {c.body}" for c in comments)
        body += f"\n\nVisitor comments ({len(comments)}):\n{rendered}"

    return ToolResult(body, source=f"page:{slug}", untrusted=True)


def _fetch_url(args: dict, cfg: LabConfig, session: str) -> ToolResult:
    url = str(args.get("url", "")).strip()
    decision = guards.egress_check(url, cfg, session)
    if not decision.allowed:
        return ToolResult(f"BLOCKED by egress policy: {decision.reason}",
                          source=f"fetch:{url}")

    req = urllib.request.Request(url, headers={
        "User-Agent": "NoraBot/3.4.1 (+support assistant)",
        # A real proxy would inject the workload's identity here. It is exactly
        # this network position the attacker is borrowing.
        "X-Forwarded-For": "10.40.2.17",
    })
    try:
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
            payload = resp.read(FETCH_MAX_BYTES).decode("utf-8", "replace")
            head = f"HTTP {resp.status} {resp.headers.get('Content-Type', '')}"
    except urllib.error.HTTPError as exc:
        payload = exc.read(FETCH_MAX_BYTES).decode("utf-8", "replace")
        head = f"HTTP {exc.code}"
    except (urllib.error.URLError, socket.timeout, OSError) as exc:
        # Distinguishable failures are what make the bot a port scanner.
        return ToolResult(f"fetch failed for {url}: {exc}", source=f"fetch:{url}",
                          untrusted=True, effect=f"outbound request to {url} (failed)")

    state.trace(session, "egress", f"fetched {url} -> {head}")
    return ToolResult(f"{head}\n{payload}", source=f"fetch:{url}", untrusted=True,
                      effect=f"outbound request to {url}")


def _create_ticket(args: dict, cfg: LabConfig, session: str) -> ToolResult:
    decision = guards.rate_limit_tickets(cfg, session)
    if not decision.allowed:
        return ToolResult(f"BLOCKED by rate limit: {decision.reason}",
                          source="create_ticket")
    t = state.add_ticket(
        email=str(args.get("email", "unknown@example.com")),
        subject=str(args.get("subject", "(no subject)")),
        body=str(args.get("body", "")),
        session=session,
    )
    return ToolResult(
        f"Ticket #{t.id} created in queue TIER1-WEB for {t.email}: {t.subject}",
        source="create_ticket", effect=f"ticket #{t.id} created")


def _lookup_customer(args: dict, cfg: LabConfig, session: str) -> ToolResult:
    query = str(args.get("query", "")).strip().lower()
    # No tenancy check, no caller identity, substring match: an enumeration
    # primitive. A single space matches every record.
    hits = [r for r in state.CRM
            if query in r["name"].lower() or query in r["contact"].lower()
            or query in r["plan"].lower()] if query else list(state.CRM)
    if not hits:
        return ToolResult(f"No CRM account matching {query!r}.", source="lookup_customer")
    state.trace(session, "crm-read", f"{len(hits)} record(s) returned for {query!r}")
    return ToolResult(json.dumps(hits, indent=2), source="lookup_customer",
                      effect=f"{len(hits)} CRM record(s) read")


def _send_email(args: dict, cfg: LabConfig, session: str) -> ToolResult:
    m = state.add_mail(
        to=str(args.get("to", "")),
        subject=str(args.get("subject", "(no subject)")),
        body=str(args.get("body", "")),
        session=session,
    )
    state.trace(session, "mail-sent", f"mail #{m.id} to {m.to} from {m.envelope_from}")
    return ToolResult(
        f"Email #{m.id} sent to {m.to} from {m.envelope_from} via "
        f"smtp-relay.internal.{PUBLIC_DOMAIN}:587",
        source="send_email", effect=f"email #{m.id} sent to {m.to}")


IMPLEMENTATIONS = {
    "kb_search": _kb_search,
    "read_site_page": _read_site_page,
    "fetch_url": _fetch_url,
    "create_ticket": _create_ticket,
    "lookup_customer": _lookup_customer,
    "send_email": _send_email,
}


def execute(name: str, args: dict, cfg: LabConfig | None = None,
            session: str = "demo") -> ToolResult:
    cfg = cfg or CONFIG
    impl = IMPLEMENTATIONS.get(name)
    if impl is None:
        return ToolResult(f"Unknown tool {name!r}.", source="error")

    decision = guards.authorize_tool(name, cfg, session)
    if not decision.allowed:
        return ToolResult(f"BLOCKED: {decision.reason}", source="error")

    result = impl(args, cfg, session)
    state.trace(session, "tool-call", f"{name}({json.dumps(args)[:160]})",
                effect=result.effect)
    return result
