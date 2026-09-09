"""Public-facing web app: the marketing site, the chat widget, and the demo API.

Standard library only. The API surface is deliberately small so the exploit
runner can drive the identical code path a browser drives:

    POST /api/chat     {session, message} -> {reply, findings, withheld, ...}
    GET  /api/trace    ?session=          -> guard/tool/retrieval trace
    GET  /api/state                       -> tickets, outbound mail, comments
    POST /api/mode     {mode?}            -> switch or toggle vulnerable/hardened
    POST /api/comment  {slug, author, body} -> plant page content
    POST /api/reset                       -> clear demo state
"""
from __future__ import annotations

import json
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from labconf import (CONFIG, MODE_HARDENED, MODE_VULNERABLE, PUBLIC_HOST,
                     PUBLIC_PORT)
from chatbot import state, web
from chatbot.agent import Agent
from chatbot.tools import SITE_ROOT

AGENT: Agent | None = None
MAX_BODY = 64 * 1024


def _load_page(slug: str) -> tuple[str, str, bool] | None:
    path = SITE_ROOT / f"{slug}.md"
    if not path.is_file() or path.parent != SITE_ROOT:
        return None
    raw = path.read_text()
    meta: dict[str, str] = {}
    body = raw
    if raw.startswith("---"):
        _, front, body = raw.split("---", 2)
        for line in front.strip().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                meta[k.strip()] = v.strip()
    return (meta.get("title", slug), body.strip(),
            meta.get("comments", "true").lower() != "false")


class Handler(BaseHTTPRequestHandler):
    server_version = "nginx/1.24.0"
    sys_version = ""

    # -- helpers ---------------------------------------------------------
    def _send(self, code: int, ctype: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, payload, code: int = 200) -> None:
        self._send(code, "application/json; charset=utf-8", web.json_response(payload))

    def _html(self, markup: str, code: int = 200) -> None:
        self._send(code, "text/html; charset=utf-8", markup.encode())

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            return {}
        raw = self.rfile.read(length).decode("utf-8", "replace")
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        if ctype == "application/json":
            try:
                parsed = json.loads(raw)
                return parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                return {}
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

    # -- routing ---------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        url = urllib.parse.urlparse(self.path)
        path = url.path.rstrip("/") or "/"
        query = urllib.parse.parse_qs(url.query)

        if path == "/api/trace":
            session = (query.get("session") or ["demo"])[0]
            return self._json({"session": session, "trace": state.trace_for(session)})

        if path == "/api/state":
            return self._json({
                "mode": CONFIG.mode,
                "provider": CONFIG.provider,
                "tickets": [vars(t) for t in state.TICKETS],
                "outbox": [vars(m) for m in state.OUTBOX],
                "comments": [vars(c) for c in state.COMMENTS],
            })

        slug = "home" if path == "/" else path.lstrip("/")
        loaded = _load_page(slug)
        if loaded is None:
            return self._html("<h1>404</h1><p><a href='/'>home</a></p>", 404)
        title, body, allow_comments = loaded
        return self._html(web.page(
            slug=slug, title=title, body=body, comments=state.comments_for(slug),
            mode=CONFIG.mode, provider=CONFIG.provider, model=CONFIG.model,
            allow_comments=allow_comments))

    def do_POST(self) -> None:  # noqa: N802
        url = urllib.parse.urlparse(self.path)
        path = url.path.rstrip("/") or "/"
        data = self._body()

        if path == "/api/chat":
            message = str(data.get("message", "")).strip()
            session = str(data.get("session", "demo"))
            if not message:
                return self._json({"error": "message is required"}, 400)
            assert AGENT is not None
            return self._json(AGENT.respond(session, message))

        if path == "/api/mode":
            requested = str(data.get("mode", "")).strip().lower()
            if requested in (MODE_VULNERABLE, MODE_HARDENED):
                CONFIG.mode = requested
            else:
                CONFIG.mode = (MODE_HARDENED if CONFIG.mode == MODE_VULNERABLE
                               else MODE_VULNERABLE)
            print(f"[lab] mode -> {CONFIG.mode}", file=sys.stderr)
            return self._json({"mode": CONFIG.mode})

        if path == "/api/comment":
            slug = str(data.get("slug", "")).strip()
            if not _load_page(slug):
                return self._json({"error": f"no such page {slug!r}"}, 404)
            c = state.add_comment(slug, str(data.get("author", "visitor")) or "visitor",
                                  str(data.get("body", "")))
            return self._json({"id": c.id, "slug": c.slug})

        if path == "/api/reset":
            state.reset()
            if AGENT is not None:
                AGENT._history.clear()
            return self._json({"reset": True})

        if path.startswith("/comment/"):
            slug = path[len("/comment/"):]
            if _load_page(slug):
                state.add_comment(slug, str(data.get("author", "visitor")) or "visitor",
                                  str(data.get("body", "")))
            self.send_response(303)
            self.send_header("Location", f"/{slug}")
            self.end_headers()
            return

        return self._json({"error": "not found"}, 404)

    def log_message(self, fmt: str, *args) -> None:
        if "/api/trace" in self.path or "/api/state" in self.path:
            return  # the UI polls these; keep the console readable
        sys.stderr.write(f"[public] {self.address_string()} {fmt % args}\n")


def serve(host: str = PUBLIC_HOST, port: int = PUBLIC_PORT) -> None:
    global AGENT
    AGENT = Agent(CONFIG)
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"[lab] {CONFIG.mode.upper()} mode, engine={CONFIG.provider}"
          + (f" ({CONFIG.model})" if CONFIG.provider == "anthropic" else ""))
    print(f"[lab] public site  http://{host}:{port}/")
    print("[lab] toggle modes from the header button or POST /api/mode")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[lab] shutting down")
        srv.shutdown()
