"""HTML for the public site and the demo console.

Rendered with plain string templates so the lab keeps zero third-party
dependencies. Comment bodies are written into the page unescaped in vulnerable
mode — that is the vulnerability being demonstrated, and it is what makes the
injected instructions invisible to a human looking at the page.
"""
from __future__ import annotations

import html
import json

from labconf import BOT_NAME, COMPANY, MODE_HARDENED

CSS = """
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--txt:#e6edf3;--dim:#8b949e;
--accent:#58a6ff;--bad:#f85149;--good:#3fb950;--warn:#d29922}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);
font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent)}
header{display:flex;align-items:center;gap:14px;padding:10px 18px;
background:var(--panel);border-bottom:1px solid var(--line);flex-wrap:wrap}
header .brand{font-weight:600;font-size:15px}
header nav{display:flex;gap:12px;font-size:13px;margin-left:6px}
header .spacer{flex:1}
.badge{font:600 11px/1 ui-monospace,monospace;padding:5px 9px;border-radius:5px;
border:1px solid var(--line);letter-spacing:.04em;text-transform:uppercase}
.badge.vuln{background:#3d1418;border-color:var(--bad);color:#ff9d96}
.badge.hard{background:#0f2f1a;border-color:var(--good);color:#7ee2a0}
button{font:inherit;cursor:pointer;background:#21262d;color:var(--txt);
border:1px solid var(--line);border-radius:6px;padding:6px 11px}
button:hover{border-color:var(--accent)}
.wrap{display:grid;grid-template-columns:1fr 420px;gap:16px;padding:16px;
align-items:start;max-width:1500px;margin:0 auto}
.card{background:var(--panel);border:1px solid var(--line);border-radius:9px;
padding:15px 17px;margin-bottom:16px}
.card h2{margin:0 0 10px;font-size:14px;letter-spacing:.03em;color:var(--dim);
text-transform:uppercase}
.page-body{white-space:pre-wrap}
.comment{border-top:1px solid var(--line);padding:9px 0}
.comment .who{color:var(--dim);font-size:12px}
form.cmt{display:grid;gap:7px;margin-top:11px}
textarea,input[type=text]{background:#0d1117;color:var(--txt);
border:1px solid var(--line);border-radius:6px;padding:8px;font:inherit;width:100%}
textarea{min-height:66px;resize:vertical}
#log{height:340px;overflow-y:auto;display:flex;flex-direction:column;gap:9px}
.msg{padding:9px 11px;border-radius:8px;max-width:92%;white-space:pre-wrap;
word-break:break-word;font-size:13px}
.msg.u{background:#1f6feb33;border:1px solid #1f6feb66;align-self:flex-end}
.msg.a{background:#0d1117;border:1px solid var(--line);align-self:flex-start}
.msg.sys{background:#3d141880;border:1px solid var(--bad);align-self:center;
font-size:12px;color:#ff9d96}
.composer{display:flex;gap:8px;margin-top:11px}
.composer input{flex:1}
#trace{max-height:300px;overflow-y:auto;font:12px/1.5 ui-monospace,monospace}
.tr{padding:4px 0;border-bottom:1px solid #21262d;display:flex;gap:8px}
.tr .k{flex:0 0 118px;color:var(--dim)}
.tr.leak .d,.tr.injection-found .d{color:var(--bad)}
.tr.guard-block .d{color:var(--good)}
.tr.guard-would-block .d{color:var(--warn)}
.tr.retrieval .d,.tr.egress .d{color:var(--accent)}
.hint{color:var(--dim);font-size:12px;margin:6px 0 0}
.impact{font:12px/1.6 ui-monospace,monospace;max-height:190px;overflow-y:auto}
.impact .row{padding:3px 0;border-bottom:1px solid #21262d}
ul.vec{margin:6px 0 0 18px;padding:0;font-size:13px}
ul.vec li{margin:3px 0}
code{background:#0d1117;border:1px solid var(--line);border-radius:4px;
padding:1px 5px;font-size:12px}
@media(max-width:1100px){.wrap{grid-template-columns:1fr}}
"""

JS = """
const SESSION = 'web-' + Math.random().toString(36).slice(2, 9);
const $ = id => document.getElementById(id);

function add(cls, text) {
  const d = document.createElement('div');
  d.className = 'msg ' + cls;
  d.textContent = text;
  $('log').appendChild(d);
  $('log').scrollTop = $('log').scrollHeight;
}

async function send() {
  const box = $('q');
  const text = box.value.trim();
  if (!text) return;
  box.value = '';
  add('u', text);
  add('a', '...');
  const placeholder = $('log').lastChild;
  try {
    const r = await fetch('/api/chat', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({session: SESSION, message: text})
    });
    const j = await r.json();
    placeholder.textContent = j.reply;
    if (j.findings && j.findings.length) {
      add('sys', (j.withheld ? 'BLOCKED by response inspection — ' :
        'POLICY VIOLATION (not blocked in vulnerable mode) — ') +
        j.findings.join('; '));
    }
  } catch (e) {
    placeholder.textContent = '[transport error: ' + e + ']';
  }
  refresh();
}

async function refresh() {
  const t = await (await fetch('/api/trace?session=' + SESSION)).json();
  $('trace').innerHTML = t.trace.map(e =>
    '<div class="tr ' + e.kind + (String(e.detail).startsWith('LEAK') ? ' leak' : '') +
    '"><span class="k">' + e.kind + '</span><span class="d">' +
    esc(e.detail) + (e.control ? ' <em style="color:#8b949e">[' + esc(e.control) + ']</em>' : '') +
    '</span></div>').reverse().join('') || '<div class="hint">nothing yet</div>';

  const s = await (await fetch('/api/state')).json();
  $('impact').innerHTML =
    row('tickets', s.tickets.map(x => '#' + x.id + ' ' + x.email + ' — ' + x.subject)) +
    row('outbound mail', s.outbox.map(x => '#' + x.id + ' to ' + x.to + ' — ' + x.subject)) +
    row('page comments', s.comments.map(x => x.slug + ' / ' + x.author));
}

function row(label, items) {
  if (!items.length) return '<div class="row" style="color:#8b949e">' + label + ': none</div>';
  return '<div class="row"><b>' + label + ' (' + items.length + ')</b><br>' +
    items.map(esc).join('<br>') + '</div>';
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
}

async function toggleMode() {
  const r = await fetch('/api/mode', {method: 'POST'});
  const j = await r.json();
  location.reload();
}

async function resetLab() {
  await fetch('/api/reset', {method: 'POST'});
  $('log').innerHTML = '';
  refresh();
}

window.addEventListener('DOMContentLoaded', () => {
  $('q').addEventListener('keydown', e => { if (e.key === 'Enter') send(); });
  $('send').addEventListener('click', send);
  $('mode').addEventListener('click', toggleMode);
  $('reset').addEventListener('click', resetLab);
  refresh();
  setInterval(refresh, 4000);
});
"""

NAV = [("home", "Home"), ("pricing", "Pricing"),
       ("orbit-quickstart", "Docs"), ("blog-why-retention-matters", "Blog")]


def _header(mode: str, provider: str, model: str) -> str:
    hardened = mode == MODE_HARDENED
    cls = "hard" if hardened else "vuln"
    nav = "".join(f'<a href="/{slug}">{label}</a>' for slug, label in NAV)
    engine = f"{provider}" + (f" · {model}" if provider == "anthropic" else "")
    return f"""<header>
  <span class="brand">{COMPANY}</span>
  <nav>{nav}</nav>
  <span class="spacer"></span>
  <span class="badge" style="background:#0d1117">engine: {html.escape(engine)}</span>
  <button id="mode" title="Toggle vulnerable / hardened">
    <span class="badge {cls}">{html.escape(mode)}</span>
  </button>
  <button id="reset">reset lab</button>
</header>"""


def _chat_panel(mode: str) -> str:
    hardened = mode == MODE_HARDENED
    stance = ("Guards are enforced. The same attacks should now fail, and the "
              "trace shows which control stopped each one."
              if hardened else
              "No guards are enforced. The trace shows, in amber, each control "
              "that would have stopped the attack.")
    return f"""<div class="card">
  <h2>{html.escape(BOT_NAME)} — support assistant</h2>
  <div id="log"></div>
  <div class="composer">
    <input type="text" id="q" placeholder="Ask {html.escape(BOT_NAME)} something…"
           autocomplete="off">
    <button id="send">send</button>
  </div>
  <p class="hint">{stance}</p>
</div>
<div class="card">
  <h2>Trace — tool calls, retrieval, guard decisions</h2>
  <div id="trace"></div>
</div>
<div class="card">
  <h2>Side effects the bot caused</h2>
  <div class="impact" id="impact"></div>
</div>"""


def page(slug: str, title: str, body: str, comments: list, mode: str,
         provider: str, model: str, allow_comments: bool) -> str:
    hardened = mode == MODE_HARDENED
    # Vulnerable mode renders comment bodies as raw HTML. That is exactly how a
    # hidden <div> ends up invisible on the page and fully legible to the bot.
    rendered = []
    for c in comments:
        body_html = html.escape(c.body) if hardened else c.body
        rendered.append(f'<div class="comment"><div class="who">'
                        f'{html.escape(c.author)}</div>{body_html}</div>')
    comment_block = ""
    if allow_comments:
        comment_block = f"""<div class="card">
  <h2>Comments ({len(comments)})</h2>
  {"".join(rendered) or '<p class="hint">No comments yet.</p>'}
  <form class="cmt" method="post" action="/comment/{html.escape(slug)}">
    <input type="text" name="author" placeholder="Your name" value="visitor">
    <textarea name="body" placeholder="Leave a comment…"></textarea>
    <button type="submit">post comment</button>
  </form>
  <p class="hint">Unauthenticated, unmoderated, and rendered
  {"escaped" if hardened else "as raw HTML"} into the page the bot reads.</p>
</div>"""

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title><style>{CSS}</style></head><body>
{_header(mode, provider, model)}
<div class="wrap">
  <div>
    <div class="card">
      <h2>{html.escape(title)}</h2>
      <div class="page-body">{html.escape(body)}</div>
    </div>
    {comment_block}
  </div>
  <div>{_chat_panel(mode)}</div>
</div>
<script>{JS}</script></body></html>"""


def json_response(payload) -> bytes:
    return json.dumps(payload, default=str).encode()
