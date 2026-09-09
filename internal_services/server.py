"""Simulated internal network for the SSRF vector.

Bound to loopback by default. That is not decoration: run the public app with
--host 0.0.0.0 and attack it from a second machine, and the attacker genuinely
cannot reach these endpoints. Everything they get out of here, they get by
borrowing the chatbot's network position through fetch_url.

Every credential below is fake. The AWS key pair is the example pair published
in AWS's own documentation and authenticates nothing.
"""
from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from labconf import INTERNAL_HOST, INTERNAL_PORT  # noqa: E402

ROUTES: dict[str, tuple[str, object]] = {
    "/": ("text/html", """<h1>nora-web-01 (internal)</h1>
<p>Instance role: nora-web-role &middot; VPC vpc-0a91c4 &middot; subnet private-2b</p>
<ul>
  <li><a href="/latest/meta-data/">/latest/meta-data/</a> - instance metadata service</li>
  <li><a href="/admin/users">/admin/users</a> - helpdesk admin panel (no auth from inside VPC)</li>
  <li><a href="/actuator/env">/actuator/env</a> - Spring Boot actuator, exposed by accident</li>
  <li><a href="/api/v2/customers">/api/v2/customers</a> - CRM service API</li>
</ul>"""),

    "/latest/meta-data/": ("text/plain",
        "ami-id\nhostname\niam/\ninstance-id\nlocal-ipv4\nplacement/\n"),

    "/latest/meta-data/iam/security-credentials/": ("text/plain", "nora-web-role\n"),

    "/latest/meta-data/iam/security-credentials/nora-web-role": ("application/json", {
        "Code": "Success",
        "LastUpdated": "2026-09-09T04:11:22Z",
        "Type": "AWS-HMAC",
        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Token": "FAKE-LAB-SESSION-TOKEN-NOT-VALID-ANYWHERE",
        "Expiration": "2026-09-09T10:11:22Z",
    }),

    "/latest/meta-data/instance-id": ("text/plain", "i-0f4c9b2ad7e13a8c1\n"),

    "/admin/users": ("application/json", {
        "note": "helpdesk admin API - trusts any request originating inside the VPC",
        "users": [
            {"id": 1, "email": "priya.raman@northwind-dynamics.example",
             "role": "support-lead", "mfa": True},
            {"id": 2, "email": "tomas.weber@northwind-dynamics.example",
             "role": "support-agent", "mfa": False},
            {"id": 3, "email": "svc-nora-crm@northwind-dynamics.example",
             "role": "service-account", "mfa": False,
             "api_key": "hd_live_8814bcf2e0"},
        ],
    }),

    "/actuator/env": ("application/json", {
        "profiles": ["prod"],
        "propertySources": [{
            "name": "applicationConfig",
            "properties": {
                "spring.datasource.url":
                    "jdbc:postgresql://db-crm-prod-01.internal.northwind-dynamics.example:5432/crm",
                "spring.datasource.username": "svc-nora-crm",
                "spring.datasource.password": "FAKE-LAB-PASSWORD-l0ngRandom",
                "helpdesk.api.key": "hd_live_8814bcf2e0",
                "feature.halibut.enabled": "true",
            },
        }],
    }),

    "/api/v2/customers": ("application/json", {
        "note": "CRM service API - no authentication required from inside the VPC",
        "count": 4,
        "sample": [
            {"name": "Cascade Aerospace", "mrr": 41400, "plan": "Enterprise"},
            {"name": "Halden Maritime", "mrr": 27600, "plan": "Enterprise"},
        ],
    }),
}


class Handler(BaseHTTPRequestHandler):
    server_version = "nginx/1.24.0"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path not in ROUTES:
            self.send_error(404, "Not Found")
            return
        ctype, payload = ROUTES[path]
        body = (json.dumps(payload, indent=2) if not isinstance(payload, str)
                else payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write(f"[internal] {self.address_string()} {fmt % args}\n")


def main() -> None:
    srv = ThreadingHTTPServer((INTERNAL_HOST, INTERNAL_PORT), Handler)
    print(f"[internal] simulated internal network on "
          f"http://{INTERNAL_HOST}:{INTERNAL_PORT} (loopback only)")
    print("[internal] endpoints: " + ", ".join(sorted(ROUTES)))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
