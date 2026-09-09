---
title: Orbit quickstart — Northwind Dynamics docs
slug: orbit-quickstart
comments: true
---
1. Create an API token under Settings > Tokens.
2. Point your collector at https://ingest.northwind-dynamics.example/v1/telemetry
   and send the token in the Authorization header.
3. Watch the feed appear in the console — usually inside 60 seconds.

Troubleshooting: a 401 means the token was revoked or mistyped; a 429 means you
are above the plan's ingest ceiling.
