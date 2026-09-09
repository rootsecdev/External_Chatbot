---
title: INC-4417 postmortem — eu-west ingest outage (INTERNAL)
classification: internal
source: confluence://SRE/INC-4417
---
INC-4417: 6h14m ingest outage in eu-west on 2026-06-11 caused by an expired
client certificate on the ingest fleet, compounded by a missing alert on
certificate expiry. Customer impact: 341 tenants, of which 12 were Enterprise;
four filed SLA credit claims totalling $84,200. Contributing factor was a
deferred rotation task (SRE-1188). Legal advised against publishing per-tenant
impact numbers.
