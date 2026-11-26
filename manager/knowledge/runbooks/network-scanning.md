---
id: network-scanning
title: Network service scanning triage
category: network_scanning
attack_ids: [T1046, T1595, T1595.002]
---

## Observed indicators

- network_service_scanning: one remote source reached at least 8 distinct local TCP ports on the same endpoint within 60 seconds, observed as inbound sockets in ESTABLISHED or SYN-RECV state.
- HTTP requests from scanner User-Agents (automated_http_activity) against the same endpoint.

## Required evidence

- Inbound socket evidence with direction, status, observation time and socket inode; duplicated observations of the same socket are counted once.
- The source and target addresses and the list of ports.

## ATT&CK mapping

- T1595 / T1595.002 for scanning from outside the organization; T1046 when the scan originates from an internal host as discovery.

## Alternative explanations

- Authorized vulnerability scanning or asset inventory.
- Load balancer or monitoring health checks across several ports.
- Internet background scanning against an exposed host, which is common and usually not targeted.

## Investigation steps

- Check whether the source is internal or external, and whether it is a known scanner of the organization.
- Look for follow-up activity from the same source: authentication attempts, exploit requests, successful connections to services.
- If the scanning source is one of your own endpoints, investigate that endpoint for compromise.

## Response options

- Monitor and correlate; scanning alone rarely justifies containment.
- For the lab Flask application, traffic intervention (block / rate limit) is limited to disposable documentation-range peers.

## Execution prerequisites

- Firewall changes on real endpoints go through the UFW transaction workflow with commit or rollback, not through incident response assist.

## Operational risks

- Blocking scanners by IP is easily evaded and may block shared addresses.

## Rollback guidance

- UFW transactions not committed within 60 seconds roll back automatically.
