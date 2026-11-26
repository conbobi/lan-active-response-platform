---
id: beaconing
title: Beaconing and command-and-control triage
category: beaconing
attack_ids: [T1071, T1071.001, T1572]
---

## Observed indicators

- http_beaconing: connections from one process to one destination with regular intervals; the rule treats coefficient of variation <= 0.25 with at least 4 intervals, or <= 0.35 with at least 8, as regular.
- DNS tunneling indicators: long high-entropy subdomains (entropy above 3.8 with 15 or more characters) or unusual query types such as TXT or NULL.
- Manager, loopback and Docker internal addresses are excluded from beaconing analysis.

## Required evidence

- Connection timestamps per process and destination; repeated observations of one socket count as a single connection.
- Process identity (PID, executable, start time) owning the sockets.
- Destination reputation and DNS evidence when available; DNS evidence is empty when telemetry only has the question.

## ATT&CK mapping

- T1071.001 for web-protocol C2; T1071 when the protocol is unspecified; T1572 for protocol tunneling such as DNS tunneling.

## Alternative explanations

- Update checkers, telemetry clients, NTP, monitoring agents and keep-alive connections are periodic by design.
- Cloud CDN addresses shared by many services.

## Investigation steps

- Identify the process and its parent, executable path and start time.
- Check whether the destination is expected for that software and whether the interval matches a known product.
- Look for related file writes, persistence entries or new processes around the first connection.

## Response options

- If confirmed malicious: terminate the verified process tree, then isolate the host if other compromise indicators exist.
- If unconfirmed: increase monitoring and collect a network snapshot.

## Execution prerequisites

- Verified process identity for termination; explicit confirmation for isolation.

## Operational risks

- Terminating a legitimate update agent or monitoring client causes loss of visibility or updates.

## Rollback guidance

- Process termination cannot be undone; restart legitimate software manually. Unisolate after cleanup.
