---
id: data-exfiltration
title: Data exfiltration triage
category: data_exfiltration
attack_ids: [T1041, T1048]
---

## Observed indicators

- Large or sustained outbound transfers from a host that normally receives traffic, especially after a compromise indicator.
- Outbound data over an existing C2 channel or over protocols not used by the service (DNS with high-entropy labels, unusual ports).

## Required evidence

- Flow records with bytes sent, destination and the owning process identity.
- Sensitive file access or file integrity events on the same host before the transfer.
- Without byte counts or file access evidence, exfiltration remains a hypothesis.

## ATT&CK mapping

- T1041 when the data leaves over the same connection or channel as the suspected C2; T1048 when it leaves over a different protocol than the C2.

## Alternative explanations

- Backups, log shipping, software uploads, container image pushes, file synchronization.

## Investigation steps

- Identify the process, destination and time window; compare to normal outbound volume for the asset.
- Check which files the process opened or which sensitive paths changed.
- Correlate with earlier initial access or C2 evidence on the same Agent.

## Response options

- Contain the host (isolate keeps only the Manager channel) if exfiltration is ongoing and verified.
- Terminate the verified process; preserve evidence before cleanup.

## Execution prerequisites

- Explicit operator confirmation for isolation and termination.

## Operational risks

- Isolation interrupts all services on the host; data already transferred cannot be recalled.

## Rollback guidance

- Unisolate after the transfer path is removed; termination has no rollback.
