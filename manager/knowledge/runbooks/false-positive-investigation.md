---
id: false-positive-investigation
title: False-positive investigation
category: false_positive_investigation
attack_ids: []
---

## Observed indicators

- An alert or incident whose only support is a score, a User-Agent string, a single repeated socket observation or an uncorrelated event.
- Desktop or remote-service activity (IDE helpers, browsers, update agents) flagged by process or network rules.

## Required evidence

- Process identity with PID, executable and process_start_time; a repeated observation of the same socket must not be counted as new connections.
- Distinguish a newly opened socket from a re-observed one (observation_count versus new_connection_count).
- Deployment thresholds, monitor mode, whitelist entries and the response policy in effect when the alert fired.

## ATT&CK mapping

- Do not assign a technique when the evidence only shows a tool name or an anomaly score; mapping requires behavior evidence.

## Alternative explanations

- Administrative or maintenance work, scheduled jobs, configuration management, backups.
- Monitoring and health checks that are periodic by design.
- Authorized security testing.

## Investigation steps

- List each claim in the alert and the evidence ID that supports it; claims without evidence IDs are hypotheses.
- Check whether the process, user and destination are expected for this asset and time window.
- Compare with recent response outcomes for the same Agent (effective, ineffective, caused_side_effect, rolled_back_by_analyst).
- Record missing evidence explicitly instead of inferring it.

## Response options

- Mark the incident as false positive with a reason, add a narrowly scoped whitelist entry if justified, and keep monitoring.
- Do not dispatch containment or termination for an unverified alert.

## Execution prerequisites

- An analyst decision; incident resolution is separate from response actions.

## Operational risks

- Broad whitelist entries hide future true positives; scope them to executable path, user and destination.

## Rollback guidance

- Remove or narrow the whitelist entry and reopen the incident if new evidence appears.
