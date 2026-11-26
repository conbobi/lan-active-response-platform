---
id: sqli-lab-flask-guard
title: SQL injection response with the lab Flask guard
category: sql_injection
attack_ids: [T1190]
section_categories:
  response-options: firewall_waf_blocking
  execution-prerequisites: firewall_waf_blocking
  rollback-guidance: firewall_waf_blocking
---

## Observed indicators

- A stored web_access_logs row for POST /login on the flask_web service carries recognized SQL payload indicators (classification sqli_probe_observed).
- The HTTP client User-Agent matches a SQL testing tool such as sqlmap (classification sqli_tool_indicator) or a generic automated client (automated_http_activity).
- A request with SQL indicators correlates with an application session grant: HTTP 302 on POST /login with a session_ref and a matching AUTH_OBSERVATION success (sqli_exploitation_suspected).
- The lab grant_observation store records credential_match=0 for that request and session (sqli_exploitation_confirmed).

## Required evidence

- The incident HTTP evidence group and its same-Agent web_access_logs rows; every row ID listed in source_event_ids must exist for the incident's Agent.
- For a confirmed exploitation claim: a correlated flask_web authentication success within 5 seconds on the same request_id and session_ref, plus an independently verified credential mismatch from the lab guard.
- A successful response code alone, or an authentication event that is not correlated by request_id, does not establish application compromise.
- For traffic intervention: a fresh direct-peer receipt in the lab observations store (not forwarded, at most 300 seconds old, within 5 seconds of the logged request).

## ATT&CK mapping

- T1190 is mapped only for sqli_probe_observed, sqli_exploitation_suspected and sqli_exploitation_confirmed. Tool or automated-client indicators alone carry no technique mapping.

## Alternative explanations

- An authorized penetration test or vulnerability scan against the lab application.
- A legitimate user whose password or username contains SQL metacharacters (quotes, comment markers).
- Automated health checks or crawlers that only resemble tools by User-Agent.
- Requests relayed through Cloudflare Tunnel or a proxy, where the logged source is not the real client.

## Investigation steps

- Correlate request, authentication and endpoint observations for the same Agent, source IP and request_id.
- Run collect_additional_evidence: it gathers related Manager records two minutes either side of the observation (HTTP, authentication, flows, process metadata, incident notes) and requests a fresh authenticated Agent network snapshot. It is read-only and has no rollback.
- Check whether the session grant followed the injected request and whether the credential mismatch receipt exists.
- Review the web server for post-exploitation signs: child shells of the Flask process, new outbound connections.

## Response options

- temporary_ip_block: the lab Flask guard rejects POST /login from the observed disposable peer with HTTP 403 for a 300-second lease.
- apply_rate_limit: the guard allows at most three POST /login requests per ten-second window from that peer; further requests receive HTTP 429 during the 300-second lease.
- revoke_session: offered only for sqli_exploitation_confirmed (see the session revocation runbook).
- increase_monitoring: review matching Manager HTTP records every 10 seconds for five minutes.
- generate_remediation_guidance: attach an evidence-linked note; fix the query with parameterized statements in the application.
- Verification: an action succeeds only when the lease is still owned and the guard recorded an HTTP 403 (block) or HTTP 429 (rate limit) receipt for that action_id and peer inside the lease window; otherwise it stays verifying, becomes expired after the deadline, or failed if the lease is gone.

## Execution prerequisites

- The proposal must be approved, then executed, by a scoped operator; the Manager re-runs the investigation and refuses if current evidence no longer supports the proposal.
- The peer must be listed by an administrator in the Agent's HTTP_RESPONSE_LAB_WAFS disposable_peers, must not be in protected_peers, and must be a host address in the documentation ranges 192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24.
- The lab adapter directory must be an absolute, existing path; otherwise the adapter is unavailable (HTTP 409).
- Only one active lease may own a peer; a second action is rejected while the first lease is live.

## Operational risks

- The block affects every POST /login request from that peer, including any legitimate user behind the same address.
- Traffic intervention is unavailable for real (non-lab) peers: the captured HTTP source has no verified relationship to the enforcement point, and UFW firewall transactions are not used for this.
- A block does not remediate the vulnerable query; the attacker can return after the TTL or from another address.

## Rollback guidance

- Rollback deletes only the lease row owned by the action (peer and action_id) and verifies it is gone; a failure to verify returns HTTP 409 and the status rollback_failed.
- Rollback is available while the action is dispatched, verifying, succeeded, partial or rollback_failed.
- If no rollback is requested, the lease expires on its own after 300 seconds.
