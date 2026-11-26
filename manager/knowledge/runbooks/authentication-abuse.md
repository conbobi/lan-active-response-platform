---
id: authentication-abuse
title: Authentication abuse (brute force, spraying, valid accounts)
category: authentication_abuse
attack_ids: [T1110, T1110.001, T1110.003, T1110.004, T1078, T1021.004]
---

## Observed indicators

- repeated_auth_failures: at least 5 failures (default threshold) for the same service within the 60-second window.
- authentication_brute_force: a burst of failures for the same account and source (password_burst_same_account_source), or the same account from three or more sources (distributed_password_burst_same_account).
- A success after the failure burst from the same source raises the score (85 versus 75).
- Usernames carrying SQL indicators on flask_web are treated as SQL probing, not as account names.

## Required evidence

- Individual authentication events with service, source IP, username, status, count and timestamp source (log or application timestamps are preferred over receipt times).
- For a compromise claim: a success event for the same account and source after the failures, and activity of that session.

## ATT&CK mapping

- T1110.001 when one account receives many passwords from one source; T1110.003 when many accounts each receive few passwords from one source; T1110.004 only when the tried pairs are shown to come from a credential dump; T1110 when the variant is unknown.
- T1078 only when a valid account is shown to be used; T1021.004 when SSH logins are used for lateral movement.

## Alternative explanations

- A user or a scheduled task retrying with an expired or rotated password.
- Monitoring or configuration management with stale credentials.
- A NAT or proxy address aggregating many users.

## Investigation steps

- Compare service, account, source and observation window across the events.
- Check whether any attempt succeeded and what the session did next (commands, new sockets, file changes).
- Review SSH keys and authorized_keys for unexpected additions after a success.

## Response options

- For the lab Flask login: apply_rate_limit (HTTP 429 after three POST /login per ten seconds) or temporary_ip_block (HTTP 403) on a disposable peer for 300 seconds.
- For SSH or system accounts: lock or reset the account and review keys; firewall changes use the UFW transaction workflow.

## Execution prerequisites

- Operator approval for any traffic intervention; lab traffic actions require a fresh direct-peer receipt.

## Operational risks

- Locking an account can deny service to its legitimate owner; blocking a shared address affects all users behind it.

## Rollback guidance

- Lab leases expire after 300 seconds or can be rolled back; account locks must be lifted manually after verification.
