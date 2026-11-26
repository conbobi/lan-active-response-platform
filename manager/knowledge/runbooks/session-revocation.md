---
id: session-revocation
title: Session revocation for the lab Flask application
category: session_revocation
attack_ids: [T1190, T1078]
---

## Observed indicators

- The lab application granted a session (HTTP 302 on POST /login with a session_ref) for a request carrying SQL indicators, and the guard recorded a credential mismatch for that grant.

## Required evidence

- Classification sqli_exploitation_confirmed: a correlated grant_observation with credential_match=0, a matching flask_web AUTH_OBSERVATION success and the same request_id and session_ref within 5 seconds.
- A fresh direct-peer receipt for the same request.
- The session_ref (sha256 of the session audit nonce); Flask uses client-side signed sessions, so the cookie itself is not stored server-side.

## ATT&CK mapping

- T1190 for the exploitation that produced the grant; T1078 only if the evidence shows the granted session being used as a valid account.

## Alternative explanations

- A legitimate login whose credentials happen to contain SQL metacharacters: in that case the credential check matches and no mismatch receipt exists.

## Investigation steps

- Confirm the mismatch receipt and the session grant correlate to the same request_id.
- Review subsequent requests that presented the session to see what the session accessed.

## Response options

- revoke_session: the Manager records the session_ref in the lab revoked_session table. When the signed cookie is next presented, the guard clears the session and returns HTTP 401; a revocation receipt with the action_id is recorded.
- Verification uses the revocation receipt for that action_id and session_ref.

## Execution prerequisites

- Operator approval and execution; the investigation must still produce the same revoke proposal at execution time.
- The Flask session guard (session_denylist capability) configured for the Agent's lab adapter.

## Operational risks

- The affected user must authenticate again.
- Revocation does not fix the injectable query or invalidate other sessions obtained the same way.

## Rollback guidance

- Irreversible for this cookie: the denylist entry is not removed. The user may authenticate again to obtain a new session.
