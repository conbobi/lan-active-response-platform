---
id: persistence-checks
title: Linux persistence checks
category: persistence
attack_ids: [T1053.003, T1543.002, T1098.004, T1505.003]
---

## Observed indicators

- File integrity changes to cron files, systemd unit files, ~/.ssh/authorized_keys or web application directories.
- New processes started by cron or systemd that open network sockets or spawn shells.

## Required evidence

- The changed path and its SHA-256 transition from file integrity monitoring.
- The process or user that made the change when available, and the time of change.
- Maintenance windows or configuration management records that could explain the change.

## ATT&CK mapping

- T1053.003 for a new or changed crontab entry; T1543.002 for a new or changed systemd unit file; T1098.004 for an added authorized_keys entry; T1505.003 for a new script file under the web application directory.

## Alternative explanations

- Package installation or upgrade, configuration management runs, administrator changes during maintenance.

## Investigation steps

- Compare the path and SHA-256 transition against the expected configuration.
- Read the new cron entry, unit file or key comment; identify what it executes and which user owns it.
- Search for web shells: new script files in web roots and web server processes spawning shells.

## Response options

- Quarantine the malicious file, remove the persistence entry, terminate verified processes started from it.
- Rotate credentials and keys that may have been exposed.

## Execution prerequisites

- Confirmation for quarantine and termination; a snapshot is captured before stateful actions.

## Operational risks

- Removing a legitimate unit or key breaks services or administrator access; keep console access available.

## Rollback guidance

- Quarantine is stateful and can be restored; restore removed configuration from the snapshot or backup after verification.
