---
id: verified-process-termination
title: Verified process termination (PID plus start time)
category: suspicious_process_execution
attack_ids: [T1059]
section_categories:
  response-options: remediation
  rollback-guidance: remediation
---

## Observed indicators

- A process with confirmed malicious behavior: an interpreter or shell spawned by a service, a process holding an unexpected outbound socket, or a process tree that respawns children.

## Required evidence

- The process identity tuple recorded by telemetry: PID, process_start_time, absolute executable path and parent PID. A bare PID or process name is not a target.
- The Agent ID that observed the process; PIDs are only meaningful per endpoint and per process start time because PIDs are reused.

## ATT&CK mapping

- Map the technique from the behavior evidence (for example T1059 for command interpreter execution); termination itself is not a technique.

## Alternative explanations

- PID reuse: the original process exited and a new process received the same PID; the start time and executable will differ.
- An administrator task or package manager that legitimately spawns shells.

## Investigation steps

- Compare PID, start time, executable and parent PID with the current process list before requesting termination.
- Review the process tree to decide between kill_process (one process) and kill_process_tree (process and all descendants).
- Check the Agent self-protection result: protected targets are refused.

## Response options

- kill_process: terminate exactly the identified process.
- kill_process_tree: terminate the process and its descendants, children first, to prevent respawn.
- The Agent opens a pidfd for each target, re-checks (start time, executable, parent PID) before signalling, sends SIGTERM through the pidfd and waits up to 1.5 seconds for verified exit. If identity changes at any point the command is rejected.

## Execution prerequisites

- Explicit operator confirmation (confirmed=true); automated actors cannot confirm.
- PID greater than 2, positive parent PID, finite positive start time and an absolute executable path.
- Protected processes are refused: init, systemd and systemd-* helpers, sshd, cloudflared, tailscaled, dbus, udevd, cron, containerd, dockerd, NetworkManager, kernel threads, and the Agent's own lineage.

## Operational risks

- Killing a service process interrupts that service; data in memory is lost.
- If the parent respawns the process, a single kill only buys time; consider the tree or persistence checks.

## Rollback guidance

- Process termination is one-shot: there is no automatic rollback and no cooldown. Restart the legitimate service manually if it was terminated in error.
