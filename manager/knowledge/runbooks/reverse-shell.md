---
id: reverse-shell
title: Reverse shell triage
category: reverse_shell
attack_ids: [T1059.004, T1059.006, T1105]
---

## Observed indicators

- builtin_linux_network_shell: a shell process (bash, dash, sh, ash, ksh, zsh, fish) whose standard input/output file descriptors are bound to a network socket.
- A web service process (apache2, httpd, nginx, php-fpm, gunicorn, uwsgi, flask) in the ancestry of the shell.
- Interpreters such as python opening sockets and spawning shells; downloads with curl or wget before the shell.

## Required evidence

- Process identity (PID, start time, executable), socket inode and file descriptors from the same sample.
- The socket holders: the rule does not assign a connection initiator; if several holders are equal, the primary process remains undetermined.
- Connection direction is recorded only when the TCP handshake was observed.

## ATT&CK mapping

- T1059.004 Unix shell; T1059.006 Python when the interpreter is the holder; T1105 when a tool was downloaded before execution.

## Alternative explanations

- Administrator SSH sessions, terminal multiplexers, remote development tools and IDE helpers hold sockets with interactive shells.
- Container exec sessions.

## Investigation steps

- Compare process identity, socket inode and FD on the same sample.
- Distinguish the socket holder from the process that created the connection.
- Check the parent chain for a web server or an unexpected interpreter, and the remote address for reputation.

## Response options

- kill_process_tree on the verified shell tree; isolate the host if the remote endpoint is confirmed malicious or the compromise path is unknown.
- Investigate the entry point (often T1190 against the web service) and persistence.

## Execution prerequisites

- PID, start time, executable and parent PID; explicit operator confirmation.

## Operational risks

- Killing an administrator session interrupts legitimate work; protected processes such as sshd are refused.

## Rollback guidance

- Termination has no rollback; isolation can be reverted with unisolate after cleanup.
