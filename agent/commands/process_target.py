"""Validate process instances before dispatching Linux signals through pidfds."""
from contextlib import ExitStack
import math
import os
import select
import signal

import psutil

PROTECTED = {
    "init", "systemd", "sshd", "sshd-session", "sshd-auth", "tailscaled", "cloudflared",
    "dbus-daemon", "dbus-broker", "udevd", "cron", "containerd", "dockerd", "NetworkManager",
}


def _protected(proc, agent_lineage):
    name = proc.name()
    exe = os.path.basename(proc.exe())
    return (proc.pid in agent_lineage or proc.pid <= 2 or proc.ppid() == 2
            or name in PROTECTED or exe in PROTECTED
            or name.startswith("systemd-") or exe.startswith("systemd-")
            or exe.startswith("larp-agent"))


def _identity(proc):
    return proc.create_time(), proc.exe(), proc.ppid()


def terminate(params, tree):
    pid = params.get("pid")
    started = params.get("process_start_time")
    executable = params.get("exe_path")
    ppid = params.get("parent_pid")
    result = {"killed_pids": [], "validation": "rejected", "status": "failed"}
    if params.get("confirmed") is not True:
        return {**result, "message": "Explicit operator confirmation required"}
    if (type(pid) is not int or pid <= 2 or type(ppid) is not int or ppid <= 0
            or type(started) not in (int, float) or not math.isfinite(started) or started <= 0
            or not isinstance(executable, str) or not executable.startswith("/")):
        return {**result, "message": "PID, start time, executable and parent PID are required"}
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        return {**result, "message": "PID file descriptors are unavailable"}

    try:
        self_process = psutil.Process()
        agent_lineage = {self_process.pid, *(parent.pid for parent in self_process.parents())}
        target = psutil.Process(pid)
        if _identity(target) != (started, executable, ppid):
            return {**result, "message": "Target process identity changed"}
        if _protected(target, agent_lineage):
            return {**result, "message": "Target is a protected process"}

        children = target.children(recursive=True) if tree else []
        processes = [target, *children]
        identities = {proc.pid: _identity(proc) for proc in processes}
        if identities[pid] != (started, executable, ppid):
            return {**result, "message": "Target process identity changed during validation"}
        if any(_protected(proc, agent_lineage) for proc in processes):
            return {**result, "message": "Process tree contains a protected process"}
        if any(identities[proc.pid][2] not in identities for proc in children):
            return {**result, "message": "Process tree relationships changed"}

        with ExitStack() as handles:
            descriptors = {}
            for proc in processes:
                fd = os.pidfd_open(proc.pid)
                handles.callback(os.close, fd)
                if _identity(psutil.Process(proc.pid)) != identities[proc.pid]:
                    return {**result, "message": "Process identity changed during validation"}
                descriptors[proc.pid] = fd
            if tree and {child.pid for child in target.children(recursive=True)} != set(identities) - {pid}:
                return {**result, "message": "Process tree changed during validation"}

            result["validation"] = "validated"
            for proc in reversed(processes):
                live = psutil.Process(proc.pid)
                if _identity(live) != identities[proc.pid] or _protected(live, agent_lineage):
                    return {**result, "message": "Process identity changed before termination"}
                fd = descriptors[proc.pid]
                signal.pidfd_send_signal(fd, signal.SIGTERM)
                poller = select.poll()
                poller.register(fd, select.POLLIN)
                if not any(events & select.POLLIN for _, events in poller.poll(1500)):
                    return {**result, "message": f"Exit of PID {proc.pid} could not be verified"}
                result["killed_pids"].append(proc.pid)
    except (psutil.Error, OSError, ValueError) as error:
        return {**result, "message": f"Process termination failed: {error}"}

    return {**result, "status": "success", "message": "Verified exit of all selected processes"}
