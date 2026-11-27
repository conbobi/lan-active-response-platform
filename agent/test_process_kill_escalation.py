"""Verified tree kill against real processes: a child that ignores SIGTERM (like the interactive bash of a
reverse shell) must still be stopped, and its parent with it. Uses only processes this test starts."""
import os
import subprocess
import sys
import time

import psutil
import pytest

from commands import process_target

IGNORES_TERM = "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(120)"
PARENT = ("import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', %r]); time.sleep(120)"
          % IGNORES_TERM)

pytestmark = pytest.mark.skipif(not hasattr(os, "pidfd_open"), reason="needs Linux pidfd")


def params(proc):
    return {"pid": proc.pid, "process_start_time": proc.create_time(), "exe_path": proc.exe(),
            "parent_pid": proc.ppid(), "confirmed": True}


def test_child_ignoring_sigterm_is_killed_and_the_whole_tree_exits():
    parent = subprocess.Popen([sys.executable, "-c", PARENT])
    try:
        target = psutil.Process(parent.pid)
        for _ in range(50):
            if target.children():
                break
            time.sleep(0.1)
        child, = target.children()
        time.sleep(0.3)  # let the child install its SIG_IGN handler
        result = process_target.terminate(params(target), tree=True)
        assert result["status"] == "success", result
        assert set(result["killed_pids"]) == {target.pid, child.pid}
        assert result["forced_pids"] == [child.pid]  # SIGTERM was ignored, SIGKILL was needed
        parent.wait(timeout=5)
        try:  # gone, or a zombie waiting to be reaped by init: either way no longer running
            assert psutil.Process(child.pid).status() == psutil.STATUS_ZOMBIE
        except psutil.NoSuchProcess:
            pass
    finally:
        if parent.poll() is None:
            parent.kill()
