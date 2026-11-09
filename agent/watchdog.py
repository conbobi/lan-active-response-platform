#!/usr/bin/env python3
"""
LARP EDR Agent Watchdog (Layer 3 Self-Healing)
Monitors the LARP agent process and automatically restarts it if terminated.
Can run continuously as a background process or as a one-shot check via Task Scheduler / Cron.
"""

import os
import sys
import time
import argparse
import logging
import subprocess
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [WATCHDOG] %(message)s"
)
logger = logging.getLogger("larp_watchdog")

DEFAULT_INTERVAL = 10  # seconds between checks in daemon mode
AGENT_SCRIPT_WINDOWS = "win_agent_minimal.py"
AGENT_SCRIPT_LINUX = "agent.py"


def is_agent_running(target_script: str) -> bool:
    """Check if the agent script is actively running."""
    # Attempt 1: Using psutil if available
    try:
        import psutil
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                cmdline = " ".join(proc.info.get("cmdline") or []).lower()
                if target_script.lower() in cmdline:
                    # Make sure we don't count watchdog itself
                    if "watchdog.py" not in cmdline:
                        return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return False
    except ImportError:
        pass

    # Attempt 2: Platform-specific CLI tools
    if sys.platform == "win32":
        try:
            output = subprocess.check_output(
                ["wmic", "process", "get", "commandline"],
                text=True, stderr=subprocess.DEVNULL
            ).lower()
            lines = output.splitlines()
            for line in lines:
                if target_script.lower() in line and "watchdog.py" not in line:
                    return True
        except Exception:
            pass
    else:
        try:
            res = subprocess.run(
                ["pgrep", "-f", target_script],
                capture_output=True, text=True
            )
            if res.returncode == 0 and res.stdout.strip():
                return True
        except Exception:
            pass

    return False


def start_agent(agent_path: str):
    """Spawns the agent process in detached background mode."""
    logger.warning(f"Agent '{agent_path}' is NOT running! Spawning restart...")
    agent_dir = os.path.dirname(os.path.abspath(agent_path))
    
    creationflags = 0
    if sys.platform == "win32":
        # DETACHED_PROCESS = 0x00000008, CREATE_NEW_PROCESS_GROUP = 0x00000200
        creationflags = 0x00000008 | 0x00000200

    try:
        proc = subprocess.Popen(
            [sys.executable, agent_path],
            cwd=agent_dir,
            creationflags=creationflags,
            close_fds=(sys.platform != "win32"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        logger.info(f"Successfully spawned agent (PID: {proc.pid})")
    except Exception as e:
        logger.error(f"Failed to spawn agent '{agent_path}': {e}", exc_info=True)


def main():
    parser = argparse.ArgumentParser(description="LARP EDR Agent Watchdog")
    parser.add_argument("--once", action="store_true", help="Run a single check and exit (for Task Scheduler / Cron)")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help="Check interval in seconds (default: 10)")
    parser.add_argument("--script", type=str, default="", help="Specific agent script to monitor")
    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))
    target_script = args.script
    if not target_script:
        target_script = AGENT_SCRIPT_WINDOWS if sys.platform == "win32" else AGENT_SCRIPT_LINUX

    agent_path = os.path.join(base_dir, target_script)
    if not os.path.exists(agent_path):
        # Fallback to win_agent_minimal.py if on Windows or file exists
        alt_path = os.path.join(base_dir, "win_agent_minimal.py")
        if os.path.exists(alt_path):
            agent_path = alt_path
            target_script = "win_agent_minimal.py"

    logger.info(f"Watchdog initialized monitoring '{target_script}' (Path: {agent_path})")

    if args.once:
        if not is_agent_running(target_script):
            start_agent(agent_path)
        else:
            logger.info(f"Agent '{target_script}' is healthy and running.")
        return

    # Continuous daemon loop
    logger.info(f"Starting continuous watchdog loop (interval: {args.interval}s)...")
    while True:
        try:
            if not is_agent_running(target_script):
                start_agent(agent_path)
            time.sleep(args.interval)
        except KeyboardInterrupt:
            logger.info("Watchdog terminated by user.")
            break
        except Exception as e:
            logger.error(f"Unexpected error in watchdog loop: {e}", exc_info=True)
            time.sleep(args.interval)


if __name__ == "__main__":
    main()

