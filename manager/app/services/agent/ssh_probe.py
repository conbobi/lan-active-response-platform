"""Verify a fresh authenticated SSH session from the Manager's recovery network."""
import asyncio
from contextlib import suppress
import ipaddress
import os
from pathlib import Path
import re

from app.core.config import settings

PROBE_DIRECTORY = Path("/run/larp-ssh-probes")
_active = set()


def configured(agent_id):
    return bool(re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}", agent_id) and agent_id not in {".", ".."}
                and agent_id in settings.NETWORK_SSH_PROBES
                and (PROBE_DIRECTORY / agent_id / "key").is_file()
                and (PROBE_DIRECTORY / agent_id / "known_hosts").is_file())


async def verify(agent_id):
    if not configured(agent_id) or agent_id in _active:
        raise RuntimeError("SSH verifier is unavailable")
    destination = settings.NETWORK_SSH_PROBES[agent_id]
    files = PROBE_DIRECTORY / agent_id
    _active.add(agent_id)
    try:
        process = await asyncio.create_subprocess_exec(
            "/usr/bin/ssh", "-F", "/dev/null", "-T", "-n", "-o", "BatchMode=yes",
            "-o", "ConnectionAttempts=1", "-o", "ConnectTimeout=3", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", f"HostKeyAlias=larp-{agent_id}",
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", f"UserKnownHostsFile={files / 'known_hosts'}",
            "-o", "ClearAllForwardings=yes", "-o", "IdentityAgent=none",
            "-i", str(files / "key"), "-p", str(destination.port), "-l", destination.user,
            "--", destination.host, "/usr/bin/printenv SSH_CONNECTION",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            env={"PATH": os.defpath, "LC_ALL": "C"}, limit=512,
        )
        try:
            async with asyncio.timeout(4):
                line = await process.stdout.readuntil(b"\n")
                if await process.stdout.read(1) or await process.wait():
                    raise RuntimeError("SSH verification failed")
            source, _, endpoint, port = line.decode("ascii").split()
            if int(port) != destination.port:
                raise ValueError("Unexpected SSH port")
            return {"source": str(ipaddress.ip_address(source)),
                    "endpoint": str(ipaddress.ip_address(endpoint)), "port": int(port)}
        except (ValueError, TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as error:
            raise RuntimeError("SSH verification failed") from error
        finally:
            if process.returncode is None:
                with suppress(ProcessLookupError):
                    process.kill()
                await process.wait()
    finally:
        _active.remove(agent_id)
