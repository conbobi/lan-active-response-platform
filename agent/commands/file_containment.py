"""inspect_file / quarantine_file / restore_file — see file_containment.py."""
import asyncio

from file_containment import FileContainmentError, inspect, quarantine, restore

from .base import BaseCommand


async def _run(fn, *args):
    try:
        receipt = await asyncio.to_thread(fn, *args)
    except FileContainmentError as error:
        receipt = {"status": "failed", "code": error.code, "message": str(error)}
    except (OSError, ValueError) as error:
        receipt = {"status": "failed", "code": "EXECUTION_ERROR", "message": f"{type(error).__name__}: {error}"}
    return {"status": receipt.get("status", "failed"), "message": receipt.get("message"), "receipt": receipt}


class InspectFileCommand(BaseCommand):
    name = "inspect_file"

    async def execute(self, params, websocket):
        return await _run(inspect, params.get("path"))


class QuarantineFileCommand(BaseCommand):
    name = "quarantine_file"

    async def execute(self, params, websocket):
        return await _run(quarantine, params.get("path"), params.get("sha256"), params.get("quarantine_id"))


class RestoreFileCommand(BaseCommand):
    name = "restore_file"

    async def execute(self, params, websocket):
        return await _run(restore, params.get("quarantine_id"), params.get("sha256"))
