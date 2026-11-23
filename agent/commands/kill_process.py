from .base import BaseCommand
from .process_target import terminate


class KillProcessCommand(BaseCommand):
    name = "kill_process"

    async def execute(self, params, websocket):
        return terminate(params, tree=False)
