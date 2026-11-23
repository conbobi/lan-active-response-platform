from .base import BaseCommand
from .process_target import terminate


class KillProcessTreeCommand(BaseCommand):
    name = "kill_process_tree"

    async def execute(self, params, websocket):
        return terminate(params, tree=True)
