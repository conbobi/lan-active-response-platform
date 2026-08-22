from .base import BaseCommand


class IsolateCommand(BaseCommand):
    name = "isolate"

    async def execute(self, params, websocket):
        # Perform iptables drop / network isolation logic
        return {"status": "success"}