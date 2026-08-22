from agent.commands.base import BaseCommand

class IsolateCommand(BaseCommand):
    name = "isolate"

    async def execute(self, params, websocket):
        # Thực hiện iptables drop, ghi file /tmp/isolated, ...
        return {"status": "success"}