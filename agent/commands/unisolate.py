import os
import subprocess
from typing import Any, Dict, Optional
from .base import BaseCommand


class AwaitableDict(dict):
    """
    Cho phép trả về dict tương thích cả gọi đồng bộ (cmd.execute())
    lẫn bất đồng bộ (await cmd.execute()).
    """
    def __await__(self):
        async def _coro():
            return self
        return _coro().__await__()


class UnisolateCommand(BaseCommand):
    name = "unisolate"

    def execute(self, params: Optional[Dict[str, Any]] = None, websocket: Any = None) -> AwaitableDict:
        """
        Thực hiện huỷ cô lập agent:
        - Đặt lại policy mặc định ACCEPT cho INPUT, OUTPUT, FORWARD.
        - Xóa toàn bộ rules iptables đã tạo khi isolate.
        - Xóa file /tmp/isolated đánh dấu trạng thái cô lập.
        """
        try:
            # 1. Đặt lại policy mặc định ACCEPT
            subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], check=False)
            subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=False)
            subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], check=False)

            # 2. Xóa rules cũ
            subprocess.run(["iptables", "-F"], check=False)
            subprocess.run(["iptables", "-X"], check=False)

            # 3. Xóa file đánh dấu /tmp/isolated
            if os.path.exists("/tmp/isolated"):
                try:
                    os.remove("/tmp/isolated")
                except OSError:
                    pass

            return AwaitableDict({
                "status": "success",
                "message": "Network unisolated successfully"
            })

        except Exception as e:
            return AwaitableDict({
                "status": "error",
                "message": str(e)
            })
