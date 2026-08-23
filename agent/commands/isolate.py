import subprocess
from .base import BaseCommand


class IsolateCommand(BaseCommand):
    name = "isolate"

    async def execute(self, params, websocket):
        """
        Thực hiện cô lập agent:
        - Chặn toàn bộ lưu lượng ra/vào (INPUT, OUTPUT, FORWARD) bằng iptables.
        - Mở kết nối đến Manager và các địa chỉ quản lý nếu cần.
        - Ghi file /tmp/isolated để đánh dấu trạng thái.
        """
        try:
            # Xóa rules cũ (nếu có)
            subprocess.run(["iptables", "-F"], check=False)
            subprocess.run(["iptables", "-X"], check=False)

            # Đặt policy mặc định DROP cho INPUT, OUTPUT, FORWARD
            subprocess.run(["iptables", "-P", "INPUT", "DROP"], check=False)
            subprocess.run(["iptables", "-P", "OUTPUT", "DROP"], check=False)
            subprocess.run(["iptables", "-P", "FORWARD", "DROP"], check=False)

            # Cho phép kết nối đến Manager (giả sử Manager IP là 172.19.0.2 hoặc host manager)
            # Bạn có thể lấy IP của manager từ biến môi trường hoặc cấu hình.
            # Ở đây dùng 'manager' hostname, cần resolve ra IP.
            import socket
            try:
                manager_ip = socket.gethostbyname("manager")
            except:
                manager_ip = "172.19.0.2"  # fallback IP

            # Mở kết nối đến manager qua cổng 8000 và 5432 (PostgreSQL) nếu cần
            subprocess.run(["iptables", "-A", "INPUT", "-s", manager_ip, "-j", "ACCEPT"], check=False)
            subprocess.run(["iptables", "-A", "OUTPUT", "-d", manager_ip, "-j", "ACCEPT"], check=False)

            # Ghi file đánh dấu
            with open("/tmp/isolated", "w") as f:
                f.write("1")

            return {"status": "success", "message": "Network isolated successfully"}

        except Exception as e:
            return {"status": "error", "message": str(e)}