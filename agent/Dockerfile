# agent/Dockerfile
FROM python:3.12-slim

# Cài đặt các gói hệ thống để hỗ trợ giám sát (tường lửa, tiến trình, công cụ mô phỏng)
RUN apt-get update && \
    apt-get install -y --no-install-recommends ufw procps net-tools hping3 iptables nano nmap curl netcat-openbsd && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent.py .
COPY commands/ /app/commands/

# Thêm thư mục mô phỏng hành vi mã độc (malware simulation)
RUN mkdir -p /app/malware_sim
COPY malware_sim/ /app/malware_sim/
RUN chmod +x /app/malware_sim/*.sh

# Giữ container chạy bằng script Python (agent.py đã có vòng lặp vô hạn)
ENV PYTHONUNBUFFERED=1
CMD ["python", "-u", "agent.py"]