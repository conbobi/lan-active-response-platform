# agent/Dockerfile
FROM python:3.12-slim

# Cài đặt các gói hệ thống để hỗ trợ giám sát (tường lửa, tiến trình)
RUN apt-get update && \
    apt-get install -y --no-install-recommends  ufw procps net-tools hping3 iptables && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent.py .
COPY commands/ /app/commands/

# Giữ container chạy bằng script Python (agent.py đã có vòng lặp vô hạn)
ENV PYTHONUNBUFFERED=1
CMD ["python", "-u", "agent.py"]