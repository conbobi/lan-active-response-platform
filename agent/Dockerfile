# agent/Dockerfile
FROM python:3.12-slim

# Cài đặt các gói hệ thống để hỗ trợ giám sát (tường lửa, tiến trình, công cụ mô phỏng)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ufw iproute2 nftables procps net-tools hping3 iptables nano nmap curl iputils-ping netcat-openbsd \
    stress openssh-client openssh-server cron at \
    socat tcpdump tshark dnsutils \
    python3-venv gcc make \
    sudo \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN echo "trap : EXIT" > /etc/bash_env

COPY *.py /app/
COPY commands/ /app/commands/
COPY vulnerable_web/ /app/vulnerable_web/

ENV PYTHONUNBUFFERED=1
CMD ["python", "-u", "agent.py"]