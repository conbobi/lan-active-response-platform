# manager/Dockerfile
FROM python:3.12-slim

# Cài đặt các gói hệ thống cần thiết để build asyncpg
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy file requirements và cài đặt dependencies Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy toàn bộ mã nguồn Manager
COPY . .

# Mở cổng 8000 (chỉ để khai báo, không ảnh hưởng thực tế)
EXPOSE 8000

# Chạy ứng dụng FastAPI bằng uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]