FROM python:3.12-slim

# Install system dependencies required for asyncpg and PostgreSQL compilation
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev curl openssh-client && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir 'uvicorn[standard]'

# Copy source code
COPY . .
RUN pip install --no-cache-dir --no-deps -e .

# Expose port 8000
EXPOSE 8000

# Launch application via Uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]