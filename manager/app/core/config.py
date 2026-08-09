# manager/app/core/config.py
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://larp:larp_password@db:5432/larpdb"
)
MANAGER_HOST = os.getenv("MANAGER_HOST", "0.0.0.0")
MANAGER_PORT = int(os.getenv("MANAGER_PORT", "8000"))
HEARTBEAT_TIMEOUT = int(os.getenv("HEARTBEAT_TIMEOUT", "30"))