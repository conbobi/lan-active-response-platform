"""
Migration: Add process_name and pid to flows table
Run: docker exec larp-manager-1 python -m scripts.migrate_add_process_to_flows
"""
import asyncio
from sqlalchemy import text
from app.core.database import async_engine

async def migrate():
    async with async_engine.begin() as conn:
        # Idempotent — dùng IF NOT EXISTS
        await conn.execute(text("""
            ALTER TABLE flows ADD COLUMN IF NOT EXISTS process_name VARCHAR(128);
        """))
        await conn.execute(text("""
            ALTER TABLE flows ADD COLUMN IF NOT EXISTS pid INTEGER;
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_flows_process_name ON flows(process_name);
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_flows_dst_port ON flows(dst_port);
        """))
    print("[✓] Migration complete: flows.process_name + flows.pid")

if __name__ == "__main__":
    asyncio.run(migrate())
