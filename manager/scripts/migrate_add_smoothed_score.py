"""Chạy 1 lần để thêm cột smoothed_score vào bảng risk_scores / risk_score_records."""
import asyncio
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sqlalchemy import text
from app.core.database import async_engine
from app.models.base import Base
import app.models  # noqa: F401


async def main():
    async with async_engine.begin() as conn:
        dialect = conn.dialect.name
        
        # Ensure all tables defined in Base metadata exist
        await conn.run_sync(Base.metadata.create_all)
        
        target_tables = ["risk_score_records", "risk_scores"]
        for table in target_tables:
            if dialect == "sqlite":
                res = await conn.execute(text(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'"))
                if not res.fetchone():
                    continue
                result = await conn.execute(text(f"PRAGMA table_info({table})"))
                cols = [row[1] for row in result.fetchall()]
            else:
                res = await conn.execute(text(f"SELECT table_name FROM information_schema.tables WHERE table_name = '{table}'"))
                if not res.fetchone():
                    continue
                result = await conn.execute(text(f"SELECT column_name FROM information_schema.columns WHERE table_name = '{table}'"))
                cols = [row[0] for row in result.fetchall()]
                
            if "smoothed_score" in cols:
                print(f"✓ Cột smoothed_score đã tồn tại trong {table}, skip")
            else:
                await conn.execute(text(
                    f"ALTER TABLE {table} ADD COLUMN smoothed_score FLOAT DEFAULT 0.0"
                ))
                print(f"✓ Đã thêm cột smoothed_score vào {table}")

    print("✓ Migration hoàn tất")


if __name__ == "__main__":
    asyncio.run(main())
