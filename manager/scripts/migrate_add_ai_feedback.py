"""
Migration script for AI Ground Truth & Feedback Foundation (Phase 2).
Thêm các trường label và feedback vào bảng incidents và response_actions.
Hỗ trợ Idempotency (chạy nhiều lần không lỗi) và cờ --rollback để hoàn tác.
"""
import asyncio
import os
import sys
import argparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sqlalchemy import text
from app.core.database import async_engine


MIGRATION_SQL = """
-- Incidents ground truth columns
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS label VARCHAR(16);
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS label_reason TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS labeled_by VARCHAR(64);
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS labeled_at TIMESTAMPTZ;

-- Response Actions feedback columns
ALTER TABLE response_actions ADD COLUMN IF NOT EXISTS outcome VARCHAR(32);
ALTER TABLE response_actions ADD COLUMN IF NOT EXISTS feedback_signal JSONB;
"""

ROLLBACK_SQL = """
-- Drop Response Actions feedback columns
ALTER TABLE response_actions DROP COLUMN IF EXISTS feedback_signal;
ALTER TABLE response_actions DROP COLUMN IF EXISTS outcome;

-- Drop Incidents ground truth columns
ALTER TABLE incidents DROP COLUMN IF EXISTS labeled_at;
ALTER TABLE incidents DROP COLUMN IF EXISTS labeled_by;
ALTER TABLE incidents DROP COLUMN IF EXISTS label_reason;
ALTER TABLE incidents DROP COLUMN IF EXISTS label;
"""


async def migrate(rollback: bool = False):
    action_desc = "ROLLBACK" if rollback else "APPLY"
    print(f"=== BẮT ĐẦU MIGRATION AI FEEDBACK: {action_desc} ===")
    
    async with async_engine.begin() as conn:
        dialect = conn.dialect.name
        print(f"[*] Database dialect: {dialect}")

        if rollback:
            print("[*] Đang thực thi rollback: xóa các cột AI feedback...")
            for statement in ROLLBACK_SQL.strip().split(";"):
                stmt = statement.strip()
                if stmt:
                    await conn.execute(text(stmt))
            print("[✓] Đã drop thành công các cột AI feedback từ incidents và response_actions.")
        else:
            print("[*] Đang thực thi apply: thêm các cột AI feedback...")
            for statement in MIGRATION_SQL.strip().split(";"):
                stmt = statement.strip()
                if stmt:
                    await conn.execute(text(stmt))
            print("[✓] Đã thêm thành công các cột AI feedback vào incidents và response_actions.")

    print(f"=== MIGRATION AI FEEDBACK ({action_desc}) HOÀN TẤT THÀNH CÔNG ===")


def main():
    parser = argparse.ArgumentParser(description="Migration script for AI Feedback columns")
    parser.add_argument("--rollback", action="store_true", help="Rollback migration by dropping added columns")
    args = parser.parse_args()

    asyncio.run(migrate(rollback=args.rollback))


if __name__ == "__main__":
    main()
