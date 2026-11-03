"""
Migration script for AI Response Suggestion columns in ai_analysis table (Phase 4 — Layer 2 AI Assist).
Hỗ trợ Idempotency (chạy nhiều lần không lỗi) và cờ --rollback để hoàn tác.
"""
import os
import sys
import argparse
import asyncio

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sqlalchemy import text
from app.core.database import async_engine

MIGRATION_SQL = """
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS suggested_action VARCHAR(32);
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS suggestion_params JSONB;
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS suggestion_reasoning TEXT;
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS blast_radius JSONB;
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS applied_by_analyst VARCHAR(64);
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS applied_at TIMESTAMPTZ;
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS dismissed_by_analyst VARCHAR(64);
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS dismissed_at TIMESTAMPTZ;
ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS dismiss_reason TEXT;
"""

ROLLBACK_SQL = """
ALTER TABLE ai_analysis DROP COLUMN IF EXISTS dismiss_reason;
ALTER TABLE ai_analysis DROP COLUMN IF EXISTS dismissed_at;
ALTER TABLE ai_analysis DROP COLUMN IF EXISTS dismissed_by_analyst;
ALTER TABLE ai_analysis DROP COLUMN IF EXISTS applied_at;
ALTER TABLE ai_analysis DROP COLUMN IF EXISTS applied_by_analyst;
ALTER TABLE ai_analysis DROP COLUMN IF EXISTS blast_radius;
ALTER TABLE ai_analysis DROP COLUMN IF EXISTS suggestion_reasoning;
ALTER TABLE ai_analysis DROP COLUMN IF EXISTS suggestion_params;
ALTER TABLE ai_analysis DROP COLUMN IF EXISTS suggested_action;
"""


async def migrate(rollback: bool = False):
    action_desc = "ROLLBACK" if rollback else "APPLY"
    print(f"=== BẮT ĐẦU MIGRATION AI RESPONSE SUGGESTION: {action_desc} ===")

    async with async_engine.begin() as conn:
        dialect = conn.dialect.name
        print(f"[*] Database dialect: {dialect}")

        if rollback:
            print("[*] Đang thực thi rollback: xóa các cột AI response suggestion...")
            for statement in ROLLBACK_SQL.strip().split(";"):
                stmt = statement.strip()
                if stmt:
                    await conn.execute(text(stmt))
            print("[✓] Đã drop thành công các cột AI response suggestion.")
        else:
            print("[*] Đang thực thi apply: thêm các cột AI response suggestion...")
            for statement in MIGRATION_SQL.strip().split(";"):
                stmt = statement.strip()
                if stmt:
                    await conn.execute(text(stmt))
            print("[✓] Đã thêm thành công các cột AI response suggestion vào ai_analysis.")

    print(f"=== MIGRATION AI RESPONSE SUGGESTION ({action_desc}) HOÀN TẤT THÀNH CÔNG ===")


def main():
    parser = argparse.ArgumentParser(description="Migration script for AI Response Suggestion columns")
    parser.add_argument("--rollback", action="store_true", help="Rollback migration by dropping added columns")
    args = parser.parse_args()

    asyncio.run(migrate(rollback=args.rollback))


if __name__ == "__main__":
    main()

