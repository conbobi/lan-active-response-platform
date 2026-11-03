"""
Migration script for AI Analysis table (Phase 3 — Layer 1 AI Investigation).
Tạo bảng ai_analysis để lưu kết quả tóm tắt, MITRE mapping, root cause và rating từ analyst.
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
CREATE TABLE IF NOT EXISTS ai_analysis (
    id VARCHAR(64) PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    analysis_type VARCHAR(32) NOT NULL DEFAULT 'triage',
    summary TEXT NOT NULL,
    mitre_techniques JSONB,
    root_cause TEXT,
    model_name VARCHAR(64),
    confidence FLOAT NOT NULL DEFAULT 0.0,
    analyst_rating VARCHAR(16),
    error_message TEXT,
    raw_response TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_analysis_incident_id ON ai_analysis(incident_id);
CREATE INDEX IF NOT EXISTS idx_ai_analysis_created_at ON ai_analysis(created_at);
"""

ROLLBACK_SQL = """
DROP TABLE IF EXISTS ai_analysis CASCADE;
"""


async def migrate(rollback: bool = False):
    action_desc = "ROLLBACK" if rollback else "APPLY"
    print(f"=== BẮT ĐẦU MIGRATION AI ANALYSIS: {action_desc} ===")

    async with async_engine.begin() as conn:
        dialect = conn.dialect.name
        print(f"[*] Database dialect: {dialect}")

        if rollback:
            print("[*] Đang thực thi rollback: xóa bảng ai_analysis...")
            for statement in ROLLBACK_SQL.strip().split(";"):
                stmt = statement.strip()
                if stmt:
                    await conn.execute(text(stmt))
            print("[✓] Đã drop thành công bảng ai_analysis.")
        else:
            print("[*] Đang thực thi apply: tạo bảng ai_analysis và indexes...")
            for statement in MIGRATION_SQL.strip().split(";"):
                stmt = statement.strip()
                if stmt:
                    await conn.execute(text(stmt))
            print("[✓] Đã tạo thành công bảng ai_analysis và các chỉ mục.")

    print(f"=== MIGRATION AI ANALYSIS ({action_desc}) HOÀN TẤT THÀNH CÔNG ===")


def main():
    parser = argparse.ArgumentParser(description="Migration script for AI Analysis table")
    parser.add_argument("--rollback", action="store_true", help="Rollback migration by dropping ai_analysis table")
    args = parser.parse_args()

    asyncio.run(migrate(rollback=args.rollback))


if __name__ == "__main__":
    main()
