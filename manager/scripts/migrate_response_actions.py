"""
Migration script for Stateful Response & Auto Rollback.
Tạo các bảng response_actions, action_audit_logs và cấu hình default trong system_settings.
Đảm bảo tính Idempotent (chạy nhiều lần không lỗi).
"""
import asyncio
import os
import sys
import uuid
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sqlalchemy import text
from app.core.database import async_engine
from app.models.base import Base
import app.models  # noqa: F401


async def main():
    print("=== BẮT ĐẦU MIGRATION: RESPONSE ACTIONS & AUDIT LOGS ===")
    async with async_engine.begin() as conn:
        dialect = conn.dialect.name
        print(f"[*] Database dialect: {dialect}")

        # 1. Tạo tất cả bảng chưa tồn tại thông qua Base.metadata
        print("[*] Đang kiểm tra và tạo bảng mới từ Base metadata...")
        await conn.run_sync(Base.metadata.create_all)
        print("[✓] Đã đảm bảo tồn tại các bảng response_actions, action_audit_logs")

        # 2. Tạo index ix_response_actions_auto_rollback nếu chưa có
        try:
            if dialect == "postgresql":
                await conn.execute(text(
                    "CREATE INDEX IF NOT EXISTS ix_response_actions_auto_rollback "
                    "ON response_actions (status, auto_rollback_at);"
                ))
            elif dialect == "sqlite":
                await conn.execute(text(
                    "CREATE INDEX IF NOT EXISTS ix_response_actions_auto_rollback "
                    "ON response_actions (status, auto_rollback_at);"
                ))
            print("[✓] Index ix_response_actions_auto_rollback đã sẵn sàng")
        except Exception as e:
            print(f"[!] Warning tạo index: {e}")

        # 3. Seed system_settings cho auto-rollback (nếu chưa có)
        default_settings = [
            {
                "key": "auto_rollback_timeout_seconds",
                "value": {"value": 300, "description": "Thời gian timeout tự động rollback action (giây)"}
            },
            {
                "key": "auto_rollback_enabled",
                "value": {"value": True, "description": "Bật/tắt tính năng auto-rollback khi hết timeout"}
            },
            {
                "key": "rollback_cooldown_seconds",
                "value": {"value": 600, "description": "Thời gian cooldown chống flapping sau khi rollback (giây)"}
            }
        ]

        for s in default_settings:
            key = s["key"]
            val_json = json.dumps(s["value"])
            # Kiểm tra key đã tồn tại chưa
            res = await conn.execute(
                text("SELECT id FROM system_settings WHERE key = :key"),
                {"key": key}
            )
            row = res.fetchone()
            if row:
                print(f"[✓] Setting '{key}' đã tồn tại, bỏ qua")
            else:
                setting_id = str(uuid.uuid4())
                await conn.execute(
                    text(
                        "INSERT INTO system_settings (id, key, value, updated_at) "
                        "VALUES (:id, :key, :val, CURRENT_TIMESTAMP)"
                    ),
                    {"id": setting_id, "key": key, "val": val_json}
                )
                print(f"[✓] Đã tạo default setting '{key}' = {val_json}")

    print("=== MIGRATION HOÀN TẤT THÀNH CÔNG ===")


if __name__ == "__main__":
    asyncio.run(main())
