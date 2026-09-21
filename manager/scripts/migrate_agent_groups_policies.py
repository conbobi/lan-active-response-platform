"""
Migration script for Group-Based Execution & Response Policies (v1.4).
Tạo các bảng agent_groups, agent_group_members, response_policies và seed dữ liệu mặc định.
Đảm bảo tính Idempotent (chạy nhiều lần không lỗi, không ghi đè dữ liệu đã có).
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


DEFAULT_GROUPS = [
    {"id": "grp_hr", "name": "HR", "description": "Human Resources Department"},
    {"id": "grp_it", "name": "IT", "description": "Information Technology Department"},
    {"id": "grp_finance", "name": "Finance", "description": "Finance & Accounting Department"},
    {"id": "grp_server", "name": "Server", "description": "Core Infrastructure & Server Zone"},
]

DEFAULT_POLICIES = [
    {
        "id": "pol_alert_agent",
        "name": "Moderate Risk Alert",
        "description": "Trigger alert notification for moderate risk score (30 - 49)",
        "min_score": 30.0,
        "max_score": 49.99,
        "action_type": "alert",
        "scope": "agent",
        "target_group_id": None,
        "action_params": {},
        "auto_rollback_seconds": None,
        "priority": 10,
        "is_active": True
    },
    {
        "id": "pol_block_ip_agent",
        "name": "High Risk Block IP",
        "description": "Block suspicious remote IP on host for score (50 - 69)",
        "min_score": 50.0,
        "max_score": 69.99,
        "action_type": "block_ip",
        "scope": "agent",
        "target_group_id": None,
        "action_params": {},
        "auto_rollback_seconds": 300,
        "priority": 20,
        "is_active": True
    },
    {
        "id": "pol_isolate_agent",
        "name": "Severe Risk Isolate Agent",
        "description": "Network isolate single compromised host for score (70 - 84)",
        "min_score": 70.0,
        "max_score": 84.99,
        "action_type": "isolate",
        "scope": "agent",
        "target_group_id": None,
        "action_params": {},
        "auto_rollback_seconds": 300,
        "priority": 30,
        "is_active": True
    },
    {
        "id": "pol_isolate_group",
        "name": "Critical Risk Isolate Group",
        "description": "Isolate entire department / network zone when critical score (85+)",
        "min_score": 85.0,
        "max_score": 100.0,
        "action_type": "isolate",
        "scope": "group",
        "target_group_id": None,
        "action_params": {},
        "auto_rollback_seconds": 300,
        "priority": 40,
        "is_active": True
    },
]


async def main():
    print("=== BẮT ĐẦU MIGRATION: AGENT GROUPS & RESPONSE POLICIES ===")
    async with async_engine.begin() as conn:
        dialect = conn.dialect.name
        print(f"[*] Database dialect: {dialect}")

        # 1. Tạo tất cả bảng mới từ Base metadata
        print("[*] Đang kiểm tra và tạo bảng mới: agent_groups, agent_group_members, response_policies...")
        await conn.run_sync(Base.metadata.create_all)
        print("[✓] Đã đảm bảo tồn tại các bảng mới.")

        # 2. Seed default Agent Groups
        print("[*] Đang seed default Agent Groups...")
        for grp in DEFAULT_GROUPS:
            res = await conn.execute(
                text("SELECT id FROM agent_groups WHERE name = :name"),
                {"name": grp["name"]}
            )
            row = res.fetchone()
            if row:
                print(f"[✓] Group '{grp['name']}' đã tồn tại (ID: {row[0]}), bỏ qua")
            else:
                await conn.execute(
                    text(
                        "INSERT INTO agent_groups (id, name, description, created_at, updated_at) "
                        "VALUES (:id, :name, :description, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                    ),
                    grp
                )
                print(f"[✓] Đã tạo group '{grp['name']}' (ID: {grp['id']})")

        # 3. Seed default Response Policies
        print("[*] Đang seed default Response Policies...")
        for pol in DEFAULT_POLICIES:
            res = await conn.execute(
                text("SELECT id FROM response_policies WHERE id = :id"),
                {"id": pol["id"]}
            )
            row = res.fetchone()
            if row:
                print(f"[✓] Policy '{pol['name']}' đã tồn tại, bỏ qua")
            else:
                await conn.execute(
                    text(
                        "INSERT INTO response_policies (id, name, description, min_score, max_score, "
                        "action_type, scope, target_group_id, action_params, auto_rollback_seconds, priority, is_active, created_at, updated_at) "
                        "VALUES (:id, :name, :description, :min_score, :max_score, "
                        ":action_type, :scope, :target_group_id, :action_params, :auto_rollback_seconds, :priority, :is_active, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                    ),
                    {
                        **pol,
                        "action_params": json.dumps(pol["action_params"])
                    }
                )
                print(f"[✓] Đã tạo policy '{pol['name']}' (Score: {pol['min_score']}-{pol['max_score']} -> {pol['action_type']} -> {pol['scope']})")

        # 4. Map client1, client2 -> HR; client3, client4 -> IT (nếu agent tồn tại)
        client_group_map = [
            ("client1", "grp_hr"),
            ("client2", "grp_hr"),
            ("client3", "grp_it"),
            ("client4", "grp_it"),
        ]
        for agent_id, group_id in client_group_map:
            # Check agent exists
            ag_res = await conn.execute(
                text("SELECT id FROM agents WHERE id = :id"),
                {"id": agent_id}
            )
            if ag_res.fetchone():
                # Check member exists
                m_res = await conn.execute(
                    text("SELECT group_id FROM agent_group_members WHERE group_id = :gid AND agent_id = :aid"),
                    {"gid": group_id, "aid": agent_id}
                )
                if not m_res.fetchone():
                    await conn.execute(
                        text("INSERT INTO agent_group_members (group_id, agent_id, added_at) VALUES (:gid, :aid, CURRENT_TIMESTAMP)"),
                        {"gid": group_id, "aid": agent_id}
                    )
                    print(f"[✓] Đã thêm agent '{agent_id}' vào nhóm '{group_id}'")

    print("=== MIGRATION AGENT GROUPS & POLICIES HOÀN TẤT THÀNH CÔNG ===")


if __name__ == "__main__":
    asyncio.run(main())
