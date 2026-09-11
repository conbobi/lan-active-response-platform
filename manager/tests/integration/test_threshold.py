import os
import sys
import asyncio

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from app.core.database import async_sessionmaker
from app.services.ml_anomaly_service import MLAnomalyService
from app.models.agent_history import AgentHistory
from sqlalchemy import delete


async def main():
    async with async_sessionmaker() as session:
        # 1. Tạo service với session
        svc = MLAnomalyService(session=session)
        
        agent_id = "test-threshold-agent"
        
        # 2. Dọn dữ liệu cũ (nếu có)
        await session.execute(
            delete(AgentHistory).where(AgentHistory.agent_id == agent_id)
        )
        await session.commit()
        
        # 3. Tạo 500 mẫu baseline giả lập agent idle
        #    CPU ~0.04%, RAM ~1%
        for i in range(500):
            session.add(AgentHistory(
                agent_id=agent_id,
                cpu=0.04 + (i % 5) * 0.01,   # 0.04 - 0.08
                ram=1.0 + (i % 3) * 0.01,    # 1.00 - 1.02
                disk=84.0
            ))
        await session.commit()
        
        # 4. Train baseline
        print("Training baseline...")
        await svc.train_baseline(agent_id)
        print("✓ Baseline trained")
        
        # 5. Test case 1: IDLE — CPU 0.52%, RAM 1.37%
        idle = await svc.score_telemetry(agent_id, {
            "cpu_usage": 0.52,
            "ram_usage": 1.37,
        })
        print(f"\n[IDLE]   is_anomaly={idle['is_anomaly']}, "
              f"score={idle.get('score')}, "
              f"z_reasons={idle.get('z_reasons')}")
        # Kỳ vọng: is_anomaly=False
        
        # 6. Test case 2: ATTACK — CPU 99%, RAM 95%
        attack = await svc.score_telemetry(agent_id, {
            "cpu_usage": 99.0,
            "ram_usage": 95.0,
        })
        print(f"[ATTACK] is_anomaly={attack['is_anomaly']}, "
              f"score={attack.get('score')}, "
              f"z_reasons={attack.get('z_reasons')}")
        # Kỳ vọng: is_anomaly=True
        
        # 7. Kết luận
        print("\n" + "="*50)
        if idle['is_anomaly'] is False and attack['is_anomaly'] is True:
            print("✅ PASS — Ngưỡng -0.05 hoạt động đúng")
        else:
            print("❌ FAIL — Cần điều chỉnh ngưỡng")
            print(f"   IDLE: expected False, got {idle['is_anomaly']}")
            print(f"   ATTACK: expected True, got {attack['is_anomaly']}")


if __name__ == "__main__":
    asyncio.run(main())