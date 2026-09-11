import os
import sys
import asyncio
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from app.core.database import AsyncSessionLocal
from app.services.ml_anomaly_service import MLAnomalyService
from app.services.risk_assessment_service import RiskAssessmentService
from app.models.agent import Agent
from app.models.agent_history import AgentHistory
from sqlalchemy import delete, select


async def main():
    async with AsyncSessionLocal() as session:
        agent_id = "test-e2e-phase2"
        
        # Ensure agent exists for FK constraint
        ag_stmt = select(Agent).where(Agent.id == agent_id)
        ag_res = await session.execute(ag_stmt)
        if not ag_res.scalar_one_or_none():
            session.add(Agent(
                id=agent_id,
                hostname=agent_id,
                ip_address="10.0.0.99",
                mac_address="aa:bb:cc:dd:ee:ff"
            ))
            await session.commit()

        # Cleanup old history
        await session.execute(delete(AgentHistory).where(AgentHistory.agent_id == agent_id))
        await session.commit()
        
        # Tạo 500 baseline
        import uuid
        for i in range(500):
            session.add(AgentHistory(
                id=str(uuid.uuid4()),
                agent_id=agent_id,
                cpu=0.04 + (i % 5) * 0.01,
                ram=1.0 + (i % 3) * 0.01,
                disk=84.0
            ))
        await session.commit()
        
        ml_svc = MLAnomalyService(session=session)
        await ml_svc.train_baseline(agent_id)
        
        # Test 1: Idle 5 chu kỳ → score phải = 0
        print("\n=== TEST 1: IDLE 5 chu kỳ ===")
        for i in range(5):
            r = await ml_svc.score_telemetry(agent_id, {
                "cpu_usage": 0.5, "ram_usage": 1.2
            })
            print(f"  Cycle {i+1}: anomaly={r['is_anomaly']}, points={r.get('risk_points', 0)}")
            assert r["is_anomaly"] is False, f"Idle cycle {i+1} báo anomaly!"
        print("  ✅ PASS — không false positive khi idle")
        
        # Test 2: Attack → anomaly + điểm <= 15
        print("\n=== TEST 2: ATTACK ===")
        r = await ml_svc.score_telemetry(agent_id, {
            "cpu_usage": 99.0, "ram_usage": 95.0
        })
        print(f"  anomaly={r['is_anomaly']}, points={r.get('risk_points')}")
        assert r["is_anomaly"] is True, "Attack không báo anomaly!"
        assert r["risk_points"] <= 15.0, f"Điểm vượt cap: {r['risk_points']}"
        print("  ✅ PASS — attack phát hiện, điểm <= 15")
        
        print("\n" + "="*50)
        print("✅ PHASE 2 E2E PASS")


if __name__ == "__main__":
    asyncio.run(main())
