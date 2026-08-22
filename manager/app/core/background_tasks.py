# app/core/background_tasks.py
import asyncio
from app.core.database import async_session
from app.services.rule_engine import RuleEngine
from app.services.action_service import ActionService

async def risk_assessment_loop():
    while True:
        await asyncio.sleep(5)
        try:
            async with async_session() as db:
                engine = RuleEngine(db)
                action_svc = ActionService(db)
                score, details = await engine.calculate_risk_score()
                if score > 0:
                    print(f"[RiskEngine] Score = {score}, details = {details}")
                    await action_svc.evaluate_and_act(score, details)
        except Exception as e:
            print(f"[Lỗi Risk Assessment Loop]: {e}")

# Bạn có thể thêm các task khác (nếu cần) hoặc tách network monitor