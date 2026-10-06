import asyncio
import logging
from typing import Callable, Any, List, Optional
from datetime import datetime, timezone

from app.core.config import settings
from app.core.database import AsyncSessionLocal

logger = logging.getLogger(__name__)


class Scheduler:
    """
    Background Task Scheduler managing periodic asynchronous jobs.
    """
    def __init__(self):
        self._tasks: List[asyncio.Task] = []
        self._running = False

    def schedule_task(self, interval_seconds: float, func: Callable, *args: Any, **kwargs: Any) -> asyncio.Task:
        """Schedule a function to run periodically at fixed interval_seconds."""
        async def loop():
            logger.info(f"Scheduled task '{func.__name__}' started with interval {interval_seconds}s.")
            while True:
                try:
                    await asyncio.sleep(interval_seconds)
                    if asyncio.iscoroutinefunction(func):
                        await func(*args, **kwargs)
                    else:
                        func(*args, **kwargs)
                except asyncio.CancelledError:
                    logger.info(f"Scheduled task '{func.__name__}' cancelled.")
                    break
                except Exception as e:
                    logger.error(f"Error in scheduled task '{func.__name__}': {e}", exc_info=True)

        task = asyncio.create_task(loop())
        self._tasks.append(task)
        return task

    def stop_all(self):
        """Cancel all running background tasks."""
        for task in self._tasks:
            if not task.done():
                task.cancel()
        self._tasks.clear()


async def start_background_tasks(scheduler: Optional[Scheduler] = None) -> Scheduler:
    """
    Initialize and start all application background tasks:
    - Dead agent sweep (periodic)
    - Threat feed sync (periodic)
    - ML anomaly baseline retrain (periodic)
    - Auto-rollback verification (periodic)
    """
    if scheduler is None:
        scheduler = Scheduler()

    logger.info("Dead Agent Sweep background task started")
    logger.info("Threat Feed Sync started")
    logger.info("ML Anomaly Training started")
    logger.info("Auto-Rollback background task started")

    # 1. Dead Agent Sweep (periodic)
    async def periodic_dead_agent_sweep():
        async with AsyncSessionLocal() as session:
            try:
                from app.services.agent.agent_service import AgentService
                agent_svc = AgentService(session)
                await agent_svc.sweep_dead_agents(
                    threshold_seconds=settings.DEAD_AGENT_TIMEOUT_SECONDS
                )
                await session.commit()
            except Exception as e:
                await session.rollback()
                logger.error(f"Error in dead agent sweep job: {e}", exc_info=True)

    scheduler.schedule_task(
        interval_seconds=settings.SWEEP_INTERVAL_SECONDS,
        func=periodic_dead_agent_sweep
    )

    # 2. Threat Feed Sync (every 6 hours)
    async def periodic_feed_sync():
        try:
            from app.services.detection.threat_intelligence_service import ThreatIntelligenceService
            async with AsyncSessionLocal() as session:
                ti_svc = ThreatIntelligenceService(session)
                await ti_svc.sync_all_feeds()
        except Exception as e:
            logger.error(f"Error in periodic threat feed sync: {e}")

    scheduler.schedule_task(21600, periodic_feed_sync)

    # 3. ML Anomaly Baseline Retrain (every 24 hours)
    async def periodic_ml_retrain():
        try:
            from app.repositories.agent_repository import AgentRepository
            from app.services.detection.ml_anomaly_service import MLAnomalyService
            async with AsyncSessionLocal() as session:
                agent_repo = AgentRepository(session)
                ml_svc = MLAnomalyService(session)
                agents = await agent_repo.list()
                for ag in agents:
                    await ml_svc.train_agent_baseline(ag.id)
        except Exception as e:
            logger.error(f"Error in periodic ML baseline retrain: {e}")

    scheduler.schedule_task(86400, periodic_ml_retrain)

    # 4. Auto-Rollback check (every 5 seconds)
    async def periodic_auto_rollback():
        try:
            from app.repositories.response_action_repository import ResponseActionRepository
            from app.services.response.rollback_service import RollbackService
            from app.services.common.setting_service import SettingService

            now = datetime.now(timezone.utc)
            async with AsyncSessionLocal() as session:
                setting_svc = SettingService(session)
                app_settings = await setting_svc.get_auto_rollback_settings()
                if not app_settings.get("enabled", True):
                    return

                action_repo = ResponseActionRepository(session)
                expired = await action_repo.get_expired_actions(now)
                if not expired:
                    return

                rollback_svc = RollbackService(session)
                for act in expired:
                    try:
                        logger.info(f"Auto-rollback triggering for action '{act.id}' (expired at {act.auto_rollback_at}).")
                        await rollback_svc.rollback_action(
                            action_id=act.id,
                            reason=f"Auto-rollback timeout expired (scheduled for {act.auto_rollback_at})",
                            actor="system"
                        )
                    except Exception as err:
                        logger.error(f"Error during auto-rollback of action '{act.id}': {err}")
        except Exception as e:
            logger.error(f"Error in periodic auto-rollback loop: {e}")

    scheduler.schedule_task(5, periodic_auto_rollback)

    return scheduler
