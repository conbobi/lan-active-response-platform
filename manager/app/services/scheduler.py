import asyncio
import logging
from typing import Callable, Any, List

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