"""Resume durable collection, monitoring and lab enforcement after restart."""
from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.models.response_action import ResponseAction
from app.services.agent.network_service import expire_commands
from app.services.response.http_investigation import ASSIST_TYPES, COLLECT, REVOKE
from app.services.response.manager_investigation import reconcile_watch
from app.services.response.waf_reconciliation import reconcile


async def reconcile_pending():
    # Keyset pagination avoids starving old leases behind terminal rows.
    cursor = ""
    while True:
        async with AsyncSessionLocal.begin() as db:
            rows = list(await db.scalars(select(ResponseAction.id).where(
                ResponseAction.id > cursor, ResponseAction.action_type.in_(ASSIST_TYPES),
                ResponseAction.status.in_(("dispatched", "executing", "verifying", "monitoring", "succeeded",
                                           "partial", "rollback_failed")),
                ~((ResponseAction.action_type.in_((COLLECT, REVOKE, "generate_remediation_guidance")))
                  & ResponseAction.status.in_(("succeeded", "partial"))),
            ).order_by(ResponseAction.id).limit(50)))
        if not rows:
            return
        for key in rows:
            async with AsyncSessionLocal.begin() as db:
                row = await db.get(ResponseAction, key)
                if not row:
                    continue
                if row.action_type == COLLECT:
                    await expire_commands(db, row.agent_id)
                else:
                    await reconcile(db, row)
                    await reconcile_watch(db, row)
        cursor = rows[-1]
