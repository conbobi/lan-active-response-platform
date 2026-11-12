import logging
from typing import Any, Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.models.process_info import ProcessInfo
from app.repositories.agent_repository import AgentRepository
from app.repositories.process_info_repository import ProcessInfoRepository
from app.services.response.response_policy_service import ResponsePolicyService
from app.services.agent.agent_group_service import AgentGroupService
from app.services.response.response_action_service import ResponseActionService
from app.services.common.audit_log_service import ActionAuditLogService
from app.services.common.setting_service import SettingService
from app.services.common.agent_protection import (
    is_agent_process,
    check_agent_kill_protection,
)
from app.schemas.response_policy import (
    PolicyEvaluateResponse,
    ResponsePolicyResponse,
    AffectedGroupInfo,
    SimulatedActionInfo,
)
from app.core.exceptions import NotFoundError

logger = logging.getLogger(__name__)

POLICY_LEVELS = [
    {"min_score": 0, "max_score": 29, "action": "log_only", "auto": True},
    {"min_score": 30, "max_score": 49, "action": "alert", "auto": True},
    {"min_score": 50, "max_score": 69, "action": "alert_with_action", "auto": False},
    {"min_score": 70, "max_score": 84, "action": "kill_process_tree", 
     "auto": True, "rollback_window": 300},
    {"min_score": 85, "max_score": 100, "action": "isolate", 
     "auto": True, "rollback_window": 300},
]


def get_action_for_score(score: float) -> dict:
    for level in POLICY_LEVELS:
        if level["min_score"] <= score <= level["max_score"]:
            return level
    if score >= 85:
        return POLICY_LEVELS[-1]
    return POLICY_LEVELS[0]


class PolicyEngineService:
    """
    Engine đánh giá chính sách phản ứng tự động (Policy Engine):
    - Đánh giá risk score đối chiếu với các ResponsePolicy đã cấu hình trong DB
    - Nếu không có custom ResponsePolicy khớp, kích hoạt Graduated Response 5 cấp độ:
      + 0-29: log_only (auto)
      + 30-49: alert (auto, không block)
      + 50-69: alert_with_action (auto=False, chờ analyst quyết định)
      + 70-84: kill_process_tree (auto, rollback 300s)
      + 85-100: isolate (auto, rollback 300s)
    - Xác định phạm vi ảnh hưởng (agent đơn lẻ hoặc toàn bộ group)
    - Hỗ trợ Dry-run Mode để kiểm tra trước hành động mà không can thiệp thực tế
    - Tự động kích hoạt phản ứng khi dry_run = False
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self.agent_repo = AgentRepository(session)
        self.policy_service = ResponsePolicyService(session)
        self.group_service = AgentGroupService(session)
        self.action_service = ResponseActionService(session)
        self.proc_repo = ProcessInfoRepository(session)
        self.audit_service = ActionAuditLogService(session)
        self.setting_service = SettingService(session)

    def _is_agent_process(self, process: Any) -> bool:
        """Check nếu process là LARP agent hoặc legitimate child."""
        return is_agent_process(process)

    async def _get_process_tree(self, agent_id: str) -> List[ProcessInfo]:
        """Lấy toàn bộ process tree của agent từ process_info."""
        import inspect
        try:
            res = self.proc_repo.find_by_agent(agent_id)
            if inspect.isawaitable(res):
                res = await res
            return list(res)
        except Exception as e:
            logger.debug(f"Could not load process tree for agent '{agent_id}': {e}")
            return []

    def _trace_ancestors(self, process_tree: List[ProcessInfo], target_pid: int) -> List[ProcessInfo]:
        """Lấy danh sách các ancestor processes của target_pid."""
        pid_map = {p.pid: p for p in process_tree}
        ancestors = []
        curr = pid_map.get(target_pid)
        visited = set()
        while curr and curr.parent_pid and curr.parent_pid not in visited:
            visited.add(curr.parent_pid)
            parent = pid_map.get(curr.parent_pid)
            if parent:
                ancestors.append(parent)
                curr = parent
            else:
                break
        return ancestors

    def _trace_descendants(self, process_tree: List[ProcessInfo], target_pid: int) -> List[ProcessInfo]:
        """Lấy danh sách các descendant processes của target_pid."""
        children_map: Dict[int, List[ProcessInfo]] = {}
        for p in process_tree:
            if p.parent_pid:
                children_map.setdefault(p.parent_pid, []).append(p)
        descendants = []
        queue = list(children_map.get(target_pid, []))
        visited = set()
        while queue:
            child = queue.pop(0)
            if child.pid in visited:
                continue
            visited.add(child.pid)
            descendants.append(child)
            queue.extend(children_map.get(child.pid, []))
        return descendants

    async def _dispatch_action(
        self,
        agent_id: str,
        action_type: str,
        target_pid: Optional[int] = None,
        action_params: Optional[Dict[str, Any]] = None,
        incident_id: Optional[str] = None,
        auto_rollback_seconds: Optional[int] = None,
        actor: str = "policy_engine"
    ) -> Dict[str, Any]:
        """Dispatch action với self-protection check — không kill/isolate agent process."""
        action_params = dict(action_params or {})

        # Check global auto-response flag (Monitor Mode check)
        setting = await self.setting_service.get_setting("auto_response_enabled", default=True)
        if isinstance(setting, dict):
            auto_enabled = setting.get("value", setting.get("data", True))
        elif setting is not None:
            auto_enabled = bool(setting)
        else:
            auto_enabled = True

        if not auto_enabled:
            logger.info(f"[MONITOR MODE] Would dispatch {action_type} for {agent_id} — skipped")
            try:
                await self.audit_service.record_event(
                    action_id=None,
                    event="would_dispatch",
                    actor=actor,
                    reason=f"Auto response disabled (Monitor Mode) — {action_type} skipped",
                    metadata={"action_type": action_type, "agent_id": agent_id, "params": action_params},
                )
            except Exception as audit_err:
                logger.debug(f"Audit log for would_dispatch skipped: {audit_err}")
            return {
                "agent_id": agent_id,
                "status": "monitor_only",
                "would_execute": action_type,
                "action_type": action_type
            }

        # Resolve target_pid if not directly passed
        if target_pid is None:
            raw_pid = action_params.get("pid") or action_params.get("target_pid")
            if raw_pid is not None:
                try:
                    target_pid = int(raw_pid)
                except (ValueError, TypeError):
                    target_pid = None

        if action_type in ("kill", "kill_process", "kill_process_tree") and target_pid is not None:
            process_tree = await self._get_process_tree(agent_id)
            allowed, block_reason = check_agent_kill_protection(process_tree, target_pid)
            if not allowed:
                logger.warning(
                    f"BLOCKED: kill action '{action_type}' targeting PID {target_pid} on agent '{agent_id}': {block_reason}"
                )
                return {
                    "agent_id": agent_id,
                    "status": "rejected",
                    "reason": block_reason,
                    "action_type": action_type,
                    "target_pid": target_pid
                }

        try:
            act = await self.action_service.create_and_apply_action(
                agent_id=agent_id,
                action_type=action_type,
                action_params=action_params,
                incident_id=incident_id,
                actor=actor,
                auto_rollback_seconds=auto_rollback_seconds
            )
            return {"action_id": act.id, "agent_id": agent_id, "status": "applied"}
        except Exception as e:
            logger.error(f"Policy engine failed to execute '{action_type}' on agent '{agent_id}': {e}", exc_info=True)
            return {"agent_id": agent_id, "status": "failed", "error": str(e)}

    async def evaluate_and_execute(
        self,
        agent_id: str,
        risk_score: float,
        context: Optional[Dict[str, Any]] = None,
        dry_run: bool = True,
        incident_id: Optional[str] = None
    ) -> PolicyEvaluateResponse:
        """
        Đánh giá điểm rủi ro của agent, xác định policy phù hợp và thực thi (hoặc dry-run).
        """
        agent = await self.agent_repo.get(agent_id)
        if not agent:
            raise NotFoundError(f"Agent with ID '{agent_id}' was not found.")

        # 1. Tìm các nhóm mà agent này trực thuộc
        agent_groups = await self.group_service.list_groups_for_agent(agent_id)
        group_ids = [g.id for g in agent_groups]

        # 2. Tìm Response Policy khớp với score và group từ DB
        matched_policy = await self.policy_service.match_policy(risk_score, group_ids)

        if not matched_policy:
            level = get_action_for_score(risk_score)
            logger.info(
                f"[GRADUATED RESPONSE] Agent '{agent_id}' score {risk_score:.2f} -> "
                f"Level '{level['action']}' (score {level['min_score']}-{level['max_score']}, auto={level['auto']})"
            )
            if not level["auto"]:
                # Chỉ alert, tạo incident với nút "Action" trên UI
                return await self._create_alert_only(agent, risk_score, level, context=context, incident_id=incident_id, dry_run=dry_run)
            # Auto action
            return await self._execute(agent, level["action"], risk_score, level, context=context, incident_id=incident_id, dry_run=dry_run)

        policy_dto = ResponsePolicyResponse.model_validate(matched_policy)
        if matched_policy.target_group:
            policy_dto.target_group_name = matched_policy.target_group.name

        # 3. Xác định phạm vi tác động (Scope & Target Agents)
        scope = matched_policy.scope
        affected_groups: List[AffectedGroupInfo] = []
        target_agents: List[Agent] = []

        if scope == "agent":
            # Chỉ tác động duy nhất lên agent gây ra rủi ro
            target_agents = [agent]
        elif scope == "group":
            # Tác động lên toàn bộ agent trong các nhóm liên quan
            relevant_groups = []
            if matched_policy.target_group_id:
                # Nếu policy chỉ định cụ thể nhóm
                for g in agent_groups:
                    if g.id == matched_policy.target_group_id:
                        relevant_groups.append(g)
                if not relevant_groups:
                    # Nếu agent không thuộc nhóm này nhưng policy khớp, vẫn lấy group chỉ định
                    tg = await self.group_service.get_group(matched_policy.target_group_id)
                    if tg:
                        relevant_groups.append(tg)
            else:
                # Nếu policy không gán target_group_id cụ thể, lấy tất cả nhóm mà agent này trực thuộc
                relevant_groups = agent_groups

            # Thu thập các agent duy nhất trong các nhóm trên
            unique_agents: Dict[str, Agent] = {}
            for g in relevant_groups:
                affected_groups.append(AffectedGroupInfo(id=g.id, name=g.name))
                group_agents = await self.group_service.list_agents_in_group(g.id)
                for ga in group_agents:
                    unique_agents[ga.id] = ga

            if unique_agents:
                target_agents = list(unique_agents.values())
            else:
                # Fallback: nếu agent chưa được phân vào nhóm nào, scope group sẽ chỉ tác động chính agent đó
                target_agents = [agent]
                logger.warning(f"Agent '{agent_id}' has scope 'group' but belongs to no groups. Falling back to agent.")

        # 4. Tạo danh sách hành động mô phỏng (Simulated Actions)
        simulated_actions = [
            SimulatedActionInfo(
                agent_id=a.id,
                hostname=a.hostname,
                ip_address=a.ip_address,
                action_type=matched_policy.action_type,
                auto_rollback_seconds=matched_policy.auto_rollback_seconds
            )
            for a in target_agents
        ]

        affected_agents_info = [
            {
                "id": a.id,
                "hostname": a.hostname,
                "ip": a.ip_address,
                "status": a.status.value if hasattr(a.status, "value") else str(a.status),
                "is_isolated": getattr(a, "is_isolated", False)
            }
            for a in target_agents
        ]

        # 5. Nếu dry_run = True -> Trả về kết quả dự kiến mà không can thiệp hệ thống
        if dry_run:
            logger.info(
                f"[DRY-RUN] Evaluated policy '{matched_policy.name}' for agent '{agent_id}' "
                f"(score: {risk_score}) -> {len(target_agents)} agents would be targeted with '{matched_policy.action_type}'."
            )
            return PolicyEvaluateResponse(
                dry_run=True,
                agent_id=agent_id,
                risk_score=risk_score,
                matched_policy=policy_dto,
                scope=scope,
                action_type=matched_policy.action_type,
                affected_groups=affected_groups,
                affected_agents=affected_agents_info,
                simulated_actions=simulated_actions,
                executed=False,
                execution_summary={"status": "dry_run_completed", "simulated_count": len(target_agents)}
            )

        # 6. Nếu dry_run = False -> Thực thi phản ứng thật
        logger.warning(
            f"[LIVE EXECUTION] Executing policy '{matched_policy.name}' for agent '{agent_id}' "
            f"(score: {risk_score}) -> action '{matched_policy.action_type}' on scope '{scope}'."
        )

        executed_actions = []
        action_params = dict(matched_policy.action_params)
        action_params["trigger_agent_id"] = agent_id
        action_params["trigger_score"] = risk_score
        action_params["policy_id"] = matched_policy.id
        action_params["policy_name"] = matched_policy.name
        action_params["reason"] = f"Auto policy '{matched_policy.name}' triggered by score {risk_score}"

        # Resolve incident_id from context if not explicitly provided
        effective_incident_id = incident_id
        if not effective_incident_id and context and isinstance(context, dict):
            effective_incident_id = context.get("incident_id")

        if scope == "agent":
            target_pid = action_params.get("pid") or action_params.get("target_pid")
            if not target_pid and context and isinstance(context, dict):
                target_pid = context.get("pid")
            res = await self._dispatch_action(
                agent_id=agent_id,
                action_type=matched_policy.action_type,
                target_pid=int(target_pid) if target_pid is not None else None,
                action_params=action_params,
                incident_id=effective_incident_id,
                auto_rollback_seconds=matched_policy.auto_rollback_seconds,
                actor="policy_engine"
            )
            executed_actions.append(res)

        elif scope == "group":
            for g in affected_groups:
                try:
                    res = await self.group_service.execute_group_action(
                        group_id=g.id,
                        action_type=matched_policy.action_type,
                        action_params=action_params,
                        incident_id=effective_incident_id,
                        actor="policy_engine",
                        auto_rollback_seconds=matched_policy.auto_rollback_seconds
                    )
                    for item in res.actions:
                        executed_actions.append({
                            "action_id": item.action_id,
                            "agent_id": item.agent_id,
                            "group_id": g.id,
                            "status": item.status,
                            "error": item.error
                        })
                except Exception as e:
                    logger.error(f"Policy engine failed on group '{g.id}': {e}", exc_info=True)

        return PolicyEvaluateResponse(
            dry_run=False,
            agent_id=agent_id,
            risk_score=risk_score,
            matched_policy=policy_dto,
            scope=scope,
            action_type=matched_policy.action_type,
            affected_groups=affected_groups,
            affected_agents=affected_agents_info,
            simulated_actions=simulated_actions,
            executed=True,
            execution_summary={
                "status": "executed",
                "total_executed": len(executed_actions),
                "details": executed_actions
            }
        )

    async def _create_alert_only(
        self,
        agent: Agent,
        risk_score: float,
        level: dict,
        context: Optional[Dict[str, Any]] = None,
        incident_id: Optional[str] = None,
        dry_run: bool = False
    ) -> PolicyEvaluateResponse:
        """Chỉ alert, tạo incident với nút Action trên UI (chờ analyst quyết định)."""
        logger.warning(
            f"[GRADUATED RESPONSE] Agent '{agent.id}' (score: {risk_score:.2f}) triggered '{level['action']}'. "
            f"Auto-action is disabled (auto=False). Alert generated with manual action button on UI."
        )
        policy_dto = ResponsePolicyResponse(
            id=f"graduated_{level['action']}",
            name=f"Graduated Policy ({level['action']})",
            description=f"Graduated response level for score {level['min_score']}-{level['max_score']}: Alert with analyst action button",
            min_score=float(level["min_score"]),
            max_score=float(level["max_score"]),
            action_type=level["action"],
            scope="agent",
            target_group_id=None,
            target_group_name=None,
            action_params={"auto": False, "requires_analyst": True},
            auto_rollback_seconds=None,
            priority=0,
            is_active=True
        )
        return PolicyEvaluateResponse(
            dry_run=dry_run,
            agent_id=agent.id,
            risk_score=risk_score,
            matched_policy=policy_dto,
            scope="agent",
            action_type=level["action"],
            affected_groups=[],
            affected_agents=[{
                "id": agent.id,
                "hostname": agent.hostname,
                "ip": agent.ip_address,
                "status": agent.status.value if hasattr(agent.status, "value") else str(agent.status),
                "is_isolated": getattr(agent, "is_isolated", False)
            }],
            simulated_actions=[],
            executed=False,
            execution_summary={
                "status": "alert_with_action",
                "action": level["action"],
                "auto": False,
                "message": "Graduated response: alert generated. Action requires analyst confirmation."
            }
        )

    async def _execute(
        self,
        agent: Agent,
        action: str,
        risk_score: float,
        level: dict,
        context: Optional[Dict[str, Any]] = None,
        incident_id: Optional[str] = None,
        dry_run: bool = False
    ) -> PolicyEvaluateResponse:
        """Thực thi hành động tự động theo cấp độ phản ứng graduated."""
        rollback_window = level.get("rollback_window", 300) if action in ("kill_process_tree", "isolate") else None

        policy_dto = ResponsePolicyResponse(
            id=f"graduated_{action}",
            name=f"Graduated Policy ({action})",
            description=f"Graduated response auto policy for score {level['min_score']}-{level['max_score']}",
            min_score=float(level["min_score"]),
            max_score=float(level["max_score"]),
            action_type=action,
            scope="agent",
            target_group_id=None,
            target_group_name=None,
            action_params={"auto": True},
            auto_rollback_seconds=rollback_window,
            priority=0,
            is_active=True
        )

        simulated_actions = [
            SimulatedActionInfo(
                agent_id=agent.id,
                hostname=agent.hostname,
                ip_address=agent.ip_address,
                action_type=action,
                auto_rollback_seconds=rollback_window
            )
        ]

        affected_agents_info = [{
            "id": agent.id,
            "hostname": agent.hostname,
            "ip": agent.ip_address,
            "status": agent.status.value if hasattr(agent.status, "value") else str(agent.status),
            "is_isolated": getattr(agent, "is_isolated", False)
        }]

        if dry_run:
            logger.info(
                f"[DRY-RUN] Graduated response evaluated '{action}' for agent '{agent.id}' (score: {risk_score:.2f})."
            )
            return PolicyEvaluateResponse(
                dry_run=True,
                agent_id=agent.id,
                risk_score=risk_score,
                matched_policy=policy_dto,
                scope="agent",
                action_type=action,
                affected_groups=[],
                affected_agents=affected_agents_info,
                simulated_actions=simulated_actions,
                executed=False,
                execution_summary={"status": "dry_run_completed", "action": action}
            )

        if action == "log_only":
            logger.info(f"[GRADUATED RESPONSE] Agent '{agent.id}' (score: {risk_score:.2f}) -> log_only (no block).")
            return PolicyEvaluateResponse(
                dry_run=False,
                agent_id=agent.id,
                risk_score=risk_score,
                matched_policy=policy_dto,
                scope="agent",
                action_type=action,
                affected_groups=[],
                affected_agents=affected_agents_info,
                simulated_actions=simulated_actions,
                executed=True,
                execution_summary={"status": "logged", "reason": "Risk score within normal threshold"}
            )

        if action == "alert":
            logger.info(f"[GRADUATED RESPONSE] Agent '{agent.id}' (score: {risk_score:.2f}) -> alert only (no block).")
            return PolicyEvaluateResponse(
                dry_run=False,
                agent_id=agent.id,
                risk_score=risk_score,
                matched_policy=policy_dto,
                scope="agent",
                action_type=action,
                affected_groups=[],
                affected_agents=affected_agents_info,
                simulated_actions=simulated_actions,
                executed=True,
                execution_summary={"status": "alert_only", "reason": "Low-to-medium risk alert triggered"}
            )

        # Auto blocking actions: kill_process_tree, isolate
        logger.warning(
            f"[GRADUATED RESPONSE LIVE] Executing graduated auto-action '{action}' for agent '{agent.id}' "
            f"(score: {risk_score:.2f}, rollback: {rollback_window}s)."
        )

        effective_incident_id = incident_id
        if not effective_incident_id and context and isinstance(context, dict):
            effective_incident_id = context.get("incident_id")

        action_params = {
            "trigger_agent_id": agent.id,
            "trigger_score": risk_score,
            "policy_name": f"Graduated Response ({action})",
            "reason": f"Graduated auto action '{action}' triggered by score {risk_score:.2f} (rollback: {rollback_window}s)",
            "auto_rollback_seconds": rollback_window
        }
        if context and isinstance(context, dict):
            if "pid" in context:
                action_params["pid"] = context["pid"]
            if "process_name" in context:
                action_params["process_name"] = context["process_name"]

        executed_actions = []
        target_pid = action_params.get("pid") or action_params.get("target_pid")
        res = await self._dispatch_action(
            agent_id=agent.id,
            action_type=action,
            target_pid=int(target_pid) if target_pid is not None else None,
            action_params=action_params,
            incident_id=effective_incident_id,
            auto_rollback_seconds=rollback_window,
            actor="policy_engine"
        )
        executed_actions.append(res)

        return PolicyEvaluateResponse(
            dry_run=False,
            agent_id=agent.id,
            risk_score=risk_score,
            matched_policy=policy_dto,
            scope="agent",
            action_type=action,
            affected_groups=[],
            affected_agents=affected_agents_info,
            simulated_actions=simulated_actions,
            executed=True,
            execution_summary={
                "status": "executed",
                "action": action,
                "rollback_window": rollback_window,
                "total_executed": len(executed_actions),
                "details": executed_actions
            }
        )

