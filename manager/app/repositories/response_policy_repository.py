from typing import List, Optional
from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.response_policy import ResponsePolicy
from app.repositories.base import SqlAlchemyRepository


class ResponsePolicyRepository(SqlAlchemyRepository[ResponsePolicy]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, ResponsePolicy)

    async def list_all_ordered(self) -> List[ResponsePolicy]:
        stmt = (
            select(ResponsePolicy)
            .options(selectinload(ResponsePolicy.target_group))
            .order_by(ResponsePolicy.priority.desc(), ResponsePolicy.min_score.asc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_id_with_group(self, policy_id: str) -> Optional[ResponsePolicy]:
        stmt = (
            select(ResponsePolicy)
            .where(ResponsePolicy.id == policy_id)
            .options(selectinload(ResponsePolicy.target_group))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def find_matching_policies(
        self,
        score: float,
        group_ids: Optional[List[str]] = None
    ) -> List[ResponsePolicy]:
        """
        Tìm các policy đang kích hoạt (is_active=True) khớp với khoảng điểm:
        min_score <= score <= max_score.
        Nếu target_group_id được chỉ định trên policy, chỉ khớp nếu nằm trong group_ids của agent.
        Sắp xếp theo priority giảm dần (ưu tiên cao nhất lên đầu).
        """
        group_ids = group_ids or []
        conditions = [
            ResponsePolicy.is_active == True,  # noqa: E712
            ResponsePolicy.min_score <= score,
            ResponsePolicy.max_score >= score,
        ]

        if group_ids:
            group_cond = or_(
                ResponsePolicy.target_group_id.is_(None),
                ResponsePolicy.target_group_id.in_(group_ids)
            )
        else:
            group_cond = ResponsePolicy.target_group_id.is_(None)

        conditions.append(group_cond)

        stmt = (
            select(ResponsePolicy)
            .where(and_(*conditions))
            .options(selectinload(ResponsePolicy.target_group))
            .order_by(ResponsePolicy.priority.desc(), ResponsePolicy.min_score.desc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
