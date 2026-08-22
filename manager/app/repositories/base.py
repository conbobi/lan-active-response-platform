from abc import ABC, abstractmethod
from typing import Generic, TypeVar, Optional, List, Type, Any
from sqlalchemy import select, delete as sql_delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.base import Base

ModelType = TypeVar("ModelType", bound=Base)


class AbstractRepository(Generic[ModelType], ABC):
    @abstractmethod
    async def get(self, id: str) -> Optional[ModelType]:
        pass

    @abstractmethod
    async def list(self, skip: int = 0, limit: int = 100) -> List[ModelType]:
        pass

    @abstractmethod
    async def add(self, entity: ModelType) -> ModelType:
        pass

    @abstractmethod
    async def update(self, id: str, obj_in: Any) -> Optional[ModelType]:
        pass

    @abstractmethod
    async def delete(self, id: str) -> bool:
        pass


class SqlAlchemyRepository(AbstractRepository[ModelType]):
    def __init__(self, session: AsyncSession, model_class: Type[ModelType]):
        self.session = session
        self.model_class = model_class

    async def get(self, id: str) -> Optional[ModelType]:
        return await self.session.get(self.model_class, id)

    async def list(self, skip: int = 0, limit: int = 100) -> List[ModelType]:
        stmt = select(self.model_class).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def add(self, entity: ModelType) -> ModelType:
        self.session.add(entity)
        await self.session.flush()
        await self.session.refresh(entity)
        return entity

    async def update(self, id: str, obj_in: Any) -> Optional[ModelType]:
        obj = await self.get(id)
        if not obj:
            return None
        if isinstance(obj_in, dict):
            update_data = obj_in
        elif hasattr(obj_in, "model_dump"):
            update_data = obj_in.model_dump(exclude_unset=True)
        elif hasattr(obj_in, "dict"):
            update_data = obj_in.dict(exclude_unset=True)
        else:
            update_data = getattr(obj_in, "__dict__", {})

        for field, value in update_data.items():
            if hasattr(obj, field) and value is not None:
                setattr(obj, field, value)

        await self.session.flush()
        await self.session.refresh(obj)
        return obj

    async def delete(self, id: str) -> bool:
        obj = await self.get(id)
        if not obj:
            return False
        await self.session.delete(obj)
        await self.session.flush()
        return True