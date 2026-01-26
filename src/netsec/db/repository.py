"""Generic async repository for CRUD operations."""
from __future__ import annotations

from typing import Any, Generic, Sequence, TypeVar
from uuid import uuid4

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from netsec.models.base import Base

T = TypeVar("T", bound=Base)


class Repository(Generic[T]):
    """Base repository with common CRUD operations."""

    def __init__(self, session: AsyncSession, model: type[T]) -> None:
        self.session = session
        self.model = model

    async def get(self, id: str) -> T | None:
        return await self.session.get(self.model, id)

    async def get_all(
        self,
        *,
        offset: int = 0,
        limit: int = 100,
        order_by: str | None = None,
    ) -> Sequence[T]:
        stmt = select(self.model).offset(offset).limit(limit)
        if order_by and hasattr(self.model, order_by):
            stmt = stmt.order_by(getattr(self.model, order_by))
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count(self) -> int:
        stmt = select(func.count()).select_from(self.model)
        result = await self.session.execute(stmt)
        return result.scalar_one()

    async def create(self, **kwargs: Any) -> T:
        if "id" not in kwargs:
            kwargs["id"] = uuid4().hex
        obj = self.model(**kwargs)
        self.session.add(obj)
        await self.session.flush()
        return obj

    async def update(self, id: str, **kwargs: Any) -> T | None:
        obj = await self.get(id)
        if obj is None:
            return None
        for key, value in kwargs.items():
            if hasattr(obj, key):
                setattr(obj, key, value)
        await self.session.flush()
        return obj

    async def delete(self, id: str) -> bool:
        obj = await self.get(id)
        if obj is None:
            return False
        await self.session.delete(obj)
        await self.session.flush()
        return True
