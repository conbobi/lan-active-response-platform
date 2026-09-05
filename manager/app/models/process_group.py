import uuid
from typing import List, Optional
from sqlalchemy import String, JSON
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base, TimestampMixin


class ProcessGroup(Base, TimestampMixin):
    """Model representing a logical group of processes with matching patterns."""
    __tablename__ = "process_groups"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(
        String(128), unique=True, index=True, nullable=False
    )
    patterns: Mapped[List[str]] = mapped_column(
        JSON, default=list, nullable=False
    )
    description: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True, default=""
    )
