from abc import ABC
from typing import Generic, TypeVar, Optional
from app.repositories.base import AbstractRepository

RepositoryType = TypeVar("RepositoryType", bound=AbstractRepository)


class AbstractService(Generic[RepositoryType], ABC):
    """Abstract Base Class for Application Services."""
    def __init__(self, repository: Optional[RepositoryType] = None):
        self.repository = repository