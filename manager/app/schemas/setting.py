from datetime import datetime
from typing import Dict, Any, Union
from pydantic import BaseModel
from app.schemas.base import ORMBaseModel


class SystemSettingUpdate(BaseModel):
    value: Union[Dict[str, Any], Any]


class SystemSettingOut(ORMBaseModel):
    id: str
    key: str
    value: Dict[str, Any]
    updated_at: datetime
