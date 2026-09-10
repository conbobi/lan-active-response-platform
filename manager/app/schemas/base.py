from pydantic import BaseModel, ConfigDict



class ORMBaseModel(BaseModel):
    """Base Pydantic schema configured for ORM mode (from_attributes)."""
    model_config = ConfigDict(from_attributes=True)