"""
Pydantic schemas for standardized API responses.
"""
from pydantic import BaseModel, ConfigDict
from typing import Generic, TypeVar, Optional

T = TypeVar('T')

class APIResponse(BaseModel, Generic[T]):
    success: bool
    message: Optional[str] = None
    data: Optional[T] = None

    model_config = ConfigDict(from_attributes=True)

class ErrorResponse(BaseModel):
    success: bool = False
    error: str

    model_config = ConfigDict(from_attributes=True)
