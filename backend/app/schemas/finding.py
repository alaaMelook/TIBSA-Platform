"""
Pydantic schemas for Findings.
"""
from pydantic import BaseModel, ConfigDict
from typing import List, Optional
from datetime import datetime

class FindingBase(BaseModel):
    finding_id: str
    title: str
    severity: str
    category: str
    affected_url: str
    evidence: Optional[str] = None
    tags: List[str] = []

class FindingCreate(FindingBase):
    pass

class FindingResponse(FindingBase):
    id: str
    investigation_id: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
