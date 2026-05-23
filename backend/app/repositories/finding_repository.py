"""
Finding data repository.
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List
from app.models.finding import Finding

class FindingRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_many(self, findings: List[Finding]) -> List[Finding]:
        """Save a batch of findings in bulk."""
        if not findings:
            return []
        self.session.add_all(findings)
        await self.session.commit()
        return findings

    async def get_by_investigation(self, investigation_id: str) -> List[Finding]:
        """Fetch all findings associated with an investigation."""
        stmt = select(Finding).filter(Finding.investigation_id == investigation_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
