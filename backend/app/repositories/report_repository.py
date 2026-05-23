"""
Threat Intelligence and Threat Modeling Report data repository.
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import Optional
from app.models.ti_report import TIReport
from app.models.tm_report import TMReport

class ReportRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_ti_report(self, report: TIReport) -> TIReport:
        """Create a threat intelligence report."""
        self.session.add(report)
        await self.session.commit()
        await self.session.refresh(report)
        return report

    async def create_tm_report(self, report: TMReport) -> TMReport:
        """Create a threat modeling report."""
        self.session.add(report)
        await self.session.commit()
        await self.session.refresh(report)
        return report

    async def get_ti_by_investigation(self, investigation_id: str) -> Optional[TIReport]:
        """Get the TI report for a specific investigation."""
        stmt = select(TIReport).filter(TIReport.investigation_id == investigation_id)
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def get_tm_by_investigation(self, investigation_id: str) -> Optional[TMReport]:
        """Get the TM report for a specific investigation."""
        stmt = select(TMReport).filter(TMReport.investigation_id == investigation_id)
        result = await self.session.execute(stmt)
        return result.scalars().first()
