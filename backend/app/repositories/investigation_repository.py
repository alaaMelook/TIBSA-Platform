"""
Investigation data repository.
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from typing import List, Optional
from app.models.investigation import Investigation

class InvestigationRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_id(self, investigation_id: str) -> Optional[Investigation]:
        """Fetch investigation by ID with all related details eager-loaded."""
        stmt = (
            select(Investigation)
            .options(
                selectinload(Investigation.findings),
                selectinload(Investigation.assets),
                selectinload(Investigation.ti_reports),
                selectinload(Investigation.tm_reports)
            )
            .filter(Investigation.id == investigation_id)
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def get_by_scan_id(self, scan_id: str) -> Optional[Investigation]:
        """Fetch investigation by scan ID."""
        stmt = (
            select(Investigation)
            .options(
                selectinload(Investigation.findings),
                selectinload(Investigation.assets),
                selectinload(Investigation.ti_reports),
                selectinload(Investigation.tm_reports)
            )
            .filter(Investigation.scan_id == scan_id)
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def create(self, investigation: Investigation) -> Investigation:
        """Save a new investigation."""
        self.session.add(investigation)
        await self.session.commit()
        await self.session.refresh(investigation)
        return investigation

    async def update(self, investigation: Investigation) -> Investigation:
        """Update an existing investigation."""
        self.session.add(investigation)
        await self.session.commit()
        await self.session.refresh(investigation)
        return investigation

    async def list_all(self) -> List[Investigation]:
        """List all investigations, newest first."""
        stmt = select(Investigation).order_by(Investigation.started_at.desc())
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
