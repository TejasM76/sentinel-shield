"""
Data access layer for SentinelShield AI Security Platform
Repository pattern implementation for clean data operations
"""

from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func, desc, asc, text
from sqlalchemy.orm import selectinload
import logging

from app.db.models import (
    ScanResult, Incident, Alert, AgentSession, AgentAction, 
    RedTeamJob, ComplianceReport, AuditLog, RiskLevel, ThreatType
)

logger = logging.getLogger(__name__)


class ScanResultRepository:
    """Repository for scan result operations"""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def create(self, scan_result: ScanResult) -> ScanResult:
        """Create a new scan result"""
        self.session.add(scan_result)
        await self.session.commit()
        await self.session.refresh(scan_result)
        return scan_result
    
    async def get_by_id(self, scan_id: str) -> Optional[ScanResult]:
        """Get scan result by ID"""
        stmt = select(ScanResult).where(ScanResult.scan_id == scan_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_by_user(self, user_id: str, limit: int = 100) -> List[ScanResult]:
        """Get scan results for a user"""
        stmt = (
            select(ScanResult)
            .where(ScanResult.user_id == user_id)
            .order_by(desc(ScanResult.timestamp))
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
    
    async def get_by_session(self, session_id: str, limit: int = 100) -> List[ScanResult]:
        """Get scan results for a session"""
        stmt = (
            select(ScanResult)
            .where(ScanResult.session_id == session_id)
            .order_by(desc(ScanResult.timestamp))
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
    
    async def get_by_risk_level(self, risk_level: RiskLevel, hours: int = 24) -> List[ScanResult]:
        """Get scan results by risk level in time window"""
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        stmt = (
            select(ScanResult)
            .where(
                and_(
                    ScanResult.risk_level == risk_level,
                    ScanResult.timestamp >= since
                )
            )
            .order_by(desc(ScanResult.timestamp))
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
    
    async def get_threat_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get threat detection statistics"""
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        # Total scans
        total_stmt = select(func.count(ScanResult.id)).where(ScanResult.timestamp >= since)
        total_result = await self.session.execute(total_stmt)
        total_scans = total_result.scalar()
        
        # Blocked scans
        blocked_stmt = select(func.count(ScanResult.id)).where(
            and_(
                ScanResult.timestamp >= since,
                ScanResult.blocked == True
            )
        )
        blocked_result = await self.session.execute(blocked_stmt)
        blocked_scans = blocked_result.scalar()
        
        # Risk level breakdown
        risk_stmt = (
            select(ScanResult.risk_level, func.count(ScanResult.id))
            .where(ScanResult.timestamp >= since)
            .group_by(ScanResult.risk_level)
        )
        risk_result = await self.session.execute(risk_stmt)
        risk_breakdown = dict(risk_result.all())
        
        # Threat type breakdown
        threat_stmt = text("""
            SELECT jsonb_array_elements_text(threat_types) as threat_type, COUNT(*)
            FROM scan_results 
            WHERE timestamp >= :since AND threat_types IS NOT NULL
            GROUP BY threat_type
        """)
        threat_result = await self.session.execute(threat_stmt, {"since": since})
        threat_breakdown = dict(threat_result.all())
        
        return {
            "total_scans": total_scans,
            "blocked_scans": blocked_scans,
            "block_rate": blocked_scans / total_scans if total_scans > 0 else 0,
            "risk_breakdown": risk_breakdown,
            "threat_breakdown": threat_breakdown,
            "period_hours": hours,
        }
    
    async def get_average_processing_time(self, hours: int = 24) -> float:
        """Get average processing time in milliseconds"""
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        stmt = select(func.avg(ScanResult.processing_time_ms)).where(
            ScanResult.timestamp >= since
        )
        result = await self.session.execute(stmt)
        avg_time = result.scalar()
        return float(avg_time) if avg_time else 0.0


class IncidentRepository:
    """Repository for incident operations"""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def create(self, incident: Incident) -> Incident:
        """Create a new incident"""
        self.session.add(incident)
        await self.session.commit()
        await self.session.refresh(incident)
        return incident
    
    async def get_by_id(self, incident_id: str) -> Optional[Incident]:
        """Get incident by ID"""
        stmt = select(Incident).where(Incident.incident_id == incident_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_open_incidents(self) -> List[Incident]:
        """Get all open incidents"""
        stmt = (
            select(Incident)
            .where(Incident.status.in_(["OPEN", "INVESTIGATING"]))
            .order_by(desc(Incident.timestamp))
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
    
    async def get_by_severity(self, severity: str, days: int = 7) -> List[Incident]:
        """Get incidents by severity"""
        since = datetime.now(timezone.utc) - timedelta(days=days)
        stmt = (
            select(Incident)
            .where(
                and_(
                    Incident.severity == severity,
                    Incident.timestamp >= since
                )
            )
            .order_by(desc(Incident.timestamp))
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
    
    async def update_status(self, incident_id: str, status: str, resolved_by: Optional[str] = None) -> Optional[Incident]:
        """Update incident status"""
        stmt = select(Incident).where(Incident.incident_id == incident_id)
        result = await self.session.execute(stmt)
        incident = result.scalar_one_or_none()
        
        if incident:
            incident.status = status
            if status == "RESOLVED" or status == "CLOSED":
                incident.resolved_at = datetime.now(timezone.utc)
                incident.resolved_by = resolved_by
            await self.session.commit()
            await self.session.refresh(incident)
        
        return incident


class AgentSessionRepository:
    """Repository for agent session operations"""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def create(self, session: AgentSession) -> AgentSession:
        """Create a new agent session"""
        self.session.add(session)
        await self.session.commit()
        await self.session.refresh(session)
        return session
    
    async def get_by_id(self, session_id: str) -> Optional[AgentSession]:
        """Get agent session by ID"""
        stmt = select(AgentSession).where(AgentSession.session_id == session_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_active_sessions(self) -> List[AgentSession]:
        """Get all active agent sessions"""
        stmt = (
            select(AgentSession)
            .where(AgentSession.status == "ACTIVE")
            .order_by(desc(AgentSession.timestamp))
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
    
    async def update_risk_score(self, session_id: str, risk_score: float) -> Optional[AgentSession]:
        """Update session risk score"""
        stmt = select(AgentSession).where(AgentSession.session_id == session_id)
        result = await self.session.execute(stmt)
        session = result.scalar_one_or_none()
        
        if session:
            session.risk_score = risk_score
            session.max_risk_score = max(session.max_risk_score, risk_score)
            await self.session.commit()
            await self.session.refresh(session)
        
        return session
    
    async def trigger_kill_switch(self, session_id: str, reason: str) -> Optional[AgentSession]:
        """Trigger kill switch for agent session"""
        stmt = select(AgentSession).where(AgentSession.session_id == session_id)
        result = await self.session.execute(stmt)
        session = result.scalar_one_or_none()
        
        if session:
            session.kill_switch_triggered = True
            session.kill_switch_reason = reason
            session.kill_switch_timestamp = datetime.now(timezone.utc)
            session.status = "TERMINATED"
            await self.session.commit()
            await self.session.refresh(session)
        
        return session


class AgentActionRepository:
    """Repository for agent action operations"""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def create(self, action: AgentAction) -> AgentAction:
        """Create a new agent action"""
        self.session.add(action)
        await self.session.commit()
        await self.session.refresh(action)
        return action
    
    async def get_by_session(self, session_id: str, limit: int = 100) -> List[AgentAction]:
        """Get actions for a session"""
        stmt = (
            select(AgentAction)
            .where(AgentAction.session_id == session_id)
            .order_by(desc(AgentAction.timestamp))
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
    
    async def get_blocked_actions(self, hours: int = 24) -> List[AgentAction]:
        """Get blocked actions in time window"""
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        stmt = (
            select(AgentAction)
            .where(
                and_(
                    AgentAction.blocked == True,
                    AgentAction.timestamp >= since
                )
            )
            .order_by(desc(AgentAction.timestamp))
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
    
    async def get_action_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get agent action statistics"""
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        # Total actions
        total_stmt = select(func.count(AgentAction.id)).where(AgentAction.timestamp >= since)
        total_result = await self.session.execute(total_stmt)
        total_actions = total_result.scalar()
        
        # Blocked actions
        blocked_stmt = select(func.count(AgentAction.id)).where(
            and_(
                AgentAction.timestamp >= since,
                AgentAction.blocked == True
            )
        )
        blocked_result = await self.session.execute(blocked_stmt)
        blocked_actions = blocked_result.scalar()
        
        # Average risk score
        risk_stmt = select(func.avg(AgentAction.risk_score)).where(AgentAction.timestamp >= since)
        risk_result = await self.session.execute(risk_stmt)
        avg_risk = risk_result.scalar()
        
        return {
            "total_actions": total_actions,
            "blocked_actions": blocked_actions,
            "block_rate": blocked_actions / total_actions if total_actions > 0 else 0,
            "average_risk_score": float(avg_risk) if avg_risk else 0.0,
            "period_hours": hours,
        }


class RedTeamJobRepository:
    """Repository for red team job operations"""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def create(self, job: RedTeamJob) -> RedTeamJob:
        """Create a new red team job"""
        self.session.add(job)
        await self.session.commit()
        await self.session.refresh(job)
        return job
    
    async def get_by_id(self, job_id: str) -> Optional[RedTeamJob]:
        """Get red team job by ID"""
        stmt = select(RedTeamJob).where(RedTeamJob.job_id == job_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_running_jobs(self) -> List[RedTeamJob]:
        """Get all running red team jobs"""
        stmt = (
            select(RedTeamJob)
            .where(RedTeamJob.status == "RUNNING")
            .order_by(desc(RedTeamJob.timestamp))
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()
    
    async def update_progress(self, job_id: str, progress: float, attacks_run: int, 
                            attacks_succeeded: int, attacks_blocked: int) -> Optional[RedTeamJob]:
        """Update job progress"""
        stmt = select(RedTeamJob).where(RedTeamJob.job_id == job_id)
        result = await self.session.execute(stmt)
        job = result.scalar_one_or_none()
        
        if job:
            job.progress = progress
            job.attacks_run = attacks_run
            job.attacks_succeeded = attacks_succeeded
            job.attacks_blocked = attacks_blocked
            await self.session.commit()
            await self.session.refresh(job)
        
        return job
    
    async def complete_job(self, job_id: str, security_score: float, grade: str,
                          critical_vulnerabilities: List[Dict], owasp_coverage: Dict) -> Optional[RedTeamJob]:
        """Complete a red team job"""
        stmt = select(RedTeamJob).where(RedTeamJob.job_id == job_id)
        result = await self.session.execute(stmt)
        job = result.scalar_one_or_none()
        
        if job:
            job.status = "COMPLETED"
            job.completed_at = datetime.now(timezone.utc)
            job.progress = 100.0
            job.security_score = security_score
            job.grade = grade
            job.critical_vulnerabilities = critical_vulnerabilities
            job.owasp_coverage = owasp_coverage
            await self.session.commit()
            await self.session.refresh(job)
        
        return job


class ComplianceReportRepository:
    """Repository for compliance report operations"""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def create(self, report: ComplianceReport) -> ComplianceReport:
        """Create a new compliance report"""
        self.session.add(report)
        await self.session.commit()
        await self.session.refresh(report)
        return report
    
    async def get_by_id(self, report_id: str) -> Optional[ComplianceReport]:
        """Get compliance report by ID"""
        stmt = select(ComplianceReport).where(ComplianceReport.report_id == report_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_by_application(self, application: str, limit: int = 10) -> List[ComplianceReport]:
        """Get compliance reports for an application"""
        stmt = (
            select(ComplianceReport)
            .where(ComplianceReport.application == application)
            .order_by(desc(ComplianceReport.timestamp))
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()


class AuditLogRepository:
    """Repository for audit log operations"""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def create(self, audit_log: AuditLog) -> AuditLog:
        """Create a new audit log entry"""
        self.session.add(audit_log)
        await self.session.commit()
        await self.session.refresh(audit_log)
        return audit_log
    
    async def search(self, event_type: Optional[str] = None, actor: Optional[str] = None,
                    start_time: Optional[datetime] = None, end_time: Optional[datetime] = None,
                    limit: int = 100) -> List[AuditLog]:
        """Search audit logs with filters"""
        conditions = []
        
        if event_type:
            conditions.append(AuditLog.event_type == event_type)
        if actor:
            conditions.append(AuditLog.actor == actor)
        if start_time:
            conditions.append(AuditLog.timestamp >= start_time)
        if end_time:
            conditions.append(AuditLog.timestamp <= end_time)
        
        stmt = (
            select(AuditLog)
            .where(and_(*conditions) if conditions else True)
            .order_by(desc(AuditLog.timestamp))
            .limit(limit)
        )
        
        result = await self.session.execute(stmt)
        return result.scalars().all()
