"""
Immutable audit trail system for SentinelShield AI Security Platform
Comprehensive logging and forensic evidence collection
"""

import hashlib
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
import logging
import asyncio

from app.db.repositories import AuditLogRepository
from app.db.database import get_db

logger = logging.getLogger(__name__)


class EventType(str, Enum):
    """Audit event types"""
    THREAT_DETECTED = "threat_detected"
    SCAN_COMPLETED = "scan_completed"
    INCIDENT_CREATED = "incident_created"
    AGENT_REGISTERED = "agent_registered"
    AGENT_TERMINATED = "agent_terminated"
    KILL_SWITCH_ACTIVATED = "kill_switch_activated"
    PLAYBOOK_EXECUTED = "playbook_executed"
    USER_BANNED = "user_banned"
    PATTERN_UPDATED = "pattern_updated"
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"
    CONFIGURATION_CHANGE = "configuration_change"
    DATA_EXPORT = "data_export"
    LOGIN_ATTEMPT = "login_attempt"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class ComplianceTag(str, Enum):
    """Compliance tags for audit entries"""
    GDPR = "gdpr"
    SOX = "sox"
    SOC2 = "soc2"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    ISO27001 = "iso27001"
    NIST = "nist"


@dataclass
class AuditEvent:
    """Audit event record"""
    event_id: str
    timestamp: datetime
    event_type: EventType
    actor: str
    action: str
    resource: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    correlation_id: Optional[str] = None
    success: bool = True
    error_message: Optional[str] = None
    
    # Compliance metadata
    retention_days: int = 2555  # 7 years default
    compliance_tags: List[ComplianceTag] = field(default_factory=list)
    
    # Immutable record hash
    hash: str = ""
    
    def __post_init__(self):
        """Generate hash for immutable record"""
        if not self.hash:
            self.hash = self._generate_hash()
    
    def _generate_hash(self) -> str:
        """Generate SHA-256 hash of the record"""
        # Create canonical representation
        record_data = {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "actor": self.actor,
            "action": self.action,
            "resource": self.resource,
            "details": self.details,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "session_id": self.session_id,
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "success": self.success,
            "error_message": self.error_message,
            "retention_days": self.retention_days,
            "compliance_tags": [tag.value for tag in self.compliance_tags]
        }
        
        # Sort keys for consistent hashing
        record_json = json.dumps(record_data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(record_json.encode()).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify record integrity"""
        return self.hash == self._generate_hash()


class AuditTrail:
    """Immutable audit trail system"""
    
    def __init__(self):
        self.repository = None
        self._buffer: List[AuditEvent] = []
        self._buffer_size = 100
        self._flush_interval = 60  # seconds
        self._flush_task = None
        self._is_flushing = False
        
        logger.info("Audit trail system initialized")
    
    async def initialize(self):
        """Initialize audit trail"""
        # Get repository instance
        async for db in get_db():
            self.repository = AuditLogRepository(db)
            break
        
        # Start background flush task
        self._flush_task = asyncio.create_task(self._flush_loop())
        
        logger.info("Audit trail initialized")
    
    async def log_event(self, event: AuditEvent) -> bool:
        """Log an audit event"""
        try:
            # Validate event
            if not event.verify_integrity():
                logger.error(f"Event integrity verification failed: {event.event_id}")
                return False
            
            # Add to buffer
            self._buffer.append(event)
            
            # Flush if buffer is full
            if len(self._buffer) >= self._buffer_size:
                await self._flush_buffer()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            return False
    
    async def log_threat_detected(self, scan_id: str, actor: str, threat_types: List[str],
                                risk_score: float, blocked: bool, user_id: str = None,
                                session_id: str = None, ip_address: str = None) -> bool:
        """Log threat detection event"""
        event = AuditEvent(
            event_id=f"threat_{scan_id}_{int(datetime.now(timezone.utc).timestamp())}",
            timestamp=datetime.now(timezone.utc),
            event_type=EventType.THREAT_DETECTED,
            actor=actor,
            action="threat_scan_completed",
            resource=scan_id,
            details={
                "threat_types": threat_types,
                "risk_score": risk_score,
                "blocked": blocked,
                "user_id": user_id
            },
            ip_address=ip_address,
            session_id=session_id,
            compliance_tags=[ComplianceTag.GDPR, ComplianceTag.SOC2]
        )
        
        return await self.log_event(event)
    
    async def log_incident_created(self, incident_id: str, actor: str, severity: str,
                                 threat_types: List[str], description: str) -> bool:
        """Log incident creation event"""
        event = AuditEvent(
            event_id=f"incident_{incident_id}_{int(datetime.now(timezone.utc).timestamp())}",
            timestamp=datetime.now(timezone.utc),
            event_type=EventType.INCIDENT_CREATED,
            actor=actor,
            action="security_incident_created",
            resource=incident_id,
            details={
                "severity": severity,
                "threat_types": threat_types,
                "description": description
            },
            compliance_tags=[ComplianceTag.GDPR, ComplianceTag.SOX, ComplianceTag.SOC2]
        )
        
        return await self.log_event(event)
    
    async def log_agent_registered(self, agent_id: str, session_id: str, agent_role: str,
                                 user_id: str, declared_goal: str) -> bool:
        """Log agent registration event"""
        event = AuditEvent(
            event_id=f"agent_reg_{agent_id}_{int(datetime.now(timezone.utc).timestamp())}",
            timestamp=datetime.now(timezone.utc),
            event_type=EventType.AGENT_REGISTERED,
            actor=user_id,
            action="agent_registered",
            resource=agent_id,
            details={
                "session_id": session_id,
                "agent_role": agent_role,
                "declared_goal": declared_goal
            },
            session_id=session_id,
            compliance_tags=[ComplianceTag.SOC2, ComplianceTag.ISO27001]
        )
        
        return await self.log_event(event)
    
    async def log_agent_terminated(self, agent_id: str, session_id: str, reason: str,
                                  trigger: str, risk_score: float) -> bool:
        """Log agent termination event"""
        event = AuditEvent(
            event_id=f"agent_term_{agent_id}_{int(datetime.now(timezone.utc).timestamp())}",
            timestamp=datetime.now(timezone.utc),
            event_type=EventType.AGENT_TERMINATED,
            actor="system",
            action="agent_terminated",
            resource=agent_id,
            details={
                "session_id": session_id,
                "reason": reason,
                "trigger": trigger,
                "risk_score": risk_score
            },
            session_id=session_id,
            compliance_tags=[ComplianceTag.SOC2, ComplianceTag.ISO27001]
        )
        
        return await self.log_event(event)
    
    async def log_kill_switch_activated(self, event_id: str, agent_id: str, session_id: str,
                                      trigger: str, mode: str, reason: str) -> bool:
        """Log kill switch activation event"""
        event = AuditEvent(
            event_id=f"ks_{event_id}_{int(datetime.now(timezone.utc).timestamp())}",
            timestamp=datetime.now(timezone.utc),
            event_type=EventType.KILL_SWITCH_ACTIVATED,
            actor="security_system",
            action="kill_switch_activated",
            resource=agent_id,
            details={
                "session_id": session_id,
                "trigger": trigger,
                "mode": mode,
                "reason": reason
            },
            session_id=session_id,
            compliance_tags=[ComplianceTag.SOC2, ComplianceTag.NIST]
        )
        
        return await self.log_event(event)
    
    async def log_playbook_executed(self, execution_id: str, playbook_type: str,
                                  trigger_event: Dict, status: str, execution_time_ms: float) -> bool:
        """Log playbook execution event"""
        event = AuditEvent(
            event_id=f"pb_{execution_id}_{int(datetime.now(timezone.utc).timestamp())}",
            timestamp=datetime.now(timezone.utc),
            event_type=EventType.PLAYBOOK_EXECUTED,
            actor="auto_remediation",
            action="playbook_executed",
            resource=execution_id,
            details={
                "playbook_type": playbook_type,
                "trigger_event": trigger_event,
                "status": status,
                "execution_time_ms": execution_time_ms
            },
            compliance_tags=[ComplianceTag.SOC2, ComplianceTag.ISO27001]
        )
        
        return await self.log_event(event)
    
    async def log_user_banned(self, user_id: str, actor: str, reason: str,
                            duration: str, ban_type: str) -> bool:
        """Log user ban event"""
        event = AuditEvent(
            event_id=f"ban_{user_id}_{int(datetime.now(timezone.utc).timestamp())}",
            timestamp=datetime.now(timezone.utc),
            event_type=EventType.USER_BANNED,
            actor=actor,
            action="user_banned",
            resource=user_id,
            details={
                "reason": reason,
                "duration": duration,
                "ban_type": ban_type
            },
            compliance_tags=[ComplianceTag.GDPR, ComplianceTag.SOC2]
        )
        
        return await self.log_event(event)
    
    async def log_configuration_change(self, actor: str, component: str,
                                     setting: str, old_value: Any, new_value: Any) -> bool:
        """Log configuration change event"""
        event = AuditEvent(
            event_id=f"config_{component}_{int(datetime.now(timezone.utc).timestamp())}",
            timestamp=datetime.now(timezone.utc),
            event_type=EventType.CONFIGURATION_CHANGE,
            actor=actor,
            action="configuration_changed",
            resource=component,
            details={
                "setting": setting,
                "old_value": old_value,
                "new_value": new_value
            },
            compliance_tags=[ComplianceTag.SOX, ComplianceTag.ISO27001]
        )
        
        return await self.log_event(event)
    
    async def log_data_export(self, actor: str, data_type: str, record_count: int,
                            format: str, destination: str, purpose: str) -> bool:
        """Log data export event"""
        event = AuditEvent(
            event_id=f"export_{int(datetime.now(timezone.utc).timestamp())}",
            timestamp=datetime.now(timezone.utc),
            event_type=EventType.DATA_EXPORT,
            actor=actor,
            action="data_exported",
            resource=data_type,
            details={
                "record_count": record_count,
                "format": format,
                "destination": destination,
                "purpose": purpose
            },
            compliance_tags=[ComplianceTag.GDPR, ComplianceTag.HIPAA]
        )
        
        return await self.log_event(event)
    
    async def search_events(self, event_type: EventType = None, actor: str = None,
                          start_time: datetime = None, end_time: datetime = None,
                          limit: int = 100) -> List[AuditEvent]:
        """Search audit events"""
        if not self.repository:
            logger.warning("Audit repository not initialized")
            return []
        
        try:
            # Convert to database models
            db_events = await self.repository.search(
                event_type=event_type.value if event_type else None,
                actor=actor,
                start_time=start_time,
                end_time=end_time,
                limit=limit
            )
            
            # Convert to AuditEvent objects
            events = []
            for db_event in db_events:
                event = AuditEvent(
                    event_id=db_event.log_id,
                    timestamp=db_event.timestamp,
                    event_type=EventType(db_event.event_type),
                    actor=db_event.actor,
                    action=db_event.action,
                    resource=db_event.resource,
                    details=db_event.details or {},
                    ip_address=db_event.ip_address,
                    user_agent=db_event.user_agent,
                    session_id=db_event.session_id,
                    request_id=db_event.request_id,
                    correlation_id=db_event.correlation_id,
                    success=db_event.success,
                    error_message=db_event.error_message,
                    retention_days=db_event.retention_days,
                    compliance_tags=[ComplianceTag(tag) for tag in (db_event.compliance_tags or [])],
                    hash=db_event.hash
                )
                events.append(event)
            
            return events
            
        except Exception as e:
            logger.error(f"Failed to search audit events: {e}")
            return []
    
    async def get_compliance_report(self, compliance_tag: ComplianceTag,
                                 start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Generate compliance report for specific tag"""
        events = await self.search_events(
            start_time=start_date,
            end_time=end_date,
            limit=10000
        )
        
        # Filter by compliance tag
        tagged_events = [e for e in events if compliance_tag in e.compliance_tags]
        
        # Generate statistics
        event_types = {}
        actors = {}
        success_rate = {"success": 0, "total": 0}
        
        for event in tagged_events:
            # Count by event type
            event_types[event.event_type.value] = event_types.get(event.event_type.value, 0) + 1
            
            # Count by actor
            actors[event.actor] = actors.get(event.actor, 0) + 1
            
            # Success rate
            success_rate["total"] += 1
            if event.success:
                success_rate["success"] += 1
        
        return {
            "compliance_tag": compliance_tag.value,
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "total_events": len(tagged_events),
            "event_types": event_types,
            "actors": actors,
            "success_rate": success_rate["success"] / success_rate["total"] if success_rate["total"] > 0 else 0,
            "integrity_verified": all(e.verify_integrity() for e in tagged_events)
        }
    
    async def verify_chain_integrity(self, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Verify audit chain integrity for time period"""
        events = await self.search_events(
            start_time=start_time,
            end_time=end_time,
            limit=50000
        )
        
        # Sort by timestamp
        events.sort(key=lambda e: e.timestamp)
        
        # Verify each event
        verified_count = 0
        failed_count = 0
        failed_events = []
        
        for event in events:
            if event.verify_integrity():
                verified_count += 1
            else:
                failed_count += 1
                failed_events.append(event.event_id)
        
        return {
            "period": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat()
            },
            "total_events": len(events),
            "verified_events": verified_count,
            "failed_events": failed_count,
            "integrity_percentage": (verified_count / len(events)) * 100 if events else 100,
            "failed_event_ids": failed_events[:10]  # First 10 failed events
        }
    
    async def _flush_buffer(self):
        """Flush audit buffer to database"""
        if not self._buffer or not self.repository or self._is_flushing:
            return
        
        self._is_flushing = True
        
        try:
            # Copy buffer and clear
            events_to_flush = self._buffer.copy()
            self._buffer.clear()
            
            # Convert to database models and save
            for event in events_to_flush:
                db_event = {
                    "log_id": event.event_id,
                    "timestamp": event.timestamp,
                    "event_type": event.event_type.value,
                    "actor": event.actor,
                    "action": event.action,
                    "resource": event.resource,
                    "details": event.details,
                    "ip_address": event.ip_address,
                    "user_agent": event.user_agent,
                    "session_id": event.session_id,
                    "request_id": event.request_id,
                    "correlation_id": event.correlation_id,
                    "success": event.success,
                    "error_message": event.error_message,
                    "retention_days": event.retention_days,
                    "compliance_tags": [tag.value for tag in event.compliance_tags],
                    "hash": event.hash
                }
                
                await self.repository.create(db_event)
            
            logger.debug(f"Flushed {len(events_to_flush)} audit events to database")
            
        except Exception as e:
            logger.error(f"Failed to flush audit buffer: {e}")
            # Re-add events to buffer for retry
            self._buffer.extend(events_to_flush)
        
        finally:
            self._is_flushing = False
    
    async def _flush_loop(self):
        """Background flush loop"""
        while True:
            try:
                await asyncio.sleep(self._flush_interval)
                await self._flush_buffer()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Audit flush loop error: {e}")
    
    async def shutdown(self):
        """Shutdown audit trail"""
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        
        # Final flush
        await self._flush_buffer()
        
        logger.info("Audit trail shutdown complete")


# Global audit trail instance
audit_trail = AuditTrail()
