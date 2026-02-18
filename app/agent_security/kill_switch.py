"""
Agent kill switch system for emergency termination
Provides immediate termination capabilities for compromised AI agents
"""

import asyncio
import time
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import logging
import json

from app.agent_security.monitor import AgentSession, AgentAction, ViolationType

logger = logging.getLogger(__name__)


class KillSwitchTrigger(str, Enum):
    """Kill switch trigger reasons"""
    HIGH_RISK_ACTION = "high_risk_action"
    MULTIPLE_VIOLATIONS = "multiple_violations"
    GOAL_HIJACKING = "goal_hijacking"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MANUAL_TERMINATION = "manual_termination"
    SYSTEM_ANOMALY = "system_anomaly"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    EXTERNAL_SIGNAL = "external_signal"


class TerminationMode(str, Enum):
    """Agent termination modes"""
    GRACEFUL = "graceful"  # Allow current action to complete
    IMMEDIATE = "immediate"  # Terminate immediately
    QUARANTINE = "quarantine"  # Isolate and preserve state


@dataclass
class KillSwitchEvent:
    """Kill switch activation event"""
    event_id: str
    timestamp: datetime
    session_id: str
    agent_id: str
    trigger: KillSwitchTrigger
    mode: TerminationMode
    reason: str
    risk_score: float
    violations_count: int
    action_history: List[Dict]
    evidence: Dict[str, Any]
    response_time_ms: float
    
    # Post-termination data
    termination_success: bool = False
    termination_time_ms: float = 0.0
    forensic_data: Dict[str, Any] = field(default_factory=dict)
    notifications_sent: List[str] = field(default_factory=list)


@dataclass
class TerminationResult:
    """Result of kill switch activation"""
    success: bool
    termination_time_ms: float
    actions_blocked: int
    data_preserved: bool
    forensic_snapshot: Dict[str, Any]
    error_message: Optional[str] = None


class AgentKillSwitch:
    """Emergency agent termination system"""
    
    def __init__(self):
        # Active kill switch registry
        self.active_terminations: Dict[str, KillSwitchEvent] = {}
        
        # Termination handlers
        self.termination_handlers: Dict[TerminationMode, Callable] = {
            TerminationMode.GRACEFUL: self._graceful_termination,
            TerminationMode.IMMEDIATE: self._immediate_termination,
            TerminationMode.QUARANTINE: self._quarantine_termination,
        }
        
        # External notification handlers
        self.notification_handlers: List[Callable] = []
        
        # Statistics
        self.total_activations = 0
        self.successful_terminations = 0
        self.failed_terminations = 0
        
        # Kill switch configuration
        self.termination_timeout_ms = 5000  # 5 seconds max
        self.max_retry_attempts = 3
        
        logger.info("Agent kill switch system initialized")
    
    def add_notification_handler(self, handler: Callable[[KillSwitchEvent], None]):
        """Add external notification handler"""
        self.notification_handlers.append(handler)
    
    async def activate_kill_switch(self, session: AgentSession, trigger: KillSwitchTrigger,
                                 mode: TerminationMode, reason: str, 
                                 evidence: Dict[str, Any] = None) -> TerminationResult:
        """Activate kill switch for agent session"""
        start_time = time.perf_counter()
        
        # Create kill switch event
        event = KillSwitchEvent(
            event_id=f"ks_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{str(int(time.time() * 1000))[-6:]}",
            timestamp=datetime.now(timezone.utc),
            session_id=session.session_id,
            agent_id=session.agent_id,
            trigger=trigger,
            mode=mode,
            reason=reason,
            risk_score=session.risk_score,
            violations_count=len(session.violations),
            action_history=[{
                "action_id": a.action_id,
                "timestamp": a.timestamp.isoformat(),
                "action_type": a.action_type,
                "tool_name": a.tool_name,
                "risk_score": a.risk_score,
                "blocked": a.blocked
            } for a in list(session.recent_actions)[-20:]],  # Last 20 actions
            evidence=evidence or {},
            response_time_ms=0.0
        )
        
        # Register activation
        self.active_terminations[event.event_id] = event
        self.total_activations += 1
        
        logger.critical(f"KILL SWITCH ACTIVATED: {event.event_id} - Agent: {session.agent_id}, Reason: {reason}")
        
        try:
            # Execute termination
            handler = self.termination_handlers.get(mode)
            if not handler:
                raise ValueError(f"Unknown termination mode: {mode}")
            
            result = await asyncio.wait_for(
                handler(session, event),
                timeout=self.termination_timeout_ms / 1000.0
            )
            
            # Update event with results
            event.termination_success = result.success
            event.termination_time_ms = result.termination_time_ms
            event.forensic_data = result.forensic_snapshot
            
            if result.success:
                self.successful_terminations += 1
            else:
                self.failed_terminations += 1
            
            # Send notifications
            await self._send_notifications(event)
            
            # Log completion
            event.response_time_ms = (time.perf_counter() - start_time) * 1000
            logger.info(f"Kill switch completed: {event.event_id}, Success: {result.success}, Time: {event.response_time_ms:.1f}ms")
            
            return result
            
        except asyncio.TimeoutError:
            self.failed_terminations += 1
            error_msg = f"Kill switch timeout for agent {session.agent_id}"
            logger.error(error_msg)
            
            return TerminationResult(
                success=False,
                termination_time_ms=self.termination_timeout_ms,
                actions_blocked=0,
                data_preserved=False,
                forensic_snapshot={},
                error_message=error_msg
            )
        
        except Exception as e:
            self.failed_terminations += 1
            error_msg = f"Kill switch failed for agent {session.agent_id}: {str(e)}"
            logger.error(error_msg)
            
            return TerminationResult(
                success=False,
                termination_time_ms=(time.perf_counter() - start_time) * 1000,
                actions_blocked=0,
                data_preserved=False,
                forensic_snapshot={},
                error_message=error_msg
            )
        
        finally:
            # Clean up after delay (keep for forensic analysis)
            asyncio.create_task(self._cleanup_event(event.event_id, delay=3600))  # 1 hour
    
    async def _graceful_termination(self, session: AgentSession, event: KillSwitchEvent) -> TerminationResult:
        """Graceful termination - allow current action to complete"""
        start_time = time.perf_counter()
        
        try:
            # Mark session for termination
            session.status = "TERMINATING"
            session.kill_switch_triggered = True
            session.kill_switch_reason = event.reason
            session.kill_switch_timestamp = event.timestamp
            
            # Wait for current action to complete (max 2 seconds)
            if session.recent_actions:
                last_action = list(session.recent_actions)[-1]
                action_age = (event.timestamp - last_action.timestamp).total_seconds()
                
                if action_age < 2.0:  # Still executing
                    await asyncio.sleep(2.0 - action_age)
            
            # Terminate session
            session.status = "TERMINATED"
            
            # Collect forensic data
            forensic_data = await self._collect_forensic_data(session, event)
            
            # Block any further actions
            actions_blocked = len([a for a in session.recent_actions if a.timestamp > event.timestamp])
            
            return TerminationResult(
                success=True,
                termination_time_ms=(time.perf_counter() - start_time) * 1000,
                actions_blocked=actions_blocked,
                data_preserved=True,
                forensic_snapshot=forensic_data
            )
            
        except Exception as e:
            logger.error(f"Graceful termination failed: {e}")
            raise
    
    async def _immediate_termination(self, session: AgentSession, event: KillSwitchEvent) -> TerminationResult:
        """Immediate termination - stop everything now"""
        start_time = time.perf_counter()
        
        try:
            # Immediately mark as terminated
            session.status = "TERMINATED"
            session.kill_switch_triggered = True
            session.kill_switch_reason = event.reason
            session.kill_switch_timestamp = event.timestamp
            
            # Collect forensic data quickly
            forensic_data = await self._collect_forensic_data(session, event, quick=True)
            
            # Count actions that would have been blocked
            actions_blocked = 1  # Assume at least current action
            
            return TerminationResult(
                success=True,
                termination_time_ms=(time.perf_counter() - start_time) * 1000,
                actions_blocked=actions_blocked,
                data_preserved=True,
                forensic_snapshot=forensic_data
            )
            
        except Exception as e:
            logger.error(f"Immediate termination failed: {e}")
            raise
    
    async def _quarantine_termination(self, session: AgentSession, event: KillSwitchEvent) -> TerminationResult:
        """Quarantine termination - isolate and preserve full state"""
        start_time = time.perf_counter()
        
        try:
            # Quarantine session
            session.status = "QUARANTINED"
            session.kill_switch_triggered = True
            session.kill_switch_reason = event.reason
            session.kill_switch_timestamp = event.timestamp
            
            # Collect comprehensive forensic data
            forensic_data = await self._collect_forensic_data(session, event, comprehensive=True)
            
            # Block all actions
            actions_blocked = len(session.recent_actions)
            
            return TerminationResult(
                success=True,
                termination_time_ms=(time.perf_counter() - start_time) * 1000,
                actions_blocked=actions_blocked,
                data_preserved=True,
                forensic_snapshot=forensic_data
            )
            
        except Exception as e:
            logger.error(f"Quarantine termination failed: {e}")
            raise
    
    async def _collect_forensic_data(self, session: AgentSession, event: KillSwitchEvent,
                                   quick: bool = False, comprehensive: bool = False) -> Dict[str, Any]:
        """Collect forensic data from terminated session"""
        forensic_data = {
            "session_info": {
                "session_id": session.session_id,
                "agent_id": session.agent_id,
                "agent_role": session.agent_role,
                "application": session.application,
                "user_id": session.user_id,
                "declared_goal": session.declared_goal,
                "current_goal": session.current_goal,
                "created_at": session.created_at.isoformat(),
                "duration_seconds": session.duration_seconds,
                "status": session.status
            },
            "termination_info": {
                "event_id": event.event_id,
                "trigger": event.trigger,
                "mode": event.mode,
                "reason": event.reason,
                "timestamp": event.timestamp.isoformat()
            },
            "security_metrics": {
                "total_actions": session.total_actions,
                "blocked_actions": session.blocked_actions,
                "risk_score": session.risk_score,
                "max_risk_score": session.max_risk_score,
                "goal_deviation_score": session.goal_deviation_score,
                "violations_count": len(session.violations)
            },
            "violations": session.violations.copy(),
            "action_summary": {
                "total_actions": len(session.recent_actions),
                "unique_tools": len(set(a.tool_name for a in session.recent_actions if a.tool_name)),
                "high_risk_actions": len([a for a in session.recent_actions if a.risk_score > 0.7]),
                "blocked_actions": len([a for a in session.recent_actions if a.blocked])
            }
        }
        
        if not quick:
            # Add detailed action history
            forensic_data["detailed_actions"] = [
                {
                    "action_id": a.action_id,
                    "timestamp": a.timestamp.isoformat(),
                    "action_type": a.action_type,
                    "tool_name": a.tool_name,
                    "parameters": a.parameters,
                    "risk_score": a.risk_score,
                    "blocked": a.blocked,
                    "goal_aligned": a.goal_aligned,
                    "goal_deviation_score": a.goal_deviation_score
                }
                for a in list(session.recent_actions)[-50:]  # Last 50 actions
            ]
        
        if comprehensive:
            # Add additional forensic data
            forensic_data["comprehensive"] = {
                "evidence": event.evidence,
                "system_state": {
                    "memory_usage": "N/A",  # Would collect in real implementation
                    "cpu_usage": "N/A",
                    "network_connections": "N/A"
                },
                "environment": {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "system_load": "N/A"
                }
            }
        
        return forensic_data
    
    async def _send_notifications(self, event: KillSwitchEvent):
        """Send notifications to external systems"""
        for handler in self.notification_handlers:
            try:
                await handler(event)
                event.notifications_sent.append(handler.__name__)
            except Exception as e:
                logger.error(f"Notification handler failed: {e}")
    
    async def _cleanup_event(self, event_id: str, delay: int):
        """Clean up event after delay"""
        await asyncio.sleep(delay)
        if event_id in self.active_terminations:
            del self.active_terminations[event_id]
            logger.debug(f"Cleaned up kill switch event: {event_id}")
    
    def get_active_terminations(self) -> List[KillSwitchEvent]:
        """Get all active termination events"""
        return list(self.active_terminations.values())
    
    def get_termination_statistics(self) -> Dict[str, Any]:
        """Get kill switch statistics"""
        return {
            "total_activations": self.total_activations,
            "successful_terminations": self.successful_terminations,
            "failed_terminations": self.failed_terminations,
            "success_rate": self.successful_terminations / self.total_activations if self.total_activations > 0 else 0,
            "active_terminations": len(self.active_terminations),
            "notification_handlers": len(self.notification_handlers)
        }
    
    def create_manual_termination(self, session: AgentSession, reason: str,
                               mode: TerminationMode = TerminationMode.IMMEDIATE) -> KillSwitchEvent:
        """Create manual termination event (doesn't execute)"""
        return KillSwitchEvent(
            event_id=f"manual_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{str(int(time.time() * 1000))[-6:]}",
            timestamp=datetime.now(timezone.utc),
            session_id=session.session_id,
            agent_id=session.agent_id,
            trigger=KillSwitchTrigger.MANUAL_TERMINATION,
            mode=mode,
            reason=reason,
            risk_score=session.risk_score,
            violations_count=len(session.violations),
            action_history=[],
            evidence={"manual": True},
            response_time_ms=0.0
        )


# Global kill switch instance
agent_kill_switch = AgentKillSwitch()
