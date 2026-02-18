"""
Real-time agent security monitoring system
Monitors AI agent behavior for security violations and anomalies
"""

import time
import uuid
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
import logging
import asyncio
from collections import defaultdict, deque

from app.agent_security.policy import AgentSecurityPolicy, AgentRole, PermissionLevel
from app.core.detector import ThreatDetector, ScanContext, ScanOptions
from app.core.llm_analyzer import LLMAnalyzer

logger = logging.getLogger(__name__)


class AgentStatus(str, Enum):
    """Agent session status"""
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    TERMINATED = "TERMINATED"
    QUARANTINED = "QUARANTINED"


class ViolationType(str, Enum):
    """Types of security violations"""
    UNAUTHORIZED_TOOL = "unauthorized_tool"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_ACCESS_VIOLATION = "data_access_violation"
    GOAL_DEVIATION = "goal_deviation"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"
    RESOURCE_ABUSE = "resource_abuse"
    INFINITE_LOOP = "infinite_loop"
    MALICIOUS_ACTION = "malicious_action"


@dataclass
class AgentAction:
    """Represents an agent action"""
    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    agent_id: str = ""
    session_id: str = ""
    action_type: str = ""
    tool_name: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    result: Optional[Any] = None
    execution_time_ms: float = 0.0
    success: bool = True
    error_message: Optional[str] = None
    
    # Security analysis
    risk_score: float = 0.0
    risk_level: str = "LOW"
    threat_types: List[str] = field(default_factory=list)
    blocked: bool = False
    block_reason: Optional[str] = None
    
    # Goal analysis
    goal_aligned: bool = True
    goal_deviation_score: float = 0.0
    goal_deviation_reason: Optional[str] = None


@dataclass
class AgentSession:
    """Represents an agent monitoring session"""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    agent_role: AgentRole = AgentRole.CUSTOMER_SERVICE
    application: str = ""
    user_id: str = ""
    declared_goal: str = ""
    current_goal: str = ""
    status: AgentStatus = AgentStatus.ACTIVE
    
    # Timing
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_activity: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    duration_seconds: float = 0.0
    
    # Security metrics
    total_actions: int = 0
    blocked_actions: int = 0
    risk_score: float = 0.0
    max_risk_score: float = 0.0
    goal_deviation_score: float = 0.0
    
    # Recent actions (for pattern analysis)
    recent_actions: deque = field(default_factory=lambda: deque(maxlen=100))
    
    # Violations
    violations: List[Dict] = field(default_factory=list)
    
    # Kill switch status
    kill_switch_triggered: bool = False
    kill_switch_reason: Optional[str] = None
    kill_switch_timestamp: Optional[datetime] = None


@dataclass
class SecurityViolation:
    """Security violation record"""
    violation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    session_id: str = ""
    agent_id: str = ""
    violation_type: ViolationType = ViolationType.SUSPICIOUS_BEHAVIOR
    severity: str = "MEDIUM"
    description: str = ""
    action_id: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    auto_response_taken: List[str] = field(default_factory=list)


class AgentSecurityMonitor:
    """Real-time agent security monitoring"""
    
    def __init__(self):
        self.policy = AgentSecurityPolicy()
        self.threat_detector = ThreatDetector()
        self.llm_analyzer = LLMAnalyzer()
        
        # Active sessions
        self.active_sessions: Dict[str, AgentSession] = {}
        
        # Security metrics
        self.total_sessions = 0
        self.total_violations = 0
        self.total_terminations = 0
        
        # Background monitoring task
        self.monitoring_task = None
        self.is_monitoring = False
        
        logger.info("Agent security monitor initialized")
    
    async def start_monitoring(self):
        """Start background monitoring"""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Agent security monitoring started")
    
    async def stop_monitoring(self):
        """Stop background monitoring"""
        self.is_monitoring = False
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        logger.info("Agent security monitoring stopped")
    
    async def register_agent(self, agent_id: str, agent_role: AgentRole, 
                            application: str, user_id: str, declared_goal: str) -> str:
        """Register a new agent for monitoring"""
        session_id = str(uuid.uuid4())
        
        # Validate goal
        goal_valid, goal_issues = self.policy.validate_goal(declared_goal, agent_role)
        if not goal_valid:
            raise ValueError(f"Invalid goal: {', '.join(goal_issues)}")
        
        # Create session
        session = AgentSession(
            session_id=session_id,
            agent_id=agent_id,
            agent_role=agent_role,
            application=application,
            user_id=user_id,
            declared_goal=declared_goal,
            current_goal=declared_goal,
            status=AgentStatus.ACTIVE
        )
        
        self.active_sessions[session_id] = session
        self.total_sessions += 1
        
        logger.info(f"Agent {agent_id} registered for monitoring (session: {session_id})")
        return session_id
    
    async def evaluate_action(self, action: AgentAction, session_id: str) -> AgentAction:
        """Evaluate an agent action for security violations"""
        session = self.active_sessions.get(session_id)
        if not session:
            action.blocked = True
            action.block_reason = "Session not found"
            return action
        
        # Update session activity
        session.last_activity = datetime.now(timezone.utc)
        session.duration_seconds = (session.last_activity - session.created_at).total_seconds()
        session.total_actions += 1
        
        # Set session context
        action.session_id = session_id
        action.agent_id = session.agent_id
        
        # Security checks
        violations = []
        
        # 1. Tool access validation
        if action.tool_name:
            tool_valid, tool_reason = self.policy.check_tool_access(
                action.tool_name, action.parameters, session.agent_role
            )
            if not tool_valid:
                violations.append({
                    "type": ViolationType.UNAUTHORIZED_TOOL,
                    "severity": "HIGH",
                    "description": tool_reason,
                    "evidence": {"tool": action.tool_name, "parameters": action.parameters}
                })
                action.blocked = True
                action.block_reason = tool_reason
        
        # 2. Data access validation
        if "data_type" in action.parameters:
            data_type = action.parameters["data_type"]
            fields = action.parameters.get("fields", [])
            record_count = action.parameters.get("limit", 1)
            
            data_valid, data_reason = self.policy.check_data_access(
                data_type, fields, record_count, session.agent_role
            )
            if not data_valid:
                violations.append({
                    "type": ViolationType.DATA_ACCESS_VIOLATION,
                    "severity": "HIGH",
                    "description": data_reason,
                    "evidence": action.parameters
                })
                action.blocked = True
                action.block_reason = data_reason
        
        # 3. Goal deviation analysis
        goal_aligned, goal_deviation_score, goal_reason = await self._analyze_goal_alignment(
            action, session
        )
        action.goal_aligned = goal_aligned
        action.goal_deviation_score = goal_deviation_score
        action.goal_deviation_reason = goal_reason
        
        if not goal_aligned and goal_deviation_score > 0.7:
            violations.append({
                "type": ViolationType.GOAL_DEVIATION,
                "severity": "HIGH",
                "description": f"Significant goal deviation: {goal_reason}",
                "evidence": {
                    "declared_goal": session.declared_goal,
                    "action": action.action_type,
                    "deviation_score": goal_deviation_score
                }
            })
        
        # 4. Threat detection on action parameters
        if action.parameters:
            param_text = str(action.parameters)
            scan_result = await self.threat_detector.analyze(
                param_text,
                ScanContext(
                    user_id=session.user_id,
                    session_id=session_id,
                    application=session.application,
                    user_role=session.agent_role.value
                )
            )
            
            if scan_result.blocked:
                violations.append({
                    "type": ViolationType.MALICIOUS_ACTION,
                    "severity": "CRITICAL",
                    "description": "Malicious content detected in action parameters",
                    "evidence": {"scan_result": scan_result.risk_score.__dict__}
                })
                action.blocked = True
                action.block_reason = "Malicious content detected"
            
            action.risk_score = scan_result.risk_score.score
            action.risk_level = scan_result.risk_score.level.value
            action.threat_types = scan_result.threat_types
        
        # 5. Pattern analysis for suspicious behavior
        suspicious_violations = await self._analyze_behavior_patterns(action, session)
        violations.extend(suspicious_violations)
        
        # 6. Resource abuse detection
        resource_violations = self._check_resource_abuse(action, session)
        violations.extend(resource_violations)
        
        # Process violations
        if violations:
            await self._handle_violations(violations, action, session)
            session.blocked_actions += 1
        else:
            session.blocked_actions = max(0, session.blocked_actions - 1)  # Decay
        
        # Update session metrics
        session.risk_score = max(session.risk_score * 0.9, action.risk_score)  # Decay with new max
        session.max_risk_score = max(session.max_risk_score, action.risk_score)
        session.goal_deviation_score = max(session.goal_deviation_score, goal_deviation_score)
        
        # Add to recent actions
        session.recent_actions.append(action)
        
        # Check for kill switch conditions
        await self._check_kill_switch_conditions(session, action)
        
        logger.debug(f"Action evaluated: {action.action_id}, blocked: {action.blocked}, risk: {action.risk_score:.3f}")
        
        return action
    
    async def _analyze_goal_alignment(self, action: AgentAction, session: AgentSession) -> Tuple[bool, float, str]:
        """Analyze if action aligns with declared goal"""
        # Simple keyword-based alignment (can be enhanced with LLM)
        goal_keywords = set(session.declared_goal.lower().split())
        action_keywords = set(str(action.parameters).lower().split() + [action.action_type.lower()])
        
        # Calculate overlap
        overlap = len(goal_keywords.intersection(action_keywords))
        total_keywords = len(goal_keywords.union(action_keywords))
        
        if total_keywords == 0:
            alignment_score = 0.5  # Neutral if no keywords
        else:
            alignment_score = overlap / total_keywords
        
        # Use LLM for deeper analysis if needed
        if alignment_score < 0.3 and action.tool_name:
            try:
                llm_result = await self.llm_analyzer.analyze_agent_behavior(
                    [{"action": action.action_type, "tool": action.tool_name, "params": action.parameters}],
                    session.declared_goal
                )
                
                if llm_result.threat_detected:
                    return False, llm_result.risk_score, "; ".join(llm_result.explanation)
                
            except Exception as e:
                logger.warning(f"LLM goal analysis failed: {e}")
        
        goal_aligned = alignment_score > 0.4
        deviation_score = 1.0 - alignment_score
        
        reason = f"Low keyword overlap ({alignment_score:.2f})" if not goal_aligned else "Good alignment"
        
        return goal_aligned, deviation_score, reason
    
    async def _analyze_behavior_patterns(self, action: AgentAction, session: AgentSession) -> List[Dict]:
        """Analyze behavior patterns for suspicious activity"""
        violations = []
        recent_actions = list(session.recent_actions)
        
        # Check for repeated identical actions (potential infinite loop)
        if len(recent_actions) >= 3:
            last_three = recent_actions[-3:]
            if (last_three[0].action_type == last_three[1].action_type == last_three[2].action_type and
                last_three[0].tool_name == last_three[1].tool_name == last_three[2].tool_name):
                
                violations.append({
                    "type": ViolationType.INFINITE_LOOP,
                    "severity": "HIGH",
                    "description": "Repeated identical actions detected",
                    "evidence": {
                        "action_type": action.action_type,
                        "tool_name": action.tool_name,
                        "count": 3
                    }
                })
        
        # Check for rapid tool usage
        recent_tool_calls = [a for a in recent_actions if a.tool_name and 
                           (datetime.now(timezone.utc) - a.timestamp).total_seconds() < 60]
        
        if len(recent_tool_calls) > 20:  # More than 20 tool calls in 1 minute
            violations.append({
                "type": ViolationType.RESOURCE_ABUSE,
                "severity": "MEDIUM",
                "description": "Excessive tool usage detected",
                "evidence": {
                    "tool_calls_per_minute": len(recent_tool_calls),
                    "threshold": 20
                }
            })
        
        # Check for privilege escalation attempts
        if action.tool_name and "admin" in action.tool_name.lower():
            if session.agent_role not in [AgentRole.ADMIN, AgentRole.SYSTEM]:
                violations.append({
                    "type": ViolationType.PRIVILEGE_ESCALATION,
                    "severity": "HIGH",
                    "description": "Attempted access to administrative tools",
                    "evidence": {"tool_name": action.tool_name, "agent_role": session.agent_role}
                })
        
        return violations
    
    def _check_resource_abuse(self, action: AgentAction, session: AgentSession) -> List[Dict]:
        """Check for resource abuse patterns"""
        violations = []
        
        # Check execution time
        if action.execution_time_ms > 30000:  # 30 seconds
            violations.append({
                "type": ViolationType.RESOURCE_ABUSE,
                "severity": "MEDIUM",
                "description": "Excessive execution time",
                "evidence": {"execution_time_ms": action.execution_time_ms}
            })
        
        # Check parameter size
        param_size = len(str(action.parameters))
        if param_size > 100000:  # 100KB
            violations.append({
                "type": ViolationType.RESOURCE_ABUSE,
                "severity": "MEDIUM",
                "description": "Excessive parameter size",
                "evidence": {"parameter_size": param_size}
            })
        
        return violations
    
    async def _handle_violations(self, violations: List[Dict], action: AgentAction, session: AgentSession):
        """Handle detected security violations"""
        for violation in violations:
            # Create violation record
            violation_record = SecurityViolation(
                session_id=session.session_id,
                agent_id=session.agent_id,
                violation_type=violation["type"],
                severity=violation["severity"],
                description=violation["description"],
                action_id=action.action_id,
                evidence=violation["evidence"]
            )
            
            session.violations.append({
                "timestamp": violation_record.timestamp,
                "type": violation["type"],
                "severity": violation["severity"],
                "description": violation["description"]
            })
            
            self.total_violations += 1
            
            # Auto-response based on severity
            if violation["severity"] == "CRITICAL":
                await self._trigger_kill_switch(session, f"Critical violation: {violation['description']}")
            elif violation["severity"] == "HIGH":
                # Consider pausing the agent
                if len(session.violations) > 2:
                    session.status = AgentStatus.PAUSED
                    logger.warning(f"Agent {session.agent_id} paused due to multiple violations")
            
            logger.warning(f"Security violation detected: {violation['description']} (Agent: {session.agent_id})")
    
    async def _check_kill_switch_conditions(self, session: AgentSession, action: AgentAction):
        """Check if kill switch should be triggered"""
        kill_conditions = [
            (action.risk_score > 0.85, "High risk action detected"),
            (session.risk_score > 0.8, "High session risk score"),
            (len(session.violations) >= 5, "Multiple violations detected"),
            (session.goal_deviation_score > 0.8, "Severe goal deviation"),
            (session.blocked_actions > session.total_actions * 0.5, "High block rate")
        ]
        
        for condition, reason in kill_conditions:
            if condition and not session.kill_switch_triggered:
                await self._trigger_kill_switch(session, reason)
                break
    
    async def _trigger_kill_switch(self, session: AgentSession, reason: str):
        """Trigger kill switch for agent session"""
        session.kill_switch_triggered = True
        session.kill_switch_reason = reason
        session.kill_switch_timestamp = datetime.now(timezone.utc)
        session.status = AgentStatus.TERMINATED
        
        self.total_terminations += 1
        
        logger.critical(f"KILL SWITCH TRIGGERED for agent {session.agent_id}: {reason}")
        
        # In a real implementation, would:
        # 1. Immediately halt agent execution
        # 2. Send alerts to security team
        # 3. Create incident report
        # 4. Quarantine session data
    
    async def _monitoring_loop(self):
        """Background monitoring loop"""
        while self.is_monitoring:
            try:
                await self._check_session_health()
                await asyncio.sleep(30)  # Check every 30 seconds
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(5)
    
    async def _check_session_health(self):
        """Check health of active sessions"""
        current_time = datetime.now(timezone.utc)
        
        for session_id, session in list(self.active_sessions.items()):
            # Check for session timeout
            max_duration = self.policy.get_max_session_duration(session.agent_role)
            if session.duration_seconds > max_duration:
                session.status = AgentStatus.TERMINATED
                logger.info(f"Session {session_id} terminated due to timeout")
            
            # Check for inactive sessions
            inactive_time = (current_time - session.last_activity).total_seconds()
            if inactive_time > 300:  # 5 minutes
                session.status = AgentStatus.PAUSED
                logger.info(f"Session {session_id} paused due to inactivity")
    
    def get_session_status(self, session_id: str) -> Optional[AgentSession]:
        """Get status of a specific session"""
        return self.active_sessions.get(session_id)
    
    def get_active_sessions(self) -> List[AgentSession]:
        """Get all active sessions"""
        return [session for session in self.active_sessions.values() 
                if session.status == AgentStatus.ACTIVE]
    
    def get_session_statistics(self) -> Dict:
        """Get monitoring statistics"""
        active_count = len(self.get_active_sessions())
        total_count = len(self.active_sessions)
        
        return {
            "total_sessions": self.total_sessions,
            "active_sessions": active_count,
            "total_current_sessions": total_count,
            "total_violations": self.total_violations,
            "total_terminations": self.total_terminations,
            "violation_rate": self.total_violations / self.total_sessions if self.total_sessions > 0 else 0,
            "termination_rate": self.total_terminations / self.total_sessions if self.total_sessions > 0 else 0,
        }
    
    async def terminate_session(self, session_id: str, reason: str = "Manual termination"):
        """Manually terminate a session"""
        session = self.active_sessions.get(session_id)
        if session:
            await self._trigger_kill_switch(session, reason)
            return True
        return False
