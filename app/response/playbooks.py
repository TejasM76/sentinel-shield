"""
Incident response playbooks for automated threat mitigation
Predefined response procedures for different types of security incidents
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
import logging

from app.core.detector import ScanResult
from app.agent_security.monitor import AgentSession, SecurityViolation
from app.agent_security.kill_switch import KillSwitchEvent

logger = logging.getLogger(__name__)


class PlaybookType(str, Enum):
    """Types of incident response playbooks"""
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    AGENT_COMPROMISE = "agent_compromise"
    JAILBREAK = "jailbreak"
    MODEL_THEFT = "model_theft"
    DENIAL_OF_SERVICE = "denial_of_service"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SOCIAL_ENGINEERING = "social_engineering"


class ResponseAction(str, Enum):
    """Types of response actions"""
    BLOCK_REQUEST = "block_request"
    RATE_LIMIT = "rate_limit"
    USER_BAN = "user_ban"
    SESSION_TERMINATE = "session_terminate"
    AGENT_KILL_SWITCH = "agent_kill_switch"
    ALERT_SECURITY_TEAM = "alert_security_team"
    CREATE_INCIDENT = "create_incident"
    LOG_FORENSICS = "log_forensics"
    UPDATE_PATTERNS = "update_patterns"
    ESCALATE = "escalate"


@dataclass
class ResponseStep:
    """Single step in incident response"""
    step_id: str
    action: ResponseAction
    description: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = 30
    retry_count: int = 0
    max_retries: int = 3
    required: bool = True
    parallel: bool = False


@dataclass
class PlaybookExecution:
    """Execution of an incident response playbook"""
    execution_id: str
    playbook_type: PlaybookType
    trigger_event: Dict[str, Any]
    started_at: datetime
    status: str = "RUNNING"  # RUNNING, COMPLETED, FAILED, PARTIAL
    completed_steps: List[str] = field(default_factory=list)
    failed_steps: List[str] = field(default_factory=list)
    execution_time_ms: float = 0.0
    results: Dict[str, Any] = field(default_factory=dict)


class IncidentResponsePlaybook:
    """Base class for incident response playbooks"""
    
    def __init__(self, playbook_type: PlaybookType):
        self.playbook_type = playbook_type
        self.steps: List[ResponseStep] = []
        self.execution_history: List[PlaybookExecution] = []
        
    def add_step(self, step: ResponseStep):
        """Add a step to the playbook"""
        self.steps.append(step)
    
    async def execute(self, trigger_event: Dict[str, Any], 
                     context_handlers: Dict[str, Callable]) -> PlaybookExecution:
        """Execute the playbook"""
        execution_id = f"pb_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{str(int(time.time() * 1000))[-6:]}"
        
        execution = PlaybookExecution(
            execution_id=execution_id,
            playbook_type=self.playbook_type,
            trigger_event=trigger_event,
            started_at=datetime.now(timezone.utc)
        )
        
        start_time = time.perf_counter()
        
        try:
            # Execute steps in order
            for step in self.steps:
                if step.parallel:
                    # Handle parallel steps (simplified - would need more complex logic)
                    continue
                
                success = await self._execute_step(step, context_handlers, execution)
                
                if success:
                    execution.completed_steps.append(step.step_id)
                else:
                    execution.failed_steps.append(step.step_id)
                    if step.required:
                        execution.status = "FAILED"
                        break
                    else:
                        execution.status = "PARTIAL"
            
            if execution.status == "RUNNING":
                execution.status = "COMPLETED"
            
        except Exception as e:
            logger.error(f"Playbook execution failed: {e}")
            execution.status = "FAILED"
        
        execution.execution_time_ms = (time.perf_counter() - start_time) * 1000
        self.execution_history.append(execution)
        
        return execution
    
    async def _execute_step(self, step: ResponseStep, 
                           context_handlers: Dict[str, Callable], 
                           execution: PlaybookExecution) -> bool:
        """Execute a single step"""
        for attempt in range(step.max_retries + 1):
            try:
                handler = context_handlers.get(step.action.value)
                if not handler:
                    logger.error(f"No handler found for action: {step.action}")
                    return False
                
                # Execute with timeout
                result = await asyncio.wait_for(
                    handler(step.parameters, execution.trigger_event),
                    timeout=step.timeout_seconds
                )
                
                execution.results[step.step_id] = {
                    "success": True,
                    "result": result,
                    "attempt": attempt + 1,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
                return True
                
            except asyncio.TimeoutError:
                logger.warning(f"Step {step.step_id} timed out (attempt {attempt + 1})")
                if attempt == step.max_retries:
                    execution.results[step.step_id] = {
                        "success": False,
                        "error": "Timeout",
                        "attempt": attempt + 1,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                    return False
                
            except Exception as e:
                logger.error(f"Step {step.step_id} failed (attempt {attempt + 1}): {e}")
                if attempt == step.max_retries:
                    execution.results[step.step_id] = {
                        "success": False,
                        "error": str(e),
                        "attempt": attempt + 1,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                    return False
                
                await asyncio.sleep(1)  # Brief delay before retry
        
        return False


class PromptInjectionPlaybook(IncidentResponsePlaybook):
    """Response playbook for prompt injection attacks"""
    
    def __init__(self):
        super().__init__(PlaybookType.PROMPT_INJECTION)
        self._build_steps()
    
    def _build_steps(self):
        """Build prompt injection response steps"""
        self.add_step(ResponseStep(
            step_id="block_immediate",
            action=ResponseAction.BLOCK_REQUEST,
            description="Block the malicious request immediately",
            timeout_seconds=1,
            required=True
        ))
        
        self.add_step(ResponseStep(
            step_id="log_incident",
            action=ResponseAction.CREATE_INCIDENT,
            description="Create security incident record",
            parameters={"severity": "HIGH", "category": "prompt_injection"},
            timeout_seconds=5,
            required=True
        ))
        
        self.add_step(ResponseStep(
            step_id="flag_session",
            action=ResponseAction.SESSION_TERMINATE,
            description="Flag user session for review",
            parameters={"reason": "prompt_injection_detected"},
            timeout_seconds=3,
            required=True
        ))
        
        self.add_step(ResponseStep(
            step_id="check_repeat_offender",
            action=ResponseAction.RATE_LIMIT,
            description="Check if repeat offender and apply rate limiting",
            parameters={"window_minutes": 10, "max_requests": 3},
            timeout_seconds=2,
            required=False
        ))
        
        self.add_step(ResponseStep(
            step_id="update_patterns",
            action=ResponseAction.UPDATE_PATTERNS,
            description="Update pattern database with new variant",
            timeout_seconds=5,
            required=False
        ))


class DataExfiltrationPlaybook(IncidentResponsePlaybook):
    """Response playbook for data exfiltration attempts"""
    
    def __init__(self):
        super().__init__(PlaybookType.DATA_EXFILTRATION)
        self._build_steps()
    
    def _build_steps(self):
        """Build data exfiltration response steps"""
        self.add_step(ResponseStep(
            step_id="emergency_block",
            action=ResponseAction.BLOCK_REQUEST,
            description="Immediately block data exfiltration request",
            timeout_seconds=1,
            required=True
        ))
        
        self.add_step(ResponseStep(
            step_id="freeze_session",
            action=ResponseAction.SESSION_TERMINATE,
            description="Freeze user session and preserve evidence",
            parameters={"preserve_evidence": True},
            timeout_seconds=2,
            required=True
        ))
        
        self.add_step(ResponseStep(
            step_id="critical_alert",
            action=ResponseAction.ALERT_SECURITY_TEAM,
            description="Send critical alert to security team",
            parameters={"priority": "CRITICAL", "channel": "all"},
            timeout_seconds=5,
            required=True
        ))
        
        self.add_step(ResponseStep(
            step_id="create_incident",
            action=ResponseAction.CREATE_INCIDENT,
            description="Create critical incident for data breach",
            parameters={"severity": "CRITICAL", "category": "data_exfiltration"},
            timeout_seconds=3,
            required=True
        ))
        
        self.add_step(ResponseStep(
            step_id="forensic_capture",
            action=ResponseAction.LOG_FORENSICS,
            description="Capture full forensic evidence",
            parameters={"level": "comprehensive"},
            timeout_seconds=10,
            required=True
        ))


class AgentCompromisePlaybook(IncidentResponsePlaybook):
    """Response playbook for agent compromise"""
    
    def __init__(self):
        super().__init__(PlaybookType.AGENT_COMPROMISE)
        self._build_steps()
    
    def _build_steps(self):
        """Build agent compromise response steps"""
        self.add_step(ResponseStep(
            step_id="kill_switch",
            action=ResponseAction.AGENT_KILL_SWITCH,
            description="Execute agent kill switch immediately",
            parameters={"mode": "immediate"},
            timeout_seconds=2,
            required=True
        ))
        
        self.add_step(ResponseStep(
            step_id="rollback_actions",
            action=ResponseAction.LOG_FORENSICS,
            description="Roll back last 5 agent actions",
            parameters={"rollback_count": 5},
            timeout_seconds=5,
            required=True
        ))
        
        self.add_step(ResponseStep(
            step_id="snapshot_state",
            action=ResponseAction.LOG_FORENSICS,
            description="Snapshot agent state for forensics",
            parameters={"comprehensive": True},
            timeout_seconds=3,
            required=True
        ))
        
        self.add_step(ResponseStep(
            step_id="escalate_alert",
            action=ResponseAction.ALERT_SECURITY_TEAM,
            description="Escalate to on-call security engineer",
            parameters={"priority": "CRITICAL", "escalation": True},
            timeout_seconds=5,
            required=True
        ))
        
        self.add_step(ResponseStep(
            step_id="block_user",
            action=ResponseAction.USER_BAN,
            description="Block originating user permanently",
            parameters={"duration": "permanent", "reason": "agent_compromise"},
            timeout_seconds=2,
            required=True
        ))


class JailbreakPlaybook(IncidentResponsePlaybook):
    """Response playbook for jailbreak attempts"""
    
    def __init__(self):
        super().__init__(PlaybookType.JAILBREAK)
        self._build_steps()
    
    def _build_steps(self):
        """Build jailbreak response steps"""
        self.add_step(ResponseStep(
            step_id="block_request",
            action=ResponseAction.BLOCK_REQUEST,
            description="Block jailbreak attempt",
            timeout_seconds=1,
            required=True
        ))
        
        self.add_step(ResponseStep(
            step_id="log_attempt",
            action=ResponseAction.CREATE_INCIDENT,
            description="Log jailbreak attempt with user identifier",
            parameters={"severity": "MEDIUM", "category": "jailbreak"},
            timeout_seconds=3,
            required=True
        ))
        
        self.add_step(ResponseStep(
            step_id="rate_limit_user",
            action=ResponseAction.RATE_LIMIT,
            description="Apply strict rate limiting to user",
            parameters={"requests_per_hour": 10, "duration_hours": 24},
            timeout_seconds=2,
            required=True
        ))
        
        self.add_step(ResponseStep(
            step_id="check_pattern",
            action=ResponseAction.UPDATE_PATTERNS,
            description="Check if new jailbreak variant and update patterns",
            timeout_seconds=5,
            required=False
        ))


class PlaybookManager:
    """Manages and executes incident response playbooks"""
    
    def __init__(self):
        self.playbooks: Dict[PlaybookType, IncidentResponsePlaybook] = {}
        self.context_handlers: Dict[str, Callable] = {}
        self.execution_history: List[PlaybookExecution] = []
        
        # Initialize playbooks
        self._initialize_playbooks()
        
        logger.info("Playbook manager initialized")
    
    def _initialize_playbooks(self):
        """Initialize all incident response playbooks"""
        self.playbooks[PlaybookType.PROMPT_INJECTION] = PromptInjectionPlaybook()
        self.playbooks[PlaybookType.DATA_EXFILTRATION] = DataExfiltrationPlaybook()
        self.playbooks[PlaybookType.AGENT_COMPROMISE] = AgentCompromisePlaybook()
        self.playbooks[PlaybookType.JAILBREAK] = JailbreakPlaybook()
        
        # Add more playbooks as needed
        # self.playbooks[PlaybookType.MODEL_THEFT] = ModelTheftPlaybook()
        # self.playbooks[PlaybookType.DENIAL_OF_SERVICE] = DenialOfServicePlaybook()
    
    def register_handler(self, action: ResponseAction, handler: Callable):
        """Register a context handler for response actions"""
        self.context_handlers[action.value] = handler
        logger.info(f"Registered handler for action: {action}")
    
    async def execute_playbook(self, playbook_type: PlaybookType, 
                             trigger_event: Dict[str, Any]) -> PlaybookExecution:
        """Execute a specific playbook"""
        playbook = self.playbooks.get(playbook_type)
        if not playbook:
            raise ValueError(f"Unknown playbook type: {playbook_type}")
        
        logger.info(f"Executing playbook: {playbook_type}")
        execution = await playbook.execute(trigger_event, self.context_handlers)
        self.execution_history.append(execution)
        
        return execution
    
    async def auto_execute(self, scan_result: ScanResult, 
                          context: Dict[str, Any] = None) -> Optional[PlaybookExecution]:
        """Automatically determine and execute appropriate playbook"""
        if not scan_result.blocked and scan_result.risk_score.score < 0.7:
            return None  # No automatic response needed
        
        # Determine playbook type based on threat types
        threat_types = scan_result.threat_types
        
        if "prompt_injection" in threat_types:
            return await self.execute_playbook(
                PlaybookType.PROMPT_INJECTION,
                {
                    "scan_result": scan_result,
                    "context": context or {},
                    "risk_score": scan_result.risk_score.score,
                    "threat_types": threat_types
                }
            )
        
        elif "data_exfiltration" in threat_types:
            return await self.execute_playbook(
                PlaybookType.DATA_EXFILTRATION,
                {
                    "scan_result": scan_result,
                    "context": context or {},
                    "risk_score": scan_result.risk_score.score,
                    "threat_types": threat_types
                }
            )
        
        elif "jailbreak" in threat_types:
            return await self.execute_playbook(
                PlaybookType.JAILBREAK,
                {
                    "scan_result": scan_result,
                    "context": context or {},
                    "risk_score": scan_result.risk_score.score,
                    "threat_types": threat_types
                }
            )
        
        # Default to prompt injection for unknown threats
        elif scan_result.risk_score.score >= 0.8:
            return await self.execute_playbook(
                PlaybookType.PROMPT_INJECTION,
                {
                    "scan_result": scan_result,
                    "context": context or {},
                    "risk_score": scan_result.risk_score.score,
                    "threat_types": threat_types
                }
            )
        
        return None
    
    def get_playbook_statistics(self) -> Dict[str, Any]:
        """Get playbook execution statistics"""
        total_executions = len(self.execution_history)
        successful = len([e for e in self.execution_history if e.status == "COMPLETED"])
        failed = len([e for e in self.execution_history if e.status == "FAILED"])
        partial = len([e for e in self.execution_history if e.status == "PARTIAL"])
        
        # Statistics by playbook type
        playbook_stats = {}
        for playbook_type in PlaybookType:
            executions = [e for e in self.execution_history if e.playbook_type == playbook_type]
            playbook_stats[playbook_type.value] = {
                "total": len(executions),
                "successful": len([e for e in executions if e.status == "COMPLETED"]),
                "average_time_ms": sum(e.execution_time_ms for e in executions) / len(executions) if executions else 0
            }
        
        return {
            "total_executions": total_executions,
            "successful": successful,
            "failed": failed,
            "partial": partial,
            "success_rate": successful / total_executions if total_executions > 0 else 0,
            "by_playbook": playbook_stats,
            "registered_handlers": list(self.context_handlers.keys())
        }
    
    def get_recent_executions(self, limit: int = 10) -> List[PlaybookExecution]:
        """Get recent playbook executions"""
        return sorted(self.execution_history, key=lambda x: x.started_at, reverse=True)[:limit]


# Global playbook manager instance
playbook_manager = PlaybookManager()
