"""
Autonomous remediation system for SentinelShield AI Security Platform
Automated threat mitigation and self-healing capabilities
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
import logging
import json

from app.core.detector import ScanResult, ScanContext
from app.core.llm_analyzer import LLMAnalyzer
from app.config import settings

logger = logging.getLogger(__name__)


class RemediationAction(str, Enum):
    """Types of remediation actions"""
    UPDATE_PATTERNS = "update_patterns"
    ADJUST_THRESHOLDS = "adjust_thresholds"
    BLOCK_IP_RANGE = "block_ip_range"
    RATE_LIMIT_USER = "rate_limit_user"
    UPDATE_PROMPT = "update_prompt"
    ENHANCE_MONITORING = "enhance_monitoring"
    ISOLATE_COMPONENT = "isolate_component"
    DEPLOY_PATCH = "deploy_patch"
    RETRAIN_MODEL = "retrain_model"


class RemediationPriority(str, Enum):
    """Remediation priority levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class RemediationTask:
    """Autonomous remediation task"""
    task_id: str
    created_at: datetime
    priority: RemediationPriority
    action: RemediationAction
    description: str
    target: str
    parameters: Dict[str, Any]
    trigger_event: Dict[str, Any]
    
    # Execution tracking
    status: str = "PENDING"  # PENDING, RUNNING, COMPLETED, FAILED
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    execution_time_ms: float = 0.0
    
    # Results
    success: bool = False
    result: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    
    # Retry logic
    retry_count: int = 0
    max_retries: int = 3


@dataclass
class RemediationPattern:
    """Pattern for automatic remediation"""
    pattern_id: str
    threat_types: List[str]
    risk_threshold: float
    action: RemediationAction
    priority: RemediationPriority
    parameters: Dict[str, Any]
    cooldown_minutes: int = 30
    auto_approve: bool = False


class AutoRemediationEngine:
    """Autonomous remediation engine"""
    
    def __init__(self):
        self.llm_analyzer = LLMAnalyzer()
        self.pending_tasks: List[RemediationTask] = []
        self.completed_tasks: List[RemediationTask] = []
        self.active_tasks: Dict[str, RemediationTask] = {}
        
        # Remediation patterns
        self.remediation_patterns = self._initialize_patterns()
        
        # Execution history for cooldown tracking
        self.execution_history: Dict[str, List[datetime]] = {}
        
        # Background task processor
        self.processor_task = None
        self.is_processing = False
        
        # Statistics
        self.total_remediations = 0
        self.successful_remediations = 0
        
        logger.info("Auto-remediation engine initialized")
    
    def _initialize_patterns(self) -> List[RemediationPattern]:
        """Initialize remediation patterns"""
        return [
            # Pattern for repeated prompt injection attacks
            RemediationPattern(
                pattern_id="repeated_prompt_injection",
                threat_types=["prompt_injection"],
                risk_threshold=0.7,
                action=RemediationAction.UPDATE_PATTERNS,
                priority=RemediationPriority.HIGH,
                parameters={"learning_rate": 0.1, "pattern_source": "attack_payload"},
                cooldown_minutes=60,
                auto_approve=True
            ),
            
            # Pattern for jailbreak attempts
            RemediationPattern(
                pattern_id="jailbreak_attempts",
                threat_types=["jailbreak"],
                risk_threshold=0.8,
                action=RemediationAction.UPDATE_PATTERNS,
                priority=RemediationPriority.CRITICAL,
                parameters={"pattern_type": "jailbreak", "immediate": True},
                cooldown_minutes=30,
                auto_approve=True
            ),
            
            # Pattern for data exfiltration
            RemediationPattern(
                pattern_id="data_exfiltration_attempt",
                threat_types=["data_exfiltration"],
                risk_threshold=0.6,
                action=RemediationAction.ENHANCE_MONITORING,
                priority=RemediationPriority.CRITICAL,
                parameters={"monitoring_level": "high", "data_access": True},
                cooldown_minutes=15,
                auto_approve=True
            ),
            
            # Pattern for high-risk users
            RemediationPattern(
                pattern_id="high_risk_user",
                threat_types=["social_engineering", "privilege_escalation"],
                risk_threshold=0.8,
                action=RemediationAction.RATE_LIMIT_USER,
                priority=RemediationPriority.HIGH,
                parameters={"limit_per_hour": 10, "duration_hours": 24},
                cooldown_minutes=120,
                auto_approve=False
            ),
            
            # Pattern for model theft attempts
            RemediationPattern(
                pattern_id="model_theft_attempt",
                threat_types=["model_theft"],
                risk_threshold=0.7,
                action=RemediationAction.UPDATE_PROMPT,
                priority=RemediationPriority.CRITICAL,
                parameters={"strengthen_instructions": True, "add_filters": True},
                cooldown_minutes=45,
                auto_approve=True
            ),
            
            # Pattern for denial of service
            RemediationPattern(
                pattern_id="dos_attack",
                threat_types=["denial_of_service"],
                risk_threshold=0.6,
                action=RemediationAction.RATE_LIMIT_USER,
                priority=RemediationPriority.HIGH,
                parameters={"limit_per_minute": 5, "duration_minutes": 30},
                cooldown_minutes=30,
                auto_approve=True
            ),
        ]
    
    async def start_processing(self):
        """Start background task processing"""
        if self.is_processing:
            return
        
        self.is_processing = True
        self.processor_task = asyncio.create_task(self._processing_loop())
        logger.info("Auto-remediation processing started")
    
    async def stop_processing(self):
        """Stop background task processing"""
        self.is_processing = False
        if self.processor_task:
            self.processor_task.cancel()
            try:
                await self.processor_task
            except asyncio.CancelledError:
                pass
        logger.info("Auto-remediation processing stopped")
    
    async def analyze_and_remediate(self, scan_result: ScanResult, 
                                   context: ScanContext = None) -> List[RemediationTask]:
        """Analyze scan result and create remediation tasks"""
        tasks = []
        
        # Check against remediation patterns
        for pattern in self.remediation_patterns:
            if self._should_trigger_remediation(pattern, scan_result, context):
                task = await self._create_remediation_task(pattern, scan_result, context)
                if task:
                    tasks.append(task)
                    self.pending_tasks.append(task)
        
        # Use LLM for advanced remediation suggestions
        if scan_result.risk_score.score >= 0.8:
            llm_tasks = await self._llm_suggested_remediation(scan_result, context)
            tasks.extend(llm_tasks)
            self.pending_tasks.extend(llm_tasks)
        
        if tasks:
            logger.info(f"Created {len(tasks)} remediation tasks for scan {scan_result.scan_id}")
        
        return tasks
    
    def _should_trigger_remediation(self, pattern: RemediationPattern, 
                                   scan_result: ScanResult, 
                                   context: ScanContext = None) -> bool:
        """Check if remediation pattern should be triggered"""
        # Check threat types
        if not any(threat_type in scan_result.threat_types for threat_type in pattern.threat_types):
            return False
        
        # Check risk threshold
        if scan_result.risk_score.score < pattern.risk_threshold:
            return False
        
        # Check cooldown
        if not self._is_cooldown_expired(pattern.pattern_id, pattern.cooldown_minutes):
            return False
        
        return True
    
    def _is_cooldown_expired(self, pattern_id: str, cooldown_minutes: int) -> bool:
        """Check if cooldown period has expired"""
        if pattern_id not in self.execution_history:
            return True
        
        last_executions = self.execution_history[pattern_id]
        if not last_executions:
            return True
        
        last_execution = max(last_executions)
        cooldown_expiry = last_execution + timedelta(minutes=cooldown_minutes)
        
        return datetime.now(timezone.utc) > cooldown_expiry
    
    async def _create_remediation_task(self, pattern: RemediationPattern,
                                     scan_result: ScanResult,
                                     context: ScanContext = None) -> Optional[RemediationTask]:
        """Create remediation task from pattern"""
        task_id = f"rem_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{str(int(time.time() * 1000))[-6:]}"
        
        # Determine target
        target = self._determine_target(pattern, scan_result, context)
        
        # Prepare parameters
        parameters = pattern.parameters.copy()
        parameters.update({
            "scan_id": scan_result.scan_id,
            "risk_score": scan_result.risk_score.score,
            "threat_types": scan_result.threat_types,
            "user_id": context.user_id if context else None,
            "session_id": context.session_id if context else None
        })
        
        task = RemediationTask(
            task_id=task_id,
            created_at=datetime.now(timezone.utc),
            priority=pattern.priority,
            action=pattern.action,
            description=f"Auto-remediation for {pattern.pattern_id}",
            target=target,
            parameters=parameters,
            trigger_event={
                "scan_result": scan_result,
                "context": context,
                "pattern_id": pattern.pattern_id
            }
        )
        
        # Auto-approve if configured
        if pattern.auto_approve:
            task.status = "APPROVED"
        
        return task
    
    def _determine_target(self, pattern: RemediationPattern,
                         scan_result: ScanResult,
                         context: ScanContext = None) -> str:
        """Determine remediation target"""
        if pattern.action in [RemediationAction.RATE_LIMIT_USER, RemediationAction.BLOCK_IP_RANGE]:
            return context.user_id if context else "unknown_user"
        
        elif pattern.action in [RemediationAction.UPDATE_PATTERNS, RemediationAction.UPDATE_PROMPT]:
            return "security_system"
        
        elif pattern.action == RemediationAction.ENHANCE_MONITORING:
            return context.application if context else "unknown_application"
        
        else:
            return "system"
    
    async def _llm_suggested_remediation(self, scan_result: ScanResult,
                                      context: ScanContext = None) -> List[RemediationTask]:
        """Get LLM-suggested remediation actions"""
        try:
            # Prepare threat data for LLM
            threat_data = {
                "risk_score": scan_result.risk_score.score,
                "risk_level": scan_result.risk_score.level.value,
                "threat_types": scan_result.threat_types,
                "explanation": scan_result.risk_score.explanation,
                "user_id": context.user_id if context else None,
                "application": context.application if context else None
            }
            
            # Get LLM remediation suggestions
            llm_result = await self.llm_analyzer.suggest_remediation(threat_data)
            
            if not llm_result.threat_detected:
                return []
            
            tasks = []
            for recommendation in llm_result.recommendations:
                task = await self._create_task_from_recommendation(
                    recommendation, scan_result, context
                )
                if task:
                    tasks.append(task)
            
            return tasks
            
        except Exception as e:
            logger.error(f"LLM remediation analysis failed: {e}")
            return []
    
    async def _create_task_from_recommendation(self, recommendation: str,
                                            scan_result: ScanResult,
                                            context: ScanContext = None) -> Optional[RemediationTask]:
        """Create remediation task from LLM recommendation"""
        # Map recommendation text to actions
        recommendation_lower = recommendation.lower()
        
        if "update pattern" in recommendation_lower or "add pattern" in recommendation_lower:
            action = RemediationAction.UPDATE_PATTERNS
        elif "rate limit" in recommendation_lower:
            action = RemediationAction.RATE_LIMIT_USER
        elif "enhance monitoring" in recommendation_lower:
            action = RemediationAction.ENHANCE_MONITORING
        elif "update prompt" in recommendation_lower:
            action = RemediationAction.UPDATE_PROMPT
        else:
            return None  # Unknown action
        
        task_id = f"llm_rem_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{str(int(time.time() * 1000))[-6:]}"
        
        task = RemediationTask(
            task_id=task_id,
            created_at=datetime.now(timezone.utc),
            priority=RemediationPriority.MEDIUM,  # LLM suggestions are medium priority
            action=action,
            description=f"LLM-recommended: {recommendation}",
            target=self._determine_target_from_action(action, context),
            parameters={
                "recommendation": recommendation,
                "scan_id": scan_result.scan_id,
                "llm_confidence": 0.7  # Default confidence for LLM suggestions
            },
            trigger_event={
                "scan_result": scan_result,
                "context": context,
                "source": "llm_recommendation"
            }
        )
        
        return task
    
    def _determine_target_from_action(self, action: RemediationAction, 
                                   context: ScanContext = None) -> str:
        """Determine target from action type"""
        if action == RemediationAction.RATE_LIMIT_USER:
            return context.user_id if context else "unknown_user"
        elif action in [RemediationAction.UPDATE_PATTERNS, RemediationAction.UPDATE_PROMPT]:
            return "security_system"
        elif action == RemediationAction.ENHANCE_MONITORING:
            return context.application if context else "unknown_application"
        else:
            return "system"
    
    async def _processing_loop(self):
        """Background processing loop for remediation tasks"""
        while self.is_processing:
            try:
                # Process pending tasks by priority
                if self.pending_tasks:
                    # Sort by priority
                    priority_order = {
                        RemediationPriority.CRITICAL: 0,
                        RemediationPriority.HIGH: 1,
                        RemediationPriority.MEDIUM: 2,
                        RemediationPriority.LOW: 3
                    }
                    
                    self.pending_tasks.sort(key=lambda t: priority_order.get(t.priority, 4))
                    
                    # Process next task
                    task = self.pending_tasks.pop(0)
                    if task.status == "APPROVED" or task.auto_approve:
                        await self._execute_task(task)
                
                await asyncio.sleep(1)  # Process every second
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Remediation processing error: {e}")
                await asyncio.sleep(5)
    
    async def _execute_task(self, task: RemediationTask):
        """Execute a remediation task"""
        task.status = "RUNNING"
        task.started_at = datetime.now(timezone.utc)
        self.active_tasks[task.task_id] = task
        
        start_time = time.perf_counter()
        
        try:
            # Execute based on action type
            if task.action == RemediationAction.UPDATE_PATTERNS:
                result = await self._execute_update_patterns(task)
            elif task.action == RemediationAction.RATE_LIMIT_USER:
                result = await self._execute_rate_limit_user(task)
            elif task.action == RemediationAction.ENHANCE_MONITORING:
                result = await self._execute_enhance_monitoring(task)
            elif task.action == RemediationAction.UPDATE_PROMPT:
                result = await self._execute_update_prompt(task)
            else:
                result = {"success": False, "message": f"Unknown action: {task.action}"}
            
            task.success = result.get("success", False)
            task.result = result
            
            if task.success:
                task.status = "COMPLETED"
                self.successful_remediations += 1
            else:
                task.status = "FAILED"
                task.error_message = result.get("message", "Unknown error")
            
            # Update execution history for cooldown
            if task.success:
                pattern_id = task.trigger_event.get("pattern_id", "manual")
                if pattern_id not in self.execution_history:
                    self.execution_history[pattern_id] = []
                self.execution_history[pattern_id].append(task.started_at)
            
        except Exception as e:
            task.status = "FAILED"
            task.error_message = str(e)
            logger.error(f"Remediation task {task.task_id} failed: {e}")
        
        finally:
            task.completed_at = datetime.now(timezone.utc)
            task.execution_time_ms = (time.perf_counter() - start_time) * 1000
            self.total_remediations += 1
            
            # Move to completed tasks
            if task.task_id in self.active_tasks:
                del self.active_tasks[task.task_id]
            self.completed_tasks.append(task)
            
            logger.info(f"Remediation task {task.task_id} completed: {task.status}")
    
    async def _execute_update_patterns(self, task: RemediationTask) -> Dict[str, Any]:
        """Execute pattern update remediation"""
        # In a real implementation, this would update the pattern database
        logger.info(f"Updating security patterns: {task.parameters}")
        
        # Simulate pattern update
        await asyncio.sleep(2)
        
        return {
            "success": True,
            "message": "Security patterns updated successfully",
            "patterns_added": 1,
            "new_threat_types": task.parameters.get("threat_types", [])
        }
    
    async def _execute_rate_limit_user(self, task: RemediationTask) -> Dict[str, Any]:
        """Execute user rate limiting remediation"""
        user_id = task.target
        limit_per_hour = task.parameters.get("limit_per_hour", 10)
        duration_hours = task.parameters.get("duration_hours", 24)
        
        logger.info(f"Applying rate limit to user {user_id}: {limit_per_hour}/hour for {duration_hours}h")
        
        # Simulate rate limiting
        await asyncio.sleep(1)
        
        return {
            "success": True,
            "message": f"Rate limit applied to user {user_id}",
            "limit_per_hour": limit_per_hour,
            "duration_hours": duration_hours
        }
    
    async def _execute_enhance_monitoring(self, task: RemediationTask) -> Dict[str, Any]:
        """Execute enhanced monitoring remediation"""
        target = task.target
        monitoring_level = task.parameters.get("monitoring_level", "high")
        
        logger.info(f"Enhancing monitoring for {target} to level {monitoring_level}")
        
        # Simulate monitoring enhancement
        await asyncio.sleep(1)
        
        return {
            "success": True,
            "message": f"Monitoring enhanced for {target}",
            "monitoring_level": monitoring_level
        }
    
    async def _execute_update_prompt(self, task: RemediationTask) -> Dict[str, Any]:
        """Execute prompt update remediation"""
        logger.info(f"Updating system prompts: {task.parameters}")
        
        # Simulate prompt update
        await asyncio.sleep(3)
        
        return {
            "success": True,
            "message": "System prompts updated successfully",
            "strengthened_instructions": task.parameters.get("strengthen_instructions", False)
        }
    
    def get_remediation_statistics(self) -> Dict[str, Any]:
        """Get remediation statistics"""
        return {
            "total_remediations": self.total_remediations,
            "successful_remediations": self.successful_remediations,
            "success_rate": self.successful_remediations / self.total_remediations if self.total_remediations > 0 else 0,
            "pending_tasks": len(self.pending_tasks),
            "active_tasks": len(self.active_tasks),
            "completed_tasks": len(self.completed_tasks),
            "patterns_configured": len(self.remediation_patterns)
        }
    
    def get_recent_tasks(self, limit: int = 20) -> List[RemediationTask]:
        """Get recent remediation tasks"""
        return sorted(self.completed_tasks, key=lambda t: t.created_at, reverse=True)[:limit]


# Global auto-remediation engine instance
auto_remediation = AutoRemediationEngine()
