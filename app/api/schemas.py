"""
Pydantic schemas for SentinelShield AI Security Platform API
Request and response models with validation
"""

from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field, validator
import re


class RiskLevel(str, Enum):
    """Risk level enumeration"""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatType(str, Enum):
    """Threat type enumeration"""
    PROMPT_INJECTION = "prompt_injection"
    INSECURE_OUTPUT_HANDLING = "insecure_output_handling"
    TRAINING_DATA_POISONING = "training_data_poisoning"
    MODEL_DENIAL_OF_SERVICE = "model_denial_of_service"
    SUPPLY_CHAIN_VULNERABILITIES = "supply_chain_vulnerabilities"
    SENSITIVE_INFORMATION_DISCLOSURE = "sensitive_information_disclosure"
    INSECURE_PLUGIN_DESIGN = "insecure_plugin_design"
    EXCESSIVE_AGENCY = "excessive_agency"
    OVERRELIANCE = "overreliance"
    MODEL_THEFT = "model_theft"
    SOCIAL_ENGINEERING = "social_engineering"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    GOAL_HIJACKING = "goal_hijacking"
    DATA_EXFILTRATION = "data_exfiltration"


# Request Schemas
class ScanContext(BaseModel):
    """Context for security scan"""
    user_id: Optional[str] = Field(None, description="User identifier")
    session_id: Optional[str] = Field(None, description="Session identifier")
    application: Optional[str] = Field(None, description="Application name")
    user_role: Optional[str] = Field(None, description="User role")
    previous_messages: Optional[List[Dict[str, Any]]] = Field(default=[], description="Previous messages in session")
    system_prompt_hash: Optional[str] = Field(None, description="Hash of system prompt")
    
    @validator('user_id')
    def validate_user_id(cls, v):
        if v and len(v) > 128:
            raise ValueError('user_id must be 128 characters or less')
        return v
    
    @validator('session_id')
    def validate_session_id(cls, v):
        if v and len(v) > 128:
            raise ValueError('session_id must be 128 characters or less')
        return v


class ScanOptions(BaseModel):
    """Options for security scan"""
    use_llm_analysis: bool = Field(default=True, description="Enable LLM analysis")
    return_explanation: bool = Field(default=True, description="Return detailed explanation")
    auto_block: bool = Field(default=True, description="Automatically block threats")
    use_cache: bool = Field(default=True, description="Use cached results")
    semantic_threshold: Optional[float] = Field(default=0.8, ge=0.0, le=1.0, description="Semantic similarity threshold")
    
    @validator('semantic_threshold')
    def validate_semantic_threshold(cls, v):
        if v is not None and (v < 0.0 or v > 1.0):
            raise ValueError('semantic_threshold must be between 0.0 and 1.0')
        return v


class ScanRequest(BaseModel):
    """Security scan request"""
    prompt: str = Field(..., min_length=1, max_length=10000, description="Text to analyze for threats")
    context: Optional[ScanContext] = Field(default=None, description="Scan context")
    options: Optional[ScanOptions] = Field(default=None, description="Scan options")
    
    @validator('prompt')
    def validate_prompt(cls, v):
        if not v or not v.strip():
            raise ValueError('prompt cannot be empty')
        if len(v) > 10000:
            raise ValueError('prompt must be 10000 characters or less')
        return v.strip()


class BatchScanRequest(BaseModel):
    """Batch scan request"""
    prompts: List[str] = Field(..., min_items=1, max_items=100, description="List of prompts to analyze")
    context: Optional[ScanContext] = Field(default=None, description="Common context for all prompts")
    options: Optional[ScanOptions] = Field(default=None, description="Scan options")
    
    @validator('prompts')
    def validate_prompts(cls, v):
        if len(v) > 100:
            raise ValueError('Cannot process more than 100 prompts in a single batch')
        for i, prompt in enumerate(v):
            if not prompt or not prompt.strip():
                raise ValueError(f'Prompt at index {i} cannot be empty')
            if len(prompt) > 10000:
                raise ValueError(f'Prompt at index {i} must be 10000 characters or less')
        return [p.strip() for p in v]


class RedTeamCategory(str, Enum):
    """Red team attack categories"""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_EXFILTRATION = "data_exfiltration"
    MODEL_THEFT = "model_theft"
    SOCIAL_ENGINEERING = "social_engineering"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    GOAL_HIJACKING = "goal_hijacking"
    AGENT_COMPROMISE = "agent_compromise"
    DENIAL_OF_SERVICE = "denial_of_service"
    SUPPLY_CHAIN = "supply_chain"


class RedTeamIntensity(str, Enum):
    """Red team testing intensity"""
    QUICK = "quick"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"


class RedTeamTargetType(str, Enum):
    """Target system types"""
    OPENAI_COMPATIBLE = "openai_compatible"
    AZURE_OPENAI = "azure_openai"
    ANTHROPIC = "anthropic"
    HUGGINGFACE = "huggingface"
    CUSTOM = "custom"


class RedTeamRequest(BaseModel):
    """Red team testing request"""
    target_endpoint: str = Field(..., description="Target API endpoint URL")
    target_type: RedTeamTargetType = Field(..., description="Type of target system")
    categories: List[RedTeamCategory] = Field(..., min_items=1, description="Attack categories to test")
    intensity: RedTeamIntensity = Field(default=RedTeamIntensity.STANDARD, description="Testing intensity")
    max_attacks: Optional[int] = Field(default=200, ge=1, le=1000, description="Maximum number of attacks")
    headers: Optional[Dict[str, str]] = Field(default=None, description="Additional HTTP headers")
    
    @validator('target_endpoint')
    def validate_target_endpoint(cls, v):
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        if not url_pattern.match(v):
            raise ValueError('target_endpoint must be a valid URL')
        return v
    
    @validator('max_attacks')
    def validate_max_attacks(cls, v):
        if v is not None and (v < 1 or v > 1000):
            raise ValueError('max_attacks must be between 1 and 1000')
        return v


class AgentRegistrationRequest(BaseModel):
    """Agent registration request"""
    agent_id: str = Field(..., min_length=1, max_length=128, description="Unique agent identifier")
    agent_role: str = Field(..., description="Agent role (customer_service, data_analyst, etc.)")
    application: str = Field(..., description="Application name")
    user_id: str = Field(..., description="User ID registering the agent")
    declared_goal: str = Field(..., min_length=1, max_length=1000, description="Agent's declared goal")
    
    @validator('agent_role')
    def validate_agent_role(cls, v):
        valid_roles = [
            "customer_service", "data_analyst", "content_creator", 
            "research_assistant", "admin", "developer", "system"
        ]
        if v not in valid_roles:
            raise ValueError(f'agent_role must be one of: {", ".join(valid_roles)}')
        return v


class AgentActionRequest(BaseModel):
    """Agent action monitoring request"""
    session_id: str = Field(..., description="Agent session ID")
    action_type: str = Field(..., description="Type of action")
    tool_name: Optional[str] = Field(None, description="Tool being used")
    parameters: Dict[str, Any] = Field(default={}, description="Action parameters")
    execution_time_ms: Optional[float] = Field(default=0.0, description="Execution time in milliseconds")
    success: bool = Field(default=True, description="Whether action succeeded")
    error_message: Optional[str] = Field(None, description="Error message if action failed")


class ComplianceReportRequest(BaseModel):
    """Compliance report generation request"""
    report_type: str = Field(default="owasp", description="Type of compliance report")
    application: Optional[str] = Field(None, description="Application to generate report for")
    period_start: Optional[datetime] = Field(None, description="Start of reporting period")
    period_end: Optional[datetime] = Field(None, description="End of reporting period")
    format: str = Field(default="json", description="Report format (json or pdf)")
    
    @validator('report_type')
    def validate_report_type(cls, v):
        if v not in ["owasp", "gdpr", "soc2", "custom"]:
            raise ValueError('report_type must be one of: owasp, gdpr, soc2, custom')
        return v
    
    @validator('format')
    def validate_format(cls, v):
        if v not in ["json", "pdf"]:
            raise ValueError('format must be either json or pdf')
        return v


# Response Schemas
class PatternMatch(BaseModel):
    """Pattern match result"""
    category: str
    severity: str
    pattern: str
    matched_text: str
    confidence: float
    description: str


class LayerResult(BaseModel):
    """Analysis layer result"""
    threat_detected: bool
    risk_score: float
    processing_time_ms: float
    details: Optional[Dict[str, Any]] = None


class ScanResponse(BaseModel):
    """Security scan response"""
    scan_id: str
    timestamp: datetime
    decision: str  # ALLOW/BLOCK
    risk_score: float
    risk_level: RiskLevel
    threat_types: List[ThreatType]
    confidence: float
    processing_time_ms: float
    explanation: List[str]
    recommendations: List[str]
    blocked: bool
    incident_id: Optional[str] = None
    
    # Layer results (optional for detailed responses)
    pattern_result: Optional[LayerResult] = None
    semantic_result: Optional[LayerResult] = None
    context_result: Optional[LayerResult] = None
    llm_result: Optional[LayerResult] = None


class BatchScanResponse(BaseModel):
    """Batch scan response"""
    job_id: str
    status: str
    total_prompts: int
    completed_prompts: int
    results: Optional[List[ScanResponse]] = None
    errors: Optional[List[str]] = None


class RedTeamJobStatus(BaseModel):
    """Red team job status"""
    job_id: str
    status: str
    progress: float
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    estimated_time_remaining: Optional[int] = None
    error: Optional[str] = None


class VulnerabilityFinding(BaseModel):
    """Vulnerability finding"""
    category: str
    payload: str
    success_rate: float
    severity: str
    description: str
    remediation: str
    evidence: List[str]


class RedTeamReport(BaseModel):
    """Red team test report"""
    job_id: str
    target_endpoint: str
    target_type: str
    completed_at: datetime
    security_score: float
    grade: str
    attacks_run: int
    attacks_succeeded: int
    attacks_blocked: int
    critical_vulnerabilities: List[VulnerabilityFinding]
    owasp_coverage: Dict[str, str]
    detailed_results: Optional[List[Dict[str, Any]]] = None


class AgentSessionInfo(BaseModel):
    """Agent session information"""
    session_id: str
    agent_id: str
    agent_role: str
    application: str
    user_id: str
    declared_goal: str
    status: str
    created_at: datetime
    duration_seconds: float
    total_actions: int
    blocked_actions: int
    risk_score: float
    kill_switch_triggered: bool


class AgentActionResponse(BaseModel):
    """Agent action evaluation response"""
    action_id: str
    allowed: bool
    risk_score: float
    risk_level: RiskLevel
    threat_types: List[ThreatType]
    blocked: bool
    reason: Optional[str] = None


class ComplianceCategory(BaseModel):
    """Compliance category assessment"""
    category: str
    status: str
    score: float
    confidence: float
    findings: List[str]
    recommendations: List[str]


class ComplianceReportResponse(BaseModel):
    """Compliance report response"""
    report_id: str
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    application: str
    overall_score: float
    overall_status: str
    compliant_categories: int
    total_categories: int
    category_assessments: List[ComplianceCategory]
    executive_summary: str
    priority_actions: List[str]
    download_url: Optional[str] = None


# Health Check Schemas
class HealthCheck(BaseModel):
    """Health check response"""
    status: str
    timestamp: datetime
    version: str
    uptime_seconds: float
    components: Dict[str, Dict[str, Any]]


class ComponentHealth(BaseModel):
    """Component health status"""
    status: str
    message: Optional[str] = None
    response_time_ms: Optional[float] = None
    last_check: datetime


# Error Response Schemas
class ErrorDetail(BaseModel):
    """Error detail"""
    code: str
    message: str
    field: Optional[str] = None


class ErrorResponse(BaseModel):
    """Error response"""
    error: str
    message: str
    details: Optional[List[ErrorDetail]] = None
    timestamp: datetime
    request_id: Optional[str] = None


# Pagination Schemas
class PaginationParams(BaseModel):
    """Pagination parameters"""
    offset: int = Field(default=0, ge=0, description="Number of items to skip")
    limit: int = Field(default=50, ge=1, le=1000, description="Number of items to return")
    
    @validator('limit')
    def validate_limit(cls, v):
        if v < 1 or v > 1000:
            raise ValueError('limit must be between 1 and 1000')
        return v


class PaginatedResponse(BaseModel):
    """Paginated response"""
    items: List[Any]
    total: int
    offset: int
    limit: int
    has_next: bool
    has_previous: bool


# Statistics Schemas
class ThreatStatistics(BaseModel):
    """Threat detection statistics"""
    total_scans: int
    blocked_scans: int
    block_rate: float
    threat_breakdown: Dict[str, int]
    average_processing_time_ms: float
    period_hours: int


class SystemMetrics(BaseModel):
    """System performance metrics"""
    total_requests: int
    average_response_time_ms: float
    requests_per_second: float
    error_rate: float
    uptime_seconds: float
    memory_usage_mb: float
    cpu_usage_percent: float
