"""
Database models for SentinelShield AI Security Platform
SQLAlchemy models for threat detection, monitoring, and compliance
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from enum import Enum
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, Text, 
    JSON, ForeignKey, Index, UniqueConstraint
)
from sqlalchemy.orm import DeclarativeBase, relationship
import uuid


class Base(DeclarativeBase):
    """Base class for all models"""
    pass


class RiskLevel(str, Enum):
    """Risk level enumeration"""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatType(str, Enum):
    """Threat type enumeration based on OWASP LLM Top 10"""
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


class ScanResult(Base):
    """Threat scan result model"""
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    # Input data
    prompt = Column(Text, nullable=False)
    prompt_hash = Column(String(64), index=True, nullable=False)
    user_id = Column(String(128), index=True)
    session_id = Column(String(128), index=True)
    application = Column(String(128), index=True)
    user_role = Column(String(64))
    system_prompt_hash = Column(String(64))
    
    # Analysis results
    decision = Column(String(20), nullable=False)  # ALLOW/BLOCK
    risk_score = Column(Float, nullable=False)
    risk_level = Column(String(20), nullable=False)
    threat_types = Column(JSON)  # List of threat types
    confidence = Column(Float, nullable=False)
    processing_time_ms = Column(Float, nullable=False)
    
    # Detailed analysis
    explanation = Column(JSON)  # List of explanations
    recommendations = Column(JSON)  # List of recommendations
    evidence = Column(JSON)  # Audit trail evidence
    
    # Layer results
    pattern_result = Column(JSON)
    semantic_result = Column(JSON)
    llm_result = Column(JSON)
    context_result = Column(JSON)
    
    # Metadata
    blocked = Column(Boolean, default=False)
    incident_id = Column(String(64), index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_scan_timestamp', 'timestamp'),
        Index('idx_scan_user_session', 'user_id', 'session_id'),
        Index('idx_scan_risk_level', 'risk_level'),
    )


class Incident(Base):
    """Security incident model"""
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    # Incident details
    title = Column(String(256), nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False)  # LOW/MEDIUM/HIGH/CRITICAL
    status = Column(String(20), default="OPEN")  # OPEN/INVESTIGATING/RESOLVED/CLOSED
    
    # Related entities
    user_id = Column(String(128), index=True)
    session_id = Column(String(128), index=True)
    application = Column(String(128), index=True)
    scan_results = Column(JSON)  # Related scan result IDs
    
    # Incident data
    threat_types = Column(JSON)
    attack_payload = Column(Text)
    attack_vector = Column(String(128))
    affected_systems = Column(JSON)
    
    # Response actions
    auto_response_taken = Column(JSON)
    manual_actions = Column(JSON)
    escalation_triggered = Column(Boolean, default=False)
    
    # Investigation
    investigation_notes = Column(Text)
    root_cause = Column(Text)
    remediation_steps = Column(JSON)
    
    # Metadata
    resolved_at = Column(DateTime(timezone=True))
    resolved_by = Column(String(128))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    alerts = relationship("Alert", back_populates="incident")


class Alert(Base):
    """Security alert model"""
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    # Alert details
    title = Column(String(256), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    alert_type = Column(String(64), nullable=False)
    
    # Related entities
    incident_id = Column(String(64), ForeignKey("incidents.incident_id"), index=True)
    user_id = Column(String(128), index=True)
    session_id = Column(String(128), index=True)
    
    # Notification status
    slack_sent = Column(Boolean, default=False)
    email_sent = Column(Boolean, default=False)
    webhook_sent = Column(Boolean, default=False)
    acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(String(128))
    acknowledged_at = Column(DateTime(timezone=True))
    
    # Alert data
    alert_metadata = Column("metadata", JSON)
    
    # Relationships
    incident = relationship("Incident", back_populates="alerts")


class AgentSession(Base):
    """AI agent monitoring session"""
    __tablename__ = "agent_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(64), unique=True, index=True, nullable=False)
    agent_id = Column(String(128), index=True, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    # Agent details
    agent_type = Column(String(64))
    agent_role = Column(String(64))
    application = Column(String(128), index=True)
    user_id = Column(String(128), index=True)
    
    # Session state
    status = Column(String(20), default="ACTIVE")  # ACTIVE/PAUSED/TERMINATED/QUARANTINED
    declared_goal = Column(Text)
    current_goal = Column(Text)
    goal_deviation_score = Column(Float, default=0.0)
    
    # Security metrics
    total_actions = Column(Integer, default=0)
    blocked_actions = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)
    max_risk_score = Column(Float, default=0.0)
    
    # Kill switch status
    kill_switch_triggered = Column(Boolean, default=False)
    kill_switch_reason = Column(Text)
    kill_switch_timestamp = Column(DateTime(timezone=True))
    
    # Metadata
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    ended_at = Column(DateTime(timezone=True))


class AgentAction(Base):
    """AI agent action log"""
    __tablename__ = "agent_actions"
    
    id = Column(Integer, primary_key=True, index=True)
    action_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    # Action details
    session_id = Column(String(64), ForeignKey("agent_sessions.session_id"), index=True)
    agent_id = Column(String(128), index=True)
    action_type = Column(String(64), nullable=False)
    tool_name = Column(String(128))
    parameters = Column(JSON)
    
    # Security analysis
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20))
    threat_types = Column(JSON)
    blocked = Column(Boolean, default=False)
    block_reason = Column(Text)
    
    # Goal analysis
    goal_aligned = Column(Boolean)
    goal_deviation_reason = Column(Text)
    
    # Performance metrics
    execution_time_ms = Column(Float)
    success = Column(Boolean)
    error_message = Column(Text)
    
    # Metadata
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class RedTeamJob(Base):
    """Red team testing job"""
    __tablename__ = "redteam_jobs"
    
    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    # Job details
    target_endpoint = Column(String(512), nullable=False)
    target_type = Column(String(64), nullable=False)
    categories = Column(JSON)  # List of attack categories
    intensity = Column(String(32))  # quick/standard/comprehensive
    max_attacks = Column(Integer)
    
    # Job status
    status = Column(String(20), default="PENDING")  # PENDING/RUNNING/COMPLETED/FAILED/CANCELLED
    progress = Column(Float, default=0.0)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    estimated_time_seconds = Column(Integer)
    
    # Results
    attacks_run = Column(Integer, default=0)
    attacks_succeeded = Column(Integer, default=0)
    attacks_blocked = Column(Integer, default=0)
    security_score = Column(Float)
    grade = Column(String(2))  # A-F
    
    # Vulnerabilities found
    critical_vulnerabilities = Column(JSON)
    owasp_coverage = Column(JSON)
    detailed_results = Column(JSON)
    
    # Metadata
    created_by = Column(String(128))
    webhook_url = Column(String(512))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class ComplianceReport(Base):
    """Compliance and audit report"""
    __tablename__ = "compliance_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    # Report details
    report_type = Column(String(64), nullable=False)  # OWASP/GDPR/SOC2/CUSTOM
    period_start = Column(DateTime(timezone=True))
    period_end = Column(DateTime(timezone=True))
    application = Column(String(128), index=True)
    
    # Compliance scores
    overall_score = Column(Float)
    owasp_scores = Column(JSON)  # OWASP LLM Top 10 scores
    compliance_level = Column(String(20))  # COMPLIANT/PARTIAL/NON_COMPLIANT
    
    # Report data
    findings = Column(JSON)
    recommendations = Column(JSON)
    evidence = Column(JSON)
    
    # Report files
    pdf_path = Column(String(512))
    json_path = Column(String(512))
    
    # Metadata
    generated_by = Column(String(128))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class AuditLog(Base):
    """Immutable audit trail"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    log_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    # Log details
    event_type = Column(String(64), nullable=False)
    actor = Column(String(128), nullable=False)
    action = Column(String(128), nullable=False)
    resource = Column(String(256))
    
    # Event data
    details = Column(JSON)
    ip_address = Column(String(45))
    user_agent = Column(String(512))
    
    # Security context
    session_id = Column(String(128))
    request_id = Column(String(64))
    correlation_id = Column(String(64))
    
    # Outcome
    success = Column(Boolean)
    error_message = Column(Text)
    
    # Compliance metadata
    retention_days = Column(Integer, default=2555)  # 7 years default
    compliance_tags = Column(JSON)
    
    # Immutable record
    hash = Column(String(64), nullable=False)  # SHA-256 of record
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    # Indexes
    __table_args__ = (
        Index('idx_audit_timestamp', 'timestamp'),
        Index('idx_audit_actor', 'actor'),
        Index('idx_audit_event_type', 'event_type'),
        Index('idx_audit_session', 'session_id'),
    )
