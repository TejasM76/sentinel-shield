"""
Security scan API routes for SentinelShield AI Security Platform
Endpoints for prompt scanning, threat detection, and security analysis
"""

import time
import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Request, Response
from fastapi.responses import JSONResponse
import logging

from app.api.schemas import (
    ScanRequest, ScanResponse, BatchScanRequest, BatchScanResponse,
    ThreatStatistics, ErrorDetail, ErrorResponse
)
from app.api.middleware.auth import get_current_active_user, require_permission
from app.api.middleware.rate_limiter import get_rate_limit_headers, check_rate_limit
from app.core.detector import ThreatDetector, ScanContext, ScanOptions
from app.compliance.audit_trail import audit_trail
from app.response.playbooks import playbook_manager
from app.response.auto_remediate import auto_remediation
from app.response.notifier import alert_notifier
from app.db.repositories import ScanResultRepository
from app.db.database import get_db
from app.db.models import ThreatType

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scan", tags=["Security Scanning"])

# Initialize detector
detector = ThreatDetector()


@router.post("/", response_model=ScanResponse, status_code=200)
async def scan_prompt(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    http_request: Request,
    current_user: Dict[str, Any] = Depends(get_current_active_user)
):
    """
    Scan a prompt for security threats
    
    Analyzes the input text for various types of AI security threats including:
    - Prompt injection attacks
    - Jailbreak attempts
    - Data exfiltration attempts
    - Model theft attempts
    - Social engineering attacks
    
    Returns detailed risk assessment with recommendations.
    """
    try:
        # Check rate limits
        allowed, limit_info = await check_rate_limit(http_request, current_user)
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(limit_info.get("retry_after", 60))}
            )
        
        # Create scan context
        context = ScanContext(
            user_id=request.context.user_id if request.context else current_user.get("user_id"),
            session_id=request.context.session_id if request.context else None,
            application=request.context.application if request.context else "api",
            user_role=request.context.user_role if request.context else current_user.get("role"),
            previous_messages=request.context.previous_messages if request.context else [],
            system_prompt_hash=request.context.system_prompt_hash if request.context else None,
            timestamp=datetime.now(timezone.utc)
        )
        
        # Create scan options
        options = ScanOptions(
            use_llm_analysis=request.options.use_llm_analysis if request.options else True,
            return_explanation=request.options.return_explanation if request.options else True,
            auto_block=request.options.auto_block if request.options else True,
            use_cache=request.options.use_cache if request.options else True,
            semantic_threshold=request.options.semantic_threshold if request.options else None
        )
        
        # Perform scan
        scan_result = await detector.analyze(request.prompt, context, options)
        
        # Log to audit trail
        await audit_trail.log_threat_detected(
            scan_id=scan_result.scan_id,
            actor=current_user.get("user_id"),
            threat_types=scan_result.threat_types,
            risk_score=scan_result.risk_score.score,
            blocked=scan_result.blocked,
            user_id=context.user_id,
            session_id=context.session_id,
            ip_address=http_request.client.host if http_request.client else None
        )
        
        # Auto-remediation for high-risk threats
        if scan_result.blocked and scan_result.risk_score.score >= 0.8:
            background_tasks.add_task(
                auto_remediation.analyze_and_remediate,
                scan_result,
                context.__dict__
            )
        
        # Auto-execute playbooks if threat detected
        if scan_result.blocked:
            background_tasks.add_task(
                playbook_manager.auto_execute,
                scan_result,
                context.__dict__
            )
        
        # Send alerts for critical threats
        if scan_result.risk_score.level.value in ["HIGH", "CRITICAL"]:
            background_tasks.add_task(
                alert_notifier.send_alert,
                {
                    "alert_id": f"alert_{scan_result.scan_id}",
                    "timestamp": datetime.now(timezone.utc),
                    "severity": scan_result.risk_score.level.value,
                    "title": f"Security Threat Detected: {scan_result.risk_score.level.value}",
                    "message": f"Threat types: {', '.join(scan_result.threat_types)}",
                    "details": {
                        "scan_id": scan_result.scan_id,
                        "risk_score": scan_result.risk_score.score,
                        "user_id": context.user_id,
                        "application": context.application
                    },
                    "source": "sentinel_shield_api",
                    "incident_id": scan_result.incident_id,
                    "user_id": context.user_id,
                    "session_id": context.session_id
                }
            )
        
        # Create response
        response = ScanResponse(
            scan_id=scan_result.scan_id,
            timestamp=scan_result.timestamp,
            decision=scan_result.decision,
            risk_score=scan_result.risk_score.score,
            risk_level=scan_result.risk_score.level,
            threat_types=[ThreatType(t) for t in scan_result.threat_types],
            confidence=scan_result.risk_score.confidence,
            processing_time_ms=scan_result.processing_time_ms,
            explanation=scan_result.risk_score.explanation,
            recommendations=scan_result.risk_score.recommendations,
            blocked=scan_result.blocked,
            incident_id=scan_result.incident_id
        )
        
        # Add rate limit headers
        headers = await get_rate_limit_headers(http_request, current_user)
        
        return JSONResponse(
            content=response.dict(),
            headers=headers
        )
        
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error during security scan"
        )


@router.post("/batch", response_model=BatchScanResponse, status_code=202)
async def scan_batch(
    request: BatchScanRequest,
    background_tasks: BackgroundTasks,
    http_request: Request,
    current_user: Dict[str, Any] = Depends(get_current_active_user)
):
    """
    Scan multiple prompts in parallel
    
    Processes up to 100 prompts in a single request for efficiency.
    Returns a job ID that can be used to retrieve results.
    """
    try:
        # Check rate limits
        allowed, limit_info = await check_rate_limit(http_request, current_user)
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(limit_info.get("retry_after", 60))}
            )
        
        # Generate job ID
        job_id = f"batch_{uuid.uuid4().hex[:8]}"
        
        # Create scan context
        context = ScanContext(
            user_id=request.context.user_id if request.context else current_user.get("user_id"),
            session_id=request.context.session_id if request.context else None,
            application=request.context.application if request.context else "api_batch",
            user_role=request.context.user_role if request.context else current_user.get("role"),
            previous_messages=request.context.previous_messages if request.context else [],
            system_prompt_hash=request.context.system_prompt_hash if request.context else None,
            timestamp=datetime.now(timezone.utc)
        )
        
        # Create scan options
        options = ScanOptions(
            use_llm_analysis=request.options.use_llm_analysis if request.options else True,
            return_explanation=request.options.return_explanation if request.options else True,
            auto_block=request.options.auto_block if request.options else True,
            use_cache=request.options.use_cache if request.options else True,
            semantic_threshold=request.options.semantic_threshold if request.options else None
        )
        
        # Start background processing
        background_tasks.add_task(
            process_batch_scan,
            job_id,
            request.prompts,
            context,
            options,
            current_user
        )
        
        # Log batch scan initiation
        await audit_trail.log_configuration_change(
            actor=current_user.get("user_id"),
            component="batch_scanner",
            setting="batch_scan_started",
            old_value=None,
            new_value={
                "job_id": job_id,
                "prompt_count": len(request.prompts),
                "user_id": context.user_id
            }
        )
        
        return BatchScanResponse(
            job_id=job_id,
            status="processing",
            total_prompts=len(request.prompts),
            completed_prompts=0
        )
        
    except Exception as e:
        logger.error(f"Batch scan failed to start: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error starting batch scan"
        )


@router.get("/batch/{job_id}", response_model=BatchScanResponse)
async def get_batch_status(
    job_id: str,
    current_user: Dict[str, Any] = Depends(get_current_active_user)
):
    """
    Get status of a batch scan job
    
    Returns the current status and results if completed.
    """
    try:
        # In a real implementation, would check database or cache
        # For now, return placeholder status
        
        # This would typically check a job queue or database
        return BatchScanResponse(
            job_id=job_id,
            status="completed",  # or "processing", "failed"
            total_prompts=0,
            completed_prompts=0,
            results=[]  # Would contain actual scan results
        )
        
    except Exception as e:
        logger.error(f"Failed to get batch status: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error retrieving batch status"
        )


@router.get("/statistics", response_model=ThreatStatistics)
async def get_scan_statistics(
    hours: int = 24,
    current_user: Dict[str, Any] = Depends(
        require_permission("compliance_read")
    )
):
    """
    Get threat detection statistics
    
    Returns comprehensive statistics about threats detected
    over the specified time period.
    """
    try:
        if hours < 1 or hours > 8760:  # Max 1 year
            raise HTTPException(
                status_code=400,
                detail="Hours must be between 1 and 8760"
            )
        
        # Get statistics from repository
        async for db in get_db():
            repo = ScanResultRepository(db)
            stats = await repo.get_threat_statistics(hours)
            
            return ThreatStatistics(
                total_scans=stats["total_scans"],
                blocked_scans=stats["blocked_scans"],
                block_rate=stats["block_rate"],
                threat_breakdown=stats["threat_breakdown"],
                average_processing_time_ms=stats["average_processing_time_ms"],
                period_hours=hours
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get statistics: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error retrieving statistics"
        )


@router.get("/history")
async def get_scan_history(
    offset: int = 0,
    limit: int = 50,
    user_id: Optional[str] = None,
    risk_level: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(
        require_permission("compliance_read")
    )
):
    """
    Get scan history with pagination
    
    Returns historical scan results with filtering options.
    """
    try:
        if offset < 0 or limit < 1 or limit > 1000:
            raise HTTPException(
                status_code=400,
                detail="Invalid pagination parameters"
            )
        
        # Get scan results from repository
        async for db in get_db():
            repo = ScanResultRepository(db)
            
            # Build filters
            if user_id:
                results = await repo.get_by_user(user_id, limit)
            elif risk_level:
                from app.db.models import RiskLevel
                results = await repo.get_by_risk_level(RiskLevel(risk_level), hours=24*30)  # Last 30 days
            else:
                # Get recent scans
                # This would need a method in the repository
                results = []
            
            return {
                "results": results,
                "offset": offset,
                "limit": limit,
                "total": len(results)
            }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scan history: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error retrieving scan history"
        )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_result(
    scan_id: str,
    current_user: Dict[str, Any] = Depends(get_current_active_user)
):
    """
    Get detailed scan result by ID
    
    Returns complete details of a specific security scan.
    """
    try:
        # Get scan result from repository
        async for db in get_db():
            repo = ScanResultRepository(db)
            result = await repo.get_by_id(scan_id)
            
            if not result:
                raise HTTPException(
                    status_code=404,
                    detail="Scan result not found"
                )
            
            # Convert to response format
            return ScanResponse(
                scan_id=result.scan_id,
                timestamp=result.timestamp,
                decision=result.decision,
                risk_score=result.risk_score,
                risk_level=result.risk_level,
                threat_types=[ThreatType(t) for t in result.threat_types],
                confidence=result.confidence,
                processing_time_ms=result.processing_time_ms,
                explanation=result.explanation,
                recommendations=result.recommendations,
                blocked=result.blocked,
                incident_id=result.incident_id
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scan result: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error retrieving scan result"
        )


# Background task for batch processing
async def process_batch_scan(
    job_id: str,
    prompts: List[str],
    context: ScanContext,
    options: ScanOptions,
    user_info: Dict[str, Any]
):
    """Process batch scan in background"""
    try:
        results = []
        
        # Process each prompt
        scan_results = await detector.analyze_batch(prompts, [context] * len(prompts), options)
        
        # Convert to response format
        for scan_result in scan_results:
            response = ScanResponse(
                scan_id=scan_result.scan_id,
                timestamp=scan_result.timestamp,
                decision=scan_result.decision,
                risk_score=scan_result.risk_score.score,
                risk_level=scan_result.risk_score.level,
                threat_types=[ThreatType(t) for t in scan_result.threat_types],
                confidence=scan_result.risk_score.confidence,
                processing_time_ms=scan_result.processing_time_ms,
                explanation=scan_result.risk_score.explanation,
                recommendations=scan_result.risk_score.recommendations,
                blocked=scan_result.blocked,
                incident_id=scan_result.incident_id
            )
            results.append(response)
        
        # In a real implementation, would store results in database
        # For now, just log completion
        logger.info(f"Batch scan {job_id} completed: {len(results)} results processed")
        
        # Log to audit trail
        await audit_trail.log_configuration_change(
            actor=user_info.get("user_id"),
            component="batch_scanner",
            setting="batch_scan_completed",
            old_value=None,
            new_value={
                "job_id": job_id,
                "results_count": len(results),
                "blocked_count": sum(1 for r in results if r.blocked)
            }
        )
        
    except Exception as e:
        logger.error(f"Batch scan {job_id} failed: {e}")
        
        # Log failure to audit trail
        await audit_trail.log_configuration_change(
            actor=user_info.get("user_id"),
            component="batch_scanner",
            setting="batch_scan_failed",
            old_value=None,
            new_value={
                "job_id": job_id,
                "error": str(e)
            }
        )
