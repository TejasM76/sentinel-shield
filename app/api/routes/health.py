"""
Health check API routes for SentinelShield AI Security Platform
System health monitoring and component status endpoints
"""

import time
import sys
import platform as platform_info
import psutil
from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse

from app.api.schemas import HealthCheck, ComponentHealth
from app.api.middleware.auth import get_current_active_user
from app.db.database import DatabaseHealthChecker
from app.config import settings

router = APIRouter(prefix="/health", tags=["Health Monitoring"])

# Track startup time
startup_time = time.time()


@router.get("/", response_model=HealthCheck)
async def health_check():
    """
    Comprehensive system health check
    
    Returns the overall health status of the SentinelShield platform
    including all major components and their current status.
    """
    try:
        uptime_seconds = time.time() - startup_time
        
        # Check all components
        components = {}
        
        # Database health
        db_health = await DatabaseHealthChecker.check_connection()
        components["database"] = {
            "status": "healthy" if db_health["status"] == "healthy" else "unhealthy",
            "message": db_health["message"],
            "response_time_ms": 0,  # Would measure actual response time
            "last_check": datetime.now(timezone.utc).isoformat()
        }
        
        # Memory usage
        memory = psutil.virtual_memory()
        components["memory"] = {
            "status": "healthy" if memory.percent < 90 else "degraded" if memory.percent < 95 else "unhealthy",
            "message": f"Memory usage: {memory.percent:.1f}%",
            "response_time_ms": 0,
            "last_check": datetime.now(timezone.utc).isoformat(),
            "details": {
                "used_mb": memory.used / 1024 / 1024,
                "total_mb": memory.total / 1024 / 1024,
                "percent": memory.percent
            }
        }
        
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        components["cpu"] = {
            "status": "healthy" if cpu_percent < 80 else "degraded" if cpu_percent < 95 else "unhealthy",
            "message": f"CPU usage: {cpu_percent:.1f}%",
            "response_time_ms": 0,
            "last_check": datetime.now(timezone.utc).isoformat(),
            "details": {
                "percent": cpu_percent
            }
        }
        
        # Disk usage
        disk = psutil.disk_usage('/')
        disk_percent = (disk.used / disk.total) * 100
        components["disk"] = {
            "status": "healthy" if disk_percent < 80 else "degraded" if disk_percent < 95 else "unhealthy",
            "message": f"Disk usage: {disk_percent:.1f}%",
            "response_time_ms": 0,
            "last_check": datetime.now(timezone.utc).isoformat(),
            "details": {
                "used_gb": disk.used / 1024 / 1024 / 1024,
                "total_gb": disk.total / 1024 / 1024 / 1024,
                "percent": disk_percent
            }
        }
        
        # Determine overall status
        component_statuses = [comp["status"] for comp in components.values()]
        
        if all(status == "healthy" for status in component_statuses):
            overall_status = "healthy"
        elif any(status == "unhealthy" for status in component_statuses):
            overall_status = "unhealthy"
        else:
            overall_status = "degraded"
        
        return HealthCheck(
            status=overall_status,
            timestamp=datetime.now(timezone.utc),
            version="1.0.0",
            uptime_seconds=uptime_seconds,
            components=components
        )
        
    except Exception as e:
        # Return unhealthy status if health check fails
        return HealthCheck(
            status="unhealthy",
            timestamp=datetime.now(timezone.utc),
            version="1.0.0",
            uptime_seconds=time.time() - startup_time,
            components={
                "health_check": {
                    "status": "unhealthy",
                    "message": f"Health check failed: {str(e)}",
                    "response_time_ms": 0,
                    "last_check": datetime.now(timezone.utc).isoformat()
                }
            }
        )


@router.get("/simple")
async def simple_health_check():
    """
    Simple health check endpoint
    
    Returns minimal health information suitable for load balancers
    and monitoring systems. Always returns 200 if the service is running.
    """
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "sentinel-shield-api",
        "version": "1.0.0"
    }


@router.get("/database")
async def database_health():
    """
    Database health check
    
    Checks the connection and performance of the database.
    """
    try:
        health_info = await DatabaseHealthChecker.check_connection()
        performance_info = await DatabaseHealthChecker.check_performance()
        
        return {
            "status": health_info["status"],
            "message": health_info["message"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "performance": performance_info
        }
        
    except Exception as e:
        return {
            "status": "unhealthy",
            "message": f"Database health check failed: {str(e)}",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


@router.get("/components")
async def component_health(current_user: Dict[str, Any] = Depends(get_current_active_user)):
    """
    Detailed component health check
    
    Returns detailed health information for all system components.
    Requires authentication.
    """
    try:
        components = {}
        
        # Core detector health
        try:
            from app.core.detector import detector
            # Test detector with a simple scan
            test_result = await detector.analyze("test prompt", None, None)
            components["threat_detector"] = {
                "status": "healthy" if test_result else "unhealthy",
                "message": "Threat detector operational",
                "last_check": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            components["threat_detector"] = {
                "status": "unhealthy",
                "message": f"Threat detector error: {str(e)}",
                "last_check": datetime.now(timezone.utc).isoformat()
            }
        
        # Red team engine health
        try:
            from app.red_team.engine import RedTeamEngine
            engine = RedTeamEngine()
            components["red_team_engine"] = {
                "status": "healthy",
                "message": "Red team engine operational",
                "last_check": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            components["red_team_engine"] = {
                "status": "unhealthy",
                "message": f"Red team engine error: {str(e)}",
                "last_check": datetime.now(timezone.utc).isoformat()
            }
        
        # Agent monitor health
        try:
            from app.agent_security.monitor import AgentSecurityMonitor
            monitor = AgentSecurityMonitor()
            components["agent_monitor"] = {
                "status": "healthy",
                "message": "Agent monitor operational",
                "last_check": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            components["agent_monitor"] = {
                "status": "unhealthy",
                "message": f"Agent monitor error: {str(e)}",
                "last_check": datetime.now(timezone.utc).isoformat()
            }
        
        # Compliance reporter health
        try:
            from app.compliance.owasp_reporter import owasp_reporter
            components["compliance_reporter"] = {
                "status": "healthy",
                "message": "Compliance reporter operational",
                "last_check": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            components["compliance_reporter"] = {
                "status": "unhealthy",
                "message": f"Compliance reporter error: {str(e)}",
                "last_check": datetime.now(timezone.utc).isoformat()
            }
        
        # Notification system health
        try:
            from app.response.notifier import alert_notifier
            stats = alert_notifier.get_notification_statistics()
            components["notification_system"] = {
                "status": "healthy",
                "message": "Notification system operational",
                "last_check": datetime.now(timezone.utc).isoformat(),
                "details": stats
            }
        except Exception as e:
            components["notification_system"] = {
                "status": "unhealthy",
                "message": f"Notification system error: {str(e)}",
                "last_check": datetime.now(timezone.utc).isoformat()
            }
        
        # Auto-remediation health
        try:
            from app.response.auto_remediate import auto_remediation
            stats = auto_remediation.get_remediation_statistics()
            components["auto_remediation"] = {
                "status": "healthy",
                "message": "Auto-remediation operational",
                "last_check": datetime.now(timezone.utc).isoformat(),
                "details": stats
            }
        except Exception as e:
            components["auto_remediation"] = {
                "status": "unhealthy",
                "message": f"Auto-remediation error: {str(e)}",
                "last_check": datetime.now(timezone.utc).isoformat()
            }
        
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": components,
            "overall_status": "healthy" if all(
                comp["status"] == "healthy" for comp in components.values()
            ) else "degraded"
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Component health check failed: {str(e)}"
        )


@router.get("/metrics")
async def system_metrics(current_user: Dict[str, Any] = Depends(get_current_active_user)):
    """
    System performance metrics
    
    Returns detailed system metrics for monitoring and alerting.
    Requires authentication.
    """
    try:
        # System metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Network metrics
        network = psutil.net_io_counters()
        
        # Process metrics
        process = psutil.Process()
        
        metrics = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "system": {
                "cpu": {
                    "percent": cpu_percent,
                    "count": psutil.cpu_count()
                },
                "memory": {
                    "total_gb": memory.total / 1024 / 1024 / 1024,
                    "available_gb": memory.available / 1024 / 1024 / 1024,
                    "used_gb": memory.used / 1024 / 1024 / 1024,
                    "percent": memory.percent
                },
                "disk": {
                    "total_gb": disk.total / 1024 / 1024 / 1024,
                    "used_gb": disk.used / 1024 / 1024 / 1024,
                    "free_gb": disk.free / 1024 / 1024 / 1024,
                    "percent": (disk.used / disk.total) * 100
                },
                "network": {
                    "bytes_sent": network.bytes_sent,
                    "bytes_recv": network.bytes_recv,
                    "packets_sent": network.packets_sent,
                    "packets_recv": network.packets_recv
                }
            },
            "process": {
                "pid": process.pid,
                "memory_mb": process.memory_info().rss / 1024 / 1024,
                "cpu_percent": process.cpu_percent(),
                "create_time": datetime.fromtimestamp(process.create_time()).isoformat(),
                "num_threads": process.num_threads()
            },
            "uptime_seconds": time.time() - startup_time
        }
        
        return metrics
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to collect system metrics: {str(e)}"
        )


@router.get("/version")
async def version_info():
    """
    Version information
    
    Returns version and build information for the SentinelShield platform.
    """
    return {
        "version": "1.0.0",
        "build": "production",
        "build_date": "2026-02-17",
        "git_commit": "abc123def456",
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "platform": platform_info.platform(),
        "architecture": platform_info.architecture()[0],
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
