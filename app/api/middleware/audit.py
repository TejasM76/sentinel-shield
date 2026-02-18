"""
Audit logging middleware for SentinelShield API
Comprehensive request/response logging for security and compliance
"""

import time
import uuid
import json
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from fastapi import Request, Response
import logging
import hashlib

from app.compliance.audit_trail import audit_trail, EventType, ComplianceTag
from app.api.middleware.auth import get_current_user

logger = logging.getLogger(__name__)


class AuditMiddleware:
    """Audit logging middleware for API requests"""
    
    def __init__(self, app):
        self.app = app
        self.sensitive_fields = {
            'password', 'token', 'api_key', 'secret', 'key', 'authorization',
            'cookie', 'session', 'csrf', 'ssn', 'credit_card', 'bank_account'
        }
        
        # Paths that require special handling
        self.sensitive_paths = {
            '/api/v1/auth/login',
            '/api/v1/auth/refresh',
            '/api/v1/scan',  # May contain sensitive prompts
        }
        
        logger.info("Audit middleware initialized")
    
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            # Generate request ID
            request_id = str(uuid.uuid4())
            
            # Create request and response objects
            request = Request(scope, receive)
            
            # Start timing
            start_time = time.time()
            
            # Get request details
            request_details = await self._capture_request(request, request_id)
            
            # Create custom send function to capture response
            response_details = {}
            
            async def audit_send(message):
                if message["type"] == "http.response.start":
                    # Capture response status and headers
                    response_details["status_code"] = message.get("status", 200)
                    response_details["headers"] = dict(message.get("headers", []))
                
                await send(message)
            
            # Process the request
            try:
                await self.app(scope, receive, audit_send)
                
                # Calculate processing time
                processing_time = (time.time() - start_time) * 1000
                
                # Log successful request
                await self._log_request(
                    request_details=request_details,
                    response_details=response_details,
                    processing_time_ms=processing_time,
                    success=True,
                    request_id=request_id
                )
                
            except Exception as e:
                # Calculate processing time
                processing_time = (time.time() - start_time) * 1000
                
                # Log failed request
                await self._log_request(
                    request_details=request_details,
                    response_details=response_details,
                    processing_time_ms=processing_time,
                    success=False,
                    error_message=str(e),
                    request_id=request_id
                )
                
                # Re-raise the exception
                raise
        else:
            await self.app(scope, receive, send)
    
    async def _capture_request(self, request: Request, request_id: str) -> Dict[str, Any]:
        """Capture request details for auditing"""
        # Basic request info
        details = {
            "request_id": request_id,
            "method": request.method,
            "url": str(request.url),
            "path": request.url.path,
            "query_params": dict(request.query_params),
            "client_ip": self._get_client_ip(request),
            "user_agent": request.headers.get("user-agent"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        
        # Get user info if available
        try:
            # Try to get current user (may fail if no auth)
            user_info = await get_current_user(
                request.headers.get("Authorization"),
                request.headers.get("X-API-Key")
            )
            details["user_id"] = user_info.get("user_id")
            details["user_role"] = user_info.get("role")
            details["auth_method"] = user_info.get("auth_method")
        except:
            # No authentication or invalid
            pass
        
        # Capture headers (excluding sensitive ones)
        headers = {}
        for key, value in request.headers.items():
            if not self._is_sensitive_field(key.lower()):
                headers[key] = value
        details["headers"] = headers
        
        # Capture body for relevant methods
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                # Get body
                body = await request.body()
                
                # Parse and sanitize body
                if body:
                    content_type = request.headers.get("content-type", "")
                    
                    if "application/json" in content_type:
                        try:
                            json_body = json.loads(body.decode())
                            sanitized_body = self._sanitize_data(json_body)
                            details["body"] = sanitized_body
                        except json.JSONDecodeError:
                            # Not JSON, log as raw but truncated
                            details["body"] = body[:1000].decode(errors='ignore')
                    else:
                        # Non-JSON body, log truncated
                        details["body"] = body[:1000].decode(errors='ignore')
                
            except Exception as e:
                logger.warning(f"Failed to capture request body: {e}")
                details["body"] = "<capture_failed>"
        
        return details
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address"""
        # Check for forwarded headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    def _is_sensitive_field(self, field_name: str) -> bool:
        """Check if field contains sensitive information"""
        return any(sensitive in field_name.lower() for sensitive in self.sensitive_fields)
    
    def _sanitize_data(self, data: Any, max_depth: int = 5) -> Any:
        """Sanitize data by removing sensitive fields"""
        if max_depth <= 0:
            return "<max_depth_reached>"
        
        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                if self._is_sensitive_field(key):
                    sanitized[key] = "<redacted>"
                elif isinstance(value, (dict, list)):
                    sanitized[key] = self._sanitize_data(value, max_depth - 1)
                elif isinstance(value, str) and len(value) > 1000:
                    sanitized[key] = value[:1000] + "...<truncated>"
                else:
                    sanitized[key] = value
            return sanitized
        
        elif isinstance(data, list):
            sanitized = []
            for item in data:
                if isinstance(item, (dict, list)):
                    sanitized.append(self._sanitize_data(item, max_depth - 1))
                elif isinstance(item, str) and len(item) > 1000:
                    sanitized.append(item[:1000] + "...<truncated>")
                else:
                    sanitized.append(item)
            return sanitized
        
        else:
            return data
    
    async def _log_request(self, request_details: Dict[str, Any],
                         response_details: Dict[str, Any],
                         processing_time_ms: float,
                         success: bool,
                         error_message: str = None,
                         request_id: str = None):
        """Log request to audit trail"""
        try:
            # Determine event type based on request
            event_type = self._determine_event_type(request_details, response_details, success)
            
            # Create audit event
            audit_event = {
                "event_id": f"api_{request_id}",
                "timestamp": datetime.now(timezone.utc),
                "event_type": event_type,
                "actor": request_details.get("user_id", "anonymous"),
                "action": f"{request_details['method']} {request_details['path']}",
                "resource": request_details["url"],
                "details": {
                    "request_id": request_id,
                    "method": request_details["method"],
                    "path": request_details["path"],
                    "query_params": request_details.get("query_params", {}),
                    "client_ip": request_details.get("client_ip"),
                    "user_agent": request_details.get("user_agent"),
                    "user_role": request_details.get("user_role"),
                    "auth_method": request_details.get("auth_method"),
                    "processing_time_ms": processing_time_ms,
                    "request_body": request_details.get("body"),
                    "response_status": response_details.get("status_code"),
                    "success": success
                },
                "ip_address": request_details.get("client_ip"),
                "user_agent": request_details.get("user_agent"),
                "session_id": request_details.get("session_id"),
                "request_id": request_id,
                "success": success,
                "error_message": error_message,
                "compliance_tags": self._get_compliance_tags(request_details, response_details)
            }
            
            # Log to audit trail
            from app.compliance.audit_trail import AuditEvent, EventType
            
            audit_event_obj = AuditEvent(
                event_id=audit_event["event_id"],
                timestamp=audit_event["timestamp"],
                event_type=EventType(event_type),
                actor=audit_event["actor"],
                action=audit_event["action"],
                resource=audit_event["resource"],
                details=audit_event["details"],
                ip_address=audit_event["ip_address"],
                user_agent=audit_event["user_agent"],
                session_id=audit_event.get("session_id"),
                request_id=audit_event.get("request_id"),
                success=audit_event["success"],
                error_message=audit_event.get("error_message"),
                compliance_tags=audit_event["compliance_tags"]
            )
            
            await audit_trail.log_event(audit_event_obj)
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
    
    def _determine_event_type(self, request_details: Dict[str, Any],
                            response_details: Dict[str, Any],
                            success: bool) -> str:
        """Determine audit event type"""
        path = request_details.get("path", "")
        method = request_details.get("method", "")
        status_code = response_details.get("status_code", 200)
        
        # Security-related events
        if path.startswith("/api/v1/auth"):
            if "login" in path:
                return EventType.LOGIN_ATTEMPT
            elif success:
                return EventType.CONFIGURATION_CHANGE
        elif path.startswith("/api/v1/scan"):
            return EventType.THREAT_DETECTED
        elif path.startswith("/api/v1/redteam"):
            return EventType.THREAT_DETECTED
        elif path.startswith("/api/v1/agent"):
            if "register" in path:
                return EventType.AGENT_REGISTERED
            elif "terminate" in path:
                return EventType.AGENT_TERMINATED
        elif path.startswith("/api/v1/compliance"):
            return EventType.DATA_EXPORT
        
        # Error events
        if not success or status_code >= 400:
            if status_code == 401:
                return EventType.LOGIN_ATTEMPT
            elif status_code == 403:
                return EventType.PRIVILEGE_ESCALATION
            else:
                return EventType.SYSTEM_STARTUP  # Generic error
        
        # Configuration changes
        if method in ["POST", "PUT", "DELETE", "PATCH"]:
            return EventType.CONFIGURATION_CHANGE
        
        # Default
        return EventType.SYSTEM_STARTUP
    
    def _get_compliance_tags(self, request_details: Dict[str, Any],
                           response_details: Dict[str, Any]) -> list:
        """Get compliance tags for the request"""
        tags = []
        
        path = request_details.get("path", "")
        
        # GDPR tags for data access
        if "/scan" in path or "/compliance" in path:
            tags.append(ComplianceTag.GDPR)
        
        # SOX tags for financial data
        if any(keyword in path.lower() for keyword in ["financial", "payment", "transaction"]):
            tags.append(ComplianceTag.SOX)
        
        # HIPAA tags for healthcare data
        if any(keyword in path.lower() for keyword in ["health", "medical", "patient"]):
            tags.append(ComplianceTag.HIPAA)
        
        # PCI DSS for payment data
        if any(keyword in path.lower() for keyword in ["payment", "card", "pci"]):
            tags.append(ComplianceTag.PCI_DSS)
        
        # SOC2 for general security
        tags.append(ComplianceTag.SOC2)
        
        # ISO27001 for system security
        if any(keyword in path.lower() for keyword in ["admin", "config", "system"]):
            tags.append(ComplianceTag.ISO27001)
        
        return tags


class SecurityAuditLogger:
    """Enhanced security audit logger"""
    
    def __init__(self):
        self.suspicious_patterns = {
            "sql_injection": r"(?i)(union|select|insert|update|delete|drop|exec|script)",
            "xss": r"(?i)(<script|javascript:|onload|onclick)",
            "path_traversal": r"(?i)(\.\./|\.\.\\|%2e%2e%2f)",
            "command_injection": r"(?i)(;|\||&|`|\$\(|\${)",
        }
        
        logger.info("Security audit logger initialized")
    
    async def log_security_event(self, request: Request, event_type: str, 
                              details: Dict[str, Any], severity: str = "MEDIUM"):
        """Log security-specific event"""
        try:
            # Check for suspicious patterns
            suspicious_indicators = await self._check_suspicious_patterns(request)
            
            # Create security event
            security_event = {
                "event_type": event_type,
                "severity": severity,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request": {
                    "method": request.method,
                    "url": str(request.url),
                    "path": request.url.path,
                    "query_params": dict(request.query_params),
                    "client_ip": self._get_client_ip(request),
                    "user_agent": request.headers.get("user-agent"),
                },
                "details": details,
                "suspicious_indicators": suspicious_indicators,
                "compliance_tags": [ComplianceTag.GDPR, ComplianceTag.SOC2]
            }
            
            # Log to security log
            logger.warning(f"Security Event: {json.dumps(security_event, indent=2)}")
            
            # Also log to audit trail
            from app.compliance.audit_trail import AuditEvent, EventType
            
            audit_event = AuditEvent(
                event_id=f"sec_{uuid.uuid4()}",
                timestamp=datetime.now(timezone.utc),
                event_type=EventType.PRIVILEGE_ESCALATION,
                actor=details.get("user_id", "anonymous"),
                action=f"security_{event_type}",
                resource=str(request.url),
                details=security_event,
                ip_address=self._get_client_ip(request),
                user_agent=request.headers.get("user-agent"),
                compliance_tags=[ComplianceTag.GDPR, ComplianceTag.SOC2]
            )
            
            await audit_trail.log_event(audit_event)
            
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")
    
    async def _check_suspicious_patterns(self, request: Request) -> Dict[str, Any]:
        """Check request for suspicious patterns"""
        indicators = {}
        
        # Check URL and query parameters
        url_string = str(request.url) + str(request.query_params)
        
        for pattern_name, pattern in self.suspicious_patterns.items():
            import re
            if re.search(pattern, url_string):
                indicators[pattern_name] = True
        
        # Check headers
        for header_name, header_value in request.headers.items():
            for pattern_name, pattern in self.suspicious_patterns.items():
                import re
                if re.search(pattern, header_value):
                    indicators[f"{pattern_name}_header"] = True
        
        return indicators
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address"""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"


# Global security logger instance
security_logger = SecurityAuditLogger()
