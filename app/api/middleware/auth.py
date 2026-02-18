"""
Authentication and authorization middleware for SentinelShield API
JWT and API key authentication with role-based access control
"""

import time
import uuid
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException, Security, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
import logging
import hashlib
import secrets

from app.config import settings

logger = logging.getLogger(__name__)


class UserRole(str):
    """User roles for authorization"""
    ADMIN = "admin"
    ANALYST = "analyst"
    OPERATOR = "operator"
    VIEWER = "viewer"
    API_USER = "api_user"


class Permission(str):
    """Permission types"""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"
    SCAN = "scan"
    RED_TEAM = "red_team"
    AGENT_MANAGE = "agent_manage"
    COMPLIANCE_READ = "compliance_read"
    COMPLIANCE_WRITE = "compliance_write"


# Role-based access control matrix
ROLE_PERMISSIONS = {
    UserRole.ADMIN: [
        Permission.READ, Permission.WRITE, Permission.DELETE, Permission.ADMIN,
        Permission.SCAN, Permission.RED_TEAM, Permission.AGENT_MANAGE,
        Permission.COMPLIANCE_READ, Permission.COMPLIANCE_WRITE
    ],
    UserRole.ANALYST: [
        Permission.READ, Permission.SCAN, Permission.RED_TEAM,
        Permission.AGENT_MANAGE, Permission.COMPLIANCE_READ, Permission.COMPLIANCE_WRITE
    ],
    UserRole.OPERATOR: [
        Permission.READ, Permission.SCAN, Permission.AGENT_MANAGE,
        Permission.COMPLIANCE_READ
    ],
    UserRole.VIEWER: [
        Permission.READ, Permission.COMPLIANCE_READ
    ],
    UserRole.API_USER: [
        Permission.SCAN
    ]
}


class JWTAuthenticator:
    """JWT authentication handler"""
    
    def __init__(self):
        self.secret_key = settings.jwt_secret_key
        self.algorithm = "HS256"
        self.access_token_expire_minutes = settings.jwt_expire_minutes
        
        # In-memory user store (in production, use database)
        self.users = {
            "admin": {
                "user_id": "admin",
                "username": "admin",
                "role": UserRole.ADMIN,
                "hashed_password": self._hash_password("admin123"),  # Change in production
                "active": True,
                "created_at": datetime.now(timezone.utc)
            },
            "analyst": {
                "user_id": "analyst",
                "username": "analyst",
                "role": UserRole.ANALYST,
                "hashed_password": self._hash_password("analyst123"),
                "active": True,
                "created_at": datetime.now(timezone.utc)
            },
            "operator": {
                "user_id": "operator",
                "username": "operator",
                "role": UserRole.OPERATOR,
                "hashed_password": self._hash_password("operator123"),
                "active": True,
                "created_at": datetime.now(timezone.utc)
            }
        }
        
        # API keys store
        self.api_keys = {}
        
        logger.info("JWT authenticator initialized")
    
    def _hash_password(self, password: str) -> str:
        """Hash password with salt"""
        salt = secrets.token_hex(16)
        pwdhash = hashlib.pbkdf2_hmac('sha256', 
                                      password.encode('utf-8'), 
                                      salt.encode('utf-8'), 
                                      100000)
        return salt + pwdhash.hex()
    
    def _verify_password(self, stored_password: str, provided_password: str) -> bool:
        """Verify password against hash"""
        salt = stored_password[:32]
        stored_hash = stored_password[32:]
        pwdhash = hashlib.pbkdf2_hmac('sha256',
                                      provided_password.encode('utf-8'),
                                      salt.encode('utf-8'),
                                      100000)
        return pwdhash.hex() == stored_hash
    
    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except JWTError as e:
            logger.warning(f"JWT verification failed: {e}")
            return None
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user with username and password"""
        user = self.users.get(username)
        if not user:
            return None
        
        if not user.get("active", False):
            return None
        
        if not self._verify_password(user["hashed_password"], password):
            return None
        
        return {
            "user_id": user["user_id"],
            "username": user["username"],
            "role": user["role"],
            "auth_method": "jwt"
        }
    
    def generate_api_key(self, user_id: str, name: str, permissions: List[str] = None) -> str:
        """Generate API key for user"""
        api_key = f"sentinel_{secrets.token_urlsafe(32)}"
        
        # Store API key
        self.api_keys[api_key] = {
            "api_key": api_key,
            "user_id": user_id,
            "name": name,
            "permissions": permissions or [Permission.SCAN],
            "created_at": datetime.now(timezone.utc),
            "last_used": None,
            "active": True
        }
        
        logger.info(f"Generated API key for user {user_id}: {name}")
        return api_key
    
    def verify_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Verify API key"""
        key_data = self.api_keys.get(api_key)
        if not key_data:
            return None
        
        if not key_data.get("active", False):
            return None
        
        # Update last used
        key_data["last_used"] = datetime.now(timezone.utc)
        
        # Get user info
        user = self.users.get(key_data["user_id"])
        if not user or not user.get("active", False):
            return None
        
        return {
            "user_id": user["user_id"],
            "username": user["username"],
            "role": user["role"],
            "permissions": key_data["permissions"],
            "auth_method": "api_key",
            "api_key_name": key_data["name"]
        }
    
    def has_permission(self, user_role: str, required_permission: str) -> bool:
        """Check if user role has required permission"""
        user_permissions = ROLE_PERMISSIONS.get(user_role, [])
        return required_permission in user_permissions


# Initialize authenticator
authenticator = JWTAuthenticator()

# Security schemes
bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = None,
                         api_key: Optional[str] = None) -> Dict[str, Any]:
    """Get current authenticated user"""
    # Try JWT authentication first
    if credentials:
        payload = authenticator.verify_token(credentials.credentials)
        if payload:
            user_id = payload.get("sub")
            if user_id:
                user = authenticator.users.get(user_id)
                if user and user.get("active", False):
                    return {
                        "user_id": user["user_id"],
                        "username": user["username"],
                        "role": user["role"],
                        "auth_method": "jwt"
                    }
    
    # Try API key authentication
    if api_key:
        user_data = authenticator.verify_api_key(api_key)
        if user_data:
            return user_data
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_active_user(current_user: Dict[str, Any] = Security(get_current_user)) -> Dict[str, Any]:
    """Get current active user"""
    return current_user


def require_permission(permission: str):
    """Decorator to require specific permission"""
    def permission_dependency(current_user: Dict[str, Any] = Security(get_current_active_user)):
        user_role = current_user.get("role")
        
        # For API key authentication, check explicit permissions
        if current_user.get("auth_method") == "api_key":
            user_permissions = current_user.get("permissions", [])
            if permission not in user_permissions:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required: {permission}"
                )
        else:
            # For JWT authentication, check role-based permissions
            if not authenticator.has_permission(user_role, permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions for role {user_role}. Required: {permission}"
                )
        
        return current_user
    
    return permission_dependency


def require_role(role: str):
    """Decorator to require specific role"""
    def role_dependency(current_user: Dict[str, Any] = Security(get_current_active_user)):
        user_role = current_user.get("role")
        if user_role != role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role: {role}"
            )
        return current_user
    
    return role_dependency


def require_admin():
    """Decorator to require admin role"""
    return require_role(UserRole.ADMIN)


# Authentication dependency for different auth methods
async def authenticate_request(request: Request) -> Dict[str, Any]:
    """Authenticate request using multiple methods"""
    # Try Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:]
        payload = authenticator.verify_token(token)
        if payload:
            user_id = payload.get("sub")
            user = authenticator.users.get(user_id)
            if user and user.get("active", False):
                return {
                    "user_id": user["user_id"],
                    "username": user["username"],
                    "role": user["role"],
                    "auth_method": "jwt"
                }
    
    # Try API key in header
    api_key = request.headers.get("X-API-Key")
    if api_key:
        user_data = authenticator.verify_api_key(api_key)
        if user_data:
            return user_data
    
    # Try API key in query parameter (for webhooks)
    query_api_key = request.query_params.get("api_key")
    if query_api_key:
        user_data = authenticator.verify_api_key(query_api_key)
        if user_data:
            return user_data
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


class AuthMiddleware:
    """Authentication middleware for FastAPI"""
    
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            # Add auth info to scope
            request = Request(scope, receive)
            
            try:
                user_data = await authenticate_request(request)
                scope["user"] = user_data
            except HTTPException:
                # Let the endpoint handle authentication
                pass
        
        await self.app(scope, receive, send)


# Utility functions
def create_user_token(username: str, password: str) -> Optional[str]:
    """Create JWT token for user"""
    user_data = authenticator.authenticate_user(username, password)
    if user_data:
        access_token = authenticator.create_access_token(
            data={"sub": user_data["user_id"], "role": user_data["role"]}
        )
        return access_token
    return None


def setup_default_users():
    """Setup default users for development"""
    if settings.is_development:
        # Generate API keys for testing
        test_api_key = authenticator.generate_api_key(
            "api_user", 
            "test_key", 
            [Permission.SCAN]
        )
        logger.info(f"Development API key generated: {test_api_key}")
        
        # Create admin token
        admin_token = create_user_token("admin", "admin123")
        if admin_token:
            logger.info("Development admin token created")


# Initialize default users
setup_default_users()
