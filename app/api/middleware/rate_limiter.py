"""
Rate limiting middleware for SentinelShield API
Configurable rate limiting with different strategies and storage backends
"""

import time
import asyncio
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException, Request, status
from collections import defaultdict, deque
import logging
import hashlib

from app.config import settings

logger = logging.getLogger(__name__)


class RateLimitStrategy:
    """Base class for rate limiting strategies"""
    
    def is_allowed(self, key: str, limit: int, window: int) -> Tuple[bool, Dict[str, Any]]:
        """Check if request is allowed"""
        raise NotImplementedError


class SlidingWindowCounter(RateLimitStrategy):
    """Sliding window rate limiter using deque"""
    
    def __init__(self):
        self.windows: Dict[str, deque] = defaultdict(lambda: deque())
        self.lock = asyncio.Lock()
    
    async def is_allowed(self, key: str, limit: int, window: int) -> Tuple[bool, Dict[str, Any]]:
        """Check sliding window rate limit"""
        async with self.lock:
            now = time.time()
            window_start = now - window
            
            # Get or create window for this key
            timestamps = self.windows[key]
            
            # Remove old timestamps outside the window
            while timestamps and timestamps[0] <= window_start:
                timestamps.popleft()
            
            # Check if limit exceeded
            if len(timestamps) >= limit:
                # Calculate reset time
                oldest_timestamp = timestamps[0]
                reset_time = oldest_timestamp + window
                
                return False, {
                    "limit": limit,
                    "remaining": 0,
                    "reset_time": reset_time,
                    "retry_after": int(reset_time - now)
                }
            
            # Add current timestamp
            timestamps.append(now)
            
            return True, {
                "limit": limit,
                "remaining": limit - len(timestamps),
                "reset_time": now + window,
                "retry_after": 0
            }


class TokenBucket(RateLimitStrategy):
    """Token bucket rate limiter"""
    
    def __init__(self):
        self.buckets: Dict[str, Dict[str, Any]] = {}
        self.lock = asyncio.Lock()
    
    async def is_allowed(self, key: str, limit: int, window: int) -> Tuple[bool, Dict[str, Any]]:
        """Check token bucket rate limit"""
        async with self.lock:
            now = time.time()
            
            # Get or create bucket
            if key not in self.buckets:
                self.buckets[key] = {
                    "tokens": limit,
                    "last_refill": now,
                    "limit": limit,
                    "refill_rate": limit / window  # tokens per second
                }
            
            bucket = self.buckets[key]
            
            # Refill tokens based on time elapsed
            time_elapsed = now - bucket["last_refill"]
            tokens_to_add = time_elapsed * bucket["refill_rate"]
            bucket["tokens"] = min(bucket["limit"], bucket["tokens"] + tokens_to_add)
            bucket["last_refill"] = now
            
            # Check if token available
            if bucket["tokens"] >= 1:
                bucket["tokens"] -= 1
                
                return True, {
                    "limit": limit,
                    "remaining": int(bucket["tokens"]),
                    "reset_time": now + (bucket["limit"] - bucket["tokens"]) / bucket["refill_rate"],
                    "retry_after": 0
                }
            else:
                # Calculate time until next token
                time_to_token = (1 - bucket["tokens"]) / bucket["refill_rate"]
                
                return False, {
                    "limit": limit,
                    "remaining": 0,
                    "reset_time": now + time_to_token,
                    "retry_after": int(time_to_token)
                }


class FixedWindowCounter(RateLimitStrategy):
    """Fixed window rate limiter"""
    
    def __init__(self):
        self.counters: Dict[str, Dict[str, Any]] = {}
        self.lock = asyncio.Lock()
    
    async def is_allowed(self, key: str, limit: int, window: int) -> Tuple[bool, Dict[str, Any]]:
        """Check fixed window rate limit"""
        async with self.lock:
            now = time.time()
            current_window = int(now // window) * window
            
            # Get or create counter
            if key not in self.counters:
                self.counters[key] = {
                    "count": 0,
                    "window_start": current_window,
                    "limit": limit
                }
            
            counter = self.counters[key]
            
            # Reset if we're in a new window
            if current_window != counter["window_start"]:
                counter["count"] = 0
                counter["window_start"] = current_window
            
            # Check limit
            if counter["count"] >= limit:
                reset_time = counter["window_start"] + window
                
                return False, {
                    "limit": limit,
                    "remaining": 0,
                    "reset_time": reset_time,
                    "retry_after": int(reset_time - now)
                }
            
            counter["count"] += 1
            
            return True, {
                "limit": limit,
                "remaining": limit - counter["count"],
                "reset_time": counter["window_start"] + window,
                "retry_after": 0
            }


class RateLimiter:
    """Main rate limiter with multiple strategies"""
    
    def __init__(self):
        # Choose strategy based on configuration
        strategy_name = getattr(settings, 'rate_limit_strategy', 'sliding_window')
        
        if strategy_name == 'token_bucket':
            self.strategy = TokenBucket()
        elif strategy_name == 'fixed_window':
            self.strategy = FixedWindowCounter()
        else:
            self.strategy = SlidingWindowCounter()
        
        # Rate limit rules
        self.rules = {
            # Default limits
            'default': {
                'requests_per_minute': settings.max_requests_per_minute,
                'requests_per_hour': 1000,
                'requests_per_day': 10000
            },
            
            # API endpoints with specific limits
            '/api/v1/scan': {
                'requests_per_minute': 100,
                'requests_per_hour': 2000,
                'requests_per_day': 20000
            },
            '/api/v1/redteam': {
                'requests_per_minute': 10,
                'requests_per_hour': 50,
                'requests_per_day': 200
            },
            '/api/v1/agent': {
                'requests_per_minute': 200,
                'requests_per_hour': 5000,
                'requests_per_day': 50000
            },
            '/api/v1/compliance': {
                'requests_per_minute': 20,
                'requests_per_hour': 200,
                'requests_per_day': 1000
            }
        }
        
        logger.info(f"Rate limiter initialized with strategy: {strategy_name}")
    
    def get_client_key(self, request: Request, user_info: Dict[str, Any] = None) -> str:
        """Generate client key for rate limiting"""
        # Priority: user_id > api_key > IP address
        
        if user_info:
            user_id = user_info.get("user_id")
            if user_id:
                return f"user:{user_id}"
            
            # For API key authentication
            if user_info.get("auth_method") == "api_key":
                api_key_name = user_info.get("api_key_name", "unknown")
                return f"api_key:{api_key_name}"
        
        # Fallback to IP address
        client_ip = self._get_client_ip(request)
        return f"ip:{client_ip}"
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request"""
        # Check for forwarded headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fallback to client host
        return request.client.host if request.client else "unknown"
    
    def get_rate_limits(self, path: str) -> Dict[str, int]:
        """Get rate limits for a specific path"""
        # Find matching rule
        for pattern, limits in self.rules.items():
            if pattern != 'default' and path.startswith(pattern):
                return limits
        
        return self.rules['default']
    
    async def check_rate_limit(self, request: Request, user_info: Dict[str, Any] = None) -> Tuple[bool, Dict[str, Any]]:
        """Check if request is within rate limits"""
        client_key = self.get_client_key(request, user_info)
        path = request.url.path
        limits = self.get_rate_limits(path)
        
        # Check each time window
        for window_name, limit in limits.items():
            if window_name == 'requests_per_minute':
                window_seconds = 60
            elif window_name == 'requests_per_hour':
                window_seconds = 3600
            elif window_name == 'requests_per_day':
                window_seconds = 86400
            else:
                continue
            
            key = f"{client_key}:{window_name}"
            allowed, info = await self.strategy.is_allowed(key, limit, window_seconds)
            
            if not allowed:
                logger.warning(f"Rate limit exceeded for {client_key} on {path}: {window_name}={limit}")
                return False, {
                    "error": "Rate limit exceeded",
                    "limit_type": window_name,
                    "limit": limit,
                    "window_seconds": window_seconds,
                    **info
                }
        
        return True, {}
    
    async def get_rate_limit_status(self, request: Request, user_info: Dict[str, Any] = None) -> Dict[str, Any]:
        """Get current rate limit status"""
        client_key = self.get_client_key(request, user_info)
        path = request.url.path
        limits = self.get_rate_limits(path)
        
        status = {}
        
        for window_name, limit in limits.items():
            if window_name == 'requests_per_minute':
                window_seconds = 60
            elif window_name == 'requests_per_hour':
                window_seconds = 3600
            elif window_name == 'requests_per_day':
                window_seconds = 86400
            else:
                continue
            
            key = f"{client_key}:{window_name}"
            _, info = await self.strategy.is_allowed(key, limit, window_seconds)
            
            status[window_name] = info
        
        return status


class RateLimitMiddleware:
    """Rate limiting middleware for FastAPI"""
    
    def __init__(self, app, rate_limiter: RateLimiter = None):
        self.app = app
        self.rate_limiter = rate_limiter or RateLimiter()
    
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            # Create request object
            request = Request(scope, receive)
            
            # Get user info from scope if available
            user_info = scope.get("user")
            
            # Check rate limit
            allowed, limit_info = await self.rate_limiter.check_rate_limit(request, user_info)
            
            if not allowed:
                # Create HTTP response for rate limit exceeded
                response = {
                    "error": "Rate limit exceeded",
                    "message": limit_info.get("error", "Too many requests"),
                    "details": {
                        "limit": limit_info.get("limit"),
                        "limit_type": limit_info.get("limit_type"),
                        "retry_after": limit_info.get("retry_after", 60),
                        "reset_time": limit_info.get("reset_time")
                    }
                }
                
                # Send 429 response
                from fastapi.responses import JSONResponse
                json_response = JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content=response,
                    headers={"Retry-After": str(limit_info.get("retry_after", 60))}
                )
                
                await json_response(scope, receive, send)
                return
            
            # Add rate limit headers to response
            async def send_with_headers(message):
                if message["type"] == "http.response.start":
                    # Get rate limit status
                    rate_status = await self.rate_limiter.get_rate_limit_status(request, user_info)
                    
                    # Add rate limit headers
                    headers = dict(message.get("headers", []))
                    
                    # Add headers for each window
                    for window_name, info in rate_status.items():
                        if window_name == "requests_per_minute":
                            headers.append((b"x-ratelimit-limit-minute", str(info["limit"]).encode()))
                            headers.append((b"x-ratelimit-remaining-minute", str(info["remaining"]).encode()))
                            if info.get("reset_time"):
                                headers.append((b"x-ratelimit-reset-minute", str(int(info["reset_time"])).encode()))
                        elif window_name == "requests_per_hour":
                            headers.append((b"x-ratelimit-limit-hour", str(info["limit"]).encode()))
                            headers.append((b"x-ratelimit-remaining-hour", str(info["remaining"]).encode()))
                            if info.get("reset_time"):
                                headers.append((b"x-ratelimit-reset-hour", str(int(info["reset_time"])).encode()))
                    
                    message["headers"] = list(headers.items())
                
                await send(message)
            
            await self.app(scope, receive, send_with_headers)
        else:
            await self.app(scope, receive, send)


# Global rate limiter instance
rate_limiter = RateLimiter()


# Utility functions
async def check_rate_limit(request: Request, user_info: Dict[str, Any] = None) -> Tuple[bool, Dict[str, Any]]:
    """Check rate limit for a request"""
    return await rate_limiter.check_rate_limit(request, user_info)


async def get_rate_limit_headers(request: Request, user_info: Dict[str, Any] = None) -> Dict[str, str]:
    """Get rate limit headers for response"""
    status = await rate_limiter.get_rate_limit_status(request, user_info)
    headers = {}
    
    for window_name, info in status.items():
        if window_name == "requests_per_minute":
            headers["x-ratelimit-limit-minute"] = str(info["limit"])
            headers["x-ratelimit-remaining-minute"] = str(info["remaining"])
            if info.get("reset_time"):
                headers["x-ratelimit-reset-minute"] = str(int(info["reset_time"]))
        elif window_name == "requests_per_hour":
            headers["x-ratelimit-limit-hour"] = str(info["limit"])
            headers["x-ratelimit-remaining-hour"] = str(info["remaining"])
            if info.get("reset_time"):
                headers["x-ratelimit-reset-hour"] = str(int(info["reset_time"]))
    
    return headers
