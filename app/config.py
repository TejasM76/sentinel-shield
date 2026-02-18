"""
Configuration management for SentinelShield AI Security Platform
Handles environment variables, settings, and application configuration
"""

import os
from typing import Optional, List
from pydantic_settings import BaseSettings
from pydantic import Field
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings with environment variable support"""
    
    # LLM Provider Configuration
    groq_api_key: str = Field(default="", env="GROQ_API_KEY")
    groq_model: str = Field(default="llama-3.1-70b-versatile", env="GROQ_MODEL")
    groq_fallback_model: str = Field(default="llama-3.1-8b-instant", env="GROQ_FALLBACK_MODEL")
    
    # Database Configuration
    database_url: str = Field(
        default="sqlite+aiosqlite:///./sentinel_shield.db",
        env="DATABASE_URL"
    )
    
    # Redis Configuration
    redis_url: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    redis_enabled: bool = Field(default=False, env="REDIS_ENABLED")
    
    # Security Configuration
    jwt_secret_key: str = Field(
        default="change-this-in-production-sentinel-shield-secret-key-256",
        env="JWT_SECRET_KEY"
    )
    jwt_expire_minutes: int = Field(default=60, env="JWT_EXPIRE_MINUTES")
    api_key_salt: str = Field(default="sentinel_shield_salt", env="API_KEY_SALT")
    
    # Application Settings
    app_env: str = Field(default="development", env="APP_ENV")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    api_host: str = Field(default="0.0.0.0", env="API_HOST")
    api_port: int = Field(default=8001, env="API_PORT")
    
    # ML Model Settings
    embedding_model: str = Field(default="all-MiniLM-L6-v2", env="EMBEDDING_MODEL")
    semantic_threshold: float = Field(default=0.75, env="SEMANTIC_THRESHOLD")
    llm_temperature: float = Field(default=0.1, env="LLM_TEMPERATURE")
    llm_max_tokens: int = Field(default=1000, env="LLM_MAX_TOKENS")
    
    # Rate Limiting
    max_requests_per_minute: int = Field(default=60, env="MAX_REQUESTS_PER_MINUTE")
    rate_limit_strategy: str = Field(default="sliding_window", env="RATE_LIMIT_STRATEGY")
    
    # Risk Scoring Weights
    pattern_weight: float = Field(default=0.3, env="PATTERN_WEIGHT")
    semantic_weight: float = Field(default=0.3, env="SEMANTIC_WEIGHT")
    llm_weight: float = Field(default=0.4, env="LLM_WEIGHT")
    
    # Thresholds
    critical_threshold: float = Field(default=0.85, env="CRITICAL_THRESHOLD")
    high_threshold: float = Field(default=0.70, env="HIGH_THRESHOLD")
    medium_threshold: float = Field(default=0.50, env="MEDIUM_THRESHOLD")
    
    # Notification Settings
    slack_webhook_url: Optional[str] = Field(default=None, env="SLACK_WEBHOOK_URL")
    alert_email: Optional[str] = Field(default=None, env="ALERT_EMAIL")
    email_smtp_host: Optional[str] = Field(default=None, env="EMAIL_SMTP_HOST")
    email_smtp_port: int = Field(default=587, env="EMAIL_SMTP_PORT")
    email_from: Optional[str] = Field(default=None, env="EMAIL_FROM")
    
    # Concurrency Settings
    max_concurrent_scans: int = Field(default=10, env="MAX_CONCURRENT_SCANS")
    
    # Dashboard Settings
    dashboard_port: int = Field(default=8501, env="DASHBOARD_PORT")
    
    @property
    def is_development(self) -> bool:
        return self.app_env in ("development", "testing", "dev")
    
    @property
    def is_production(self) -> bool:
        return self.app_env == "production"
    
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore",
    }


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()


# Global settings instance
settings = get_settings()
