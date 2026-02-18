"""
Database connection and session management for SentinelShield AI Security Platform
Async SQLAlchemy setup with connection pooling and performance optimization
"""

import asyncio
import time
from typing import AsyncGenerator
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import event, text
from sqlalchemy.pool import StaticPool
import logging

from app.config import settings
from app.db.models import Base


logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages database connections and sessions"""
    
    def __init__(self):
        self.engine = None
        self.async_session_factory = None
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize database engine and session factory"""
        if self._initialized:
            return
        
        try:
            # Create async engine with optimized settings
            if settings.database_url.startswith("sqlite"):
                # SQLite configuration
                self.engine = create_async_engine(
                    settings.database_url,
                    echo=settings.is_development,
                    poolclass=StaticPool,
                    connect_args={
                        "check_same_thread": False,
                        "timeout": 20,
                    },
                    pool_pre_ping=True,
                )
            else:
                # PostgreSQL configuration
                self.engine = create_async_engine(
                    settings.database_url,
                    echo=settings.is_development,
                    pool_size=20,
                    max_overflow=30,
                    pool_pre_ping=True,
                    pool_recycle=3600,
                    connect_args={
                        "command_timeout": 60,
                        "server_settings": {
                            "application_name": "sentinel_shield",
                            "jit": "off",
                        }
                    },
                )
            
            # Create session factory
            self.async_session_factory = async_sessionmaker(
                self.engine,
                class_=AsyncSession,
                expire_on_commit=False,
                autoflush=True,
                autocommit=False,
            )
            
            # Create tables
            await self.create_tables()
            
            self._initialized = True
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
    
    async def create_tables(self) -> None:
        """Create all database tables"""
        try:
            async with self.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Failed to create database tables: {e}")
            raise
    
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get database session with proper cleanup"""
        if not self._initialized:
            await self.initialize()
        
        async with self.async_session_factory() as session:
            try:
                yield session
            except Exception as e:
                await session.rollback()
                logger.error(f"Database session error: {e}")
                raise
            finally:
                await session.close()
    
    async def close(self) -> None:
        """Close database connections"""
        if self.engine:
            await self.engine.dispose()
            logger.info("Database connections closed")


# Global database manager instance
db_manager = DatabaseManager()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency to get database session"""
    async for session in db_manager.get_session():
        yield session


async def init_db() -> None:
    """Initialize database on application startup"""
    await db_manager.initialize()


async def close_db() -> None:
    """Close database connections on application shutdown"""
    await db_manager.close()


class DatabaseHealthChecker:
    """Health check for database connectivity"""
    
    @staticmethod
    async def check_connection() -> dict:
        """Check database connection health"""
        try:
            async with db_manager.engine.begin() as conn:
                result = await conn.execute(text("SELECT 1"))
                await result.fetchone()
            
            return {
                "status": "healthy",
                "message": "Database connection successful",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "message": f"Database connection failed: {str(e)}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
    
    @staticmethod
    async def check_performance() -> dict:
        """Check database performance metrics"""
        try:
            async with db_manager.engine.begin() as conn:
                # Simple performance test
                start_time = time.monotonic()
                result = await conn.execute(text("SELECT 1"))
                await result.fetchone()
                end_time = time.monotonic()
                
                query_time = (end_time - start_time) * 1000  # Convert to ms
                
                return {
                    "status": "healthy" if query_time < 100 else "degraded",
                    "query_time_ms": round(query_time, 2),
                    "message": f"Query executed in {query_time:.2f}ms",
                }
        except Exception as e:
            return {
                "status": "unhealthy",
                "message": f"Performance check failed: {str(e)}",
            }
