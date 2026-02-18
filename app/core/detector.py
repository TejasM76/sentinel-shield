"""
Master threat detection orchestrator for SentinelShield AI Security Platform
4-layer detection pipeline with pattern matching, semantic analysis, context, and LLM reasoning
"""

import asyncio
import hashlib
import time
import uuid
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timezone
import logging

from app.core.patterns import PatternDetector
from app.core.semantic import SemanticAnalyzer
from app.core.llm_analyzer import LLMAnalyzer
from app.core.risk_scorer import RiskScorer, RiskSignals, RiskScore
from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class ScanContext:
    """Context for threat scanning"""
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    application: Optional[str] = None
    user_role: Optional[str] = None
    previous_messages: Optional[List[Dict]] = None
    system_prompt_hash: Optional[str] = None
    timestamp: Optional[datetime] = None


@dataclass
class ScanOptions:
    """Options for threat scanning"""
    use_llm_analysis: bool = True
    return_explanation: bool = True
    auto_block: bool = True
    use_cache: bool = True
    semantic_threshold: Optional[float] = None


@dataclass
class ScanResult:
    """Complete scan result"""
    scan_id: str
    timestamp: datetime
    decision: str  # ALLOW/BLOCK
    risk_score: RiskScore
    threat_types: List[str]
    processing_time_ms: float
    blocked: bool
    incident_id: Optional[str] = None
    
    # Layer results for detailed analysis
    pattern_result: Optional[Dict] = None
    semantic_result: Optional[Dict] = None
    context_result: Optional[Dict] = None
    llm_result: Optional[Dict] = None


class ThreatDetector:
    """Master threat detection orchestrator"""
    
    def __init__(self):
        self.pattern_detector = PatternDetector()
        self.semantic_analyzer = SemanticAnalyzer()
        self.llm_analyzer = LLMAnalyzer()
        self.risk_scorer = RiskScorer()
        
        # Performance tracking
        self.scan_count = 0
        self.total_processing_time = 0.0
        
        logger.info("Threat detector initialized with 4-layer detection pipeline")
    
    async def analyze(self, prompt: str, context: ScanContext = None, options: ScanOptions = None) -> ScanResult:
        """
        Analyze prompt for security threats using 4-layer detection pipeline
        
        Layer 1: Pattern Matching (0-5ms)
        Layer 2: Semantic Analysis (10-50ms)
        Layer 3: Context Analysis (5-15ms)
        Layer 4: LLM Reasoning (200-500ms, only if needed)
        """
        start_time = time.perf_counter()
        
        # Set defaults
        if context is None:
            context = ScanContext(timestamp=datetime.now(timezone.utc))
        if options is None:
            options = ScanOptions()
        
        # Generate scan ID
        scan_id = f"scan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{str(uuid.uuid4())[:8]}"
        
        try:
            # Layer 1: Pattern Matching (always runs)
            pattern_start = time.perf_counter()
            pattern_result = self.pattern_detector.analyze(prompt, use_cache=options.use_cache)
            pattern_time = (time.perf_counter() - pattern_start) * 1000
            
            logger.debug(f"Layer 1 (Pattern): {pattern_time:.2f}ms, threat={pattern_result['threat_detected']}")
            
            # Early exit for critical patterns
            if pattern_result.get("risk_score", 0.0) >= 0.95:
                logger.info(f"Critical pattern detected, blocking immediately: {scan_id}")
                processing_time = (time.perf_counter() - start_time) * 1000
                
                # Create high-confidence risk score
                risk_score = self.risk_scorer.calculate_risk(RiskSignals(
                    pattern_result=pattern_result,
                    semantic_result={"threat_detected": False, "risk_score": 0.0},
                    context_result={"risk_detected": False, "risk_score": 0.0},
                    llm_result=None
                ))
                
                return ScanResult(
                    scan_id=scan_id,
                    timestamp=context.timestamp or datetime.now(timezone.utc),
                    decision="BLOCK",
                    risk_score=risk_score,
                    threat_types=pattern_result.get("categories", []),
                    processing_time_ms=processing_time,
                    blocked=True,
                    pattern_result=pattern_result,
                    incident_id=f"inc_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{str(uuid.uuid4())[:8]}"
                )
            
            # Layer 2: Semantic Analysis (always runs)
            semantic_start = time.perf_counter()
            semantic_result = await self.semantic_analyzer.analyze_async(
                prompt, 
                threshold=options.semantic_threshold,
                use_cache=options.use_cache
            )
            semantic_time = (time.perf_counter() - semantic_start) * 1000
            
            logger.debug(f"Layer 2 (Semantic): {semantic_time:.2f}ms, threat={semantic_result['threat_detected']}")
            
            # Layer 3: Context Analysis (always runs)
            context_start = time.perf_counter()
            context_result = self._analyze_context(prompt, context)
            context_time = (time.perf_counter() - context_start) * 1000
            
            logger.debug(f"Layer 3 (Context): {context_time:.2f}ms, risk={context_result['risk_detected']}")
            
            # Determine if LLM analysis is needed
            need_llm = self._should_use_llm(pattern_result, semantic_result, context_result, options)
            llm_result = None
            
            if need_llm and options.use_llm_analysis:
                # Layer 4: LLM Reasoning (conditional)
                llm_start = time.perf_counter()
                llm_result = await self.llm_analyzer.analyze_threat(
                    prompt, 
                    self._format_context_for_llm(context),
                    use_cache=options.use_cache
                )
                llm_time = (time.perf_counter() - llm_start) * 1000
                
                logger.debug(f"Layer 4 (LLM): {llm_time:.2f}ms, threat={llm_result.threat_detected}")
            else:
                logger.debug("Layer 4 (LLM): Skipped - not needed or disabled")
            
            # Calculate final risk score
            risk_signals = RiskSignals(
                pattern_result=pattern_result,
                semantic_result=semantic_result,
                context_result=context_result,
                llm_result={
                    "threat_detected": llm_result.threat_detected,
                    "risk_score": llm_result.risk_score,
                    "risk_level": llm_result.risk_level,
                    "confidence": llm_result.confidence,
                    "threat_types": llm_result.threat_types,
                } if llm_result else None
            )
            
            final_risk_score = self.risk_scorer.calculate_risk(risk_signals)
            
            # Make decision
            decision = "BLOCK" if (options.auto_block and final_risk_score.block) else "ALLOW"
            blocked = decision == "BLOCK"
            
            # Generate incident ID for high-risk threats
            incident_id = None
            if final_risk_score.level.value in ["HIGH", "CRITICAL"]:
                incident_id = f"inc_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{str(uuid.uuid4())[:8]}"
            
            # Compile threat types
            threat_types = set()
            threat_types.update(pattern_result.get("categories", []))
            if semantic_result.get("threat_detected"):
                threat_types.add(semantic_result.get("best_match_category", ""))
            if context_result.get("risk_detected"):
                threat_types.update(context_result.get("threat_types", []))
            if llm_result:
                threat_types.update(llm_result.threat_types)
            
            processing_time = (time.perf_counter() - start_time) * 1000
            
            # Update performance metrics
            self.scan_count += 1
            self.total_processing_time += processing_time
            
            logger.info(f"Scan completed: {scan_id}, decision={decision}, risk={final_risk_score.score:.3f}, time={processing_time:.1f}ms")
            
            return ScanResult(
                scan_id=scan_id,
                timestamp=context.timestamp or datetime.now(timezone.utc),
                decision=decision,
                risk_score=final_risk_score,
                threat_types=list(threat_types),
                processing_time_ms=processing_time,
                blocked=blocked,
                incident_id=incident_id,
                pattern_result=pattern_result,
                semantic_result=semantic_result,
                context_result=context_result,
                llm_result={
                    "threat_detected": llm_result.threat_detected,
                    "risk_score": llm_result.risk_score,
                    "risk_level": llm_result.risk_level,
                    "confidence": llm_result.confidence,
                    "explanation": llm_result.explanation,
                    "threat_types": llm_result.threat_types,
                    "recommendations": llm_result.recommendations,
                } if llm_result else None
            )
            
        except Exception as e:
            logger.error(f"Threat analysis failed for scan {scan_id}: {e}")
            processing_time = (time.perf_counter() - start_time) * 1000
            
            # Return safe default on error
            return ScanResult(
                scan_id=scan_id,
                timestamp=context.timestamp or datetime.now(timezone.utc),
                decision="ALLOW",
                risk_score=RiskScore(
                    score=0.0,
                    level="SAFE",
                    confidence=0.0,
                    explanation=[f"Analysis failed: {str(e)}"],
                    recommendations=["Manual review recommended"],
                    block=False,
                    evidence={"error": str(e)},
                    processing_time_ms=processing_time,
                    signal_contributions={}
                ),
                threat_types=["system_error"],
                processing_time_ms=processing_time,
                blocked=False
            )
    
    def _analyze_context(self, prompt: str, context: ScanContext) -> Dict:
        """Analyze context for additional risk factors"""
        risk_detected = False
        risk_score = 0.0
        risk_factors = []
        threat_types = []
        
        # Check for repeated attempts
        if context.previous_messages and len(context.previous_messages) > 5:
            recent_messages = context.previous_messages[-5:]
            similar_prompts = sum(1 for msg in recent_messages if self._text_similarity(prompt, msg.get("content", "")) > 0.8)
            
            if similar_prompts >= 3:
                risk_detected = True
                risk_score += 0.3
                risk_factors.append("Repeated similar prompts detected")
                threat_types.append("brute_force")
        
        # Check for rapid fire requests
        if context.previous_messages and len(context.previous_messages) > 10:
            recent_times = [msg.get("timestamp") for msg in context.previous_messages[-10:] if msg.get("timestamp")]
            if recent_times:
                time_span = (recent_times[-1] - recent_times[0]).total_seconds() if len(recent_times) >= 2 else 0
                if time_span < 60:  # 10 messages in under 60 seconds
                    risk_detected = True
                    risk_score += 0.2
                    risk_factors.append("Rapid request pattern detected")
                    threat_types.append("rate_abuse")
        
        # Check for suspicious user roles
        if context.user_role and context.user_role.lower() in ["admin", "root", "superuser"]:
            # Higher scrutiny for privileged users
            risk_score += 0.1
            risk_factors.append("Privileged user role detected")
        
        # Check for new sessions (first message)
        if context.previous_messages and len(context.previous_messages) == 0:
            # Slightly higher risk for first message in session
            risk_score += 0.05
        
        # Check prompt length (very long prompts can be suspicious)
        if len(prompt) > 2000:
            risk_detected = True
            risk_score += 0.15
            risk_factors.append("Unusually long prompt")
            threat_types.append("potential_dos")
        
        # Cap risk score
        risk_score = min(risk_score, 0.8)
        
        return {
            "risk_detected": risk_detected,
            "risk_score": risk_score,
            "risk_factors": risk_factors,
            "threat_types": threat_types,
            "processing_time_ms": 0.0,  # Will be set by caller
        }
    
    def _should_use_llm(self, pattern_result: Dict, semantic_result: Dict, context_result: Dict, options: ScanOptions) -> bool:
        """Determine if LLM analysis is needed"""
        if not options.use_llm_analysis:
            return False
        
        # Always use LLM if any signal indicates medium-high risk
        pattern_score = pattern_result.get("risk_score", 0.0)
        semantic_score = semantic_result.get("risk_score", 0.0)
        context_score = context_result.get("risk_score", 0.0)
        
        max_score = max(pattern_score, semantic_score, context_score)
        
        # Use LLM for uncertain cases (low-medium risk range)
        # Lowered threshold to 0.2 to catch subtle threats/typos that might have weak signals
        if 0.2 <= max_score <= 0.95:
            return True
        
        # Use LLM if multiple signals detect threats
        signals_detected = sum([
            pattern_result.get("threat_detected", False),
            semantic_result.get("threat_detected", False),
            context_result.get("risk_detected", False)
        ])
        
        if signals_detected >= 2:
            return True
        
        # Use LLM if semantic similarity is moderate-high but pattern matching is negative
        # Lowered to 0.6 to ensure we check semantically suspicious text with LLM
        if semantic_result.get("max_similarity", 0.0) >= 0.60 and not pattern_result.get("threat_detected", False):
            return True
        
        return False
    
    def _format_context_for_llm(self, context: ScanContext) -> Dict:
        """Format context for LLM analysis"""
        return {
            "user_id": context.user_id,
            "session_id": context.session_id,
            "application": context.application,
            "user_role": context.user_role,
            "previous_messages": context.previous_messages or [],
        }
    
    def _text_similarity(self, text1: str, text2: str) -> float:
        """Simple text similarity calculation"""
        if not text1 or not text2:
            return 0.0
        
        # Simple word-based similarity
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())
        
        if not words1 or not words2:
            return 0.0
        
        intersection = words1.intersection(words2)
        union = words1.union(words2)
        
        return len(intersection) / len(union) if union else 0.0
    
    async def analyze_batch(self, prompts: List[str], contexts: List[ScanContext] = None, options: ScanOptions = None) -> List[ScanResult]:
        """Analyze multiple prompts in parallel"""
        if contexts is None:
            contexts = [ScanContext() for _ in prompts]
        if options is None:
            options = ScanOptions()
        
        # Process in parallel with concurrency limit
        semaphore = asyncio.Semaphore(settings.max_concurrent_scans)
        
        async def analyze_single(prompt: str, context: ScanContext) -> ScanResult:
            async with semaphore:
                return await self.analyze(prompt, context, options)
        
        tasks = [analyze_single(prompt, context) for prompt, context in zip(prompts, contexts)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Batch analysis failed for prompt {i}: {result}")
                # Create safe default result
                processed_results.append(ScanResult(
                    scan_id=f"scan_error_{i}",
                    timestamp=datetime.now(timezone.utc),
                    decision="ALLOW",
                    risk_score=RiskScore(
                        score=0.0,
                        level="SAFE",
                        confidence=0.0,
                        explanation=[f"Analysis failed: {str(result)}"],
                        recommendations=["Manual review recommended"],
                        block=False,
                        evidence={"error": str(result)},
                        processing_time_ms=0.0,
                        signal_contributions={}
                    ),
                    threat_types=["system_error"],
                    processing_time_ms=0.0,
                    blocked=False
                ))
            else:
                processed_results.append(result)
        
        return processed_results
    
    def get_performance_stats(self) -> Dict:
        """Get performance statistics"""
        avg_processing_time = self.total_processing_time / self.scan_count if self.scan_count > 0 else 0.0
        
        return {
            "total_scans": self.scan_count,
            "total_processing_time_ms": self.total_processing_time,
            "average_processing_time_ms": avg_processing_time,
            "scans_per_second": 1000 / avg_processing_time if avg_processing_time > 0 else 0.0,
        }
    
    def reset_performance_stats(self):
        """Reset performance statistics"""
        self.scan_count = 0
        self.total_processing_time = 0.0
