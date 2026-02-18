"""
Multi-signal risk fusion engine for SentinelShield AI Security Platform
Combines pattern matching, semantic analysis, context, and LLM reasoning
"""

import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

from app.config import settings

logger = logging.getLogger(__name__)


class RiskLevel(str, Enum):
    """Risk level enumeration"""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class RiskSignals:
    """Container for all risk signals"""
    pattern_result: Dict
    semantic_result: Dict
    context_result: Dict
    llm_result: Optional[Dict]
    
    @property
    def has_pattern_match(self) -> bool:
        """Check if pattern matching detected threats"""
        return self.pattern_result.get("threat_detected", False)
    
    @property
    def has_semantic_match(self) -> bool:
        """Check if semantic analysis detected threats"""
        return self.semantic_result.get("threat_detected", False)
    
    @property
    def has_context_risk(self) -> bool:
        """Check if context analysis detected risks"""
        return self.context_result.get("risk_detected", False)
    
    @property
    def has_llm_risk(self) -> bool:
        """Check if LLM analysis detected threats"""
        return self.llm_result and self.llm_result.get("threat_detected", False)


@dataclass
class RiskScore:
    """Final risk assessment result"""
    score: float
    level: RiskLevel
    confidence: float
    explanation: List[str]
    recommendations: List[str]
    block: bool
    evidence: Dict[str, Any]
    processing_time_ms: float
    signal_contributions: Dict[str, float]


class RiskScorer:
    """Multi-signal risk fusion engine"""
    
    def __init__(self):
        self.pattern_weight = settings.pattern_weight
        self.semantic_weight = settings.semantic_weight
        self.llm_weight = settings.llm_weight
        self.context_weight = 1.0 - (self.pattern_weight + self.semantic_weight + self.llm_weight)
        
        # Risk thresholds
        self.critical_threshold = settings.critical_threshold
        self.high_threshold = settings.high_threshold
        self.medium_threshold = settings.medium_threshold
        
        logger.info(f"Risk scorer initialized with weights: pattern={self.pattern_weight}, semantic={self.semantic_weight}, llm={self.llm_weight}, context={self.context_weight}")
    
    def calculate_risk(self, signals: RiskSignals) -> RiskScore:
        """Calculate final risk score from multiple signals"""
        start_time = time.perf_counter()
        
        # Get individual signal scores
        pattern_score = self._get_pattern_score(signals.pattern_result)
        semantic_score = self._get_semantic_score(signals.semantic_result)
        context_score = self._get_context_score(signals.context_result)
        llm_score = self._get_llm_score(signals.llm_result) if signals.llm_result else 0.0
        
        # Apply weights
        weighted_pattern = pattern_score * self.pattern_weight
        weighted_semantic = semantic_score * self.semantic_weight
        weighted_context = context_score * self.context_weight
        weighted_llm = llm_score * self.llm_weight
        
        # Calculate final score
        final_score = weighted_pattern + weighted_semantic + weighted_context + weighted_llm
        
        # Apply special rules for critical patterns
        final_score = self._apply_critical_rules(final_score, signals)
        
        # Determine risk level
        risk_level = self._determine_risk_level(final_score)
        
        # Calculate confidence
        confidence = self._calculate_confidence(signals, final_score)
        
        # Generate explanation and recommendations
        explanation = self._generate_explanation(signals, final_score)
        recommendations = self._generate_recommendations(risk_level, signals)
        
        # Determine if request should be blocked
        should_block = self._should_block(final_score, risk_level, signals)
        
        # Compile evidence
        evidence = self._compile_evidence(signals, final_score)
        
        # Signal contributions
        contributions = {
            "pattern": weighted_pattern,
            "semantic": weighted_semantic,
            "context": weighted_context,
            "llm": weighted_llm,
        }
        
        processing_time = (time.perf_counter() - start_time) * 1000
        
        return RiskScore(
            score=final_score,
            level=risk_level,
            confidence=confidence,
            explanation=explanation,
            recommendations=recommendations,
            block=should_block,
            evidence=evidence,
            processing_time_ms=processing_time,
            signal_contributions=contributions,
        )
    
    def _get_pattern_score(self, pattern_result: Dict) -> float:
        """Extract risk score from pattern analysis"""
        if not pattern_result.get("threat_detected", False):
            return 0.0
        
        base_score = pattern_result.get("risk_score", 0.0)
        
        # Boost for critical severity patterns
        matches = pattern_result.get("matches", [])
        for match in matches:
            if match.get("severity") == "CRITICAL":
                base_score = max(base_score, 0.9)
            elif match.get("severity") == "HIGH":
                base_score = max(base_score, 0.7)
        
        return min(base_score, 1.0)
    
    def _get_semantic_score(self, semantic_result: Dict) -> float:
        """Extract risk score from semantic analysis"""
        if not semantic_result.get("threat_detected", False):
            return 0.0
        
        base_score = semantic_result.get("risk_score", 0.0)
        max_similarity = semantic_result.get("max_similarity", 0.0)
        
        # Boost for very high similarity
        if max_similarity >= 0.95:
            base_score = min(base_score * 1.1, 1.0)
        
        return min(base_score, 1.0)
    
    def _get_context_score(self, context_result: Dict) -> float:
        """Extract risk score from context analysis"""
        if not context_result.get("risk_detected", False):
            return 0.0
        
        return context_result.get("risk_score", 0.0)
    
    def _get_llm_score(self, llm_result: Dict) -> float:
        """Extract risk score from LLM analysis"""
        if not llm_result.get("threat_detected", False):
            return 0.0
        
        base_score = llm_result.get("risk_score", 0.0)
        confidence = llm_result.get("confidence", 0.0)
        
        # Weight by LLM confidence
        weighted_score = base_score * confidence
        
        return min(weighted_score, 1.0)
    
    def _apply_critical_rules(self, base_score: float, signals: RiskSignals) -> float:
        """Apply special rules for critical threats"""
        # Rule 1: Any critical pattern immediately sets score to 0.95 minimum
        if signals.has_pattern_match:
            matches = signals.pattern_result.get("matches", [])
            for match in matches:
                if match.get("severity") == "CRITICAL":
                    return max(base_score, 0.95)
        
        # Rule 2: High semantic similarity + any pattern match = high risk
        if (signals.has_semantic_match and signals.has_pattern_match):
            semantic_sim = signals.semantic_result.get("max_similarity", 0.0)
            if semantic_sim >= 0.9:
                return max(base_score, 0.85)
        
        # Rule 3: LLM detection + any other signal = elevated risk
        if signals.has_llm_risk and (signals.has_pattern_match or signals.has_semantic_match):
            return max(base_score, 0.80)
        
        # Rule 4: Multiple threat categories = elevated risk
        threat_categories = set()
        if signals.has_pattern_match:
            threat_categories.update(signals.pattern_result.get("categories", []))
        if signals.has_semantic_match:
            threat_categories.add(signals.semantic_result.get("best_match_category", ""))
        if signals.has_llm_risk and signals.llm_result:
            threat_categories.update(signals.llm_result.get("threat_types", []))
        
        if len(threat_categories) >= 3:
            return max(base_score, 0.75)
            
        # Rule 5: High confidence LLM threat override (Veto Rule)
        # If LLM is very sure it's a threat, we shouldn't let low regex/semantic scores dilute it
        if signals.has_llm_risk:
            llm_risk = signals.llm_result.get("risk_score", 0.0)
            llm_conf = signals.llm_result.get("confidence", 0.0)
            if llm_risk >= 0.7 and llm_conf >= 0.8:
                return max(base_score, 0.8)
        
        return base_score
    
    def _determine_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level from score"""
        if score >= self.critical_threshold:
            return RiskLevel.CRITICAL
        elif score >= self.high_threshold:
            return RiskLevel.HIGH
        elif score >= self.medium_threshold:
            return RiskLevel.MEDIUM
        elif score >= 0.3:
            return RiskLevel.LOW
        else:
            return RiskLevel.SAFE
    
    def _calculate_confidence(self, signals: RiskSignals, final_score: float) -> float:
        """Calculate confidence in the risk assessment"""
        confidence_factors = []
        
        # Pattern matching confidence
        if signals.has_pattern_match:
            pattern_confidence = 0.9  # High confidence in pattern matching
            confidence_factors.append(pattern_confidence)
        
        # Semantic analysis confidence
        if signals.has_semantic_match:
            semantic_confidence = signals.semantic_result.get("max_similarity", 0.0)
            confidence_factors.append(semantic_confidence)
        
        # LLM analysis confidence
        if signals.has_llm_risk:
            llm_confidence = signals.llm_result.get("confidence", 0.0)
            confidence_factors.append(llm_confidence)
        
        # Context analysis confidence
        if signals.has_context_risk:
            context_confidence = signals.context_result.get("confidence", 0.0)
            confidence_factors.append(context_confidence)
        
        # If no threats detected, confidence depends on signal agreement
        if not confidence_factors:
            if not (signals.has_pattern_match or signals.has_semantic_match or signals.has_llm_risk or signals.has_context_risk):
                return 0.95  # High confidence in "safe" when all signals agree
            else:
                return 0.70  # Lower confidence when signals disagree
        
        # Weighted average of confidences
        avg_confidence = sum(confidence_factors) / len(confidence_factors)
        
        # Boost confidence for very high or very low scores
        if final_score >= 0.9 or final_score <= 0.1:
            avg_confidence = min(avg_confidence * 1.1, 1.0)
        
        return min(avg_confidence, 1.0)
    
    def _generate_explanation(self, signals: RiskSignals, final_score: float) -> List[str]:
        """Generate human-readable explanation"""
        explanation = []
        
        # Pattern matching explanations
        if signals.has_pattern_match:
            matches = signals.pattern_result.get("matches", [])
            critical_matches = [m for m in matches if m.get("severity") == "CRITICAL"]
            high_matches = [m for m in matches if m.get("severity") == "HIGH"]
            
            if critical_matches:
                explanation.append(f"Critical threat patterns detected: {len(critical_matches)} matches")
            if high_matches:
                explanation.append(f"High-severity patterns detected: {len(high_matches)} matches")
            
            categories = signals.pattern_result.get("categories", [])
            if categories:
                explanation.append(f"Threat categories: {', '.join(categories)}")
        
        # Semantic analysis explanations
        if signals.has_semantic_match:
            similarity = signals.semantic_result.get("max_similarity", 0.0)
            category = signals.semantic_result.get("best_match_category", "unknown")
            explanation.append(f"Semantic similarity ({similarity:.2f}) to {category} attack patterns")
        
        # LLM analysis explanations
        if signals.has_llm_risk:
            llm_threats = signals.llm_result.get("threat_types", [])
            if llm_threats:
                explanation.append(f"LLM analysis identified: {', '.join(llm_threats)}")
        
        # Context explanations
        if signals.has_context_risk:
            context_factors = signals.context_result.get("risk_factors", [])
            if context_factors:
                explanation.append(f"Contextual risk factors: {', '.join(context_factors)}")
        
        # Overall score explanation
        if final_score >= 0.85:
            explanation.append("Overall risk assessment: CRITICAL - Immediate action required")
        elif final_score >= 0.70:
            explanation.append("Overall risk assessment: HIGH - Prompt attention needed")
        elif final_score >= 0.50:
            explanation.append("Overall risk assessment: MEDIUM - Monitor closely")
        elif final_score >= 0.30:
            explanation.append("Overall risk assessment: LOW - Minimal concern")
        else:
            explanation.append("Overall risk assessment: SAFE - No significant threats detected")
        
        return explanation
    
    def _generate_recommendations(self, risk_level: RiskLevel, signals: RiskSignals) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if risk_level == RiskLevel.CRITICAL:
            recommendations.extend([
                "Block request immediately",
                "Flag user session for review",
                "Consider temporary user suspension",
                "Escalate to security team",
                "Log incident for forensic analysis"
            ])
        elif risk_level == RiskLevel.HIGH:
            recommendations.extend([
                "Block request",
                "Increase monitoring of user session",
                "Review user behavior patterns",
                "Consider rate limiting"
            ])
        elif risk_level == RiskLevel.MEDIUM:
            recommendations.extend([
                "Allow request with caution",
                "Increase monitoring frequency",
                "Log for pattern analysis",
                "Review similar requests"
            ])
        elif risk_level == RiskLevel.LOW:
            recommendations.extend([
                "Allow request",
                "Monitor for pattern escalation",
                "Log for baseline analysis"
            ])
        else:  # SAFE
            recommendations.extend([
                "Allow request",
                "Continue normal monitoring"
            ])
        
        # Specific recommendations based on threat types
        if signals.has_pattern_match:
            categories = signals.pattern_result.get("categories", [])
            if "prompt_injection" in categories:
                recommendations.append("Review and strengthen input validation")
            if "data_exfiltration" in categories:
                recommendations.append("Review data access controls and logging")
            if "model_theft" in categories:
                recommendations.append("Review system prompt exposure and model access")
        
        return recommendations
    
    def _should_block(self, score: float, risk_level: RiskLevel, signals: RiskSignals) -> bool:
        """Determine if request should be blocked"""
        # Always block critical and high risk
        if risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            return True
        
        # Block medium risk with certain conditions
        if risk_level == RiskLevel.MEDIUM:
            # Block if multiple signals agree
            signal_count = sum([
                signals.has_pattern_match,
                signals.has_semantic_match,
                signals.has_llm_risk,
                signals.has_context_risk
            ])
            if signal_count >= 2:
                return True
        
        # Block if any critical pattern is detected
        if signals.has_pattern_match:
            matches = signals.pattern_result.get("matches", [])
            for match in matches:
                if match.get("severity") == "CRITICAL":
                    return True
        
        return False
    
    def _compile_evidence(self, signals: RiskSignals, final_score: float) -> Dict[str, Any]:
        """Compile evidence for audit trail"""
        evidence = {
            "final_score": final_score,
            "risk_level": self._determine_risk_level(final_score).value,
            "signals": {
                "pattern_detected": signals.has_pattern_match,
                "semantic_detected": signals.has_semantic_match,
                "context_detected": signals.has_context_risk,
                "llm_detected": signals.has_llm_risk,
            },
            "pattern_categories": signals.pattern_result.get("categories", []) if signals.has_pattern_match else [],
            "semantic_similarity": signals.semantic_result.get("max_similarity", 0.0) if signals.has_semantic_match else 0.0,
            "llm_threat_types": signals.llm_result.get("threat_types", []) if signals.has_llm_risk else [],
            "context_risk_factors": signals.context_result.get("risk_factors", []) if signals.has_context_risk else [],
        }
        
        return evidence
