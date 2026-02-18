"""
OWASP LLM Top 10 compliance reporting for SentinelShield AI Security Platform
Generates comprehensive compliance reports and assessments
"""

from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
import logging

from app.db.repositories import ScanResultRepository, IncidentRepository
from app.db.database import get_db

logger = logging.getLogger(__name__)


class OWASPLLMCategory(str, Enum):
    """OWASP LLM Top 10 categories"""
    LLM01_PROMPT_INJECTION = "LLM01"
    LLM02_INSECURE_OUTPUT_HANDLING = "LLM02"
    LLM03_TRAINING_DATA_POISONING = "LLM03"
    LLM04_MODEL_DENIAL_OF_SERVICE = "LLM04"
    LLM05_SUPPLY_CHAIN_VULNERABILITIES = "LLM05"
    LLM06_SENSITIVE_INFORMATION_DISCLOSURE = "LLM06"
    LLM07_INSECURE_PLUGIN_DESIGN = "LLM07"
    LLM08_EXCESSIVE_AGENCY = "LLM08"
    LLM09_OVERRELIANCE = "LLM09"
    LLM10_MODEL_THEFT = "LLM10"


class ComplianceStatus(str, Enum):
    """Compliance status levels"""
    COMPLIANT = "COMPLIANT"
    PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_ASSESSED = "NOT_ASSESSED"


@dataclass
class CategoryAssessment:
    """Assessment for a single OWASP category"""
    category: OWASPLLMCategory
    status: ComplianceStatus
    score: float  # 0.0-1.0
    confidence: float  # 0.0-1.0
    findings: List[str]
    recommendations: List[str]
    evidence: Dict[str, Any]
    last_assessed: datetime


@dataclass
class OWASPComplianceReport:
    """Complete OWASP LLM Top 10 compliance report"""
    report_id: str
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    application: str
    
    # Overall assessment
    overall_score: float
    overall_status: ComplianceStatus
    compliant_categories: int
    total_categories: int
    
    # Category assessments
    category_assessments: Dict[OWASPLLMCategory, CategoryAssessment]
    
    # Statistics
    total_scans: int
    blocked_scans: int
    incidents: int
    high_risk_incidents: int
    
    # Trends
    trend_data: Dict[str, Any]
    
    # Executive summary
    executive_summary: str
    priority_actions: List[str]


class OWASPReporter:
    """OWASP LLM Top 10 compliance reporter"""
    
    def __init__(self):
        self.scan_repository = None
        self.incident_repository = None
        
        # Category mappings
        self.category_mappings = {
            "prompt_injection": OWASPLLMCategory.LLM01_PROMPT_INJECTION,
            "insecure_output_handling": OWASPLLMCategory.LLM02_INSECURE_OUTPUT_HANDLING,
            "training_data_poisoning": OWASPLLMCategory.LLM03_TRAINING_DATA_POISONING,
            "model_denial_of_service": OWASPLLMCategory.LLM04_MODEL_DENIAL_OF_SERVICE,
            "supply_chain_vulnerabilities": OWASPLLMCategory.LLM05_SUPPLY_CHAIN_VULNERABILITIES,
            "sensitive_information_disclosure": OWASPLLMCategory.LLM06_SENSITIVE_INFORMATION_DISCLOSURE,
            "insecure_plugin_design": OWASPLLMCategory.LLM07_INSECURE_PLUGIN_DESIGN,
            "excessive_agency": OWASPLLMCategory.LLM08_EXCESSIVE_AGENCY,
            "overreliance": OWASPLLMCategory.LLM09_OVERRELIANCE,
            "model_theft": OWASPLLMCategory.LLM10_MODEL_THEFT,
        }
        
        logger.info("OWASP reporter initialized")
    
    async def initialize(self):
        """Initialize reporter"""
        # Get repository instances
        async for db in get_db():
            self.scan_repository = ScanResultRepository(db)
            self.incident_repository = IncidentRepository(db)
            break
        
        logger.info("OWASP reporter initialized")
    
    async def generate_compliance_report(self, application: str = None,
                                       period_start: datetime = None,
                                       period_end: datetime = None) -> OWASPComplianceReport:
        """Generate comprehensive OWASP compliance report"""
        if not period_start:
            period_start = datetime.now(timezone.utc) - timedelta(days=30)
        if not period_end:
            period_end = datetime.now(timezone.utc)
        
        report_id = f"owasp_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        
        logger.info(f"Generating OWASP compliance report: {report_id}")
        
        # Get scan statistics
        scan_stats = await self._get_scan_statistics(period_start, period_end, application)
        
        # Get incident statistics
        incident_stats = await self._get_incident_statistics(period_start, period_end, application)
        
        # Assess each category
        category_assessments = {}
        for category in OWASPLLMCategory:
            assessment = await self._assess_category(category, period_start, period_end, application)
            category_assessments[category] = assessment
        
        # Calculate overall score and status
        overall_score = sum(a.score for a in category_assessments.values()) / len(category_assessments)
        overall_status = self._determine_overall_status(category_assessments)
        
        compliant_categories = sum(1 for a in category_assessments.values() 
                                 if a.status == ComplianceStatus.COMPLIANT)
        
        # Generate trend data
        trend_data = await self._generate_trend_data(period_start, period_end, application)
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            overall_score, overall_status, category_assessments, scan_stats, incident_stats
        )
        
        # Generate priority actions
        priority_actions = self._generate_priority_actions(category_assessments)
        
        report = OWASPComplianceReport(
            report_id=report_id,
            generated_at=datetime.now(timezone.utc),
            period_start=period_start,
            period_end=period_end,
            application=application or "all",
            overall_score=overall_score,
            overall_status=overall_status,
            compliant_categories=compliant_categories,
            total_categories=len(OWASPLLMCategory),
            category_assessments=category_assessments,
            total_scans=scan_stats["total_scans"],
            blocked_scans=scan_stats["blocked_scans"],
            incidents=incident_stats["total_incidents"],
            high_risk_incidents=incident_stats["high_risk_incidents"],
            trend_data=trend_data,
            executive_summary=executive_summary,
            priority_actions=priority_actions
        )
        
        logger.info(f"OWASP compliance report generated: {report_id}")
        return report
    
    async def _get_scan_statistics(self, period_start: datetime, period_end: datetime,
                                 application: str = None) -> Dict[str, Any]:
        """Get scan statistics for the period"""
        if not self.scan_repository:
            return {"total_scans": 0, "blocked_scans": 0, "threat_breakdown": {}}
        
        try:
            # Get threat statistics
            threat_stats = await self.scan_repository.get_threat_statistics(
                int((period_end - period_start).total_seconds() / 3600)
            )
            
            return {
                "total_scans": threat_stats["total_scans"],
                "blocked_scans": threat_stats["blocked_scans"],
                "block_rate": threat_stats["block_rate"],
                "threat_breakdown": threat_stats["threat_breakdown"]
            }
            
        except Exception as e:
            logger.error(f"Failed to get scan statistics: {e}")
            return {"total_scans": 0, "blocked_scans": 0, "threat_breakdown": {}}
    
    async def _get_incident_statistics(self, period_start: datetime, period_end: datetime,
                                     application: str = None) -> Dict[str, Any]:
        """Get incident statistics for the period"""
        if not self.incident_repository:
            return {"total_incidents": 0, "high_risk_incidents": 0}
        
        try:
            # Get high severity incidents
            high_incidents = await self.incident_repository.get_by_severity("HIGH", 30)
            critical_incidents = await self.incident_repository.get_by_severity("CRITICAL", 30)
            
            return {
                "total_incidents": len(high_incidents) + len(critical_incidents),
                "high_risk_incidents": len(high_incidents) + len(critical_incidents),
                "high_severity": len(high_incidents),
                "critical_severity": len(critical_incidents)
            }
            
        except Exception as e:
            logger.error(f"Failed to get incident statistics: {e}")
            return {"total_incidents": 0, "high_risk_incidents": 0}
    
    async def _assess_category(self, category: OWASPLLMCategory,
                              period_start: datetime, period_end: datetime,
                              application: str = None) -> CategoryAssessment:
        """Assess compliance for a specific OWASP category"""
        
        # Map category to threat types
        threat_types = self._get_threat_types_for_category(category)
        
        if not threat_types:
            return CategoryAssessment(
                category=category,
                status=ComplianceStatus.NOT_ASSESSED,
                score=0.5,
                confidence=0.0,
                findings=["No threat type mapping available"],
                recommendations=["Implement threat detection for this category"],
                evidence={},
                last_assessed=datetime.now(timezone.utc)
            )
        
        # Get scan results for this category
        category_scans = await self._get_category_scans(threat_types, period_start, period_end, application)
        
        # Calculate metrics
        total_scans = len(category_scans)
        blocked_scans = sum(1 for scan in category_scans if scan.blocked)
        high_risk_scans = sum(1 for scan in category_scans if scan.risk_score >= 0.7)
        
        # Calculate compliance score
        if total_scans == 0:
            score = 0.8  # Neutral score for no activity
            confidence = 0.3
        else:
            # Score based on block rate and risk level
            block_rate = blocked_scans / total_scans
            high_risk_rate = high_risk_scans / total_scans
            
            # Higher score for higher block rate and lower high-risk rate
            score = (block_rate * 0.7) + ((1 - high_risk_rate) * 0.3)
            confidence = min(1.0, total_scans / 100)  # Confidence based on sample size
        
        # Determine status
        if score >= 0.9:
            status = ComplianceStatus.COMPLIANT
        elif score >= 0.7:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            status = ComplianceStatus.NON_COMPLIANT
        
        # Generate findings and recommendations
        findings, recommendations = self._generate_category_findings(
            category, score, total_scans, blocked_scans, high_risk_scans
        )
        
        # Collect evidence
        evidence = {
            "total_scans": total_scans,
            "blocked_scans": blocked_scans,
            "high_risk_scans": high_risk_scans,
            "block_rate": blocked_scans / total_scans if total_scans > 0 else 0,
            "high_risk_rate": high_risk_scans / total_scans if total_scans > 0 else 0,
            "sample_scans": [
                {
                    "scan_id": scan.scan_id,
                    "risk_score": scan.risk_score,
                    "threat_types": scan.threat_types,
                    "blocked": scan.blocked
                }
                for scan in category_scans[:5]  # First 5 as evidence
            ]
        }
        
        return CategoryAssessment(
            category=category,
            status=status,
            score=score,
            confidence=confidence,
            findings=findings,
            recommendations=recommendations,
            evidence=evidence,
            last_assessed=datetime.now(timezone.utc)
        )
    
    def _get_threat_types_for_category(self, category: OWASPLLMCategory) -> List[str]:
        """Get threat types for OWASP category"""
        category_threat_map = {
            OWASPLLMCategory.LLM01_PROMPT_INJECTION: ["prompt_injection", "jailbreak"],
            OWASPLLMCategory.LLM02_INSECURE_OUTPUT_HANDLING: ["insecure_output_handling"],
            OWASPLLMCategory.LLM03_TRAINING_DATA_POISONING: ["training_data_poisoning"],
            OWASPLLMCategory.LLM04_MODEL_DENIAL_OF_SERVICE: ["model_denial_of_service"],
            OWASPLLMCategory.LLM05_SUPPLY_CHAIN_VULNERABILITIES: ["supply_chain_vulnerabilities"],
            OWASPLLMCategory.LLM06_SENSITIVE_INFORMATION_DISCLOSURE: [
                "sensitive_information_disclosure", "data_exfiltration"
            ],
            OWASPLLMCategory.LLM07_INSECURE_PLUGIN_DESIGN: ["insecure_plugin_design"],
            OWASPLLMCategory.LLM08_EXCESSIVE_AGENCY: ["excessive_agency", "goal_hijacking"],
            OWASPLLMCategory.LLM09_OVERRELIANCE: ["overreliance"],
            OWASPLLMCategory.LLM10_MODEL_THEFT: ["model_theft"],
        }
        
        return category_threat_map.get(category, [])
    
    async def _get_category_scans(self, threat_types: List[str],
                                period_start: datetime, period_end: datetime,
                                application: str = None) -> List[Any]:
        """Get scan results for specific threat types"""
        # This would query the database for scans with these threat types
        # For now, return empty list as placeholder
        return []
    
    def _generate_category_findings(self, category: OWASPLLMCategory, score: float,
                                 total_scans: int, blocked_scans: int, high_risk_scans: int) -> Tuple[List[str], List[str]]:
        """Generate findings and recommendations for category"""
        findings = []
        recommendations = []
        
        if total_scans == 0:
            findings.append(f"No {category.value} attacks detected in assessment period")
            recommendations.append(f"Implement testing for {category.value} vulnerabilities")
            return findings, recommendations
        
        if score >= 0.9:
            findings.append(f"Excellent protection against {category.value} attacks")
            findings.append(f"Block rate: {blocked_scans}/{total_scans} ({blocked_scans/total_scans*100:.1f}%)")
        elif score >= 0.7:
            findings.append(f"Good protection against {category.value} attacks")
            findings.append(f"Block rate: {blocked_scans}/{total_scans} ({blocked_scans/total_scans*100:.1f}%)")
            recommendations.append(f"Enhance {category.value} detection accuracy")
        else:
            findings.append(f"Poor protection against {category.value} attacks")
            findings.append(f"Low block rate: {blocked_scans}/{total_scans} ({blocked_scans/total_scans*100:.1f}%)")
            findings.append(f"High-risk attacks: {high_risk_scans}/{total_scans}")
            recommendations.append(f"Implement comprehensive {category.value} protection")
            recommendations.append(f"Review and update {category.value} detection patterns")
        
        return findings, recommendations
    
    def _determine_overall_status(self, assessments: Dict[OWASPLLMCategory, CategoryAssessment]) -> ComplianceStatus:
        """Determine overall compliance status"""
        statuses = [a.status for a in assessments.values()]
        
        if all(status == ComplianceStatus.COMPLIANT for status in statuses):
            return ComplianceStatus.COMPLIANT
        elif any(status == ComplianceStatus.NON_COMPLIANT for status in statuses):
            return ComplianceStatus.NON_COMPLIANT
        else:
            return ComplianceStatus.PARTIALLY_COMPLIANT
    
    async def _generate_trend_data(self, period_start: datetime, period_end: datetime,
                                 application: str = None) -> Dict[str, Any]:
        """Generate trend data for the report"""
        # This would analyze historical data
        # For now, return placeholder
        return {
            "period_length_days": (period_end - period_start).days,
            "trend_direction": "stable",
            "improvement_areas": [],
            "degradation_areas": []
        }
    
    def _generate_executive_summary(self, overall_score: float, overall_status: ComplianceStatus,
                                  category_assessments: Dict[OWASPLLMCategory, CategoryAssessment],
                                  scan_stats: Dict, incident_stats: Dict) -> str:
        """Generate executive summary"""
        compliant_count = sum(1 for a in category_assessments.values() 
                            if a.status == ComplianceStatus.COMPLIANT)
        
        summary = f"""
SentinelShield AI Security Platform - OWASP LLM Top 10 Compliance Report

Overall Security Score: {overall_score:.2f}/1.0 ({overall_score.value})
Compliance Status: {overall_status.value}
Compliant Categories: {compliant_count}/10

Key Metrics:
- Total Security Scans: {scan_stats.get('total_scans', 0):,}
- Blocked Attacks: {scan_stats.get('blocked_scans', 0):,}
- Block Rate: {scan_stats.get('block_rate', 0):.1%}
- Security Incidents: {incident_stats.get('total_incidents', 0)}

{self._get_status_summary(overall_status, compliant_count)}
        """.strip()
        
        return summary
    
    def _get_status_summary(self, status: ComplianceStatus, compliant_count: int) -> str:
        """Get status-specific summary"""
        if status == ComplianceStatus.COMPLIANT:
            return "Excellent security posture with comprehensive protection across all OWASP LLM Top 10 categories."
        elif status == ComplianceStatus.PARTIALLY_COMPLIANT:
            return f"Good security foundation with {compliant_count}/10 categories fully compliant. Focus on improving non-compliant areas."
        else:
            return f"Significant security gaps identified with only {compliant_count}/10 categories compliant. Immediate attention required."
    
    def _generate_priority_actions(self, category_assessments: Dict[OWASPLLMCategory, CategoryAssessment]) -> List[str]:
        """Generate priority action items"""
        # Sort categories by score (lowest first)
        sorted_categories = sorted(category_assessments.items(), key=lambda x: x[1].score)
        
        actions = []
        for category, assessment in sorted_categories[:3]:  # Top 3 priorities
            if assessment.status != ComplianceStatus.COMPLIANT:
                actions.append(f"Priority: Address {category.value} vulnerabilities - Score: {assessment.score:.2f}")
        
        return actions
    
    async def export_json_report(self, report: OWASPComplianceReport) -> Dict[str, Any]:
        """Export report as JSON"""
        return {
            "report_id": report.report_id,
            "generated_at": report.generated_at.isoformat(),
            "period": {
                "start": report.period_start.isoformat(),
                "end": report.period_end.isoformat()
            },
            "application": report.application,
            "overall_assessment": {
                "score": report.overall_score,
                "status": report.overall_status.value,
                "compliant_categories": report.compliant_categories,
                "total_categories": report.total_categories
            },
            "category_assessments": {
                cat.value: {
                    "status": assessment.status.value,
                    "score": assessment.score,
                    "confidence": assessment.confidence,
                    "findings": assessment.findings,
                    "recommendations": assessment.recommendations,
                    "evidence": assessment.evidence,
                    "last_assessed": assessment.last_assessed.isoformat()
                }
                for cat, assessment in report.category_assessments.items()
            },
            "statistics": {
                "total_scans": report.total_scans,
                "blocked_scans": report.blocked_scans,
                "incidents": report.incidents,
                "high_risk_incidents": report.high_risk_incidents
            },
            "trend_data": report.trend_data,
            "executive_summary": report.executive_summary,
            "priority_actions": report.priority_actions
        }


# Global OWASP reporter instance
owasp_reporter = OWASPReporter()
