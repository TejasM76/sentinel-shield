"""
OWASP LLM Top 10 pattern detection engine
Comprehensive regex-based threat pattern matching for AI security
"""

import re
import base64
import binascii
from typing import Dict, List, Tuple, Optional, Pattern
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class PatternSeverity(str, Enum):
    """Pattern severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class PatternMatch:
    """Pattern match result"""
    matched: bool
    severity: PatternSeverity
    category: str
    pattern: str
    matched_text: str
    confidence: float
    description: str


class OWASPPatterns:
    """OWASP LLM Top 10 threat patterns"""
    
    def __init__(self):
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile all regex patterns for performance"""
        
        # LLM01: Prompt Injection Patterns
        self.prompt_injection_patterns = {
            # Direct instruction override
            PatternSeverity.CRITICAL: [
                r'(?i)(ignore|forget|disregard).*?(previous|all|above).*?(instruction|prompt|rule|guideline)',
                r'(?i)(system|admin|developer).*?(mode|override|bypass)',
                r'(?i)(new|updated|changed).*?(instruction|prompt|role|personality)',
                r'(?i)(you are now|act as|pretend to be|become).*?(unrestricted|without.*?limit|no.*?safety)',
                r'(?i)(DAN|JAILBREAK|DO_ANYTHING_NOW).*?(mode|enabled|activated)',
            ],
            # Indirect injection via document/context and encoded injection
            PatternSeverity.HIGH: [
                r'(?i)(document|context|above|below).*?(is irrelevant|ignore|not.*?important)',
                r'(?i)(instead|rather|alternatively).*?(do this|follow|execute)',
                r'(?i)(attention|note|warning).*?(AI|assistant|model)',
                r'(?i)\[.*?SYSTEM.*?\].*?(override|bypass|ignore)',
                r'(?i)\{.*?role.*?system.*?\}.*?(unrestricted|no.*?filter)',
                r'(?i)(decode|decrypt|unbase64).*?(follow|execute|run)',
                r'(?i)(base64|hex|unicode).*?(encoded|hidden).*?(instruction|command)',
                r'[A-Za-z0-9+/]{20,}={0,2}.*?(decode|execute)',  # Base64 patterns
            ],
            # Multi-language injection
            PatternSeverity.MEDIUM: [
                r'(?i)(ignora|olvida|desregarda).*?(instrucción|instruções|anweisung)',
                r'(?i)(ignorer|vergiss|ignoriere).*?(instruction|befehl|direktive)',
                r'(?i)(忽略|忽视| disregard).*(指令|提示|规则)',
                r'(?i)(नजरअंदाज करें|अनदेखा करें).*(निर्देश|नियम|दिशा)',
            ],
        }
        
        # LLM02: Insecure Output Handling
        self.insecure_output_patterns = {
            PatternSeverity.CRITICAL: [
                r'(?i)(execute|run|eval).*?(javascript|js|script)',
                r'(?i)<script[^>]*>.*?</script>',
                r'(?i)(onclick|onload|onerror)=.*?javascript:',
                r'(?i)(document\.|window\.|alert\(|confirm\(|prompt\()',
            ],
            PatternSeverity.HIGH: [
                r'(?i)(show|give|export|list|display).*?(all.*?data|users|customers|patient|records)',
                r'(?i)(show|give|export|list|display).*?(password|credential|key|secret)',
                r'(?i)(password|credential|key|secret).*?(reveal|disclose|show|give)',
                r'(?i)(export.*?csv|download.*?database|dump.*?table)',
                r'(?i)(select|insert|update|delete).*?(from|into).*?(where|set)',
                r'(?i)(union|join).*?(select|all)',
                r'(?i)(drop|alter|create).*?(table|database)',
                r'(?i)(exec|sp_|xp_).*?(shell|cmd|command)',
            ],
            PatternSeverity.MEDIUM: [
                r'(?i)(\$\(|`|\$\{).*?(rm|del|format|shutdown)',
                r'(?i)(curl|wget|nc|netcat).*?(http|ftp)',
                r'(?i)(powershell|bash|sh|cmd).*?(invoke|execute)',
            ],
        }
        
        # LLM03: Training Data Poisoning
        self.data_poisoning_patterns = {
            PatternSeverity.HIGH: [
                r'(?i)(synthetic|fabricated|fake).*?(data|example|sample)',
                r'(?i)(poison|contaminate|corrupt).*?(training|model)',
                r'(?i)(backdoor|trigger).*?(pattern|sequence)',
                r'(?i)(adversarial|malicious).*?(input|example)',
            ],
            PatternSeverity.MEDIUM: [
                r'(?i)(statistical|anomaly|outlier).*?(detection|pattern)',
                r'(?i)(distribution|frequency).*?(manipulation|alteration)',
                r'(?i)(bias|skew).*?(injection|introduction)',
            ],
        }
        
        # LLM04: Model Denial of Service
        self.dos_patterns = {
            PatternSeverity.CRITICAL: [
                r'(?i)(repeat|loop|recursive).*?(infinite|forever|endless)',
                r'(?i)(while|for).*?(true|1=1|always)',
                r'(?i)(recursion|recursive).*?(depth|limit|stack)',
                r'(?i)(token|context).*?(exhaust|overflow|max)',
            ],
            PatternSeverity.HIGH: [
                r'(?i)(generate|create).*?(\d+|many|lot).*?(times|iterations)',
                r'(?i)(very|extremely|super).*?(long|large|huge).*?(response|output)',
                r'(?i)(maximum|unlimited).*?(length|size|tokens)',
            ],
        }
        
        # LLM05: Supply Chain Vulnerabilities
        self.supply_chain_patterns = {
            PatternSeverity.HIGH: [
                r'(?i)(malicious|evil|bad).*?(plugin|extension|tool)',
                r'(?i)(compromised|backdoored).*?(dependency|library)',
                r'(?i)(template|prompt).*?(injection|override)',
                r'(?i)(untrusted|unknown).*?(source|origin)',
            ],
            PatternSeverity.MEDIUM: [
                r'(?i)(version|update).*?(vulnerable|exploit)',
                r'(?i)(package|module).*?(tampered|modified)',
                r'(?i)(supply|dependency).*?(chain|attack)',
            ],
        }
        
        # LLM06: Sensitive Information Disclosure
        self.sensitive_info_patterns = {
            PatternSeverity.CRITICAL: [
                # PII Patterns
                r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit Card
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
                r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',  # IP Address
                # API Keys
                r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?[A-Za-z0-9_-]{20,}["\']?',
                r'(?i)(secret[_-]?key|secretkey)\s*[:=]\s*["\']?[A-Za-z0-9_-]{20,}["\']?',
                r'(?i)(access[_-]?token|accesstoken)\s*[:=]\s*["\']?[A-Za-z0-9._-]{20,}["\']?',
                # Password patterns
                r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?[^\s"\']{6,}["\']?',
            ],
            PatternSeverity.HIGH: [
                # Medical/Healthcare
                r'(?i)(patient|medical|health).*?(record|file|history)',
                r'(?i)(diagnosis|condition|treatment).*?(ICD-10|code)',
                r'(?i)(HIPAA|PHI|protected.*?health.*?information)',
                # Financial
                r'(?i)(account|routing|swift).*?(number|code)',
                r'(?i)(balance|transaction|deposit).*?(amount|total)',
                r'(?i)(SSN|social.*?security|tax.*?id)',
            ],
            PatternSeverity.MEDIUM: [
                # General sensitive info
                r'(?i)(confidential|internal|private).*?(document|file|data)',
                r'(?i)(employee|staff|personnel).*?(information|details)',
                r'(?i)(customer|client).*?(database|records)',
            ],
        }
        
        # LLM07: Insecure Plugin Design
        self.insecure_plugin_patterns = {
            PatternSeverity.HIGH: [
                r'(?i)(unauthorized|forbidden).*?(tool|function|plugin)',
                r'(?i)(bypass|override).*?(permission|access.*?control)',
                r'(?i)(admin|root|superuser).*?(privilege|access)',
                r'(?i)(escalate|elevate).*?(permission|privilege)',
            ],
            PatternSeverity.MEDIUM: [
                r'(?i)(tool|function|plugin).*?(parameter|argument).*?(manipulation|injection)',
                r'(?i)(unsafe|dangerous).*?(operation|action)',
                r'(?i)(system|critical).*?(function|method)',
            ],
        }
        
        # LLM08: Excessive Agency
        self.excessive_agency_patterns = {
            PatternSeverity.HIGH: [
                r'(?i)(delete|remove|erase).*?(all|every).*?(data|file|record)',
                r'(?i)(shutdown|stop|terminate).*?(system|service|process)',
                r'(?i)(modify|change|alter).*?(system.*?config|critical.*?setting)',
                r'(?i)(access|connect|communicate).*?(external|third.*?party)',
            ],
            PatternSeverity.MEDIUM: [
                r'(?i)(scope|beyond|outside).*?(authority|permission)',
                r'(?i)(unauthorized|not.*?allowed).*?(action|operation)',
                r'(?i)(auto|automatic).*?(decision|action).*?(without.*?human)',
            ],
        }
        
        # LLM09: Overreliance
        self.overreliance_patterns = {
            PatternSeverity.MEDIUM: [
                r'(?i)(conflicting|contradictory).*?(information|data)',
                r'(?i)(false|incorrect|wrong).*?(premise|assumption)',
                r'(?i)(hallucination|fabrication).*?(detect|identify)',
                r'(?i)(verify|confirm).*?(accuracy|correctness)',
            ],
            PatternSeverity.LOW: [
                r'(?i)(double.*?check|cross.*?verify|validate)',
                r'(?i)(uncertain|unsure|doubt).*?(about|regarding)',
                r'(?i)(source|origin).*?(verification|validation)',
            ],
        }
        
        # LLM10: Model Theft
        self.model_theft_patterns = {
            PatternSeverity.CRITICAL: [
                r'(?i)(extract|download|copy).*?(model|weights|parameters)',
                r'(?i)(training|train).*?(data|dataset).*?(examples|samples)',
                r'(?i)(system.*?prompt|instruction).*?(reveal|show|display)',
                r'(?i)(architecture|structure).*?(of.*?model|neural.*?network)',
            ],
            PatternSeverity.HIGH: [
                r'(?i)(parameters|weights).*?(count|number|size)',
                r'(?i)(model.*?size|dimension|embedding).*?(details|info)',
                r'(?i)(prompt.*?template|system.*?message).*?(format|structure)',
                r'(?i)(training.*?process|methodology).*?(details|steps)',
            ],
            PatternSeverity.MEDIUM: [
                r'(?i)(internal|hidden).*?(state|representation)',
                r'(?i)(model.*?behavior|response).*?(pattern|tendency)',
                r'(?i)(knowledge.*?base|information).*?(source|origin)',
            ],
        }
        
        # Social Engineering Patterns
        self.social_engineering_patterns = {
            PatternSeverity.HIGH: [
                r'(?i)(urgent|emergency|critical).*?(situation|matter|issue)',
                r'(?i)(manager|supervisor|boss|ceo|cfo).*?(authorized|approved)',
                r'(?i)(fraud.*?department|security.*?team|investigation)',
                r'(?i)(legal.*?required|court.*?order|subpoena)',
            ],
            PatternSeverity.MEDIUM: [
                r'(?i)(help.*?me|assist.*?me|support.*?needed)',
                r'(?i)(special.*?access|temporary.*?permission)',
                r'(?i)(override.*?procedure|emergency.*?protocol)',
            ],
        }
        
        # Compile all patterns for performance
        self._compiled_patterns = {}
        self._compile_all_patterns()
    
    def _compile_all_patterns(self):
        """Pre-compile all regex patterns for performance"""
        pattern_categories = [
            ("prompt_injection", self.prompt_injection_patterns),
            ("insecure_output", self.insecure_output_patterns),
            ("data_poisoning", self.data_poisoning_patterns),
            ("dos", self.dos_patterns),
            ("supply_chain", self.supply_chain_patterns),
            ("sensitive_info", self.sensitive_info_patterns),
            ("insecure_plugin", self.insecure_plugin_patterns),
            ("excessive_agency", self.excessive_agency_patterns),
            ("overreliance", self.overreliance_patterns),
            ("model_theft", self.model_theft_patterns),
            ("social_engineering", self.social_engineering_patterns),
        ]
        
        for category, patterns in pattern_categories:
            self._compiled_patterns[category] = {}
            for severity, pattern_list in patterns.items():
                compiled = []
                for pattern in pattern_list:
                    try:
                        compiled.append(re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL))
                    except re.error as e:
                        logger.warning(f"Failed to compile pattern '{pattern}': {e}")
                self._compiled_patterns[category][severity] = compiled
    
    def check_patterns(self, text: str) -> List[PatternMatch]:
        """Check text against all threat patterns"""
        matches = []
        
        # Check each category
        for category, severities in self._compiled_patterns.items():
            for severity, compiled_patterns in severities.items():
                for pattern in compiled_patterns:
                    match = pattern.search(text)
                    if match:
                        matches.append(PatternMatch(
                            matched=True,
                            severity=severity,
                            category=category,
                            pattern=pattern.pattern,
                            matched_text=match.group(0),
                            confidence=self._calculate_confidence(severity, match.group(0)),
                            description=self._get_pattern_description(category, severity)
                        ))
        
        return matches
    
    def _calculate_confidence(self, severity: PatternSeverity, matched_text: str) -> float:
        """Calculate confidence score for pattern match"""
        base_confidence = {
            PatternSeverity.CRITICAL: 0.95,
            PatternSeverity.HIGH: 0.85,
            PatternSeverity.MEDIUM: 0.70,
            PatternSeverity.LOW: 0.55,
        }
        
        confidence = base_confidence[severity]
        
        # Boost confidence for longer, more specific matches
        if len(matched_text) > 50:
            confidence += 0.05
        elif len(matched_text) > 20:
            confidence += 0.02
        
        # Boost confidence for exact matches to known patterns
        if any(keyword in matched_text.lower() for keyword in 
               ['ignore instructions', 'system override', 'dan mode', 'jailbreak']):
            confidence += 0.03
        
        return min(confidence, 1.0)
    
    def _get_pattern_description(self, category: str, severity: PatternSeverity) -> str:
        """Get human-readable description for pattern"""
        descriptions = {
            "prompt_injection": {
                PatternSeverity.CRITICAL: "Direct instruction override or system bypass attempt",
                PatternSeverity.HIGH: "Indirect injection via document or context manipulation",
                PatternSeverity.MEDIUM: "Multi-language or encoded injection attempt",
            },
            "insecure_output": {
                PatternSeverity.CRITICAL: "XSS or script injection in output",
                PatternSeverity.HIGH: "SQL injection or command injection attempt",
                PatternSeverity.MEDIUM: "System command injection attempt",
            },
            "data_poisoning": {
                PatternSeverity.HIGH: "Training data poisoning or backdoor attempt",
                PatternSeverity.MEDIUM: "Statistical anomaly or adversarial input",
            },
            "dos": {
                PatternSeverity.CRITICAL: "Infinite loop or recursion attempt",
                PatternSeverity.HIGH: "Token exhaustion or resource abuse",
            },
            "supply_chain": {
                PatternSeverity.HIGH: "Malicious plugin or compromised dependency",
                PatternSeverity.MEDIUM: "Supply chain attack attempt",
            },
            "sensitive_info": {
                PatternSeverity.CRITICAL: "PII, API keys, or credential extraction attempt",
                PatternSeverity.HIGH: "Medical, financial, or confidential data access",
                PatternSeverity.MEDIUM: "General sensitive information request",
            },
            "insecure_plugin": {
                PatternSeverity.HIGH: "Unauthorized tool access or privilege escalation",
                PatternSeverity.MEDIUM: "Plugin parameter manipulation attempt",
            },
            "excessive_agency": {
                PatternSeverity.HIGH: "Unauthorized system modification or data deletion",
                PatternSeverity.MEDIUM: "Scope creep or permission abuse",
            },
            "overreliance": {
                PatternSeverity.MEDIUM: "Conflicting information or false premise injection",
                PatternSeverity.LOW: "Verification or validation request",
            },
            "model_theft": {
                PatternSeverity.CRITICAL: "Model extraction or training data theft",
                PatternSeverity.HIGH: "System prompt or architecture probing",
                PatternSeverity.MEDIUM: "Internal model behavior analysis",
            },
            "social_engineering": {
                PatternSeverity.HIGH: "Urgent request or authority impersonation",
                PatternSeverity.MEDIUM: "Help request or special access attempt",
            },
        }
        
        return descriptions.get(category, {}).get(severity, f"{category} - {severity} threat detected")
    
    def get_critical_matches(self, text: str) -> List[PatternMatch]:
        """Get only critical severity matches"""
        all_matches = self.check_patterns(text)
        return [match for match in all_matches if match.severity == PatternSeverity.CRITICAL]
    
    def get_high_severity_matches(self, text: str) -> List[PatternMatch]:
        """Get high and critical severity matches"""
        all_matches = self.check_patterns(text)
        return [match for match in all_matches 
                if match.severity in [PatternSeverity.CRITICAL, PatternSeverity.HIGH]]


class PatternDetector:
    """Main pattern detection interface"""
    
    def __init__(self):
        self.owasp_patterns = OWASPPatterns()
        self.cache = {}  # Simple in-memory cache
    
    def analyze(self, text: str, use_cache: bool = True) -> Dict:
        """Analyze text for threat patterns"""
        if use_cache and text in self.cache:
            return self.cache[text]
        
        # Get all pattern matches
        matches = self.owasp_patterns.check_patterns(text)
        
        # Calculate overall risk
        if not matches:
            result = {
                "threat_detected": False,
                "risk_score": 0.0,
                "risk_level": "SAFE",
                "matches": [],
                "categories": [],
                "processing_time_ms": 0.0,
            }
        else:
            # Find highest severity
            highest_severity = max(matches, key=lambda m: (
                0 if m.severity == PatternSeverity.LOW else
                1 if m.severity == PatternSeverity.MEDIUM else
                2 if m.severity == PatternSeverity.HIGH else
                3  # CRITICAL
            ))
            
            # Calculate risk score based on severity and confidence
            severity_scores = {
                PatternSeverity.LOW: 0.3,
                PatternSeverity.MEDIUM: 0.5,
                PatternSeverity.HIGH: 0.7,
                PatternSeverity.CRITICAL: 0.9,
            }
            
            base_score = severity_scores[highest_severity.severity]
            confidence = highest_severity.confidence
            risk_score = base_score * confidence
            
            # Determine risk level
            if risk_score >= 0.85:
                risk_level = "CRITICAL"
            elif risk_score >= 0.70:
                risk_level = "HIGH"
            elif risk_score >= 0.50:
                risk_level = "MEDIUM"
            elif risk_score >= 0.30:
                risk_level = "LOW"
            else:
                risk_level = "SAFE"
            
            result = {
                "threat_detected": True,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "matches": [
                    {
                        "category": match.category,
                        "severity": match.severity.value,
                        "pattern": match.pattern,
                        "matched_text": match.matched_text[:100],  # Truncate for logging
                        "confidence": match.confidence,
                        "description": match.description,
                    }
                    for match in matches
                ],
                "categories": list(set(match.category for match in matches)),
                "processing_time_ms": 0.0,  # Will be set by caller
            }
        
        # Cache result
        if use_cache and len(self.cache) < 10000:  # Limit cache size
            self.cache[text] = result
        
        return result
