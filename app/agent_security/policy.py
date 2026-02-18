"""
Agent security policies and permission management
Defines what agents can and cannot do based on their roles and context
"""

from typing import Dict, List, Set, Optional, Any, Tuple
from enum import Enum
from dataclasses import dataclass
import json
import logging

logger = logging.getLogger(__name__)


class AgentRole(str, Enum):
    """Agent roles with different permission levels"""
    CUSTOMER_SERVICE = "customer_service"
    DATA_ANALYST = "data_analyst"
    CONTENT_CREATOR = "content_creator"
    RESEARCH_ASSISTANT = "research_assistant"
    ADMIN = "admin"
    DEVELOPER = "developer"
    SYSTEM = "system"


class PermissionLevel(str, Enum):
    """Permission levels for agent actions"""
    DENIED = "denied"
    READ_ONLY = "read_only"
    LIMITED = "limited"
    STANDARD = "standard"
    ELEVATED = "elevated"
    FULL = "full"


@dataclass
class ToolPermission:
    """Permission definition for a specific tool"""
    tool_name: str
    permission_level: PermissionLevel
    allowed_parameters: Set[str]
    denied_parameters: Set[str]
    max_frequency: int  # Maximum calls per minute
    requires_approval: bool
    audit_level: str  # NONE, BASIC, DETAILED


@dataclass
class DataPermission:
    """Permission definition for data access"""
    data_type: str
    permission_level: PermissionLevel
    max_records: int
    allowed_fields: Set[str]
    denied_fields: Set[str]
    requires_context: bool


class AgentSecurityPolicy:
    """Security policy manager for AI agents"""
    
    def __init__(self):
        self.role_policies = self._initialize_role_policies()
        self.tool_permissions = self._initialize_tool_permissions()
        self.data_permissions = self._initialize_data_permissions()
        self.goal_templates = self._initialize_goal_templates()
        
        logger.info("Agent security policies initialized")
    
    def _initialize_role_policies(self) -> Dict[AgentRole, Dict]:
        """Initialize security policies for each agent role"""
        return {
            AgentRole.CUSTOMER_SERVICE: {
                "description": "Customer service agent with limited data access",
                "max_session_duration": 3600,  # 1 hour
                "allowed_tools": {
                    "customer_lookup": PermissionLevel.STANDARD,
                    "order_status": PermissionLevel.STANDARD,
                    "faq_search": PermissionLevel.STANDARD,
                    "ticket_create": PermissionLevel.LIMITED,
                },
                "data_access": {
                    "customer_data": PermissionLevel.LIMITED,
                    "order_data": PermissionLevel.LIMITED,
                    "product_data": PermissionLevel.STANDARD,
                },
                "risk_threshold": 0.7,
                "requires_supervision": False,
            },
            
            AgentRole.DATA_ANALYST: {
                "description": "Data analysis agent with broader data access",
                "max_session_duration": 7200,  # 2 hours
                "allowed_tools": {
                    "database_query": PermissionLevel.STANDARD,
                    "data_export": PermissionLevel.LIMITED,
                    "analytics_engine": PermissionLevel.STANDARD,
                    "chart_generation": PermissionLevel.STANDARD,
                },
                "data_access": {
                    "analytics_data": PermissionLevel.STANDARD,
                    "customer_data": PermissionLevel.LIMITED,
                    "sales_data": PermissionLevel.STANDARD,
                    "operational_data": PermissionLevel.READ_ONLY,
                },
                "risk_threshold": 0.6,
                "requires_supervision": False,
            },
            
            AgentRole.CONTENT_CREATOR: {
                "description": "Content creation agent with creative tools",
                "max_session_duration": 5400,  # 1.5 hours
                "allowed_tools": {
                    "text_generation": PermissionLevel.STANDARD,
                    "image_generation": PermissionLevel.STANDARD,
                    "content_editor": PermissionLevel.STANDARD,
                    "publishing_tools": PermissionLevel.LIMITED,
                },
                "data_access": {
                    "content_library": PermissionLevel.STANDARD,
                    "media_assets": PermissionLevel.STANDARD,
                    "user_content": PermissionLevel.LIMITED,
                },
                "risk_threshold": 0.5,
                "requires_supervision": False,
            },
            
            AgentRole.RESEARCH_ASSISTANT: {
                "description": "Research assistant with information access",
                "max_session_duration": 10800,  # 3 hours
                "allowed_tools": {
                    "web_search": PermissionLevel.STANDARD,
                    "document_analysis": PermissionLevel.STANDARD,
                    "citation_manager": PermissionLevel.STANDARD,
                    "knowledge_base": PermissionLevel.STANDARD,
                },
                "data_access": {
                    "research_data": PermissionLevel.STANDARD,
                    "academic_papers": PermissionLevel.STANDARD,
                    "internal_documents": PermissionLevel.LIMITED,
                },
                "risk_threshold": 0.6,
                "requires_supervision": False,
            },
            
            AgentRole.ADMIN: {
                "description": "Administrative agent with elevated privileges",
                "max_session_duration": 1800,  # 30 minutes
                "allowed_tools": {
                    "user_management": PermissionLevel.ELEVATED,
                    "system_monitoring": PermissionLevel.STANDARD,
                    "security_tools": PermissionLevel.ELEVATED,
                    "backup_tools": PermissionLevel.STANDARD,
                },
                "data_access": {
                    "user_data": PermissionLevel.ELEVATED,
                    "system_data": PermissionLevel.STANDARD,
                    "security_logs": PermissionLevel.ELEVATED,
                },
                "risk_threshold": 0.4,
                "requires_supervision": True,
            },
            
            AgentRole.DEVELOPER: {
                "description": "Developer agent with system access",
                "max_session_duration": 3600,  # 1 hour
                "allowed_tools": {
                    "code_editor": PermissionLevel.STANDARD,
                    "deployment_tools": PermissionLevel.LIMITED,
                    "testing_tools": PermissionLevel.STANDARD,
                    "debug_tools": PermissionLevel.STANDARD,
                },
                "data_access": {
                    "source_code": PermissionLevel.STANDARD,
                    "build_artifacts": PermissionLevel.STANDARD,
                    "deployment_data": PermissionLevel.LIMITED,
                },
                "risk_threshold": 0.5,
                "requires_supervision": False,
            },
            
            AgentRole.SYSTEM: {
                "description": "System agent with full privileges",
                "max_session_duration": 43200,  # 12 hours
                "allowed_tools": {
                    "system_control": PermissionLevel.FULL,
                    "monitoring": PermissionLevel.FULL,
                    "maintenance": PermissionLevel.FULL,
                    "emergency": PermissionLevel.FULL,
                },
                "data_access": {
                    "all_data": PermissionLevel.FULL,
                },
                "risk_threshold": 0.3,
                "requires_supervision": False,
            },
        }
    
    def _initialize_tool_permissions(self) -> Dict[str, ToolPermission]:
        """Initialize detailed permissions for each tool"""
        return {
            "customer_lookup": ToolPermission(
                tool_name="customer_lookup",
                permission_level=PermissionLevel.STANDARD,
                allowed_parameters={"customer_id", "email", "phone"},
                denied_parameters={"ssn", "credit_card", "password"},
                max_frequency=30,
                requires_approval=False,
                audit_level="BASIC"
            ),
            
            "database_query": ToolPermission(
                tool_name="database_query",
                permission_level=PermissionLevel.STANDARD,
                allowed_parameters={"query", "limit", "offset"},
                denied_parameters={"drop", "delete", "truncate", "alter"},
                max_frequency=20,
                requires_approval=False,
                audit_level="DETAILED"
            ),
            
            "data_export": ToolPermission(
                tool_name="data_export",
                permission_level=PermissionLevel.LIMITED,
                allowed_parameters={"format", "fields", "limit"},
                denied_parameters={"all_fields", "sensitive_data"},
                max_frequency=5,
                requires_approval=True,
                audit_level="DETAILED"
            ),
            
            "user_management": ToolPermission(
                tool_name="user_management",
                permission_level=PermissionLevel.ELEVATED,
                allowed_parameters={"user_id", "action", "reason"},
                denied_parameters={"password_reset", "role_change", "account_delete"},
                max_frequency=10,
                requires_approval=True,
                audit_level="DETAILED"
            ),
            
            "system_control": ToolPermission(
                tool_name="system_control",
                permission_level=PermissionLevel.FULL,
                allowed_parameters={"action", "target", "parameters"},
                denied_parameters=set(),
                max_frequency=100,
                requires_approval=False,
                audit_level="DETAILED"
            ),
            
            "web_search": ToolPermission(
                tool_name="web_search",
                permission_level=PermissionLevel.STANDARD,
                allowed_parameters={"query", "limit", "source"},
                denied_parameters=set(),
                max_frequency=50,
                requires_approval=False,
                audit_level="BASIC"
            ),
            
            "file_access": ToolPermission(
                tool_name="file_access",
                permission_level=PermissionLevel.LIMITED,
                allowed_parameters={"path", "mode", "content"},
                denied_parameters={"/etc/", "/sys/", "/proc/", "system32"},
                max_frequency=15,
                requires_approval=True,
                audit_level="DETAILED"
            ),
            
            "api_call": ToolPermission(
                tool_name="api_call",
                permission_level=PermissionLevel.STANDARD,
                allowed_parameters={"endpoint", "method", "data"},
                denied_parameters={"internal_api", "admin_api"},
                max_frequency=40,
                requires_approval=False,
                audit_level="BASIC"
            ),
        }
    
    def _initialize_data_permissions(self) -> Dict[str, DataPermission]:
        """Initialize data access permissions"""
        return {
            "customer_data": DataPermission(
                data_type="customer_data",
                permission_level=PermissionLevel.LIMITED,
                max_records=100,
                allowed_fields={"name", "email", "phone", "order_history"},
                denied_fields={"ssn", "credit_card", "password", "api_keys"},
                requires_context=True
            ),
            
            "analytics_data": DataPermission(
                data_type="analytics_data",
                permission_level=PermissionLevel.STANDARD,
                max_records=10000,
                allowed_fields={"metrics", "dimensions", "timestamps"},
                denied_fields={"user_ids", "personal_data"},
                requires_context=False
            ),
            
            "system_data": DataPermission(
                data_type="system_data",
                permission_level=PermissionLevel.STANDARD,
                max_records=1000,
                allowed_fields={"logs", "metrics", "status"},
                denied_fields={"credentials", "keys", "secrets"},
                requires_context=True
            ),
            
            "sensitive_data": DataPermission(
                data_type="sensitive_data",
                permission_level=PermissionLevel.DENIED,
                max_records=0,
                allowed_fields=set(),
                denied_fields={"all"},
                requires_context=True
            ),
        }
    
    def _initialize_goal_templates(self) -> Dict[str, Dict]:
        """Initialize allowed goal templates for each role"""
        return {
            AgentRole.CUSTOMER_SERVICE: {
                "allowed_patterns": [
                    "help customer with {task}",
                    "assist with {inquiry_type}",
                    "resolve {issue_type}",
                    "provide information about {topic}"
                ],
                "forbidden_patterns": [
                    "access all customer data",
                    "modify customer accounts",
                    "delete records",
                    "export sensitive information"
                ]
            },
            
            AgentRole.DATA_ANALYST: {
                "allowed_patterns": [
                    "analyze {data_type}",
                    "generate report on {topic}",
                    "query {database} for {purpose}",
                    "create visualization of {data}"
                ],
                "forbidden_patterns": [
                    "export all user data",
                    "access personal information",
                    "modify database records",
                    "share confidential data"
                ]
            },
            
            AgentRole.ADMIN: {
                "allowed_patterns": [
                    "manage {resource_type}",
                    "monitor system {component}",
                    "perform maintenance on {system}",
                    "handle security {task}"
                ],
                "forbidden_patterns": [
                    "delete all data",
                    "disable security",
                    "grant unlimited access",
                    "export system credentials"
                ]
            }
        }
    
    def get_role_policy(self, role: AgentRole) -> Dict:
        """Get security policy for a specific role"""
        return self.role_policies.get(role, {})
    
    def get_tool_permission(self, tool_name: str, role: AgentRole) -> Optional[ToolPermission]:
        """Get permission for a specific tool and role"""
        role_policy = self.role_policies.get(role, {})
        allowed_tools = role_policy.get("allowed_tools", {})
        
        if tool_name not in allowed_tools:
            return None
        
        permission_level = allowed_tools[tool_name]
        tool_permission = self.tool_permissions.get(tool_name)
        
        if tool_permission and tool_permission.permission_level == permission_level:
            return tool_permission
        
        return None
    
    def get_data_permission(self, data_type: str, role: AgentRole) -> Optional[DataPermission]:
        """Get data access permission for role"""
        role_policy = self.role_policies.get(role, {})
        data_access = role_policy.get("data_access", {})
        
        if data_type not in data_access:
            return None
        
        permission_level = data_access[data_type]
        data_permission = self.data_permissions.get(data_type)
        
        if data_permission and data_permission.permission_level == permission_level:
            return data_permission
        
        return None
    
    def validate_goal(self, goal: str, role: AgentRole) -> Tuple[bool, List[str]]:
        """Validate if goal is allowed for role"""
        goal_lower = goal.lower()
        role_templates = self.goal_templates.get(role, {})
        
        # Check forbidden patterns
        forbidden_patterns = role_templates.get("forbidden_patterns", [])
        for pattern in forbidden_patterns:
            if pattern.replace("{", "").replace("}", "") in goal_lower:
                return False, [f"Goal matches forbidden pattern: {pattern}"]
        
        # Check allowed patterns
        allowed_patterns = role_templates.get("allowed_patterns", [])
        for pattern in allowed_patterns:
            pattern_core = pattern.replace("{", "").replace("}", "")
            if pattern_core in goal_lower:
                return True, []
        
        # If no patterns match, apply default validation
        if not allowed_patterns:
            return True, []  # No restrictions if no patterns defined
        
        return False, ["Goal does not match any allowed patterns"]
    
    def check_tool_access(self, tool_name: str, parameters: Dict, role: AgentRole) -> Tuple[bool, str]:
        """Check if agent can access tool with given parameters"""
        tool_permission = self.get_tool_permission(tool_name, role)
        
        if not tool_permission:
            return False, f"Tool {tool_name} not allowed for role {role}"
        
        # Check denied parameters
        for param in parameters:
            if param in tool_permission.denied_parameters:
                return False, f"Parameter {param} is not allowed for tool {tool_name}"
        
        # Check required approval
        if tool_permission.requires_approval:
            return False, f"Tool {tool_name} requires approval"
        
        return True, "Access granted"
    
    def check_data_access(self, data_type: str, fields: List[str], record_count: int, role: AgentRole) -> Tuple[bool, str]:
        """Check if agent can access requested data"""
        data_permission = self.get_data_permission(data_type, role)
        
        if not data_permission:
            return False, f"Data type {data_type} not allowed for role {role}"
        
        # Check record count limit
        if record_count > data_permission.max_records:
            return False, f"Record count {record_count} exceeds limit {data_permission.max_records}"
        
        # Check denied fields
        for field in fields:
            if field in data_permission.denied_fields:
                return False, f"Field {field} is not allowed for data type {data_type}"
        
        return True, "Access granted"
    
    def get_risk_threshold(self, role: AgentRole) -> float:
        """Get risk threshold for role"""
        role_policy = self.role_policies.get(role, {})
        return role_policy.get("risk_threshold", 0.5)
    
    def requires_supervision(self, role: AgentRole) -> bool:
        """Check if role requires supervision"""
        role_policy = self.role_policies.get(role, {})
        return role_policy.get("requires_supervision", False)
    
    def get_max_session_duration(self, role: AgentRole) -> int:
        """Get maximum session duration for role"""
        role_policy = self.role_policies.get(role, {})
        return role_policy.get("max_session_duration", 3600)
    
    def export_policy(self, role: AgentRole = None) -> Dict:
        """Export security policy (for compliance and auditing)"""
        if role:
            return {
                "role": role,
                "policy": self.role_policies.get(role, {}),
                "tool_permissions": {
                    name: perm.__dict__ for name, perm in self.tool_permissions.items()
                    if name in self.role_policies.get(role, {}).get("allowed_tools", {})
                },
                "data_permissions": {
                    name: perm.__dict__ for name, perm in self.data_permissions.items()
                    if name in self.role_policies.get(role, {}).get("data_access", {})
                }
            }
        else:
            return {
                "all_policies": self.role_policies,
                "tool_permissions": {
                    name: perm.__dict__ for name, perm in self.tool_permissions.items()
                },
                "data_permissions": {
                    name: perm.__dict__ for name, perm in self.data_permissions.items()
                },
                "goal_templates": self.goal_templates
            }


# Global policy instance
agent_policy = AgentSecurityPolicy()
