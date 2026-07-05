from enum import Enum
from typing import Optional, Dict, Any, List

from pydantic import BaseModel, Field


class PermissionLevel(str, Enum):
    """Permission level for tool operations"""

    ALLOW = "allow"  # Always allow
    ASK = "ask"      # Ask user before executing
    DENY = "deny"    # Always deny


class PermissionScope(str, Enum):
    """Scope of a permission rule"""

    GLOBAL = "global"       # Applies to all files/operations
    DIRECTORY = "directory"  # Applies to specific directory
    FILE = "file"           # Applies to specific file
    PATTERN = "pattern"     # Applies to file pattern (glob)


class PermissionRule(BaseModel):
    """
    Permission rule definition.

    Rules are evaluated in order, and the first matching rule is applied.
    """

    permission: Optional[str] = None  # Permission category (read, edit, etc.)
    level: PermissionLevel = PermissionLevel.ASK
    scope: PermissionScope = PermissionScope.GLOBAL
    pattern: Optional[str] = None  # Glob pattern for PATTERN scope
    path: Optional[str] = None     # Path for DIRECTORY or FILE scope
    tools: List[str] = Field(default_factory=list)  # Specific tools, empty = all
    description: Optional[str] = None


class PermissionRequest(BaseModel):
    """Request for permission check"""

    tool: str
    path: Optional[str] = None
    operation: Optional[str] = None  # read, write, execute, etc.
    context: Dict[str, Any] = Field(default_factory=dict)


class PermissionResult(BaseModel):
    """Result of permission check"""

    allowed: bool
    level: PermissionLevel
    rule: Optional[PermissionRule] = None
    reason: Optional[str] = None
    requires_confirmation: bool = False
