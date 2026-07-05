from typing import Optional, Dict, Any, List, Set

from flocks.utils.log import Log
from flocks.permission.rule import (
    PermissionLevel,
    PermissionScope,
    PermissionRule,
    PermissionRequest,
    PermissionResult,
)

log = Log.create(service="permission")


class PermissionManager:
    """
    Permission management for agent operations.

    Manages permission rules and checks for tool execution.
    """

    def __init__(self):
        self._rules: List[PermissionRule] = []
        self._auto_approved: Set[str] = set()  # Tool+path combinations auto-approved
        self._denied: Set[str] = set()  # Tool+path combinations denied

    def add_rule(self, rule: PermissionRule) -> None:
        """Add a permission rule."""
        self._rules.append(rule)
        log.info("permission.rule_added", {
            "level": rule.level.value,
            "scope": rule.scope.value,
        })

    def remove_rule(self, index: int) -> bool:
        """Remove a rule by index."""
        if 0 <= index < len(self._rules):
            self._rules.pop(index)
            return True
        return False

    def clear_rules(self) -> None:
        """Clear all rules."""
        self._rules.clear()
        self._auto_approved.clear()
        self._denied.clear()

    def get_rules(self) -> List[PermissionRule]:
        """Get all rules."""
        return self._rules.copy()

    def check(self, request: PermissionRequest) -> PermissionResult:
        """Check permission for a request."""
        key = self._make_key(request.tool, request.path)

        if key in self._denied:
            return PermissionResult(
                allowed=False,
                level=PermissionLevel.DENY,
                reason="Previously denied",
            )

        if key in self._auto_approved:
            return PermissionResult(
                allowed=True,
                level=PermissionLevel.ALLOW,
                reason="Previously approved",
            )

        for rule in self._rules:
            if self._rule_matches(rule, request):
                if rule.level == PermissionLevel.ALLOW:
                    return PermissionResult(
                        allowed=True,
                        level=PermissionLevel.ALLOW,
                        rule=rule,
                        reason="Allowed by rule",
                    )
                if rule.level == PermissionLevel.DENY:
                    return PermissionResult(
                        allowed=False,
                        level=PermissionLevel.DENY,
                        rule=rule,
                        reason="Denied by rule",
                    )
                return PermissionResult(
                    allowed=False,
                    level=PermissionLevel.ASK,
                    rule=rule,
                    reason="Requires user confirmation",
                    requires_confirmation=True,
                )

        return PermissionResult(
            allowed=False,
            level=PermissionLevel.ASK,
            reason="No matching rule, requires confirmation",
            requires_confirmation=True,
        )

    def approve(self, request: PermissionRequest, remember: bool = False) -> None:
        """Approve a permission request."""
        key = self._make_key(request.tool, request.path)

        if remember:
            self._auto_approved.add(key)
            self._denied.discard(key)

        log.info("permission.approved", {
            "tool": request.tool,
            "path": request.path,
            "remember": remember,
        })

    def deny(self, request: PermissionRequest, remember: bool = False) -> None:
        """Deny a permission request."""
        key = self._make_key(request.tool, request.path)

        if remember:
            self._denied.add(key)
            self._auto_approved.discard(key)

        log.info("permission.denied", {
            "tool": request.tool,
            "path": request.path,
            "remember": remember,
        })

    def _make_key(self, tool: str, path: Optional[str]) -> str:
        """Generate cache key."""
        if path:
            return f"{tool}:{path}"
        return tool

    def _rule_matches(self, rule: PermissionRule, request: PermissionRequest) -> bool:
        """Check if a rule matches a request."""
        if rule.tools and request.tool not in rule.tools:
            return False

        if rule.scope == PermissionScope.GLOBAL:
            return True

        if not request.path:
            return False

        if rule.scope == PermissionScope.FILE:
            return rule.path == request.path

        if rule.scope == PermissionScope.DIRECTORY:
            if rule.path:
                return request.path.startswith(rule.path.rstrip("/") + "/")
            return False

        if rule.scope == PermissionScope.PATTERN:
            if rule.pattern:
                import fnmatch
                return fnmatch.fnmatch(request.path, rule.pattern)
            return False

        return False


class Permission:
    """
    Permission namespace for agent operations.

    Provides a high-level interface for permission checking.
    """

    _manager: Optional[PermissionManager] = None

    DEFAULT_RULES: List[Dict[str, Any]] = [
        {
            "level": "allow",
            "scope": "global",
            "tools": ["read_file", "list_directory", "search_files"],
            "description": "Allow read operations",
        },
        {
            "level": "ask",
            "scope": "global",
            "tools": ["write_file", "edit_file", "delete_file", "create_file"],
            "description": "Confirm write operations",
        },
        {
            "level": "deny",
            "scope": "pattern",
            "pattern": "**/.env*",
            "tools": ["write_file", "edit_file"],
            "description": "Protect environment files",
        },
        {
            "level": "deny",
            "scope": "pattern",
            "pattern": "**/*.key",
            "tools": ["write_file", "edit_file", "read_file"],
            "description": "Protect key files",
        },
        {
            "level": "ask",
            "scope": "global",
            "tools": ["execute_command", "run_shell", "terminal"],
            "description": "Confirm command execution",
        },
    ]

    @classmethod
    def get_manager(cls) -> PermissionManager:
        """Get the permission manager instance."""
        if cls._manager is None:
            cls._manager = PermissionManager()
            cls._load_default_rules()
        return cls._manager

    @classmethod
    def _load_default_rules(cls) -> None:
        """Load default permission rules."""
        manager = cls._manager
        if not manager:
            return

        for rule_data in cls.DEFAULT_RULES:
            rule = PermissionRule(
                level=PermissionLevel(rule_data["level"]),
                scope=PermissionScope(rule_data.get("scope", "global")),
                pattern=rule_data.get("pattern"),
                path=rule_data.get("path"),
                tools=rule_data.get("tools", []),
                description=rule_data.get("description"),
            )
            manager.add_rule(rule)

    @classmethod
    def check(cls, tool: str, path: Optional[str] = None, **kwargs) -> PermissionResult:
        """Check permission for a tool operation."""
        manager = cls.get_manager()
        request = PermissionRequest(tool=tool, path=path, context=kwargs)
        return manager.check(request)

    @classmethod
    def approve(cls, tool: str, path: Optional[str] = None, remember: bool = False) -> None:
        """Approve a tool operation."""
        manager = cls.get_manager()
        request = PermissionRequest(tool=tool, path=path)
        manager.approve(request, remember)

    @classmethod
    def deny(cls, tool: str, path: Optional[str] = None, remember: bool = False) -> None:
        """Deny a tool operation."""
        manager = cls.get_manager()
        request = PermissionRequest(tool=tool, path=path)
        manager.deny(request, remember)

    @classmethod
    def add_rule(cls, rule: PermissionRule) -> None:
        """Add a permission rule."""
        manager = cls.get_manager()
        manager.add_rule(rule)

    @classmethod
    def get_rules(cls) -> List[PermissionRule]:
        """Get all permission rules."""
        manager = cls.get_manager()
        return manager.get_rules()

    @classmethod
    def reset(cls) -> None:
        """Reset permission manager to defaults."""
        cls._manager = None
