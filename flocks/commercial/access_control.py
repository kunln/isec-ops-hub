"""Commercial access-control policy for local-admin deployments."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Callable

from fastapi import HTTPException, Request, status

from flocks.auth.context import AuthUser
from flocks.commercial import audit
from flocks.commercial.models import AuditStatus
from flocks.server.auth import get_optional_user, require_user


Capability = str


ROLE_CAPABILITIES: dict[str, set[Capability]] = {
    "admin": {"*"},
    "commercial_admin": {
        "commercial.admin",
        "commercial.audit.read",
        "security.ops.read",
        "security.ops.write",
        "security.ops.configure",
        "security.ops.notify",
        "security.connectors.test",
        "security.credentials.manage",
        "security.credentials.rotate",
        "security.schedules.manage",
        "security.events.ack",
        "security.bulk.manage",
        "security.admin",
        "system.config.read",
        "system.config.write",
        "system.logs.read",
        "channels.read",
        "channels.manage",
        "channels.send",
        "tools.read",
        "tools.manage",
        "models.read",
        "models.manage",
        "providers.read",
        "providers.manage",
    },
    "security_admin": {
        "security.ops.read",
        "security.ops.write",
        "security.ops.configure",
        "security.ops.notify",
        "security.connectors.test",
        "security.credentials.manage",
        "security.credentials.rotate",
        "security.schedules.manage",
        "security.events.ack",
        "security.bulk.manage",
        "security.admin",
        "devices.read",
        "devices.manage",
        "channels.read",
        "tools.read",
        "tools.execute",
        "workflows.read",
        "workflows.run",
    },
    "operator": {
        "ai.sessions",
        "ai.workspace",
        "tasks.read",
        "tasks.write",
        "agents.read",
        "workflows.read",
        "workflows.run",
        "skills.read",
        "tools.read",
        "tools.execute",
        "channels.read",
        "channels.send",
        "security.ops.read",
        "security.ops.write",
        "security.connectors.test",
        "security.events.ack",
        "devices.read",
        "hub.read",
        "models.read",
    },
    # Backward-compatible non-admin role used by existing local auth records.
    "member": {
        "ai.sessions",
        "ai.workspace",
        "tasks.read",
        "tasks.write",
        "agents.read",
        "workflows.read",
        "workflows.run",
        "skills.read",
        "tools.read",
        "tools.execute",
        "channels.read",
        "channels.send",
        "security.ops.read",
        "security.ops.write",
        "security.connectors.test",
        "security.events.ack",
        "devices.read",
        "hub.read",
        "models.read",
    },
    "viewer": {
        "ai.sessions",
        "ai.workspace",
        "tasks.read",
        "agents.read",
        "workflows.read",
        "skills.read",
        "tools.read",
        "channels.read",
        "security.ops.read",
        "devices.read",
        "hub.read",
        "models.read",
    },
}


UI_ROUTE_CAPABILITIES: dict[str, Capability] = {
    "/sessions": "ai.sessions",
    "/workspace": "ai.workspace",
    "/tasks": "tasks.read",
    "/agents": "agents.read",
    "/workflows/new": "workflows.write",
    "/workflows/create": "workflows.write",
    "/workflows": "workflows.read",
    "/skills": "skills.read",
    "/tools": "tools.read",
    "/devices": "devices.read",
    "/hub": "hub.read",
    "/models": "models.read",
    "/channels": "channels.manage",
    "/security-admin": "security.admin",
    "/security": "security.ops.read",
    "/config": "system.config.read",
    "/system-logs": "system.logs.read",
    "/permissions": "system.permissions.read",
    "/monitoring": "system.monitoring.read",
    "/admin": "commercial.admin",
}


def capability_for_api_request(path: str, method: str) -> Capability | None:
    method = method.upper()
    path = path.rstrip("/") or "/"
    if path.startswith("/api/commercial/access-control"):
        return None
    if path.startswith("/api/commercial/branding") and method == "GET":
        return None
    if path == "/api/commercial" or path.startswith("/api/commercial/"):
        if path.startswith("/api/commercial/audit"):
            return "commercial.audit.read"
        return "commercial.admin"

    if path.startswith("/api/config"):
        return "system.config.read" if method == "GET" else "system.config.write"
    if path.startswith("/api/logs"):
        return "system.logs.read"

    if path.startswith("/api/channel/") or path == "/api/channel":
        if path.endswith("/webhook"):
            return None
        if method == "GET":
            return "channels.read"
        if path.endswith("/send") or path.endswith("/session-send"):
            return "channels.send"
        return "channels.manage"

    if path.startswith("/api/security"):
        if method == "GET":
            return "security.ops.read"
        if path.startswith("/api/security/connectors/operations/settings"):
            return "security.ops.configure"
        if path == "/api/security/connectors/operations/events/ack" or path.endswith("/ack"):
            return "security.events.ack"
        if path.endswith("/notify"):
            return "security.ops.notify"
        if path.startswith("/api/security/connectors/credentials/expiry-monitor"):
            return "security.ops.configure"
        if path == "/api/security/connectors/credentials/bulk-remediation":
            return "security.bulk.manage"
        if path.endswith("/test") or path.endswith("/validate"):
            return "security.connectors.test"
        if "/credentials/profiles/" in path and path.endswith("/rotate"):
            return "security.credentials.rotate"
        if "/credentials" in path:
            return "security.credentials.manage"
        if (
            "/sync-schedules" in path
            or "/sync-runs" in path
            or "/sync-dead-letters" in path
            or "/sync-cursor" in path
            or path.endswith("/sync-schedule")
            or path.endswith("/sync")
            or path.endswith("/sync/cancel")
            or path.startswith("/api/security/connectors/scheduler")
        ):
            return "security.schedules.manage"
        return "security.ops.write"

    if path.startswith("/api/tools"):
        if method == "GET":
            return "tools.read"
        if path.endswith("/execute") or path.endswith("/test") or path.endswith("/batch"):
            return "tools.execute"
        return "tools.manage"

    if path.startswith("/api/workflow-center"):
        if method == "GET":
            return "workflows.read"
        if path.endswith("/invoke"):
            return "workflows.run"
        return "workflows.write"

    if path.startswith("/api/workflow"):
        if method == "GET":
            return "workflows.read"
        if path.endswith("/run") or "/run-node" in path:
            return "workflows.run"
        return "workflows.write"

    if path.startswith("/api/agent"):
        return "agents.read" if method == "GET" else "agents.write"
    if path.startswith("/api/skills"):
        return "skills.read" if method == "GET" else "skills.write"
    if path.startswith("/api/devices"):
        return "devices.read" if method == "GET" else "devices.manage"
    if path.startswith("/api/model") or path.startswith("/api/default-model"):
        return "models.read" if method == "GET" else "models.manage"
    if path.startswith("/api/provider") or path.startswith("/api/custom"):
        return "providers.read" if method == "GET" else "providers.manage"
    if path.startswith("/api/hub"):
        return "hub.read"
    if path.startswith("/api/permission"):
        return "system.permissions.read"
    return None


def capabilities_for_role(role: str | None) -> set[Capability]:
    if not role:
        return set()
    return set(ROLE_CAPABILITIES.get(role, set()))


def has_capability(user: AuthUser | None, capability: Capability) -> bool:
    if not user:
        return False
    capabilities = capabilities_for_role(user.role)
    return "*" in capabilities or capability in capabilities


def has_any_capability(user: AuthUser | None, capabilities: Iterable[Capability]) -> bool:
    return any(has_capability(user, capability) for capability in capabilities)


def capability_matrix() -> dict[str, list[Capability]]:
    return {
        role: sorted(capabilities)
        for role, capabilities in ROLE_CAPABILITIES.items()
    }


def ui_route_capabilities() -> dict[str, Capability]:
    return dict(UI_ROUTE_CAPABILITIES)


async def _record_denied(
    request: Request,
    *,
    action: str,
    target: str,
    capability: str,
) -> None:
    await audit.record_audit_event(
        action=action,
        target=target,
        status=AuditStatus.DENIED,
        actor=get_optional_user(request),
        request=request,
        summary=f"Missing capability: {capability}",
        metadata={"capability": capability},
    )


async def require_capability_for_request(
    request: Request,
    capability: Capability,
    *,
    action: str | None = None,
    target: str | None = None,
) -> AuthUser:
    user = require_user(request)
    if has_capability(user, capability):
        return user
    audit_action = action or "access_control.denied"
    audit_target = target or request.url.path
    await _record_denied(
        request,
        action=audit_action,
        target=audit_target,
        capability=capability,
    )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"缺少权限: {capability}",
    )


def require_capability(
    capability: Capability,
    *,
    action: str | None = None,
    target: str | None = None,
) -> Callable[[Request], object]:
    async def dependency(request: Request) -> AuthUser:
        return await require_capability_for_request(
            request,
            capability,
            action=action,
            target=target,
        )

    return dependency
