"""Commercial local-admin audit helpers."""

from __future__ import annotations

from typing import Any

from flocks.auth.context import AuthUser
from flocks.commercial.models import AuditStatus, CommercialAuditEvent
from flocks.commercial.store import default_store


def _request_ip(request: Any) -> str | None:
    client = getattr(request, "client", None)
    return getattr(client, "host", None) if client else None


def _user_agent(request: Any) -> str | None:
    headers = getattr(request, "headers", None)
    return headers.get("user-agent") if headers is not None else None


async def record_audit_event(
    *,
    action: str,
    target: str,
    status: AuditStatus | str = AuditStatus.SUCCESS,
    actor: AuthUser | None = None,
    request: Any = None,
    summary: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> CommercialAuditEvent:
    return await default_store.record_audit_event(
        CommercialAuditEvent(
            action=action,
            target=target,
            status=status,
            actor_id=actor.id if actor else None,
            actor_username=actor.username if actor else None,
            actor_role=actor.role if actor else None,
            request_ip=_request_ip(request) if request else None,
            user_agent=_user_agent(request) if request else None,
            summary=summary,
            metadata=metadata or {},
        )
    )


async def list_audit_events(limit: int = 100) -> list[CommercialAuditEvent]:
    return await default_store.list_audit_events(limit=limit)
