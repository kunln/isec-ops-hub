"""Commercial policy checks for outbound, notifications, and updates."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from urllib.parse import urlparse

from flocks.commercial import features as commercial_features
from flocks.commercial.models import (
    ConnectivityConfig,
    NotificationPolicy,
    NotificationPolicyUpdate,
    UpdatePolicy,
)
from flocks.commercial.store import default_store


class CommercialPolicyError(PermissionError):
    """Raised when a commercial policy blocks an operation."""


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str | None = None


_LOCAL_HOSTS = {"localhost", "ip6-localhost", "0.0.0.0"}


async def get_connectivity_policy() -> ConnectivityConfig:
    return await default_store.get_connectivity()


async def get_notification_policy() -> NotificationPolicy:
    return await default_store.get_notification_policy()


async def update_notification_policy(payload: NotificationPolicyUpdate) -> NotificationPolicy:
    return await default_store.update_notification_policy(payload)


async def get_update_policy() -> UpdatePolicy:
    return await default_store.get_update_policy()


def _normalize_host(value: str | None) -> str:
    return (value or "").strip().lower().rstrip(".")


def _commercial_storage_ready() -> bool:
    try:
        from flocks.storage.storage import Storage

        return bool(getattr(Storage, "_initialized", False))
    except Exception:
        return False


def is_local_url(url: str | None) -> bool:
    if not url:
        return False
    parsed = urlparse(url)
    host = _normalize_host(parsed.hostname)
    if not host:
        return False
    if host in _LOCAL_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def is_private_network_url(url: str | None) -> bool:
    if not url:
        return False
    parsed = urlparse(url)
    host = _normalize_host(parsed.hostname)
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_private or address.is_link_local


def _host_matches_rule(host: str, rule: str) -> bool:
    normalized_host = _normalize_host(host)
    normalized_rule = _normalize_host(rule)
    if not normalized_host or not normalized_rule:
        return False
    if normalized_rule == "*":
        return True
    if normalized_rule.startswith("*."):
        suffix = normalized_rule[1:]
        return normalized_host.endswith(suffix) and normalized_host != normalized_rule[2:]
    return normalized_host == normalized_rule


def is_host_allowed(connectivity: ConnectivityConfig, url: str | None) -> bool:
    if is_local_url(url):
        return True
    if not url or not connectivity.allowed_hosts:
        return True
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return False
    return any(_host_matches_rule(host, rule) for rule in connectivity.allowed_hosts)


async def is_commercial_connectivity_enforced() -> bool:
    """Return true only when licensed commercial connectivity policy should apply.

    Community/unlicensed deployments keep development outbound access open.
    The commercial outbound allowlist/deny policy is enforced only when the
    current active license explicitly enables the connectivity feature.
    """
    return await commercial_features.is_feature_enabled(commercial_features.FEATURE_CONNECTIVITY)


async def decide_outbound_allowed(
    *,
    url: str | None = None,
    purpose: str = "outbound",
    require_initialized: bool = True,
    require_url_for_allowed_hosts: bool = False,
    allow_private_network: bool = False,
) -> PolicyDecision:
    if not require_initialized and not _commercial_storage_ready():
        return PolicyDecision(True)
    if is_local_url(url):
        return PolicyDecision(True)
    if allow_private_network and is_private_network_url(url):
        return PolicyDecision(True)
    if not await is_commercial_connectivity_enforced():
        return PolicyDecision(True)
    connectivity = await get_connectivity_policy()
    if not connectivity.outbound_enabled:
        return PolicyDecision(False, f"{purpose} is disabled by commercial connectivity policy")
    if require_url_for_allowed_hosts and connectivity.allowed_hosts and not url:
        return PolicyDecision(False, f"{purpose} target host cannot be verified against commercial allowed_hosts")
    if not is_host_allowed(connectivity, url):
        return PolicyDecision(False, f"{purpose} host is not in commercial allowed_hosts")
    return PolicyDecision(True)


async def ensure_outbound_allowed(
    *,
    url: str | None = None,
    purpose: str = "outbound",
    require_initialized: bool = True,
    require_url_for_allowed_hosts: bool = False,
    allow_private_network: bool = False,
) -> None:
    decision = await decide_outbound_allowed(
        url=url,
        purpose=purpose,
        require_initialized=require_initialized,
        require_url_for_allowed_hosts=require_url_for_allowed_hosts,
        allow_private_network=allow_private_network,
    )
    if not decision.allowed:
        await record_outbound_denial(url=url, purpose=purpose, reason=decision.reason)
        raise CommercialPolicyError(decision.reason or "Outbound connectivity is disabled")


async def record_outbound_denial(
    *,
    url: str | None,
    purpose: str,
    reason: str | None,
) -> None:
    if not _commercial_storage_ready():
        return
    try:
        from flocks.commercial import audit

        await audit.record_audit_event(
            action="commercial.outbound.denied",
            target=url or purpose,
            status="denied",
            summary=reason,
            metadata={
                "purpose": purpose,
                "url": url,
            },
        )
    except Exception:
        pass


async def decide_update_check_allowed() -> PolicyDecision:
    update_policy = await get_update_policy()
    if not update_policy.update_check_enabled:
        return PolicyDecision(False, "Update checks are disabled by commercial update policy")
    if not update_policy.legacy_flocks_update_sources_enabled:
        return PolicyDecision(False, "Legacy Flocks update sources are disabled by commercial update policy")
    outbound = await decide_outbound_allowed(purpose="update check")
    if not outbound.allowed:
        return outbound
    return PolicyDecision(True)


async def decide_update_apply_allowed() -> PolicyDecision:
    update_policy = await get_update_policy()
    if not update_policy.update_apply_enabled:
        return PolicyDecision(False, "Applying updates is disabled by commercial update policy")
    if not update_policy.legacy_flocks_update_sources_enabled:
        return PolicyDecision(False, "Legacy Flocks update sources are disabled by commercial update policy")
    outbound = await decide_outbound_allowed(purpose="update download")
    if not outbound.allowed:
        return outbound
    return PolicyDecision(True)


async def ensure_update_check_allowed() -> None:
    decision = await decide_update_check_allowed()
    if not decision.allowed:
        raise CommercialPolicyError(decision.reason or "Update checks are disabled")


async def ensure_update_apply_allowed() -> None:
    decision = await decide_update_apply_allowed()
    if not decision.allowed:
        raise CommercialPolicyError(decision.reason or "Applying updates is disabled")
