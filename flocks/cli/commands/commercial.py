"""Commercial local administration commands."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Optional
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.table import Table

from flocks.commercial.features import get_feature_state
from flocks.commercial.license import import_license
from flocks.commercial.models import (
    AuditStatus,
    CommercialAuditEvent,
    ConnectivityConfig,
    ConnectivityUpdate,
    LicenseImportRequest,
    LicenseInfo,
)
from flocks.commercial.store import default_store
from flocks.storage.storage import Storage

commercial_app = typer.Typer(help="Commercial local administration commands")
console = Console()


def _default_temp_license_id() -> str:
    return f"TEMP-COMMERCIAL-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"


def _normalize_host(value: str) -> str:
    text = value.strip()
    if not text:
        raise ValueError("host cannot be empty")

    if text.startswith("*."):
        return f"*.{text[2:].split('/', 1)[0].split(':', 1)[0].strip().lower().rstrip('.')}"

    parsed = urlparse(text if "://" in text else f"//{text.split('/', 1)[0]}")
    host = parsed.hostname or text.split("/", 1)[0].split(":", 1)[0]
    normalized = host.strip().lower().rstrip(".")
    if not normalized:
        raise ValueError(f"invalid host: {value!r}")
    return normalized


async def issue_temp_license_local(
    *,
    days: int = 30,
    licensed_to: str = "Local Commercial Evaluation",
    license_id: str | None = None,
    features: list[str] | None = None,
) -> LicenseInfo:
    """Create a local-only temporary commercial license in the active Storage."""
    if days < 1:
        raise ValueError("days must be >= 1")

    await Storage.init()
    try:
        now = datetime.now(UTC)
        manifest = {
            "status": "active",
            "edition": "commercial",
            "licensed_to": licensed_to,
            "license_id": license_id or _default_temp_license_id(),
            "expires_at": (now + timedelta(days=days)).isoformat(),
            "features": features or ["*"],
            "source": "local_temp_cli",
            "message": "Local temporary commercial license for evaluation and delivery validation.",
        }
        license_info = await import_license(LicenseImportRequest(manifest=manifest))
        await default_store.record_audit_event(
            CommercialAuditEvent(
                action="commercial.license.issue_temp",
                target=license_info.license_id or "local-temp-license",
                status=AuditStatus.SUCCESS,
                actor_username="local-cli",
                actor_role="operator",
                summary="Issued local temporary commercial license",
                metadata={"days": days, "licensed_to": licensed_to},
            )
        )
        return license_info
    finally:
        await Storage.shutdown()


async def allow_host_local(
    host: str,
    *,
    enable_outbound: bool = True,
) -> ConnectivityConfig:
    """Add one host to the commercial outbound allowlist in the active Storage."""
    normalized_host = _normalize_host(host)

    await Storage.init()
    try:
        current = await default_store.get_connectivity()
        allowed_hosts = list(current.allowed_hosts)
        if normalized_host not in allowed_hosts:
            allowed_hosts.append(normalized_host)
        allowed_hosts.sort()

        updated = await default_store.update_connectivity(
            ConnectivityUpdate(
                outbound_enabled=True if enable_outbound else current.outbound_enabled,
                allowed_hosts=allowed_hosts,
            )
        )
        await default_store.record_audit_event(
            CommercialAuditEvent(
                action="commercial.connectivity.allow_host",
                target=normalized_host,
                status=AuditStatus.SUCCESS,
                actor_username="local-cli",
                actor_role="operator",
                summary="Updated commercial outbound allowlist",
                metadata={"enable_outbound": enable_outbound},
            )
        )
        return updated
    finally:
        await Storage.shutdown()


@commercial_app.command("issue-temp-license")
def issue_temp_license(
    days: int = typer.Option(30, "--days", min=1, help="Temporary license validity in days"),
    licensed_to: str = typer.Option(
        "Local Commercial Evaluation",
        "--licensed-to",
        help="Display name for the licensed organization",
    ),
    license_id: Optional[str] = typer.Option(None, "--license-id", help="Override the generated license ID"),
    feature: Optional[list[str]] = typer.Option(
        None,
        "--feature",
        "-f",
        help="Licensed feature; repeat to restrict features. Defaults to all commercial features.",
    ),
):
    """
    Issue a local-only temporary commercial license.

    This does not contact a remote license service.
    """
    try:
        license_info = asyncio.run(
            issue_temp_license_local(
                days=days,
                licensed_to=licensed_to,
                license_id=license_id,
                features=feature,
            )
        )
    except Exception as exc:
        console.print(f"[red]Failed to issue temporary commercial license: {exc}[/red]")
        raise typer.Exit(1) from exc

    console.print("[green]Temporary commercial license issued[/green]")
    console.print(f"License ID: [bold]{license_info.license_id or '-'}[/bold]")
    console.print(f"Licensed to: [bold]{license_info.licensed_to or '-'}[/bold]")
    console.print(f"Edition: [bold]{license_info.edition}[/bold]")
    console.print(f"Expires at: [bold]{license_info.expires_at or '-'}[/bold]")


@commercial_app.command("allow-host")
def allow_host(
    host: str = typer.Argument(..., help="Host or URL to allow, for example api.minimax.chat"),
    enable_outbound: bool = typer.Option(
        True,
        "--enable-outbound/--no-enable-outbound",
        help="Enable global outbound connectivity while adding the host",
    ),
):
    """
    Add a host to the commercial outbound allowlist.
    """
    try:
        connectivity = asyncio.run(allow_host_local(host, enable_outbound=enable_outbound))
    except Exception as exc:
        console.print(f"[red]Failed to update commercial outbound allowlist: {exc}[/red]")
        raise typer.Exit(1) from exc

    console.print("[green]Commercial outbound allowlist updated[/green]")
    console.print(f"Outbound enabled: [bold]{connectivity.outbound_enabled}[/bold]")
    console.print(f"Allowed hosts: [bold]{', '.join(connectivity.allowed_hosts) or '-'}[/bold]")


@commercial_app.command("status")
def status():
    """
    Show the local commercial license and connectivity state.
    """

    async def _load():
        await Storage.init()
        try:
            license_info = await default_store.get_license()
            feature_state = await get_feature_state()
            connectivity = await default_store.get_connectivity()
            update_policy = await default_store.get_update_policy()
            notification_policy = await default_store.get_notification_policy()
            return license_info, feature_state, connectivity, update_policy, notification_policy
        finally:
            await Storage.shutdown()

    try:
        license_info, feature_state, connectivity, update_policy, notification_policy = asyncio.run(_load())
    except Exception as exc:
        console.print(f"[red]Failed to load commercial status: {exc}[/red]")
        raise typer.Exit(1) from exc

    table = Table(title="Commercial Status")
    table.add_column("Item", style="bold")
    table.add_column("Value")
    table.add_row("License", f"{license_info.edition} / {license_info.status}")
    table.add_row("Licensed to", license_info.licensed_to or "-")
    table.add_row("License ID", license_info.license_id or "-")
    table.add_row("Expires at", license_info.expires_at or "-")
    table.add_row("Enabled features", ", ".join(sorted(feature_state.licensed_features)) or "-")
    table.add_row("Outbound enabled", str(connectivity.outbound_enabled))
    table.add_row("Allowed hosts", ", ".join(connectivity.allowed_hosts) or "-")
    table.add_row("Update check enabled", str(update_policy.update_check_enabled))
    table.add_row("Update apply enabled", str(update_policy.update_apply_enabled))
    table.add_row("Legacy update sources enabled", str(update_policy.legacy_flocks_update_sources_enabled))
    table.add_row("Built-in notifications", str(notification_policy.built_in_notifications_enabled))
    table.add_row("Benefit notifications", str(notification_policy.benefit_notifications_enabled))
    table.add_row("Whats-new notifications", str(notification_policy.whats_new_notifications_enabled))
    table.add_row("Vendor notifications", str(notification_policy.vendor_notifications_enabled))
    console.print(table)
