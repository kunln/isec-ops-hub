"""In-process connector registry for Security Extension connectors."""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Awaitable, Callable

from flocks.security.connectors.mock import MOCK_CONNECTOR_ID, build_mock_manifest, test_mock_connection
from flocks.security.connectors.models import (
    ConnectorCapability,
    ConnectorManifest,
    ConnectorPreviewResult,
    ConnectorTestResult,
    ConnectorValidateResult,
)
from flocks.security.connectors.package_loader import (
    build_connector_package_diagnostics,
    build_package_registration,
    disable_connector_package,
    discover_enabled_connector_packages,
    enable_connector_package,
    install_connector_package,
    rollback_connector_package,
    uninstall_connector_package,
)
from flocks.security.connectors.installed_registry import get_installed_connector_package
from flocks.security.connectors.operations import (
    BULK_ACTIONS,
    acknowledge_connector_operation_events,
    acknowledge_connector_operation_event,
    connector_operations_summary,
    deliver_connector_operation_event_notifications,
    get_connector_operation_event,
    get_connector_operations_settings,
    list_connector_operation_events,
    load_connector_operations_registry,
    mark_expiry_monitor_run,
    record_connector_bulk_operation,
    record_connector_operation_event,
    update_connector_operations_settings,
)
from flocks.security.connectors.package_staging import (
    discard_staged_connector_package,
    install_staged_connector_package,
    list_staged_connector_packages,
    stage_connector_package_artifact,
    staging_registry_summary,
    validate_staged_connector_package,
)
from flocks.security.connectors.scheduler import (
    delete_connector_sync_schedule,
    disable_connector_sync_schedule,
    enable_connector_sync_schedule,
    get_connector_sync_schedule,
    list_connector_sync_schedules,
    load_connector_sync_schedule_registry,
    recover_policy_paused_schedules_for_credential,
    run_connector_sync_schedule,
    run_due_connector_sync_schedules,
    sync_schedule_summary,
    upsert_connector_sync_schedule,
)
from flocks.security.connectors.credential_bindings import (
    bind_connector_credentials,
    credential_binding_summary,
    delete_connector_credentials,
    get_connector_credential_binding,
    get_connector_credential_env,
    get_connector_credential_health,
    list_connector_credential_bindings,
    record_connector_credential_sync_result,
    record_connector_credential_test_result,
    rotate_connector_credentials,
    set_active_connector_credential_profile,
)
from flocks.security.connectors.sync_runtime import (
    list_active_connector_sync_runs,
    list_connector_sync_cursors,
    list_connector_sync_dead_letters,
    list_connector_sync_runs,
    load_connector_sync_run_registry,
    record_blocked_connector_sync_run,
    replay_connector_sync_dead_letters,
    request_connector_sync_cancel,
    reset_connector_sync_cursor,
    sync_connector_preview_result,
    sync_run_summary,
)
from flocks.security.evidence_graph import (
    evidence_graph_summary,
    load_evidence_graph,
    rebuild_evidence_graph as rebuild_security_evidence_graph,
)


REPLAY_CONNECTOR_ID = "fixture-replay-demo"
_credential_profile_overrides: ContextVar[dict[str, str]] = ContextVar(
    "connector_credential_profile_overrides",
    default={},
)
ConnectorTestFn = Callable[[], Awaitable[ConnectorTestResult]]
ConnectorPreviewFn = Callable[[ConnectorCapability], Awaitable[ConnectorPreviewResult]]
ConnectorValidateFn = Callable[[], Awaitable[ConnectorValidateResult]]


@dataclass
class ConnectorRegistry:
    _manifests: dict[str, ConnectorManifest] = field(default_factory=dict)
    _testers: dict[str, ConnectorTestFn] = field(default_factory=dict)
    _previewers: dict[str, ConnectorPreviewFn] = field(default_factory=dict)
    _validators: dict[str, ConnectorValidateFn] = field(default_factory=dict)
    _package_roots: list[Path] | None = None
    _installed_registry_path: Path | None = None
    _staging_registry_path: Path | None = None
    _credential_binding_path: Path | None = None
    _sync_run_registry_path: Path | None = None
    _sync_schedule_registry_path: Path | None = None
    _operations_registry_path: Path | None = None
    _evidence_graph_path: Path | None = None
    _ignore_installed_registry: bool = False
    _initialized: bool = False

    def ensure_initialized(self) -> None:
        if self._initialized:
            return
        self.register(build_mock_manifest(), test_mock_connection)
        packages = [] if self._ignore_installed_registry else discover_enabled_connector_packages(
            registry_path=self._installed_registry_path
        )
        for package in packages:
            self.register(
                *build_package_registration(
                    package,
                    credential_env_provider=self.credential_env,
                )
            )
        self._initialized = True

    def register(
        self,
        manifest: ConnectorManifest,
        test_connection: ConnectorTestFn | None = None,
        preview: ConnectorPreviewFn | None = None,
        validate: ConnectorValidateFn | None = None,
    ) -> None:
        self._manifests[manifest.id] = manifest
        if test_connection is not None:
            self._testers[manifest.id] = test_connection
        if preview is not None:
            self._previewers[manifest.id] = preview
        if validate is not None:
            self._validators[manifest.id] = validate

    def list(self) -> list[ConnectorManifest]:
        self.ensure_initialized()
        return sorted(self._manifests.values(), key=lambda item: item.id)

    def get(self, connector_id: str) -> ConnectorManifest | None:
        self.ensure_initialized()
        return self._manifests.get(connector_id)

    def list_capabilities(self, connector_id: str) -> list[ConnectorCapability]:
        manifest = self.get(connector_id)
        if manifest is None:
            raise ValueError(f"Connector not found: {connector_id}")
        return manifest.capabilities

    async def test_connection(
        self,
        connector_id: str,
        *,
        credential_profile_id: str | None = None,
        actor: dict[str, Any] | None = None,
    ) -> ConnectorTestResult:
        self.ensure_initialized()
        tester = self._testers.get(connector_id)
        if tester is None:
            raise ValueError(f"Connector test not available: {connector_id}")
        token = self._push_credential_profile(connector_id, credential_profile_id)
        try:
            result = await tester()
        finally:
            _credential_profile_overrides.reset(token)
        if credential_profile_id:
            self.record_credential_test_result(
                connector_id,
                credential_profile_id,
                success=result.success,
                message=result.message,
                actor=actor,
            )
        return result

    async def preview(
        self,
        connector_id: str,
        capability: str | ConnectorCapability,
        *,
        credential_profile_id: str | None = None,
    ) -> ConnectorPreviewResult:
        manifest = self.get(connector_id)
        if manifest is None:
            raise ValueError(f"Connector not found: {connector_id}")
        try:
            capability_value = ConnectorCapability(str(capability))
        except ValueError as exc:
            raise ValueError(f"Unknown connector capability: {capability}") from exc
        if capability_value not in manifest.capabilities:
            return ConnectorPreviewResult(
                connector_id=connector_id,
                capability=capability_value,
                success=False,
                warnings=[f"Connector does not declare capability: {capability_value}"],
                missing_capabilities=[capability_value],
            )
        previewer = self._previewers.get(connector_id)
        if previewer is None:
            raise ValueError(f"Connector preview not available: {connector_id}")
        token = self._push_credential_profile(connector_id, credential_profile_id)
        try:
            return await previewer(capability_value)
        finally:
            _credential_profile_overrides.reset(token)

    async def validate(self, connector_id: str) -> ConnectorValidateResult:
        self.ensure_initialized()
        validator = self._validators.get(connector_id)
        if validator is None:
            raise ValueError(f"Connector validation not available: {connector_id}")
        return await validator()

    async def package_diagnostics(self) -> dict[str, Any]:
        self.ensure_initialized()
        diagnostics = await build_connector_package_diagnostics(
            roots=self._package_roots,
            workspace_root=Path.cwd(),
            registry_path=self._installed_registry_path,
            include_installed_registry=not self._ignore_installed_registry,
        )
        diagnostics["staging_registry"] = staging_registry_summary(self._staging_registry_path)
        diagnostics["staging_packages"] = list_staged_connector_packages(self._staging_registry_path)
        diagnostics["credential_bindings"] = list_connector_credential_bindings(self._credential_binding_path)
        diagnostics["credential_binding_registry"] = credential_binding_summary(self._credential_binding_path)
        diagnostics["sync_run_registry"] = sync_run_summary(self._sync_run_registry_path)
        diagnostics["sync_runs"] = list_connector_sync_runs(limit=20, path=self._sync_run_registry_path)
        diagnostics["active_sync_runs"] = list_active_connector_sync_runs()
        diagnostics["sync_cursors"] = list_connector_sync_cursors(path=self._sync_run_registry_path)
        diagnostics["sync_dead_letters"] = list_connector_sync_dead_letters(limit=20, path=self._sync_run_registry_path)
        diagnostics["sync_schedule_registry"] = sync_schedule_summary(self._sync_schedule_registry_path)
        diagnostics["sync_schedules"] = list_connector_sync_schedules(path=self._sync_schedule_registry_path)
        diagnostics["connector_operations"] = connector_operations_summary(self._operations_registry_path)
        diagnostics["operation_events"] = self.list_operation_events(limit=20)
        diagnostics["operations_dashboard"] = _build_operations_dashboard(
            diagnostics,
            operations_registry_path=self._operations_registry_path,
            sync_run_registry_path=self._sync_run_registry_path,
            sync_schedule_registry_path=self._sync_schedule_registry_path,
        )
        diagnostics["evidence_graph"] = evidence_graph_summary(self._evidence_graph_path)
        diagnostics["summary"]["staging_packages"] = len(diagnostics["staging_packages"])
        diagnostics["summary"]["validated_staging_packages"] = sum(
            1 for record in diagnostics["staging_packages"] if record.get("status") == "validated"
        )
        diagnostics["summary"]["invalid_staging_packages"] = sum(
            1 for record in diagnostics["staging_packages"] if record.get("status") == "invalid"
        )
        diagnostics["summary"]["credential_bindings"] = len(diagnostics["credential_bindings"])
        diagnostics["summary"]["sync_runs"] = len(diagnostics["sync_runs"])
        diagnostics["summary"]["active_sync_runs"] = len(diagnostics["active_sync_runs"])
        diagnostics["summary"]["sync_cursors"] = len(diagnostics["sync_cursors"])
        diagnostics["summary"]["sync_dead_letters"] = len(diagnostics["sync_dead_letters"])
        diagnostics["summary"]["pending_sync_dead_letters"] = int(
            diagnostics["sync_run_registry"].get("pending_dead_letters") or 0
        )
        diagnostics["summary"]["replayed_sync_dead_letters"] = int(
            diagnostics["sync_run_registry"].get("replayed_dead_letters") or 0
        )
        diagnostics["summary"]["blocked_sync_runs"] = int(diagnostics["sync_run_registry"].get("blocked_runs") or 0)
        diagnostics["summary"]["sync_schedules"] = len(diagnostics["sync_schedules"])
        diagnostics["summary"]["enabled_sync_schedules"] = sum(
            1 for record in diagnostics["sync_schedules"] if record.get("enabled")
        )
        diagnostics["summary"]["due_sync_schedules"] = sum(
            1 for record in diagnostics["sync_schedules"] if record.get("due")
        )
        diagnostics["summary"]["policy_paused_sync_schedules"] = int(
            diagnostics["sync_schedule_registry"].get("policy_paused") or 0
        )
        diagnostics["summary"]["connector_operation_events"] = int(
            diagnostics["connector_operations"].get("events") or 0
        )
        diagnostics["summary"]["open_connector_operation_events"] = int(
            diagnostics["connector_operations"].get("open_events") or 0
        )
        diagnostics["summary"]["expiry_risks"] = int(
            diagnostics["operations_dashboard"]["current"].get("expiry_risks") or 0
        )
        diagnostics["summary"]["average_recovery_seconds"] = (
            diagnostics["operations_dashboard"]["mttr"].get("seconds")
        )
        diagnostics["summary"]["bulk_remediation_runs"] = int(diagnostics["operations_dashboard"]["bulk"].get("runs") or 0)
        diagnostics["summary"]["bulk_remediation_failed"] = int(
            diagnostics["operations_dashboard"]["bulk"].get("failed") or 0
        )
        diagnostics["summary"]["evidence_graph_nodes"] = int(diagnostics["evidence_graph"].get("nodes") or 0)
        diagnostics["summary"]["evidence_graph_edges"] = int(diagnostics["evidence_graph"].get("edges") or 0)
        diagnostics["summary"]["evidence_graph_entities"] = int(diagnostics["evidence_graph"].get("asset_entities") or 0)
        diagnostics["summary"]["evidence_graph_conflicts"] = int(diagnostics["evidence_graph"].get("conflicts") or 0)
        return diagnostics

    async def customer_summary(self, *, trend_days: int = 14) -> dict[str, Any]:
        """Return a customer-facing connector health summary.

        This intentionally hides package registries, dead-letter payloads, bulk
        remediation runs and other maintenance diagnostics. The 8080 device
        integration page should consume this instead of package_diagnostics().
        """
        diagnostics = await self.package_diagnostics()
        checked_at = str(diagnostics.get("checked_at") or datetime.now(UTC).isoformat())
        package_by_id = {
            str(item.get("id")): item
            for item in diagnostics.get("packages") or []
            if isinstance(item, dict) and item.get("id")
        }
        manifest_by_id = {manifest.id: manifest for manifest in self.list()}
        connector_ids = sorted(
            set(manifest_by_id)
            | {
                connector_id
                for connector_id, package in package_by_id.items()
                if package.get("installed") or package.get("active") or package.get("enabled")
            }
        )
        credential_by_id = {
            str(item.get("connector_id")): item
            for item in diagnostics.get("credential_bindings") or []
            if isinstance(item, dict) and item.get("connector_id")
        }
        schedules_by_connector: dict[str, list[dict[str, Any]]] = {}
        for schedule in diagnostics.get("sync_schedules") or []:
            if not isinstance(schedule, dict):
                continue
            schedules_by_connector.setdefault(str(schedule.get("connector_id") or ""), []).append(schedule)
        runs_by_connector: dict[str, list[dict[str, Any]]] = {}
        for run in diagnostics.get("sync_runs") or []:
            if not isinstance(run, dict):
                continue
            runs_by_connector.setdefault(str(run.get("connector_id") or ""), []).append(run)
        active_runs_by_connector: dict[str, list[dict[str, Any]]] = {}
        for run in diagnostics.get("active_sync_runs") or []:
            if not isinstance(run, dict):
                continue
            active_runs_by_connector.setdefault(str(run.get("connector_id") or ""), []).append(run)

        dashboard = diagnostics.get("operations_dashboard") if isinstance(diagnostics.get("operations_dashboard"), dict) else {}
        expiry_warning_days = _dashboard_int(dashboard.get("expiry_warning_days"), default=14)
        now = _parse_datetime(dashboard.get("checked_at")) or datetime.now(UTC)
        data_sources = [
            _customer_data_source_summary(
                connector_id,
                manifest_by_id.get(connector_id),
                package_by_id.get(connector_id),
                credential_by_id.get(connector_id),
                schedules_by_connector.get(connector_id, []),
                runs_by_connector.get(connector_id, []),
                active_runs_by_connector.get(connector_id, []),
                credential_health=self.credential_health(connector_id),
                checked_at=now,
                expiry_warning_days=expiry_warning_days,
            )
            for connector_id in connector_ids
        ]
        data_sources.sort(key=lambda item: (str(item.get("vendor") or ""), str(item.get("name") or item.get("id") or "")))

        recent_events = _customer_operation_events(
            diagnostics.get("operation_events") or [],
            data_sources=data_sources,
            limit=10,
        )
        trend = _customer_trend(dashboard.get("trend") if isinstance(dashboard, dict) else [], trend_days=trend_days)
        summary = {
            "device_api_note": "Device connectivity, tool access, and connector sync are unified in Device Integration.",
            "data_sources": len(data_sources),
            "connected_data_sources": sum(1 for item in data_sources if item.get("connection_status") == "connected"),
            "attention_data_sources": sum(1 for item in data_sources if _customer_source_needs_attention(item)),
            "sync_schedules": sum(len(item.get("schedules") or []) for item in data_sources),
            "enabled_sync_schedules": sum(
                1
                for item in data_sources
                for schedule in item.get("schedules") or []
                if schedule.get("enabled")
            ),
            "expiry_risks": _dashboard_int((dashboard.get("current") or {}).get("expiry_risks")) if isinstance(dashboard, dict) else 0,
            "sync_blocked": sum(1 for item in data_sources if item.get("sync_status") == "blocked"),
            "paused_schedules": sum(
                1
                for item in data_sources
                for schedule in item.get("schedules") or []
                if schedule.get("status") == "paused"
            ),
            "recent_anomalies": len(recent_events),
        }
        return {
            "version": "connector.customer.summary.v1",
            "checked_at": checked_at,
            "trend_window_days": max(1, min(14, int(trend_days or 14))),
            "summary": summary,
            "data_sources": data_sources,
            "recent_events": recent_events,
            "trend": trend,
        }

    async def customer_test_connection(
        self,
        connector_id: str,
        *,
        credential_profile_id: str | None = None,
        actor: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            result = await self.test_connection(
                connector_id,
                credential_profile_id=credential_profile_id,
                actor=actor,
            )
        except ValueError as exc:
            detail = str(exc)
            if "not found" in detail.lower():
                raise
            return {
                "connector_id": connector_id,
                "success": False,
                "status": "error",
                "message": _customer_failure_message({"errors": [detail]}, None),
                "checked_at": datetime.now(UTC).isoformat(),
                "latency_ms": None,
            }
        health_check = result.health_check.model_dump(mode="json") if result.health_check else {}
        return {
            "connector_id": connector_id,
            "success": bool(result.success),
            "status": "connected" if result.success else "failed",
            "message": "连接测试通过。" if result.success else _customer_failure_message({}, health_check),
            "checked_at": health_check.get("checked_at") or datetime.now(UTC).isoformat(),
            "latency_ms": health_check.get("latency_ms"),
        }

    async def install_package(self, package_root: Path | str, *, enabled: bool = False) -> dict[str, Any]:
        record = await install_connector_package(
            package_root,
            enabled=enabled,
            registry_path=self._installed_registry_path,
        )
        self.reload()
        return record

    async def enable_package(self, package_id: str) -> dict[str, Any]:
        record = await enable_connector_package(package_id, registry_path=self._installed_registry_path)
        self.reload()
        return record

    def disable_package(self, package_id: str) -> dict[str, Any]:
        record = disable_connector_package(package_id, registry_path=self._installed_registry_path)
        self.reload()
        return record

    def uninstall_package(self, package_id: str) -> dict[str, Any]:
        record = uninstall_connector_package(package_id, registry_path=self._installed_registry_path)
        self.reload()
        return record

    async def rollback_package(self, package_id: str) -> dict[str, Any]:
        record = await rollback_connector_package(package_id, registry_path=self._installed_registry_path)
        self.reload()
        return record

    def list_staging_packages(self) -> list[dict[str, Any]]:
        return list_staged_connector_packages(self._staging_registry_path)

    async def upload_package_artifact(self, filename: str, content: bytes) -> dict[str, Any]:
        return await stage_connector_package_artifact(
            filename=filename,
            content=content,
            staging_registry_path=self._staging_registry_path,
        )

    async def validate_staging_package(self, staging_id: str) -> dict[str, Any]:
        return await validate_staged_connector_package(staging_id, staging_registry_path=self._staging_registry_path)

    async def install_staging_package(self, staging_id: str, *, enabled: bool = False) -> dict[str, Any]:
        record = await install_staged_connector_package(
            staging_id,
            enabled=enabled,
            installed_registry_path=self._installed_registry_path,
            staging_registry_path=self._staging_registry_path,
        )
        self.reload()
        return record

    def discard_staging_package(self, staging_id: str) -> dict[str, Any]:
        return discard_staged_connector_package(staging_id, staging_registry_path=self._staging_registry_path)

    def credential_env(self, connector_id: str) -> dict[str, str]:
        profile_id = _credential_profile_overrides.get({}).get(connector_id)
        return get_connector_credential_env(connector_id, profile_id=profile_id, path=self._credential_binding_path)

    def credential_health(self, connector_id: str, profile_id: str | None = None) -> dict[str, Any]:
        return get_connector_credential_health(connector_id, profile_id=profile_id, path=self._credential_binding_path)

    def list_credential_bindings(self) -> list[dict[str, Any]]:
        return list_connector_credential_bindings(self._credential_binding_path)

    def get_credential_binding(self, connector_id: str) -> dict[str, Any] | None:
        return get_connector_credential_binding(connector_id, path=self._credential_binding_path)

    def bind_credentials(
        self,
        connector_id: str,
        values: dict[str, str],
        *,
        secret_keys: list[str] | None = None,
        profile_id: str = "default",
        profile_name: str | None = None,
        make_active: bool = True,
        expires_at: str | None = None,
        actor: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return bind_connector_credentials(
            connector_id,
            values,
            secret_keys=secret_keys,
            profile_id=profile_id,
            profile_name=profile_name,
            make_active=make_active,
            expires_at=expires_at,
            actor=actor,
            path=self._credential_binding_path,
        )

    async def bind_credentials_and_test(
        self,
        connector_id: str,
        values: dict[str, str],
        *,
        secret_keys: list[str] | None = None,
        profile_id: str = "default",
        profile_name: str | None = None,
        make_active: bool = True,
        expires_at: str | None = None,
        recover_policy_paused_schedules: str = "preview",
        actor: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        binding = self.bind_credentials(
            connector_id,
            values,
            secret_keys=secret_keys,
            profile_id=profile_id,
            profile_name=profile_name,
            make_active=make_active,
            expires_at=expires_at,
            actor=actor,
        )
        await self._test_credential_profile_if_available(connector_id, profile_id)
        updated = self.get_credential_binding(connector_id) or binding
        updated["policy_recovery"] = self.recover_policy_paused_schedules(
            connector_id,
            profile_id,
            mode=recover_policy_paused_schedules,
        )
        return updated

    async def rotate_credentials(
        self,
        connector_id: str,
        profile_id: str,
        values: dict[str, str],
        *,
        secret_keys: list[str] | None = None,
        expires_at: str | None = None,
        make_active: bool = True,
        recover_policy_paused_schedules: str = "preview",
        actor: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        binding = rotate_connector_credentials(
            connector_id,
            profile_id,
            values,
            secret_keys=secret_keys,
            expires_at=expires_at,
            make_active=make_active,
            actor=actor,
            path=self._credential_binding_path,
        )
        await self._test_credential_profile_if_available(connector_id, profile_id)
        updated = self.get_credential_binding(connector_id) or binding
        updated["policy_recovery"] = self.recover_policy_paused_schedules(
            connector_id,
            profile_id,
            mode=recover_policy_paused_schedules,
        )
        return updated

    def activate_credential_profile(
        self,
        connector_id: str,
        profile_id: str,
        *,
        actor: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return set_active_connector_credential_profile(
            connector_id,
            profile_id,
            actor=actor,
            path=self._credential_binding_path,
        )

    async def test_credential_profile(
        self,
        connector_id: str,
        profile_id: str,
        *,
        actor: dict[str, Any] | None = None,
    ) -> ConnectorTestResult:
        return await self.test_connection(connector_id, credential_profile_id=profile_id, actor=actor)

    def record_credential_test_result(
        self,
        connector_id: str,
        profile_id: str,
        *,
        success: bool,
        message: str | None = None,
        actor: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return record_connector_credential_test_result(
            connector_id,
            profile_id,
            success=success,
            message=message,
            actor=actor,
            path=self._credential_binding_path,
        )

    def delete_credentials(
        self,
        connector_id: str,
        profile_id: str | None = None,
        *,
        actor: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return delete_connector_credentials(
            connector_id,
            profile_id=profile_id,
            actor=actor,
            path=self._credential_binding_path,
        )

    def list_operation_events(
        self,
        *,
        status: str | None = None,
        kind: str | None = None,
        severity: str | None = None,
        connector_id: str | None = None,
        profile_id: str | None = None,
        schedule_id: str | None = None,
        reason_code: str | None = None,
        keyword: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        return list_connector_operation_events(
            status=status,
            kind=kind,
            severity=severity,
            connector_id=connector_id,
            profile_id=profile_id,
            schedule_id=schedule_id,
            reason_code=reason_code,
            keyword=keyword,
            limit=limit,
            path=self._operations_registry_path,
        )

    def get_operation_event(self, event_id: str) -> dict[str, Any] | None:
        return get_connector_operation_event(event_id, path=self._operations_registry_path)

    def acknowledge_operation_event(self, event_id: str, *, actor: dict[str, Any] | None = None) -> dict[str, Any]:
        return acknowledge_connector_operation_event(event_id, actor=actor, path=self._operations_registry_path)

    def acknowledge_operation_events(self, event_ids: list[str], *, actor: dict[str, Any] | None = None) -> dict[str, Any]:
        return acknowledge_connector_operation_events(event_ids, actor=actor, path=self._operations_registry_path)

    def operation_settings(self) -> dict[str, Any]:
        return get_connector_operations_settings(self._operations_registry_path)

    def update_operation_settings(
        self,
        settings: dict[str, Any],
        *,
        actor: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return update_connector_operations_settings(settings, actor=actor, path=self._operations_registry_path)

    def notify_operation_event(self, event_id: str, *, force: bool = False) -> list[dict[str, Any]]:
        return deliver_connector_operation_event_notifications(event_id, force=force, path=self._operations_registry_path)

    def monitor_credential_expiry(
        self,
        *,
        days: int | None = None,
        notify: bool | None = None,
        actor: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        settings = self.operation_settings()["expiry_monitor"]
        days = max(0, int(settings.get("days") if days is None else days))
        notify = bool(settings.get("notify", True) if notify is None else notify)
        now = datetime.now(UTC)
        profiles: list[dict[str, Any]] = []
        events: list[dict[str, Any]] = []
        for binding in self.list_credential_bindings():
            connector_id = str(binding.get("connector_id") or "")
            for profile in binding.get("profiles") or []:
                if not isinstance(profile, dict):
                    continue
                expires_at = profile.get("expires_at")
                expires_at_dt = _parse_datetime(str(expires_at)) if expires_at else None
                if expires_at_dt is None:
                    continue
                delta_seconds = (expires_at_dt - now).total_seconds()
                days_until = int(delta_seconds // 86400)
                if delta_seconds < 0:
                    state = "expired"
                    severity = "critical"
                    kind = "credential_expired"
                    reason_code = "expired"
                elif delta_seconds <= days * 86400:
                    state = "expiring_soon"
                    severity = "medium"
                    kind = "credential_expiring_soon"
                    reason_code = "expires_soon"
                else:
                    continue
                item = {
                    "connector_id": connector_id,
                    "profile_id": profile.get("id"),
                    "active": bool(profile.get("active")),
                    "status": profile.get("status"),
                    "state": state,
                    "severity": severity,
                    "expires_at": expires_at,
                    "days_until_expiry": days_until,
                }
                profiles.append(item)
                if notify:
                    events.append(
                        self._record_operation_event(
                            kind,
                            severity=severity,
                            connector_id=connector_id,
                            profile_id=str(profile.get("id") or ""),
                            reason_code=reason_code,
                            title=(
                                "Credential profile expired"
                                if state == "expired"
                                else "Credential profile expiring soon"
                            ),
                            message=(
                                f"Credential profile {connector_id}/{profile.get('id')} expired at {expires_at}."
                                if state == "expired"
                                else f"Credential profile {connector_id}/{profile.get('id')} expires at {expires_at}."
                            ),
                            metadata={**item, "monitor_days": days},
                            dedupe_key=f"{kind}:{connector_id}:{profile.get('id')}:{expires_at}",
                            actor=actor,
                        )
                    )
        result = {
            "version": "connector.credential.expiry_monitor.v1",
            "checked_at": datetime.now(UTC).isoformat(),
            "days": days,
            "notify": bool(notify),
            "matched": len(profiles),
            "expired": sum(1 for item in profiles if item["state"] == "expired"),
            "expiring_soon": sum(1 for item in profiles if item["state"] == "expiring_soon"),
            "profiles": profiles,
            "events": events,
        }
        mark_expiry_monitor_run(result, path=self._operations_registry_path)
        return result

    async def bulk_remediate_credentials(
        self,
        items: list[dict[str, Any]],
        *,
        action: str,
        recovery_mode: str = "enable",
        notify: bool = True,
        actor: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        action = str(action or "")
        if action not in BULK_ACTIONS:
            raise ValueError(f"Unsupported connector bulk remediation action: {action}")
        results: list[dict[str, Any]] = []
        for raw_item in items:
            connector_id = str((raw_item or {}).get("connector_id") or "").strip()
            profile_id = str((raw_item or {}).get("profile_id") or "").strip()
            result = {
                "connector_id": connector_id,
                "profile_id": profile_id,
                "action": action,
                "status": "pending",
                "success": False,
                "event": None,
                "result": None,
                "error": None,
            }
            if not connector_id or not profile_id:
                result["status"] = "error"
                result["error"] = "connector_id and profile_id are required"
                results.append(result)
                continue
            try:
                health = self.credential_health(connector_id, profile_id)
                if action == "test":
                    test_result = await self.test_credential_profile(connector_id, profile_id)
                    result["result"] = test_result.model_dump(mode="json")
                    result["success"] = bool(test_result.success)
                    result["status"] = "success" if test_result.success else "failed"
                elif action == "enable_schedules":
                    recovery = self.recover_policy_paused_schedules(
                        connector_id,
                        profile_id,
                        mode=recovery_mode,
                        actor=actor,
                    )
                    result["result"] = recovery
                    result["success"] = bool(recovery.get("healthy")) and int(recovery.get("recovered") or 0) > 0
                    result["status"] = "success" if result["success"] else "no_change"
                else:
                    event = self._record_operation_event(
                            "credential_remediation_requested",
                            severity=str(health.get("severity") or "medium"),
                            connector_id=connector_id,
                            profile_id=profile_id,
                            reason_code=health.get("reason_code"),
                            title="Credential remediation requested",
                            message=f"Bulk remediation requested for {connector_id}/{profile_id}: {health.get('message')}",
                            metadata={"health": health, "notify": bool(notify)},
                            actor=actor,
                        ) if notify else None
                    result["event"] = event
                    result["result"] = {"credential_health": health}
                    result["success"] = True
                    result["status"] = "success"
            except Exception as exc:
                result["status"] = "error"
                result["error"] = str(exc)
            results.append(result)
        succeeded = sum(1 for item in results if item.get("success"))
        failed = len(results) - succeeded
        bulk_run = record_connector_bulk_operation(
            action=action,
            requested=len(items),
            succeeded=succeeded,
            failed=failed,
            results=results,
            metadata={"recovery_mode": recovery_mode, "notify": bool(notify)},
            actor=actor,
            path=self._operations_registry_path,
        )
        return {
            "version": "connector.bulk.remediation.v1",
            "action": action,
            "requested": len(items),
            "succeeded": succeeded,
            "failed": failed,
            "results": results,
            "bulk_run": bulk_run,
        }

    def recover_policy_paused_schedules(
        self,
        connector_id: str,
        profile_id: str,
        *,
        mode: str = "preview",
        actor: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        health = self.credential_health(connector_id, profile_id)
        result = recover_policy_paused_schedules_for_credential(
            connector_id,
            profile_id,
            mode="preview" if health.get("blocking") else mode,
            actor=actor,
            path=self._sync_schedule_registry_path,
        )
        result["credential_health"] = health
        result["healthy"] = not bool(health.get("blocking"))
        if health.get("blocking"):
            result["blocked_reason_code"] = health.get("reason_code")
            result["blocked_reason"] = health.get("reason")
        return result

    async def sync(
        self,
        connector_id: str,
        capability: str | ConnectorCapability,
        *,
        mode: str = "full",
        reset_cursor: bool = False,
        trigger: str = "manual",
        schedule_id: str | None = None,
        credential_profile_id: str | None = None,
    ) -> dict[str, Any]:
        manifest = self.get(connector_id)
        if manifest is None:
            raise ValueError(f"Connector not found: {connector_id}")
        try:
            capability_value = ConnectorCapability(str(capability))
        except ValueError as exc:
            raise ValueError(f"Unknown connector capability: {capability}") from exc
        package_metadata = self._package_metadata(connector_id)
        credential_health = self.credential_health(connector_id, credential_profile_id)
        if credential_health.get("blocking"):
            run_profile_id = credential_profile_id or str(credential_health.get("profile_id") or "")
            run = record_blocked_connector_sync_run(
                connector_id,
                str(capability_value.value if hasattr(capability_value, "value") else capability_value),
                mode=mode,
                trigger=trigger,
                schedule_id=schedule_id,
                credential_profile_id=run_profile_id or None,
                package_metadata=package_metadata,
                credential_health=credential_health,
                path=self._sync_run_registry_path,
            )
            record_connector_credential_sync_result(
                connector_id,
                run_profile_id,
                success=False,
                run_id=str(run.get("id") or ""),
                message=str(credential_health.get("message") or run.get("errors", ["Connector sync blocked"])[0]),
                path=self._credential_binding_path,
            ) if credential_health.get("reason_code") in {"expired", "failed"} else None
            self._record_sync_blocked_event(run, credential_health)
            return run
        preview = await self.preview(connector_id, capability, credential_profile_id=credential_profile_id)
        run = await sync_connector_preview_result(
            preview,
            mode=mode,
            reset_cursor=reset_cursor,
            trigger=trigger,
            schedule_id=schedule_id,
            credential_profile_id=credential_profile_id,
            package_metadata=package_metadata,
            path=self._sync_run_registry_path,
            evidence_graph_path=self._evidence_graph_path,
        )
        record_connector_credential_sync_result(
            connector_id,
            credential_profile_id,
            success=run.get("status") not in {"error", "canceled", "busy", "blocked"},
            run_id=str(run.get("id") or ""),
            message="; ".join(str(item) for item in run.get("errors", [])) or None,
            path=self._credential_binding_path,
        )
        return run

    def list_sync_runs(self, connector_id: str | None = None, *, limit: int = 50) -> list[dict[str, Any]]:
        return list_connector_sync_runs(connector_id=connector_id, limit=limit, path=self._sync_run_registry_path)

    def list_active_sync_runs(self, connector_id: str | None = None, capability: str | None = None) -> list[dict[str, Any]]:
        return list_active_connector_sync_runs(connector_id=connector_id, capability=capability)

    def list_sync_cursors(self, connector_id: str | None = None) -> list[dict[str, Any]]:
        return list_connector_sync_cursors(connector_id=connector_id, path=self._sync_run_registry_path)

    def list_sync_dead_letters(
        self,
        connector_id: str | None = None,
        *,
        status: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        return list_connector_sync_dead_letters(
            connector_id=connector_id,
            status=status,
            limit=limit,
            path=self._sync_run_registry_path,
        )

    async def replay_sync_dead_letters(
        self,
        *,
        ids: list[str] | None = None,
        connector_id: str | None = None,
        limit: int = 50,
        payload_updates: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        return await replay_connector_sync_dead_letters(
            ids=ids,
            connector_id=connector_id,
            limit=limit,
            payload_updates=payload_updates,
            path=self._sync_run_registry_path,
            evidence_graph_path=self._evidence_graph_path,
        )

    def cancel_sync_run(self, run_id: str) -> dict[str, Any]:
        return request_connector_sync_cancel(run_id=run_id, path=self._sync_run_registry_path)

    def cancel_sync(self, connector_id: str, capability: str | None = None) -> dict[str, Any]:
        return request_connector_sync_cancel(
            connector_id=connector_id,
            capability=capability,
            path=self._sync_run_registry_path,
        )

    def reset_sync_cursor(self, connector_id: str, capability: str | None = None) -> dict[str, Any]:
        return reset_connector_sync_cursor(connector_id, capability=capability, path=self._sync_run_registry_path)

    def list_sync_schedules(self, connector_id: str | None = None) -> list[dict[str, Any]]:
        return list_connector_sync_schedules(connector_id=connector_id, path=self._sync_schedule_registry_path)

    def get_sync_schedule(self, schedule_id: str) -> dict[str, Any] | None:
        return get_connector_sync_schedule(schedule_id, path=self._sync_schedule_registry_path)

    def upsert_sync_schedule(
        self,
        connector_id: str,
        capability: str,
        *,
        enabled: bool = False,
        interval_seconds: int = 3600,
        mode: str = "incremental",
        full_interval_seconds: int | None = None,
        retry_max_attempts: int = 1,
        retry_backoff_seconds: int = 60,
        timeout_seconds: int = 300,
        credential_profile_id: str | None = None,
        actor: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self.get(connector_id) is None:
            raise ValueError(f"Connector not found: {connector_id}")
        self.list_capabilities(connector_id)
        if capability not in [str(item.value if hasattr(item, "value") else item) for item in self.list_capabilities(connector_id)]:
            raise ValueError(f"Connector does not declare capability: {capability}")
        return upsert_connector_sync_schedule(
            connector_id,
            capability,
            enabled=enabled,
            interval_seconds=interval_seconds,
            mode=mode,
            full_interval_seconds=full_interval_seconds,
            retry_max_attempts=retry_max_attempts,
            retry_backoff_seconds=retry_backoff_seconds,
            timeout_seconds=timeout_seconds,
            credential_profile_id=credential_profile_id,
            actor=actor,
            path=self._sync_schedule_registry_path,
        )

    def enable_sync_schedule(self, schedule_id: str, *, actor: dict[str, Any] | None = None) -> dict[str, Any]:
        return enable_connector_sync_schedule(schedule_id, actor=actor, path=self._sync_schedule_registry_path)

    def disable_sync_schedule(self, schedule_id: str, *, actor: dict[str, Any] | None = None) -> dict[str, Any]:
        return disable_connector_sync_schedule(schedule_id, actor=actor, path=self._sync_schedule_registry_path)

    def delete_sync_schedule(self, schedule_id: str, *, actor: dict[str, Any] | None = None) -> dict[str, Any]:
        return delete_connector_sync_schedule(schedule_id, actor=actor, path=self._sync_schedule_registry_path)

    async def run_sync_schedule(
        self,
        schedule_id: str,
        *,
        trigger: str = "manual",
        mode: str | None = None,
        actor: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        result = await run_connector_sync_schedule(
            schedule_id,
            trigger=trigger,
            mode=mode,
            actor=actor,
            path=self._sync_schedule_registry_path,
        )
        self._record_policy_pause_event(result)
        return result

    async def run_due_sync_schedules(self) -> dict[str, Any]:
        result = await run_due_connector_sync_schedules(path=self._sync_schedule_registry_path)
        for item in result.get("results") or []:
            if isinstance(item, dict):
                self._record_policy_pause_event(item)
        return result

    def evidence_graph(self) -> dict[str, Any]:
        return load_evidence_graph(self._evidence_graph_path)

    def evidence_graph_summary(self) -> dict[str, Any]:
        return evidence_graph_summary(self._evidence_graph_path)

    async def rebuild_evidence_graph(self) -> dict[str, Any]:
        return await rebuild_security_evidence_graph(path=self._evidence_graph_path)

    def _record_sync_blocked_event(self, run: dict[str, Any], credential_health: dict[str, Any]) -> None:
        self._record_operation_event(
            "sync_blocked",
            severity=str(credential_health.get("severity") or "high"),
            connector_id=str(run.get("connector_id") or ""),
            profile_id=run.get("credential_profile_id"),
            schedule_id=run.get("schedule_id"),
            run_id=str(run.get("id") or ""),
            reason_code=credential_health.get("reason_code"),
            title="Connector sync blocked",
            message=str(credential_health.get("message") or "; ".join(str(item) for item in run.get("errors", []))),
            metadata={
                "capability": run.get("capability"),
                "trigger": run.get("trigger"),
                "run_policy": run.get("run_policy"),
                "credential_health": credential_health,
            },
        )

    def _record_policy_pause_event(self, result: dict[str, Any]) -> None:
        schedule = result.get("schedule") if isinstance(result.get("schedule"), dict) else {}
        run = result.get("run") if isinstance(result.get("run"), dict) else {}
        if result.get("status") != "blocked" or schedule.get("policy_state") != "paused":
            return
        self._record_operation_event(
            "schedule_policy_paused",
            severity=str((run.get("credential_health") or {}).get("severity") or "high"),
            connector_id=str(schedule.get("connector_id") or run.get("connector_id") or ""),
            profile_id=schedule.get("credential_profile_id") or run.get("credential_profile_id"),
            schedule_id=str(schedule.get("id") or ""),
            run_id=str(run.get("id") or ""),
            reason_code=schedule.get("policy_reason_code"),
            title="Connector schedule policy-paused",
            message=str(schedule.get("policy_message") or "; ".join(str(item) for item in run.get("errors", []))),
            metadata={
                "capability": schedule.get("capability"),
                "policy_reason": schedule.get("policy_reason"),
                "policy_actions": schedule.get("policy_actions") or [],
                "run_policy": run.get("run_policy"),
            },
        )

    def _record_operation_event(self, kind: str, **kwargs: Any) -> dict[str, Any]:
        event = record_connector_operation_event(
            kind,
            path=self._operations_registry_path,
            **kwargs,
        )
        if int(event.get("seen_count") or 0) == 1:
            deliver_connector_operation_event_notifications(
                str(event.get("id") or ""),
                path=self._operations_registry_path,
            )
        return event

    def _push_credential_profile(self, connector_id: str, profile_id: str | None):
        current = dict(_credential_profile_overrides.get({}))
        if profile_id:
            current[connector_id] = profile_id
        else:
            current.pop(connector_id, None)
        return _credential_profile_overrides.set(current)

    async def _test_credential_profile_if_available(self, connector_id: str, profile_id: str) -> None:
        try:
            await self.test_connection(connector_id, credential_profile_id=profile_id)
        except ValueError as exc:
            if "not available" not in str(exc).lower() and "not found" not in str(exc).lower():
                self.record_credential_test_result(connector_id, profile_id, success=False, message=str(exc))
        except Exception as exc:
            self.record_credential_test_result(connector_id, profile_id, success=False, message=str(exc))

    def _package_metadata(self, connector_id: str) -> dict[str, Any]:
        record = get_installed_connector_package(connector_id, self._installed_registry_path)
        if not isinstance(record, dict):
            return {}
        return {
            "id": record.get("id"),
            "version": record.get("version"),
            "package_version": record.get("package_version"),
            "hash": record.get("hash"),
            "source": record.get("source"),
            "root": record.get("root"),
            "installed_at": record.get("installed_at"),
            "enabled": bool(record.get("enabled")),
        }

    def reload(self) -> None:
        self._manifests.clear()
        self._testers.clear()
        self._previewers.clear()
        self._validators.clear()
        self._initialized = False

    def reset_for_tests(
        self,
        package_roots: list[Path] | None = None,
        installed_registry_path: Path | None = None,
        staging_registry_path: Path | None = None,
        credential_binding_path: Path | None = None,
        sync_run_registry_path: Path | None = None,
        sync_schedule_registry_path: Path | None = None,
        operations_registry_path: Path | None = None,
        evidence_graph_path: Path | None = None,
    ) -> None:
        self.reload()
        self._package_roots = package_roots
        self._installed_registry_path = installed_registry_path
        self._staging_registry_path = (
            staging_registry_path
            if staging_registry_path is not None
            else installed_registry_path.parent / "connector-package-staging.json"
            if installed_registry_path is not None
            else None
        )
        self._credential_binding_path = (
            credential_binding_path
            if credential_binding_path is not None
            else installed_registry_path.parent / "connector-credential-bindings.json"
            if installed_registry_path is not None
            else None
        )
        self._sync_run_registry_path = (
            sync_run_registry_path
            if sync_run_registry_path is not None
            else installed_registry_path.parent / "connector-sync-runs.json"
            if installed_registry_path is not None
            else None
        )
        self._sync_schedule_registry_path = (
            sync_schedule_registry_path
            if sync_schedule_registry_path is not None
            else installed_registry_path.parent / "connector-sync-schedules.json"
            if installed_registry_path is not None
            else None
        )
        self._operations_registry_path = (
            operations_registry_path
            if operations_registry_path is not None
            else installed_registry_path.parent / "connector-operations.json"
            if installed_registry_path is not None
            else None
        )
        self._evidence_graph_path = (
            evidence_graph_path
            if evidence_graph_path is not None
            else installed_registry_path.parent / "connector-evidence-graph.json"
            if installed_registry_path is not None
            else None
        )
        self._ignore_installed_registry = installed_registry_path is None


def _customer_data_source_summary(
    connector_id: str,
    manifest: ConnectorManifest | None,
    package: dict[str, Any] | None,
    binding: dict[str, Any] | None,
    schedules: list[dict[str, Any]],
    runs: list[dict[str, Any]],
    active_runs: list[dict[str, Any]],
    *,
    credential_health: dict[str, Any],
    checked_at: datetime,
    expiry_warning_days: int,
) -> dict[str, Any]:
    latest_run = _latest_customer_run(runs)
    schedule_summaries = [_customer_schedule_summary(schedule) for schedule in schedules]
    credential = _customer_credential_summary(
        credential_health,
        binding,
        checked_at=checked_at,
        expiry_warning_days=expiry_warning_days,
    )
    connection_status = _customer_connection_status(manifest, package, credential_health, credential)
    sync_status = _customer_sync_status(latest_run, schedule_summaries, active_runs, credential_health)
    sync = _customer_sync_summary(latest_run, schedule_summaries, sync_status, credential_health)
    risk_level = _customer_risk_level(connection_status, sync_status, credential, schedule_summaries)
    capabilities = _customer_capabilities(manifest, package)
    actions = _customer_data_source_actions(connector_id, credential_health, credential, schedule_summaries)
    health_message = _customer_health_message(connection_status, sync_status, credential, sync)
    return {
        "id": connector_id,
        "type": "connector",
        "name": getattr(manifest, "name", None) or (package or {}).get("name") or connector_id,
        "vendor": getattr(manifest, "vendor", None) or (package or {}).get("vendor") or "",
        "product": getattr(manifest, "product", None) or (package or {}).get("product") or "",
        "product_version": getattr(manifest, "product_version", None) or (package or {}).get("version"),
        "enabled": bool(getattr(manifest, "enabled", None)) if manifest is not None else bool((package or {}).get("enabled")),
        "connection_status": connection_status,
        "sync_status": sync_status,
        "risk_level": risk_level,
        "message": health_message,
        "capabilities": capabilities,
        "sync_targets": _customer_sync_targets(capabilities),
        "credential": credential,
        "sync": sync,
        "schedules": schedule_summaries,
        "actions": actions,
        }


def _customer_source_needs_attention(item: dict[str, Any]) -> bool:
    if item.get("risk_level") in {"warning", "critical"}:
        return True
    if item.get("sync_status") in {"partial", "pending_sync"}:
        return True
    return item.get("connection_status") == "attention"


def _customer_capabilities(manifest: ConnectorManifest | None, package: dict[str, Any] | None) -> list[str]:
    raw_capabilities = getattr(manifest, "capabilities", None) if manifest is not None else (package or {}).get("capabilities")
    capabilities = []
    for item in raw_capabilities or []:
        capabilities.append(str(getattr(item, "value", item)))
    return sorted(set(capabilities))


def _customer_sync_targets(capabilities: list[str]) -> list[str]:
    targets = []
    if any(capability.startswith("asset.") for capability in capabilities):
        targets.append("assets")
    if any(capability.startswith("vulnerability.") for capability in capabilities):
        targets.append("vulnerabilities")
    if any(capability.startswith("alert.") for capability in capabilities):
        targets.append("alerts")
    if any(capability.startswith("honeypot.") for capability in capabilities):
        targets.append("honeypot_events")
    return targets


def _latest_customer_run(runs: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not runs:
        return None
    return sorted(
        runs,
        key=lambda item: str(item.get("finished_at") or item.get("started_at") or ""),
        reverse=True,
    )[0]


def _customer_connection_status(
    manifest: ConnectorManifest | None,
    package: dict[str, Any] | None,
    credential_health: dict[str, Any],
    credential: dict[str, Any],
) -> str:
    if manifest is None and package is not None and not bool(package.get("enabled")):
        return "disabled"
    if credential_health.get("blocking"):
        return "blocked"
    if credential.get("state") in {"expired", "expiring_soon", "failed", "pending_test", "missing"}:
        return "attention"
    if credential_health.get("reason_code") == "not_configured":
        return "not_configured"
    return "connected"


def _customer_sync_status(
    latest_run: dict[str, Any] | None,
    schedules: list[dict[str, Any]],
    active_runs: list[dict[str, Any]],
    credential_health: dict[str, Any],
) -> str:
    if active_runs:
        return "syncing"
    if credential_health.get("blocking"):
        return "blocked"
    if any(schedule.get("status") == "paused" for schedule in schedules):
        return "paused"
    schedule_status = _customer_schedule_sync_status(schedules)
    if schedule_status:
        return schedule_status
    if latest_run is None:
        return "not_synced"
    status = str(latest_run.get("status") or "")
    if status in {"success", "ok", "completed"}:
        return "ok"
    if status == "partial":
        return "partial"
    if (
        status == "blocked"
        and str(latest_run.get("source") or "") == "credential_health_gate"
        and _credential_recovered_after_run(latest_run, credential_health)
        and any(bool(schedule.get("enabled")) for schedule in schedules)
    ):
        return "pending_sync"
    if status == "blocked":
        return "blocked"
    if status in {"error", "failed", "canceled", "cancelled"}:
        return "failed"
    return status or "unknown"


def _customer_schedule_sync_status(schedules: list[dict[str, Any]]) -> str | None:
    enabled = [schedule for schedule in schedules if schedule.get("enabled")]
    with_status = [
        schedule
        for schedule in enabled
        if str(schedule.get("last_status") or "").strip()
    ]
    if not with_status:
        return None

    failed = [
        schedule
        for schedule in with_status
        if str(schedule.get("last_status") or "").lower() in {"error", "failed", "canceled", "cancelled", "blocked"}
    ]
    if not failed:
        return None

    succeeded = [
        schedule
        for schedule in with_status
        if str(schedule.get("last_status") or "").lower() in {"success", "ok", "completed"}
    ]
    if succeeded:
        return "partial"
    if all(str(schedule.get("last_status") or "").lower() == "blocked" for schedule in failed):
        return "blocked"
    return "failed"


def _customer_risk_level(
    connection_status: str,
    sync_status: str,
    credential: dict[str, Any],
    schedules: list[dict[str, Any]],
) -> str:
    if connection_status == "blocked" or sync_status == "blocked" or credential.get("state") == "expired":
        return "critical"
    if sync_status in {"paused", "failed"} or credential.get("state") in {"failed", "missing", "pending_test"}:
        return "warning"
    if credential.get("state") == "expiring_soon" or any(schedule.get("status") == "paused" for schedule in schedules):
        return "warning"
    if sync_status in {"partial", "not_synced", "pending_sync"}:
        return "attention"
    return "healthy"


def _credential_recovered_after_run(run: dict[str, Any], health: dict[str, Any]) -> bool:
    if health.get("blocking"):
        return False
    profile = health.get("profile") if isinstance(health.get("profile"), dict) else {}
    if str(profile.get("last_test_status") or "") != "success":
        return False
    last_test_at = _parse_datetime(profile.get("last_test_at"))
    run_at = _parse_datetime(run.get("finished_at") or run.get("started_at"))
    return bool(last_test_at and run_at and last_test_at > run_at)


def _customer_credential_summary(
    health: dict[str, Any],
    binding: dict[str, Any] | None,
    *,
    checked_at: datetime,
    expiry_warning_days: int,
) -> dict[str, Any]:
    active_profile = binding.get("active_profile") if isinstance(binding, dict) else None
    profile = health.get("profile") if isinstance(health.get("profile"), dict) else active_profile if isinstance(active_profile, dict) else {}
    env = active_profile.get("env") if isinstance(active_profile, dict) and isinstance(active_profile.get("env"), dict) else {}
    expires_at = profile.get("expires_at") if isinstance(profile, dict) else None
    expires_at_dt = _parse_datetime(expires_at)
    state = str(health.get("reason_code") or "unknown")
    if expires_at_dt is not None and expires_at_dt <= checked_at:
        state = "expired"
    elif expires_at_dt is not None and expires_at_dt <= checked_at + timedelta(days=max(0, expiry_warning_days)):
        state = "expiring_soon"
    if state == "healthy":
        state = "ok"
    message = _customer_credential_message(state, expires_at, health)
    return {
        "profile_id": health.get("profile_id") or (binding or {}).get("active_profile_id"),
        "profile_name": profile.get("name") if isinstance(profile, dict) else None,
        "state": state,
        "healthy": not bool(health.get("blocking")) and state not in {"expired", "failed", "missing", "pending_test"},
        "blocking": bool(health.get("blocking")) or state in {"expired", "failed", "missing", "pending_test"},
        "expires_at": expires_at,
        "last_test_at": profile.get("last_test_at") if isinstance(profile, dict) else None,
        "last_sync_at": profile.get("last_sync_at") if isinstance(profile, dict) else None,
        "last_successful_sync_at": profile.get("last_successful_sync_at") if isinstance(profile, dict) else None,
        "fields": [
            {
                "key": str(key),
                "kind": "secret" if str((entry or {}).get("kind") or "") == "secret" else "value",
                "configured": bool((entry or {}).get("configured", True)),
            }
            for key, entry in sorted(env.items())
            if isinstance(entry, dict)
        ],
        "message": message,
        "recommended_action": _customer_credential_recommendation(state),
    }


def _customer_credential_message(state: str, expires_at: Any, health: dict[str, Any] | None = None) -> str:
    health_message = str((health or {}).get("message") or "").strip()
    if health_message and state in {"failed", "missing", "pending_test", "expired", "not_active"}:
        return health_message
    if state == "expired":
        return f"凭据已过期，请更新凭据后重新测试连接。{_customer_time_suffix(expires_at)}"
    if state == "expiring_soon":
        return f"凭据即将过期，建议提前更新凭据。{_customer_time_suffix(expires_at)}"
    if state == "failed":
        return "连接测试失败，请检查访问地址、网络连通性和凭据是否正确。"
    if state == "missing":
        return "当前凭据配置不完整，请补充访问地址和授权信息。"
    if state == "pending_test":
        return "凭据已保存但还未通过连通测试，请先测试连接。"
    if state == "not_active":
        return "当前凭据不是默认生效配置，如需使用请设为生效配置。"
    if state == "not_configured":
        return "暂未配置凭据；如该数据源需要授权，请先更新凭据。"
    return "连接凭据状态正常。"


def _customer_credential_recommendation(state: str) -> str:
    recommendations = {
        "expired": "更新凭据并测试连接。",
        "expiring_soon": "在过期前更新凭据。",
        "failed": "检查地址、网络和凭据后重新测试。",
        "missing": "补充凭据并测试连接。",
        "pending_test": "执行一次连通测试。",
        "not_active": "确认是否切换为生效凭据。",
        "not_configured": "按需补充凭据。",
    }
    return recommendations.get(state, "保持当前配置。")


def _customer_time_suffix(value: Any) -> str:
    return f" 到期时间：{value}" if value else ""


def _customer_schedule_summary(schedule: dict[str, Any]) -> dict[str, Any]:
    paused = str(schedule.get("policy_state") or "") == "paused" or str(schedule.get("runtime_status") or "") == "policy_paused"
    enabled = bool(schedule.get("enabled"))
    status = "paused" if paused else "enabled" if enabled else "disabled"
    return {
        "id": schedule.get("id"),
        "connector_id": schedule.get("connector_id"),
        "capability": schedule.get("capability"),
        "enabled": enabled,
        "status": status,
        "mode": schedule.get("mode"),
        "interval_seconds": schedule.get("interval_seconds"),
        "full_interval_seconds": schedule.get("full_interval_seconds"),
        "retry_max_attempts": schedule.get("retry_max_attempts"),
        "retry_backoff_seconds": schedule.get("retry_backoff_seconds"),
        "timeout_seconds": schedule.get("timeout_seconds"),
        "credential_profile_id": schedule.get("credential_profile_id"),
        "next_run_at": schedule.get("next_run_at"),
        "last_run_at": schedule.get("last_run_at"),
        "last_successful_run_at": schedule.get("last_successful_run_at"),
        "last_status": schedule.get("last_status"),
        "last_error": schedule.get("last_error"),
        "message": (
            _customer_schedule_pause_message(schedule)
            if paused
            else "同步调度已启用。" if enabled else "同步调度已停用。"
        ),
        "recommended_action": "确认凭据恢复后重新启用调度。" if paused else "无需处理。" if enabled else "按需启用调度。",
    }


def _customer_schedule_pause_message(schedule: dict[str, Any]) -> str:
    reason_code = str(schedule.get("policy_reason_code") or "")
    if reason_code == "expired":
        return "调度已暂停，因为同步凭据已过期。"
    if reason_code == "failed":
        return "调度已暂停，因为最近的连接测试失败。"
    if reason_code == "pending_test":
        return "调度已暂停，因为凭据尚未通过连通测试。"
    return "调度已暂停，请确认凭据和连接恢复后再启用。"


def _customer_sync_summary(
    latest_run: dict[str, Any] | None,
    schedules: list[dict[str, Any]],
    sync_status: str,
    credential_health: dict[str, Any],
) -> dict[str, Any]:
    counts = _customer_sync_counts(latest_run)
    latest_schedule_time = max(
        [str(schedule.get("last_run_at") or "") for schedule in schedules if schedule.get("last_run_at")] or [""]
    ) or None
    last_time = _latest_customer_sync_time(latest_run, latest_schedule_time)
    return {
        "status": sync_status,
        "last_sync_at": last_time,
        "last_successful_sync_at": _latest_schedule_success_time(schedules),
        "counts": counts,
        "failure_reason": _customer_failure_message(latest_run, credential_health, schedules) if sync_status in {"blocked", "failed", "partial", "paused"} else None,
        "recommended_action": _customer_sync_recommendation(sync_status, credential_health),
    }


def _latest_customer_sync_time(latest_run: dict[str, Any] | None, latest_schedule_time: str | None) -> str | None:
    candidates = [
        str(value)
        for value in [
            (latest_run or {}).get("finished_at"),
            (latest_run or {}).get("started_at"),
            latest_schedule_time,
        ]
        if value
    ]
    return max(candidates) if candidates else None


def _latest_schedule_success_time(schedules: list[dict[str, Any]]) -> str | None:
    values = [str(schedule.get("last_successful_run_at") or "") for schedule in schedules if schedule.get("last_successful_run_at")]
    return max(values) if values else None


def _customer_sync_counts(run: dict[str, Any] | None) -> dict[str, int]:
    counts = run.get("counts") if isinstance(run, dict) and isinstance(run.get("counts"), dict) else {}
    return {
        "assets": _dashboard_int(counts.get("assets")),
        "vulnerabilities": _dashboard_int(counts.get("vulnerabilities")),
        "alerts": _dashboard_int(counts.get("alerts")),
        "honeypot_events": _dashboard_int(counts.get("honeypot_events")),
    }


def _customer_failure_message(run: dict[str, Any] | None, health: dict[str, Any] | None, schedules: list[dict[str, Any]] | None = None) -> str:
    reason_code = str((health or {}).get("reason_code") or "")
    health_message = str((health or {}).get("message") or "").strip()
    if reason_code == "expired":
        return health_message or "同步被阻断，因为凭据已过期。请更新凭据并重新测试连接。"
    if reason_code == "failed":
        return f"同步被阻断，因为连接测试失败：{health_message}" if health_message else "同步被阻断，因为连接测试失败。请检查地址、网络和凭据后重试。"
    if reason_code == "missing":
        return f"同步被阻断，因为凭据配置不完整：{health_message}" if health_message else "同步被阻断，因为凭据配置不完整。请补充凭据。"
    if reason_code == "pending_test":
        return f"同步暂未开始，因为凭据尚未通过连通测试：{health_message}" if health_message else "同步暂未开始，因为凭据尚未通过连通测试。请先测试连接。"
    schedule_failure = _customer_schedule_failure_message(schedules or [])
    if schedule_failure:
        return schedule_failure
    status = str((run or {}).get("status") or "")
    if status == "partial":
        return "部分数据未同步成功，请检查数据源字段完整性或稍后重试。"
    if status == "blocked":
        return "同步被阻断，请检查凭据和数据源连接状态。"
    if status in {"error", "failed"}:
        return "上次同步失败，请检查数据源连接、权限和同步范围后重试。"
    if status in {"canceled", "cancelled"}:
        return "上次同步已取消，可在确认配置后重新启用调度。"
    return "当前数据源需要关注，请按推荐动作处理。"


def _customer_schedule_failure_message(schedules: list[dict[str, Any]]) -> str | None:
    failures = [
        schedule
        for schedule in schedules
        if schedule.get("enabled")
        and str(schedule.get("last_status") or "").lower() in {"error", "failed", "canceled", "cancelled", "blocked"}
    ]
    if not failures:
        return None

    details = []
    for schedule in failures[:3]:
        capability = str(schedule.get("capability") or schedule.get("id") or "同步调度")
        error = str(schedule.get("last_error") or schedule.get("last_status") or "执行失败")
        details.append(f"{capability}: {error}")
    suffix = f"；另有 {len(failures) - 3} 个调度失败" if len(failures) > 3 else ""
    return "最近同步调度失败：" + "；".join(details) + suffix


def _customer_sync_recommendation(sync_status: str, health: dict[str, Any]) -> str:
    if sync_status == "blocked":
        return _customer_credential_recommendation(str(health.get("reason_code") or ""))
    if sync_status == "paused":
        return "确认连接恢复后重新启用调度。"
    if sync_status == "partial":
        return "查看同步范围和字段配置，必要时联系维护人员。"
    if sync_status == "failed":
        return "测试连接并检查同步配置。"
    if sync_status == "pending_sync":
        return "等待下一次调度执行，或手动运行同步验证。"
    if sync_status == "not_synced":
        return "等待调度执行或联系维护人员确认同步计划。"
    return "保持当前配置。"


def _customer_health_message(
    connection_status: str,
    sync_status: str,
    credential: dict[str, Any],
    sync: dict[str, Any],
) -> str:
    if connection_status in {"blocked", "attention"}:
        return str(credential.get("message") or "数据源连接需要关注。")
    if connection_status == "not_configured":
        return str(credential.get("message") or "暂未配置凭据。")
    if sync_status in {"blocked", "paused", "failed", "partial"}:
        return str(sync.get("failure_reason") or "数据同步需要关注。")
    if sync_status == "pending_sync":
        return "凭据已恢复，等待下一次同步验证。"
    if connection_status == "disabled":
        return "数据源已停用。"
    if sync_status == "not_synced":
        return "数据源已接入，暂未产生同步结果。"
    return "数据源连接和同步状态正常。"


def _customer_data_source_actions(
    connector_id: str,
    health: dict[str, Any],
    credential: dict[str, Any],
    schedules: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    actions = [
        {
            "id": "test_connection",
            "kind": "test_connection",
            "label": "测试连接",
            "connector_id": connector_id,
            "requires_confirmation": False,
        }
    ]
    if (
        credential.get("state") in {"expired", "expiring_soon", "failed", "missing", "pending_test", "not_configured"}
        and _credential_has_editable_fields(credential)
    ):
        actions.append(
            {
                "id": "update_credentials",
                "kind": "update_credentials",
                "label": "更新凭据",
                "connector_id": connector_id,
                "profile_id": health.get("profile_id"),
                "requires_confirmation": True,
            }
        )
    for schedule in schedules:
        if not schedule.get("id"):
            continue
        if schedule.get("status") == "paused" or not schedule.get("enabled"):
            actions.append(
                {
                    "id": f"resume_schedule:{schedule.get('id')}",
                    "kind": "resume_schedule",
                    "label": "恢复调度",
                    "connector_id": connector_id,
                    "schedule_id": schedule.get("id"),
                    "requires_confirmation": True,
                }
            )
        elif schedule.get("enabled"):
            actions.append(
                {
                    "id": f"pause_schedule:{schedule.get('id')}",
                    "kind": "pause_schedule",
                    "label": "暂停调度",
                    "connector_id": connector_id,
                    "schedule_id": schedule.get("id"),
                    "requires_confirmation": True,
                }
            )
    return actions


def _credential_has_editable_fields(credential: dict[str, Any]) -> bool:
    return any(
        isinstance(field, dict) and not str(field.get("key") or "").startswith("FLOCKS_CONNECTOR_")
        for field in credential.get("fields") or []
    )


def _customer_operation_events(
    events: list[Any],
    *,
    data_sources: list[dict[str, Any]],
    limit: int,
) -> list[dict[str, Any]]:
    name_by_id = {str(item.get("id")): str(item.get("name") or item.get("id")) for item in data_sources}
    results = []
    for event in events:
        if not isinstance(event, dict) or event.get("status") != "open":
            continue
        connector_id = str(event.get("connector_id") or "")
        kind = str(event.get("kind") or "")
        message, recommendation = _customer_event_message(kind, event)
        results.append(
            {
                "id": event.get("id"),
                "kind": kind,
                "label": _customer_event_label(kind),
                "severity": event.get("severity") or "info",
                "connector_id": connector_id,
                "connector_name": name_by_id.get(connector_id, connector_id),
                "profile_id": event.get("profile_id"),
                "schedule_id": event.get("schedule_id"),
                "created_at": event.get("created_at"),
                "last_seen_at": event.get("last_seen_at"),
                "message": message,
                "recommended_action": recommendation,
            }
        )
    results.sort(key=lambda item: str(item.get("last_seen_at") or item.get("created_at") or ""), reverse=True)
    return results[: max(0, int(limit))]


def _customer_event_label(kind: str) -> str:
    labels = {
        "credential_expiring_soon": "凭据即将过期",
        "credential_expired": "凭据已过期",
        "sync_blocked": "同步被阻断",
        "schedule_policy_paused": "调度已暂停",
        "credential_remediation_requested": "已请求凭据处理",
    }
    return labels.get(kind, "数据源异常")


def _customer_event_message(kind: str, event: dict[str, Any]) -> tuple[str, str]:
    if kind == "credential_expiring_soon":
        return ("凭据即将过期，请在过期前更新凭据。", "更新凭据并测试连接。")
    if kind == "credential_expired":
        return ("凭据已过期，相关同步可能无法继续。", "立即更新凭据并恢复调度。")
    if kind == "sync_blocked":
        return ("数据同步被阻断，请先处理凭据或连接问题。", "按提示修复后测试连接。")
    if kind == "schedule_policy_paused":
        return ("同步调度已暂停，避免持续失败。", "确认连接恢复后重新启用调度。")
    if kind == "credential_remediation_requested":
        return ("已发起凭据处理请求，请跟进凭据更新结果。", "等待处理完成后测试连接。")
    severity = str(event.get("severity") or "info")
    return (f"数据源存在 {severity} 级别异常，请检查接入状态。", "查看数据源健康状态。")


def _customer_trend(raw_trend: Any, *, trend_days: int) -> list[dict[str, Any]]:
    window = max(1, min(14, int(trend_days or 14)))
    items = raw_trend if isinstance(raw_trend, list) else []
    trend = []
    for item in items[-window:]:
        if not isinstance(item, dict):
            continue
        trend.append(
            {
                "date": item.get("date"),
                "expiry_risks": _dashboard_int(item.get("expiry_risks")),
                "sync_blocked": _dashboard_int(item.get("blocked_runs")),
                "paused_schedules": _dashboard_int(item.get("policy_paused_schedules")),
                "recoveries": _dashboard_int(item.get("recoveries")),
            }
        )
    return trend


def _build_operations_dashboard(
    diagnostics: dict[str, Any],
    *,
    operations_registry_path: Path | None,
    sync_run_registry_path: Path | None,
    sync_schedule_registry_path: Path | None,
) -> dict[str, Any]:
    checked_at = datetime.now(UTC)
    operations_registry = load_connector_operations_registry(operations_registry_path)
    sync_run_registry = load_connector_sync_run_registry(sync_run_registry_path)
    sync_schedule_registry = load_connector_sync_schedule_registry(sync_schedule_registry_path)
    events = [item for item in operations_registry.get("events") or [] if isinstance(item, dict)]
    bulk_runs = [item for item in operations_registry.get("bulk_runs") or [] if isinstance(item, dict)]
    sync_runs = [item for item in sync_run_registry.get("runs") or [] if isinstance(item, dict)]
    schedule_audit = [item for item in sync_schedule_registry.get("audit") or [] if isinstance(item, dict)]
    schedules = [item for item in diagnostics.get("sync_schedules") or [] if isinstance(item, dict)]
    settings = operations_registry.get("settings") if isinstance(operations_registry.get("settings"), dict) else {}
    expiry_monitor = settings.get("expiry_monitor") if isinstance(settings.get("expiry_monitor"), dict) else {}
    expiry_warning_days = _dashboard_int(expiry_monitor.get("days"), default=14)
    expiry = _credential_expiry_dashboard(
        diagnostics.get("credential_bindings") or [],
        warning_days=expiry_warning_days,
        checked_at=checked_at,
    )
    mttr = _operations_mttr_dashboard(events, schedule_audit)
    bulk = _operations_bulk_dashboard(bulk_runs)
    current = {
        "expiry_risks": expiry["expiry_risks"],
        "expired_profiles": expiry["expired_profiles"],
        "expiring_profiles": expiry["expiring_profiles"],
        "blocked_runs": sum(1 for run in sync_runs if run.get("status") == "blocked"),
        "policy_paused_schedules": sum(1 for schedule in schedules if schedule.get("policy_state") == "paused"),
        "open_events": sum(1 for event in events if event.get("status") == "open"),
        "bulk_runs": bulk["runs"],
        "average_recovery_seconds": mttr["seconds"],
    }
    trend = _operations_trend_dashboard(
        events,
        sync_runs,
        schedule_audit,
        bulk_runs,
        checked_at=checked_at,
        window_days=14,
    )
    _apply_expiry_monitor_to_trend(trend, expiry_monitor)
    return {
        "version": "connector.operations.dashboard.v1",
        "checked_at": checked_at.isoformat(),
        "window_days": 14,
        "expiry_warning_days": expiry_warning_days,
        "current": current,
        "mttr": mttr,
        "bulk": bulk,
        "trend": trend,
    }


def _credential_expiry_dashboard(
    credential_bindings: list[Any],
    *,
    warning_days: int,
    checked_at: datetime,
) -> dict[str, int]:
    warning_at = checked_at + timedelta(days=max(0, int(warning_days)))
    expired = 0
    expiring = 0
    for binding in credential_bindings:
        if not isinstance(binding, dict):
            continue
        for profile in binding.get("profiles") or []:
            if not isinstance(profile, dict):
                continue
            expires_at = _parse_datetime(profile.get("expires_at"))
            status = str(profile.get("status") or "")
            if status == "expired" or (expires_at is not None and expires_at <= checked_at):
                expired += 1
            elif expires_at is not None and expires_at <= warning_at:
                expiring += 1
    return {
        "expiry_risks": expired + expiring,
        "expired_profiles": expired,
        "expiring_profiles": expiring,
    }


def _operations_bulk_dashboard(bulk_runs: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(bulk_runs, key=lambda item: str(item.get("created_at") or ""), reverse=True)
    by_action: dict[str, dict[str, Any]] = {}
    requested = succeeded = failed = 0
    for run in bulk_runs:
        action = str(run.get("action") or "unknown")
        stats = by_action.setdefault(
            action,
            {"runs": 0, "requested": 0, "succeeded": 0, "failed": 0, "success_rate": None},
        )
        run_requested = _dashboard_int(run.get("requested"))
        run_succeeded = _dashboard_int(run.get("succeeded"))
        run_failed = _dashboard_int(run.get("failed"))
        requested += run_requested
        succeeded += run_succeeded
        failed += run_failed
        stats["runs"] += 1
        stats["requested"] += run_requested
        stats["succeeded"] += run_succeeded
        stats["failed"] += run_failed
    for stats in by_action.values():
        stats["success_rate"] = _dashboard_rate(stats["succeeded"], stats["requested"])
    latest = ordered[0] if ordered else None
    latest_run = None
    if latest is not None:
        latest_run = {
            "id": latest.get("id"),
            "action": latest.get("action"),
            "requested": _dashboard_int(latest.get("requested")),
            "succeeded": _dashboard_int(latest.get("succeeded")),
            "failed": _dashboard_int(latest.get("failed")),
            "created_at": latest.get("created_at"),
            "actor": latest.get("actor"),
        }
    return {
        "runs": len(bulk_runs),
        "requested": requested,
        "succeeded": succeeded,
        "failed": failed,
        "success_rate": _dashboard_rate(succeeded, requested),
        "latest_run": latest_run,
        "by_action": by_action,
    }


def _operations_mttr_dashboard(events: list[dict[str, Any]], schedule_audit: list[dict[str, Any]]) -> dict[str, Any]:
    event_durations: list[float] = []
    for event in events:
        created_at = _parse_datetime(event.get("created_at"))
        acknowledged_at = _parse_datetime(event.get("acknowledged_at"))
        if created_at is not None and acknowledged_at is not None and acknowledged_at >= created_at:
            event_durations.append((acknowledged_at - created_at).total_seconds())

    schedule_durations: list[float] = []
    open_pauses: dict[str, datetime] = {}
    ordered_audit = sorted(schedule_audit, key=lambda item: str(item.get("created_at") or ""))
    for item in ordered_audit:
        schedule_id = str(item.get("schedule_id") or "")
        if not schedule_id:
            continue
        created_at = _parse_datetime(item.get("created_at"))
        if created_at is None:
            continue
        action = str(item.get("action") or "")
        if action == "policy_pause":
            open_pauses[schedule_id] = created_at
        elif action == "policy_recovered" and schedule_id in open_pauses:
            paused_at = open_pauses.pop(schedule_id)
            if created_at >= paused_at:
                schedule_durations.append((created_at - paused_at).total_seconds())

    durations = event_durations + schedule_durations
    average_seconds = round(sum(durations) / len(durations), 2) if durations else None
    return {
        "seconds": average_seconds,
        "samples": len(durations),
        "event_samples": len(event_durations),
        "schedule_samples": len(schedule_durations),
    }


def _operations_trend_dashboard(
    events: list[dict[str, Any]],
    sync_runs: list[dict[str, Any]],
    schedule_audit: list[dict[str, Any]],
    bulk_runs: list[dict[str, Any]],
    *,
    checked_at: datetime,
    window_days: int,
) -> list[dict[str, Any]]:
    start = checked_at.date() - timedelta(days=max(1, int(window_days)) - 1)
    buckets: dict[str, dict[str, Any]] = {}
    for offset in range(max(1, int(window_days))):
        date_key = (start + timedelta(days=offset)).isoformat()
        buckets[date_key] = {
            "date": date_key,
            "expiry_risks": 0,
            "blocked_runs": 0,
            "policy_paused_schedules": 0,
            "recoveries": 0,
            "bulk_requested": 0,
            "bulk_succeeded": 0,
            "bulk_failed": 0,
            "operation_events": 0,
        }

    def add(timestamp: Any, field: str, amount: int = 1) -> None:
        date_key = _date_key(timestamp)
        if date_key in buckets:
            buckets[date_key][field] += amount

    for event in events:
        event_time = event.get("created_at") or event.get("last_seen_at")
        add(event_time, "operation_events")
        if event.get("kind") in {"credential_expiring_soon", "credential_expired"}:
            add(event_time, "expiry_risks")

    for run in sync_runs:
        if run.get("status") == "blocked":
            add(run.get("started_at") or run.get("finished_at"), "blocked_runs")

    for item in schedule_audit:
        action = str(item.get("action") or "")
        if action == "policy_pause":
            add(item.get("created_at"), "policy_paused_schedules")
        elif action == "policy_recovered":
            add(item.get("created_at"), "recoveries")

    for run in bulk_runs:
        add(run.get("created_at"), "bulk_requested", _dashboard_int(run.get("requested")))
        add(run.get("created_at"), "bulk_succeeded", _dashboard_int(run.get("succeeded")))
        add(run.get("created_at"), "bulk_failed", _dashboard_int(run.get("failed")))

    return [buckets[key] for key in sorted(buckets)]


def _apply_expiry_monitor_to_trend(trend: list[dict[str, Any]], expiry_monitor: dict[str, Any]) -> None:
    last_result = expiry_monitor.get("last_result") if isinstance(expiry_monitor.get("last_result"), dict) else {}
    if not last_result:
        return
    date_key = _date_key(expiry_monitor.get("last_run_at"))
    matched = _dashboard_int(last_result.get("matched"))
    if matched <= 0:
        matched = _dashboard_int(last_result.get("expired")) + _dashboard_int(last_result.get("expiring_soon"))
    if not date_key or matched <= 0:
        return
    for bucket in trend:
        if bucket.get("date") == date_key:
            bucket["expiry_risks"] = max(_dashboard_int(bucket.get("expiry_risks")), matched)
            return


def _date_key(value: Any) -> str | None:
    parsed = _parse_datetime(value)
    return parsed.date().isoformat() if parsed else None


def _dashboard_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _dashboard_rate(succeeded: int, requested: int) -> float | None:
    if requested <= 0:
        return None
    return round(succeeded / requested, 4)


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


connector_registry = ConnectorRegistry()


def get_mock_connector_id() -> str:
    return MOCK_CONNECTOR_ID


def get_replay_connector_id() -> str:
    return REPLAY_CONNECTOR_ID
