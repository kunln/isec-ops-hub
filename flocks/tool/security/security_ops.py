"""Security Extension tools for agents."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flocks.security.connectors import connector_registry
from flocks.security.correlation import correlate_alert
from flocks.security.prioritization import prioritize_vulnerabilities
from flocks.security.profile import build_asset_risk_profile
from flocks.security.report import generate_incident_report
from flocks.security.schemas import IncidentCreate, SecurityListFilters
from flocks.security.store import default_store
from flocks.security.triage import triage_alert
from flocks.tool.registry import (
    ParameterType,
    ToolCategory,
    ToolContext,
    ToolParameter,
    ToolRegistry,
    ToolResult,
)


def _dump_items(items: list[Any]) -> list[dict[str, Any]]:
    return [item.model_dump(mode="json") if hasattr(item, "model_dump") else item for item in items]


def _ok(title: str, output: Any, **metadata: Any) -> ToolResult:
    return ToolResult(success=True, title=title, output=output, metadata=metadata)


def _fail(message: str) -> ToolResult:
    return ToolResult(success=False, error=message)


def _filters(**kwargs: Any) -> SecurityListFilters:
    data = {key: value for key, value in kwargs.items() if value not in (None, "")}
    if "limit" not in data:
        data["limit"] = 50
    return SecurityListFilters(**data)


@ToolRegistry.register_function(
    name="security_connector_list",
    description="List standardized security connectors and their manifest metadata.",
    description_cn="列出标准化安全连接器及其 Manifest 元数据。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "integration"],
    parameters=[],
)
async def security_connector_list(ctx: ToolContext) -> ToolResult:
    connectors = connector_registry.list()
    return _ok("Security connectors", {"items": _dump_items(connectors), "count": len(connectors)})


@ToolRegistry.register_function(
    name="security_connector_package_diagnostics",
    description="Inspect connector package roots, manifest files, adapter contracts, and mapping contracts.",
    description_cn="检查连接器 package 目录、manifest、adapter 契约和 mapping 契约诊断信息。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "package", "diagnostics"],
    parameters=[],
)
async def security_connector_package_diagnostics(ctx: ToolContext) -> ToolResult:
    diagnostics = await connector_registry.package_diagnostics()
    return _ok("Security connector package diagnostics", diagnostics)


@ToolRegistry.register_function(
    name="security_connector_package_install",
    description="Install a validated connector package from a local package directory into the installed connector registry.",
    description_cn="从本地 package 目录安装已校验的连接器 package，写入已安装连接器 registry。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "package", "install"],
    parameters=[
        ToolParameter(name="package_root", type=ParameterType.STRING, description="Local connector package directory."),
        ToolParameter(name="enabled", type=ParameterType.BOOLEAN, required=False, default=False, description="Enable after install."),
    ],
)
async def security_connector_package_install(ctx: ToolContext, package_root: str, enabled: bool = False) -> ToolResult:
    try:
        record = await connector_registry.install_package(package_root, enabled=enabled)
    except ValueError as exc:
        return _fail(str(exc))
    return _ok("Security connector package installed", record, package_id=record.get("id"))


@ToolRegistry.register_function(
    name="security_connector_package_stage_upload",
    description="Stage an uploaded connector package archive from a local .zip, .tar.gz, or .tgz artifact and validate it.",
    description_cn="从本地 .zip、.tar.gz 或 .tgz 压缩包暂存连接器 package 并执行校验。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "package", "staging", "upload"],
    parameters=[
        ToolParameter(name="artifact_path", type=ParameterType.STRING, description="Local connector package archive path."),
    ],
)
async def security_connector_package_stage_upload(ctx: ToolContext, artifact_path: str) -> ToolResult:
    path = Path(artifact_path).expanduser()
    if not path.is_file():
        return _fail(f"Connector package artifact not found: {artifact_path}")
    try:
        record = await connector_registry.upload_package_artifact(path.name, path.read_bytes())
    except (OSError, ValueError) as exc:
        return _fail(str(exc))
    return _ok("Security connector package staged", record, staging_id=record.get("id"))


@ToolRegistry.register_function(
    name="security_connector_package_stage_validate",
    description="Revalidate one staged connector package.",
    description_cn="重新校验一个暂存中的连接器 package。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "package", "staging", "validate"],
    parameters=[
        ToolParameter(name="staging_id", type=ParameterType.STRING, description="Staged connector package ID."),
    ],
)
async def security_connector_package_stage_validate(ctx: ToolContext, staging_id: str) -> ToolResult:
    try:
        record = await connector_registry.validate_staging_package(staging_id)
    except ValueError as exc:
        return _fail(str(exc))
    return _ok("Security connector package staging validated", record, staging_id=staging_id)


@ToolRegistry.register_function(
    name="security_connector_package_stage_install",
    description="Install one validated staged connector package into the managed connector install store.",
    description_cn="将一个已校验的暂存连接器 package 安装到受管安装仓库。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "package", "staging", "install"],
    parameters=[
        ToolParameter(name="staging_id", type=ParameterType.STRING, description="Staged connector package ID."),
        ToolParameter(name="enabled", type=ParameterType.BOOLEAN, required=False, default=False, description="Enable after install."),
    ],
)
async def security_connector_package_stage_install(ctx: ToolContext, staging_id: str, enabled: bool = False) -> ToolResult:
    try:
        record = await connector_registry.install_staging_package(staging_id, enabled=enabled)
    except ValueError as exc:
        return _fail(str(exc))
    return _ok("Security connector package staged install completed", record, package_id=record.get("id"))


@ToolRegistry.register_function(
    name="security_connector_package_stage_discard",
    description="Discard one staged connector package artifact and remove its extracted staging files.",
    description_cn="丢弃一个暂存连接器 package，并删除其解包暂存文件。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "package", "staging", "discard"],
    parameters=[
        ToolParameter(name="staging_id", type=ParameterType.STRING, description="Staged connector package ID."),
    ],
)
async def security_connector_package_stage_discard(ctx: ToolContext, staging_id: str) -> ToolResult:
    try:
        record = connector_registry.discard_staging_package(staging_id)
    except ValueError as exc:
        return _fail(str(exc))
    return _ok("Security connector package staging discarded", record, staging_id=staging_id)


@ToolRegistry.register_function(
    name="security_connector_package_enable",
    description="Enable one installed connector package. Runtime reloads it only when validation and hash checks pass.",
    description_cn="启用一个已安装连接器 package；仅当校验和 hash 检查通过后加载到运行时。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "package", "enable"],
    parameters=[
        ToolParameter(name="package_id", type=ParameterType.STRING, description="Connector package ID."),
    ],
)
async def security_connector_package_enable(ctx: ToolContext, package_id: str) -> ToolResult:
    try:
        record = await connector_registry.enable_package(package_id)
    except ValueError as exc:
        return _fail(str(exc))
    return _ok("Security connector package enabled", record, package_id=package_id)


@ToolRegistry.register_function(
    name="security_connector_package_disable",
    description="Disable one installed connector package and remove it from connector runtime registration.",
    description_cn="禁用一个已安装连接器 package，并从连接器运行时注册中移除。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "package", "disable"],
    parameters=[
        ToolParameter(name="package_id", type=ParameterType.STRING, description="Connector package ID."),
    ],
)
async def security_connector_package_disable(ctx: ToolContext, package_id: str) -> ToolResult:
    try:
        record = connector_registry.disable_package(package_id)
    except ValueError as exc:
        return _fail(str(exc))
    return _ok("Security connector package disabled", record, package_id=package_id)


@ToolRegistry.register_function(
    name="security_connector_package_uninstall",
    description="Uninstall one connector package from the runtime registry while preserving lifecycle audit history.",
    description_cn="从运行时 registry 卸载一个连接器 package，同时保留生命周期审计历史。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "package", "uninstall"],
    parameters=[
        ToolParameter(name="package_id", type=ParameterType.STRING, description="Connector package ID."),
    ],
)
async def security_connector_package_uninstall(ctx: ToolContext, package_id: str) -> ToolResult:
    try:
        record = connector_registry.uninstall_package(package_id)
    except ValueError as exc:
        return _fail(str(exc))
    return _ok("Security connector package uninstalled", record, package_id=package_id)


@ToolRegistry.register_function(
    name="security_connector_package_rollback",
    description="Rollback one connector package to the latest restorable installed version and enable it.",
    description_cn="将一个连接器 package 回滚到最近可恢复的已安装版本并启用。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "package", "rollback"],
    parameters=[
        ToolParameter(name="package_id", type=ParameterType.STRING, description="Connector package ID."),
    ],
)
async def security_connector_package_rollback(ctx: ToolContext, package_id: str) -> ToolResult:
    try:
        record = await connector_registry.rollback_package(package_id)
    except ValueError as exc:
        return _fail(str(exc))
    return _ok("Security connector package rolled back", record, package_id=package_id)


@ToolRegistry.register_function(
    name="security_connector_credentials_bind",
    description="Bind runtime environment values and secrets for one connector package HTTP adapter.",
    description_cn="为一个连接器 package HTTP adapter 绑定运行时环境值和密钥。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "credential", "runtime"],
    parameters=[
        ToolParameter(name="connector_id", type=ParameterType.STRING, description="Connector ID."),
        ToolParameter(name="values", type=ParameterType.OBJECT, description="Environment variable values for the connector runtime."),
        ToolParameter(
            name="secret_keys",
            type=ParameterType.ARRAY,
            required=False,
            default=[],
            description="Environment variable names that must be stored as secrets.",
        ),
        ToolParameter(name="profile_id", type=ParameterType.STRING, required=False, default="default", description="Credential profile ID."),
        ToolParameter(name="profile_name", type=ParameterType.STRING, required=False, default="", description="Optional credential profile name."),
        ToolParameter(name="make_active", type=ParameterType.BOOLEAN, required=False, default=True, description="Make this profile active after binding."),
        ToolParameter(name="expires_at", type=ParameterType.STRING, required=False, default="", description="Optional ISO timestamp when the profile expires."),
    ],
)
async def security_connector_credentials_bind(
    ctx: ToolContext,
    connector_id: str,
    values: dict[str, Any],
    secret_keys: list[str] | None = None,
    profile_id: str = "default",
    profile_name: str = "",
    make_active: bool = True,
    expires_at: str = "",
) -> ToolResult:
    try:
        string_values = {str(key): str(value) for key, value in values.items()}
        binding = await connector_registry.bind_credentials_and_test(
            connector_id,
            string_values,
            secret_keys=secret_keys or [],
            profile_id=profile_id or "default",
            profile_name=profile_name or None,
            make_active=make_active,
            expires_at=expires_at or None,
        )
    except ValueError as exc:
        return _fail(str(exc))
    return _ok("Security connector credentials bound", binding, connector_id=connector_id)


@ToolRegistry.register_function(
    name="security_connector_credentials_list",
    description="List connector credential binding summaries without returning secret values.",
    description_cn="列出连接器凭据绑定摘要，不返回密钥明文。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "credential", "runtime"],
    parameters=[],
)
async def security_connector_credentials_list(ctx: ToolContext) -> ToolResult:
    bindings = connector_registry.list_credential_bindings()
    return _ok("Security connector credential bindings", {"items": bindings, "count": len(bindings)})


@ToolRegistry.register_function(
    name="security_connector_credentials_rotate",
    description="Rotate one connector credential profile, update secrets, test it, and optionally activate it.",
    description_cn="轮换一个连接器凭据 profile，更新密钥并测试，可选择设为生效 profile。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "credential", "rotation"],
    parameters=[
        ToolParameter(name="connector_id", type=ParameterType.STRING, description="Connector ID."),
        ToolParameter(name="profile_id", type=ParameterType.STRING, description="Credential profile ID."),
        ToolParameter(name="values", type=ParameterType.OBJECT, description="Environment variable values for this profile."),
        ToolParameter(name="secret_keys", type=ParameterType.ARRAY, required=False, default=[], description="Environment variable names stored as secrets."),
        ToolParameter(name="make_active", type=ParameterType.BOOLEAN, required=False, default=True, description="Make this profile active after rotation."),
        ToolParameter(name="expires_at", type=ParameterType.STRING, required=False, default="", description="Optional ISO timestamp when the profile expires."),
    ],
)
async def security_connector_credentials_rotate(
    ctx: ToolContext,
    connector_id: str,
    profile_id: str,
    values: dict[str, Any],
    secret_keys: list[str] | None = None,
    make_active: bool = True,
    expires_at: str = "",
) -> ToolResult:
    try:
        string_values = {str(key): str(value) for key, value in values.items()}
        binding = await connector_registry.rotate_credentials(
            connector_id,
            profile_id,
            string_values,
            secret_keys=secret_keys or [],
            make_active=make_active,
            expires_at=expires_at or None,
        )
    except ValueError as exc:
        return _fail(str(exc))
    return _ok("Security connector credentials rotated", binding, connector_id=connector_id, profile_id=profile_id)


@ToolRegistry.register_function(
    name="security_connector_credentials_activate",
    description="Activate one connector credential profile for runtime preview and sync.",
    description_cn="将一个连接器凭据 profile 设为运行时预览和同步的生效 profile。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "credential", "runtime"],
    parameters=[
        ToolParameter(name="connector_id", type=ParameterType.STRING, description="Connector ID."),
        ToolParameter(name="profile_id", type=ParameterType.STRING, description="Credential profile ID."),
    ],
)
async def security_connector_credentials_activate(ctx: ToolContext, connector_id: str, profile_id: str) -> ToolResult:
    try:
        binding = connector_registry.activate_credential_profile(connector_id, profile_id)
    except ValueError as exc:
        return _fail(str(exc))
    return _ok("Security connector credential profile activated", binding, connector_id=connector_id, profile_id=profile_id)


@ToolRegistry.register_function(
    name="security_connector_credentials_test",
    description="Test one connector with a specific credential profile and record the result.",
    description_cn="使用指定凭据 profile 测试连接器并记录结果。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "credential", "test"],
    parameters=[
        ToolParameter(name="connector_id", type=ParameterType.STRING, description="Connector ID."),
        ToolParameter(name="profile_id", type=ParameterType.STRING, description="Credential profile ID."),
    ],
)
async def security_connector_credentials_test(ctx: ToolContext, connector_id: str, profile_id: str) -> ToolResult:
    try:
        result = await connector_registry.test_credential_profile(connector_id, profile_id)
    except ValueError as exc:
        return _fail(str(exc))
    output = result.model_dump(mode="json") if hasattr(result, "model_dump") else result
    return _ok("Security connector credential profile tested", output, connector_id=connector_id, profile_id=profile_id)


@ToolRegistry.register_function(
    name="security_connector_sync",
    description="Run one connector capability, map the payload, and write normalized objects into the Security Store.",
    description_cn="执行一个连接器能力，将载荷映射并写入安全对象存储。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "sync", "analysis"],
    parameters=[
        ToolParameter(name="connector_id", type=ParameterType.STRING, description="Connector ID."),
        ToolParameter(name="capability", type=ParameterType.STRING, description="Connector capability, e.g. asset.search."),
        ToolParameter(
            name="mode",
            type=ParameterType.STRING,
            required=False,
            default="full",
            description="Sync mode: full or incremental.",
        ),
        ToolParameter(
            name="reset_cursor",
            type=ParameterType.BOOLEAN,
            required=False,
            default=False,
            description="Reset this connector/capability cursor before running sync.",
        ),
        ToolParameter(
            name="credential_profile_id",
            type=ParameterType.STRING,
            required=False,
            default="",
            description="Optional credential profile ID to use for this run.",
        ),
    ],
)
async def security_connector_sync(
    ctx: ToolContext,
    connector_id: str,
    capability: str,
    mode: str = "full",
    reset_cursor: bool = False,
    credential_profile_id: str = "",
) -> ToolResult:
    try:
        run = await connector_registry.sync(
            connector_id,
            capability,
            mode=mode,
            reset_cursor=reset_cursor,
            credential_profile_id=credential_profile_id or None,
        )
    except ValueError as exc:
        return _fail(str(exc))
    return _ok(
        "Security connector sync completed",
        run,
        connector_id=connector_id,
        capability=capability,
        mode=mode,
    )


@ToolRegistry.register_function(
    name="security_connector_sync_runs",
    description="List recent connector sync runs and write counts.",
    description_cn="列出最近的连接器同步运行记录和写入数量。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "sync", "analysis"],
    parameters=[
        ToolParameter(name="connector_id", type=ParameterType.STRING, required=False, default="", description="Optional connector ID."),
        ToolParameter(name="limit", type=ParameterType.INTEGER, required=False, default=50, description="Maximum runs to return."),
    ],
)
async def security_connector_sync_runs(ctx: ToolContext, connector_id: str = "", limit: int = 50) -> ToolResult:
    runs = connector_registry.list_sync_runs(connector_id or None, limit=limit)
    return _ok("Security connector sync runs", {"items": runs, "count": len(runs)}, connector_id=connector_id or None)


@ToolRegistry.register_function(
    name="security_connector_sync_active_runs",
    description="List currently running connector sync operations.",
    description_cn="列出当前正在运行的连接器同步任务。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "sync", "runtime"],
    parameters=[
        ToolParameter(name="connector_id", type=ParameterType.STRING, required=False, default="", description="Optional connector ID."),
        ToolParameter(name="capability", type=ParameterType.STRING, required=False, default="", description="Optional connector capability."),
    ],
)
async def security_connector_sync_active_runs(ctx: ToolContext, connector_id: str = "", capability: str = "") -> ToolResult:
    runs = connector_registry.list_active_sync_runs(connector_id or None, capability or None)
    return _ok(
        "Security connector active sync runs",
        {"items": runs, "count": len(runs)},
        connector_id=connector_id or None,
        capability=capability or None,
    )


@ToolRegistry.register_function(
    name="security_connector_sync_cancel",
    description="Request cancellation for active connector sync runs by run ID or connector/capability.",
    description_cn="按运行 ID 或连接器/能力请求取消正在运行的连接器同步。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "sync", "runtime"],
    parameters=[
        ToolParameter(name="run_id", type=ParameterType.STRING, required=False, default="", description="Optional sync run ID."),
        ToolParameter(name="connector_id", type=ParameterType.STRING, required=False, default="", description="Optional connector ID."),
        ToolParameter(name="capability", type=ParameterType.STRING, required=False, default="", description="Optional connector capability."),
    ],
)
async def security_connector_sync_cancel(
    ctx: ToolContext,
    run_id: str = "",
    connector_id: str = "",
    capability: str = "",
) -> ToolResult:
    if run_id:
        result = connector_registry.cancel_sync_run(run_id)
    elif connector_id:
        result = connector_registry.cancel_sync(connector_id, capability or None)
    else:
        return _fail("run_id or connector_id is required")
    return _ok("Security connector sync cancel requested", result)


@ToolRegistry.register_function(
    name="security_connector_sync_cursors",
    description="List connector incremental sync cursors.",
    description_cn="列出连接器增量同步游标。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "sync", "cursor"],
    parameters=[
        ToolParameter(name="connector_id", type=ParameterType.STRING, required=False, default="", description="Optional connector ID."),
    ],
)
async def security_connector_sync_cursors(ctx: ToolContext, connector_id: str = "") -> ToolResult:
    cursors = connector_registry.list_sync_cursors(connector_id or None)
    return _ok("Security connector sync cursors", {"items": cursors, "count": len(cursors)}, connector_id=connector_id or None)


@ToolRegistry.register_function(
    name="security_connector_sync_cursor_reset",
    description="Reset connector incremental sync cursor for one connector and optional capability.",
    description_cn="重置某个连接器及可选能力的增量同步游标。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "sync", "cursor"],
    parameters=[
        ToolParameter(name="connector_id", type=ParameterType.STRING, description="Connector ID."),
        ToolParameter(
            name="capability",
            type=ParameterType.STRING,
            required=False,
            default="",
            description="Optional capability. Empty resets all cursors for the connector.",
        ),
    ],
)
async def security_connector_sync_cursor_reset(ctx: ToolContext, connector_id: str, capability: str = "") -> ToolResult:
    result = connector_registry.reset_sync_cursor(connector_id, capability or None)
    return _ok("Security connector sync cursor reset", result, connector_id=connector_id, capability=capability or None)


@ToolRegistry.register_function(
    name="security_connector_sync_dead_letters",
    description="List connector sync dead-letter records for invalid mapped items.",
    description_cn="列出连接器同步中无效映射项的 dead-letter 记录。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "sync", "quality"],
    parameters=[
        ToolParameter(name="connector_id", type=ParameterType.STRING, required=False, default="", description="Optional connector ID."),
        ToolParameter(name="limit", type=ParameterType.INTEGER, required=False, default=50, description="Maximum records to return."),
    ],
)
async def security_connector_sync_dead_letters(ctx: ToolContext, connector_id: str = "", limit: int = 50) -> ToolResult:
    letters = connector_registry.list_sync_dead_letters(connector_id or None, limit=limit)
    return _ok(
        "Security connector sync dead letters",
        {"items": letters, "count": len(letters)},
        connector_id=connector_id or None,
    )


@ToolRegistry.register_function(
    name="security_connector_sync_dead_letter_replay",
    description="Replay connector sync dead letters without rerunning a full connector sync.",
    description_cn="重放连接器同步死信，不重新执行完整连接器同步。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "sync", "quality", "replay"],
    parameters=[
        ToolParameter(name="ids", type=ParameterType.ARRAY, required=False, description="Optional dead-letter IDs to replay."),
        ToolParameter(name="connector_id", type=ParameterType.STRING, required=False, default="", description="Optional connector ID."),
        ToolParameter(name="limit", type=ParameterType.INTEGER, required=False, default=50, description="Maximum records to replay when IDs are omitted."),
        ToolParameter(name="payload_updates", type=ParameterType.OBJECT, required=False, description="Optional payload patches keyed by dead-letter ID."),
    ],
)
async def security_connector_sync_dead_letter_replay(
    ctx: ToolContext,
    ids: list[str] | None = None,
    connector_id: str = "",
    limit: int = 50,
    payload_updates: dict[str, dict[str, Any]] | None = None,
) -> ToolResult:
    result = await connector_registry.replay_sync_dead_letters(
        ids=ids or [],
        connector_id=connector_id or None,
        limit=limit,
        payload_updates=payload_updates or {},
    )
    return _ok("Security connector sync dead letters replayed", result)


@ToolRegistry.register_function(
    name="security_connector_sync_schedule_upsert",
    description="Create or update a connector sync schedule for one connector capability.",
    description_cn="创建或更新某个连接器能力的同步调度。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "sync", "schedule"],
    parameters=[
        ToolParameter(name="connector_id", type=ParameterType.STRING, description="Connector ID."),
        ToolParameter(name="capability", type=ParameterType.STRING, description="Connector capability, e.g. alert.search."),
        ToolParameter(name="enabled", type=ParameterType.BOOLEAN, required=False, default=False, description="Whether the schedule is enabled."),
        ToolParameter(name="interval_seconds", type=ParameterType.INTEGER, required=False, default=3600, description="Recurring interval in seconds."),
        ToolParameter(name="mode", type=ParameterType.STRING, required=False, default="incremental", description="Default sync mode: incremental or full."),
        ToolParameter(name="full_interval_seconds", type=ParameterType.INTEGER, required=False, default=0, description="Optional full-sync interval in seconds."),
        ToolParameter(name="retry_max_attempts", type=ParameterType.INTEGER, required=False, default=1, description="Maximum attempts per run."),
        ToolParameter(name="retry_backoff_seconds", type=ParameterType.INTEGER, required=False, default=60, description="Retry backoff base seconds."),
        ToolParameter(name="timeout_seconds", type=ParameterType.INTEGER, required=False, default=300, description="Per-attempt timeout seconds."),
        ToolParameter(name="credential_profile_id", type=ParameterType.STRING, required=False, default="", description="Optional credential profile ID to use for scheduled runs."),
    ],
)
async def security_connector_sync_schedule_upsert(
    ctx: ToolContext,
    connector_id: str,
    capability: str,
    enabled: bool = False,
    interval_seconds: int = 3600,
    mode: str = "incremental",
    full_interval_seconds: int = 0,
    retry_max_attempts: int = 1,
    retry_backoff_seconds: int = 60,
    timeout_seconds: int = 300,
    credential_profile_id: str = "",
) -> ToolResult:
    try:
        schedule = connector_registry.upsert_sync_schedule(
            connector_id,
            capability,
            enabled=enabled,
            interval_seconds=interval_seconds,
            mode=mode,
            full_interval_seconds=full_interval_seconds or None,
            retry_max_attempts=retry_max_attempts,
            retry_backoff_seconds=retry_backoff_seconds,
            timeout_seconds=timeout_seconds,
            credential_profile_id=credential_profile_id or None,
        )
    except ValueError as exc:
        return _fail(str(exc))
    return _ok("Security connector sync schedule saved", schedule, connector_id=connector_id, capability=capability)


@ToolRegistry.register_function(
    name="security_connector_sync_schedules",
    description="List connector sync schedules and operational status.",
    description_cn="列出连接器同步调度及运行状态。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "sync", "schedule"],
    parameters=[
        ToolParameter(name="connector_id", type=ParameterType.STRING, required=False, default="", description="Optional connector ID."),
    ],
)
async def security_connector_sync_schedules(ctx: ToolContext, connector_id: str = "") -> ToolResult:
    schedules = connector_registry.list_sync_schedules(connector_id or None)
    return _ok("Security connector sync schedules", {"items": schedules, "count": len(schedules)}, connector_id=connector_id or None)


@ToolRegistry.register_function(
    name="security_connector_sync_schedule_run",
    description="Run one connector sync schedule immediately through the orchestrator.",
    description_cn="通过编排器立即运行一个连接器同步调度。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "sync", "schedule"],
    parameters=[
        ToolParameter(name="schedule_id", type=ParameterType.STRING, description="Connector sync schedule ID."),
        ToolParameter(name="mode", type=ParameterType.STRING, required=False, default="", description="Optional mode override: full or incremental."),
    ],
)
async def security_connector_sync_schedule_run(ctx: ToolContext, schedule_id: str, mode: str = "") -> ToolResult:
    try:
        result = await connector_registry.run_sync_schedule(schedule_id, trigger="manual", mode=mode or None)
    except ValueError as exc:
        return _fail(str(exc))
    return _ok("Security connector sync schedule run", result, schedule_id=schedule_id)


@ToolRegistry.register_function(
    name="security_connector_sync_schedule_enable",
    description="Enable one connector sync schedule.",
    description_cn="启用一个连接器同步调度。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "sync", "schedule"],
    parameters=[ToolParameter(name="schedule_id", type=ParameterType.STRING, description="Connector sync schedule ID.")],
)
async def security_connector_sync_schedule_enable(ctx: ToolContext, schedule_id: str) -> ToolResult:
    try:
        schedule = connector_registry.enable_sync_schedule(schedule_id)
    except ValueError as exc:
        return _fail(str(exc))
    return _ok("Security connector sync schedule enabled", schedule, schedule_id=schedule_id)


@ToolRegistry.register_function(
    name="security_connector_sync_schedule_disable",
    description="Disable one connector sync schedule.",
    description_cn="禁用一个连接器同步调度。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "sync", "schedule"],
    parameters=[ToolParameter(name="schedule_id", type=ParameterType.STRING, description="Connector sync schedule ID.")],
)
async def security_connector_sync_schedule_disable(ctx: ToolContext, schedule_id: str) -> ToolResult:
    try:
        schedule = connector_registry.disable_sync_schedule(schedule_id)
    except ValueError as exc:
        return _fail(str(exc))
    return _ok("Security connector sync schedule disabled", schedule, schedule_id=schedule_id)


@ToolRegistry.register_function(
    name="security_connector_sync_schedule_delete",
    description="Delete one connector sync schedule.",
    description_cn="删除一个连接器同步调度。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "sync", "schedule"],
    parameters=[ToolParameter(name="schedule_id", type=ParameterType.STRING, description="Connector sync schedule ID.")],
)
async def security_connector_sync_schedule_delete(ctx: ToolContext, schedule_id: str) -> ToolResult:
    try:
        schedule = connector_registry.delete_sync_schedule(schedule_id)
    except ValueError as exc:
        return _fail(str(exc))
    return _ok("Security connector sync schedule deleted", schedule, schedule_id=schedule_id)


@ToolRegistry.register_function(
    name="security_connector_sync_scheduler_tick",
    description="Run due connector sync schedules once.",
    description_cn="执行一次当前到期的连接器同步调度。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "sync", "schedule"],
    parameters=[],
)
async def security_connector_sync_scheduler_tick(ctx: ToolContext) -> ToolResult:
    result = await connector_registry.run_due_sync_schedules()
    return _ok("Security connector sync scheduler tick", result)


@ToolRegistry.register_function(
    name="security_evidence_graph_get",
    description="Get the current cross-connector entity resolution and evidence graph snapshot.",
    description_cn="获取当前跨连接器实体归一和证据图快照。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "entity", "evidence", "graph"],
    parameters=[],
)
async def security_evidence_graph_get(ctx: ToolContext) -> ToolResult:
    graph = connector_registry.evidence_graph()
    return _ok("Security evidence graph", graph)


@ToolRegistry.register_function(
    name="security_evidence_graph_rebuild",
    description="Rebuild the cross-connector evidence graph from Security Store objects and annotate normalized records.",
    description_cn="基于安全对象存储重建跨连接器证据图，并回写对象的归一化证据索引。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "entity", "evidence", "graph"],
    parameters=[],
)
async def security_evidence_graph_rebuild(ctx: ToolContext) -> ToolResult:
    graph = await connector_registry.rebuild_evidence_graph()
    return _ok("Security evidence graph rebuilt", graph, summary=graph.get("summary"))


@ToolRegistry.register_function(
    name="security_entity_resolution_candidates",
    description="List cross-connector asset merge candidates and unresolved identity conflicts.",
    description_cn="列出跨连接器资产合并候选和未解决的身份冲突。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "entity", "resolution"],
    parameters=[],
)
async def security_entity_resolution_candidates(ctx: ToolContext) -> ToolResult:
    graph = connector_registry.evidence_graph()
    payload = {
        "items": graph.get("merge_candidates") or [],
        "count": len(graph.get("merge_candidates") or []),
        "conflicts": graph.get("conflicts") or [],
        "conflict_count": len(graph.get("conflicts") or []),
        "summary": graph.get("summary") or {},
    }
    return _ok("Security entity resolution candidates", payload)


@ToolRegistry.register_function(
    name="security_connector_get",
    description="Get one standardized security connector manifest by ID.",
    description_cn="按 ID 获取单个标准化安全连接器 Manifest。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "integration"],
    parameters=[
        ToolParameter(name="connector_id", type=ParameterType.STRING, description="Connector ID."),
    ],
)
async def security_connector_get(ctx: ToolContext, connector_id: str) -> ToolResult:
    connector = connector_registry.get(connector_id)
    if connector is None:
        return _fail(f"Connector not found: {connector_id}")
    return _ok("Security connector", connector.model_dump(mode="json"), connector_id=connector_id)


@ToolRegistry.register_function(
    name="security_connector_test_connection",
    description="Test a standardized security connector connection. The MVP mock connector performs no external network call.",
    description_cn="测试标准化安全连接器连接；MVP Mock 连接器不会发起外部网络请求。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "integration", "health"],
    parameters=[
        ToolParameter(name="connector_id", type=ParameterType.STRING, description="Connector ID."),
    ],
)
async def security_connector_test_connection(ctx: ToolContext, connector_id: str) -> ToolResult:
    try:
        result = await connector_registry.test_connection(connector_id)
    except ValueError as exc:
        return _fail(str(exc))
    return _ok("Security connector test", result.model_dump(mode="json"), connector_id=connector_id)


@ToolRegistry.register_function(
    name="security_connector_list_capabilities",
    description="List standardized capability declarations for one security connector.",
    description_cn="列出单个安全连接器声明支持的标准化能力。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "capability"],
    parameters=[
        ToolParameter(name="connector_id", type=ParameterType.STRING, description="Connector ID."),
    ],
)
async def security_connector_list_capabilities(ctx: ToolContext, connector_id: str) -> ToolResult:
    try:
        capabilities = connector_registry.list_capabilities(connector_id)
    except ValueError as exc:
        return _fail(str(exc))
    return _ok(
        "Security connector capabilities",
        {"connector_id": connector_id, "capabilities": [str(item) for item in capabilities]},
        connector_id=connector_id,
    )


@ToolRegistry.register_function(
    name="security_connector_preview",
    description="Preview one connector capability using offline fixture replay when available. Returns raw response, normalized data, and missing-field warnings without writing business objects.",
    description_cn="使用离线 fixture replay 预览连接器能力，返回 raw response、normalized data 和缺失字段告警，不写入业务对象。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "fixture", "preview"],
    parameters=[
        ToolParameter(name="connector_id", type=ParameterType.STRING, description="Connector ID."),
        ToolParameter(name="capability", type=ParameterType.STRING, description="Capability, for example asset.search or alert.search."),
    ],
)
async def security_connector_preview(ctx: ToolContext, connector_id: str, capability: str) -> ToolResult:
    try:
        preview = await connector_registry.preview(connector_id, capability)
    except ValueError as exc:
        return _fail(str(exc))
    return _ok(
        "Security connector preview",
        preview.model_dump(mode="json"),
        connector_id=connector_id,
        capability=capability,
    )


@ToolRegistry.register_function(
    name="security_connector_validate",
    description="Validate one connector's adapter and mapping contracts without writing business objects.",
    description_cn="验证单个连接器的 adapter 与 mapping 契约，不写入业务对象。",
    category=ToolCategory.CUSTOM,
    tags=["security", "connector", "adapter", "mapping", "validate"],
    parameters=[
        ToolParameter(name="connector_id", type=ParameterType.STRING, description="Connector ID."),
    ],
)
async def security_connector_validate(ctx: ToolContext, connector_id: str) -> ToolResult:
    try:
        validation = await connector_registry.validate(connector_id)
    except ValueError as exc:
        return _fail(str(exc))
    return _ok(
        "Security connector validation",
        validation.model_dump(mode="json"),
        connector_id=connector_id,
    )


@ToolRegistry.register_function(
    name="security_asset_search",
    description="Search security assets by keyword, IP, domain, hostname, importance, or exposure level.",
    description_cn="按关键字、IP、域名、主机名、重要性或暴露面查询安全资产。",
    category=ToolCategory.CUSTOM,
    tags=["security", "asset", "risk"],
    parameters=[
        ToolParameter(name="keyword", type=ParameterType.STRING, required=False, description="Keyword matching asset name, business system, owner, tags, or description."),
        ToolParameter(name="ip", type=ParameterType.STRING, required=False, description="Asset IP address."),
        ToolParameter(name="domain", type=ParameterType.STRING, required=False, description="Asset domain."),
        ToolParameter(name="hostname", type=ParameterType.STRING, required=False, description="Asset hostname."),
        ToolParameter(name="importance", type=ParameterType.STRING, required=False, description="low | medium | high | critical."),
        ToolParameter(name="exposure_level", type=ParameterType.STRING, required=False, description="internal | external | unknown."),
        ToolParameter(name="limit", type=ParameterType.INTEGER, required=False, default=50, description="Maximum number of results."),
    ],
)
async def security_asset_search(
    ctx: ToolContext,
    keyword: str | None = None,
    ip: str | None = None,
    domain: str | None = None,
    hostname: str | None = None,
    importance: str | None = None,
    exposure_level: str | None = None,
    limit: int = 50,
) -> ToolResult:
    items = await default_store.list_assets(_filters(
        keyword=keyword,
        ip=ip,
        domain=domain,
        hostname=hostname,
        importance=importance,
        exposure_level=exposure_level,
        limit=limit,
    ))
    return _ok("Security assets", {"items": _dump_items(items), "count": len(items)})


@ToolRegistry.register_function(
    name="security_asset_get",
    description="Get one security asset by ID.",
    description_cn="按 ID 获取单个安全资产。",
    category=ToolCategory.CUSTOM,
    tags=["security", "asset"],
    parameters=[
        ToolParameter(name="asset_id", type=ParameterType.STRING, description="Asset ID."),
    ],
)
async def security_asset_get(ctx: ToolContext, asset_id: str) -> ToolResult:
    asset = await default_store.get_asset(asset_id)
    if asset is None:
        return _fail(f"Asset not found: {asset_id}")
    return _ok("Security asset", asset.model_dump(mode="json"), asset_id=asset_id)


@ToolRegistry.register_function(
    name="security_asset_risk_profile",
    description="Build a full asset risk profile with related vulnerabilities, alerts, incidents, honeypot signals, risk score, evidence, uncertainty, and recommendations.",
    description_cn="生成资产风险画像，包含关联漏洞、告警、事件、诱捕信号、风险评分、证据、不确定性和整改建议。",
    category=ToolCategory.CUSTOM,
    tags=["security", "asset", "risk", "profile"],
    parameters=[
        ToolParameter(name="asset_id", type=ParameterType.STRING, description="Asset ID."),
    ],
)
async def security_asset_risk_profile(ctx: ToolContext, asset_id: str) -> ToolResult:
    try:
        profile = await build_asset_risk_profile(asset_id)
    except ValueError as exc:
        return _fail(str(exc))
    return _ok("Security asset risk profile", profile.model_dump(mode="json"), asset_id=asset_id)


@ToolRegistry.register_function(
    name="security_vulnerability_search",
    description="Search vulnerabilities by asset, CVE, severity, status, or keyword.",
    description_cn="按资产、CVE、严重等级、状态或关键字查询漏洞。",
    category=ToolCategory.CUSTOM,
    tags=["security", "vulnerability", "risk"],
    parameters=[
        ToolParameter(name="asset_id", type=ParameterType.STRING, required=False, description="Related asset ID."),
        ToolParameter(name="cve_id", type=ParameterType.STRING, required=False, description="CVE or placeholder ID."),
        ToolParameter(name="severity", type=ParameterType.STRING, required=False, description="info | low | medium | high | critical."),
        ToolParameter(name="status", type=ParameterType.STRING, required=False, description="Vulnerability status."),
        ToolParameter(name="keyword", type=ParameterType.STRING, required=False, description="Keyword."),
        ToolParameter(name="limit", type=ParameterType.INTEGER, required=False, default=50, description="Maximum number of results."),
    ],
)
async def security_vulnerability_search(
    ctx: ToolContext,
    asset_id: str | None = None,
    cve_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    keyword: str | None = None,
    limit: int = 50,
) -> ToolResult:
    items = await default_store.list_vulnerabilities(_filters(
        asset_id=asset_id,
        cve_id=cve_id,
        severity=severity,
        status=status,
        keyword=keyword,
        limit=limit,
    ))
    return _ok("Security vulnerabilities", {"items": _dump_items(items), "count": len(items)})


@ToolRegistry.register_function(
    name="security_vulnerability_prioritize",
    description="Rank vulnerabilities by severity, CVSS, EPSS, KEV, exploit availability, asset importance, exposure, alerts, and honeypot signals.",
    description_cn="结合严重性、CVSS、EPSS、KEV、可利用性、资产重要性、暴露面、告警和诱捕信号对漏洞排序。",
    category=ToolCategory.CUSTOM,
    tags=["security", "vulnerability", "risk", "priority"],
    parameters=[
        ToolParameter(name="asset_id", type=ParameterType.STRING, required=False, description="Filter by related asset ID."),
        ToolParameter(name="cve_id", type=ParameterType.STRING, required=False, description="Filter by CVE or placeholder ID."),
        ToolParameter(name="severity", type=ParameterType.STRING, required=False, description="info | low | medium | high | critical."),
        ToolParameter(name="status", type=ParameterType.STRING, required=False, description="Vulnerability status."),
        ToolParameter(name="keyword", type=ParameterType.STRING, required=False, description="Keyword."),
        ToolParameter(name="limit", type=ParameterType.INTEGER, required=False, default=50, description="Maximum number of results."),
    ],
)
async def security_vulnerability_prioritize(
    ctx: ToolContext,
    asset_id: str | None = None,
    cve_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    keyword: str | None = None,
    limit: int = 50,
) -> ToolResult:
    priorities = await prioritize_vulnerabilities(_filters(
        asset_id=asset_id,
        cve_id=cve_id,
        severity=severity,
        status=status,
        keyword=keyword,
        limit=limit,
    ))
    return _ok(
        "Security vulnerability priorities",
        {"items": _dump_items(priorities), "count": len(priorities)},
    )


@ToolRegistry.register_function(
    name="security_alert_search",
    description="Search security alerts by asset, source, severity, status, IOC, MITRE technique, or keyword.",
    description_cn="按资产、来源、严重等级、状态、IOC、MITRE 技术或关键字查询告警。",
    category=ToolCategory.CUSTOM,
    tags=["security", "alert", "triage"],
    parameters=[
        ToolParameter(name="asset_id", type=ParameterType.STRING, required=False, description="Related asset ID."),
        ToolParameter(name="source", type=ParameterType.STRING, required=False, description="xdr | edr | ndr | waf | siem | honeypot | scanner | manual | other."),
        ToolParameter(name="severity", type=ParameterType.STRING, required=False, description="info | low | medium | high | critical."),
        ToolParameter(name="status", type=ParameterType.STRING, required=False, description="Alert status."),
        ToolParameter(name="ioc", type=ParameterType.STRING, required=False, description="IOC value."),
        ToolParameter(name="mitre_technique", type=ParameterType.STRING, required=False, description="MITRE ATT&CK technique ID."),
        ToolParameter(name="keyword", type=ParameterType.STRING, required=False, description="Keyword."),
        ToolParameter(name="limit", type=ParameterType.INTEGER, required=False, default=50, description="Maximum number of results."),
    ],
)
async def security_alert_search(
    ctx: ToolContext,
    asset_id: str | None = None,
    source: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    ioc: str | None = None,
    mitre_technique: str | None = None,
    keyword: str | None = None,
    limit: int = 50,
) -> ToolResult:
    items = await default_store.list_alerts(_filters(
        asset_id=asset_id,
        source=source,
        severity=severity,
        status=status,
        ioc=ioc,
        mitre_technique=mitre_technique,
        keyword=keyword,
        limit=limit,
    ))
    return _ok("Security alerts", {"items": _dump_items(items), "count": len(items)})


@ToolRegistry.register_function(
    name="security_alert_get",
    description="Get one security alert by ID.",
    description_cn="按 ID 获取单个安全告警。",
    category=ToolCategory.CUSTOM,
    tags=["security", "alert"],
    parameters=[
        ToolParameter(name="alert_id", type=ParameterType.STRING, description="Alert ID."),
    ],
)
async def security_alert_get(ctx: ToolContext, alert_id: str) -> ToolResult:
    alert = await default_store.get_alert(alert_id)
    if alert is None:
        return _fail(f"Alert not found: {alert_id}")
    return _ok("Security alert", alert.model_dump(mode="json"), alert_id=alert_id)


@ToolRegistry.register_function(
    name="security_alert_triage",
    description="Triage a security alert. By default, creates an incident when escalation is recommended.",
    description_cn="研判安全告警；默认在建议升级时自动创建安全事件。",
    category=ToolCategory.CUSTOM,
    tags=["security", "alert", "triage", "incident"],
    parameters=[
        ToolParameter(name="alert_id", type=ParameterType.STRING, description="Alert ID."),
        ToolParameter(name="create_incident", type=ParameterType.BOOLEAN, required=False, default=True, description="Create an incident when escalation is recommended."),
    ],
)
async def security_alert_triage(
    ctx: ToolContext,
    alert_id: str,
    create_incident: bool = True,
) -> ToolResult:
    try:
        result = await triage_alert(alert_id, create_incident=create_incident)
    except ValueError as exc:
        return _fail(str(exc))
    return _ok("Security alert triage", result.model_dump(mode="json"), alert_id=alert_id)


@ToolRegistry.register_function(
    name="security_correlate_alert",
    description="Correlate one alert with assets, vulnerabilities, related alerts, honeypot events, and risk score.",
    description_cn="对单个告警进行资产、漏洞、相关告警、诱捕事件和风险评分关联分析。",
    category=ToolCategory.CUSTOM,
    tags=["security", "alert", "correlation"],
    parameters=[
        ToolParameter(name="alert_id", type=ParameterType.STRING, description="Alert ID."),
    ],
)
async def security_correlate_alert(ctx: ToolContext, alert_id: str) -> ToolResult:
    try:
        result = await correlate_alert(alert_id)
    except ValueError as exc:
        return _fail(str(exc))
    return _ok("Security alert correlation", result.model_dump(mode="json"), alert_id=alert_id)


@ToolRegistry.register_function(
    name="security_incident_create",
    description="Create a security incident record from investigation context. This does not execute remediation.",
    description_cn="根据研判上下文创建安全事件记录；不会执行真实处置动作。",
    category=ToolCategory.CUSTOM,
    tags=["security", "incident"],
    parameters=[
        ToolParameter(name="title", type=ParameterType.STRING, description="Incident title."),
        ToolParameter(name="severity", type=ParameterType.STRING, required=False, default="medium", description="low | medium | high | critical."),
        ToolParameter(name="summary", type=ParameterType.STRING, required=False, description="Executive summary."),
        ToolParameter(name="analysis", type=ParameterType.STRING, required=False, description="Technical analysis."),
        ToolParameter(name="recommendation", type=ParameterType.STRING, required=False, description="Recommended actions."),
        ToolParameter(name="asset_ids", type=ParameterType.ARRAY, required=False, description="Linked asset IDs."),
        ToolParameter(name="vulnerability_ids", type=ParameterType.ARRAY, required=False, description="Linked vulnerability IDs."),
        ToolParameter(name="alert_ids", type=ParameterType.ARRAY, required=False, description="Linked alert IDs."),
        ToolParameter(name="confidence", type=ParameterType.STRING, required=False, default="medium", description="low | medium | high."),
    ],
)
async def security_incident_create(
    ctx: ToolContext,
    title: str,
    severity: str = "medium",
    summary: str = "",
    analysis: str = "",
    recommendation: str = "",
    asset_ids: list[str] | None = None,
    vulnerability_ids: list[str] | None = None,
    alert_ids: list[str] | None = None,
    confidence: str = "medium",
) -> ToolResult:
    incident = await default_store.create_incident(
        IncidentCreate(
            title=title,
            severity=severity,  # type: ignore[arg-type]
            summary=summary,
            analysis=analysis,
            recommendation=recommendation,
            asset_ids=asset_ids or [],
            vulnerability_ids=vulnerability_ids or [],
            alert_ids=alert_ids or [],
            confidence=confidence,  # type: ignore[arg-type]
            created_by="security_tool",
        )
    )
    return _ok("Security incident created", incident.model_dump(mode="json"), incident_id=incident.id)


@ToolRegistry.register_function(
    name="security_incident_get",
    description="Get one security incident by ID.",
    description_cn="按 ID 获取单个安全事件。",
    category=ToolCategory.CUSTOM,
    tags=["security", "incident"],
    parameters=[
        ToolParameter(name="incident_id", type=ParameterType.STRING, description="Incident ID."),
    ],
)
async def security_incident_get(ctx: ToolContext, incident_id: str) -> ToolResult:
    incident = await default_store.get_incident(incident_id)
    if incident is None:
        return _fail(f"Incident not found: {incident_id}")
    return _ok("Security incident", incident.model_dump(mode="json"), incident_id=incident_id)


@ToolRegistry.register_function(
    name="security_report_generate",
    description="Generate a Markdown report for a security incident.",
    description_cn="为安全事件生成 Markdown 研判报告。",
    category=ToolCategory.CUSTOM,
    tags=["security", "incident", "report"],
    parameters=[
        ToolParameter(name="incident_id", type=ParameterType.STRING, description="Incident ID."),
        ToolParameter(name="format", type=ParameterType.STRING, required=False, default="markdown", description="Only markdown is supported in MVP."),
    ],
)
async def security_report_generate(
    ctx: ToolContext,
    incident_id: str,
    format: str = "markdown",
) -> ToolResult:
    if format != "markdown":
        return _fail("Only markdown format is supported.")
    try:
        content = await generate_incident_report(incident_id)
    except ValueError as exc:
        return _fail(str(exc))
    return _ok("Security incident report", {"incident_id": incident_id, "format": "markdown", "content": content})


@ToolRegistry.register_function(
    name="security_honeypot_event_search",
    description="Search honeypot events by source IP, target IP, protocol, service, or keyword.",
    description_cn="按源 IP、目标 IP、协议、服务或关键字查询诱捕事件。",
    category=ToolCategory.CUSTOM,
    tags=["security", "honeypot", "correlation"],
    parameters=[
        ToolParameter(name="ip", type=ParameterType.STRING, required=False, description="Source or target IP."),
        ToolParameter(name="keyword", type=ParameterType.STRING, required=False, description="Keyword."),
        ToolParameter(name="limit", type=ParameterType.INTEGER, required=False, default=50, description="Maximum number of results."),
    ],
)
async def security_honeypot_event_search(
    ctx: ToolContext,
    ip: str | None = None,
    keyword: str | None = None,
    limit: int = 50,
) -> ToolResult:
    items = await default_store.list_honeypot_events(_filters(ip=ip, keyword=keyword, limit=limit))
    return _ok("Security honeypot events", {"items": _dump_items(items), "count": len(items)})
