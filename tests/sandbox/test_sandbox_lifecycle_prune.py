"""Additional tests for sandbox lifecycle and prune behavior."""

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from flocks.sandbox.types import SandboxConfig, SandboxPruneConfig
from flocks.sandbox.shared import resolve_sandbox_scope_key, slugify_session_key


def _cfg() -> SandboxConfig:
    """Build a default sandbox config for lifecycle tests."""
    return SandboxConfig(mode="on", scope="session", workspace_access="none")


def _expected_container_name(cfg: SandboxConfig, session_key: str) -> str:
    """Compute container name with the same naming logic as production code."""
    scope_key = resolve_sandbox_scope_key(cfg.scope, session_key)
    slug = "shared" if cfg.scope == "shared" else slugify_session_key(scope_key)
    return f"{cfg.docker.container_prefix}{slug}"[:63]


@pytest.mark.asyncio
async def test_ensure_sandbox_container_recreates_on_cold_hash_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cold running container with hash mismatch should be recreated."""
    from flocks.sandbox import docker as mod

    cfg = _cfg()
    session_key = "sess-recreate"
    container_name = _expected_container_name(cfg, session_key)

    monkeypatch.setattr(mod, "compute_sandbox_config_hash", lambda **_: "new-hash")
    monkeypatch.setattr(
        mod,
        "docker_container_state",
        AsyncMock(return_value={"exists": True, "running": True}),
    )
    monkeypatch.setattr(mod, "read_container_config_hash", AsyncMock(return_value="old-hash"))
    monkeypatch.setattr(
        mod,
        "find_registry_entry",
        AsyncMock(
            return_value=SimpleNamespace(
                container_name=container_name,
                    session_key=session_key,
                created_at_ms=(time.time() - 3600) * 1000,
                last_used_at_ms=(time.time() - 3600) * 1000,
                image="python:slim",
                config_hash="old-hash",
            )
        ),
    )
    create_mock = AsyncMock()
    update_mock = AsyncMock()
    exec_mock = AsyncMock(return_value=("", "", 0))
    monkeypatch.setattr(mod, "create_sandbox_container", create_mock)
    monkeypatch.setattr(mod, "update_registry", update_mock)
    monkeypatch.setattr(mod, "exec_docker", exec_mock)

    got = await mod.ensure_sandbox_container(
        session_key=session_key,
        workspace_dir="/tmp/ws",
        agent_workspace_dir="/tmp/agent",
        cfg=cfg,
    )
    assert got == container_name
    exec_mock.assert_awaited_with(["rm", "-f", container_name], allow_failure=True)
    create_mock.assert_awaited_once()
    update_mock.assert_awaited_once()
    assert update_mock.await_args.kwargs["config_hash"] == "new-hash"


@pytest.mark.asyncio
async def test_ensure_sandbox_container_keeps_hot_mismatch_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hot running container with hash mismatch should not be recreated."""
    from flocks.sandbox import docker as mod

    cfg = _cfg()
    session_key = "sess-hot"
    container_name = _expected_container_name(cfg, session_key)

    now_ms = time.time() * 1000
    monkeypatch.setattr(mod, "compute_sandbox_config_hash", lambda **_: "new-hash")
    monkeypatch.setattr(
        mod,
        "docker_container_state",
        AsyncMock(return_value={"exists": True, "running": True}),
    )
    monkeypatch.setattr(mod, "read_container_config_hash", AsyncMock(return_value="old-hash"))
    monkeypatch.setattr(
        mod,
        "find_registry_entry",
        AsyncMock(
            return_value=SimpleNamespace(
                container_name=container_name,
                    session_key=session_key,
                created_at_ms=now_ms - 10000,
                last_used_at_ms=now_ms - 1000,
                image="python:slim",
                config_hash="old-hash",
            )
        ),
    )
    create_mock = AsyncMock()
    update_mock = AsyncMock()
    exec_mock = AsyncMock(return_value=("", "", 0))
    monkeypatch.setattr(mod, "create_sandbox_container", create_mock)
    monkeypatch.setattr(mod, "update_registry", update_mock)
    monkeypatch.setattr(mod, "exec_docker", exec_mock)

    got = await mod.ensure_sandbox_container(
        session_key=session_key,
        workspace_dir="/tmp/ws",
        agent_workspace_dir="/tmp/agent",
        cfg=cfg,
    )
    assert got == container_name
    create_mock.assert_not_awaited()
    exec_mock.assert_not_awaited()
    update_mock.assert_awaited_once()
    # Keep running hot container, so registry hash is not overwritten yet.
    assert update_mock.await_args.kwargs["config_hash"] is None


@pytest.mark.asyncio
async def test_ensure_sandbox_container_starts_existing_stopped_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Existing stopped container should be started instead of recreated."""
    from flocks.sandbox import docker as mod

    cfg = _cfg()
    session_key = "sess-stopped"
    container_name = _expected_container_name(cfg, session_key)

    monkeypatch.setattr(mod, "compute_sandbox_config_hash", lambda **_: "hash-ok")
    monkeypatch.setattr(
        mod,
        "docker_container_state",
        AsyncMock(return_value={"exists": True, "running": False}),
    )
    monkeypatch.setattr(mod, "read_container_config_hash", AsyncMock(return_value="hash-ok"))
    monkeypatch.setattr(mod, "find_registry_entry", AsyncMock(return_value=None))
    create_mock = AsyncMock()
    update_mock = AsyncMock()
    exec_mock = AsyncMock(return_value=("", "", 0))
    monkeypatch.setattr(mod, "create_sandbox_container", create_mock)
    monkeypatch.setattr(mod, "update_registry", update_mock)
    monkeypatch.setattr(mod, "exec_docker", exec_mock)

    got = await mod.ensure_sandbox_container(
        session_key=session_key,
        workspace_dir="/tmp/ws",
        agent_workspace_dir="/tmp/agent",
        cfg=cfg,
    )
    assert got == container_name
    create_mock.assert_not_awaited()
    exec_mock.assert_awaited_with(["start", container_name])
    update_mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_maybe_prune_sandboxes_throttles_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """maybe_prune_sandboxes should run prune at most once per interval."""
    from flocks.sandbox import prune as mod

    cfg = SandboxConfig(
        mode="on",
        prune=SandboxPruneConfig(idle_hours=1, max_age_days=1),
    )
    prune_mock = AsyncMock(return_value=0)
    monkeypatch.setattr(mod, "prune_sandboxes", prune_mock)
    monkeypatch.setattr(mod, "_last_prune_at_ms", 0)

    base = 1_000_000.0
    times = iter([base, base + 1, base + 301])  # seconds
    monkeypatch.setattr(mod.time, "time", lambda: next(times))

    await mod.maybe_prune_sandboxes(cfg)
    await mod.maybe_prune_sandboxes(cfg)
    await mod.maybe_prune_sandboxes(cfg)

    assert prune_mock.await_count == 2


@pytest.mark.asyncio
async def test_prune_sandboxes_removes_idle_or_old_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """prune_sandboxes should remove entries by idle timeout and max age."""
    from flocks.sandbox import prune as mod
    from flocks.sandbox.registry import Registry, RegistryEntry

    now_ms = 10 * 24 * 3600 * 1000
    cfg = SandboxConfig(
        mode="on",
        prune=SandboxPruneConfig(idle_hours=24, max_age_days=7),
    )

    registry = Registry()
    # remove by idle timeout
    registry.entries.append(
        RegistryEntry(
            container_name="c-idle",
            session_key="s1",
            created_at_ms=now_ms - (2 * 24 * 3600 * 1000),
            last_used_at_ms=now_ms - (26 * 3600 * 1000),
            image="python:slim",
        )
    )
    # remove by max age
    registry.entries.append(
        RegistryEntry(
            container_name="c-old",
            session_key="s2",
            created_at_ms=now_ms - (8 * 24 * 3600 * 1000),
            last_used_at_ms=now_ms - (1 * 3600 * 1000),
            image="python:slim",
        )
    )
    # keep: not idle and not old
    registry.entries.append(
        RegistryEntry(
            container_name="c-keep",
            session_key="s3",
            created_at_ms=now_ms - (1 * 24 * 3600 * 1000),
            last_used_at_ms=now_ms - (1 * 3600 * 1000),
            image="python:slim",
        )
    )

    monkeypatch.setattr(mod, "read_registry", AsyncMock(return_value=registry))
    rm_container = AsyncMock()
    rm_registry = AsyncMock()
    monkeypatch.setattr(mod, "remove_container", rm_container)
    monkeypatch.setattr(mod, "remove_registry_entry", rm_registry)
    monkeypatch.setattr(mod.time, "time", lambda: now_ms / 1000)

    removed = await mod.prune_sandboxes(cfg)
    assert removed == 2
    assert rm_container.await_count == 2
    assert rm_registry.await_count == 2
    removed_names = {c.args[0] for c in rm_container.await_args_list}
    assert removed_names == {"c-idle", "c-old"}


@pytest.mark.asyncio
async def test_ensure_docker_image_pulls_default_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing default image should trigger docker pull."""
    from flocks.sandbox import docker as mod
    from flocks.sandbox.defaults import DEFAULT_SANDBOX_IMAGE

    monkeypatch.setattr(mod, "docker_image_exists", AsyncMock(return_value=False))
    exec_mock = AsyncMock(return_value=("", "", 0))
    monkeypatch.setattr(mod, "exec_docker", exec_mock)

    await mod.ensure_docker_image(DEFAULT_SANDBOX_IMAGE)
    exec_mock.assert_awaited_once_with(["pull", DEFAULT_SANDBOX_IMAGE])


@pytest.mark.asyncio
async def test_ensure_docker_image_raises_for_missing_custom_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing custom image should raise actionable error."""
    from flocks.sandbox import docker as mod

    monkeypatch.setattr(mod, "docker_image_exists", AsyncMock(return_value=False))
    with pytest.raises(RuntimeError, match="Sandbox image not found"):
        await mod.ensure_docker_image("custom:image-not-found")
