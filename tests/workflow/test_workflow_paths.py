"""
Tests for workflow canonical path changes.

Verifies that:
- resolve_global_workflow_roots() includes plugins/workflows/ as new canonical path
- resolve_project_workflow_roots() includes plugins/workflows/ as new canonical path
- scan_skill_workflows() discovers workflows from plugins/workflows/ directories
- Legacy paths (workflow/, plugins/workflow/) are still scanned for compat
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from flocks.workflow import center
from flocks.workflow.center import (
    resolve_global_workflow_roots,
    resolve_project_workflow_roots,
)
from flocks.storage.storage import Storage


# ---------------------------------------------------------------------------
# Path resolution unit tests
# ---------------------------------------------------------------------------

class TestResolveGlobalWorkflowRoots:
    def test_includes_new_canonical_path(self):
        roots = resolve_global_workflow_roots()
        canonical = Path.home() / ".flocks" / "plugins" / "workflows"
        assert canonical in roots

    def test_canonical_path_is_highest_priority(self):
        """plugins/workflows/ must be last (highest priority, last-wins)."""
        roots = resolve_global_workflow_roots()
        canonical = Path.home() / ".flocks" / "plugins" / "workflows"
        assert roots[-1] == canonical

    def test_includes_legacy_compat_paths(self):
        roots = resolve_global_workflow_roots()
        legacy_plugin = Path.home() / ".flocks" / "plugins" / "workflow"
        legacy_main = Path.home() / ".flocks" / "workflow"
        assert legacy_plugin in roots
        assert legacy_main in roots

    def test_returns_three_paths(self):
        roots = resolve_global_workflow_roots()
        assert len(roots) == 3


class TestResolveProjectWorkflowRoots:
    def test_includes_new_canonical_path(self, tmp_path: Path):
        roots = resolve_project_workflow_roots(tmp_path)
        canonical = tmp_path / ".flocks" / "plugins" / "workflows"
        assert canonical in roots

    def test_canonical_path_is_highest_priority(self, tmp_path: Path):
        roots = resolve_project_workflow_roots(tmp_path)
        canonical = tmp_path / ".flocks" / "plugins" / "workflows"
        assert roots[-1] == canonical

    def test_includes_legacy_compat_paths(self, tmp_path: Path):
        roots = resolve_project_workflow_roots(tmp_path)
        legacy_plugin = tmp_path / ".flocks" / "plugins" / "workflow"
        legacy_main = tmp_path / ".flocks" / "workflow"
        assert legacy_plugin in roots
        assert legacy_main in roots

    def test_returns_three_paths(self, tmp_path: Path):
        roots = resolve_project_workflow_roots(tmp_path)
        assert len(roots) == 3


# ---------------------------------------------------------------------------
# Scan integration tests
# ---------------------------------------------------------------------------

def _workflow_payload(name: str) -> dict:
    return {
        "id": f"{name}-id",
        "name": name,
        "start": "n1",
        "nodes": [{"id": "n1", "type": "python", "code": "outputs['ok'] = True"}],
        "edges": [],
    }


@pytest.fixture
async def isolated_storage(tmp_path: Path):
    Storage._initialized = False
    Storage._db_path = None
    await Storage.init(tmp_path / "test.db")
    yield
    Storage._initialized = False
    Storage._db_path = None


@pytest.mark.asyncio
async def test_scan_discovers_new_canonical_path(
    tmp_path: Path,
    isolated_storage,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Workflows placed in plugins/workflows/ (new canonical) are discovered."""
    wf_dir = tmp_path / ".flocks" / "plugins" / "workflows" / "my-wf"
    wf_dir.mkdir(parents=True)
    (wf_dir / "workflow.json").write_text(
        json.dumps(_workflow_payload("my-wf")), encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    # Isolate from real global ~/.flocks/ workflows
    monkeypatch.setattr(center, "resolve_global_workflow_roots", lambda: [])

    results = await center.scan_skill_workflows(tmp_path)
    assert len(results) == 1
    assert results[0]["name"] == "my-wf"
    assert results[0]["sourceType"] == "project"


@pytest.mark.asyncio
async def test_scan_still_discovers_legacy_workflow_path(
    tmp_path: Path,
    isolated_storage,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Workflows in old .flocks/workflow/ (legacy) are still discovered."""
    wf_dir = tmp_path / ".flocks" / "workflow" / "legacy-wf"
    wf_dir.mkdir(parents=True)
    (wf_dir / "workflow.json").write_text(
        json.dumps(_workflow_payload("legacy-wf")), encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(center, "resolve_global_workflow_roots", lambda: [])

    results = await center.scan_skill_workflows(tmp_path)
    assert len(results) == 1
    assert results[0]["name"] == "legacy-wf"


@pytest.mark.asyncio
async def test_new_canonical_path_wins_over_legacy(
    tmp_path: Path,
    isolated_storage,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When same directory name exists in both legacy and new canonical path, new wins."""
    for subdir in [
        tmp_path / ".flocks" / "workflow" / "shared-wf",
        tmp_path / ".flocks" / "plugins" / "workflows" / "shared-wf",
    ]:
        subdir.mkdir(parents=True)
        payload = _workflow_payload(
            "shared-wf" if "workflows" not in str(subdir) else "shared-wf-new"
        )
        (subdir / "workflow.json").write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(center, "resolve_global_workflow_roots", lambda: [])

    results = await center.scan_skill_workflows(tmp_path)
    # The new canonical path (plugins/workflows/) has higher priority and wins
    names = [r["name"] for r in results]
    assert "shared-wf-new" in names
