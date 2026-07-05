"""
TASKS extension point registration and collection.

This module intentionally stays thin:
- register the TASKS extension point with PluginLoader
- collect TaskSpec objects discovered from plugin YAML files
- expose public helpers used by the server/routes

TaskSpec parsing lives in ``plugin_models.py``.
DB synchronization logic lives in ``plugin_sync.py``.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from flocks.utils.log import Log
from .plugin_models import TaskSpec, task_spec_from_raw, task_spec_to_dict
from .plugin_sync import upsert_task_specs

log = Log.create(service="task.plugin")

# Module-level in-memory store, populated by the PluginLoader consumer.
# Reset on each call to seed_tasks_from_plugin() so results are fresh.
_collected_specs: List["TaskSpec"] = []


# ---------------------------------------------------------------------------
# PluginLoader consumer — synchronous, only collects into memory
# ---------------------------------------------------------------------------

def _collect_task_specs(items: list, source: str) -> None:
    """Consumer callback: accumulate TaskSpec instances from all plugin files.

    Performs dedup by dedup_key at the consumer level because PluginLoader
    resets its internal ``_seen_keys`` between ``load_for_extension`` calls,
    which means cross-directory dedup (global vs project) is lost.
    Later sources (project) overwrite earlier ones (global).
    """
    for item in items:
        if not isinstance(item, TaskSpec):
            continue
        # Replace existing spec with same dedup_key (project overrides global).
        for i, existing in enumerate(_collected_specs):
            if existing.dedup_key == item.dedup_key:
                _collected_specs[i] = item
                log.info("task.plugin.overridden", {
                    "dedup_key": item.dedup_key,
                    "source": source,
                })
                break
        else:
            _collected_specs.append(item)
            log.info("task.plugin.collected", {
                "dedup_key": item.dedup_key,
                "title": item.title,
                "source": source,
            })


# ---------------------------------------------------------------------------
# Extension-point registration
# ---------------------------------------------------------------------------

def register_task_extension_point() -> None:
    """Register the TASKS extension point with PluginLoader (idempotent)."""
    from flocks.plugin import ExtensionPoint, PluginLoader

    PluginLoader.register_extension_point(ExtensionPoint(
        attr_name="TASKS",
        subdir="tasks",
        consumer=_collect_task_specs,
        item_type=TaskSpec,
        dedup_key=lambda t: t.dedup_key,
        yaml_item_factory=task_spec_from_raw,
    ))


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def list_loaded_task_specs() -> List[TaskSpec]:
    """Return the TaskSpec list collected during the last seed run (read-only)."""
    return list(_collected_specs)


def list_builtin_task_files_as_dicts() -> List[dict]:
    """Return collected specs as plain dicts for UI/API consumption."""
    return [task_spec_to_dict(spec) for spec in _collected_specs]


# ---------------------------------------------------------------------------
# Main async entry point
# ---------------------------------------------------------------------------

async def seed_tasks_from_plugin(project_dir: Optional[Path] = None) -> int:
    """Load task specs via PluginLoader, then sync them to the DB."""
    from flocks.plugin import PluginLoader, scan_directory

    # Reset collected list so repeated calls (e.g. tests) are idempotent.
    _collected_specs.clear()

    register_task_extension_point()

    # 1. Global: ~/.flocks/plugins/tasks/
    PluginLoader.load_default_for_extension("TASKS")

    # 2. Project-level: {cwd}/.flocks/plugins/tasks/
    base = project_dir or Path.cwd()
    project_tasks_dir = base / ".flocks" / "plugins" / "tasks"
    if project_tasks_dir.is_dir():
        sources = scan_directory(project_tasks_dir)
        if sources:
            PluginLoader.load_for_extension("TASKS", sources, project_tasks_dir)

    if not _collected_specs:
        log.info("task.plugin.no_specs")
        return 0

    return await upsert_task_specs(_collected_specs)
