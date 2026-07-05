"""
Task plugin models and YAML parsing helpers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class TaskSpec:
    dedup_key: str
    title: str
    description: str = ""
    user_prompt: Optional[str] = None
    agent_name: str = "rex"
    execution_mode: str = "agent"
    workflow_id: Optional[str] = None
    task_type: str = "scheduled"
    priority: str = "normal"
    enabled: bool = True
    cron: Optional[str] = None
    timezone: str = "Asia/Shanghai"
    cron_description: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)


def task_spec_from_raw(raw: dict, source_path: Path) -> TaskSpec:
    """Parse a YAML mapping into a ``TaskSpec``."""

    def _get(camel: str, snake: str, default=None):
        return raw.get(camel, raw.get(snake, default))

    dedup_key = _get("dedupKey", "dedup_key")
    if not dedup_key:
        raise ValueError(f"Missing required field 'dedupKey' in {source_path}")

    title = raw.get("title")
    if not title:
        raise ValueError(f"Missing required field 'title' in {source_path}")

    task_type = raw.get("type", "scheduled")
    cron = raw.get("cron")
    if task_type == "scheduled" and not cron:
        raise ValueError(
            f"Scheduled task '{dedup_key}' in {source_path} requires a 'cron' field"
        )

    return TaskSpec(
        dedup_key=dedup_key,
        title=title,
        description=raw.get("description", ""),
        user_prompt=_get("userPrompt", "user_prompt"),
        agent_name=_get("agentName", "agent_name", "rex"),
        execution_mode=_get("executionMode", "execution_mode", "agent"),
        workflow_id=_get("workflowID", "workflow_id", _get("workflowId", "workflow_id")),
        task_type=task_type,
        priority=raw.get("priority", "normal"),
        enabled=raw.get("enabled", True),
        cron=cron,
        timezone=raw.get("timezone", "Asia/Shanghai"),
        cron_description=_get("cronDescription", "cron_description"),
        tags=raw.get("tags", []),
        context=raw.get("context", {}),
    )


def task_spec_to_dict(spec: TaskSpec) -> dict[str, Any]:
    return {
        "dedupKey": spec.dedup_key,
        "title": spec.title,
        "description": spec.description,
        "userPrompt": spec.user_prompt,
        "agentName": spec.agent_name,
        "executionMode": spec.execution_mode,
        "workflowID": spec.workflow_id,
        "type": spec.task_type,
        "priority": spec.priority,
        "enabled": spec.enabled,
        "cron": spec.cron,
        "timezone": spec.timezone,
        "cronDescription": spec.cron_description,
        "tags": spec.tags,
        "context": spec.context,
    }
