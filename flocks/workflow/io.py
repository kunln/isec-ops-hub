"""Import/export workflow JSON."""

import json
from pathlib import Path
from typing import Any, Union

from .errors import WorkflowValidationError
from .models import Workflow


def load_workflow(path: Union[str, Path]) -> Workflow:
    p = Path(path)
    try:
        data: Any = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise WorkflowValidationError(f"Workflow file not found: {p}") from e
    except json.JSONDecodeError as e:
        raise WorkflowValidationError(f"Invalid JSON in workflow file: {e.msg} at line {e.lineno}") from e
    except UnicodeDecodeError as e:
        raise WorkflowValidationError(f"File encoding error: {e}") from e
    except Exception as e:
        raise WorkflowValidationError(f"Failed to read workflow file: {type(e).__name__}: {e}") from e
    if not isinstance(data, dict):
        raise WorkflowValidationError(f"Workflow JSON must be an object, got {type(data).__name__}")
    return Workflow.from_dict(data)


def dump_workflow(workflow: Workflow, path: Union[str, Path], *, indent: int = 2) -> None:
    p = Path(path)
    payload = workflow.to_dict()
    p.write_text(json.dumps(payload, ensure_ascii=False, indent=indent) + "\n", encoding="utf-8")
