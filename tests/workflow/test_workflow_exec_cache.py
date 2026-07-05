import os
import time
from pathlib import Path

from flocks.workflow import run_workflow
from flocks.workflow.compiler import default_exec_path


def _write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def _touch(path: Path, *, mtime: float) -> None:
    os.utime(path, (mtime, mtime))


def test_run_workflow_reuses_exec_cache_when_fresh(tmp_path: Path) -> None:
    workflow_path = tmp_path / "workflow.json"
    exec_path = default_exec_path(workflow_path)

    # Use a logic node so compilation would occur when cache is stale/missing.
    _write_text(
        workflow_path,
        """
{
  "name": "cache_test",
  "start": "n1",
  "nodes": [
    {
      "id": "n1",
      "type": "logic",
      "description": "输入：x。输出：y。逻辑：y=x+1"
    }
  ],
  "edges": []
}
""".strip(),
    )

    # First run: exec cache doesn't exist -> compile and write exec.
    res1 = run_workflow(
        workflow=str(workflow_path),
        inputs={"x": 1},
        use_llm=False,
        ensure_requirements=False,
    )
    assert res1.status == "SUCCEEDED"
    assert exec_path.exists()

    # Make exec newer than source.
    now = time.time()
    _touch(workflow_path, mtime=now - 10)
    _touch(exec_path, mtime=now)
    exec_mtime_before = exec_path.stat().st_mtime

    # Second run: cache is fresh -> should NOT rewrite exec file.
    res2 = run_workflow(
        workflow=str(workflow_path),
        inputs={"x": 1},
        use_llm=False,
        ensure_requirements=False,
    )
    assert res2.status == "SUCCEEDED"
    assert exec_path.stat().st_mtime == exec_mtime_before


def test_run_workflow_recompiles_when_source_is_newer(tmp_path: Path) -> None:
    workflow_path = tmp_path / "workflow.json"
    exec_path = default_exec_path(workflow_path)

    _write_text(
        workflow_path,
        """
{
  "name": "cache_test_recompile",
  "start": "n1",
  "nodes": [
    {
      "id": "n1",
      "type": "logic",
      "description": "输入：x。输出：y。逻辑：y=x+1"
    }
  ],
  "edges": []
}
""".strip(),
    )

    # First run to generate exec cache.
    res1 = run_workflow(
        workflow=str(workflow_path),
        inputs={"x": 1},
        use_llm=False,
        ensure_requirements=False,
    )
    assert res1.status == "SUCCEEDED"
    assert exec_path.exists()

    # Make source newer than exec.
    now = time.time()
    _touch(exec_path, mtime=now - 10)
    _touch(workflow_path, mtime=now)
    exec_mtime_before = exec_path.stat().st_mtime

    # Run again: should recompile and overwrite exec (mtime updates).
    res2 = run_workflow(
        workflow=str(workflow_path),
        inputs={"x": 1},
        use_llm=False,
        ensure_requirements=False,
    )
    assert res2.status == "SUCCEEDED"
    assert exec_path.stat().st_mtime > exec_mtime_before

