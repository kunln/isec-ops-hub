"""Workflow compilation utilities.

Goal: turn a workflow that contains 'logic' nodes into a fully-runnable workflow by
materializing Python code for those nodes, and optionally converting them into
`type="python"` nodes.

This module is intentionally self-contained inside `flocks.workflow` (no dependency
on the external `flocks-workflow` package).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional, Union

from .code_gen import CodeGen, LLMCodeGen, SimpleCodeGen
from .io import dump_workflow, load_workflow
from .models import Node, Workflow
from .workflow_lint import lint_workflow


_logger = logging.getLogger("flocks.workflow.compiler")


def default_exec_path(input_path: Union[str, Path]) -> Path:
    """Derive the default compiled output path.

    - If the input filename is `workflow.json`, output `workflow-exec.json` alongside it.
    - Otherwise output `{stem}-exec{suffix}` alongside it.
    """
    p = Path(input_path)
    if p.name == "workflow.json":
        return p.with_name("workflow-exec.json")
    return p.with_name(f"{p.stem}-exec{p.suffix}")


def workflow_has_logic_nodes(workflow: Workflow) -> bool:
    return any(n.type == "logic" for n in workflow.nodes)


def compile_workflow(
    workflow: Workflow,
    *,
    code_gen: Optional[CodeGen] = None,
    use_llm: bool = False,
    convert_logic_to_python: bool = True,
    preserve_description: bool = True,
    workflow_path: Optional[Union[str, Path]] = None,
) -> Workflow:
    """Return a compiled copy of `workflow` with runnable code for logic nodes."""
    logic_nodes = [n for n in workflow.nodes if n.type == "logic"]
    _logger.info(f"开始编译 workflow: 共 {len(workflow.nodes)} 个节点，其中 {len(logic_nodes)} 个 logic 节点")
    
    if code_gen is None:
        code_gen_type = "LLMCodeGen" if use_llm else "SimpleCodeGen"
        _logger.info(f"使用代码生成器: {code_gen_type}")
        code_gen = LLMCodeGen(workflow_path=workflow_path) if use_llm else SimpleCodeGen()

    compiled = workflow.model_copy(deep=True)
    compiled_nodes: list[Node] = []

    for idx, node in enumerate(compiled.nodes, 1):
        if node.type != "logic":
            compiled_nodes.append(node)
            continue

        _logger.info(f"编译 logic 节点 [{idx}/{len(compiled.nodes)}]: {node.id}")
        code = node.code
        if code is None or not str(code).strip():
            _logger.info(f"  为节点 {node.id} 生成代码...")
            code = code_gen.generate(node)
            _logger.info(f"  代码生成完成，长度: {len(code)} 字符")

        if convert_logic_to_python:
            compiled_nodes.append(
                node.model_copy(
                    update={
                        "type": "python",
                        "code": code,
                        "description": node.description if preserve_description else None,
                    }
                )
            )
        else:
            compiled_nodes.append(
                node.model_copy(
                    update={
                        "code": code,
                        "description": node.description if preserve_description else None,
                    }
                )
            )

    compiled.nodes = compiled_nodes

    md = dict(compiled.metadata or {})
    md.setdefault("compiled", {})
    if not isinstance(md.get("compiled"), dict):
        md["compiled"] = {"_original_compiled": md.get("compiled")}
    md["compiled"].update(
        {
            "converted_logic_to_python": convert_logic_to_python,
            "preserve_description": preserve_description,
            "code_gen": "llm" if use_llm else "simple",
        }
    )
    # Best-effort lint metadata (helpful for exec caches and debugging).
    try:
        lint_results = lint_workflow(compiled)
        md["compiled"]["lint_warnings_count"] = len(lint_results)
        md["compiled"]["lint_warnings_preview"] = lint_results[:20]
    except Exception:
        # Compilation must not fail due to lints.
        pass
    compiled.metadata = md
    return compiled


def compile_workflow_file(
    input_path: Union[str, Path],
    output_path: Optional[Union[str, Path]] = None,
    *,
    use_llm: bool = False,
    convert_logic_to_python: bool = True,
    preserve_description: bool = True,
    indent: int = 2,
) -> Workflow:
    """Compile a workflow JSON file and write the compiled workflow JSON."""
    input_path_obj = Path(input_path)
    wf = load_workflow(input_path_obj)
    compiled = compile_workflow(
        wf,
        use_llm=use_llm,
        convert_logic_to_python=convert_logic_to_python,
        preserve_description=preserve_description,
        workflow_path=str(input_path_obj) if input_path_obj.exists() else None,
    )
    out = Path(output_path) if output_path is not None else default_exec_path(input_path)
    dump_workflow(compiled, out, indent=indent)
    return compiled

