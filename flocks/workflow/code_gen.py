"""Code generation for 'logic' nodes.

The engine can execute a 'logic' node by first turning its natural language
specification (stored in Node.description) into Python code.

This module defines a small, pluggable interface:
- Provide your own CodeGen implementation (e.g. LLM-backed) and pass it into WorkflowEngine.
"""

from __future__ import annotations

import logging
import re
import inspect
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union

from .errors import NodeExecutionError
from .models import Node
from .llm import get_llm_client, LLMClient
from .tools import get_tool_registry


_logger = logging.getLogger("flocks.workflow.code_gen")


class CodeGen:
    """Generate Python code for a logic node."""

    def generate(self, node: Node) -> str:  # pragma: no cover
        raise NotImplementedError


_PY_BLOCK_RE = re.compile(r"```python\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)
_OUTPUT_KEYS_RE = re.compile(r"输出[:：]\s*([^\n。；;]+)")
_TOOL_NAME_RE = re.compile(r"\bTool\s*:\s*([A-Za-z0-9_\-]+)", re.IGNORECASE)
_TOOLS_LIST_RE = re.compile(r"\bTools?\s*:\s*([A-Za-z0-9_\-\s,，、]+)", re.IGNORECASE)


def _extract_python_block(text: str) -> Optional[str]:
    m = _PY_BLOCK_RE.search(text)
    if not m:
        return None
    code = m.group(1)
    code = code.strip("\n")
    return code.strip() if code.strip() else None


def _extract_output_keys(description: str) -> list[str]:
    """Best-effort extraction of output keys from a Chinese description.

    Example:
    - "输入：x。输出：y。逻辑：..." -> ["y"]
    - "输出：a, b, c。" -> ["a", "b", "c"]
    """
    if not description:
        return ["result"]
    m = _OUTPUT_KEYS_RE.search(description)
    if not m:
        return ["result"]
    raw = (m.group(1) or "").strip()
    # Split on common Chinese/English separators.
    parts = re.split(r"[，,、\s]+", raw)
    keys = [p.strip() for p in parts if p and p.strip()]
    return keys if keys else ["result"]


def _extract_referenced_tools(description: str) -> list[str]:
    """Extract tool names referenced in a node description.

    Supported patterns (case-insensitive):
    - "Tool: xxx"
    - "Tools: a, b, c"
    """
    if not description:
        return []
    names: list[str] = []

    # Repeated "Tool: xxx"
    for m in _TOOL_NAME_RE.finditer(description):
        n = (m.group(1) or "").strip()
        if n and n not in names:
            names.append(n)

    # "Tools: a, b, c"
    for m in _TOOLS_LIST_RE.finditer(description):
        raw = (m.group(1) or "").strip()
        if not raw:
            continue
        for part in re.split(r"[，,、\s]+", raw):
            n = (part or "").strip()
            if n and n not in names:
                names.append(n)

    return names


@dataclass
class SimpleCodeGen(CodeGen):
    """
    A best-effort, non-LLM code generator for logic nodes.

    Rationale:
    - Workflows should remain runnable in offline / CI environments without LLM credentials.
    - If the description already embeds a ```python``` block, we can execute it directly.
    - Otherwise we generate a minimal fallback implementation that satisfies `outputs` keys.
    """

    def generate(self, node: Node) -> str:
        if node.type != "logic":
            raise NodeExecutionError(
                node_id=node.id, message="SimpleCodeGen can only generate for logic nodes"
            )
        if not node.description or not node.description.strip():
            raise NodeExecutionError(
                node_id=node.id, message="logic node missing description"
            )

        # If author provided explicit python code, prefer it.
        code = _extract_python_block(node.description)
        if code:
            return code

        # Fallback: keep it executable and deterministic without an LLM.
        # We follow the engine contract: read `inputs`, write `outputs`.
        keys = _extract_output_keys(node.description)
        if not keys:
            keys = ["result"]

        # If the description suggests multiple outputs, assign them deterministically.
        # Prefer passing through identically-named inputs, else None.
        lines: list[str] = [
            "# Fallback implementation (no LLM).",
            "# The logic node description did not include a ```python``` block,",
            "# so we produce deterministic placeholder outputs.",
            "",
        ]
        for k in keys:
            # Avoid clobbering reserved error channel.
            if k == "error":
                continue
            lines.append(f"outputs[{k!r}] = inputs.get({k!r}, None)")

        # Always provide a generic result for convenience if caller didn't ask for it.
        if "result" not in keys:
            # Avoid circular reference: outputs['result'] must not point to outputs itself,
            # otherwise JSON serialization (e.g., StepResult.model_dump(mode="json"))
            # will fail with "Circular reference detected".
            lines.append("outputs['result'] = dict(outputs)")

        # Helpful note for debugging downstream.
        lines.append(
            "outputs.setdefault('error', 'SimpleCodeGen fallback: provide a ```python``` block or run with use_llm=True')"
        )
        return "\n".join(lines).rstrip() + "\n"


@dataclass
class LLMCodeGen(CodeGen):
    """LLM-backed code generator."""

    client: Optional[LLMClient] = None
    workflow_path: Optional[Union[str, Path]] = None
    max_syntax_repair_attempts: int = 2

    def __post_init__(self) -> None:
        # IMPORTANT: keep this lazy.
        # We should not require env vars (like API keys) unless a logic node
        # actually needs LLM-backed code generation at runtime.
        pass

    def _get_client(self) -> LLMClient:
        if self.client is None:
            self.client = get_llm_client()
        return self.client

    def _normalize_llm_code(self, response: str) -> str:
        """Normalize LLM output into plain Python code (best-effort)."""
        extracted = _extract_python_block(response)
        final_code = extracted if extracted else (response or "").strip()

        # If it still looks like it's wrapped in markdown (e.g. without language tag)
        if final_code.startswith("```") and final_code.endswith("```"):
            inner_code = final_code.strip("`").strip()
            if inner_code.startswith("python"):
                inner_code = inner_code[6:].strip()
            final_code = inner_code

        # 自动处理可能出现的 JSON 字符串解析逻辑
        if "import json" not in final_code and "json.loads" in final_code:
            final_code = "import json\n" + final_code

        return final_code.strip() + "\n"

    def _validate_syntax(self, code: str, *, node_id: str) -> Optional[SyntaxError]:
        try:
            compile(code, f"<wf_node:{node_id}>", "exec")
            return None
        except SyntaxError as e:
            return e

    def generate(self, node: Node) -> str:
        if node.type != "logic":
            raise NodeExecutionError(
                node_id=node.id, message="LLMCodeGen can only generate for logic nodes"
            )
        if not node.description or not node.description.strip():
            raise NodeExecutionError(
                node_id=node.id, message="logic node missing description"
            )

        # First try to extract from description if it already contains code
        code = _extract_python_block(node.description)
        if code:
            _logger.info(f"节点 {node.id}: 从描述中提取到嵌入的 Python 代码")
            return code

        _logger.info(f"节点 {node.id}: 准备使用 LLM 生成代码")
        
        # Provide tool catalog to help the LLM generate correct calls.
        # Optimization: if the node description explicitly references tools (e.g. "Tool: xxx"),
        # only include those tools to keep prompts small and relevant.
        registry = get_tool_registry()
        referenced = _extract_referenced_tools(node.description)
        if referenced:
            _logger.info(f"节点 {node.id}: 检测到引用的工具: {referenced}")
        tool_catalog = self._tool_catalog(registry, only=referenced if referenced else None)

        # Try to load workflow.md if workflow_path is provided
        _logger.info(f"节点 {node.id}: 尝试加载 workflow.md 上下文")
        workflow_md_content = self._load_workflow_md()

        workflow_context = ""
        if workflow_md_content:
            workflow_context = f"""

完整工作流上下文（workflow.md）:
{workflow_md_content}
"""

        prompt = f"""你是一个 Python 代码生成专家。
## 目标
根据逻辑描述生成一段“可直接 exec 执行”的 Python 顶层代码，用于实现一个 workflow 的 logic 节点。

## 约定
1. 输入数据在 `inputs` 字典中。
2. 输出数据必须存放在 `outputs` 字典中。
3. 本节点代码会在顶层执行（不是函数入口）。允许定义少量 helper 函数/类，但必须在本代码块内被调用并最终写入 outputs。
4. inputs 是“上游 payload”：包含本节点入参 + 上游节点 outputs 合并结果；不要假设某个 key 一定存在，优先用get(...)方法取值。
5. 代码应该简洁且健壮，**优先使用 Python 标准库**。
6. 只返回代码块本身，不要包含任何解释文字，不要包含任何 Markdown 代码块标记（如 ```python）。

!!!重要!!!
禁止使用异步语法:代码通过 `exec()` 在顶层同步执行,**严禁使用 `await`、`async def`、`async for`、`async with` 等异步语法**。如需调用异步 API,必须在代码块内使用 `asyncio.run()` 包装,或改用同步库(如 requests 而非 aiohttp)。

## 输出要求（强制）
- 必须对以下 outputs keys 全部赋值（每个 key 都必须出现一次赋值）
- 如果无法满足业务逻辑，仍必须给每个 key 一个合理降级值，并额外写 outputs["error"] 说明原因（不影响上述 keys）。

## 工具调用规则（强制）
- 只能调用提供的工具；工具名必须完全一致
- 每次 tool.run 调用，kwargs 参数名必须严格匹配工具 schema；如果不确定参数，先不调用工具，改为降级逻辑并写 outputs["error"]。
- 推荐：将 tool.run 返回值先保存到局部变量，再写入 outputs，避免丢失。
- **重要：tool.run 的返回值类型不保证是 dict**（可能是 str / list / None）。除非你先判断 `isinstance(x, dict)`，否则不要对返回值直接调用 `.get(...)`。
- **特别是 write**：返回值通常是“文件路径字符串”（或 str-like）。要获取路径请优先使用 `str(result)`；如需兼容 dict-like 写法，可以使用 `getattr(result, "get", None)` 判断后再调用。

## 如需 llm.ask（推荐输出 JSON）
- 如果需要模型判断/抽取，请让 llm.ask 返回“严格 JSON（不带 markdown、不带额外解释）”，并用 json.loads 解析。
- 解析失败要兜底：把原始文本写入 outputs 的某个字段，并写 outputs["parse_error"]=True。

## 输入信息
{workflow_context}

需要生成代码的逻辑描述:
{node.description}

已注册工具列表（调用 `tool.run(name, ...)` 时请严格匹配参数名；不要凭空添加参数）:
{tool_catalog}

请开始生成代码:
"""
        _logger.info(f"节点 {node.id}: 调用 LLM 生成代码...")
        response = self._get_client().ask(prompt)
        _logger.info(f"节点 {node.id}: LLM 响应完成，长度: {len(response)} 字符")
        final_code = self._normalize_llm_code(response)

        # Guardrail: ensure returned code is syntactically valid before execution.
        # If not, ask the LLM to repair it using the SyntaxError details.
        max_repairs = max(0, int(self.max_syntax_repair_attempts))
        for attempt in range(max_repairs + 1):
            err = self._validate_syntax(final_code, node_id=node.id)
            if err is None:
                _logger.info(f"节点 {node.id}: 代码语法验证通过")
                return final_code
            if attempt >= max_repairs:
                _logger.error(f"节点 {node.id}: 代码语法错误，已达最大修复次数")
                raise NodeExecutionError(
                    node_id=node.id,
                    message=(
                        "LLM generated invalid Python code (syntax error). "
                        f"line={err.lineno} msg={err.msg}"
                    ),
                ) from err

            _logger.warning(f"节点 {node.id}: 代码语法错误 (尝试 {attempt + 1}/{max_repairs + 1}): line={err.lineno}, msg={err.msg}")
            err_text = (err.text or "").rstrip("\n")
            repair_prompt = textwrap.dedent(
                f"""
                你上一次生成的 Python 代码存在语法错误，无法执行。请你修复并输出**完整可执行的 Python 代码**。

                语法错误信息:
                - line: {err.lineno}
                - offset: {err.offset}
                - msg: {err.msg}
                - text: {err_text}

                硬性要求:
                - 只输出代码本身，不要解释，不要 Markdown。
                - **严禁使用三引号字符串（''' 或 \"\"\"）**，避免“未闭合字符串”类错误。
                - 如需多行文本，请使用 \"\\n\".join([...]) 或 json.dumps(...) / repr(...)。
                - 保持 `inputs`/`outputs` 协议：读 inputs，写 outputs。
                - 工具调用仅使用 `tool.run(name, **kwargs)`，参数名必须严格匹配注册工具。

                逻辑描述:
                {node.description}

                工具列表:
                {tool_catalog}

                需要修复的代码:
                {final_code}
                """
            ).strip()

            _logger.info(f"节点 {node.id}: 请求 LLM 修复代码...")
            repaired = self._get_client().ask(repair_prompt)
            final_code = self._normalize_llm_code(repaired)

        return final_code  # pragma: no cover

    def _tool_catalog(self, registry: Any, *, only: Optional[list[str]] = None) -> str:
        lines: list[str] = []
        names = list(only) if only else registry.list()
        for name in names:
            impl = registry.get(name)
            spec = registry.get_spec(name)
            sig = ""
            doc = ""
            try:
                if impl is None:
                    sig = "(missing)"
                elif callable(impl) and not hasattr(impl, "run"):
                    sig = str(inspect.signature(impl))
                    doc = (getattr(impl, "__doc__", "") or "").strip().splitlines()[0:1]
                    doc = doc[0] if doc else ""
                else:
                    run = getattr(impl, "run", None)
                    if run is None:
                        sig = "(missing run())"
                    else:
                        sig = str(inspect.signature(run))
                        doc = (getattr(run, "__doc__", "") or "").strip().splitlines()[0:1]
                        doc = doc[0] if doc else ""
            except Exception:
                sig = "(signature unavailable)"
                doc = ""

            # Prefer structured metadata if available (more like LangChain/Claude tools).
            if spec is not None:
                if spec.signature and sig in {"", "(signature unavailable)"}:
                    sig = spec.signature
                if spec.description and not doc:
                    doc = spec.description

            if doc:
                lines.append(f"- {name}{sig}  # {doc}")
            else:
                lines.append(f"- {name}{sig}")

        return "\n".join(lines) if lines else "- (no tools registered)"

    def _load_workflow_md(self) -> Optional[str]:
        """尝试加载 workflow.md 文件内容。
        
        如果 workflow_path 已设置，尝试在同目录下查找 workflow.md 文件。
        如果找到，返回其内容；否则返回 None。
        """
        if not self.workflow_path:
            return None
        
        try:
            workflow_path = Path(self.workflow_path)
            # 如果是文件路径，获取其所在目录；如果是目录路径，直接使用
            if workflow_path.is_file():
                workflow_dir = workflow_path.parent
            else:
                workflow_dir = workflow_path
            
            # 查找同目录下的 workflow.md
            workflow_md_path = workflow_dir / "workflow.md"
            if workflow_md_path.exists() and workflow_md_path.is_file():
                return workflow_md_path.read_text(encoding="utf-8")
        except Exception:
            # 如果读取失败，静默忽略，不影响代码生成
            pass
        
        return None

