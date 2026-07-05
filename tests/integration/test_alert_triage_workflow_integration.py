"""
Alert Triage Workflow 集成测试

分别在主机模式（host）和 sandbox 模式下执行
.flocks/workflow/alert_triage/workflow.json

测试要求：
- ThreatBook API Key 已配置（.flocks/.secret.json）
- LLM Provider 已配置（.flocks/flocks.json）
- Docker 可用（sandbox 模式）

执行方式:
    uv run python tests/test_alert_triage_workflow_integration.py
"""

import json
import logging
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Dict, Optional

# 确保项目根目录在 sys.path 中
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from flocks.workflow.runner import run_workflow, RunWorkflowResult


# ───────────────────── 日志配置 ─────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
_logger = logging.getLogger("test.alert_triage")


# ───────────────────── 测试数据 ─────────────────────
SAMPLE_ALERT_DATA = {
    "alert_id": "ALT-2026-0211-001",
    "source_ip": "1.1.1.1",
    "dest_ip": "8.8.8.8",
    "timestamp": "2026-02-11T08:30:00Z",
    "event_type": "suspicious_connection",
}

WORKFLOW_PATH = PROJECT_ROOT / ".flocks" / "workflow" / "alert_triage" / "workflow.json"


# ───────────────────── 辅助函数 ─────────────────────
def _print_separator(title: str) -> None:
    width = 70
    print("\n" + "=" * width)
    print(f"  {title}")
    print("=" * width)


def _print_result(result: RunWorkflowResult, mode: str) -> None:
    """格式化打印执行结果"""
    status_icon = "✅" if result.status == "SUCCEEDED" else "❌"
    print(f"\n{status_icon} [{mode}] 执行结果:")
    print(f"  状态: {result.status}")
    print(f"  Run ID: {result.run_id}")
    print(f"  总步骤: {result.steps}")
    print(f"  最后节点: {result.last_node_id}")

    if result.error:
        print(f"  错误: {result.error}")

    if result.history:
        print(f"\n  步骤详情 ({len(result.history)} 步):")
        for i, step in enumerate(result.history, 1):
            node_id = step.get("node_id", "?") if isinstance(step, dict) else getattr(step, "node_id", "?")
            error = step.get("error") if isinstance(step, dict) else getattr(step, "error", None)
            duration = step.get("duration_ms") if isinstance(step, dict) else getattr(step, "duration_ms", None)
            outputs = step.get("outputs", {}) if isinstance(step, dict) else getattr(step, "outputs", {})

            duration_str = f"{duration:.1f}ms" if duration else "N/A"
            status_str = "❌ ERROR" if error else "✅ OK"
            output_keys = list(outputs.keys()) if isinstance(outputs, dict) else []

            print(f"    [{i}] {node_id}: {status_str} ({duration_str}) -> {output_keys}")
            if error:
                print(f"        错误: {error[:200]}")

    # 打印最终输出
    if result.outputs:
        print(f"\n  最终输出 keys: {list(result.outputs.keys())}")
        # 打印报告摘要（如果存在）
        report = result.outputs.get("report")
        if report and isinstance(report, str):
            preview = report[:500].replace("\n", "\n    ")
            print(f"  报告预览:\n    {preview}")
            if len(report) > 500:
                print(f"    ... (共 {len(report)} 字符)")


# ───────────────────── 主机模式测试 ─────────────────────
def test_host_mode() -> RunWorkflowResult:
    """在主机模式下运行 alert_triage workflow"""
    _print_separator("主机模式 (Host Mode) 测试")

    # 强制使用 host 模式：monkeypatch _load_config_data
    import flocks.workflow.runner as runner_module

    original_load = runner_module._load_config_data

    def _patched_load_config_host() -> Dict[str, Any]:
        data = original_load()
        if isinstance(data, dict):
            data = dict(data)
            data["sandbox"] = {"mode": "off"}
        return data

    runner_module._load_config_data = _patched_load_config_host

    try:
        _logger.info("开始执行 alert_triage workflow（主机模式）")
        t0 = time.perf_counter()

        result = run_workflow(
            workflow=str(WORKFLOW_PATH),
            inputs={"alert_data": SAMPLE_ALERT_DATA},
            timeout_s=180.0,
            node_timeout_s=120.0,
            trace=True,
            ensure_requirements=True,
        )

        elapsed = time.perf_counter() - t0
        _logger.info(f"主机模式执行完成，耗时 {elapsed:.2f}s")
        _print_result(result, "HOST")
        return result

    except Exception as e:
        _logger.error(f"主机模式执行异常: {e}")
        traceback.print_exc()
        return RunWorkflowResult(status="EXCEPTION", error=str(e))
    finally:
        # 还原
        runner_module._load_config_data = original_load


# ───────────────────── Sandbox 模式测试 ─────────────────────
def test_sandbox_mode() -> RunWorkflowResult:
    """在 sandbox 模式下运行 alert_triage workflow"""
    _print_separator("Sandbox 模式测试")

    # 检查 Docker 可用性
    import subprocess

    try:
        cp = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if cp.returncode != 0:
            _logger.error("Docker 不可用，跳过 sandbox 测试")
            return RunWorkflowResult(status="SKIPPED", error="Docker not available")
        _logger.info(f"Docker 版本: {cp.stdout.strip()}")
    except Exception as e:
        _logger.error(f"Docker 检测失败: {e}")
        return RunWorkflowResult(status="SKIPPED", error=str(e))

    # 检查 sandbox 容器是否存在
    try:
        cp = subprocess.run(
            ["docker", "ps", "--filter", "name=flocks-sbx", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        containers = [c.strip() for c in cp.stdout.strip().splitlines() if c.strip()]
        if containers:
            _logger.info(f"检测到 sandbox 容器: {containers}")
        else:
            _logger.warning("未检测到 flocks sandbox 容器，将尝试自动创建")
    except Exception:
        pass

    # 强制使用 sandbox 模式
    import flocks.workflow.runner as runner_module

    original_load = runner_module._load_config_data

    def _patched_load_config_sandbox() -> Dict[str, Any]:
        data = original_load()
        if isinstance(data, dict):
            data = dict(data)
            sandbox_cfg = data.get("sandbox", {})
            if isinstance(sandbox_cfg, dict):
                sandbox_cfg = dict(sandbox_cfg)
            else:
                sandbox_cfg = {}
            sandbox_cfg["mode"] = "on"
            data["sandbox"] = sandbox_cfg
        return data

    runner_module._load_config_data = _patched_load_config_sandbox

    try:
        _logger.info("开始执行 alert_triage workflow（sandbox 模式）")
        t0 = time.perf_counter()

        result = run_workflow(
            workflow=str(WORKFLOW_PATH),
            inputs={"alert_data": SAMPLE_ALERT_DATA},
            timeout_s=300.0,
            node_timeout_s=120.0,
            trace=True,
            ensure_requirements=True,
        )

        elapsed = time.perf_counter() - t0
        _logger.info(f"Sandbox 模式执行完成，耗时 {elapsed:.2f}s")
        _print_result(result, "SANDBOX")
        return result

    except Exception as e:
        _logger.error(f"Sandbox 模式执行异常: {e}")
        traceback.print_exc()
        return RunWorkflowResult(status="EXCEPTION", error=str(e))
    finally:
        runner_module._load_config_data = original_load


# ───────────────────── 结果对比 ─────────────────────
def compare_results(host_result: RunWorkflowResult, sandbox_result: RunWorkflowResult) -> None:
    """对比两种模式的执行结果"""
    _print_separator("执行结果对比")

    rows = [
        ("属性", "Host 模式", "Sandbox 模式"),
        ("状态", host_result.status, sandbox_result.status),
        ("步骤数", str(host_result.steps), str(sandbox_result.steps)),
        ("最后节点", str(host_result.last_node_id), str(sandbox_result.last_node_id)),
        ("输出 keys", str(list(host_result.outputs.keys())), str(list(sandbox_result.outputs.keys()))),
        ("错误", str(host_result.error or "无"), str(sandbox_result.error or "无")),
    ]

    col_widths = [max(len(str(row[i])) for row in rows) for i in range(3)]
    for row in rows:
        line = "  ".join(str(row[i]).ljust(col_widths[i]) for i in range(3))
        print(f"  {line}")

    # 一致性检查
    print()
    if host_result.status == "SUCCEEDED" and sandbox_result.status == "SUCCEEDED":
        print("  ✅ 两种模式均执行成功")
        if host_result.steps == sandbox_result.steps:
            print(f"  ✅ 步骤数一致: {host_result.steps}")
        else:
            print(f"  ⚠️  步骤数不一致: host={host_result.steps} sandbox={sandbox_result.steps}")
        if host_result.last_node_id == sandbox_result.last_node_id:
            print(f"  ✅ 最后节点一致: {host_result.last_node_id}")
        else:
            print(f"  ⚠️  最后节点不一致: host={host_result.last_node_id} sandbox={sandbox_result.last_node_id}")
    else:
        if host_result.status != "SUCCEEDED":
            print(f"  ❌ Host 模式失败: {host_result.error}")
        if sandbox_result.status != "SUCCEEDED":
            print(f"  ❌ Sandbox 模式失败: {sandbox_result.error}")


# ───────────────────── 入口 ─────────────────────
def main() -> None:
    _print_separator("Alert Triage Workflow 集成测试")
    print(f"  Workflow: {WORKFLOW_PATH}")
    print(f"  测试数据: {json.dumps(SAMPLE_ALERT_DATA, ensure_ascii=False)}")

    if not WORKFLOW_PATH.exists():
        _logger.error(f"Workflow 文件不存在: {WORKFLOW_PATH}")
        sys.exit(1)

    # 1. 主机模式测试
    host_result = test_host_mode()

    # 2. Sandbox 模式测试
    sandbox_result = test_sandbox_mode()

    # 3. 结果对比
    compare_results(host_result, sandbox_result)

    # 返回码
    if host_result.status == "SUCCEEDED" and sandbox_result.status in ("SUCCEEDED", "SKIPPED"):
        print("\n🎉 所有测试通过!")
        sys.exit(0)
    else:
        print("\n💥 存在测试失败!")
        sys.exit(1)


if __name__ == "__main__":
    main()
