"""
沙箱工作区管理

对齐 OpenClaw sandbox/workspace.ts：
- 创建沙箱工作区目录
- 从 agent workspace 种子文件初始化
"""

import os
import shutil
from pathlib import Path
from typing import Optional

from flocks.utils.log import Log

log = Log.create(service="sandbox.workspace")


async def ensure_sandbox_workspace(
    workspace_dir: str,
    seed_from: Optional[str] = None,
) -> None:
    """
    确保沙箱工作区存在。

    对齐 OpenClaw ensureSandboxWorkspace。

    Args:
        workspace_dir: 目标工作区路径
        seed_from: 种子工作区路径（用于复制初始文件）
    """
    os.makedirs(workspace_dir, exist_ok=True)

    if seed_from:
        seed_path = os.path.expanduser(seed_from)
        # 仅在种子目录存在时复制
        if os.path.isdir(seed_path):
            _seed_files(seed_path, workspace_dir)


def _seed_files(src_dir: str, dest_dir: str) -> None:
    """
    从种子目录复制初始文件到沙箱工作区。

    仅复制顶层配置文件，不覆盖已有文件。
    """
    # 可选的种子文件列表（flocks 配置文件）
    seed_filenames = [
        ".flocks",
        "flocks.json",
        ".gitignore",
    ]

    for name in seed_filenames:
        src = os.path.join(src_dir, name)
        dest = os.path.join(dest_dir, name)

        # 不覆盖已有文件
        if os.path.exists(dest):
            continue

        try:
            if os.path.isdir(src):
                shutil.copytree(src, dest, dirs_exist_ok=False)
            elif os.path.isfile(src):
                shutil.copy2(src, dest)
        except (FileNotFoundError, FileExistsError, OSError):
            # 忽略缺失的种子文件
            pass
