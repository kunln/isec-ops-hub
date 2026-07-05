"""
沙箱路径安全模块

对齐 OpenClaw sandbox-paths.ts：
- 防止路径逃逸 (.. 检测)
- 防止 symlink 攻击
- Unicode 空格标准化
"""

import os
import re
from pathlib import Path
from typing import NamedTuple

# Unicode 空格字符正则
_UNICODE_SPACES = re.compile(
    r"[\u00A0\u2000-\u200A\u202F\u205F\u3000]"
)
_HTTP_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_DATA_URL_RE = re.compile(r"^data:", re.IGNORECASE)


class ResolvedPath(NamedTuple):
    """路径解析结果."""

    resolved: str  # 绝对路径
    relative: str  # 相对于 root 的路径（空串表示根本身）


def _normalize_unicode_spaces(text: str) -> str:
    """将 Unicode 空格替换为普通空格."""
    return _UNICODE_SPACES.sub(" ", text)


def _expand_path(file_path: str) -> str:
    """展开 ~ 等特殊路径."""
    normalized = _normalize_unicode_spaces(file_path)
    if normalized == "~":
        return str(Path.home())
    if normalized.startswith("~/"):
        return str(Path.home() / normalized[2:])
    return normalized


def _resolve_to_cwd(file_path: str, cwd: str) -> str:
    """将相对路径解析为绝对路径."""
    expanded = _expand_path(file_path)
    if os.path.isabs(expanded):
        return expanded
    return os.path.normpath(os.path.join(cwd, expanded))


def resolve_sandbox_path(
    file_path: str,
    cwd: str,
    root: str,
) -> ResolvedPath:
    """
    解析路径并确保在沙箱根目录内。

    Args:
        file_path: 需要解析的文件路径
        cwd: 当前工作目录
        root: 沙箱根目录

    Returns:
        ResolvedPath(resolved, relative)

    Raises:
        ValueError: 路径逃逸沙箱根目录
    """
    resolved = _resolve_to_cwd(file_path, cwd)
    root_resolved = os.path.normpath(os.path.abspath(root))
    relative = os.path.relpath(resolved, root_resolved)

    if not relative or relative == ".":
        return ResolvedPath(resolved=resolved, relative="")

    if relative.startswith("..") or os.path.isabs(relative):
        short_root = _short_path(root_resolved)
        raise ValueError(
            f"Path escapes sandbox root ({short_root}): {file_path}"
        )

    return ResolvedPath(resolved=resolved, relative=relative)


async def assert_sandbox_path(
    file_path: str,
    cwd: str,
    root: str,
) -> ResolvedPath:
    """
    解析路径并检查 symlink 安全性。

    Args:
        file_path: 需要解析的文件路径
        cwd: 当前工作目录
        root: 沙箱根目录

    Returns:
        ResolvedPath(resolved, relative)

    Raises:
        ValueError: 路径逃逸或存在 symlink
    """
    result = resolve_sandbox_path(file_path, cwd, root)
    await _assert_no_symlink(result.relative, os.path.abspath(root))
    return result


def assert_media_not_data_url(media: str) -> None:
    """检查媒体源不是 data: URL."""
    raw = media.strip()
    if _DATA_URL_RE.match(raw):
        raise ValueError(
            "data: URLs are not supported for media. Use buffer instead."
        )


async def resolve_sandboxed_media_source(
    media: str,
    sandbox_root: str,
) -> str:
    """
    解析沙箱内的媒体源路径。

    Args:
        media: 媒体路径或 URL
        sandbox_root: 沙箱根目录

    Returns:
        解析后的绝对路径或原始 URL
    """
    raw = media.strip()
    if not raw:
        return raw
    if _HTTP_URL_RE.match(raw):
        return raw

    candidate = raw
    if candidate.startswith("file://"):
        # 简易 file:// 解析
        candidate = candidate[7:]

    result = await assert_sandbox_path(
        file_path=candidate,
        cwd=sandbox_root,
        root=sandbox_root,
    )
    return result.resolved


async def _assert_no_symlink(relative: str, root: str) -> None:
    """
    沿路径逐级检查 symlink。

    Raises:
        ValueError: 路径中存在 symlink
    """
    if not relative:
        return

    import aiofiles.os as aio_os

    parts = Path(relative).parts
    current = root
    for part in parts:
        current = os.path.join(current, part)
        try:
            stat = os.lstat(current)
            import stat as stat_mod

            if stat_mod.S_ISLNK(stat.st_mode):
                raise ValueError(
                    f"Symlink not allowed in sandbox path: {current}"
                )
        except FileNotFoundError:
            # 路径不存在，后续也不会有 symlink
            return
        except ValueError:
            raise
        except OSError:
            return


def _short_path(value: str) -> str:
    """将 home 目录缩写为 ~."""
    home = str(Path.home())
    if value.startswith(home):
        return "~" + value[len(home):]
    return value
