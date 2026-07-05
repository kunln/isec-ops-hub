#!/usr/bin/env python3
"""Run Flocks Python tests through the project uv environment."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE_MARKER = "not integration and not slow and not live"


def process_env() -> dict[str, str]:
    env = os.environ.copy()
    tmp_root = Path(env.get("TMPDIR", "/tmp"))
    test_home = Path(env.get("FLOCKS_TEST_HOME", tmp_root / f"flocks-test-home-{os.getpid()}"))
    test_home.mkdir(parents=True, exist_ok=True)

    cache_root = tmp_root / "flocks-uv-cache"
    env.setdefault("UV_CACHE_DIR", str(cache_root))
    if env.get("FLOCKS_TEST_REAL_HOME", "").lower() not in {"1", "true", "yes"}:
        env["HOME"] = str(test_home)
    env.setdefault("FLOCKS_ROOT", str(test_home / ".flocks"))
    env.setdefault("FLOCKS_DATA_DIR", str(test_home / ".flocks" / "data"))
    env.setdefault("FLOCKS_LOG_DIR", str(test_home / ".flocks" / "logs"))
    return env


def eprint(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run Flocks Python tests with the same entry point used by Makefile.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run every pytest test, including integration, slow, and live tests.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Use verbose pytest output and long tracebacks.",
    )
    parser.add_argument(
        "--marker",
        help=(
            "Override the default pytest marker expression. By default core tests "
            f"use: {CORE_MARKER!r}."
        ),
    )
    parser.add_argument(
        "pytest_args",
        nargs=argparse.REMAINDER,
        help="Additional pytest arguments. Use '--' before pytest flags.",
    )
    return parser


def local_executable(command: str) -> Path | None:
    suffixes = [".exe", ".cmd", ".bat"] if sys.platform.startswith("win") else [""]
    bin_dir = ROOT / ".venv" / ("Scripts" if sys.platform.startswith("win") else "bin")
    for suffix in suffixes:
        candidate = bin_dir / f"{command}{suffix}"
        if candidate.exists():
            return candidate
    return None


def require_uv() -> str | None:
    uv = shutil.which("uv")
    if uv:
        return uv
    local_uv = local_executable("uv")
    if local_uv:
        return str(local_uv)

    eprint("[flocks-test] error: uv is required but was not found on PATH.")
    eprint("[flocks-test] run: make bootstrap-check")
    eprint("[flocks-test] then install uv globally or into .venv and run: make bootstrap")
    return None


def normalize_pytest_args(args: list[str]) -> list[str]:
    if args and args[0] == "--":
        return args[1:]
    return args


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    uv = require_uv()
    if not uv:
        return 127

    pytest_args = normalize_pytest_args(args.pytest_args)
    marker = args.marker if args.marker is not None else (None if args.all else CORE_MARKER)

    cmd = [uv, "run", "--no-sync", "pytest"]
    if marker:
        cmd.extend(["-m", marker])
    if args.verbose:
        cmd.extend(["-vv", "--tb=long"])
    else:
        cmd.extend(["-v", "--tb=short"])
    cmd.extend(pytest_args or ["tests/"])

    print("[flocks-test] " + " ".join(cmd), flush=True)
    return subprocess.run(cmd, cwd=ROOT, env=process_env()).returncode


if __name__ == "__main__":
    raise SystemExit(main())
