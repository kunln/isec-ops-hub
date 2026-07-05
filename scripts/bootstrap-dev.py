#!/usr/bin/env python3
"""Bootstrap or validate the local Flocks development environment."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEBUI_DIR = ROOT / "webui"
TUI_DIR = ROOT / "tui"


def process_env() -> dict[str, str]:
    env = os.environ.copy()
    cache_root = Path(env.get("TMPDIR", "/tmp")) / "flocks-uv-cache"
    env.setdefault("UV_CACHE_DIR", str(cache_root))
    return env


def log(message: str) -> None:
    print(f"[flocks-bootstrap] {message}", flush=True)


def eprint(message: str) -> None:
    print(f"[flocks-bootstrap] {message}", file=sys.stderr, flush=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Install or check the Python and frontend dependencies needed for Flocks development.",
    )
    parser.add_argument("--check", action="store_true", help="Only check the environment; do not install.")
    parser.add_argument("--skip-python", action="store_true", help="Skip Python dependency bootstrap.")
    parser.add_argument("--skip-webui", action="store_true", help="Skip WebUI dependency bootstrap.")
    parser.add_argument("--include-tui", action="store_true", help="Also bootstrap the optional TUI dependencies.")
    parser.add_argument(
        "--webui-install-command",
        choices=("ci", "install"),
        default="ci",
        help="npm command for WebUI dependencies. Defaults to npm ci.",
    )
    parser.add_argument(
        "--uv-default-index",
        default=os.environ.get("UV_DEFAULT_INDEX"),
        help="Optional package index passed to uv sync as --default-index.",
    )
    parser.add_argument(
        "--frozen",
        action="store_true",
        help="Pass --frozen to uv sync so CI verifies the lockfile without updating it.",
    )
    return parser


def local_executable(command: str) -> Path | None:
    suffixes = [".exe", ".cmd", ".bat"] if os.name == "nt" else [""]
    bin_dir = ROOT / ".venv" / ("Scripts" if os.name == "nt" else "bin")
    for suffix in suffixes:
        candidate = bin_dir / f"{command}{suffix}"
        if candidate.exists():
            return candidate
    return None


def resolve_command(command: str) -> str | None:
    found = shutil.which(command)
    if found:
        return found
    local = local_executable(command)
    return str(local) if local else None


def command_version(command: str, *version_args: str) -> str | None:
    executable = resolve_command(command)
    if not executable:
        return None
    try:
        result = subprocess.run(
            [executable, *version_args],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    output = (result.stdout or result.stderr).strip()
    return output.splitlines()[0] if output else "available"


def node_major(version: str | None) -> int | None:
    if not version:
        return None
    raw = version.strip().lstrip("v")
    try:
        return int(raw.split(".", 1)[0])
    except (TypeError, ValueError):
        return None


def run_command(command: list[str], cwd: Path) -> int:
    location = "." if cwd == ROOT else str(cwd.relative_to(ROOT))
    log(f"({location}) $ {' '.join(command)}")
    return subprocess.run(command, cwd=cwd, env=process_env()).returncode


def check_environment(args: argparse.Namespace) -> int:
    missing: list[str] = []

    if not args.skip_python:
        uv_version = command_version("uv", "--version")
        if uv_version:
            log(f"uv: {uv_version}")
        else:
            missing.append("uv command")

        if (ROOT / ".venv").exists():
            log("Python environment: .venv present")
        else:
            missing.append("Python environment (.venv)")

    if not args.skip_webui:
        node_version = command_version("node", "--version")
        major = node_major(node_version)
        if node_version and major is not None and major >= 22:
            log(f"node: {node_version}")
        elif node_version:
            missing.append(f"Node.js 22+ (found {node_version})")
        else:
            missing.append("node command")

        npm_version = command_version("npm", "--version")
        if npm_version:
            log(f"npm: {npm_version}")
        else:
            missing.append("npm command")

        if (WEBUI_DIR / "node_modules").exists():
            log("WebUI dependencies: webui/node_modules present")
        else:
            missing.append("WebUI dependencies (webui/node_modules)")

    if args.include_tui:
        bun_version = command_version("bun", "--version")
        if bun_version:
            log(f"bun: {bun_version}")
        else:
            missing.append("bun command")

        if (TUI_DIR / "node_modules").exists():
            log("TUI dependencies: tui/node_modules present")
        else:
            missing.append("TUI dependencies (tui/node_modules)")

    if missing:
        eprint("environment is not ready:")
        for item in missing:
            eprint(f"  - {item}")
        eprint("run: make bootstrap")
        if args.include_tui:
            eprint("for TUI dependencies, run: make bootstrap-tui")
        return 1

    log("environment looks ready")
    return 0


def bootstrap(args: argparse.Namespace) -> int:
    if not args.skip_python:
        uv = resolve_command("uv")
        if not uv:
            eprint("uv is required but was not found on PATH.")
            eprint("install uv globally or into .venv, then rerun: make bootstrap")
            return 127

        # Keep bootstrap focused on dependencies. Installing the current project
        # during local dev forces hatchling to package runtime .flocks assets,
        # which can fail when plugin caches contain incomplete or protected files.
        command = [uv, "sync", "--group", "dev", "--no-install-project"]
        if args.frozen:
            command.append("--frozen")
        if args.uv_default_index:
            command.extend(["--default-index", args.uv_default_index])
        code = run_command(command, ROOT)
        if code:
            return code

    if not args.skip_webui:
        node_version = command_version("node", "--version")
        major = node_major(node_version)
        if major is None or major < 22:
            found = node_version or "missing"
            eprint(f"Node.js 22+ is required for WebUI dependencies (found {found}).")
            return 127
        if not shutil.which("npm"):
            eprint("npm is required but was not found on PATH.")
            return 127

        command = ["npm", args.webui_install_command]
        code = run_command(command, WEBUI_DIR)
        if code:
            return code

    if args.include_tui:
        if not shutil.which("bun"):
            eprint("bun is required for TUI dependencies but was not found on PATH.")
            return 127
        code = run_command(["bun", "install"], TUI_DIR)
        if code:
            return code

    log("bootstrap complete")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.check:
        return check_environment(args)
    return bootstrap(args)


if __name__ == "__main__":
    raise SystemExit(main())
