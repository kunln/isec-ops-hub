"""
Flocks configuration directory helpers.

Ported from oh-my-opencode to keep path resolution consistent.
"""

import os
import platform
from pathlib import Path


TAURI_APP_IDENTIFIER = "ai.opencode.desktop"
TAURI_APP_IDENTIFIER_DEV = "ai.opencode.desktop.dev"


def _is_dev_build(version: str | None) -> bool:
    if not version:
        return False
    return "-dev" in version or ".dev" in version


def _get_tauri_config_dir(identifier: str) -> Path:
    system = platform.system().lower()
    home = Path.home()
    if system == "darwin":
        return home / "Library" / "Application Support" / identifier
    if system == "windows":
        app_data = os.environ.get("APPDATA") or (home / "AppData" / "Roaming")
        return Path(app_data) / identifier
    xdg_config = os.environ.get("XDG_CONFIG_HOME") or (home / ".config")
    return Path(xdg_config) / identifier


def _get_cli_config_dir() -> Path:
    env_dir = os.environ.get("FLOCKS_CONFIG_DIR", "").strip()
    if env_dir:
        return Path(env_dir).expanduser()

    system = platform.system().lower()
    home = Path.home()
    if system == "windows":
        cross_dir = home / ".config" / "opencode"
        cross_config = cross_dir / "flocks.json"
        if cross_config.exists():
            return cross_dir

        app_data = os.environ.get("APPDATA") or (home / "AppData" / "Roaming")
        app_dir = Path(app_data) / "opencode"
        app_config = app_dir / "flocks.json"
        if app_config.exists():
            return app_dir

        return cross_dir

    xdg_config = os.environ.get("XDG_CONFIG_HOME") or (home / ".config")
    return Path(xdg_config) / "opencode"


def get_flocks_config_dir(binary: str = "opencode", version: str | None = None, check_existing: bool = True) -> Path:
    """
    Resolve Flocks config dir for CLI or desktop.
    """
    if binary == "opencode":
        return _get_cli_config_dir()

    identifier = TAURI_APP_IDENTIFIER_DEV if _is_dev_build(version) else TAURI_APP_IDENTIFIER
    tauri_dir = _get_tauri_config_dir(identifier)
    if check_existing:
        legacy_dir = _get_cli_config_dir()
        legacy_config = legacy_dir / "flocks.json"
        legacy_configc = legacy_dir / "flocks.jsonc"
        if legacy_config.exists() or legacy_configc.exists():
            return legacy_dir
    return tauri_dir
