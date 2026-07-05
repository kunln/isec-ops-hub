"""
Deployment mode detection.

Determines whether the current process is running inside a Docker container
or from a source (host) installation so that update behaviour can adapt
accordingly.
"""

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

DeployMode = Literal["docker", "source"]


@lru_cache(maxsize=1)
def detect_deploy_mode() -> DeployMode:
    """
    Return ``"docker"`` when the process is running inside a container,
    ``"source"`` otherwise.

    Detection priority:
      1. Explicit ``FLOCKS_DEPLOY_MODE`` environment variable (always wins).
      2. Presence of ``/.dockerenv`` (created by Docker automatically).
      3. ``/proc/1/cgroup`` containing ``docker`` or ``containerd``.
    """
    env_val = os.environ.get("FLOCKS_DEPLOY_MODE", "").strip().lower()
    if env_val in ("docker", "source"):
        return env_val  # type: ignore[return-value]

    if Path("/.dockerenv").exists():
        return "docker"

    try:
        cgroup_text = Path("/proc/1/cgroup").read_text(encoding="utf-8")
        if "docker" in cgroup_text or "containerd" in cgroup_text:
            return "docker"
    except Exception:
        pass

    return "source"
