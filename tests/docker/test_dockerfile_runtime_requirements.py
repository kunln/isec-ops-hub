from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "docker" / "Dockerfile"


def test_runtime_image_installs_required_cli_tools() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    assert "bash ./scripts/install.sh" in dockerfile
    assert 'AGENT_BROWSER_BIN="$(npm prefix -g)/bin/agent-browser"' in dockerfile
    assert 'ln -sf "$AGENT_BROWSER_BIN" /usr/local/bin/agent-browser' in dockerfile


def test_runtime_image_no_longer_bundles_system_chromium() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    assert "AGENT_BROWSER_EXECUTABLE_PATH=/usr/bin/chromium" not in dockerfile
    assert "    chromium \\" not in dockerfile
