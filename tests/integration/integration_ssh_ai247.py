"""
Integration test: SSH connection to ai247 host.

This file is intentionally excluded from git (see .gitignore).
Run manually to verify the ssh_host_cmd tool works end-to-end.

Usage:
    uv run python tests/integration_ssh_ai247.py
    # or via pytest (skips if ai247 not reachable):
    uv run pytest tests/integration_ssh_ai247.py -v
"""

import asyncio
import json
import subprocess
import sys
from pathlib import Path

import pytest

# Ensure project root is on sys.path when run directly
sys.path.insert(0, str(Path(__file__).parent.parent))

from flocks.tool.security.ssh_host_cmd import (
    SafetyDecision,
    classify_command,
    _audit_log,
    AUDIT_LOG_PATH,
)
from flocks.tool.registry import ToolContext, ToolRegistry

TARGET_HOST = "ai247"
TARGET_USER = "root"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_host_reachable(host: str) -> bool:
    """Quick connectivity check."""
    try:
        result = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes", host, "echo ok"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def _make_ctx() -> ToolContext:
    return ToolContext(session_id="integration-test", message_id="msg-001")


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def require_ai247():
    """Skip all tests in this module if ai247 is not reachable."""
    if not _is_host_reachable(TARGET_HOST):
        pytest.skip(f"Host '{TARGET_HOST}' not reachable — skipping integration tests")


# ---------------------------------------------------------------------------
# Safety classifier integration tests
# ---------------------------------------------------------------------------

class TestSafetyClassifierIntegration:
    """Verify classifier behavior with realistic forensic commands."""

    def test_allowed_commands_pass(self):
        forensic_cmds = [
            "ps aux",
            "ss -tunap",
            "uname -a",
            "cat /etc/passwd",
            "last -n 20",
            "crontab -l",
            "systemctl list-units --type=service",
            "find /tmp -type f",
            "grep 'Failed' /var/log/auth.log | head -20",
        ]
        for cmd in forensic_cmds:
            decision, reason = classify_command(cmd, set())
            assert decision == SafetyDecision.ALLOWED, (
                f"Command should be ALLOWED: {cmd!r} → {decision} ({reason})"
            )

    def test_destructive_commands_blocked(self):
        dangerous_cmds = [
            "rm -rf /tmp/test",
            "sudo cat /etc/shadow",
            "kill -9 1",
            "systemctl stop sshd",
            "apt install netcat",
            "echo payload > /tmp/evil.sh",
        ]
        for cmd in dangerous_cmds:
            decision, _ = classify_command(cmd, set())
            assert decision == SafetyDecision.BLOCKED, (
                f"Command should be BLOCKED: {cmd!r} → {decision}"
            )


# ---------------------------------------------------------------------------
# Live SSH execution tests
# ---------------------------------------------------------------------------

class TestLiveSSHExecution:
    """Execute real commands on ai247 and verify results."""

    @pytest.fixture(autouse=True)
    def _import_tool(self):
        # Ensure tool is registered
        import flocks.tool.security.ssh_host_cmd  # noqa: F401

    def _run(self, command: str, **kwargs) -> dict:
        """Run ssh_host_cmd synchronously."""
        ctx = _make_ctx()
        result = asyncio.run(
            ToolRegistry.execute("ssh_host_cmd", ctx, host=TARGET_HOST, command=command, **kwargs)
        )
        return result

    def test_uname(self):
        """Basic connectivity and command execution."""
        result = self._run("uname -a")
        assert result.success, f"uname failed: {result.error}"
        assert "Linux" in result.output, f"Unexpected uname output: {result.output}"
        print(f"\n[ai247] uname: {result.output.strip()}")

    def test_process_list(self):
        """Process listing returns meaningful output."""
        result = self._run("ps aux | head -20")
        assert result.success, f"ps failed: {result.error}"
        assert "PID" in result.output or "root" in result.output, (
            f"Unexpected ps output: {result.output[:200]}"
        )
        print(f"\n[ai247] ps aux (first 20 lines):\n{result.output[:500]}")

    def test_network_connections(self):
        """Network connection listing works."""
        result = self._run("ss -tunap")
        assert result.success, f"ss failed: {result.error}"
        print(f"\n[ai247] ss -tunap:\n{result.output[:500]}")

    def test_who_is_logged_in(self):
        """Session information retrieval."""
        result = self._run("who; w")
        assert result.success, f"who failed: {result.error}"
        print(f"\n[ai247] who / w:\n{result.output}")

    def test_last_logins(self):
        """Login history."""
        result = self._run("last -n 10")
        assert result.success, f"last failed: {result.error}"
        print(f"\n[ai247] last -n 10:\n{result.output}")

    def test_cron_jobs(self):
        """Cron job listing."""
        result = self._run("crontab -l 2>/dev/null || echo '(no crontab)'")
        # Even if no crontab, it should not error at SSH level
        print(f"\n[ai247] crontab -l:\n{result.output}")

    def test_temp_dirs(self):
        """Temp directory inspection."""
        result = self._run("ls -la /tmp /dev/shm 2>/dev/null")
        assert result.success, f"ls /tmp failed: {result.error}"
        print(f"\n[ai247] /tmp contents:\n{result.output}")

    def test_auth_log_recent(self):
        """Auth log read."""
        result = self._run("tail -30 /var/log/auth.log 2>/dev/null || tail -30 /var/log/secure 2>/dev/null || echo '(no auth log)'")
        print(f"\n[ai247] auth.log (last 30):\n{result.output[:1000]}")

    def test_systemctl_status(self):
        """Systemd service listing."""
        result = self._run("systemctl list-units --type=service --state=running --no-pager 2>/dev/null || echo '(systemd not available)'")
        print(f"\n[ai247] running services:\n{result.output[:1000]}")

    def test_listening_ports(self):
        """Listening port enumeration."""
        result = self._run("ss -tlnup")
        assert result.success, f"ss -tlnup failed: {result.error}"
        print(f"\n[ai247] listening ports:\n{result.output}")

    def test_dry_run_mode(self):
        """dry_run=True should classify without executing."""
        result = self._run("ps aux", dry_run=True)
        assert result.success
        assert result.output["dry_run"] is True
        assert result.output["safety_decision"] == SafetyDecision.ALLOWED
        print(f"\n[dry_run] ps aux: {result.output}")

    def test_blocked_command_rejected(self):
        """Destructive command must be rejected without executing."""
        result = self._run("rm -rf /tmp/integration_test_should_not_exist")
        assert not result.success, "Destructive command should have been rejected"
        assert "BLOCKED" in result.error
        print(f"\n[BLOCKED] rm -rf result: {result.error}")

    def test_audit_log_written(self):
        """Verify audit log is created after command execution."""
        before_size = AUDIT_LOG_PATH.stat().st_size if AUDIT_LOG_PATH.exists() else 0
        self._run("hostname")
        assert AUDIT_LOG_PATH.exists(), "Audit log file should exist"
        after_size = AUDIT_LOG_PATH.stat().st_size
        assert after_size > before_size, "Audit log should have grown"
        # Verify log content
        content = AUDIT_LOG_PATH.read_text()
        assert TARGET_HOST in content
        print(f"\n[Audit] Log file: {AUDIT_LOG_PATH}")
        print(f"[Audit] Last entry:\n{content.split(chr(10)+chr(10))[-2]}")

    def test_command_timeout(self):
        """Commands that take too long should timeout."""
        result = self._run("sleep 10", timeout=2)
        assert not result.success
        assert "timed out" in result.error.lower() or "timeout" in result.error.lower()
        print(f"\n[Timeout] sleep 10 with timeout=2: {result.error}")


# ---------------------------------------------------------------------------
# ssh_run_script triage integration tests
# ---------------------------------------------------------------------------

TRIAGE_SCRIPT_PATH = ".flocks/plugins/agents/host-forensics/scripts/triage.sh"


class TestLiveTriageExecution:
    """Verify ssh_run_script tool works end-to-end with triage.sh."""

    @pytest.fixture(autouse=True)
    def _import_tools(self):
        import flocks.tool.security.ssh_host_cmd   # noqa: F401
        import flocks.tool.security.ssh_run_script  # noqa: F401

    def _run_triage(self, **kwargs) -> dict:
        ctx = _make_ctx()
        return asyncio.run(
            ToolRegistry.execute(
                "ssh_run_script", ctx,
                host=TARGET_HOST,
                script_path=TRIAGE_SCRIPT_PATH,
                **kwargs,
            )
        )

    def test_triage_succeeds(self):
        """Full triage script runs successfully and returns output."""
        result = self._run_triage()
        assert result.success, f"Triage failed: {result.error}"
        assert result.output is not None
        assert "TRIAGE_COMPLETE" in result.output
        print(f"\n[Triage] success, output length: {len(result.output)} chars")

    def test_triage_sections_present(self):
        """Key forensic sections must be present in triage output."""
        result = self._run_triage()
        assert result.success, f"Triage failed: {result.error}"
        required_sections = [
            "CPU_TOP_PROCESSES",
            "LISTENING_PORTS",
            "CRON_JOBS",
            "RECENT_AUTH_EVENTS",
            "USER_ACCOUNTS_INTERACTIVE",
        ]
        for section in required_sections:
            assert section in result.output, f"Missing section: {section}"
        print(f"\n[Triage] All required sections present")

    def test_triage_metadata(self):
        """Metadata contains expected keys."""
        result = self._run_triage()
        assert result.success
        meta = result.metadata
        assert "sections_collected" in meta
        assert "script" in meta
        assert meta["script"] == "triage.sh"
        assert "elapsed_ms" in meta
        print(f"\n[Triage] script={meta['script']}")
        print(f"[Triage] sections_collected={meta['sections_collected']}")
        print(f"[Triage] elapsed_ms={meta['elapsed_ms']}")

    def test_triage_summary_header(self):
        """Triage output starts with a summary header."""
        result = self._run_triage()
        assert result.success
        assert "SCRIPT EXECUTION SUMMARY" in result.output
        assert "triage.sh" in result.output

    def test_triage_audit_log(self):
        """Triage execution is recorded in the audit log."""
        from flocks.tool.security.ssh_utils import AUDIT_LOG_PATH
        before_size = AUDIT_LOG_PATH.stat().st_size if AUDIT_LOG_PATH.exists() else 0
        self._run_triage()
        assert AUDIT_LOG_PATH.exists()
        after_size = AUDIT_LOG_PATH.stat().st_size
        assert after_size > before_size, "Audit log should have grown after triage"
        content = AUDIT_LOG_PATH.read_text()
        assert "[script:triage.sh]" in content
        print(f"\n[Triage Audit] Log updated, size: {before_size} → {after_size}")

    def test_triage_timeout_parameter(self):
        """Triage respects timeout parameter (just verify it doesn't crash with low timeout)."""
        # With a 15s timeout the script should still collect partial output on most hosts
        result = self._run_triage(timeout=15)
        # May succeed or timeout, but should not raise unhandled exception
        assert result.output is not None or result.error is not None
        print(f"\n[Triage timeout=15] success={result.success}, error={result.error}")


# ---------------------------------------------------------------------------
# Quick forensic sweep
# ---------------------------------------------------------------------------

def quick_forensic_sweep():
    """
    Run a mini compromise detection sweep on ai247.
    Useful for manual validation of the analysis workflow.
    """
    import flocks.tool.security.ssh_host_cmd  # noqa: F401

    ctx = _make_ctx()

    async def _sweep():
        print(f"\n{'='*60}")
        print(f"Quick Forensic Sweep: {TARGET_HOST}")
        print(f"{'='*60}\n")

        commands = [
            ("System info",      "uname -a && hostname && uptime"),
            ("CPU top processes","ps aux --sort=-%cpu | head -15"),
            ("Network conns",    "ss -tunap | grep ESTAB | head -20"),
            ("Listening ports",  "ss -tlnup"),
            ("Temp files",       "ls -la /tmp /dev/shm 2>/dev/null"),
            ("Cron jobs",        "crontab -l 2>/dev/null; cat /etc/cron.d/* 2>/dev/null | head -30"),
            ("Recent auth",      "grep 'Failed\\|Accepted' /var/log/auth.log 2>/dev/null | tail -20 || grep 'Failed\\|Accepted' /var/log/secure 2>/dev/null | tail -20"),
            ("Recent logins",    "last -n 10"),
        ]

        for label, cmd in commands:
            print(f"\n--- {label} ---")
            result = await ToolRegistry.execute(
                "ssh_host_cmd", ctx, host=TARGET_HOST, command=cmd
            )
            if result.success:
                print(result.output[:800])
            else:
                print(f"[ERROR] {result.error}")

        print(f"\n{'='*60}")
        print("Sweep complete. Check audit log:")
        print(f"  {AUDIT_LOG_PATH}")

    asyncio.run(_sweep())


# ---------------------------------------------------------------------------
# Entry point for direct execution
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if not _is_host_reachable(TARGET_HOST):
        print(f"ERROR: Host '{TARGET_HOST}' is not reachable. Check SSH config.")
        sys.exit(1)

    print(f"Host '{TARGET_HOST}' is reachable. Running quick forensic sweep...\n")
    quick_forensic_sweep()
