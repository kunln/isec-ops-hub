"""
SSH Host Command Tool - Read-only remote forensic command execution

Executes commands on remote Linux hosts via SSH with a three-tier safety system:
  ① Static rule classifier (ALLOWED / BLOCKED / NEEDS_CONFIRM)
  ② LLM safety evaluation for gray-area commands (NEEDS_CONFIRM only)
  ③ Human confirmation with 1-minute timeout (LLM-UNCERTAIN only)

All commands are audit-logged to ~/.flocks/audit/ssh_commands.log.
Users can permanently whitelist commands via ~/.flocks/ssh_allowed_commands.json.
"""

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Optional

from flocks.tool.registry import (
    ParameterType,
    ToolCategory,
    ToolContext,
    ToolParameter,
    ToolRegistry,
    ToolResult,
)
from flocks.tool.security.ssh_utils import (
    audit_log,
    execute_ssh_command,
    resolve_ssh_credentials,
)
from flocks.utils.log import Log

log = Log.create(service="tool.ssh_host_cmd")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_TIMEOUT_S = 120
DEFAULT_TIMEOUT_S = 30
HUMAN_CONFIRM_TIMEOUT_S = 60  # 1 minute

USER_ALLOWLIST_PATH = Path.home() / ".flocks" / "ssh_allowed_commands.json"

# ---------------------------------------------------------------------------
# Safety: Static rule sets
# ---------------------------------------------------------------------------

# Commands that are unconditionally blocked (destructive / privilege-escalation).
# Pre-compiled at module level to avoid per-call regex compilation overhead.
_BLOCKED_PATTERN_SOURCES = [
    # File destruction / modification
    r"(?<![a-z])rm\b",
    r"\brmdir\b",
    r"\bmkdir\b",
    r"\btouch\b",
    r"\bcp\b\s",
    r"\bmv\b\s",
    r"\bln\b\s",
    r"\bchmod\b",
    r"\bchown\b",
    r"\bchattr\b",
    r"\btruncate\b",
    # Write redirections (applied to quote-stripped text, see _strip_quoted)
    r"(?<![<>])>>?\s",
    r"\btee\b",
    # Privilege escalation (note: passwd as FILE PATH /etc/passwd is allowed;
    # passwd as a COMMAND is caught via BLOCKED_BASE_COMMANDS below)
    r"(?<![a-z])sudo\b",
    r"(?<![a-z])su\b(\s|$)",
    # Process termination
    r"(?<![a-z])kill\b",
    r"\bkillall\b",
    r"\bpkill\b",
    r"\bpgrep\b.*-[a-z]*[Sk]",  # pgrep with kill signal
    # Package installation
    r"\bapt(?:-get)?\s+install\b",
    r"\byum\s+install\b",
    r"\bdnf\s+install\b",
    r"\bpip\s+install\b",
    r"\bnpm\s+install\b",
    r"\bsnap\s+install\b",
    r"\bbrew\s+install\b",
    # Service control (start/stop/restart/enable/disable)
    r"\bsystemctl\s+(start|stop|restart|enable|disable|mask|unmask)\b",
    r"\bservice\s+\S+\s+(start|stop|restart)\b",
    # File download with output
    r"\bwget\b",
    r"\bcurl\b.*(?:-o\b|--output\b)",
    # Shell rewriting
    r"\bsed\b.*-i\b",
    # Dangerous find with exec
    r"\bfind\b.*-exec\s+(?:rm|mv|cp|chmod|chown)\b",
    r"\bfind\b.*-delete\b",
]
BLOCKED_PATTERNS = [re.compile(p) for p in _BLOCKED_PATTERN_SOURCES]

# Commands that are unconditionally allowed (known read-only forensic commands)
ALLOWED_BASE_COMMANDS = {
    # System info
    "uname", "hostname", "hostnamectl", "uptime", "date", "timedatectl",
    "id", "whoami", "groups",
    # Process
    "ps", "pstree", "top", "htop", "pmap", "lsof",
    # Network
    "netstat", "ss", "ip", "ifconfig", "arp", "route", "nstat",
    "traceroute", "tracepath", "ping", "dig", "nslookup", "host",
    # File read
    "ls", "find", "cat", "head", "tail", "less", "more",
    "stat", "file", "wc", "diff",
    # Text processing (read-only)
    "grep", "egrep", "fgrep", "rg", "awk", "sed", "sort", "uniq",
    "cut", "tr", "strings", "hexdump", "xxd", "od",
    # Hashing / integrity
    "md5sum", "sha1sum", "sha256sum", "sha512sum",
    # Users / sessions
    "who", "w", "last", "lastlog", "lastb", "finger",
    "getent",
    # Persistence check
    "crontab", "at",
    "systemctl",  # read-only subcommands: status, list-units, list-timers
    # Package listing
    "dpkg", "rpm", "pip", "pip3", "gem", "npm", "snap",
    # Environment / history
    "env", "printenv", "export", "set",
    "history",
    # Disk / memory
    "df", "du", "free", "vmstat", "iostat", "sar", "dmesg",
    "lsblk", "fdisk", "parted", "mount",
    # Kernel / hardware
    "lsmod", "lspci", "lsusb", "lshw", "dmidecode",
    "sysctl",
    # Misc read tools
    "journalctl", "ausearch", "aureport",
    "readelf", "objdump", "nm",
    "openssl",
    # Shell builtins / utility commands commonly used in forensic pipelines
    "echo", "printf", "true", "false", "test", "sleep",
    "xargs",
    "column", "jq",
}

# Base commands that go to NEEDS_CONFIRM for LLM evaluation
NEEDS_CONFIRM_BASE_COMMANDS = {
    "python", "python2", "python3",
    "perl", "ruby", "node", "php",
    "bash", "sh", "zsh", "dash",  # only when used as interpreter with -c
    "curl",  # allowed only for GET without -o
    "nc", "ncat", "netcat",
    "strace", "ltrace",
    "dd",
    "base64",
}

# Base commands that are always blocked regardless of arguments
BLOCKED_BASE_COMMANDS = {
    "passwd", "usermod", "useradd", "userdel", "newgrp",
    "visudo", "vipw", "vigr",
}

# Read-only pip subcommands (positional, not flag-based)
PIP_READONLY_SUBCMDS = {"list", "show", "freeze", "check", "inspect"}

# Read-only systemctl subcommands
SYSTEMCTL_READONLY = {
    "status", "list-units", "list-timers", "list-sockets",
    "list-services", "show", "cat", "is-active", "is-enabled",
    "is-failed", "get-default",
}

# Read-only dpkg/rpm subcommands
PKG_READONLY = {"-l", "-L", "-s", "-S", "--list", "--listfiles",
                "--status", "--search", "-qa", "-ql", "-qi", "-qf"}


# ---------------------------------------------------------------------------
# Safety classifier
# ---------------------------------------------------------------------------

class SafetyDecision:
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    NEEDS_CONFIRM = "NEEDS_CONFIRM"


def _strip_quoted(text: str) -> str:
    """Remove single- and double-quoted substrings from *text*.

    Used before blocked-pattern regex matching so that operators inside
    quotes (e.g. ``awk '{if ($1 > 0) print}'``) are not misclassified
    as write redirections.
    """
    return re.sub(r"""'[^']*'|"[^"]*\"""", " ", text)


def _split_pipeline(command: str) -> list[str]:
    """Split a compound shell command into individual sub-commands.

    Respects single and double quotes so that delimiters inside quoted
    strings (e.g. ``grep "a|b" file``) are not treated as split points.
    """
    in_single = False
    in_double = False
    segments: list[str] = []
    current: list[str] = []
    i = 0
    n = len(command)

    while i < n:
        c = command[i]
        if c == "'" and not in_double:
            in_single = not in_single
            current.append(c)
        elif c == '"' and not in_single:
            in_double = not in_double
            current.append(c)
        elif not in_single and not in_double:
            if c == '|' or c == ';':
                segments.append("".join(current).strip())
                current = []
            elif c == '&' and i + 1 < n and command[i + 1] == '&':
                segments.append("".join(current).strip())
                current = []
                i += 1  # skip second &
            else:
                current.append(c)
        else:
            current.append(c)
        i += 1

    segments.append("".join(current).strip())
    return [s for s in segments if s]


def _get_base_command(segment: str) -> str:
    """Extract the base command name from a shell segment."""
    # Strip one or more leading env var assignments: LANG=C LC_ALL=C cmd → cmd
    segment = re.sub(r"^\s*(?:\w+=\S+\s+)+", "", segment).strip()
    tokens = segment.split()
    if not tokens:
        return ""
    return Path(tokens[0]).name  # handle /usr/bin/ps → ps


def _is_systemctl_readonly(segment: str) -> bool:
    tokens = segment.split()
    if len(tokens) < 2:
        return True
    subcmd = tokens[1].lstrip("-")
    return subcmd in SYSTEMCTL_READONLY


def _is_pkg_cmd_readonly(segment: str) -> bool:
    tokens = segment.split()
    if len(tokens) < 2:
        return True
    base = Path(tokens[0]).name
    # pip/pip3: check positional subcommand (pip list, pip show, pip freeze …)
    if base in {"pip", "pip3"}:
        subcmd = tokens[1] if not tokens[1].startswith("-") else None
        if subcmd and subcmd in PIP_READONLY_SUBCMDS:
            return True
        # Also allow flag-only variants: pip --version
        return all(t.startswith("-") for t in tokens[1:])
    # dpkg / rpm / gem / npm: check flag-based readonly markers
    for t in tokens[1:]:
        if t.startswith("-") and t in PKG_READONLY:
            return True
        if not t.startswith("-"):
            break
    return False


def _classify_segment(segment: str) -> str:
    """Classify a single pipeline segment."""
    # Strip quoted content so that operators inside strings
    # (e.g. awk '{if ($1 > 0) print}') are not mis-detected.
    stripped = _strip_quoted(segment)
    for compiled_re in BLOCKED_PATTERNS:
        if compiled_re.search(stripped):
            return SafetyDecision.BLOCKED

    base = _get_base_command(segment)
    if not base:
        return SafetyDecision.ALLOWED

    # Check base command against unconditional blocklist
    if base in BLOCKED_BASE_COMMANDS:
        return SafetyDecision.BLOCKED

    # Special handling for systemctl
    if base == "systemctl":
        return SafetyDecision.ALLOWED if _is_systemctl_readonly(segment) else SafetyDecision.BLOCKED

    # Special handling for dpkg / rpm / pip / npm
    if base in {"dpkg", "rpm", "pip", "pip3", "npm", "gem"}:
        return SafetyDecision.ALLOWED if _is_pkg_cmd_readonly(segment) else SafetyDecision.BLOCKED

    # Special handling for crontab
    if base == "crontab":
        # crontab -l is OK; -e/-r are not
        if re.search(r"\bcrontab\s+(-l|--list)\b", segment):
            return SafetyDecision.ALLOWED
        return SafetyDecision.BLOCKED

    # Special handling for at
    if base == "at":
        if re.search(r"\bat\s+-l\b|\batq\b", segment):
            return SafetyDecision.ALLOWED
        return SafetyDecision.BLOCKED

    if base in NEEDS_CONFIRM_BASE_COMMANDS:
        return SafetyDecision.NEEDS_CONFIRM

    if base in ALLOWED_BASE_COMMANDS:
        return SafetyDecision.ALLOWED

    # Unknown command → NEEDS_CONFIRM (conservative)
    return SafetyDecision.NEEDS_CONFIRM


def classify_command(command: str, user_allowlist: set[str]) -> tuple[str, str]:
    """
    Classify the full command string.

    Returns:
        (decision, reason) where decision is ALLOWED / BLOCKED / NEEDS_CONFIRM
    """
    # Check user persistent allowlist first
    command_stripped = command.strip()
    if command_stripped in user_allowlist:
        return SafetyDecision.ALLOWED, "user-allowlist"

    segments = _split_pipeline(command)
    decisions = []
    for seg in segments:
        d = _classify_segment(seg)
        decisions.append((d, seg))

    # Most restrictive wins
    if any(d == SafetyDecision.BLOCKED for d, _ in decisions):
        blocked_segs = [s for d, s in decisions if d == SafetyDecision.BLOCKED]
        return SafetyDecision.BLOCKED, f"blocked segment(s): {blocked_segs}"

    if any(d == SafetyDecision.NEEDS_CONFIRM for d, _ in decisions):
        confirm_segs = [s for d, s in decisions if d == SafetyDecision.NEEDS_CONFIRM]
        return SafetyDecision.NEEDS_CONFIRM, f"gray-area segment(s): {confirm_segs}"

    return SafetyDecision.ALLOWED, "static-rule"


# ---------------------------------------------------------------------------
# User allowlist persistence
# ---------------------------------------------------------------------------

def _load_user_allowlist() -> set[str]:
    if USER_ALLOWLIST_PATH.exists():
        try:
            data = json.loads(USER_ALLOWLIST_PATH.read_text())
            return set(data.get("commands", []))
        except Exception:
            pass
    return set()


def _save_to_user_allowlist(command: str) -> None:
    USER_ALLOWLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    existing = _load_user_allowlist()
    existing.add(command.strip())
    USER_ALLOWLIST_PATH.write_text(
        json.dumps({"commands": sorted(existing)}, indent=2, ensure_ascii=False)
    )


# Backward-compatible alias so internal callers and tests keep working.
_audit_log = audit_log


# ---------------------------------------------------------------------------
# LLM safety evaluation
# ---------------------------------------------------------------------------

async def _llm_evaluate_command(command: str) -> tuple[str, str]:
    """
    Ask the configured LLM to evaluate whether a command is safe for forensic use.

    Input: command string only (no host output, to prevent prompt injection).
    Returns: (decision, reason) where decision is SAFE / UNSAFE / UNCERTAIN.
    """
    try:
        from flocks.provider.manager import ProviderManager
        from flocks.config.config import Config

        llm = await Config.resolve_default_llm()
        if not llm:
            return "UNCERTAIN", "no LLM configured"

        provider = await ProviderManager.get(llm["provider_id"])

        system_prompt = (
            "You are a security command safety evaluator. "
            "Given a shell command intended for read-only forensic investigation of a potentially compromised Linux host, "
            "determine if it is safe to execute.\n\n"
            "Rules:\n"
            "- SAFE: the command only reads system state (processes, files, network, logs) without modifying anything\n"
            "- UNSAFE: the command could modify, delete, or damage the system in any way\n"
            "- UNCERTAIN: you cannot determine safety with confidence\n\n"
            "Respond with exactly one line in this format:\n"
            "DECISION: <SAFE|UNSAFE|UNCERTAIN>\n"
            "REASON: <one sentence explanation>\n\n"
            "Do NOT include any other text."
        )

        messages = [{"role": "user", "content": f"Command to evaluate:\n```\n{command}\n```"}]

        response_text = ""
        async for event in provider.chat_stream(
            model=llm["model_id"],
            system=system_prompt,
            messages=messages,
            max_tokens=100,
            temperature=0.0,
        ):
            if event.get("type") == "content_delta":
                response_text += event.get("text", "")

        # Parse response
        decision = "UNCERTAIN"
        reason = "parse error"
        for line in response_text.strip().splitlines():
            if line.startswith("DECISION:"):
                raw = line.split(":", 1)[1].strip().upper()
                if raw in ("SAFE", "UNSAFE", "UNCERTAIN"):
                    decision = raw
            elif line.startswith("REASON:"):
                reason = line.split(":", 1)[1].strip()

        return decision, reason

    except Exception as e:
        log.warn("ssh_host_cmd.llm_eval_failed", {"error": str(e)})
        return "UNCERTAIN", f"LLM eval error: {e}"


# ---------------------------------------------------------------------------
# Human confirmation with timeout
# ---------------------------------------------------------------------------

_CONFIRM_ALLOW_ONCE = "仅此次允许"
_CONFIRM_ALLOW_ALWAYS = "允许并加入永久白名单"
_CONFIRM_DENY = "拒绝执行"


async def _ask_human_with_timeout(
    ctx: ToolContext,
    command: str,
    llm_reason: str,
    timeout_s: int = HUMAN_CONFIRM_TIMEOUT_S,
) -> tuple[str, bool]:
    """
    Ask the human to confirm a command via the ``question`` tool.

    Returns (decision, add_to_allowlist).
    Automatically rejects after *timeout_s* seconds.
    """
    try:
        result = await asyncio.wait_for(
            ToolRegistry.execute(
                "question",
                ctx=ctx,
                questions=[{
                    "question": (
                        f"SSH命令安全确认\n\n"
                        f"命令：`{command}`\n"
                        f"原因：{llm_reason}\n\n"
                        f"是否允许执行？（{timeout_s // 60}分钟内无响应将自动拒绝）"
                    ),
                    "type": "choice",
                    "options": [
                        {"label": _CONFIRM_ALLOW_ONCE},
                        {"label": _CONFIRM_ALLOW_ALWAYS},
                        {"label": _CONFIRM_DENY},
                    ],
                }],
            ),
            timeout=timeout_s,
        )

        if not result.success:
            return "denied", False

        answers = result.metadata.get("answers", [])
        if not answers or not answers[0]:
            return "denied", False

        selected = answers[0][0]
        if selected == _CONFIRM_ALLOW_ALWAYS:
            return "approved", True
        elif selected == _CONFIRM_ALLOW_ONCE:
            return "approved", False
        else:
            return "denied", False

    except asyncio.TimeoutError:
        return "timeout", False
    except Exception:
        return "denied", False


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

@ToolRegistry.register_function(
    name="ssh_host_cmd",
    description=(
        "Execute read-only forensic commands on a remote Linux host via SSH. "
        "Use this tool during security investigations to check for compromise indicators, "
        "trace attack paths, analyze processes, network connections, logs, and persistence mechanisms. "
        "All commands are safety-checked before execution: destructive operations are automatically blocked. "
        "Supports multi-round interaction — call repeatedly to investigate based on previous findings."
    ),
    category=ToolCategory.TERMINAL,
    parameters=[
        ToolParameter(
            name="host",
            type=ParameterType.STRING,
            description="Target host IP address or hostname",
            required=True,
        ),
        ToolParameter(
            name="command",
            type=ParameterType.STRING,
            description="Read-only forensic command to execute (e.g. 'ps aux', 'ss -tunap', 'cat /var/log/auth.log')",
            required=True,
        ),
        ToolParameter(
            name="username",
            type=ParameterType.STRING,
            description="SSH username. Falls back to SecretManager 'ssh_default_user' if omitted.",
            required=False,
            default=None,
        ),
        ToolParameter(
            name="port",
            type=ParameterType.INTEGER,
            description="SSH port number",
            required=False,
            default=22,
        ),
        ToolParameter(
            name="key_path",
            type=ParameterType.STRING,
            description="Path to SSH private key file. Falls back to SecretManager 'ssh_default_key_path' or SSH agent.",
            required=False,
            default=None,
        ),
        ToolParameter(
            name="password",
            type=ParameterType.STRING,
            description="SSH password (prefer key-based auth). Falls back to SecretManager 'ssh_default_password'.",
            required=False,
            default=None,
        ),
        ToolParameter(
            name="timeout",
            type=ParameterType.INTEGER,
            description=f"Command execution timeout in seconds (default {DEFAULT_TIMEOUT_S}, max {MAX_TIMEOUT_S})",
            required=False,
            default=DEFAULT_TIMEOUT_S,
        ),
        ToolParameter(
            name="dry_run",
            type=ParameterType.BOOLEAN,
            description="If true, only check command safety without executing. Returns the safety decision.",
            required=False,
            default=False,
        ),
    ],
)
async def ssh_host_cmd(
    ctx: ToolContext,
    host: str,
    command: str,
    username: Optional[str] = None,
    port: int = 22,
    key_path: Optional[str] = None,
    password: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT_S,
    dry_run: bool = False,
) -> ToolResult:
    """Execute a read-only forensic command on a remote Linux host via SSH."""
    start_ms = int(time.time() * 1000)

    username, key_path, password = resolve_ssh_credentials(username, key_path, password)
    timeout = min(max(1, timeout), MAX_TIMEOUT_S)

    # ── ① Static rule classification ─────────────────────────────────────
    user_allowlist = _load_user_allowlist()
    decision, reason = classify_command(command, user_allowlist)

    if decision == SafetyDecision.BLOCKED:
        _audit_log(
            session_id=ctx.session_id,
            host=host, username=username, port=port,
            command=command,
            decision="BLOCKED", source="static-rule",
        )
        return ToolResult(
            success=False,
            output=None,
            error=f"[BLOCKED] Command rejected by safety policy: {reason}. Use only read-only forensic commands.",
        )

    # ── ② LLM evaluation for gray-area commands ──────────────────────────
    llm_source = "static-rule"
    if decision == SafetyDecision.NEEDS_CONFIRM:
        llm_decision, llm_reason = await _llm_evaluate_command(command)

        if llm_decision == "UNSAFE":
            _audit_log(
                session_id=ctx.session_id,
                host=host, username=username, port=port,
                command=command,
                decision="BLOCKED", source="LLM-blocked",
            )
            return ToolResult(
                success=False,
                output=None,
                error=f"[BLOCKED by LLM] {llm_reason}",
            )

        if llm_decision == "SAFE":
            llm_source = "LLM-approved"
            decision = SafetyDecision.ALLOWED

        else:  # UNCERTAIN → ③ human confirmation
            human_decision, add_to_allowlist = await _ask_human_with_timeout(
                ctx, command, llm_reason
            )

            if human_decision == "timeout":
                _audit_log(
                    session_id=ctx.session_id,
                    host=host, username=username, port=port,
                    command=command,
                    decision="BLOCKED", source="timeout-5min",
                )
                return ToolResult(
                    success=False,
                    output=None,
                    error="[BLOCKED] Human confirmation timed out (1 minute). Command rejected for safety.",
                )

            if human_decision == "denied":
                _audit_log(
                    session_id=ctx.session_id,
                    host=host, username=username, port=port,
                    command=command,
                    decision="BLOCKED", source="human-rejected",
                )
                return ToolResult(
                    success=False,
                    output=None,
                    error="[BLOCKED] User rejected command execution.",
                )

            # Approved by human
            if add_to_allowlist:
                _save_to_user_allowlist(command)
                llm_source = "human-approved+allowlisted"
            else:
                llm_source = "human-approved"
            decision = SafetyDecision.ALLOWED

    # ── Dry run ──────────────────────────────────────────────────────────
    if dry_run:
        return ToolResult(
            success=True,
            output={
                "dry_run": True,
                "command": command,
                "safety_decision": decision,
                "reason": reason,
                "source": llm_source,
            },
        )

    # ── Execute via SSH (with session-level connection pooling) ──────────
    try:
        exit_code, stdout, stderr = await execute_ssh_command(
            host=host,
            command=command,
            username=username,
            port=port,
            key_path=key_path,
            password=password,
            timeout_s=timeout,
            session_id=ctx.session_id,
        )
    except (asyncio.TimeoutError, Exception) as e:
        elapsed = int(time.time() * 1000) - start_ms
        _audit_log(
            session_id=ctx.session_id,
            host=host, username=username, port=port,
            command=command,
            decision="ALLOWED", source=llm_source,
            exit_code=-1, output_bytes=0, elapsed_ms=elapsed,
        )
        error_msg = (
            f"Command timed out after {timeout}s"
            if isinstance(e, asyncio.TimeoutError)
            else f"SSH connection failed: {e}"
        )
        return ToolResult(success=False, output=None, error=error_msg)

    elapsed = int(time.time() * 1000) - start_ms
    combined_output = stdout
    if stderr:
        combined_output += f"\n[stderr]\n{stderr}"

    _audit_log(
        session_id=ctx.session_id,
        host=host, username=username, port=port,
        command=command,
        decision="ALLOWED", source=llm_source,
        exit_code=exit_code,
        output_bytes=len(combined_output.encode()),
        elapsed_ms=elapsed,
    )

    return ToolResult(
        success=(exit_code == 0),
        output=combined_output or "(no output)",
        error=None if exit_code == 0 else f"Command exited with code {exit_code}",
        metadata={
            "host": host,
            "username": username,
            "port": port,
            "exit_code": exit_code,
            "elapsed_ms": elapsed,
            "safety_source": llm_source,
        },
    )
