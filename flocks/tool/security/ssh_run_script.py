"""
SSH Run Script Tool

Executes a local shell script on a remote Linux host via SSH in a single
connection. Designed for forensic data collection using user-visible,
user-editable scripts stored in skill directories.

Key differences from ssh_host_cmd:
  - Runs an entire script file (not ad-hoc commands)
  - Script is read from the local filesystem (skill directory)
  - Pre-flight safety scan checks for destructive operations
  - Parses ### SECTION_NAME ### markers into structured output
  - No CommandSafetyChecker interactive approval — responsibility lies
    with the script author (user-editable scripts are trusted by design
    after the automated safety scan passes)

Typical usage:
  ssh_run_script(host="10.0.0.1", script_path=".flocks/plugins/agents/host-forensics/scripts/triage.sh")
  ssh_run_script(host="10.0.0.1", script_path=".flocks/plugins/agents/host-forensics/scripts/deep_scan.sh", timeout=300)
"""

import asyncio
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
from flocks.tool.security.ssh_utils import audit_log, execute_ssh_command, resolve_ssh_credentials
from flocks.utils.log import Log

log = Log.create(service="tool.ssh_run_script")

DEFAULT_TIMEOUT_S = 60
MAX_TIMEOUT_S = 600
MAX_OUTPUT_BYTES = 80_000  # ~80KB

# ---------------------------------------------------------------------------
# Pre-flight safety scanner
# ---------------------------------------------------------------------------

# Patterns that indicate write / destructive / privilege-escalating operations.
# Applied line-by-line after stripping comments and quoted substrings.
_DANGEROUS_PATTERN_SOURCES = [
    # File deletion / overwrite
    (r"(?<![a-z])rm\b", "file deletion (rm)"),
    (r"\brmdir\b", "directory deletion (rmdir)"),
    (r"\btruncate\b", "file truncation"),
    # Write redirections — catches `> file` and `>> file`.
    # Excludes `> /dev/null` and `>> /dev/null` (harmless output discard).
    # We strip quoted strings first so awk/sed patterns don't trigger.
    (r"(?<![<>])>>?\s+(?!/dev/null)\S", "write redirection (> or >>)"),
    (r"\btee\b", "file write via tee"),
    # Permission / ownership changes
    (r"\bchmod\b", "permission change (chmod)"),
    (r"\bchown\b", "ownership change (chown)"),
    (r"\bchattr\b", "attribute change (chattr)"),
    # File creation / move
    (r"\btouch\b", "file creation (touch)"),
    (r"\bmkdir\b", "directory creation (mkdir)"),
    (r"\bmv\b\s", "file move (mv)"),
    (r"\bcp\b\s", "file copy (cp)"),
    (r"\bln\b\s", "symlink/hardlink (ln)"),
    # Privilege escalation
    (r"(?<![a-z])sudo\b", "privilege escalation (sudo)"),
    (r"(?<![a-z])su\b(\s|$)", "privilege escalation (su)"),
    # Process termination
    (r"(?<![a-z])kill\b", "process termination (kill)"),
    (r"\bkillall\b", "process termination (killall)"),
    (r"\bpkill\b", "process termination (pkill)"),
    # Service control
    (r"\bsystemctl\s+(start|stop|restart|enable|disable|mask|unmask)\b", "service control (systemctl)"),
    (r"\bservice\s+\S+\s+(start|stop|restart)\b", "service control (service)"),
    # Package installation
    (r"\bapt(?:-get)?\s+install\b", "package install (apt)"),
    (r"\byum\s+install\b", "package install (yum)"),
    (r"\bdnf\s+install\b", "package install (dnf)"),
    (r"\bpip\s+install\b", "package install (pip)"),
    # File download to disk
    (r"\bwget\b", "file download (wget)"),
    (r"\bcurl\b.*(?:-o\b|--output\b)", "file download (curl -o)"),
    # In-place editing
    (r"\bsed\b.*-i\b", "in-place file edit (sed -i)"),
    # Dangerous find with exec
    (r"\bfind\b.*-exec\s+(?:rm|mv|cp|chmod|chown)\b", "destructive find -exec"),
    (r"\bfind\b.*-delete\b", "destructive find -delete"),
]

_DANGEROUS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(src), desc) for src, desc in _DANGEROUS_PATTERN_SOURCES
]


def _strip_quoted(text: str) -> str:
    """Remove single- and double-quoted substrings to avoid false positives."""
    return re.sub(r"""'[^']*'|"[^"]*\"""", " ", text)


def _scan_script_safety(script_content: str) -> list[str]:
    """
    Scan script content for dangerous operations line by line.

    Returns a list of human-readable violation descriptions.
    Empty list means the script passed all checks.
    """
    violations: list[str] = []
    for lineno, raw_line in enumerate(script_content.splitlines(), start=1):
        stripped = raw_line.strip()
        # Skip blank lines and comment lines
        if not stripped or stripped.startswith("#"):
            continue
        # Strip inline comments (heuristic: # preceded by whitespace)
        code_part = re.sub(r"\s+#.*$", "", stripped)
        # Strip quoted content to avoid false positives on string literals
        scannable = _strip_quoted(code_part)
        for pattern, description in _DANGEROUS_PATTERNS:
            if pattern.search(scannable):
                violations.append(f"  Line {lineno}: {description} — `{stripped[:120]}`")
                break  # one violation per line is enough
    return violations


# ---------------------------------------------------------------------------
# Output post-processing
# ---------------------------------------------------------------------------

def _extract_sections(output: str) -> dict[str, str]:
    """Parse '### SECTION_NAME ###' markers into a dict."""
    sections: dict[str, str] = {}
    current_section = "HEADER"
    current_lines: list[str] = []

    for line in output.splitlines():
        if line.startswith("### ") and line.endswith(" ###"):
            sections[current_section] = "\n".join(current_lines).strip()
            current_section = line[4:-4].strip()
            current_lines = []
        else:
            current_lines.append(line)

    sections[current_section] = "\n".join(current_lines).strip()
    return sections


def _truncate_output(output: str, max_bytes: int = MAX_OUTPUT_BYTES) -> tuple[str, bool]:
    """Truncate output to max_bytes, preserving line boundaries."""
    encoded = output.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return output, False
    truncated = encoded[:max_bytes].decode("utf-8", errors="replace")
    last_newline = truncated.rfind("\n")
    if last_newline > 0:
        truncated = truncated[:last_newline]
    return truncated + "\n\n[... output truncated, remaining data omitted ...]", True


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

@ToolRegistry.register_function(
    name="ssh_run_script",
    description=(
        "Execute a local shell script on a remote Linux host via SSH in a single connection. "
        "The script is read from the local filesystem (typically a skill's scripts/ directory), "
        "safety-scanned for destructive operations, then executed on the remote host.\n\n"
        "WHEN TO USE: When following a skill or plugin agent that defines forensic investigation scripts "
        "(e.g. .flocks/plugins/agents/host-forensics/scripts/triage.sh). "
        "The script runs as a single SSH session — efficient for batch data collection.\n\n"
        "OUTPUT: Structured text with ### SECTION_NAME ### markers for each category of "
        "collected data. If any dangerous operations (rm, chmod, write redirections, etc.) "
        "are detected in the script, execution is blocked and violations are reported.\n\n"
        "SCRIPT PATH: Prefer a path relative to the current working directory (workspace root), "
        "e.g. '.flocks/plugins/agents/host-forensics/scripts/triage.sh'. "
        "Absolute paths and '~' home-directory paths are also accepted."
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
            name="script_path",
            type=ParameterType.STRING,
            description=(
                "Path to the local .sh script to execute on the remote host. "
                "Relative paths are resolved from the current working directory (workspace root). "
                "Example: .flocks/plugins/agents/host-forensics/scripts/triage.sh"
            ),
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
            description="SSH password (prefer key-based auth).",
            required=False,
            default=None,
        ),
        ToolParameter(
            name="timeout",
            type=ParameterType.INTEGER,
            description=f"Script execution timeout in seconds (default {DEFAULT_TIMEOUT_S}, max {MAX_TIMEOUT_S}). "
                        "Use a higher value (e.g. 300) for deep_scan.sh which runs more commands.",
            required=False,
            default=DEFAULT_TIMEOUT_S,
        ),
    ],
)
async def ssh_run_script(
    ctx: ToolContext,
    host: str,
    script_path: str,
    username: Optional[str] = None,
    port: int = 22,
    key_path: Optional[str] = None,
    password: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT_S,
) -> ToolResult:
    """
    Read a local shell script, safety-scan it, and execute it on a remote
    host via SSH. Returns structured output parsed by ### SECTION ### markers.
    """
    start_ms = int(time.time() * 1000)

    # Resolve script path (relative to cwd = workspace root)
    resolved_path = Path(script_path).expanduser()
    if not resolved_path.is_absolute():
        resolved_path = Path.cwd() / resolved_path

    if not resolved_path.exists():
        return ToolResult(
            success=False,
            output=None,
            error=(
                f"Script not found: {resolved_path}\n"
                "Expected a path relative to workspace root, e.g. "
                ".flocks/plugins/agents/host-forensics/scripts/triage.sh"
            ),
        )

    if not resolved_path.is_file():
        return ToolResult(
            success=False,
            output=None,
            error=f"Path is not a file: {resolved_path}",
        )

    # Read script content
    try:
        script_content = resolved_path.read_text(encoding="utf-8")
    except OSError as e:
        return ToolResult(success=False, output=None, error=f"Cannot read script: {e}")

    if not script_content.strip():
        return ToolResult(success=False, output=None, error="Script file is empty.")

    # Safety scan
    violations = _scan_script_safety(script_content)
    if violations:
        violation_list = "\n".join(violations)
        return ToolResult(
            success=False,
            output=None,
            error=(
                f"Script safety scan FAILED — {len(violations)} dangerous operation(s) detected "
                f"in '{script_path}':\n{violation_list}\n\n"
                "Edit the script to remove destructive commands before running on a remote host."
            ),
        )

    username, key_path, password = resolve_ssh_credentials(username, key_path, password)
    timeout = min(max(10, timeout), MAX_TIMEOUT_S)

    script_label = resolved_path.name  # e.g. "triage.sh"
    log.debug(f"Loaded script '{script_label}' ({len(script_content)} bytes) for host {host}")

    try:
        exit_code, stdout, stderr = await execute_ssh_command(
            host=host,
            command=script_content,
            username=username,
            port=port,
            key_path=key_path,
            password=password,
            timeout_s=timeout,
            session_id=ctx.session_id,
        )
    except Exception as e:
        elapsed = int(time.time() * 1000) - start_ms
        audit_log(
            session_id=ctx.session_id,
            host=host, username=username, port=port,
            command=f"[script:{script_label}]",
            decision="ALLOWED", source="ssh_run_script",
            exit_code=-1, output_bytes=0, elapsed_ms=elapsed,
        )
        error_msg = (
            f"Script '{script_label}' timed out after {timeout}s"
            if isinstance(e, asyncio.TimeoutError)
            else f"SSH connection failed: {e}"
        )
        return ToolResult(success=False, output=None, error=error_msg)

    elapsed = int(time.time() * 1000) - start_ms
    raw_output = stdout
    if stderr:
        raw_output += f"\n[stderr]\n{stderr}"

    truncated_output, was_truncated = _truncate_output(raw_output)
    sections = _extract_sections(truncated_output)

    audit_log(
        session_id=ctx.session_id,
        host=host, username=username, port=port,
        command=f"[script:{script_label}]",
        decision="ALLOWED", source="ssh_run_script",
        exit_code=exit_code,
        output_bytes=len(raw_output.encode()),
        elapsed_ms=elapsed,
    )

    summary_header = (
        f"=== SCRIPT EXECUTION SUMMARY ===\n"
        f"Script: {script_label} | Host: {host} | User: {username} | Elapsed: {elapsed}ms\n"
        f"Exit code: {exit_code} | Sections collected: {len([k for k in sections if k not in ('HEADER', '')])}\n"
    )
    if was_truncated:
        summary_header += f"[WARNING] Output was truncated to {MAX_OUTPUT_BYTES // 1024}KB\n"
    summary_header += "\n=== FULL OUTPUT ===\n"

    final_output = summary_header + truncated_output

    return ToolResult(
        success=(exit_code == 0),
        output=final_output,
        error=None if exit_code == 0 else f"Script exited with code {exit_code} (partial output may still be useful)",
        metadata={
            "host": host,
            "username": username,
            "port": port,
            "script": script_label,
            "script_path": str(resolved_path),
            "exit_code": exit_code,
            "elapsed_ms": elapsed,
            "output_bytes_raw": len(raw_output.encode()),
            "output_truncated": was_truncated,
            "sections_collected": [k for k in sections if k not in ("HEADER", "")],
        },
    )
