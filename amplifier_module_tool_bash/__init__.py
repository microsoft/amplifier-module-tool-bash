"""
Bash command execution tool for Amplifier.
Includes safety features and approval mechanisms.
"""

# Amplifier module metadata
__amplifier_module_type__ = "tool"

import asyncio
import logging
import os
import shlex
import shutil
import signal
import sys
from typing import Any

from amplifier_core import ModuleCoordinator
from amplifier_core import ToolResult

logger = logging.getLogger(__name__)


async def mount(coordinator: ModuleCoordinator, config: dict[str, Any] | None = None):
    """
    Mount the bash tool.

    Args:
        coordinator: Module coordinator
        config: Tool configuration

    Returns:
        Optional cleanup function
    """
    config = config or {}
    tool = BashTool(config)
    await coordinator.mount("tools", tool, name=tool.name)
    logger.info("Mounted BashTool")
    return


class BashTool:
    """Execute bash commands with safety features."""

    name = "bash"
    description = """
Low-level shell command execution. This is a fallback primitive - before using bash directly,
consider whether specialized capabilities exist for your task. Specialized options typically offer
better error handling, structured output, domain expertise, and safety guardrails.

WHEN TO USE BASH:
- Build and test commands (pytest, npm test, cargo build, make)
- Package management (pip, npm, cargo, brew)
- Version control operations (git status, git diff, git commit)
- Container operations (docker, podman, kubectl)
- GitHub CLI (gh pr create, gh issue list)
- System utilities when no specialized option exists

INTRINSIC LIMITATIONS (why specialized options are often better):
- Raw text output requiring manual parsing
- No domain-specific context or best practices built in
- No built-in retry logic or intelligent error recovery
- No semantic understanding of your intent

OUTPUT LIMITS:
- Long outputs are automatically truncated to prevent context overflow
- When truncated, you'll see: first lines, "[...truncated...]", last lines, and byte counts
- WARNING: If output contains JSON, XML, or similar structured data, truncation may break parsing
- WORKAROUND: For large structured output, redirect to a file (command > output.json) and use
  file reading capabilities to inspect portions of the file as needed

COMMAND GUIDELINES:
- Quote paths containing spaces: cd "/path/with spaces"
- Prefer absolute paths to maintain working directory context
- Chain dependent commands with && (mkdir foo && cd foo)
- Use `run_in_background` for long-running processes (dev servers, watchers)
- Interactive commands (-i flags, editors requiring input) are not supported

SAFETY:
- Destructive commands (rm -rf /, sudo rm, etc.) are blocked
- Commands requiring interactive input will fail
                   """

    # Default output limit: ~100KB (roughly 25k tokens)
    DEFAULT_MAX_OUTPUT_BYTES = 100_000

    def __init__(self, config: dict[str, Any]):
        """
        Initialize bash tool.

        Args:
            config: Tool configuration
        """
        self.config = config
        self.require_approval = config.get("require_approval", True)
        self.allowed_commands = config.get("allowed_commands", [])
        self.denied_commands = config.get(
            "denied_commands", ["rm -rf /", "sudo rm", "dd if=/dev/zero", "fork bomb", ":(){ :|:& };:"]
        )
        self.timeout = config.get("timeout", 30)
        self.working_dir = config.get("working_dir", ".")
        # Output limiting to prevent context overflow
        self.max_output_bytes = config.get("max_output_bytes", self.DEFAULT_MAX_OUTPUT_BYTES)

    @property
    def input_schema(self) -> dict:
        """Return JSON schema for tool parameters."""
        return {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Bash command to execute"},
                "run_in_background": {
                    "type": "boolean",
                    "description": "Run command in background, returning immediately with PID. Use for long-running processes like dev servers.",
                    "default": False,
                },
            },
            "required": ["command"],
        }

    def get_metadata(self) -> dict[str, Any]:
        """Return tool metadata for approval system."""
        return {
            "requires_approval": self.require_approval,
            "approval_hints": {
                "risk_level": "high",
                "dangerous_patterns": self.denied_commands,
                "safe_patterns": self.allowed_commands,
            },
        }

    async def execute(self, input: dict[str, Any]) -> ToolResult:
        """
        Execute a bash command.

        Args:
            input: Dictionary with 'command' and optional 'run_in_background' keys

        Returns:
            Tool result with command output
        """
        command = input.get("command")
        if not command:
            return ToolResult(success=False, error={"message": "Command is required"})

        run_in_background = input.get("run_in_background", False)

        # Safety checks
        if not self._is_safe_command(command):
            return ToolResult(success=False, error={"message": f"Command denied for safety: {command}"})

        # Approval is now handled by approval hook via tool:pre event

        try:
            if run_in_background:
                # Execute command in background and return immediately
                result = await self._run_command_background(command)
                return ToolResult(
                    success=True,
                    output={
                        "pid": result["pid"],
                        "message": f"Command started in background with PID {result['pid']}",
                        "note": "Use 'ps' or 'kill' commands to manage the background process.",
                    },
                )
            else:
                # Execute command and wait for completion
                result = await self._run_command(command)

                # Apply output truncation to prevent context overflow
                stdout, stdout_truncated, stdout_bytes = self._truncate_output(result["stdout"])
                stderr, stderr_truncated, stderr_bytes = self._truncate_output(result["stderr"])

                output = {
                    "stdout": stdout,
                    "stderr": stderr,
                    "returncode": result["returncode"],
                }

                # Include truncation metadata if either was truncated
                if stdout_truncated or stderr_truncated:
                    output["truncated"] = True
                    if stdout_truncated:
                        output["stdout_total_bytes"] = stdout_bytes
                    if stderr_truncated:
                        output["stderr_total_bytes"] = stderr_bytes

                return ToolResult(
                    success=result["returncode"] == 0,
                    output=output,
                )

        except TimeoutError:
            return ToolResult(success=False, error={"message": f"Command timed out after {self.timeout} seconds"})
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return ToolResult(success=False, error={"message": str(e)})

    def _is_safe_command(self, command: str) -> bool:
        """Check if command is safe to execute."""
        command_lower = command.lower()

        # Check against denied commands
        for denied in self.denied_commands:
            if denied.lower() in command_lower:
                logger.warning(f"Denied dangerous command: {command}")
                return False

        # Check for suspicious patterns
        dangerous_patterns = [
            "rm -rf",
            "rm -fr",
            "dd if=",
            "mkfs",
            "> /dev/",
            "sudo",
            "su -",
            "passwd",
            "chmod 777 /",
            "chown -R",
        ]

        for pattern in dangerous_patterns:
            if pattern in command_lower:
                logger.warning(f"Suspicious pattern detected: {pattern}")
                return False

        return True

    def _is_pre_approved(self, command: str) -> bool:
        """Check if command is pre-approved."""
        if not self.allowed_commands:
            return False

        # Check exact matches
        if command in self.allowed_commands:
            return True

        # Check pattern matches
        for allowed in self.allowed_commands:
            if allowed.endswith("*"):
                # Prefix match
                if command.startswith(allowed[:-1]):
                    return True
            elif "*" in allowed:
                # Pattern match (simple)
                pattern = allowed.replace("*", ".*")
                import re

                if re.match(pattern, command):
                    return True

        return False

    def _truncate_output(self, output: str) -> tuple[str, bool, int]:
        """Truncate output if it exceeds max_output_bytes.

        Returns:
            Tuple of (possibly truncated output, was_truncated, original_bytes)
        """
        original_bytes = len(output.encode("utf-8"))

        if original_bytes <= self.max_output_bytes:
            return output, False, original_bytes

        # Preserve head and tail with truncation indicator
        # Use roughly 40% head, 40% tail, leaving room for indicator
        head_bytes = int(self.max_output_bytes * 0.4)
        tail_bytes = int(self.max_output_bytes * 0.4)

        # Split into lines for cleaner truncation
        lines = output.split("\n")

        # Build head (first N lines up to head_bytes)
        head_lines = []
        head_size = 0
        for line in lines:
            line_bytes = len((line + "\n").encode("utf-8"))
            if head_size + line_bytes > head_bytes:
                break
            head_lines.append(line)
            head_size += line_bytes

        # Build tail (last N lines up to tail_bytes)
        tail_lines = []
        tail_size = 0
        for line in reversed(lines):
            line_bytes = len((line + "\n").encode("utf-8"))
            if tail_size + line_bytes > tail_bytes:
                break
            tail_lines.insert(0, line)
            tail_size += line_bytes

        # Compose truncated output
        truncation_indicator = (
            f"\n\n[...OUTPUT TRUNCATED...]\n"
            f"[Showing first {len(head_lines)} lines and last {len(tail_lines)} lines]\n"
            f"[Total output: {original_bytes:,} bytes, limit: {self.max_output_bytes:,} bytes]\n"
            f"[TIP: For large structured output (JSON/XML), redirect to file and read portions]\n\n"
        )

        truncated = "\n".join(head_lines) + truncation_indicator + "\n".join(tail_lines)
        return truncated, True, original_bytes

    async def _run_command_background(self, command: str) -> dict[str, Any]:
        """Run command in background, returning immediately with PID.

        The process is fully detached with:
        - New session (setsid) so it's not killed when parent exits
        - Pipes redirected to /dev/null to prevent blocking
        - Returns immediately with PID for management
        """
        is_windows = sys.platform == "win32"

        if is_windows:
            # Windows background execution
            bash_exe = shutil.which("bash")
            if bash_exe:
                # Use bash with nohup-style detachment
                process = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                    stdin=asyncio.subprocess.DEVNULL,
                    executable=bash_exe,
                    cwd=self.working_dir,
                    creationflags=0x00000008,  # DETACHED_PROCESS on Windows
                )
            else:
                try:
                    args = shlex.split(command)
                except ValueError as e:
                    raise ValueError(f"Invalid command syntax: {e}")

                process = await asyncio.create_subprocess_exec(
                    *args,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                    stdin=asyncio.subprocess.DEVNULL,
                    cwd=self.working_dir,
                    creationflags=0x00000008,  # DETACHED_PROCESS
                )
        else:
            # Unix-like: Use setsid to create new session, fully detached
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                stdin=asyncio.subprocess.DEVNULL,
                executable="/bin/bash",
                cwd=self.working_dir,
                start_new_session=True,  # Creates new session, detaches from terminal
            )

        return {"pid": process.pid}

    async def _run_command(self, command: str) -> dict[str, Any]:
        """Run command asynchronously with platform-appropriate shell.

        On Unix-like systems (Linux, macOS, WSL), uses bash for full shell features.
        On Windows, attempts to find bash (Git Bash or WSL bash).
        Falls back to cmd.exe with limitations if bash is not found.

        Uses process groups for proper cleanup on timeout - kills entire process tree.
        """
        # Detect platform
        is_windows = sys.platform == "win32"
        process = None
        pgid = None

        if is_windows:
            # Try to find bash (Git Bash or WSL bash)
            bash_exe = shutil.which("bash")

            if bash_exe:
                # Bash found on Windows - use it with full shell features
                process = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    executable=bash_exe,
                    cwd=self.working_dir,
                )
            else:
                # No bash found - fall back to limited cmd.exe behavior
                # Check for shell features that won't work in cmd.exe
                shell_features = ["|", "&&", "||", "~", ">", "<", "2>&1", "$(", "`"]
                if any(feature in command for feature in shell_features):
                    return {
                        "stdout": "",
                        "stderr": (
                            "Bash not found in PATH.\n"
                            "\n"
                            "Shell features like |, &&, ||, ~, redirects require bash.\n"
                            "\n"
                            "Install Git for Windows (includes Git Bash):\n"
                            "  https://git-scm.com/download/win\n"
                            "\n"
                            "Or install WSL:\n"
                            "  https://learn.microsoft.com/en-us/windows/wsl/install"
                        ),
                        "returncode": 1,
                    }

                # Windows: Use direct execution (no shell) for simple commands
                try:
                    args = shlex.split(command)
                except ValueError as e:
                    raise ValueError(f"Invalid command syntax: {e}")

                process = await asyncio.create_subprocess_exec(
                    *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, cwd=self.working_dir
                )
        else:
            # Unix-like (Linux, macOS, WSL): Use real bash shell
            # This enables:
            # - Tilde expansion (~)
            # - Shell operators (&&, ||, |, ;)
            # - Redirects (>, <, 2>&1, &>)
            # - Command substitution ($(...), `...`)
            # - Variable expansion ($VAR)
            # - Heredocs (<<EOF)
            #
            # start_new_session=True creates a new process group, enabling
            # us to kill the entire process tree on timeout (not just bash)

            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                executable="/bin/bash",  # Explicit bash (not /bin/sh)
                cwd=self.working_dir,
                start_new_session=True,  # Creates new process group for proper cleanup
            )
            # Get the process group ID (same as PID when start_new_session=True)
            pgid = process.pid

        # Wait for completion with timeout
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.timeout)

            return {
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stderr": stderr.decode("utf-8", errors="replace"),
                "returncode": process.returncode,
            }

        except TimeoutError:
            # Kill the entire process group (all children) on Unix
            if pgid is not None and not is_windows:
                try:
                    # Send SIGTERM to process group first (graceful shutdown)
                    os.killpg(pgid, signal.SIGTERM)
                    # Give processes a moment to clean up
                    await asyncio.sleep(0.5)
                    # Force kill if still running
                    try:
                        os.killpg(pgid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass  # Already terminated
                except ProcessLookupError:
                    pass  # Process group already gone
                except PermissionError:
                    # Fall back to killing just the main process
                    process.kill()
            else:
                # Windows or no pgid: kill just the main process
                process.kill()

            # Clean up
            try:
                await asyncio.wait_for(process.communicate(), timeout=5)
            except TimeoutError:
                pass  # Best effort cleanup
            raise
