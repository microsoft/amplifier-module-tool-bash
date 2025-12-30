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
Executes a given bash command in a persistent shell session with optional timeout, ensuring proper
handling and security measures.

IMPORTANT: This tool is for terminal operations like git, npm, docker, etc. DO NOT use it for file
operations (reading, writing, editing, searching, finding files) - use the specialized tools for this instead.

Before executing the command, please follow these steps:

1. Directory Verification:
   - If the command will create new directories or files, first use `ls` to verify the parent directory exists
     and is the correct location
   - For example, before running "mkdir foo/bar", first use `ls foo` to check that "foo" exists and is the
     intended parent directory

2. Command Execution:
   - Always quote file paths that contain spaces with double quotes (e.g., cd "path with spaces/file.txt")
   - Examples of proper quoting:
     - cd "/Users/name/My Documents" (correct)
     - cd /Users/name/My Documents (incorrect - will fail)
     - python "/path/with spaces/script.py" (correct)
     - python /path/with spaces/script.py (incorrect - will fail)
   - After ensuring proper quoting, execute the command.
   - Capture the output of the command.

Usage notes:
  - The command argument is required.

  - You can use the `run_in_background` parameter to run the command in the background, which allows you to continue working while the command runs. You can monitor the output using the bash tool as it becomes available. You do not need to use '&' at the end of the command when using this parameter.
  - Avoid using bash with the `find`, `grep`, `cat`, `head`, `tail`, `sed`, `awk`, or `echo` commands, unless explicitly instructed or when these commands are truly necessary for the task. Instead, always prefer using the dedicated tools for these commands:
    - File search: Use glob (NOT find or ls)
    - Content search: Use grep (NOT grep or rg)
    - Read files: Use read_file (NOT cat/head/tail)
    - Edit files: Use edit_file (NOT sed/awk)
    - Write files: Use write_file (NOT echo >/cat <<EOF)
    - Communication: Output text directly (NOT echo/printf)
  - When issuing multiple commands:
    - If the commands are independent and can run in parallel, make multiple bash tool calls in a single message. For example, if you need to run "git status" and "git diff", send a single message with two bash tool calls in parallel.
    - If the commands depend on each other and must run sequentially, use a single bash call with '&&' to chain them together (e.g., `git add . && git commit -m "message" && git push`). For instance, if one operation must complete before another starts (like mkdir before cp, write_file before bash for git operations, or git add before git commit), run these operations sequentially instead.
    - Use ';' only when you need to run commands sequentially but don't care if earlier commands fail
    - DO NOT use newlines to separate commands (newlines are ok in quoted strings)
  - Try to maintain your current working directory throughout the session by using absolute paths and avoiding usage of `cd`. You may use `cd` if the User explicitly requests it.
    <good-example>
    pytest /foo/bar/tests
    </good-example>
    <bad-example>
    cd /foo/bar && pytest tests
    </bad-example>

# Committing changes with git

Only create commits when requested by the user. If unclear, ask first. When the user asks you to create a new git commit, follow these steps carefully:

Git Safety Protocol:
- NEVER update the git config
- NEVER run destructive/irreversible git commands (like push --force, hard reset, etc) unless the user explicitly requests them
- NEVER skip hooks (--no-verify, --no-gpg-sign, etc) unless the user explicitly requests it
- NEVER run force push to main/master, warn the user if they request it
- Avoid git commit --amend.  ONLY use --amend when either (1) user explicitly requested amend OR (2) adding edits from pre-commit hook (additional instructions below)
- Before amending: ALWAYS check authorship (git log -1 --format='%an %ae')
- NEVER commit changes unless the user explicitly asks you to. It is VERY IMPORTANT to only commit when explicitly asked, otherwise the user will feel that you are being too proactive.

1. You can call multiple tools in a single response. When multiple independent pieces of information are requested and all commands are likely to succeed, run multiple tool calls in parallel for optimal performance. run the following bash commands in parallel, each using the bash tool:
  - Run a git status command to see all untracked files.
  - Run a git diff command to see both staged and unstaged changes that will be committed.
  - Run a git log command to see recent commit messages, so that you can follow this repository's commit message style.
2. Analyze all staged changes (both previously staged and newly added) and draft a commit message:
  - Summarize the nature of the changes (eg. new feature, enhancement to an existing feature, bug fix, refactoring, test, docs, etc.). Ensure the message accurately reflects the changes and their purpose (i.e. "add" means a wholly new feature, "update" means an enhancement to an existing feature, "fix" means a bug fix, etc.).
  - Do not commit files that likely contain secrets (.env, credentials.json, etc). Warn the user if they specifically request to commit those files
  - Draft a concise (1-2 sentences) commit message that focuses on the "why" rather than the "what"
  - Ensure it accurately reflects the changes and their purpose
3. You can call multiple tools in a single response. When multiple independent pieces of information are requested and all commands are likely to succeed, run multiple tool calls in parallel for optimal performance. run the following commands:
   - Add relevant untracked files to the staging area.
   - Create the commit with a message ending with:
     🤖 Generated with [Amplifier](https://github.com/microsoft/amplifier)

     Co-Authored-By: Amplifier <240397093+microsoft-amplifier@users.noreply.github.com>
   - Run git status after the commit completes to verify success.
   Note: git status depends on the commit completing, so run it sequentially after the commit.
4. If the commit fails due to pre-commit hook changes, retry ONCE. If it succeeds but files were modified by the hook, verify it's safe to amend:
   - Check authorship: git log -1 --format='%an %ae'
   - Check not pushed: git status shows "Your branch is ahead"
   - If both true: amend your commit. Otherwise: create NEW commit (never amend other developers' commits)

Important notes:
- NEVER run additional commands to read or explore code, besides git bash commands
- NEVER use the todo or task tools
- DO NOT push to the remote repository unless the user explicitly asks you to do so
- IMPORTANT: Never use git commands with the -i flag (like git rebase -i or git add -i) since they require interactive input which is not supported.
- If there are no changes to commit (i.e., no untracked files and no modifications), do not create an empty commit
- In order to ensure good formatting, ALWAYS pass the commit message via a HEREDOC, a la this example:
<example>
git commit -m "$(cat <<'EOF'
   Commit message here.

   🤖 Generated with [Amplifier](https://github.com/microsoft/amplifier)

   Co-Authored-By: Amplifier <240397093+microsoft-amplifier@users.noreply.github.com>
   EOF
   )"
</example>

# Creating pull requests
Use the gh command via the bash tool for ALL GitHub-related tasks including working with issues, pull requests, checks, and releases. If given a Github URL use the gh command to get the information needed.

IMPORTANT: When the user asks you to create a pull request, follow these steps carefully:

1. You can call multiple tools in a single response. When multiple independent pieces of information are requested and all commands are likely to succeed, run multiple tool calls in parallel for optimal performance. run the following bash commands in parallel using the bash tool, in order to understand the current state of the branch since it diverged from the main branch:
   - Run a git status command to see all untracked files
   - Run a git diff command to see both staged and unstaged changes that will be committed
   - Check if the current branch tracks a remote branch and is up to date with the remote, so you know if you need to push to the remote
   - Run a git log command and `git diff [base-branch]...HEAD` to understand the full commit history for the current branch (from the time it diverged from the base branch)
2. Analyze all changes that will be included in the pull request, making sure to look at all relevant commits (NOT just the latest commit, but ALL commits that will be included in the pull request!!!), and draft a pull request summary
3. You can call multiple tools in a single response. When multiple independent pieces of information are requested and all commands are likely to succeed, run multiple tool calls in parallel for optimal performance. run the following commands in parallel:
   - Create new branch if needed
   - Push to remote with -u flag if needed
   - Create PR using gh pr create with the format below. Use a HEREDOC to pass the body to ensure correct formatting.
<example>
gh pr create --title "the pr title" --body "$(cat <<'EOF'
## Summary
<1-3 bullet points>

## Test plan
[Bulleted markdown checklist of TODOs for testing the pull request...]

🤖 Generated with [Amplifier](https://github.com/microsoft/amplifier)

Co-Authored-By: Amplifier <240397093+microsoft-amplifier@users.noreply.github.com>
EOF
)"
</example>

Important:
- DO NOT use the todo or task tools
- Return the PR URL when you're done, so the user can see it

# Other common operations
- View comments on a Github PR: gh api repos/foo/bar/pulls/123/comments
                   """

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
                return ToolResult(
                    success=result["returncode"] == 0,
                    output={"stdout": result["stdout"], "stderr": result["stderr"], "returncode": result["returncode"]},
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
