"""Regression test: bash-not-found on Windows must give an actionable error
for EVERY command, not a bare OS error for "simple" ones.

## Why this test exists

Confirmed on Windows with no bash on PATH (patching ``shutil.which`` to
return ``None`` and driving the real installed ``BashTool.execute()``):

| Command                     | Result                                    |
|------------------------------|--------------------------------------------|
| ``ls -la \\| head -3`` (shell) | actionable error naming bash + install URLs |
| ``echo hello``               | bare ``[WinError 2] ...``                   |
| ``ls``                       | bare ``[WinError 2] ...``                   |
| ``dir``                      | bare ``[WinError 2] ...``                   |

Root cause: the no-bash-on-Windows branch only returned the actionable
error when the command contained an obvious shell metacharacter (``|``,
``&&``, etc). Anything else fell through to ``shlex.split(command)`` +
``create_subprocess_exec`` with **no shell at all**, so every cmd.exe
builtin (echo, dir, cd, type, set, copy) failed with a bare OS error naming
neither the cause nor the fix.

The fix makes the actionable error unconditional: if bash is not found on
Windows, EVERY command gets the actionable message. This tool's entire
contract is POSIX shell semantics; there is no partial/degraded fallback.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from amplifier_module_tool_bash import BashTool


@pytest.mark.asyncio
async def test_simple_command_gets_actionable_error_when_bash_missing() -> None:
    """`echo hello` (no shell metacharacters) must still get the actionable
    "bash not found" error when bash is missing on Windows -- not a bare
    OS error from trying to exec a non-existent program with no shell.
    """
    tool = BashTool({})

    # A spy on create_subprocess_exec: if this is ever called, the fix
    # regressed back to the no-shell fallback path this test exists to
    # forbid.
    exec_spy = AsyncMock()

    with (
        patch("amplifier_module_tool_bash.sys.platform", "win32"),
        patch("amplifier_module_tool_bash.shutil.which", return_value=None),
        # Neutralising PATH alone is NOT "no bash on this machine" any more.
        # Git Bash discovery probes well-known install locations directly on
        # the filesystem, precisely because Git for Windows never puts
        # Git\bin on PATH. On a real Windows box with Git installed, this
        # test passed on Linux (where it is skipped) and failed on Windows:
        # bash WAS found, the actionable error never fired, and execution
        # reached create_subprocess_exec.
        patch("amplifier_module_tool_bash._find_git_bash_executable", return_value=None),
        patch("amplifier_module_tool_bash._find_wsl_bash_executable", return_value=None),
        patch("amplifier_module_tool_bash.asyncio.create_subprocess_exec", exec_spy),
    ):
        result = await tool._run_command("echo hello", timeout=5)

    assert not exec_spy.called, (
        "no-bash-on-Windows fell through to create_subprocess_exec (no "
        "shell at all) for a command with no shell metacharacters -- this "
        "is the exact regression the fix removes: a plain command like "
        "`echo hello` must never be executed with no shell, it must get "
        "the actionable bash-missing error like every other command"
    )
    assert result["returncode"] != 0
    assert "WinError" not in result["stderr"], (
        f"got a bare OS error instead of the actionable message: {result['stderr']!r}"
    )
    assert "bash" in result["stderr"].lower()
    assert (
        "git-scm.com" in result["stderr"]
        or "git for windows" in result["stderr"].lower()
    )
    assert "wsl" in result["stderr"].lower()


@pytest.mark.asyncio
async def test_shell_metacharacter_command_still_gets_actionable_error() -> None:
    """The pre-existing good case (a command with shell features) must keep
    working -- this fix removes the *conditional*, it doesn't touch the
    message itself.
    """
    tool = BashTool({})
    exec_spy = AsyncMock()

    with (
        patch("amplifier_module_tool_bash.sys.platform", "win32"),
        patch("amplifier_module_tool_bash.shutil.which", return_value=None),
        # See the note in the test above: PATH is no longer the only way bash
        # is found on Windows, so a "no bash" simulation has to neutralise the
        # filesystem probes too.
        patch("amplifier_module_tool_bash._find_git_bash_executable", return_value=None),
        patch("amplifier_module_tool_bash._find_wsl_bash_executable", return_value=None),
        patch("amplifier_module_tool_bash.asyncio.create_subprocess_exec", exec_spy),
    ):
        result = await tool._run_command("ls -la | head -3", timeout=5)

    assert not exec_spy.called
    assert result["returncode"] != 0
    assert "bash" in result["stderr"].lower()


@pytest.mark.asyncio
async def test_posix_is_unaffected_when_bash_is_missing() -> None:
    """This fix only changes the Windows no-bash branch. On POSIX, bash
    missing is a wholly different (and pre-existing, out of scope) code
    path -- verify it isn't touched by asserting the Windows-only spy
    (create_subprocess_exec) is never reached via that branch when the
    platform is POSIX.
    """
    tool = BashTool({})
    exec_spy = AsyncMock()

    with (
        patch("amplifier_module_tool_bash.sys.platform", "linux"),
        patch("amplifier_module_tool_bash.shutil.which", return_value=None),
        patch("amplifier_module_tool_bash.asyncio.create_subprocess_exec", exec_spy),
        patch(
            "amplifier_module_tool_bash.asyncio.create_subprocess_shell",
            AsyncMock(side_effect=RuntimeError("posix path reached shell exec")),
        ),pytest.raises(RuntimeError, match="posix path reached shell exec")
    ):
        await tool._run_command("echo hello", timeout=5)

    assert not exec_spy.called, (
        "the Windows no-shell fallback (create_subprocess_exec) ran on "
        "POSIX -- the platform guard leaks"
    )
