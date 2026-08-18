"""Regression test: bash-not-found on Windows must give an actionable error
for the BACKGROUND (`run_in_background=True`) path too, not a misleading
success or a bare OS error.

## Why this test exists

The foreground path (`_run_command`, covered by
``test_gap_bash_missing_actionable_error.py``) was fixed to return the
actionable "bash not found" error unconditionally when no bash is
discoverable on Windows. The background path (`_run_command_background`)
was not fixed and still contained the pre-fix fallback:

```python
else:
    try:
        args = shlex.split(command)
    except ValueError as e:
        raise ValueError(f"Invalid command syntax: {e}")
    process = subprocess.Popen(args, ...)
```

Two distinct failure modes resulted:

- If the command's first token is not a real ``.exe`` (``echo hello``,
  ``dir``): ``Popen`` raises ``FileNotFoundError`` -> caught by
  ``execute()``'s generic ``except Exception`` -> the model sees a bare
  ``[WinError 2] The system cannot find the file specified`` with no cause
  and no remedy.
- If the first token IS a real exe (``python --version``, ``git status``):
  it launches with **no shell at all** and returns a PID -> ``execute()``
  reports ``success=True``. ``&&``, pipes, ``~``, ``$VAR`` are silently
  passed as literal argv. This is the worse case: a **misleading success**.

The fix makes ``_run_command_background`` return the same actionable error
as the foreground path (via the shared ``_WINDOWS_NO_BASH_ERROR`` constant)
without launching anything, and wires ``execute()`` to surface that as
``ToolResult(success=False, ...)`` instead of wrapping a (nonexistent) PID
into a success result.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import amplifier_module_tool_bash as mod
from amplifier_module_tool_bash import BashTool


@pytest.mark.asyncio
async def test_background_real_exe_command_does_not_launch_when_bash_missing() -> None:
    """`python --version` (first token IS a real executable) must NOT be
    launched with no shell when bash is missing on Windows -- this is the
    misleading-success regression: a PID gets returned and `execute()`
    reports success=True even though no real shell ran the command.
    """
    tool = BashTool({})

    # `subprocess.Popen` is synchronous -- spy with MagicMock, not
    # AsyncMock. An AsyncMock returns a coroutine, so the pre-fix code
    # would die on `process.pid` instead of producing the misleading
    # success this test exists to guard against. Returning a usable
    # fake process is what lets the pre-fix path reach `success=True`
    # with a PID -- i.e. actually reproduce the regression.
    class _FakeProcess:
        pid = 1234

    popen_spy = MagicMock(return_value=_FakeProcess())

    with (
        patch("amplifier_module_tool_bash.sys.platform", "win32"),
        patch("amplifier_module_tool_bash.shutil.which", return_value=None),
        patch(
            "amplifier_module_tool_bash._find_git_bash_executable", return_value=None
        ),
        patch(
            "amplifier_module_tool_bash._find_wsl_bash_executable", return_value=None
        ),
        patch("amplifier_module_tool_bash.subprocess.Popen", popen_spy),
        # Windows-only constants absent from `subprocess` on Linux/macOS.
        # Without these, the PRE-FIX code raises AttributeError while
        # evaluating `creationflags=` -- BEFORE Popen is ever reached --
        # so `assert not popen_spy.called` below would pass against the
        # broken code for entirely the wrong reason, and the
        # misleading-success regression would never be exercised at all.
        # Supplying them makes this test model real Windows.
        patch.object(mod.subprocess, "DETACHED_PROCESS", 0x00000008, create=True),
        patch.object(
            mod.subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200, create=True
        ),
    ):
        result = await tool.execute(
            {"command": "python --version", "run_in_background": True}
        )

    assert not popen_spy.called, (
        "no-bash-on-Windows background path called subprocess.Popen with no "
        "shell at all -- this is the exact regression the fix removes: a "
        "command whose first token happens to be a real executable must "
        "never be launched with no shell and reported as a misleading "
        "success, it must get the actionable bash-missing error"
    )
    assert result.success is False
    assert "bash" in str(result.output).lower()
    assert (
        "git-scm.com" in str(result.output)
        or "git for windows" in str(result.output).lower()
    )
    assert "wsl" in str(result.output).lower()


@pytest.mark.asyncio
async def test_background_plain_command_gets_actionable_error_when_bash_missing() -> (
    None
):
    """`echo hello` (no shell metacharacters, first token is not a real
    exe) must get the actionable "bash not found" error in the background
    path too -- not a bare FileNotFoundError/WinError from Popen.
    """
    tool = BashTool({})

    # Synchronous spy -- see the note in the test above.
    class _FakeProcess:
        pid = 1234

    popen_spy = MagicMock(return_value=_FakeProcess())

    with (
        patch("amplifier_module_tool_bash.sys.platform", "win32"),
        patch("amplifier_module_tool_bash.shutil.which", return_value=None),
        patch(
            "amplifier_module_tool_bash._find_git_bash_executable", return_value=None
        ),
        patch(
            "amplifier_module_tool_bash._find_wsl_bash_executable", return_value=None
        ),
        patch("amplifier_module_tool_bash.subprocess.Popen", popen_spy),
        # See the note in the test above: without these Windows-only
        # constants the pre-fix code dies on AttributeError before
        # reaching Popen, so this test would not exercise the real
        # bare-WinError regression it is written to guard.
        patch.object(mod.subprocess, "DETACHED_PROCESS", 0x00000008, create=True),
        patch.object(
            mod.subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200, create=True
        ),
    ):
        result = await tool.execute(
            {"command": "echo hello", "run_in_background": True}
        )

    assert not popen_spy.called
    assert result.success is False
    assert "WinError" not in str(result.output), (
        f"got a bare OS error instead of the actionable message: {result.output!r}"
    )
    assert "bash" in str(result.output).lower()


@pytest.mark.asyncio
async def test_background_launches_normally_when_bash_is_found() -> None:
    """No regression: when bash IS found on Windows, the background path
    must still launch via subprocess.Popen exactly as before.
    """
    tool = BashTool({})

    class _FakeProcess:
        pid = 4242

    popen_spy = MagicMock(return_value=_FakeProcess())

    with (
        patch("amplifier_module_tool_bash.sys.platform", "win32"),
        patch(
            "amplifier_module_tool_bash.shutil.which",
            return_value="C:\\fake\\Git\\bin\\bash.exe",
        ),
        patch.object(BashTool, "_is_wsl_bash", AsyncMock(return_value=False)),
        patch("amplifier_module_tool_bash.subprocess.Popen", popen_spy),
        # Windows-only constants that don't exist on the real `subprocess`
        # module on Linux/macOS -- the test suite runs there, so these must
        # be supplied for the (mocked-anyway) Popen call's keyword
        # arguments to even evaluate. Matches the pattern used in
        # test_windows_shell_resolution.py.
        patch.object(mod.subprocess, "DETACHED_PROCESS", 0x00000008, create=True),
        patch.object(
            mod.subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200, create=True
        ),
    ):
        result = await tool.execute(
            {"command": "echo hello", "run_in_background": True}
        )

    assert popen_spy.called, "bash was found but subprocess.Popen was never called"
    assert result.success is True
    assert result.output["pid"] == 4242
