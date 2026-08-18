"""Contract tests for Windows orphan-protection wiring.

An independent review found the existing GAP-013 test drives
``_assign_to_windows_job`` **directly**, bypassing ``_run_command`` entirely.
That guards "does the raw ctypes wiring work" -- useful -- but not the contract
the module actually promises: *every foreground subprocess this module spawns
is assigned to the kill-on-close job*. If a refactor dropped one of the three
call sites, or added a fourth path without the call, that suite would still
pass.

These tests close that gap, and deliberately run on **every** platform. The
Windows-only test file needs a Windows box and there is no Windows CI in this
repo, so its 3 tests execute nowhere automatically. Call-site wiring does not
need a real kernel to verify -- patch ``sys.platform`` and the two helpers, and
assert the real ``_run_command`` reaches them. That runs on Linux, on macOS, in
CI, today.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from amplifier_module_tool_bash import BashTool


class _FakeProc:
    """Minimal stand-in for an asyncio subprocess."""

    def __init__(self, pid: int = 424242) -> None:
        self.pid = pid
        self.returncode = 0

    async def communicate(self, *_: Any, **__: Any) -> tuple[bytes, bytes]:
        return (b"ok", b"")

    async def wait(self) -> int:
        return 0

    def kill(self) -> None:  # pragma: no cover - not exercised here
        pass


@pytest.mark.asyncio
async def test_windows_foreground_subprocess_is_job_assigned() -> None:
    """The real _run_command must job-assign the PID it spawned.

    Patches only the platform and the two Win32 helpers -- the command-dispatch
    logic under test is the genuine article.
    """
    tool = BashTool({})
    proc = _FakeProc()

    with (
        patch("amplifier_module_tool_bash.sys.platform", "win32"),
        patch(
            "amplifier_module_tool_bash._assign_to_windows_job", MagicMock()
        ) as assign,
        patch("amplifier_module_tool_bash._spawn_descendant_sweep", MagicMock()),
        patch(
            "amplifier_module_tool_bash.asyncio.create_subprocess_exec",
            AsyncMock(return_value=proc),
        ),
        patch(
            "amplifier_module_tool_bash.asyncio.create_subprocess_shell",
            AsyncMock(return_value=proc),
        ),
        patch("amplifier_module_tool_bash.shutil.which", return_value="C:\\bash.exe"),
    ):
        await tool._run_command("echo hi", timeout=5)

    assert assign.called, (
        "_run_command spawned a foreground subprocess on Windows without "
        "assigning it to the kill-on-close job object. That is the entire "
        "orphan protection this module promises."
    )
    assert assign.call_args.args[0] == proc.pid, (
        f"job assignment used {assign.call_args.args[0]!r}, not the spawned "
        f"pid {proc.pid!r}"
    )


@pytest.mark.asyncio
async def test_posix_never_touches_the_windows_helpers() -> None:
    """POSIX must take a byte-identical path to what shipped before.

    The guard that matters most in this whole change: Linux, macOS and WSL
    users currently work, and a Windows fix that reaches them is a net loss.
    """
    tool = BashTool({})
    proc = _FakeProc()

    with (
        patch("amplifier_module_tool_bash.sys.platform", "linux"),
        patch(
            "amplifier_module_tool_bash._assign_to_windows_job", MagicMock()
        ) as assign,
        patch(
            "amplifier_module_tool_bash._spawn_descendant_sweep", MagicMock()
        ) as sweep,
        patch(
            "amplifier_module_tool_bash.asyncio.create_subprocess_exec",
            AsyncMock(return_value=proc),
        ),
        patch(
            "amplifier_module_tool_bash.asyncio.create_subprocess_shell",
            AsyncMock(return_value=proc),
        ),
    ):
        await tool._run_command("echo hi", timeout=5)

    assert not assign.called, (
        "a Windows job-object helper ran on POSIX -- the platform guard leaks"
    )
    assert not sweep.called, (
        "the Windows descendant sweep ran on POSIX -- the platform guard leaks"
    )


def test_job_failure_is_reported_loudly_once_not_silently() -> None:
    """An environmental job failure must be visible, and must not spam.

    Before this, every failure was ``logger.debug`` and every caller discarded
    the return value, so the protection could be entirely inert under a
    restrictive parent job object -- the normal state on CI runners and in
    Windows containers -- with no operator-visible signal whatsoever.
    """
    import amplifier_module_tool_bash as mod

    original = mod._windows_job_failure_reported
    try:
        mod._windows_job_failure_reported = False
        with patch.object(mod, "logger") as log:
            mod._report_windows_job_failure("first failure (%s)", "boom")
            mod._report_windows_job_failure("second failure (%s)", "boom")

        assert log.warning.call_count == 1, (
            f"expected exactly one warning, got {log.warning.call_count}. "
            "Zero means the failure is invisible; more than one means every "
            "command spams and people learn to ignore it."
        )
        assert log.debug.call_count == 1, (
            "subsequent failures should still be recorded at debug level"
        )
        warned = log.warning.call_args.args[0]
        assert "NOT active" in warned, (
            f"warning does not state the protection is inactive: {warned!r}"
        )
    finally:
        mod._windows_job_failure_reported = original
