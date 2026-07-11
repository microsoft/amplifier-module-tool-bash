"""Regression test: timeout cleanup must kill setsid-detached descendants.

Root cause (confirmed via minimal reproduction outside this test):

`_run_command()` kills the timed-out command's process tree via
`os.killpg(pgid, ...)`, which only reaches processes still in the
*original* process group. A descendant that calls `setsid` (directly,
or via a wrapper that manages its own session lifecycle -- e.g. some
container-exec shims) moves to a NEW session/process-group id. Since
setsid() never reparents the process, its PPID chain back to the
timed-out command is preserved even though its pgid/sid changed --
so `os.killpg()` never touches it, and it survives the timeout,
running forever as an orphan reparented to PID 1.

These tests are Unix-only (they rely on setsid, /proc, and
os.killpg semantics that don't exist on Windows).
"""

import asyncio
import os
import signal
import sys

import pytest

from amplifier_module_tool_bash import BashTool

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="Unix process-group semantics only"
)


def _pid_alive(pid: int) -> bool:
    """Check whether a process is still alive (best-effort, no zombies check)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Exists but owned by someone else -- treat as alive.
        return True
    return True


def _force_kill(pid: int) -> None:
    """Best-effort cleanup so a failing test never leaks an orphan into CI."""
    try:
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


class TestTimeoutKillsSetsidDetachedDescendants:
    """Timeout cleanup must reach descendants that escaped the process group."""

    @pytest.mark.asyncio
    async def test_setsid_detached_child_is_killed_on_timeout(self, tmp_path):
        """A `setsid`-detached grandchild must not survive timeout cleanup."""
        marker = tmp_path / "detached_child.pid"
        tool = BashTool({})

        # Spawn a detached grandchild via setsid that records its own PID,
        # then sleeps far longer than the tool timeout. The outer `sleep`
        # keeps the parent bash alive past the timeout so the tool actually
        # times out (rather than exiting cleanly on its own).
        command = f"setsid bash -c 'echo $$ > {marker}; sleep 60' & sleep 30"

        detached_pid: int | None = None
        try:
            with pytest.raises(TimeoutError):
                await tool._run_command(command, timeout=2)

            # The marker file should appear almost immediately (well before
            # the 2s timeout even fires). Note: we cannot do a "sanity"
            # liveness check on the detached PID here -- `_run_command`
            # performs its full SIGTERM/grace/SIGKILL cleanup synchronously,
            # inside the `except TimeoutError` handler, *before* re-raising.
            # By the time `_run_command` returns control to us, cleanup has
            # already run (or, pre-fix, already failed to reach the
            # escaped descendant). So the only meaningful check is the
            # post-return liveness check below.
            for _ in range(50):
                if marker.exists() and marker.read_text().strip():
                    break
                await asyncio.sleep(0.1)
            assert marker.exists(), "Detached child never wrote its PID marker"

            detached_pid = int(marker.read_text().strip())

            # Small margin in case cleanup is still settling.
            await asyncio.sleep(0.5)

            assert not _pid_alive(detached_pid), (
                f"Detached setsid child (pid {detached_pid}) survived "
                "timeout cleanup -- it escaped the killed process group "
                "and was orphaned instead of terminated"
            )
        finally:
            if detached_pid is not None:
                _force_kill(detached_pid)

    @pytest.mark.asyncio
    async def test_non_detached_sibling_still_killed(self, tmp_path):
        """Regression guard: the existing (working) process-group kill path
        must keep working -- only the setsid escape case was broken."""
        marker = tmp_path / "plain_child.pid"
        tool = BashTool({})

        command = f"bash -c 'echo $$ > {marker}; sleep 60' & sleep 30"

        plain_pid: int | None = None
        try:
            with pytest.raises(TimeoutError):
                await tool._run_command(command, timeout=2)

            for _ in range(50):
                if marker.exists() and marker.read_text().strip():
                    break
                await asyncio.sleep(0.1)
            assert marker.exists(), "Plain child never wrote its PID marker"

            plain_pid = int(marker.read_text().strip())

            await asyncio.sleep(1.5)

            assert not _pid_alive(plain_pid), (
                f"Non-detached child (pid {plain_pid}) should have been "
                "killed via the process group -- this path already worked "
                "before the fix and must not regress"
            )
        finally:
            if plain_pid is not None:
                _force_kill(plain_pid)
