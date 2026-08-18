"""Regression tests for timeout and cancellation process cleanup.

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

Process-group tests are Unix-only. Tests for setsid-detached descendants
are additionally Linux-only and require /proc plus the setsid executable.
"""

import asyncio
import os
import shlex
import shutil
import signal
import sys

import pytest

import amplifier_module_tool_bash
from amplifier_module_tool_bash import BashTool

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="Unix process-group semantics only"
)
linux_detached_only = pytest.mark.skipif(
    not (
        sys.platform.startswith("linux")
        and os.path.isdir("/proc")
        and shutil.which("setsid") is not None
    ),
    reason="Detached-descendant cleanup requires Linux /proc and setsid",
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


class TestForegroundProcessCleanup:
    """Foreground cleanup must terminate the command's process tree."""

    @linux_detached_only
    @pytest.mark.asyncio
    async def test_setsid_detached_child_is_killed_on_timeout(self, tmp_path):
        """A setsid-detached grandchild must not survive timeout cleanup.

        Detachment is performed via `os.setsid()` inside an inline Python
        process rather than shelling out to the `setsid(1)` binary: `setsid`
        is a util-linux program that Linux ships but macOS does not (no
        `/usr/bin/setsid` on macOS -- confirmed via
        https://stackoverflow.com/questions/36590905, and the existence of
        third-party "ersatz setsid" replacements written specifically to fill
        that gap on macOS). Shelling out to `setsid bash -c '...'` made this
        test *vacuous* on macOS: the subshell failed instantly with
        "command not found", no marker was ever written, and the test failed
        at the marker-existence assertion without ever exercising the actual
        cleanup hazard.

        Calling `os.setsid()` directly is portable (it's a POSIX syscall
        exposed by Python's `os` module on every Unix, including macOS) and
        exercises the identical hazard: a descendant that moves itself to a
        new session/process group, whose PPID chain back to the timed-out
        command is preserved (setsid() never reparents).
        """
        marker = tmp_path / "detached_child.pid"
        tool = BashTool({})

        # Spawn a detached grandchild that calls os.setsid() on itself,
        # records its own PID, then sleeps far longer than the tool timeout.
        # The outer `sleep` keeps the parent bash alive past the timeout so
        # the tool actually times out (rather than exiting cleanly on its
        # own).
        detach_snippet = (
            "import os\n"
            "os.setsid()\n"
            f"open({str(marker)!r}, 'w').write(str(os.getpid()))\n"
            "import time\n"
            "time.sleep(60)\n"
        )
        command = (
            f"{shlex.quote(sys.executable)} -c {shlex.quote(detach_snippet)} & sleep 30"
        )

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

    @pytest.mark.asyncio
    async def test_timeout_cleanup_survives_external_cancellation(
        self, tmp_path, monkeypatch
    ):
        """Cancellation during timeout cleanup waits for cleanup, then propagates."""
        parent_marker = tmp_path / "parent.pid"
        child_marker = tmp_path / "child.pid"
        tool = BashTool({})
        cleanup_started = asyncio.Event()
        cleanup_finished = asyncio.Event()
        original_cleanup = amplifier_module_tool_bash._cleanup_process_tree

        async def tracked_cleanup(*args, **kwargs):
            cleanup_started.set()
            try:
                await original_cleanup(*args, **kwargs)
            finally:
                cleanup_finished.set()

        monkeypatch.setattr(
            amplifier_module_tool_bash, "_cleanup_process_tree", tracked_cleanup
        )

        # Ignore SIGTERM so cleanup stays in its bounded grace period long
        # enough to cancel the outer task after the command timeout fires.
        command = (
            f"trap '' TERM; echo $$ > {parent_marker}; "
            f"bash -c 'trap \"\" TERM; echo $$ > {child_marker}; sleep 60' & "
            "sleep 60"
        )

        parent_pid: int | None = None
        child_pid: int | None = None
        task = asyncio.create_task(tool._run_command(command, timeout=1))
        try:
            for _ in range(50):
                if (
                    parent_marker.exists()
                    and child_marker.exists()
                    and parent_marker.read_text().strip()
                    and child_marker.read_text().strip()
                ):
                    break
                await asyncio.sleep(0.1)

            assert parent_marker.exists() and parent_marker.read_text().strip()
            assert child_marker.exists() and child_marker.read_text().strip()
            parent_pid = int(parent_marker.read_text().strip())
            child_pid = int(child_marker.read_text().strip())

            await asyncio.wait_for(cleanup_started.wait(), timeout=2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

            assert cleanup_finished.is_set(), (
                "Cancellation propagated before timeout cleanup completed"
            )

            for _ in range(20):
                if not _pid_alive(parent_pid) and not _pid_alive(child_pid):
                    break
                await asyncio.sleep(0.1)

            assert not _pid_alive(parent_pid), (
                f"Main process (pid {parent_pid}) survived cancelled timeout cleanup"
            )
            assert not _pid_alive(child_pid), (
                f"Child process (pid {child_pid}) survived cancelled timeout cleanup"
            )
        finally:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            for pid in (parent_pid, child_pid):
                if pid is not None:
                    _force_kill(pid)

    @pytest.mark.asyncio
    async def test_external_cancellation_kills_process_group(self, tmp_path):
        """Ordinary process-group cleanup must work across supported Unix systems."""
        parent_marker = tmp_path / "parent.pid"
        child_marker = tmp_path / "child.pid"
        tool = BashTool({})

        command = (
            f"echo $$ > {parent_marker}; "
            f"bash -c 'echo $$ > {child_marker}; sleep 60' & "
            "sleep 60"
        )

        parent_pid: int | None = None
        child_pid: int | None = None
        task = asyncio.create_task(tool._run_command(command, timeout=120))
        try:
            for _ in range(50):
                if (
                    parent_marker.exists()
                    and child_marker.exists()
                    and parent_marker.read_text().strip()
                    and child_marker.read_text().strip()
                ):
                    break
                await asyncio.sleep(0.1)

            assert parent_marker.exists() and parent_marker.read_text().strip()
            assert child_marker.exists() and child_marker.read_text().strip()
            parent_pid = int(parent_marker.read_text().strip())
            child_pid = int(child_marker.read_text().strip())

            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

            assert not _pid_alive(parent_pid), (
                f"Main process (pid {parent_pid}) survived cancellation cleanup"
            )
            assert not _pid_alive(child_pid), (
                f"Child process (pid {child_pid}) survived cancellation cleanup"
            )
        finally:
            for pid in (parent_pid, child_pid):
                if pid is not None:
                    _force_kill(pid)

    @pytest.mark.asyncio
    async def test_repeated_cancellation_waits_for_cleanup(self, tmp_path, monkeypatch):
        """A second cancellation must not interrupt the bounded cleanup task."""
        parent_marker = tmp_path / "parent.pid"
        child_marker = tmp_path / "child.pid"
        tool = BashTool({})
        cleanup_finished = asyncio.Event()
        original_cleanup = amplifier_module_tool_bash._cleanup_process_tree

        async def tracked_cleanup(*args, **kwargs):
            try:
                await original_cleanup(*args, **kwargs)
            finally:
                cleanup_finished.set()

        monkeypatch.setattr(
            amplifier_module_tool_bash, "_cleanup_process_tree", tracked_cleanup
        )

        # Ignore SIGTERM so cleanup cannot complete until its bounded grace
        # period ends and it sends SIGKILL. This makes an early return caused
        # by the second cancellation observable as still-live processes.
        command = (
            f"trap '' TERM; echo $$ > {parent_marker}; "
            f"bash -c 'trap \"\" TERM; echo $$ > {child_marker}; sleep 60' & "
            "sleep 60"
        )

        parent_pid: int | None = None
        child_pid: int | None = None
        task = asyncio.create_task(tool._run_command(command, timeout=120))
        try:
            for _ in range(50):
                if (
                    parent_marker.exists()
                    and child_marker.exists()
                    and parent_marker.read_text().strip()
                    and child_marker.read_text().strip()
                ):
                    break
                await asyncio.sleep(0.1)

            assert parent_marker.exists() and parent_marker.read_text().strip()
            assert child_marker.exists() and child_marker.read_text().strip()
            parent_pid = int(parent_marker.read_text().strip())
            child_pid = int(child_marker.read_text().strip())

            task.cancel()
            await asyncio.sleep(0)
            assert not task.done(), (
                "First cancellation returned before cleanup finished"
            )

            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

            assert cleanup_finished.is_set(), (
                "Outer task propagated repeated cancellation before cleanup completed"
            )

            # The main process has been reaped by communicate(); allow an
            # orphaned child a brief moment to be reaped by the OS as well.
            for _ in range(20):
                if not _pid_alive(parent_pid) and not _pid_alive(child_pid):
                    break
                await asyncio.sleep(0.1)

            assert not _pid_alive(parent_pid), (
                f"Main process (pid {parent_pid}) survived repeated cancellation"
            )
            assert not _pid_alive(child_pid), (
                f"Child process (pid {child_pid}) survived repeated cancellation"
            )
        finally:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            for pid in (parent_pid, child_pid):
                if pid is not None:
                    _force_kill(pid)

    @linux_detached_only
    @pytest.mark.asyncio
    async def test_external_cancellation_kills_setsid_detached_descendant(
        self, tmp_path
    ):
        """If the coroutine is externally cancelled, the spawned process tree
        (including setsid-detached descendants) must still be cleaned up."""

        parent_marker = tmp_path / "parent.pid"
        child_marker = tmp_path / "child.pid"
        detached_marker = tmp_path / "detached.pid"
        tool = BashTool({})

        # Parent writes its own PID; it then spawns:
        #   - a normal background child (same process group)
        #   - a setsid-detached background child (new pgid/sid)
        # Then sleeps so the process tree stays alive until we cancel.
        command = (
            f"echo $$ > {parent_marker}; "
            f"bash -c 'echo $$ > {child_marker}; sleep 60' & "
            f"setsid bash -c 'echo $$ > {detached_marker}; sleep 60' & "
            "sleep 60"
        )

        parent_pid: int | None = None
        child_pid: int | None = None
        detached_pid: int | None = None

        task = asyncio.create_task(tool._run_command(command, timeout=120))
        try:
            # Wait for all PID markers to appear.
            for _ in range(50):
                if (
                    parent_marker.exists()
                    and child_marker.exists()
                    and detached_marker.exists()
                    and parent_marker.read_text().strip()
                    and child_marker.read_text().strip()
                    and detached_marker.read_text().strip()
                ):
                    break
                await asyncio.sleep(0.1)

            assert parent_marker.exists() and parent_marker.read_text().strip()
            assert child_marker.exists() and child_marker.read_text().strip()
            assert detached_marker.exists() and detached_marker.read_text().strip()

            parent_pid = int(parent_marker.read_text().strip())
            child_pid = int(child_marker.read_text().strip())
            detached_pid = int(detached_marker.read_text().strip())

            # Cancel the tool call while it is waiting for process completion.
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

            await asyncio.sleep(0.5)

            assert not _pid_alive(parent_pid), (
                f"Main process (pid {parent_pid}) survived external cancellation cleanup"
            )
            assert not _pid_alive(child_pid), (
                f"Child process (pid {child_pid}) survived external cancellation cleanup"
            )
            assert not _pid_alive(detached_pid), (
                f"Detached setsid child (pid {detached_pid}) survived external cancellation cleanup"
            )
        finally:
            for pid in (parent_pid, child_pid, detached_pid):
                if pid is not None:
                    _force_kill(pid)
