"""Regression test: foreground commands must not inherit the parent's stdin.

Root cause (confirmed on three production Amplifier Resolve instances --
4a332ce97f71, 13e758564fc4):

`_run_command()` spawned the shell without passing `stdin=`, so every command
-- and every descendant it forked (`npm`, `npx`, `git`, ...) -- inherited the
parent process's fd 0. When the parent is an Amplifier resolver, fd 0 is its
live JSON-RPC control channel. A descendant reading from that shared pipe, or
mutating its open-file flags, produced a spurious EOF on the resolver's own
stdin: the dispatcher loop ended mid-run and the worker exited "transient"
with no diagnostic, surfacing to the host as `resolver_disconnected`.

`_run_command_background()` already redirected stdin to /dev/null; only the
foreground path was exposed. The fix passes
`stdin=asyncio.subprocess.DEVNULL` on the foreground spawns too.

These tests are Unix-only (they rely on fd/pipe semantics that differ on
Windows).
"""

import os
import sys

import pytest
from amplifier_module_tool_bash import BashTool

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="Unix fd/pipe semantics only"
)

SENTINEL = b"PARENT-STDIN-MUST-NOT-BE-READ\n"


class TestForegroundStdinIsolation:
    """A spawned command must see /dev/null on fd 0, not the parent's stdin."""

    @pytest.mark.asyncio
    async def test_command_does_not_consume_parent_stdin(self):
        """`cat` must return empty and leave the parent's stdin untouched.

        Pre-fix, `cat` inherited fd 0, drained SENTINEL, and then blocked
        forever (the write end stays open), so `_run_command` raised
        TimeoutError instead of returning.
        """
        tool = BashTool({})

        read_fd, write_fd = os.pipe()
        saved_fd0 = os.dup(0)
        try:
            os.dup2(read_fd, 0)
            os.write(write_fd, SENTINEL)

            result = await tool._run_command("cat", timeout=5)
        finally:
            os.dup2(saved_fd0, 0)
            os.close(saved_fd0)

        try:
            assert result["stdout"] == "", (
                "command read the parent's stdin -- it inherited fd 0 instead "
                f"of /dev/null. Got: {result['stdout']!r}"
            )
            assert result["returncode"] == 0

            # The sentinel must still be queued: nothing consumed it.
            assert os.read(read_fd, len(SENTINEL)) == SENTINEL, (
                "the parent's stdin was drained by the spawned command"
            )
        finally:
            os.close(read_fd)
            os.close(write_fd)

    @pytest.mark.asyncio
    async def test_stdin_reads_return_eof_immediately(self):
        """Commands that read stdin get EOF, not a hang.

        `read` blocks forever on an inherited-but-idle pipe; on /dev/null it
        returns immediately with a non-zero status.
        """
        tool = BashTool({})

        read_fd, write_fd = os.pipe()
        saved_fd0 = os.dup(0)
        try:
            os.dup2(read_fd, 0)
            # Deliberately write nothing and keep the write end open: an
            # inherited fd 0 would block here until the tool timed out.
            result = await tool._run_command('read line; echo "read=$?"', timeout=5)
        finally:
            os.dup2(saved_fd0, 0)
            os.close(saved_fd0)
            os.close(read_fd)
            os.close(write_fd)

        assert "read=1" in result["stdout"], (
            "reading stdin must hit EOF immediately (exit 1), which only "
            f"happens when fd 0 is /dev/null. Got: {result['stdout']!r}"
        )

    @pytest.mark.asyncio
    async def test_normal_command_output_unaffected(self):
        """Sanity: redirecting stdin must not disturb ordinary execution."""
        tool = BashTool({})

        result = await tool._run_command("echo hello", timeout=5)

        assert result["stdout"].strip() == "hello"
        assert result["returncode"] == 0
