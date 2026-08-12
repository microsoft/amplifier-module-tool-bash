"""Regression test: foreground command execution must never inherit the
host's stdin.

Root cause (confirmed via live session forensics -- see PR description):

`_run_command()` (the foreground/awaited path) spawns the child via
`asyncio.create_subprocess_shell` / `asyncio.create_subprocess_exec`
without specifying `stdin=`. When no `stdin` is given, the child inherits
fd 0 from the parent process verbatim.

When the parent is the Amplifier CLI (a prompt_toolkit TUI), fd 0 is the
real controlling TTY, held in prompt_toolkit's raw mode. Any child that
reads from or reconfigures that TTY -- `ssh` is the canonical case, since
without `-n` it reads stdin to forward to the remote and calls `tcsetattr`
on the local tty -- becomes a second, competing reader/writer on the
terminal prompt_toolkit is driving. That contention stalls prompt_toolkit's
terminal coordination (`run_in_terminal`, which every Rich write goes
through under `patch_stdout`), which runs on the event loop thread. Once
that stalls, the loop's timers (including this tool's own
`asyncio.wait_for(..., timeout=N)`) stop firing -- the session hangs until
the user presses a key, at which point the overdue timeout fires instantly.

The background path (`_run_command_background`) already does this
correctly with `stdin=devnull`. This module tests that the FOREGROUND path
(`_run_command`) gets the same treatment.

These tests attach a REAL pty to the test process's fd 0 for their
duration. This matters: pytest normally captures/redirects stdin to
something already non-TTY (often a closed file or /dev/null), so a naive
test using the ambient pytest stdin would pass even against the buggy
pre-fix code, for the wrong reason. By forcing fd 0 to be a genuine TTY
before invoking the tool, we guarantee:
  - pre-fix code (no stdin= kwarg) truly inherits a TTY and the test fails
  - post-fix code (stdin=DEVNULL) never sees that TTY and the test passes

Unix-only: relies on `pty`, `os.dup2`, and TTY semantics that don't apply
on Windows (the Windows foreground path is fixed by the same change but
is not covered by this pty-based test).
"""

import sys

import pytest

# `pty` is POSIX-only and is imported at module scope, so on Windows this
# file fails at COLLECTION -- a hard ERROR, not a skip. The pytestmark
# below is evaluated only AFTER the module body has already executed, so
# it cannot prevent the import from raising. An ImportError during
# collection is indistinguishable in CI output from a real breakage.
if sys.platform == "win32":
    pytest.skip(
        "POSIX-only: requires pty, which has no Windows equivalent",
        allow_module_level=True,
    )

import asyncio
import contextlib
import os
import pty
import sys

import pytest
from amplifier_module_tool_bash import BashTool

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="pty-based TTY inheritance test is Unix-only"
)


@contextlib.contextmanager
def attached_pty_on_stdin():
    """Temporarily replace the test process's fd 0 with a real pty slave.

    Yields nothing; on exit, restores the original fd 0 and closes the
    pty fds. This makes `isatty(0)` True and gives the fd real termios
    behavior for the duration of the context -- exactly the situation
    the Amplifier CLI's real TTY puts a spawned child into.
    """
    master_fd, slave_fd = pty.openpty()
    saved_stdin_fd = os.dup(0)
    try:
        os.dup2(slave_fd, 0)
        yield
    finally:
        os.dup2(saved_stdin_fd, 0)
        os.close(saved_stdin_fd)
        os.close(slave_fd)
        os.close(master_fd)


class TestForegroundCommandDoesNotInheritStdin:
    """The foreground (`_run_command`) path must never hand a child the
    host's stdin -- especially not a real TTY."""

    @pytest.mark.asyncio
    async def test_child_stdin_is_not_a_tty_even_when_parent_has_one(self):
        """With a real pty on the parent's fd 0, the child must NOT see a TTY.

        Pre-fix: no `stdin=` kwarg -> child inherits fd 0 -> sees the pty
        -> `test -t 0` reports TTY. This assertion fails against the
        buggy code, proving the test is meaningful.

        Post-fix: `stdin=asyncio.subprocess.DEVNULL` -> child's fd 0 is
        /dev/null -> `test -t 0` reports NOT_TTY.
        """
        tool = BashTool({})

        with attached_pty_on_stdin():
            assert os.isatty(0), "Test setup failed: fd 0 is not a TTY"
            result = await tool._run_command(
                "test -t 0 && echo TTY || echo NOT_TTY", timeout=10
            )

        assert result["returncode"] == 0
        assert "NOT_TTY" in result["stdout"], (
            f"Child inherited the parent's TTY on stdin (stdout={result['stdout']!r}). "
            "Foreground subprocess spawn must pass stdin=DEVNULL."
        )

    @pytest.mark.asyncio
    async def test_stdin_reading_command_gets_immediate_eof(self):
        """A command that reads stdin (e.g. `cat`) must see immediate EOF
        and exit promptly -- not block waiting for input from a terminal
        it was never meant to share.

        This is the behavioral analogue of the `ssh`-without-`-n` hang:
        any child that tries to read stdin must find it already closed
        (EOF), not a live, contended TTY. We use a generous timeout
        relative to expected completion time so this test is robust
        even under CI scheduling jitter, while still failing hard
        against code that hangs indefinitely (pre-fix, with a real TTY
        attached, `cat` blocks waiting on terminal input that never
        arrives from that fd).
        """
        tool = BashTool({})

        with attached_pty_on_stdin():
            # `cat` with stdin inherited from a live pty (nothing written
            # to the master side) would block forever waiting for input.
            # With stdin=DEVNULL it reads EOF immediately and exits.
            result = await asyncio.wait_for(
                tool._run_command("cat; echo DONE=$?", timeout=5),
                timeout=8,
            )

        assert result["returncode"] == 0
        # `cat` sees immediate EOF (stdin=DEVNULL) and produces no output of
        # its own -- the only output is the `echo` that follows it.
        assert result["stdout"].strip() == "DONE=0"
