"""Regression test: GAP-013 / GAP-024 -- a tool-call subprocess (and its own
descendants) must not outlive the host process, even when the host is
killed outright rather than shut down through this module's own code.

## Why this test exists

GAP-013 ("orphaned process trees left after amplifier exits") was first
retracted as a harness artifact -- the two experiments behind that
retraction never actually had a tool-call subprocess in flight at the
moment of the kill. An adversarial re-test built that missing state (a
live ``bash`` tool subprocess, then ``Stop-Process`` on *only* the
top-level PID -- no ``/T``, no console Ctrl+C) and found a real orphan:
Windows has no parent-death signal (no ``PR_SET_PDEATHSIG`` equivalent),
so a subprocess this module spawns has no way to notice its parent died,
and none of this module's own cleanup code runs to catch it.

The fix (GAP-024) is a lazily-created Windows Job Object per process,
with ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` set, and every foreground
subprocess this module spawns is assigned to it via
``_assign_to_windows_job``. The job's only handle lives in the host
process; when that process ends for ANY reason -- including a forceful
kill that runs none of this module's own Python -- the OS itself closes
the handle and the kernel tears down every process still assigned to the
job. This does not depend on any of our code running, so it covers
crashes too, not just graceful shutdown.

Nothing previously locked this in as an automated regression -- the only
proof was a one-shot manual test against a specific process tree on a
specific box. If the job-object wiring regresses (the assignment call is
dropped from a new/changed subprocess-spawn site, ``AssignProcessToJobObject``
silently starts failing, or ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` is
accidentally cleared), this test is what catches it.

## Design

This exercises the REAL ``_get_windows_job_object`` / ``_assign_to_windows_job``
functions from ``amplifier_module_tool_bash`` -- not a reimplementation --
against a small, deterministic two-level process tree, rather than
depending on WSL/bash being installed on whatever box runs this suite
(the real GAP-013 scenario happened to go through a WSL-routed ``bash``
tool call, but the fix and the guarantee it protects are generic to every
foreground subprocess this module spawns).

* A *harness* process stands in for the host (``amplifier.exe``): it
  spawns a *grandchild* process, assigns the grandchild to a Job Object
  using this module's own real functions, and writes PID markers for
  both.
* **Case (a) -- normal completion:** the grandchild is short-lived, the
  harness waits for it and then exits on its own. Asserts nothing is left
  running -- the job-object wiring must not itself cause anything to
  linger under the ordinary, successful-completion path.
* **Case (b) -- abnormal external kill:** the grandchild is long-lived,
  and once both are confirmed alive, the test kills ONLY the harness PID
  (``taskkill /F /PID`` -- deliberately no ``/T``, mirroring
  ``Stop-Process -Id`` with no children flag, the exact case the original
  false retraction never tested). Asserts the grandchild dies anyway,
  without anything explicitly killing it -- proving the OS-level
  kill-on-close mechanism, not just a Python cleanup path that happens to
  run.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

import amplifier_module_tool_bash as tool_bash_pkg

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="GAP-013/024 orphan-prevention is a Windows-only mechanism (Job Objects)",
)


_GRANDCHILD_SCRIPT = """
import sys
import os
import time
from pathlib import Path

marker_dir = Path(sys.argv[1])
sleep_s = float(sys.argv[2])

(marker_dir / "grandchild_started.pid").write_text(str(os.getpid()))
time.sleep(sleep_s)
(marker_dir / "grandchild_finished.marker").write_text("done")
"""

# The harness stands in for "amplifier.exe": it spawns a grandchild and
# assigns it to a kill-on-close Job Object using the module's REAL
# functions (imported, not reimplemented), then either waits for a short
# grandchild to finish on its own (case a) or sleeps indefinitely,
# simulating a live process to be killed externally (case b).
_HARNESS_SCRIPT = """
import sys
import os
import subprocess
import time
from pathlib import Path

mode = sys.argv[1]
marker_dir = Path(sys.argv[2])
grandchild_script = sys.argv[3]
grandchild_sleep_s = sys.argv[4]

from amplifier_module_tool_bash import _assign_to_windows_job

grandchild = subprocess.Popen(
    [sys.executable, grandchild_script, str(marker_dir), grandchild_sleep_s]
)
_assign_to_windows_job(grandchild.pid)

(marker_dir / "harness.pid").write_text(str(os.getpid()))
(marker_dir / "grandchild.pid").write_text(str(grandchild.pid))

if mode == "normal":
    grandchild.wait()
    # Falls off the end and exits cleanly right after its own child does --
    # this is the ordinary "tool call completed" path.
elif mode == "abnormal":
    # Simulates a live amplifier.exe mid-turn. Deliberately never exits on
    # its own -- the test kills it externally to exercise the job-object
    # kill-on-close path, not a graceful shutdown.
    time.sleep(120)
"""


def _pid_alive(pid: int) -> bool:
    """Best-effort Windows liveness check via ``tasklist`` (no admin needed)."""
    result = subprocess.run(
        ["tasklist", "/FI", f"PID eq {pid}"],
        capture_output=True,
        text=True,
        check=False,
    )
    return str(pid) in result.stdout


def _wait_for_marker(path: Path, timeout_s: float = 10.0) -> str:
    """Poll for a marker file to appear with non-empty content."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if path.exists():
            text = path.read_text().strip()
            if text:
                return text
        time.sleep(0.1)
    raise TimeoutError(f"marker file {path} never appeared with content")


def _force_kill(pid: int) -> None:
    """Best-effort cleanup so a failing test never leaks a stand-in process."""
    subprocess.run(
        ["taskkill", "/F", "/T", "/PID", str(pid)],
        capture_output=True,
        check=False,
    )


def _write_scripts(tmp_path: Path) -> tuple[Path, Path]:
    harness_script = tmp_path / "gap013_harness.py"
    grandchild_script = tmp_path / "gap013_grandchild.py"
    harness_script.write_text(_HARNESS_SCRIPT)
    grandchild_script.write_text(_GRANDCHILD_SCRIPT)
    return harness_script, grandchild_script


class TestGap013NormalCompletionLeavesNoOrphans:
    """Case (a): ordinary, successful completion -- nothing left behind."""

    def test_normal_completion_no_surviving_descendants(self, tmp_path: Path) -> None:
        harness_script, grandchild_script = _write_scripts(tmp_path)

        harness = subprocess.Popen(
            [
                sys.executable,
                str(harness_script),
                "normal",
                str(tmp_path),
                str(grandchild_script),
                "2",  # short-lived grandchild: 2s
            ]
        )

        harness_pid: int | None = None
        grandchild_pid: int | None = None
        try:
            grandchild_pid = int(_wait_for_marker(tmp_path / "grandchild.pid"))
            harness_pid = int(_wait_for_marker(tmp_path / "harness.pid"))

            # Bounded wait for the harness to exit on its own. Budget:
            # ~2s grandchild sleep + interpreter startup/shutdown overhead
            # on both processes. 20s gives generous headroom without
            # masking a real hang.
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline and harness.poll() is None:
                time.sleep(0.2)

            assert harness.poll() is not None, (
                "harness process never exited on its own within 20s during "
                "normal completion -- unrelated to GAP-013, but a real "
                "regression in the stand-in harness or the module import"
            )

            # Give the OS a brief moment to fully reap/update process state.
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and _pid_alive(grandchild_pid):
                time.sleep(0.2)

            assert not _pid_alive(grandchild_pid), (
                f"grandchild process (pid {grandchild_pid}) was still alive "
                "after the harness completed normally -- normal-completion "
                "cleanup regressed"
            )
            assert not _pid_alive(harness_pid), (
                f"harness process (pid {harness_pid}) reported exited but "
                "is still visible in the process table"
            )
        finally:
            if harness.poll() is None:
                harness.kill()
            if harness_pid is not None:
                _force_kill(harness_pid)
            if grandchild_pid is not None:
                _force_kill(grandchild_pid)


class TestGap013ExternalKillStillReapsDescendantViaJobObject:
    """Case (b): the exact state the original false retraction never
    tested -- external kill of ONLY the top-level PID, no /T, no console
    Ctrl+C."""

    def test_kill_top_level_pid_only_still_kills_grandchild(
        self, tmp_path: Path
    ) -> None:
        harness_script, grandchild_script = _write_scripts(tmp_path)

        harness = subprocess.Popen(
            [
                sys.executable,
                str(harness_script),
                "abnormal",
                str(tmp_path),
                str(grandchild_script),
                "120",  # long-lived grandchild: would run for 2 minutes
                # unassisted -- only the job-object kill-on-close should
                # end it early.
            ]
        )

        harness_pid: int | None = None
        grandchild_pid: int | None = None
        try:
            grandchild_pid = int(_wait_for_marker(tmp_path / "grandchild.pid"))
            harness_pid = int(_wait_for_marker(tmp_path / "harness.pid"))
            _wait_for_marker(tmp_path / "grandchild_started.pid")

            assert _pid_alive(harness_pid), "harness never actually started"
            assert _pid_alive(grandchild_pid), (
                "grandchild never actually started -- can't test whether "
                "killing the harness reaps it"
            )

            # Kill ONLY the top-level harness PID. Deliberately no /T (no
            # process-tree flag) and no console Ctrl+C -- this is the exact
            # state ("Stop-Process -Id <pid>", no children flag) that the
            # original GAP-013 investigation's false retraction never
            # exercised.
            kill_result = subprocess.run(
                ["taskkill", "/F", "/PID", str(harness_pid)],
                capture_output=True,
                text=True,
                check=False,
            )
            assert kill_result.returncode == 0, (
                f"failed to kill harness pid {harness_pid} for the test "
                f"itself: {kill_result.stderr}"
            )

            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and _pid_alive(harness_pid):
                time.sleep(0.2)
            assert not _pid_alive(harness_pid), (
                "harness process survived being killed -- broken test "
                "setup, not a GAP-013 finding"
            )

            # The grandchild has NOTHING killing it directly -- only the
            # Job Object's kill-on-close semantics, triggered by Windows
            # closing the harness's job handle when that process ends,
            # should bring it down. Bound: this is an OS-level handle-close
            # notification, not anything involving network/auth variance,
            # so it should be near-instant -- but 15s gives real headroom
            # above what a loaded CI box might need for the kernel to
            # process the handle closure and for tasklist to reflect it.
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and _pid_alive(grandchild_pid):
                time.sleep(0.2)

            assert not _pid_alive(grandchild_pid), (
                f"grandchild process (pid {grandchild_pid}) survived the "
                "external kill of ONLY the top-level harness PID -- this "
                "is GAP-013's exact orphan signature. The Job Object "
                "kill-on-close wiring (_assign_to_windows_job / GAP-024) "
                "regressed."
            )
        finally:
            if harness.poll() is None:
                harness.kill()
            if harness_pid is not None:
                _force_kill(harness_pid)
            if grandchild_pid is not None:
                _force_kill(grandchild_pid)


def test_module_exposes_the_functions_this_test_depends_on() -> None:
    """Sanity check: fail loudly and clearly if a refactor renames/removes
    the real functions this test imports inside the harness subprocess,
    rather than surfacing as a confusing harness-side ImportError deep in
    a subprocess with no visible traceback."""
    assert hasattr(tool_bash_pkg, "_assign_to_windows_job")
    assert hasattr(tool_bash_pkg, "_get_windows_job_object")
