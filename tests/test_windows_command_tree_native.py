"""Native command-tree behavior, using only finite test-started processes.

The normal-child test is first run against bf36c12 (no product change) to pin
existing behavior: normal return must not kill a child with redirected pipes.
GitHub Windows CI has Git Bash, but no WSL.
"""

from __future__ import annotations

import asyncio
import ctypes
from ctypes import wintypes
import shlex
import sys
import time

import pytest

import amplifier_module_tool_bash as mod

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Objects")


@pytest.fixture(params=[False, True], ids=["module-job-on", "host-guard"])
def module_job(request, monkeypatch):
    # Only a test-owned job may be closed. Every child is finite, and the test
    # waits for its effect before closing this module-wide kill-on-close job.
    monkeypatch.setattr(mod, "_windows_job_handle", None)
    if request.param:
        monkeypatch.setattr(mod, "_get_windows_job_object", lambda: None)
        monkeypatch.setattr(mod, "_assign_to_windows_job", lambda pid: False)
    yield request.param
    job = mod._windows_job_handle
    if job is not None:
        dll = ctypes.WinDLL("kernel32", use_last_error=True)
        dll.CloseHandle.argtypes = [wintypes.HANDLE]
        dll.CloseHandle.restype = wintypes.BOOL
        assert dll.CloseHandle(job)
        mod._windows_job_handle = None


async def wait_file(path, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"test process did not write {path}")


@pytest.mark.asyncio
async def test_normal_command_preserves_redirected_child(tmp_path, module_job):
    marker = tmp_path / "child-finished"
    release = tmp_path / "release-child"
    child = (
        "import time\nfrom pathlib import Path\n"
        "deadline = time.monotonic() + 30\n"
        f"while not Path({str(release)!r}).exists() and time.monotonic() < deadline:\n"
        "    time.sleep(0.02)\n"
        f"Path({str(marker)!r}).write_text('survived', encoding='utf-8')\n"
    )
    parent = (
        "import subprocess,sys; "
        f"subprocess.Popen([sys.executable,'-c',{child!r}], "
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
        "print('parent-output'); sys.exit(7)"
    )
    tool = mod.BashTool({"working_dir": str(tmp_path)})
    tool._windows_bash_resolved = (sys._base_executable, False)
    try:
        result = await asyncio.wait_for(tool._run_command(parent, timeout=30), 40)
        assert result["returncode"] == 7
        assert result["stdout"].splitlines() == ["parent-output"]
        assert result["stderr"] == ""
        assert not marker.exists(), "child must still be running at normal return"
    finally:
        # Release only AFTER normal return. No scheduler-dependent sleep window.
        release.write_text("go", encoding="utf-8")
    await wait_file(marker)
    assert marker.read_text(encoding="utf-8") == "survived"


def git_bash_tool(tmp_path):
    bash = mod._find_git_bash_executable()
    assert bash is not None, "native Windows CI/manager test requires Git for Windows"
    tool = mod.BashTool({"working_dir": str(tmp_path), "windows_shell": "gitbash"})
    tool._windows_bash_resolved = (bash, False)
    return tool


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", ["timeout", "cancel"])
async def test_git_bash_ends_tree_before_late_effect(tmp_path, module_job, reason):
    ready = tmp_path / "command-ready"
    late = tmp_path / "must-not-appear"
    command = (
        f"printf ready > {shlex.quote(ready.as_posix())}; "
        f"sleep 6; printf late > {shlex.quote(late.as_posix())}"
    )
    tool = git_bash_tool(tmp_path)
    task = asyncio.create_task(
        tool._run_command(command, timeout=1 if reason == "timeout" else 30)
    )
    start = time.monotonic()
    try:
        await wait_file(ready)
        if reason == "cancel":
            start = time.monotonic()
            task.cancel("native command cancellation")
        with pytest.raises(
            TimeoutError if reason == "timeout" else asyncio.CancelledError
        ):
            await asyncio.wait_for(task, 5)
        assert time.monotonic() - start < 4.5, "old five-second pipe wait returned"
        # Wait past the entire finite command; an orphan must not write later.
        await asyncio.sleep(9)
        assert not late.exists(), "timed-out/cancelled command tree kept running"
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_git_bash_normal_output_and_exit(tmp_path, module_job):
    result = await git_bash_tool(tmp_path)._run_command(
        "printf normal; printf diagnostic >&2; exit 7", timeout=30
    )
    assert result["returncode"] == 7
    assert result["stdout"] == "normal"
    assert result["stderr"] == "diagnostic"


@pytest.mark.asyncio
async def test_timeout_does_not_end_other_command_in_same_module_job(
    tmp_path, module_job
):
    peer_ready = tmp_path / "peer-ready"
    peer_done = tmp_path / "peer-done"
    tool = git_bash_tool(tmp_path)
    peer = asyncio.create_task(
        tool._run_command(
            f"printf ready > {shlex.quote(peer_ready.as_posix())}; "
            f"sleep 3; printf survived > {shlex.quote(peer_done.as_posix())}",
            timeout=30,
        )
    )
    try:
        await wait_file(peer_ready)
        with pytest.raises(TimeoutError):
            await tool._run_command("sleep 6", timeout=1)
        result = await asyncio.wait_for(peer, 10)
        assert result["returncode"] == 0
        assert peer_done.read_text(encoding="utf-8") == "survived"
    finally:
        if not peer.done():
            peer.cancel()
        await asyncio.gather(peer, return_exceptions=True)
