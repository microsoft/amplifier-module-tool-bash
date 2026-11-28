"""Native command-tree behavior, using only finite test-started processes.

The normal-child test is first run against bf36c12 (no product change) to pin
existing behavior: normal return must not kill a child with redirected pipes.
GitHub Windows CI has Git Bash, but no WSL.
"""

from __future__ import annotations

import asyncio
import ctypes
from ctypes import wintypes
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
    child = f"import time; from pathlib import Path; time.sleep(1); Path({str(marker)!r}).write_text('survived', encoding='utf-8')"
    parent = (
        "import subprocess,sys; "
        f"subprocess.Popen([sys.executable,'-c',{child!r}], "
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
        "print('parent-output'); sys.exit(7)"
    )
    tool = mod.BashTool({"working_dir": str(tmp_path)})
    tool._windows_bash_resolved = (sys._base_executable, False)
    result = await asyncio.wait_for(tool._run_command(parent, timeout=30), 40)
    assert result["returncode"] == 7
    assert result["stdout"].splitlines() == ["parent-output"]
    assert result["stderr"] == ""
    assert not marker.exists(), "child must still be running at normal return"
    await wait_file(marker)
    assert marker.read_text(encoding="utf-8") == "survived"
