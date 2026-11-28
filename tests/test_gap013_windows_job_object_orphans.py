"""Native GAP-013/024/028 tests: join the job BEFORE a command can run.

The old late-assignment harness did not prove inheritance at birth. These tests
run the real foreground helper/job with throwaway Python commands, check each
tree member with IsProcessInJob, exclude an unrelated test-owned process, and
retain kill-on-host-exit coverage. No process-table walk or bare-PID termination.
GitHub Windows runners have no WSL; this is native Python mechanism coverage.
"""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import os
import subprocess
import sys
import time

import pytest

import amplifier_module_tool_bash as mod

pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="native Windows jobs/threads"
)


def _kernel32():
    dll = ctypes.WinDLL("kernel32", use_last_error=True)
    dll.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    dll.OpenProcess.restype = wintypes.HANDLE
    dll.CloseHandle.argtypes = [wintypes.HANDLE]
    dll.CloseHandle.restype = wintypes.BOOL
    dll.IsProcessInJob.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.BOOL),
    ]
    dll.IsProcessInJob.restype = wintypes.BOOL
    dll.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    dll.WaitForSingleObject.restype = wintypes.DWORD
    dll.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    dll.QueryInformationJobObject.restype = wintypes.BOOL
    return dll


@pytest.fixture
def native_job(monkeypatch):
    # Each test's job contains ONLY commands created by that test. Restore the
    # module cache afterwards, never close another test/host's job.
    dll = _kernel32()
    monkeypatch.setattr(mod, "_windows_job_handle", None)
    job = mod._get_windows_job_object()
    assert job is not None
    try:
        yield dll, job
    finally:
        assert dll.CloseHandle(job)
        mod._windows_job_handle = None


def _tool(tmp_path):
    tool = mod.BashTool({"working_dir": str(tmp_path)})
    # Bypass shell discovery and the venv redirector. The real _run_command
    # Windows branch, creation flags, helper, pipes and exit handling all run.
    tool._windows_bash_resolved = (sys._base_executable, False)
    return tool


async def _marker(path):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if path.exists():
            text = path.read_text(encoding="utf-8").strip()
            if text:
                return int(text)
        await asyncio.sleep(0.05)
    raise AssertionError(f"test process did not become ready: {path}")


@contextmanager
def _owned_handle(dll, pid):
    # Read/wait only. PID comes solely from our finite, still-running tree.
    handle = dll.OpenProcess(0x101000, False, pid)
    assert handle
    try:
        yield handle
    finally:
        assert dll.CloseHandle(handle)


def _in_job(dll, job, handle):
    member = wintypes.BOOL()
    assert dll.IsProcessInJob(handle, job, ctypes.byref(member))
    return bool(member.value)


def _job_pids(dll, job):
    class ProcessList(ctypes.Structure):
        _fields_ = [
            ("NumberOfAssignedProcesses", wintypes.DWORD),
            ("NumberOfProcessIdsInList", wintypes.DWORD),
            ("ProcessIdList", ctypes.c_size_t * 64),
        ]

    info = ProcessList()
    assert dll.QueryInformationJobObject(
        job, 3, ctypes.byref(info), ctypes.sizeof(info), None
    )
    assert info.NumberOfAssignedProcesses <= 64
    return set(info.ProcessIdList[: info.NumberOfProcessIdsInList])


_TREE = """
import os
from pathlib import Path
import subprocess
import sys
import time
root = Path(sys.argv[1])
level = int(sys.argv[2])
# Spawn IMMEDIATELY; the production helper must assign before this can run.
if level < 2:
    subprocess.Popen([sys.executable, __file__, str(root), str(level + 1)])
(root / (str(level) + '.pid')).write_text(str(os.getpid()), encoding='utf-8')
deadline = time.monotonic() + 60
while not (root / 'stop').exists() and time.monotonic() < deadline:
    time.sleep(0.05)
"""


@pytest.mark.asyncio
async def test_immediate_tree_inherits_job_and_unrelated_process_does_not(
    tmp_path, native_job
):
    dll, job = native_job
    script = tmp_path / "tree.py"
    script.write_text(_TREE, encoding="utf-8")
    unrelated = subprocess.Popen(
        [sys._base_executable, "-c", "import time; time.sleep(60)"]
    )
    # Parent starts child, and child starts grandchild, as their first action.
    command = f"import runpy,sys; sys.argv=[{str(script)!r},{str(tmp_path)!r},'0']; runpy.run_path({str(script)!r},run_name='__main__')"
    task = asyncio.create_task(_tool(tmp_path)._run_command(command, timeout=90))
    try:
        pids = {await _marker(tmp_path / f"{level}.pid") for level in range(3)}
        for pid in pids:
            with _owned_handle(dll, pid) as handle:
                assert _in_job(dll, job, handle), (
                    f"test-owned PID {pid} missed inheritance"
                )
        assert pids <= _job_pids(dll, job)  # conhost.exe may also join the job
        with _owned_handle(dll, unrelated.pid) as handle:
            assert not _in_job(dll, job, handle)
    finally:
        (tmp_path / "stop").write_text("stop", encoding="utf-8")
        try:
            result = await asyncio.wait_for(task, 40)
            assert result["returncode"] == 0, result
        finally:
            # Popen retains the actual test-created process handle; no PID walk.
            if unrelated.poll() is None:
                unrelated.kill()
            unrelated.wait(timeout=30)


@pytest.mark.asyncio
async def test_immediate_exit_keeps_output_and_exit_code(tmp_path, native_job):
    result = await asyncio.wait_for(
        _tool(tmp_path)._run_command(
            "import sys; print('instant'); sys.exit(23)", timeout=30
        ),
        40,
    )
    assert result["returncode"] == 23
    assert result["stdout"].splitlines() == ["instant"]
    assert result["stderr"] == ""


@pytest.mark.asyncio
async def test_suspended_start_preserves_complete_pipe_output(tmp_path, native_job):
    # More than a pipe buffer on both streams, not merely one buffered line.
    command = "import sys; sys.stdout.write('o'*262144); sys.stderr.write('e'*262144)"
    result = await asyncio.wait_for(
        _tool(tmp_path)._run_command(command, timeout=30), 40
    )
    assert result["returncode"] == 0
    assert result["stdout"] == "o" * 262144
    assert result["stderr"] == "e" * 262144


@pytest.mark.asyncio
async def test_real_suspended_command_is_reaped_when_resume_fails(
    tmp_path, native_job, monkeypatch
):
    spawned = []
    create = mod.asyncio.create_subprocess_exec

    async def record(*args, **kwargs):
        process = await create(*args, **kwargs)
        spawned.append(process)
        return process

    monkeypatch.setattr(mod.asyncio, "create_subprocess_exec", record)

    def failed(_):
        raise RuntimeError("injected ResumeThread failure")

    monkeypatch.setattr(mod, "_resume_windows_process", failed)
    try:
        result = await asyncio.wait_for(
            _tool(tmp_path)._run_command("print('must not run')", timeout=30), 10
        )
        assert result["returncode"] == 1
        assert "injected ResumeThread failure" in result["stderr"]
        assert result["stdout"] == ""
        assert len(spawned) == 1
        assert spawned[0].returncode is not None
    finally:
        for process in spawned:
            if process.returncode is None:
                process.kill()
            await asyncio.wait_for(process.wait(), 30)


_HOST = """
import asyncio
from pathlib import Path
import sys
from amplifier_module_tool_bash import _assign_and_resume_windows_process
async def main():
    child = await asyncio.create_subprocess_exec(sys._base_executable, '-c', 'import time; time.sleep(60)', creationflags=0x4)
    _assign_and_resume_windows_process(child)
    Path(sys.argv[1]).write_text(str(child.pid), encoding='utf-8')
    await child.wait()
asyncio.run(main())
"""


@pytest.mark.asyncio
async def test_abrupt_host_exit_still_kills_assigned_child(tmp_path):
    dll = _kernel32()
    marker = tmp_path / "child.pid"
    # The base interpreter avoids killing only a venv redirector. PYTHONPATH
    # carries this test's installed module/dependencies into the stand-in host.
    host = subprocess.Popen(
        [sys._base_executable, "-c", _HOST, str(marker)],
        env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)},
    )
    try:
        child_pid = await _marker(marker)
        with _owned_handle(dll, child_pid) as child:
            assert dll.WaitForSingleObject(child, 0) == 258  # WAIT_TIMEOUT: alive
            host.kill()  # only the owned host handle, not a tree/PID kill
            host.wait(timeout=30)
            assert dll.WaitForSingleObject(child, 30000) == 0
    finally:
        if host.poll() is None:
            host.kill()
        host.wait(timeout=30)
