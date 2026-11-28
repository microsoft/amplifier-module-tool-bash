"""All-platform command-job ownership contracts. Never touch a real PID here."""

from __future__ import annotations

import asyncio
import ctypes
from ctypes import wintypes
from unittest.mock import AsyncMock, MagicMock, call

import pytest

import amplifier_module_tool_bash as mod


@pytest.fixture
def kernel32(monkeypatch):
    dll = MagicMock()
    dll.CreateJobObjectW.return_value = 0x100000001
    dll.OpenProcess.return_value = 0x100000002
    dll.AssignProcessToJobObject.return_value = True
    dll.TerminateJobObject.return_value = True
    dll.CloseHandle.return_value = True
    monkeypatch.setattr(mod.sys, "platform", "win32")
    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **k: dll, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
    monkeypatch.setattr(mod, "_windows_command_job_failure_reported", False)
    return dll


def test_command_job_is_non_kill_on_close_and_has_explicit_signatures(kernel32):
    job = mod._create_windows_command_job(4242)
    assert job is not None
    kernel32.CreateJobObjectW.assert_called_once_with(None, None)
    kernel32.OpenProcess.assert_called_once_with(0x101, False, 4242)
    kernel32.AssignProcessToJobObject.assert_called_once_with(0x100000001, 0x100000002)
    kernel32.CloseHandle.assert_called_once_with(0x100000002)
    # Defaults have no limit flags; do NOT add KILL_ON_JOB_CLOSE or breakaway.
    kernel32.SetInformationJobObject.assert_not_called()
    for name in (
        "CreateJobObjectW",
        "OpenProcess",
        "AssignProcessToJobObject",
        "TerminateJobObject",
        "CloseHandle",
    ):
        assert isinstance(vars(getattr(kernel32, name)).get("argtypes"), list), name
        assert "restype" in vars(getattr(kernel32, name)), name
    assert kernel32.TerminateJobObject.argtypes == [wintypes.HANDLE, wintypes.UINT]
    assert job.terminate() is True
    kernel32.TerminateJobObject.assert_called_once_with(0x100000001, 1)
    job.close()
    job.close()
    assert kernel32.CloseHandle.call_args_list == [call(0x100000002), call(0x100000001)]


@pytest.mark.parametrize("failure", ["create", "open", "assign", "exception"])
def test_command_job_setup_failure_closes_acquired_handles_and_warns_once(
    kernel32, caplog, failure
):
    if failure == "create":
        kernel32.CreateJobObjectW.return_value = None
    elif failure == "open":
        kernel32.OpenProcess.return_value = None
    elif failure == "assign":
        kernel32.AssignProcessToJobObject.return_value = False
    else:
        kernel32.AssignProcessToJobObject.side_effect = OSError("assignment failed")
    for _ in range(2):
        assert mod._create_windows_command_job(4242) is None
    expected = []
    if failure != "create":
        if failure in ("assign", "exception"):
            expected.append(call(0x100000002))
        expected.append(call(0x100000001))
    assert kernel32.CloseHandle.call_args_list == expected * 2
    assert caplog.text.count("timeouts/cancellation fall back") == 1


class Process:
    def __init__(self, events):
        self.pid = 4242
        self.events = events
        self.returncode = None
        self._transport = MagicMock()
        self._transport.close.side_effect = lambda: self.events.append("pipes-close")

    def kill(self):
        self.events.append("kill-root")
        self.returncode = 1

    async def wait(self):
        self.events.append("reap")
        return self.returncode

    async def communicate(self):
        self.events.append("communicate")
        self.returncode = 7
        return b"output", b"diagnostic"


def setup_command(monkeypatch, *, job_available=True, resume_error=None):
    events = []
    process = Process(events)
    job = MagicMock()
    job.terminate.side_effect = lambda: events.append("terminate-tree") or True
    job.close.side_effect = lambda: events.append("job-close")
    tool = mod.BashTool({})
    monkeypatch.setattr(mod.sys, "platform", "win32")
    monkeypatch.setattr(
        tool, "_resolve_windows_bash", AsyncMock(return_value=("bash.exe", False))
    )

    async def create(*args, **kwargs):
        assert kwargs["creationflags"] & 0x4
        events.append("create-suspended")
        return process

    def module_assign(pid):
        assert pid == process.pid
        events.append("module-assign-disabled")
        return False  # host guard is on in these tests

    def command_assign(pid):
        assert pid == process.pid
        events.append("command-assign")
        return job if job_available else None

    def resume(pid):
        assert pid == process.pid
        events.append("resume")
        if resume_error:
            raise resume_error

    monkeypatch.setattr(mod.asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(mod, "_get_windows_job_object", lambda: None)
    monkeypatch.setattr(mod, "_assign_to_windows_job", module_assign)
    monkeypatch.setattr(mod, "_create_windows_command_job", command_assign)
    monkeypatch.setattr(mod, "_resume_windows_process", resume)
    return tool, process, job, events


@pytest.mark.asyncio
async def test_order_with_host_guard_and_normal_exit_does_not_terminate_children(
    monkeypatch,
):
    tool, process, job, events = setup_command(monkeypatch)
    result = await tool._run_command("echo hi", timeout=30)
    assert result["returncode"] == 7
    assert result["stdout"] == "output"
    assert events == [
        "create-suspended",
        "module-assign-disabled",
        "command-assign",
        "resume",
        "communicate",
        "job-close",
    ]
    assert process._tool_bash_command_job is None
    job.terminate.assert_not_called()
    process._transport.close.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", ["timeout", "cancel"])
@pytest.mark.parametrize("job_available", [True, False])
async def test_timeout_and_cancel_end_tree_without_five_second_pipe_wait(
    monkeypatch, reason, job_available
):
    tool, process, job, events = setup_command(monkeypatch, job_available=job_available)
    process.communicate = AsyncMock(
        side_effect=TimeoutError() if reason == "timeout" else asyncio.CancelledError()
    )
    with pytest.raises(TimeoutError if reason == "timeout" else asyncio.CancelledError):
        await asyncio.wait_for(tool._run_command("long command", timeout=300), 1)
    if job_available:
        assert events[-4:] == ["terminate-tree", "pipes-close", "reap", "job-close"]
        assert "kill-root" not in events
        job.terminate.assert_called_once_with()
        job.close.assert_called_once_with()
    else:
        assert events[-3:] == ["kill-root", "pipes-close", "reap"]
        job.close.assert_not_called()
    assert process.communicate.call_count == 1  # never communicate again for EOF
    process._transport.close.assert_called_once_with()
    assert process._tool_bash_command_job is None


@pytest.mark.asyncio
async def test_termination_api_failure_falls_back_to_root_and_closes_job(monkeypatch):
    tool, process, job, events = setup_command(monkeypatch)
    job.terminate.side_effect = lambda: events.append("terminate-tree-failed") or False
    process.communicate = AsyncMock(side_effect=TimeoutError())
    with pytest.raises(TimeoutError):
        await tool._run_command("long command", timeout=30)
    assert events[-5:] == [
        "terminate-tree-failed",
        "kill-root",
        "pipes-close",
        "reap",
        "job-close",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error", [RuntimeError("resume failed"), asyncio.CancelledError("Stop")]
)
async def test_failed_resume_closes_new_job_and_keeps_existing_bounded_cleanup(
    monkeypatch, error
):
    tool, process, job, events = setup_command(monkeypatch, resume_error=error)
    if isinstance(error, Exception):
        result = await tool._run_command("echo hi", timeout=30)
        assert "resume failed" in result["stderr"]
    else:
        with pytest.raises(asyncio.CancelledError):
            await tool._run_command("echo hi", timeout=30)
    assert "kill-root" in events and "reap" in events
    job.close.assert_called_once_with()
    assert process._tool_bash_command_job is None


@pytest.mark.asyncio
async def test_many_commands_release_every_command_handle(monkeypatch):
    tool, process, _, _ = setup_command(monkeypatch)
    jobs = []

    def new_job(pid):
        job = MagicMock()
        jobs.append(job)
        return job

    monkeypatch.setattr(mod, "_create_windows_command_job", new_job)
    for _ in range(300):
        await tool._run_command("echo hi", timeout=30)
    assert len(jobs) == 300
    for job in jobs:
        job.close.assert_called_once_with()
        job.terminate.assert_not_called()
    assert process._tool_bash_command_job is None


@pytest.mark.asyncio
async def test_tree_ended_before_cleanup_task_can_be_cancelled(monkeypatch):
    tool, process, job, events = setup_command(monkeypatch)
    process.communicate = AsyncMock(side_effect=TimeoutError())
    create_task = asyncio.create_task

    def cancel_reap(coro, *args, **kwargs):
        if coro.cr_code.co_name == "_reap_failed_windows_start":
            assert "terminate-tree" in events and "pipes-close" in events
            task = create_task(coro, *args, **kwargs)
            task.cancel()
            return task
        return create_task(coro, *args, **kwargs)

    monkeypatch.setattr(mod.asyncio, "create_task", cancel_reap)
    with pytest.raises(TimeoutError):
        await tool._run_command("long command", timeout=30)
    job.close.assert_called_once_with()


@pytest.mark.asyncio
async def test_timeout_does_not_consult_or_terminate_module_wide_job(monkeypatch):
    tool, process, job, _ = setup_command(monkeypatch)
    get_shared = MagicMock(side_effect=AssertionError("must not terminate shared job"))
    monkeypatch.setattr(mod, "_get_windows_job_object", get_shared)
    process.communicate = AsyncMock(side_effect=TimeoutError())
    with pytest.raises(TimeoutError):
        await tool._run_command("long command", timeout=30)
    job.terminate.assert_called_once_with()
    get_shared.assert_not_called()


@pytest.mark.asyncio
async def test_unexpected_communication_error_still_closes_command_job(monkeypatch):
    tool, process, job, _ = setup_command(monkeypatch)
    process.communicate = AsyncMock(side_effect=OSError("pipe failure"))
    with pytest.raises(OSError, match="pipe failure"):
        await tool._run_command("echo hi", timeout=30)
    job.close.assert_called_once_with()


@pytest.mark.parametrize("failure", [False, OSError("terminate failed")])
def test_native_termination_failure_warns_and_returns_false(kernel32, caplog, failure):
    job = mod._create_windows_command_job(4242)
    if failure is False:
        kernel32.TerminateJobObject.return_value = False
    else:
        kernel32.TerminateJobObject.side_effect = failure
    assert job.terminate() is False
    assert "root only" in caplog.text
    job.close()
