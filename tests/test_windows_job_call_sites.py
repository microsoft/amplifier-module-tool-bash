"""All-platform suspended-start contracts; fake the OS boundary, not the ordering.

GAP-013/GAP-028 no longer uses a descendant walk. Both foreground Windows
branches must assign before resume without an intervening await, and must still
resume with a disabled or failing optional job. POSIX/background stay unchanged.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
from pathlib import Path
import textwrap
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import amplifier_module_tool_bash as mod


class _FakeProc:
    def __init__(self, events):
        self.pid = 424242
        self.returncode = None
        self.events = events
        self.killed = False

    async def communicate(self):
        self.events.append("communicate")
        self.returncode = 7
        return b"complete output", b"diagnostic"

    def kill(self):
        self.events.append("kill")
        self.killed = True
        self.returncode = 1

    async def wait(self):
        self.events.append("reap")
        # A missing kill must not be hidden by an immediately returning mock.
        if not self.killed:
            await asyncio.Event().wait()
        return self.returncode


@pytest.mark.asyncio
@pytest.mark.parametrize("is_wsl", [True, False], ids=["wsl", "gitbash"])
@pytest.mark.parametrize("assignment", [True, False, "raises"])
async def test_windows_create_assign_resume_order(monkeypatch, is_wsl, assignment):
    events = []
    proc = _FakeProc(events)
    tool = mod.BashTool({})
    monkeypatch.setattr(
        tool, "_resolve_windows_bash", AsyncMock(return_value=("bash.exe", is_wsl))
    )
    monkeypatch.setattr(mod.sys, "platform", "win32")

    async def create(*args, **kwargs):
        events.append("create")
        assert kwargs["creationflags"] & 0x4, "command must be born suspended"
        assert kwargs["stdin"] == asyncio.subprocess.DEVNULL
        assert args == (
            ("wsl", "--exec", "bash", "-c", "echo hi")
            if is_wsl
            else ("bash.exe", "-c", "echo hi")
        )
        return proc

    def assign(pid):
        assert pid == proc.pid
        events.append("assign")
        if assignment == "raises":
            raise RuntimeError("host assignment failed")
        return assignment

    def resume(pid):
        assert pid == proc.pid
        events.append("resume")

    monkeypatch.setattr(mod.asyncio, "create_subprocess_exec", create)
    # Replacements AFTER module import must be used: hosts disable the job here.
    monkeypatch.setattr(mod, "_assign_to_windows_job", assign)
    monkeypatch.setattr(mod, "_resume_windows_process", resume)
    result = await asyncio.wait_for(tool._run_command("echo hi", timeout=30), 5)
    assert events == ["create", "assign", "resume", "communicate"]
    assert result["stdout"] == "complete output"
    assert result["stderr"] == "diagnostic"
    assert result["returncode"] == 7
    assert not proc.killed


@pytest.mark.asyncio
@pytest.mark.parametrize("is_wsl", [True, False], ids=["wsl", "gitbash"])
@pytest.mark.parametrize("cause", ["No thread found", "ResumeThread failed"])
async def test_failed_resume_kills_reaps_and_returns_error_without_hang(
    monkeypatch, is_wsl, cause
):
    events = []
    proc = _FakeProc(events)
    tool = mod.BashTool({})
    monkeypatch.setattr(
        tool, "_resolve_windows_bash", AsyncMock(return_value=("bash.exe", is_wsl))
    )
    monkeypatch.setattr(mod.sys, "platform", "win32")
    monkeypatch.setattr(
        mod.asyncio, "create_subprocess_exec", AsyncMock(return_value=proc)
    )
    monkeypatch.setattr(mod, "_assign_to_windows_job", lambda _: False)
    monkeypatch.setattr(
        mod, "_resume_windows_process", MagicMock(side_effect=RuntimeError(cause))
    )
    result = await asyncio.wait_for(tool._run_command("echo hi", timeout=30), 2)
    assert events == ["kill", "reap"]
    assert result == {
        "stdout": "",
        "stderr": f"Windows command could not resume: {cause}",
        "stdout_raw": b"",
        "stderr_raw": f"Windows command could not resume: {cause}".encode("utf-8"),
        "returncode": 1,
    }


@pytest.mark.asyncio
async def test_execute_failed_resume_preserves_person_visible_cause(monkeypatch):
    events = []
    proc = _FakeProc(events)
    tool = mod.BashTool({"safety_profile": "unrestricted"})
    monkeypatch.setattr(mod.sys, "platform", "win32")
    monkeypatch.setattr(
        tool, "_resolve_windows_bash", AsyncMock(return_value=("bash.exe", False))
    )
    monkeypatch.setattr(
        mod.asyncio, "create_subprocess_exec", AsyncMock(return_value=proc)
    )
    monkeypatch.setattr(mod, "_assign_to_windows_job", lambda _: False)
    cause = "ResumeThread failed (Windows error code 5)"
    monkeypatch.setattr(
        mod, "_resume_windows_process", MagicMock(side_effect=RuntimeError(cause))
    )
    result = await asyncio.wait_for(tool.execute({"command": "echo hi"}), 5)
    assert result.success is False
    assert isinstance(result.output, dict), result.output
    assert cause in result.output["stderr"]
    assert result.output["returncode"] == 1
    assert events == ["kill", "reap"]


@pytest.mark.asyncio
async def test_execute_no_bash_preserves_person_visible_cause(monkeypatch):
    tool = mod.BashTool({"safety_profile": "unrestricted"})
    monkeypatch.setattr(mod.sys, "platform", "win32")
    monkeypatch.setattr(
        tool, "_resolve_windows_bash", AsyncMock(return_value=(None, False))
    )
    result = await tool.execute({"command": "echo hi"})
    assert result.success is False
    assert isinstance(result.output, dict), result.output
    assert result.output["stderr"] == mod._WINDOWS_NO_BASH_ERROR
    assert result.output["returncode"] == 1


@pytest.mark.asyncio
async def test_execute_decoded_only_result_uses_utf8_fallback(monkeypatch):
    tool = mod.BashTool({"safety_profile": "unrestricted"})
    monkeypatch.setattr(
        tool,
        "_run_command",
        AsyncMock(
            return_value={
                "stdout": "caf\u00e9",
                "stderr": "cause \u00e9",
                "returncode": 1,
            }
        ),
    )
    result = await tool.execute({"command": "echo hi"})
    assert result.success is False
    assert result.output == {
        "stdout": "caf\u00e9",
        "stderr": "cause \u00e9",
        "returncode": 1,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "interrupt_type", [KeyboardInterrupt, SystemExit, asyncio.CancelledError]
)
@pytest.mark.parametrize("failure_site", ["assign", "resume"])
async def test_interrupt_kills_reaps_then_reraises(
    monkeypatch, interrupt_type, failure_site
):
    events = []
    proc = _FakeProc(events)
    tool = mod.BashTool({})
    monkeypatch.setattr(mod.sys, "platform", "win32")
    monkeypatch.setattr(
        tool, "_resolve_windows_bash", AsyncMock(return_value=("bash.exe", False))
    )
    monkeypatch.setattr(
        mod.asyncio, "create_subprocess_exec", AsyncMock(return_value=proc)
    )
    interrupt = interrupt_type("stop")
    monkeypatch.setattr(
        mod,
        "_assign_to_windows_job",
        MagicMock(side_effect=interrupt)
        if failure_site == "assign"
        else lambda _: False,
    )
    resume = (
        MagicMock(side_effect=interrupt) if failure_site == "resume" else MagicMock()
    )
    monkeypatch.setattr(mod, "_resume_windows_process", resume)
    # Catch in this same coroutine; an unhandled KeyboardInterrupt in a separate
    # asyncio task would stop pytest's loop instead of testing the contract.
    with pytest.raises(interrupt_type) as raised:
        await tool._run_command("echo hi", timeout=30)
    assert raised.value is interrupt
    assert events == ["kill", "reap"]
    if failure_site == "assign":
        resume.assert_not_called()


@pytest.mark.asyncio
async def test_failed_resume_already_exited_process_is_still_reaped(monkeypatch):
    events = []
    proc = _FakeProc(events)
    proc.killed = True
    proc.returncode = 1

    def gone():
        events.append("kill")
        raise ProcessLookupError("already ended")

    proc.kill = gone
    tool = mod.BashTool({})
    monkeypatch.setattr(mod.sys, "platform", "win32")
    monkeypatch.setattr(
        tool, "_resolve_windows_bash", AsyncMock(return_value=("bash.exe", False))
    )
    monkeypatch.setattr(
        mod.asyncio, "create_subprocess_exec", AsyncMock(return_value=proc)
    )
    monkeypatch.setattr(mod, "_assign_to_windows_job", lambda _: False)
    monkeypatch.setattr(
        mod,
        "_resume_windows_process",
        MagicMock(side_effect=RuntimeError("resume failed")),
    )
    result = await asyncio.wait_for(tool._run_command("echo hi", timeout=30), 5)
    assert events == ["kill", "reap"]
    assert result["stderr"] == "Windows command could not resume: resume failed"
    assert result["stderr_raw"] == result["stderr"].encode("utf-8")
    assert result["returncode"] == 1


def test_get_job_entry_point_is_looked_up_at_call_time(monkeypatch):
    # The REAL assign function must consult the replacement get-job function.
    get_job = MagicMock(return_value=None)
    resume = MagicMock()
    monkeypatch.setattr(mod.sys, "platform", "win32")
    monkeypatch.setattr(mod, "_get_windows_job_object", get_job)
    monkeypatch.setattr(mod, "_resume_windows_process", resume)
    proc = _FakeProc([])
    mod._assign_and_resume_windows_process(proc)
    get_job.assert_called_once_with()
    resume.assert_called_once_with(proc.pid)


def test_helper_and_post_spawn_path_have_no_await():
    helper = ast.parse(
        textwrap.dedent(inspect.getsource(mod._assign_and_resume_windows_process))
    )
    assert not any(
        isinstance(node, (ast.Await, ast.AsyncFunctionDef)) for node in ast.walk(helper)
    )
    # Also guard the call's arguments, not merely the gap before its start.
    _assert_no_await_before_resume(inspect.getsource(mod.BashTool._run_command))


def _assert_no_await_before_resume(source):
    run = ast.parse(textwrap.dedent(source))
    create = next(
        node
        for node in ast.walk(run)
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Await)
        and isinstance(node.value.value, ast.Call)
        and getattr(node.value.value.func, "attr", "") == "create_subprocess_exec"
    )
    resume = next(
        node
        for node in ast.walk(run)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_assign_and_resume_windows_process"
    )
    assert create.lineno < resume.lineno
    after_create = (create.end_lineno, create.end_col_offset)
    through_resume = (resume.end_lineno, resume.end_col_offset)
    assert not any(
        isinstance(node, ast.Await)
        and after_create < (node.lineno, node.col_offset) < through_resume
        for node in ast.walk(run)
    )


@pytest.mark.parametrize(
    "call",
    [
        "await asyncio.sleep(0); _assign_and_resume_windows_process(process)",
        "_assign_and_resume_windows_process(await something(process))",
    ],
    ids=["same-line-await", "await-in-helper-argument"],
)
def test_no_await_guard_rejects_yields_through_end_of_call(call):
    source = (
        "async def run():\n"
        "    process = await asyncio.create_subprocess_exec('command')\n"
        f"    {call}\n"
    )
    with pytest.raises(AssertionError):
        _assert_no_await_before_resume(source)


def test_no_windows_process_table_walk_or_time_ancestry():
    for name in (
        "_protect_windows_descendants",
        "_spawn_descendant_sweep",
        "_enumerate_child_pids_windows",
        "_windows_sweep_tasks",
        "_open_windows_process",
        "_verified_windows_child",
        "_WindowsProcessIdentity",
        "_WINDOWS_SWEEP_MAX_PROCESSES",
    ):
        assert not hasattr(mod, name), name
    for path in Path(mod.__file__).parent.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        for forbidden in (
            "TH32CS_SNAPPROCESS",
            "Process32First",
            "Process32Next",
            "GetProcessTimes",
            "NtResumeProcess",
        ):
            assert forbidden not in source, (path, forbidden)


@pytest.mark.asyncio
async def test_posix_never_touches_windows_helpers(monkeypatch):
    tool = mod.BashTool({})
    proc = _FakeProc([])
    assign = MagicMock()
    resume = MagicMock()
    monkeypatch.setattr(mod.sys, "platform", "linux")
    monkeypatch.setattr(mod, "_assign_to_windows_job", assign)
    monkeypatch.setattr(mod, "_assign_and_resume_windows_process", resume)
    create = AsyncMock(return_value=proc)
    monkeypatch.setattr(mod.asyncio, "create_subprocess_shell", create)
    await tool._run_command("echo hi", timeout=30)
    assign.assert_not_called()
    resume.assert_not_called()
    assert "creationflags" not in create.call_args.kwargs


def test_job_failure_is_reported_loudly_once_not_silently():
    original = mod._windows_job_failure_reported
    try:
        mod._windows_job_failure_reported = False
        with patch.object(mod, "logger") as log:
            mod._report_windows_job_failure("first failure (%s)", "boom")
            mod._report_windows_job_failure("second failure (%s)", "boom")
        assert log.warning.call_count == 1
        assert log.debug.call_count == 1
        assert "NOT active" in log.warning.call_args.args[0]
    finally:
        mod._windows_job_failure_reported = original
