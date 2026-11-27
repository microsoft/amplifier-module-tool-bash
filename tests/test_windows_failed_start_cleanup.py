"""Failed Windows start must not wait for pipes held by an owned descendant.

Fake Windows start/resume boundaries permit this regression on every platform.
CPython 3.11 to 3.13 can wait for inherited pipes too. Real-process cases use finite Python trees
started here, with cooperative descendant shutdown and retained root handles.
"""

from __future__ import annotations

import asyncio
import sys
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

import amplifier_module_tool_bash as mod


class _Process:
    def __init__(self, *, depends_on_close=False):
        self.pid = 424242
        self.killed = False
        self.returncode = None
        self.waiting = asyncio.Event()
        self.release = asyncio.Event()
        self.wait_finished = False
        self._transport = MagicMock()
        if depends_on_close:
            self._transport.close.side_effect = self.release.set

    def kill(self):
        self.killed = True
        self.returncode = 1

    async def wait(self):
        assert self.killed, "must kill before waiting"
        self.waiting.set()
        await self.release.wait()
        self.wait_finished = True
        return self.returncode


def _setup(monkeypatch, process, first):
    tool = mod.BashTool({"safety_profile": "unrestricted"})
    monkeypatch.setattr(mod.sys, "platform", "win32")
    monkeypatch.setattr(
        tool, "_resolve_windows_bash", AsyncMock(return_value=("python", False))
    )
    monkeypatch.setattr(
        mod.asyncio, "create_subprocess_exec", AsyncMock(return_value=process)
    )
    monkeypatch.setattr(mod, "_assign_to_windows_job", lambda _: False)
    monkeypatch.setattr(mod, "_resume_windows_process", MagicMock(side_effect=first))
    return tool


async def _catch_first(tool):
    # Catch control-flow errors INSIDE the task: a raw KeyboardInterrupt in an
    # asyncio Task would stop pytest's event loop rather than exercise cleanup.
    try:
        return "result", await tool._run_command("echo hi", timeout=300)
    except BaseException as error:
        return "raised", error


def _first(kind):
    return {
        "failure": RuntimeError,
        "cancellation": asyncio.CancelledError,
        "interrupt": KeyboardInterrupt,
        "exit": SystemExit,
    }[kind]("original later-thread resume failure")


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["failure", "cancellation", "interrupt", "exit"])
async def test_cleanup_deadline_preserves_first_outcome_and_closes_transport(
    monkeypatch, kind
):
    process = _Process()  # even closing pipes cannot complete this wait
    first = _first(kind)
    tool = _setup(monkeypatch, process, first)
    monkeypatch.setattr(mod, "_WINDOWS_START_CLEANUP_TIMEOUT_SECONDS", 0.05)
    start = time.monotonic()
    task = asyncio.create_task(_catch_first(tool))
    try:
        done, _ = await asyncio.wait({task}, timeout=2)
        assert task in done, "failed-start cleanup exceeded its independent bound"
        assert time.monotonic() - start < 2
        status, value = task.result()
        if kind == "failure":
            assert status == "result"
            assert str(first) in value["stderr"]
            assert "cleanup did not finish within 0.05 seconds" in value["stderr"]
            assert value["stderr_raw"] == value["stderr"].encode("utf-8")
            assert value["returncode"] == 1
        else:
            assert status == "raised"
            assert value is first
            assert any(
                "cleanup did not finish within 0.05 seconds" in note
                for note in value.__notes__
            )
        assert process.killed
        process._transport.close.assert_called_once_with()
    finally:
        process.release.set()  # mutation backstop: never leave a blocked task
        await asyncio.wait_for(task, 5)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["failure", "cancellation", "interrupt", "exit"])
async def test_repeated_cancellation_during_cleanup_keeps_first_outcome(
    monkeypatch, caplog, kind
):
    # Round 5 intentionally changes the ordinary-failure expectation: a Stop
    # during cleanup must stop the caller after reaping, not become a result.
    # An original interrupt still takes precedence over later cancellations.
    process = _Process()
    first = _first(kind)
    tool = _setup(monkeypatch, process, first)
    monkeypatch.setattr(mod, "_WINDOWS_START_CLEANUP_TIMEOUT_SECONDS", 0.5)
    task = asyncio.create_task(_catch_first(tool))
    try:
        await asyncio.wait_for(process.waiting.wait(), 2)
        task.cancel("second cancellation")
        await asyncio.sleep(0)
        task.cancel("third cancellation")
        await asyncio.sleep(0)
        assert process.killed
        process._transport.close.assert_called_once_with()
        assert not task.done(), "a later cancellation replaced the first outcome"
        assert not process.wait_finished
        process.release.set()
        done, _ = await asyncio.wait({task}, timeout=2)
        assert task in done
        status, value = task.result()
        assert process.wait_finished, "cancellation was raised before reaping finished"
        assert status == "raised"
        if kind == "failure":
            assert isinstance(value, asyncio.CancelledError)
            assert value.args == ("second cancellation",)
            assert str(first) in caplog.text
        else:
            assert value is first
    finally:
        process.release.set()
        await asyncio.wait_for(task, 5)


@pytest.mark.asyncio
async def test_stop_during_cleanup_cancels_execute_and_prevents_caller_next_step(
    monkeypatch, caplog
):
    process = _Process()
    first = RuntimeError("original resume error before Stop")
    tool = _setup(monkeypatch, process, first)
    monkeypatch.setattr(mod, "_WINDOWS_START_CLEANUP_TIMEOUT_SECONDS", 0.5)
    next_steps = []

    async def caller():
        await tool.execute({"command": "echo hi"})
        next_steps.append("must not run")

    task = asyncio.create_task(caller())
    try:
        await asyncio.wait_for(process.waiting.wait(), 2)
        task.cancel("person's Stop")
        await asyncio.sleep(0)
        assert not task.done()
        process.release.set()
        with pytest.raises(asyncio.CancelledError, match="person's Stop"):
            await asyncio.wait_for(task, 2)
        assert task.cancelled()
        assert process.wait_finished
        assert next_steps == []
        assert str(first) in caplog.text
    finally:
        process.release.set()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_wait_for_execute_remains_a_timeout_after_bounded_reap(
    monkeypatch, caplog
):
    process = _Process()
    first = RuntimeError("original resume error before caller timeout")
    tool = _setup(monkeypatch, process, first)
    monkeypatch.setattr(mod, "_WINDOWS_START_CLEANUP_TIMEOUT_SECONDS", 0.05)
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(tool.execute({"command": "echo hi"}), 0.01)
    assert time.monotonic() - start < 2
    assert process.killed
    process._transport.close.assert_called_once_with()
    assert str(first) in caplog.text
    assert "cleanup did not finish within 0.05 seconds" in caplog.text


@pytest.mark.parametrize("kind", ["failure", "cancellation", "interrupt", "exit"])
def test_asyncio_run_shutdown_before_reap_first_step_already_killed_and_closed(
    monkeypatch, kind
):
    saved = {}

    async def main():
        process = _Process()
        first = _first(kind)
        tool = _setup(monkeypatch, process, first)
        saved.update(process=process, first=first)
        saved["worker"] = asyncio.create_task(_catch_first(tool))
        # Return without awaiting the worker. run_until_complete queues its stop
        # callback after the worker's first step, but before the new reap's first
        # step. asyncio.run then directly cancels ALL pending tasks at shutdown.

    asyncio.run(main())
    process, first = saved["process"], saved["first"]
    assert process.killed, "root kill must not depend on the reap task's first step"
    process._transport.close.assert_called_once_with()
    assert not process.waiting.is_set(), "the reap must not have started in this probe"
    status, value = saved["worker"].result()
    if kind == "failure":
        assert status == "result"
        assert str(first) in value["stderr"]
        assert "reap task was cancelled" in value["stderr"]
        assert value["stderr_raw"] == value["stderr"].encode("utf-8")
    else:
        assert status == "raised"
        assert value is first
        assert any("reap task was cancelled" in note for note in first.__notes__)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["failure", "cancellation", "interrupt", "exit"])
async def test_direct_reap_cancellation_does_not_replace_original_outcome(
    monkeypatch, kind
):
    process = _Process()
    first = _first(kind)
    tool = _setup(monkeypatch, process, first)
    create_task = asyncio.create_task
    reaps = []

    def cancel_before_start(coro, *args, **kwargs):
        if coro.cr_code.co_name == "_reap_failed_windows_start":
            assert process.killed, "kill must precede reap task creation"
            process._transport.close.assert_called_once_with()
            task = create_task(coro, *args, **kwargs)
            reaps.append(task)
            task.cancel("direct reap cancellation")
            return task
        return create_task(coro, *args, **kwargs)

    monkeypatch.setattr(mod.asyncio, "create_task", cancel_before_start)
    status, value = await _catch_first(tool)
    assert len(reaps) == 1
    assert reaps[0].cancelled()
    assert not process.waiting.is_set()
    if kind == "failure":
        assert status == "result"
        assert str(first) in value["stderr"]
        assert "reap task was cancelled" in value["stderr"]
    else:
        assert status == "raised"
        assert value is first
        assert any("reap task was cancelled" in note for note in first.__notes__)


@pytest.mark.asyncio
async def test_closes_local_pipes_before_wait_not_after_timeout(monkeypatch):
    process = _Process(depends_on_close=True)
    tool = _setup(monkeypatch, process, RuntimeError("late failure"))
    monkeypatch.setattr(mod, "_WINDOWS_START_CLEANUP_TIMEOUT_SECONDS", 0.05)
    task = asyncio.create_task(_catch_first(tool))
    try:
        done, _ = await asyncio.wait({task}, timeout=2)
        assert task in done
        status, result = task.result()
        assert status == "result"
        assert result["stderr"] == "Windows command could not resume: late failure"
        process._transport.close.assert_called_once_with()
    finally:
        process.release.set()
        await asyncio.wait_for(task, 5)


async def _wait_file(path):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if path.exists() and path.read_text(encoding="utf-8").strip():
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"test-owned process did not write {path}")


@pytest.mark.asyncio
async def test_partial_resume_owned_child_holds_pipes_but_call_returns(
    tmp_path, monkeypatch
):
    # A fake Windows creation boundary launches a REAL native Python root. It
    # partly 'resumes' by spawning a child inheriting both pipes, then fails.
    # No Windows job or real foreign process is touched on any platform.
    ready = tmp_path / "child.ready"
    stop = tmp_path / "child.stop"
    ended = tmp_path / "child.ended"
    child_script = tmp_path / "pipe_holder.py"
    child_script.write_text(
        "from pathlib import Path\nimport sys,time\n"
        "ready,stop,ended=map(Path,sys.argv[1:])\n"
        "ready.write_text('ready',encoding='utf-8')\n"
        "deadline=time.monotonic()+60\n"
        "while not stop.exists() and time.monotonic()<deadline: time.sleep(0.02)\n"
        "ended.write_text('ended',encoding='utf-8')\n",
        encoding="utf-8",
    )
    parent_code = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable,{str(child_script)!r},{str(ready)!r},{str(stop)!r},{str(ended)!r}]); "
        "time.sleep(60)"
    )
    tool = mod.BashTool({})
    create = asyncio.create_subprocess_exec
    roots = []

    async def partially_started(*args, **kwargs):
        # Strip Windows-only creation flags; this is the fake OS boundary.
        kwargs.pop("creationflags")
        root = await create(sys._base_executable, "-c", parent_code, **kwargs)
        roots.append(root)
        await _wait_file(ready)
        return root

    monkeypatch.setattr(mod.sys, "platform", "win32")
    monkeypatch.setattr(
        tool, "_resolve_windows_bash", AsyncMock(return_value=("python", False))
    )
    monkeypatch.setattr(mod.asyncio, "create_subprocess_exec", partially_started)
    monkeypatch.setattr(mod, "_assign_to_windows_job", lambda _: False)
    cause = "later Thread32Next failed (Windows error code 5)"
    monkeypatch.setattr(
        mod, "_resume_windows_process", MagicMock(side_effect=RuntimeError(cause))
    )
    monkeypatch.setattr(mod, "_WINDOWS_START_CLEANUP_TIMEOUT_SECONDS", 0.5)
    task = asyncio.create_task(_catch_first(tool))
    try:
        await _wait_file(ready)
        done, _ = await asyncio.wait({task}, timeout=5)
        assert task in done, (
            "owned child's inherited pipes blocked failed-start cleanup"
        )
        status, result = task.result()
        assert status == "result"
        assert result["stderr"] == f"Windows command could not resume: {cause}"
        assert result["returncode"] == 1
        assert not ended.exists(), "child must still hold its pipe ends at return"
        assert len(roots) == 1
        assert roots[0].returncode is not None
        assert roots[0]._transport.is_closing()
    finally:
        stop.write_text("stop", encoding="utf-8")
        # The child exits cooperatively; only our retained root object can kill.
        try:
            await _wait_file(ended)
        finally:
            for root in roots:
                if root.returncode is None:
                    root.kill()
                root._transport.close()
                await asyncio.wait_for(root.wait(), 10)
            await asyncio.wait_for(task, 10)
