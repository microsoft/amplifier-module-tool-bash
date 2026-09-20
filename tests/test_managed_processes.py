"""Real process lifecycle tests through the public bash action interface."""

import asyncio
import shlex
import sys
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from amplifier_module_tool_bash import BashTool, mount

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX managed process backend"
)


def python(code):
    return f"{shlex.quote(sys.executable)} -u -c {shlex.quote(code)}"


@pytest_asyncio.fixture
async def tool():
    instance = BashTool(
        {
            "managed_processes": True,
            "managed_stdin": True,
            "safety_profile": "unrestricted",
        }
    )
    yield instance
    await instance.close()


async def action(tool, action, **kwargs):
    result = await tool.execute({"action": action, **kwargs})
    assert result.success, result.error
    return result.output


async def finished(tool, process_id):
    # Wait on the owned supervisor, then observe the result through the public
    # interface. No sleeps or dependence on subprocess scheduler speed.
    await asyncio.wait_for(
        asyncio.shield(tool._processes.records[process_id].supervisor), 5
    )
    return await action(tool, "read", process_id=process_id)


def text(result, stream="stdout"):
    return "".join(
        chunk["text"] for chunk in result["chunks"] if chunk["stream"] == stream
    )


@pytest.mark.asyncio
async def test_incremental_output_stdin_eof_and_real_exit_code(tool):
    started = await action(
        tool,
        "start",
        command=python(
            "import sys; print('ready'); line=sys.stdin.readline(); print('got:'+line.strip()); print('err', file=sys.stderr); sys.exit(7)"
        ),
    )
    process_id = started["process_id"]
    first = await action(
        tool, "wait", process_id=process_id, cursor=started["next_cursor"], wait_ms=5000
    )
    assert "ready" in text(started) + text(first)
    assert first["state"] == "running"
    await action(
        tool, "write", process_id=process_id, stdin="hello\n", close_stdin=True
    )
    result = await finished(tool, process_id)
    assert result["state"] == "failed"
    assert result["returncode"] == 7
    assert result["output_complete"] is True
    remaining = await action(
        tool, "read", process_id=process_id, cursor=first["next_cursor"]
    )
    assert text(remaining) == "got:hello\n"
    assert text(remaining, "stderr") == "err\n"
    assert (
        await action(
            tool, "read", process_id=process_id, cursor=remaining["next_cursor"]
        )
    )["chunks"] == []
    assert (
        await action(tool, "read", process_id=process_id, cursor=first["next_cursor"])
        == remaining
    )


@pytest.mark.asyncio
async def test_output_bounds_cursor_expiry_and_page_budget():
    tool = BashTool(
        {
            "managed_processes": True,
            "managed_max_output_bytes": 8192,
            "safety_profile": "unrestricted",
        }
    )
    try:
        started = await action(
            tool, "start", command=python("import sys; sys.stdout.write('x'*100000)")
        )
        result = await finished(tool, started["process_id"])
        assert result["total_output_bytes"] == 100000
        assert result["dropped_output_bytes"] >= 91808
        assert result["cursor_expired"] is True
        assert len(text(result)) <= 8192
        page = await action(
            tool, "read", process_id=started["process_id"], max_bytes=4096
        )
        assert sum(chunk["source_bytes"] for chunk in page["chunks"]) <= 4096
        assert page["next_cursor"] > page["earliest_cursor"]
        invalid = await tool.execute(
            {
                "action": "read",
                "process_id": started["process_id"],
                "cursor": result["latest_cursor"] + 1,
            }
        )
        assert not invalid.success
    finally:
        await tool.close()


@pytest.mark.asyncio
async def test_split_utf8_and_binary_output(tool):
    started = await action(
        tool,
        "start",
        command=python(
            "import os,sys; os.write(1,b'\\xe2'); sys.stdin.readline(); os.write(1,b'\\x82\\xac'); os.write(2,bytes(range(256))*4)"
        ),
    )
    await action(tool, "wait", process_id=started["process_id"], wait_ms=5000)
    await action(tool, "write", process_id=started["process_id"], stdin="go\n")
    result = await finished(tool, started["process_id"])
    assert text(result) == "€"
    assert any(chunk["binary_output_withheld"] for chunk in result["chunks"])
    assert "withheld" in text(result, "stderr").lower()


@pytest.mark.asyncio
async def test_timeout_is_failed_with_real_signal_code(tool):
    started = await action(tool, "start", command="sleep 30", timeout=1)
    result = await finished(tool, started["process_id"])
    assert result["state"] == "failed"
    assert result["termination_reason"] == "timeout"
    assert result["returncode"] < 0
    assert result["cancellation_requested"] is False


@pytest.mark.asyncio
async def test_terminate_kills_descendant_and_reports_completed_cancellation(
    tool, tmp_path
):
    marker = tmp_path / "should-not-exist"
    # Child would write after the parent terminates if process group teardown
    # only killed the shell. Its output pipes also keep collection open.
    started = await action(
        tool, "start", command=f"(sleep 1; touch {shlex.quote(str(marker))}) & wait"
    )
    result = await action(tool, "terminate", process_id=started["process_id"])
    assert result["state"] == "cancelled"
    assert result["cancellation_requested"] is True
    assert result["returncode"] < 0
    assert result["output_complete"] is True
    await asyncio.sleep(1)
    assert not marker.exists()
    assert (await action(tool, "terminate", process_id=started["process_id"]))[
        "state"
    ] == "cancelled"


@pytest.mark.asyncio
async def test_completion_and_termination_race_preserves_completed_state(tool):
    started = await action(tool, "start", command="exit 0")
    await finished(tool, started["process_id"])
    result = await action(tool, "terminate", process_id=started["process_id"])
    assert result["state"] == "completed"
    assert result["returncode"] == 0
    assert result["cancellation_requested"] is False


@pytest.mark.asyncio
async def test_session_ownership_and_cleanup(tool):
    other = BashTool({"managed_processes": True})
    started = await action(tool, "start", command="sleep 30")
    assert not (
        await other.execute(
            {"action": "terminate", "process_id": started["process_id"]}
        )
    ).success
    assert (await action(other, "list"))["processes"] == []
    await tool.close()
    record = tool._processes.records[started["process_id"]]
    assert record.done.is_set()
    assert record.state == "cancelled"
    assert record.process.returncode is not None
    assert not (
        await tool.execute({"action": "start", "command": "echo should-not-start"})
    ).success
    await other.close()


@pytest.mark.asyncio
async def test_managed_and_ordinary_commands_share_concurrency_limit():
    tool = BashTool({"managed_processes": True, "max_concurrent": 1})
    try:
        started = await action(tool, "start", command="sleep 30")
        assert not (await tool.execute({"command": "echo blocked"})).success
        assert not (
            await tool.execute({"action": "start", "command": "echo blocked"})
        ).success
        await action(tool, "terminate", process_id=started["process_id"])
        assert tool._active_commands == 0
        assert (await tool.execute({"command": "echo okay"})).success
    finally:
        await tool.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "config",
    [
        {},
        {"managed_stdin": True},
        {"safety_profile": "unrestricted"},
        {
            "managed_stdin": True,
            "safety_profile": "unrestricted",
            "denied_commands": ["dangerous"],
        },
        {
            "managed_stdin": True,
            "safety_profile": "unrestricted",
            "allowed_commands": ["cat"],
        },
        {
            "managed_stdin": True,
            "safety_profile": "unrestricted",
            "safety_overrides": {"block": ["dangerous"]},
        },
    ],
)
async def test_stdin_cannot_bypass_command_policy(config):
    tool = BashTool({"managed_processes": True, **config})
    try:
        started = await action(tool, "start", command="cat")
        denied = await tool.execute(
            {
                "action": "write",
                "process_id": started["process_id"],
                "stdin": "anything\n",
            }
        )
        assert not denied.success
        assert "Raw stdin requires" in denied.error["message"]
        await action(tool, "write", process_id=started["process_id"], close_stdin=True)
        result = await finished(tool, started["process_id"])
        assert result["state"] == "completed"
        assert text(result) == ""
    finally:
        await tool.close()


@pytest.mark.asyncio
async def test_managed_start_uses_same_shell_validator():
    tool = BashTool({"managed_processes": True, "denied_commands": ["echo forbidden"]})
    assert not (
        await tool.execute({"action": "start", "command": "echo forbidden"})
    ).success
    assert tool._active_commands == 0
    assert not tool._processes.records


@pytest.mark.asyncio
async def test_followup_rejects_command_approval_spoofing(tool):
    started = await action(tool, "start", command="cat")
    denied = await tool.execute(
        {
            "action": "write",
            "command": "echo safe",
            "process_id": started["process_id"],
            "stdin": "dangerous\n",
        }
    )
    assert not denied.success


@pytest.mark.asyncio
async def test_uncertain_write_closes_input_and_cannot_be_retried(tool, monkeypatch):
    started = await action(tool, "start", command="cat")
    record = tool._processes.records[started["process_id"]]
    monkeypatch.setattr(
        record.process.stdin, "drain", AsyncMock(side_effect=TimeoutError)
    )
    result = await tool.execute(
        {
            "action": "write",
            "process_id": started["process_id"],
            "stdin": "possibly delivered\n",
        }
    )
    assert not result.success
    assert "outcome unknown" in result.error["message"]
    assert record.process.stdin.is_closing()
    retry = await tool.execute(
        {
            "action": "write",
            "process_id": started["process_id"],
            "stdin": "must not retry\n",
        }
    )
    assert not retry.success
    assert "closed" in retry.error["message"]
    output = await finished(tool, started["process_id"])
    assert "must not retry" not in text(output)


@pytest.mark.asyncio
async def test_mount_returns_owned_cleanup_callback():
    coordinator = AsyncMock()
    coordinator.get_capability = lambda name: None
    cleanup = await mount(coordinator, {"managed_processes": True})
    tool = coordinator.mount.call_args.args[1]
    started = await action(tool, "start", command="sleep 30")
    await cleanup()
    assert tool._processes.records[started["process_id"]].state == "cancelled"


@pytest.mark.asyncio
async def test_start_cancelled_during_spawn_is_cleaned(tool, monkeypatch):
    original = asyncio.create_subprocess_shell
    spawned = asyncio.Event()
    release = asyncio.Event()
    children = []

    async def delayed(*args, **kwargs):
        child = await original(*args, **kwargs)
        children.append(child)
        spawned.set()
        await release.wait()
        return child

    monkeypatch.setattr(asyncio, "create_subprocess_shell", delayed)
    start = asyncio.create_task(
        tool.execute({"action": "start", "command": "sleep 30"})
    )
    await spawned.wait()
    start.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await start
    assert children[0].returncode is not None
    assert tool._active_commands == 0


@pytest.mark.asyncio
async def test_close_waits_for_pending_spawn(tool, monkeypatch):
    original = asyncio.create_subprocess_shell
    spawned = asyncio.Event()
    release = asyncio.Event()

    async def delayed(*args, **kwargs):
        child = await original(*args, **kwargs)
        spawned.set()
        await release.wait()
        return child

    monkeypatch.setattr(asyncio, "create_subprocess_shell", delayed)
    start = asyncio.create_task(
        tool.execute({"action": "start", "command": "sleep 30"})
    )
    await spawned.wait()
    close = asyncio.create_task(tool.close())
    await asyncio.sleep(0)
    assert not close.done()
    release.set()
    assert not (await start).success
    await close
    assert tool._active_commands == 0
    assert all(
        record.process.returncode is not None
        for record in tool._processes.records.values()
    )


@pytest.mark.asyncio
async def test_record_limit_counts_concurrent_spawns():
    tool = BashTool({"managed_processes": True, "managed_max_processes": 1})
    try:
        results = await asyncio.gather(
            *(
                tool.execute({"action": "start", "command": "sleep 30"})
                for _ in range(2)
            )
        )
        assert sum(result.success for result in results) == 1
        assert len(tool._processes.records) == 1
        running = next(result.output for result in results if result.success)
        await action(tool, "terminate", process_id=running["process_id"])
        next_process = await action(tool, "start", command="echo new")
        assert next_process["process_id"] != running["process_id"]
        assert not (
            await tool.execute(
                {"action": "status", "process_id": running["process_id"]}
            )
        ).success
    finally:
        await tool.close()


@pytest.mark.asyncio
async def test_spawn_error_releases_capacity(tool, tmp_path):
    tool.working_dir = str(tmp_path / "missing")
    result = await tool.execute({"action": "start", "command": "echo missing"})
    assert not result.success
    assert tool._active_commands == 0


@pytest.mark.asyncio
async def test_legacy_schema_and_execution_unchanged():
    tool = BashTool({})
    assert tool.input_schema["required"] == ["command"]
    assert "action" not in tool.input_schema["properties"]
    assert tool.description == BashTool.description
    assert (await tool.execute({"command": "echo legacy"})).output[
        "stdout"
    ] == "legacy\n"
    denied = await tool.execute({"action": "start", "command": "echo unavailable"})
    assert not denied.success
    assert "managed_processes=true" in denied.error["message"]
