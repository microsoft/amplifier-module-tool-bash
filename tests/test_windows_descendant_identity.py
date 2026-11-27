"""All-platform tests of PID pinning, ancestry verification and handle ownership."""

from __future__ import annotations

import asyncio
import ctypes
from ctypes import wintypes
from unittest.mock import MagicMock

import pytest

import amplifier_module_tool_bash as mod


@pytest.fixture
def processes(monkeypatch):
    """Fake only the OS boundary; run the real verifier, sweep and close code."""
    live = {}
    opened = []
    walked = []
    assigned = []
    kernel32 = MagicMock()
    times = {1: 100, 2: 101, 3: 102}
    edges = {1: {2}, 2: {3}}

    def open_process(pid):
        if pid not in times:
            return None
        identity = mod._WindowsProcessIdentity(pid, pid + 1000, times[pid], kernel32)
        live[pid] = identity
        opened.append(identity)
        return identity

    def enumerate_children(pid):
        assert live[pid].handle is not None, "parent not held during enumeration"
        # Rejected candidates are closed immediately; accepted ones stay pinned.
        assert all(live[accepted].handle is not None for accepted in assigned)
        walked.append(pid)
        return edges.get(pid, set())

    monkeypatch.setattr(mod, "_open_windows_process", open_process)
    monkeypatch.setattr(mod, "_enumerate_child_pids_windows", enumerate_children)
    monkeypatch.setattr(mod, "_assign_to_windows_job", assigned.append)
    return times, edges, open_process, opened, walked, assigned, kernel32


def assert_closed(opened, kernel32):
    assert all(identity.handle is None for identity in opened)
    assert sorted(
        call.args[0] for call in kernel32.CloseHandle.call_args_list
    ) == sorted(identity.pid + 1000 for identity in opened)


@pytest.mark.asyncio
async def test_real_tree_is_verified_and_pinned_until_end(processes):
    _, _, open_process, opened, walked, assigned, kernel32 = processes
    await mod._protect_windows_descendants(open_process(1))
    assert assigned == [2, 3]
    assert {1, 2, 3} <= set(walked)
    assert_closed(opened, kernel32)


@pytest.mark.asyncio
async def test_older_recorded_child_is_neither_assigned_nor_walked(processes):
    times, _, open_process, opened, walked, assigned, kernel32 = processes
    times[2] = 99
    # Rejected candidates can be reopened on later rounds, but never traversed.
    await mod._protect_windows_descendants(open_process(1))
    assert assigned == []
    assert set(walked) == {1}
    assert_closed(opened, kernel32)


@pytest.mark.asyncio
async def test_equal_creation_time_is_allowed(processes):
    times, _, open_process, _, _, assigned, _ = processes
    times[2] = times[1]
    await mod._protect_windows_descendants(open_process(1))
    assert assigned == [2, 3]


@pytest.mark.asyncio
async def test_failed_open_is_neither_assigned_nor_walked(processes):
    times, _, open_process, opened, walked, assigned, kernel32 = processes
    del times[2]
    await mod._protect_windows_descendants(open_process(1))
    assert assigned == []
    assert set(walked) == {1}
    assert_closed(opened, kernel32)


@pytest.mark.asyncio
async def test_unverified_pid_is_not_remembered_and_can_be_retried(
    processes, monkeypatch
):
    _, _, open_process, opened, _, assigned, kernel32 = processes
    attempts = 0

    def temporarily_unavailable(pid):
        nonlocal attempts
        if pid == 2:
            attempts += 1
            if attempts == 1:
                return None
        return open_process(pid)

    monkeypatch.setattr(mod, "_open_windows_process", temporarily_unavailable)
    await mod._protect_windows_descendants(open_process(1))
    assert attempts == 2
    assert assigned == [2, 3]
    assert_closed(opened, kernel32)


def test_child_pid_reused_between_snapshot_and_open_is_rejected(processes):
    _, edges, open_process, opened, _, assigned, kernel32 = processes
    root = open_process(1)
    # The initial snapshot had candidate 2; its replacement has a different PPID.
    edges[1] = set()
    assert mod._verified_windows_child(root, 2) is None
    assert assigned == []
    root.close()
    assert_closed(opened, kernel32)


def test_closed_parent_cannot_verify_child(processes):
    _, _, open_process, opened, walked, _, kernel32 = processes
    root = open_process(1)
    root.close()
    assert mod._verified_windows_child(root, 2) is None
    assert len(opened) == 1
    assert walked == []
    assert_closed(opened, kernel32)


@pytest.mark.asyncio
async def test_failed_assignment_does_not_replace_ancestry_verification(
    processes, monkeypatch
):
    _, _, open_process, opened, walked, _, kernel32 = processes
    assign = MagicMock(return_value=False)
    monkeypatch.setattr(mod, "_assign_to_windows_job", assign)
    await mod._protect_windows_descendants(open_process(1))
    assert [call.args[0] for call in assign.call_args_list] == [2, 3]
    assert 2 in walked  # verified child still pins and anchors its own children
    assert_closed(opened, kernel32)


@pytest.mark.asyncio
async def test_sweep_bounds_handles_and_warns_once(processes, monkeypatch, caplog):
    times, edges, open_process, opened, _, assigned, kernel32 = processes
    for pid in range(2, 400):
        times[pid] = 101
    edges[1] = set(range(2, 400))
    # No grandchildren needed for this wide-tree limit.
    monkeypatch.setattr(mod, "_WINDOWS_SWEEP_MAX_PROCESSES", 256)
    await mod._protect_windows_descendants(open_process(1))
    assert len(opened) == 256
    assert len(assigned) == 255
    assert caplog.text.count("Windows descendant sweep reached") == 1
    assert_closed(opened, kernel32)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_site", ["enumerate", "assign", "verify"])
async def test_handles_close_on_errors(processes, monkeypatch, failure_site):
    _, _, open_process, opened, _, _, kernel32 = processes
    if failure_site == "assign":
        monkeypatch.setattr(
            mod, "_assign_to_windows_job", MagicMock(side_effect=OSError("assign"))
        )
    else:
        calls = 0

        def broken_enumeration(pid):
            nonlocal calls
            calls += 1
            if failure_site == "enumerate" or calls == 2:
                raise OSError("snapshot")
            return {2}

        monkeypatch.setattr(mod, "_enumerate_child_pids_windows", broken_enumeration)
    await mod._protect_windows_descendants(open_process(1))
    assert_closed(opened, kernel32)


@pytest.mark.asyncio
async def test_handles_close_on_cancellation(processes, monkeypatch):
    _, _, open_process, opened, _, _, kernel32 = processes
    sleeping = asyncio.Event()
    blocked = asyncio.Event()

    async def sleep(_):
        sleeping.set()
        await blocked.wait()

    monkeypatch.setattr(mod.asyncio, "sleep", sleep)
    task = asyncio.create_task(mod._protect_windows_descendants(open_process(1)))
    await sleeping.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert_closed(opened, kernel32)


@pytest.mark.asyncio
async def test_spawn_pins_synchronously_and_closes_if_cancelled_before_start(processes):
    _, _, _, opened, walked, _, kernel32 = processes
    previous = set(mod._windows_sweep_tasks)
    mod._spawn_descendant_sweep(1)
    assert len(opened) == 1  # before yielding to the new task
    assert opened[0].handle is not None
    (task,) = mod._windows_sweep_tasks - previous
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert task not in mod._windows_sweep_tasks
    assert walked == []
    assert_closed(opened, kernel32)


@pytest.mark.asyncio
async def test_spawn_normal_completion_closes_root_exactly_once(processes):
    _, _, _, opened, _, assigned, kernel32 = processes
    previous = set(mod._windows_sweep_tasks)
    mod._spawn_descendant_sweep(1)
    (task,) = mod._windows_sweep_tasks - previous
    await task
    assert task not in mod._windows_sweep_tasks
    assert assigned == [2, 3]
    assert_closed(opened, kernel32)


def test_spawn_scheduling_failure_closes_root(processes, monkeypatch):
    _, _, _, opened, _, _, kernel32 = processes
    monkeypatch.setattr(
        mod.asyncio, "create_task", MagicMock(side_effect=RuntimeError("no loop"))
    )
    with pytest.raises(RuntimeError, match="no loop"):
        mod._spawn_descendant_sweep(1)
    assert_closed(opened, kernel32)


def test_spawn_failed_root_open_starts_nothing(processes, monkeypatch):
    times, _, _, _, _, _, _ = processes
    del times[1]
    create_task = MagicMock()
    monkeypatch.setattr(mod.asyncio, "create_task", create_task)
    mod._spawn_descendant_sweep(1)
    create_task.assert_not_called()


class TestOpenProcess:
    """Exercise real ctypes setup and cleanup with a fake DLL on all platforms."""

    @pytest.fixture
    def kernel32(self, monkeypatch):
        kernel32 = MagicMock()
        kernel32.OpenProcess.return_value = 123456789012

        def get_times(handle, creation, *_):
            creation._obj.dwHighDateTime = 17
            creation._obj.dwLowDateTime = 23
            return True

        kernel32.GetProcessTimes.side_effect = get_times
        monkeypatch.setattr(mod.sys, "platform", "win32")
        monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **k: kernel32, raising=False)
        return kernel32

    def test_minimal_access_full_timestamp_and_signatures(self, kernel32):
        identity = mod._open_windows_process(123)
        assert identity is not None
        assert identity.handle == 123456789012
        assert identity.creation_time == (17 << 32) | 23
        kernel32.OpenProcess.assert_called_once_with(0x101000, False, 123)
        kernel32.CloseHandle.assert_not_called()
        assert kernel32.OpenProcess.argtypes == [
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        assert kernel32.OpenProcess.restype is wintypes.HANDLE
        assert kernel32.GetProcessTimes.argtypes == [
            wintypes.HANDLE,
            *([ctypes.POINTER(wintypes.FILETIME)] * 4),
        ]
        assert kernel32.GetProcessTimes.restype is wintypes.BOOL
        assert kernel32.CloseHandle.argtypes == [wintypes.HANDLE]
        assert kernel32.CloseHandle.restype is wintypes.BOOL
        identity.close()
        identity.close()
        kernel32.CloseHandle.assert_called_once_with(123456789012)

    @pytest.mark.parametrize("failure", ["false", "exception"])
    def test_failed_timing_closes_handle(self, kernel32, failure):
        kernel32.GetProcessTimes.side_effect = (
            OSError("timing") if failure == "exception" else None
        )
        kernel32.GetProcessTimes.return_value = False
        assert mod._open_windows_process(123) is None
        kernel32.CloseHandle.assert_called_once_with(123456789012)

    def test_failed_open_does_not_close_invalid_handle(self, kernel32):
        kernel32.OpenProcess.return_value = None
        assert mod._open_windows_process(123) is None
        kernel32.GetProcessTimes.assert_not_called()
        kernel32.CloseHandle.assert_not_called()
