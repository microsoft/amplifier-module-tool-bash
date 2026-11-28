"""Run real Win32 ctypes declaration/control flow with a fake DLL on every OS.

Windows CI also exercises real jobs and suspended starts. These tests guard
pointer-sized signatures, thread-owner filtering and failure-path handle cleanup
without assigning/resuming any live process. There is no process-table walk.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from unittest.mock import MagicMock, call

import pytest

import amplifier_module_tool_bash as mod


def _assert_signature_declared(kernel32, name):
    fn = getattr(kernel32, name)
    # Do not let MagicMock's synthesized attributes impersonate declarations.
    assert isinstance(vars(fn).get("argtypes"), list), name
    assert "restype" in vars(fn), name
    assert fn.restype is not None, name


@pytest.fixture
def kernel32(monkeypatch):
    dll = MagicMock()
    monkeypatch.setattr(mod.sys, "platform", "win32")
    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **k: dll, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 18, raising=False)
    monkeypatch.setattr(mod, "_windows_job_handle", None)
    return dll


def test_job_object_creation_declares_signatures(kernel32):
    assert mod._get_windows_job_object() is not None
    for name in ("CreateJobObjectW", "SetInformationJobObject", "CloseHandle"):
        _assert_signature_declared(kernel32, name)


def test_assign_to_job_declares_signatures(kernel32):
    assert mod._assign_to_windows_job(4242) is True
    for name in ("OpenProcess", "AssignProcessToJobObject", "CloseHandle"):
        _assert_signature_declared(kernel32, name)


@pytest.fixture
def threads(kernel32):
    # Foreign threads first, including an adjacent PID, to prove exact filtering.
    entries = iter([(90, 400), (91, 4243), (92, 4242)])
    kernel32.CreateToolhelp32Snapshot.return_value = 0x100000010
    kernel32.OpenThread.return_value = 0x100000020
    kernel32.GetProcessIdOfThread.return_value = 4242
    kernel32.ResumeThread.return_value = 1

    def next_entry(snapshot, pointer):
        try:
            tid, owner = next(entries)
        except StopIteration:
            return False
        assert pointer._obj.dwSize == ctypes.sizeof(pointer._obj)
        pointer._obj.th32ThreadID = tid
        pointer._obj.th32OwnerProcessID = owner
        return True

    kernel32.Thread32First.side_effect = next_entry
    kernel32.Thread32Next.side_effect = next_entry
    return kernel32


def test_resume_uses_thread_snapshot_exact_owner_minimal_rights_and_signatures(threads):
    mod._resume_windows_process(4242)
    threads.CreateToolhelp32Snapshot.assert_called_once_with(0x4, 0)
    threads.OpenThread.assert_called_once_with(0x802, False, 92)
    threads.GetProcessIdOfThread.assert_called_once_with(0x100000020)
    threads.ResumeThread.assert_called_once_with(0x100000020)
    assert threads.CloseHandle.call_args_list == [call(0x100000020), call(0x100000010)]
    for name in (
        "CreateToolhelp32Snapshot",
        "Thread32First",
        "Thread32Next",
        "OpenThread",
        "GetProcessIdOfThread",
        "ResumeThread",
        "CloseHandle",
    ):
        _assert_signature_declared(threads, name)
    assert threads.CreateToolhelp32Snapshot.restype is wintypes.HANDLE
    assert threads.OpenThread.restype is wintypes.HANDLE
    assert threads.OpenThread.argtypes == [
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    assert threads.ResumeThread.restype is wintypes.DWORD
    assert threads.ResumeThread.argtypes == [wintypes.HANDLE]
    assert threads.GetProcessIdOfThread.restype is wintypes.DWORD
    assert threads.GetProcessIdOfThread.argtypes == [wintypes.HANDLE]


@pytest.mark.parametrize("invalid", [None, 0, ctypes.c_void_p(-1).value])
def test_invalid_thread_snapshot_not_used_or_closed(kernel32, invalid):
    kernel32.CreateToolhelp32Snapshot.return_value = invalid
    with pytest.raises(
        RuntimeError, match=r"CreateToolhelp32Snapshot.*Windows error code 18"
    ):
        mod._resume_windows_process(4242)
    kernel32.Thread32First.assert_not_called()
    kernel32.OpenThread.assert_not_called()
    kernel32.CloseHandle.assert_not_called()


@pytest.mark.parametrize(
    "failure", ["empty", "no_owner", "open", "owner", "resume", "exception"]
)
def test_resume_failure_closes_only_acquired_handles(threads, failure):
    if failure == "empty":
        threads.Thread32First.side_effect = None
        threads.Thread32First.return_value = False
        cause = "Thread32First"
    elif failure == "no_owner":
        cause = "No thread found"
    elif failure == "open":
        threads.OpenThread.return_value = None
        cause = "OpenThread"
    elif failure == "resume":
        threads.ResumeThread.return_value = 0xFFFFFFFF
        cause = "ResumeThread"
    elif failure == "owner":
        threads.GetProcessIdOfThread.return_value = 0
        cause = "GetProcessIdOfThread"
    else:
        threads.ResumeThread.side_effect = RuntimeError("DLL error")
        cause = "DLL error"
    with pytest.raises(RuntimeError, match=cause):
        mod._resume_windows_process(7777 if failure == "no_owner" else 4242)
    expected = [call(0x100000010)]
    if failure in ("owner", "resume", "exception"):
        expected.insert(0, call(0x100000020))
    assert threads.CloseHandle.call_args_list == expected
    if failure in ("empty", "no_owner"):
        threads.OpenThread.assert_not_called()
        threads.ResumeThread.assert_not_called()
    if failure in ("open", "owner"):
        threads.ResumeThread.assert_not_called()


@pytest.mark.parametrize("count", [0, 1])
def test_resume_accepts_previous_counts_zero_and_one(threads, count):
    threads.ResumeThread.return_value = count
    mod._resume_windows_process(4242)
    threads.ResumeThread.assert_called_once_with(0x100000020)


@pytest.mark.parametrize("count", [2, 3, 127])
def test_resume_rejects_still_suspended_count_without_looping(threads, count):
    threads.ResumeThread.return_value = count
    with pytest.raises(RuntimeError, match=f"thread was suspended {count} times"):
        mod._resume_windows_process(4242)
    threads.ResumeThread.assert_called_once_with(0x100000020)
    assert threads.CloseHandle.call_args_list == [call(0x100000020), call(0x100000010)]


def test_reused_opened_thread_owner_is_not_resumed(threads):
    threads.GetProcessIdOfThread.return_value = 7777
    with pytest.raises(RuntimeError, match="No thread found"):
        mod._resume_windows_process(4242)
    threads.OpenThread.assert_called_once_with(0x802, False, 92)
    threads.ResumeThread.assert_not_called()
    assert threads.CloseHandle.call_args_list == [call(0x100000020), call(0x100000010)]


def test_resumes_all_verified_threads_once_and_skips_reused_id(threads):
    entries = iter([92, 93, 94])

    def next_entry(snapshot, pointer):
        try:
            pointer._obj.th32ThreadID = next(entries)
        except StopIteration:
            return False
        pointer._obj.th32OwnerProcessID = 4242
        return True

    threads.Thread32First.side_effect = next_entry
    threads.Thread32Next.side_effect = next_entry
    threads.OpenThread.side_effect = [1002, 1003, 1004]
    threads.GetProcessIdOfThread.side_effect = [4242, 7777, 4242]
    threads.ResumeThread.side_effect = [1, 0]
    mod._resume_windows_process(4242)
    assert threads.OpenThread.call_args_list == [
        call(0x802, False, tid) for tid in (92, 93, 94)
    ]
    assert threads.GetProcessIdOfThread.call_args_list == [
        call(handle) for handle in (1002, 1003, 1004)
    ]
    assert threads.ResumeThread.call_args_list == [call(1002), call(1004)]
    assert threads.CloseHandle.call_args_list == [
        call(handle) for handle in (1002, 1003, 1004, 0x100000010)
    ]


def test_thread_entry_type_cached_without_loading_windows_dll(monkeypatch):
    monkeypatch.setattr(mod, "_windows_thread_entry_type", None)
    dll = MagicMock(
        side_effect=AssertionError("no DLL should load for type definition")
    )
    monkeypatch.setattr(ctypes, "WinDLL", dll, raising=False)
    first = mod._get_windows_thread_entry_type()
    assert mod._get_windows_thread_entry_type() is first
    assert mod._windows_thread_entry_type is first
    assert issubclass(first, ctypes.Structure)
    dll.assert_not_called()


@pytest.mark.parametrize(
    "failure", ["snapshot", "first", "next", "open", "owner", "resume"]
)
def test_windows_api_failures_include_error_code(threads, monkeypatch, failure):
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
    if failure == "snapshot":
        threads.CreateToolhelp32Snapshot.return_value = None
    elif failure == "first":
        threads.Thread32First.side_effect = None
        threads.Thread32First.return_value = False
    elif failure == "open":
        threads.OpenThread.return_value = None
    elif failure == "owner":
        threads.GetProcessIdOfThread.return_value = 0
    elif failure == "resume":
        threads.ResumeThread.return_value = 0xFFFFFFFF
    with pytest.raises(RuntimeError, match="Windows error code 5"):
        mod._resume_windows_process(4242)
