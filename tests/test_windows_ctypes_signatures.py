"""Regression test: every Win32 ctypes call site declares argtypes/restype.

## Why this test exists

ctypes silently defaults an undeclared `restype`/`argtypes` to C `int`
(32-bit signed). On 64-bit Windows, a HANDLE or pointer-sized value routed
through that default gets truncated -- producing wrong results or memory
corruption rather than a clean error. This is exactly the kind of bug that
looks fine in review and only misbehaves on a real 64-bit Windows box.

None of the existing suites exercise this class of bug on non-Windows CI:

- `test_windows_job_call_sites.py` patches `_assign_to_windows_job` and
  `_spawn_descendant_sweep` as whole functions, so the ctypes calls inside
  them never run.
- `test_gap013_windows_job_object_orphans.py` is `skipif`'d to
  `sys.platform == "win32"`, so it executes nowhere in this repo's CI.

That leaves the signature declarations for `CreateJobObjectW`,
`SetInformationJobObject`, `OpenProcess`, `AssignProcessToJobObject`,
`CreateToolhelp32Snapshot`, `Process32First`, `Process32Next`, and
`CloseHandle` unverified anywhere except a real Windows machine.

`ctypes.WinDLL` does not exist as a real attribute on non-Windows platforms
(hence `create=True` below), but `ctypes.wintypes` is plain, portable
`ctypes.Structure`/`c_*` aliasing that imports and behaves identically on
any platform. That means the three Windows-only functions under test can
run for real here -- only the DLL handle itself is a stand-in -- so this
test drives the genuine signature-declaration code, not a paraphrase of it,
and asserts that every Win32 function actually invoked had both `argtypes`
and `restype` explicitly assigned. It runs on Linux, macOS, and CI, today.
"""

from __future__ import annotations

import ctypes
from unittest.mock import MagicMock, patch

import amplifier_module_tool_bash as mod


def _assert_signature_declared(kernel32_mock: MagicMock, name: str) -> None:
    fn = getattr(kernel32_mock, name)
    assert fn.argtypes is not None, (
        f"kernel32.{name} has no argtypes declared -- ctypes will default "
        "arguments to C int, truncating a 64-bit pointer/HANDLE on 64-bit "
        "Windows"
    )
    assert fn.restype is not None, (
        f"kernel32.{name} has no restype declared -- ctypes defaults the "
        "return value to C int, truncating a 64-bit HANDLE on 64-bit "
        "Windows"
    )


class TestWin32CallSignatures:
    """Drives the real Windows-only functions with a mocked kernel32 DLL
    handle so the signature declarations are exercised on any platform.
    """

    def setup_method(self) -> None:
        # Module-level cache; must not leak between tests or across the
        # rest of the suite.
        self._saved_job_handle = mod._windows_job_handle
        mod._windows_job_handle = None

    def teardown_method(self) -> None:
        mod._windows_job_handle = self._saved_job_handle

    def test_job_object_creation_declares_signatures(self) -> None:
        kernel32 = MagicMock(name="kernel32")
        windll_factory = MagicMock(return_value=kernel32)

        with (
            patch("amplifier_module_tool_bash.sys.platform", "win32"),
            patch.object(ctypes, "WinDLL", windll_factory, create=True),
        ):
            job = mod._get_windows_job_object()

        assert job is not None, (
            "job creation must succeed against a mocked, all-truthy kernel32"
        )
        for name in ("CreateJobObjectW", "SetInformationJobObject", "CloseHandle"):
            _assert_signature_declared(kernel32, name)

    def test_assign_to_job_declares_signatures(self) -> None:
        kernel32 = MagicMock(name="kernel32")
        windll_factory = MagicMock(return_value=kernel32)

        with (
            patch("amplifier_module_tool_bash.sys.platform", "win32"),
            patch.object(ctypes, "WinDLL", windll_factory, create=True),
        ):
            assigned = mod._assign_to_windows_job(4242)

        assert assigned is True, (
            "assignment must succeed against a mocked, all-truthy kernel32"
        )
        for name in ("OpenProcess", "AssignProcessToJobObject", "CloseHandle"):
            _assert_signature_declared(kernel32, name)

    def test_descendant_enumeration_declares_signatures(self) -> None:
        kernel32 = MagicMock(name="kernel32")
        # Falsy on the first call ends the process-table walk immediately
        # (simulates an empty/failed walk) -- a real MagicMock is truthy
        # forever, which would otherwise spin the `while True` loop in
        # `_enumerate_child_pids_windows` forever via `Process32Next`.
        kernel32.Process32First.return_value = False
        windll_factory = MagicMock(return_value=kernel32)

        with (
            patch("amplifier_module_tool_bash.sys.platform", "win32"),
            patch.object(ctypes, "WinDLL", windll_factory, create=True),
        ):
            children = mod._enumerate_child_pids_windows(1234)

        assert children == set()
        # All four signatures are declared unconditionally before the walk
        # begins, so this holds even though Process32Next is never reached.
        for name in (
            "CreateToolhelp32Snapshot",
            "Process32First",
            "Process32Next",
            "CloseHandle",
        ):
            _assert_signature_declared(kernel32, name)

    def test_snapshot_invalid_handle_value_is_treated_as_failure(self) -> None:
        """CreateToolhelp32Snapshot signals failure via INVALID_HANDLE_VALUE,
        i.e. `(HANDLE)-1` -- NOT NULL. With a HANDLE (c_void_p) restype,
        ctypes converts that bit pattern to a large *positive* Python int
        (18446744073709551615 on 64-bit) -- never to the Python literal -1
        or to 0. A guard written as ``if snap in (-1, 0)`` therefore never
        matches this real failure value and falls through to call
        Process32First/CloseHandle on an invalid handle.

        This test must fail against that old guard: with it restored, the
        invalid-handle value is not caught, so both Process32First and
        CloseHandle get called on the invalid handle below (Process32First
        is stubbed to return False purely so the walk terminates instead of
        spinning forever on an always-truthy MagicMock Process32Next --
        it does NOT make the old guard correct).
        """
        kernel32 = MagicMock(name="kernel32")
        kernel32.CreateToolhelp32Snapshot.return_value = ctypes.c_void_p(-1).value
        kernel32.Process32First.return_value = False
        windll_factory = MagicMock(return_value=kernel32)

        with (
            patch("amplifier_module_tool_bash.sys.platform", "win32"),
            patch.object(ctypes, "WinDLL", windll_factory, create=True),
        ):
            children = mod._enumerate_child_pids_windows(1234)

        assert children == set()
        kernel32.Process32First.assert_not_called()
        kernel32.CloseHandle.assert_not_called()
