"""Native Windows evidence using only finite, test-created Python processes.

No real PID reuse is forced. The stale-edge case supplies an older throwaway
candidate to a younger live parent's verifier. Assignment is recorded, not
performed: these tests isolate native identity/snapshot behavior; GAP-013 tests
separately exercise actual Job Objects.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path
import subprocess
import sys
import time

import pytest

import amplifier_module_tool_bash as mod

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="native Windows API")

_TREE_SCRIPT = """
import os
from pathlib import Path
import subprocess
import sys
import time

directory = Path(sys.argv[1])
mode = sys.argv[2]
(directory / (mode + '.pid')).write_text(str(os.getpid()), encoding='utf-8')
if mode in ('orphan_parent', 'tree_parent', 'tree_child'):
    child_mode = {
        'orphan_parent': 'orphan_child',
        'tree_parent': 'tree_child',
        'tree_child': 'tree_grandchild',
    }[mode]
    subprocess.Popen([sys.executable, __file__, str(directory), child_mode])
if mode != 'orphan_parent':
    deadline = time.monotonic() + 60
    while not (directory / 'stop').exists() and time.monotonic() < deadline:
        time.sleep(0.05)
"""


def _wait_for_pid(directory: Path, mode: str) -> int:
    deadline = time.monotonic() + 20
    path = directory / (mode + ".pid")
    while time.monotonic() < deadline:
        if path.exists() and path.read_text(encoding="utf-8").strip():
            return int(path.read_text(encoding="utf-8"))
        time.sleep(0.05)
    raise AssertionError(f"test-created {mode} never became ready")


def _wait_for_exit(identity) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    assert kernel32.WaitForSingleObject(identity.handle, 30000) == 0


@pytest.fixture
def tree(tmp_path):
    script = tmp_path / "tree.py"
    script.write_text(_TREE_SCRIPT, encoding="utf-8")
    started = []
    pinned = []

    def start(mode):
        # Bypass the Windows venv redirector so Popen.pid is the actual Python
        # parent, not a short-lived launcher with a second interpreter below it.
        process = subprocess.Popen(
            [sys._base_executable, str(script), str(tmp_path), mode]
        )
        started.append(process)
        return process

    def pin(mode):
        identity = mod._open_windows_process(_wait_for_pid(tmp_path, mode))
        assert identity is not None
        pinned.append(identity)
        return identity

    try:
        yield tmp_path, start, pin
    finally:
        # Cooperative shutdown, never taskkill on a bare/reusable PID. The
        # finite 60s deadline is a second backstop even if this fixture aborts.
        (tmp_path / "stop").write_text("stop", encoding="utf-8")
        try:
            for process in started:
                process.wait(timeout=30)
            for identity in pinned:
                if identity.handle is not None:
                    _wait_for_exit(identity)
        finally:
            for identity in pinned:
                identity.close()


def test_snapshot_keeps_recorded_parent_id_after_parent_exit(tree):
    _, start, pin = tree
    parent = start("orphan_parent")
    child = pin("orphan_child")
    assert parent.wait(timeout=30) == 0
    assert child.pid in mod._enumerate_child_pids_windows(parent.pid)


def test_live_younger_parent_rejects_older_candidate(tree, monkeypatch):
    _, start, pin = tree
    start("older")
    older = pin("older")
    # FILETIME resolution can be coarse; ensure a distinct later creation time.
    time.sleep(0.1)
    start("younger")
    younger = pin("younger")
    assert older.creation_time < younger.creation_time
    assigned = []
    monkeypatch.setattr(mod, "_assign_to_windows_job", assigned.append)
    # Supply the stale recorded edge without trying to force OS PID reuse.
    monkeypatch.setattr(mod, "_enumerate_child_pids_windows", lambda _: {older.pid})
    assert mod._verified_windows_child(younger, older.pid) is None
    assert assigned == []
    assert younger.handle is not None
    assert older.handle is not None


@pytest.mark.asyncio
async def test_native_real_tree_fully_accepted(tree, monkeypatch):
    _, start, pin = tree
    parent_proc = start("tree_parent")
    # Separate fixture-owned handles let cleanup wait after the sweep closes its
    # own handles. All these processes were started by this test's script.
    parent = pin("tree_parent")
    child = pin("tree_child")
    grandchild = pin("tree_grandchild")
    assert parent.pid == parent_proc.pid
    assigned = []
    monkeypatch.setattr(mod, "_assign_to_windows_job", assigned.append)
    root = mod._open_windows_process(parent.pid)
    assert root is not None
    await mod._protect_windows_descendants(root)
    assert set(assigned) == {child.pid, grandchild.pid}
    assert root.handle is None
