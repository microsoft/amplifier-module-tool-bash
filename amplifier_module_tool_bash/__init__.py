"""
Bash command execution tool for Amplifier.
Includes safety features and approval mechanisms.
"""

# Amplifier module metadata
__amplifier_module_type__ = "tool"

import asyncio
import logging
import os
import shutil
import signal
import subprocess
import sys
import threading
from typing import Any

from amplifier_core import ModuleCoordinator
from amplifier_core import ToolResult

from .safety import SafetyConfig, SafetyValidator

logger = logging.getLogger(__name__)

TIMEOUT_MIN_SECONDS = 1
TIMEOUT_MAX_SECONDS = 3600


def _validate_timeout_seconds(value: Any, *, source: str) -> int:
    """Validate a timeout value (seconds) from either config or caller input.

    Requirements:
      - must be an int (bool rejected)
      - 1 <= value <= 3600

    Raises:
        TypeError: If the value is not an integer (including bool).
        ValueError: If the integer is outside the supported range.
    """

    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(
            f"Invalid {source} timeout: timeout must be an integer number of seconds "
            f"between {TIMEOUT_MIN_SECONDS} and {TIMEOUT_MAX_SECONDS} (got {value!r})."
        )
    if value < TIMEOUT_MIN_SECONDS:
        raise ValueError(
            f"Invalid {source} timeout: timeout must be an integer number of seconds "
            f"between {TIMEOUT_MIN_SECONDS} and {TIMEOUT_MAX_SECONDS} (got {value!r})."
        )
    if value > TIMEOUT_MAX_SECONDS:
        suggestion = ""
        if value % 1000 == 0:
            as_seconds = value // 1000
            if TIMEOUT_MIN_SECONDS <= as_seconds <= TIMEOUT_MAX_SECONDS:
                suggestion = f" It looks like you passed milliseconds; did you mean {as_seconds} seconds?"
        raise ValueError(
            f"Invalid {source} timeout: timeout is specified in seconds and must be <= "
            f"{TIMEOUT_MAX_SECONDS} (got {value!r}).{suggestion}"
        )
    return value


def _read_ppid(pid: int) -> int | None:
    """Read a process's parent PID from /proc/<pid>/stat (Linux only).

    Returns None if the process doesn't exist or can't be read.
    """
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as f:
            content = f.read()
    except OSError:
        return None

    # Format: "<pid> (<comm>) <state> <ppid> ...". comm can contain spaces
    # or parentheses, so find the LAST ')' to safely skip past it before
    # splitting the remaining whitespace-separated fields.
    close_paren = content.rfind(")")
    if close_paren == -1:
        return None
    fields = content[close_paren + 1 :].split()
    if len(fields) < 2:
        return None
    try:
        return int(fields[1])
    except ValueError:
        return None


def _descendants_from_pid_ppid_pairs(
    root_pid: int, pairs: list[tuple[int, int]]
) -> set[int]:
    """Walk a flat list of (pid, ppid) pairs to find all descendants of root_pid."""
    children_by_ppid: dict[int, list[int]] = {}
    for pid, ppid in pairs:
        children_by_ppid.setdefault(ppid, []).append(pid)

    descendants: set[int] = set()
    frontier = [root_pid]
    while frontier:
        current = frontier.pop()
        for child in children_by_ppid.get(current, []):
            if child not in descendants:
                descendants.add(child)
                frontier.append(child)
    return descendants


def _find_descendant_pids_via_ps(root_pid: int) -> set[int]:
    """Fallback descendant walk using `ps` for POSIX systems without /proc
    (e.g. macOS, which has no /proc filesystem).

    `ps -A -o pid=,ppid=` is portable across GNU (Linux) and BSD (macOS) ps
    implementations: `-A` selects every process, and the trailing `=` after
    each column name suppresses the header on both. Returns an empty set on
    any failure (missing `ps`, unexpected output, etc.) -- this is a
    best-effort fallback, not a hard requirement.
    """
    try:
        result = subprocess.run(
            ["ps", "-A", "-o", "pid=,ppid="],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return set()

    pairs: list[tuple[int, int]] = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        try:
            pairs.append((int(fields[0]), int(fields[1])))
        except ValueError:
            continue

    return _descendants_from_pid_ppid_pairs(root_pid, pairs)


def _find_descendant_pids(root_pid: int) -> set[int]:
    """Recursively find all descendant PIDs of root_pid.

    Unlike process-group membership, the PPID chain survives setsid() --
    a process that detaches into its own session/process group (directly,
    or via a wrapper like tmux/incus/docker that manages its own session
    lifecycle) keeps its original parent. Walking the process table lets us
    find and kill descendants that escaped the process group and that
    os.killpg() can no longer reach.

    Prefers /proc (Linux) for speed and reliability; falls back to `ps`
    (e.g. macOS, which has no /proc) when /proc is unavailable. Returns an
    empty set if neither source is usable.
    """
    try:
        all_pids = [int(name) for name in os.listdir("/proc") if name.isdigit()]
    except OSError:
        return _find_descendant_pids_via_ps(root_pid)

    pairs: list[tuple[int, int]] = []
    for pid in all_pids:
        ppid = _read_ppid(pid)
        if ppid is not None:
            pairs.append((pid, ppid))

    return _descendants_from_pid_ppid_pairs(root_pid, pairs)


def _signal_pids(pids: set[int], sig: int) -> None:
    """Best-effort send `sig` to every pid in `pids`, ignoring already-dead ones."""
    for pid in pids:
        try:
            os.kill(pid, sig)
        except (ProcessLookupError, PermissionError):
            pass


# --- Windows orphan prevention (GAP-024) ---------------------------------
#
# On POSIX, `_run_command`'s existing timeout-cleanup path (`os.killpg` +
# `_find_descendant_pids`) only covers the case where THIS module's own code
# is still running to execute that cleanup -- e.g. the tool-level timeout
# firing, or a normal asyncio.CancelledError propagating through a still-
# alive event loop. It does NOT cover the host `amplifier.exe` process being
# killed outright (crash, `Stop-Process`/`taskkill /F` on just the top PID,
# a supervisor terminating only the parent) -- Windows has no equivalent of
# POSIX's parent-death signal (`prctl(PR_SET_PDEATHSIG)`), so a subprocess
# spawned here has no way to notice its parent is gone and no code of ours
# runs to clean it up.
#
# Confirmed empirically (adversarial Windows re-test, alienware-r13):
# spawning `sleep 60` via this module's WSL-routed path
# (`wsl --exec bash -c ...`), then killing ONLY the top-level `amplifier.exe`
# PID (no /T, no console Ctrl+C -- a plain `Stop-Process -Id <pid>`), left
# the resulting `wsl.exe -> wsl.exe -> wslhost.exe` chain running with a
# dead parent for the entire 60+ second observation window. This directly
# contradicts the prior claim that killing only the top-level PID always
# brings the whole tree down within ~2s -- that was true for amplifier's own
# internal python-to-python self-relaunch (which IS covered by an existing
# job-object association), but not for tool-call subprocesses spawned from
# deep inside a running turn, which were never assigned to that job.
#
# Fix: create one Windows Job Object per process, with
# JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE set, and assign every subprocess this
# module spawns (on the foreground/tracked path only -- NOT
# `_run_command_background`, whose whole point is to outlive us) to that
# job. The job's only handle lives in this process; when this process ends
# for ANY reason -- including a forceful kill that runs none of our own
# Python cleanup code -- the OS closes that handle and the kernel itself
# tears down every process still assigned to the job. This does not depend
# on any application code running, so it also covers crashes.
_windows_job_handle = None
# Created at import, not lazily. A `if _lock is None: _lock = Lock()` guard is
# itself unsynchronised -- two OS threads can both see None and build two locks,
# defeating the mutual exclusion it exists to provide. Nothing in this module
# currently calls off the event-loop thread, so this was latent, but a
# module-level construction costs nothing and removes the trap.
_windows_job_lock = threading.Lock()

# Background descendant-sweep tasks, held so the event loop cannot garbage
# collect them mid-flight. asyncio.create_task returns a task that is only
# weakly referenced by the loop; the docs are explicit that an unreferenced task
# "may get garbage collected at any time, even before it's done". These sweeps
# are the entire GAP-013/GAP-028 protection for WSL descendants, and if one
# vanished the symptom would be indistinguishable from a silent assignment
# failure.
_windows_sweep_tasks: set = set()

# One-shot flag so a job-object failure is reported loudly ONCE per process
# rather than either spamming every command or (as before) being invisible.
_windows_job_failure_reported = False


def _report_windows_job_failure(message: str, *args) -> None:
    """Report a job-object failure ONCE per process, at warning level.

    These failures used to be logged at debug only and their return values
    discarded by every caller, so the entire orphan-protection mechanism could
    be inert with no operator-visible signal at all.

    That matters most in exactly the environments this protection is for.
    ``AssignProcessToJobObject`` fails when the process is already inside a job
    that disallows the assignment -- the normal state under CI runners (GitHub
    Actions wraps every step in a job object), Windows containers, and some
    endpoint-security agents. In those environments this ships, every command
    still "succeeds", and nothing anywhere indicates the protection never
    engaged. A later orphan report would then be wrongly dismissed as
    already-fixed.

    Warning rather than error because the tool call itself is unaffected --
    this is defense-in-depth, not a correctness requirement. Once per process
    rather than per command because the cause is environmental and constant;
    repeating it every command would be noise that trains people to ignore it.
    """
    global _windows_job_failure_reported
    if _windows_job_failure_reported:
        logger.debug("tool-bash: " + message, *args)
        return
    _windows_job_failure_reported = True
    logger.warning(
        "tool-bash: Windows orphan protection is NOT active for this process. "
        + message
        + ". Subprocesses spawned by this tool may survive an abrupt exit. "
        "This is expected inside a restrictive parent job object (CI runners, "
        "Windows containers); it is reported once per process.",
        *args,
    )


def _get_windows_job_object():
    """Lazily create (once per process) a Job Object with kill-on-close set.

    Returns the job handle (an int, per ctypes' ``wintypes.HANDLE``) or
    ``None`` if creation failed for any reason -- callers must treat that as
    "no extra protection available" and continue without raising, since
    this is a defense-in-depth addition, not a required dependency for the
    tool to function.
    """
    global _windows_job_handle, _windows_job_lock
    if sys.platform != "win32":
        return None
    if _windows_job_lock is None:
        import threading

        _windows_job_lock = threading.Lock()
    with _windows_job_lock:
        if _windows_job_handle is not None:
            return _windows_job_handle
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

            # Declare signatures rather than letting ctypes default an
            # undeclared return to c_int (32-bit signed), which truncates a
            # 64-bit HANDLE. Win32 guarantees handle values are 32-bit
            # significant, so the untyped form happens to work -- but relying on
            # an unstated guarantee is how a silent, platform-specific
            # corruption bug gets in.
            kernel32.CreateJobObjectW.restype = wintypes.HANDLE
            kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
            kernel32.SetInformationJobObject.restype = wintypes.BOOL
            kernel32.SetInformationJobObject.argtypes = [
                wintypes.HANDLE,
                ctypes.c_int,
                wintypes.LPVOID,
                wintypes.DWORD,
            ]
            kernel32.CloseHandle.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

            job = kernel32.CreateJobObjectW(None, None)
            if not job:
                _report_windows_job_failure(
                    "CreateJobObjectW failed (%s)",
                    ctypes.WinError(ctypes.get_last_error()),
                )
                return None

            # JOBOBJECT_BASIC_LIMIT_INFORMATION + JOBOBJECT_EXTENDED_LIMIT_INFORMATION
            # layout (winnt.h). We only need to set LimitFlags on the basic
            # struct embedded at the start of the extended one.
            JobObjectExtendedLimitInformation = 9
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

            class IO_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("ReadOperationCount", ctypes.c_uint64),
                    ("WriteOperationCount", ctypes.c_uint64),
                    ("OtherOperationCount", ctypes.c_uint64),
                    ("ReadTransferCount", ctypes.c_uint64),
                    ("WriteTransferCount", ctypes.c_uint64),
                    ("OtherTransferCount", ctypes.c_uint64),
                ]

            class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_int64),
                    ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

            ok = kernel32.SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
            if not ok:
                _report_windows_job_failure(
                    "SetInformationJobObject failed (%s)",
                    ctypes.WinError(ctypes.get_last_error()),
                )
                kernel32.CloseHandle(job)
                return None

            _windows_job_handle = job
            return job
        except Exception as e:  # pragma: no cover - defense in depth only
            logger.debug(
                "tool-bash: Windows job-object setup failed (%s); "
                "proceeding without orphan protection",
                e,
            )
            return None


def _assign_to_windows_job(pid: int) -> bool:
    """Best-effort: assign `pid` to this process's kill-on-close job object.

    Returns whether assignment actually succeeded. Most callers only need
    "did I do my best" semantics and can ignore the return value; the
    descendant-walker below (GAP-013/GAP-028) uses it to log clearly.

    Failure is intentionally swallowed as far as the CALLER's control flow
    goes (logged at debug only) -- this is defense-in-depth cleanup, not a
    correctness requirement for the command itself to run. A process that
    can't be assigned (e.g. already exited, or running with different
    privileges) just doesn't get the extra protection; it does not fail
    the tool call.
    """
    if sys.platform != "win32":
        return False
    job = _get_windows_job_object()
    if job is None:
        return False
    try:
        import ctypes

        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = [
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
        ]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        PROCESS_ALL_ACCESS = 0x1F0FFF
        hproc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not hproc:
            # Debug, not warning: the overwhelmingly common cause is that the
            # process already exited between spawn and assignment, which is
            # benign and expected for fast commands. Distinct from the
            # environmental failures reported once at warning level.
            logger.debug(
                "tool-bash: OpenProcess(%s) failed (%s); pid not job-protected "
                "(usually means it already exited)",
                pid,
                ctypes.WinError(ctypes.get_last_error()),
            )
            return False
        try:
            if not kernel32.AssignProcessToJobObject(job, hproc):
                # This one IS environmental: the dominant cause is that this
                # process already sits inside a job object that disallows the
                # assignment -- the normal state under CI runners, Windows
                # containers, and some endpoint-security agents. Report it
                # loudly once, because in that case the protection is inert for
                # every command and nothing else would ever say so.
                _report_windows_job_failure(
                    "AssignProcessToJobObject(pid=%s) failed (%s)",
                    pid,
                    ctypes.WinError(ctypes.get_last_error()),
                )
                return False
            return True
        finally:
            kernel32.CloseHandle(hproc)
    except Exception as e:  # pragma: no cover - defense in depth only
        logger.debug("tool-bash: failed to job-protect pid %s (%s)", pid, e)
        return False


def _enumerate_child_pids_windows(parent_pid: int) -> set[int]:
    """Direct children of `parent_pid` via CreateToolhelp32Snapshot -- a
    plain Win32 API walk of the system-wide process snapshot, filtered by
    th32ParentProcessID. No WMI/CIM, no PowerShell subprocess.

    Windows-only. Returns an empty set on any failure or on other platforms.
    """
    if sys.platform != "win32":
        return set()
    try:
        import ctypes
        from ctypes import wintypes

        TH32CS_SNAPPROCESS = 0x00000002
        # CreateToolhelp32Snapshot signals failure by returning
        # INVALID_HANDLE_VALUE, i.e. (HANDLE)-1 -- NOT NULL. With restype
        # HANDLE (c_void_p), ctypes converts NULL to None and any other
        # pointer value, including the -1 bit pattern, to a positive Python
        # int (18446744073709551615 on 64-bit). Compare against the real
        # sentinel, not the signed literal -1.
        _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_char * 260),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        # Same reasoning as the job-object signatures above: CreateToolhelp32Snapshot
        # returns a HANDLE, and leaving restype undeclared truncates it to a 32-bit
        # c_int on 64-bit Windows. Declare all four signatures explicitly.
        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel32.Process32First.restype = wintypes.BOOL
        kernel32.Process32First.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(PROCESSENTRY32),
        ]
        kernel32.Process32Next.restype = wintypes.BOOL
        kernel32.Process32Next.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(PROCESSENTRY32),
        ]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap is None or snap == _INVALID_HANDLE_VALUE:
            return set()
        try:
            entry = PROCESSENTRY32()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
            children: set[int] = set()
            if not kernel32.Process32First(snap, ctypes.byref(entry)):
                return set()
            while True:
                if entry.th32ParentProcessID == parent_pid:
                    children.add(entry.th32ProcessID)
                if not kernel32.Process32Next(snap, ctypes.byref(entry)):
                    break
            return children
        finally:
            kernel32.CloseHandle(snap)
    except Exception as e:  # pragma: no cover - defense in depth only
        logger.debug(
            "tool-bash: descendant enumeration failed for %s (%s)", parent_pid, e
        )
        return set()


def _spawn_descendant_sweep(root_pid: int) -> None:
    """Start the descendant sweep and KEEP A REFERENCE to the task.

    ``asyncio.create_task`` returns a task the loop holds only weakly. The
    stdlib docs are explicit: "Save a reference to the result of this
    function... A task that isn't referenced elsewhere may get garbage
    collected at any time, even before it's done."

    These sweeps are the whole GAP-013/GAP-028 protection for WSL descendants
    (inner ``wsl.exe``, ``wslhost.exe``), which do NOT inherit job membership
    from the immediate spawned PID. If one were collected mid-flight, the
    symptom would be orphaned processes with nothing in the logs -- outwardly
    identical to a silent job-assignment failure, and correspondingly awful to
    diagnose.

    In practice the task is always parked on ``asyncio.sleep``, so the loop's
    timer structures probably keep it reachable. "Probably" is not a property
    worth betting a process-cleanup guarantee on, and a set costs nothing.
    """
    task = asyncio.create_task(_protect_windows_descendants(root_pid))
    _windows_sweep_tasks.add(task)
    task.add_done_callback(_windows_sweep_tasks.discard)


async def _protect_windows_descendants(root_pid: int) -> None:
    """Best-effort background task (GAP-013/GAP-028): assign every
    descendant of `root_pid` to the same kill-on-close job object, not
    just the immediate spawned PID.

    Why this exists: `_assign_to_windows_job(process.pid)` alone was found
    NOT to actually protect a WSL-routed command's real descendants.
    Verified directly against the deployed code with the Win32
    `IsProcessInJob` query (native Windows, alienware-r13): after spawning
    `wsl --exec bash -c <cmd>` and calling `_assign_to_windows_job()` on
    the immediate PID, that top-level PID *was* a job member -- but the
    inner `wsl.exe` and `wslhost.exe` processes underneath it (the ones
    that do the actual work, and the ones this module's own comments
    elsewhere claim are covered) were NOT. Windows only auto-propagates
    job membership to children spawned directly by a job-member process
    via CreateProcess; WSL's inner process tree is connected to the outer
    `wsl.exe` via an RPC/session channel rather than a plain parent-child
    CreateProcess relationship, so it never inherits membership that way.

    An external kill of the top-level process was still observed (same
    investigation) to bring the whole WSL tree down in practice -- but via
    WSL's own connection-teardown behavior when its client disconnects,
    not via the job object. That is a real, currently-working mechanism,
    but it is undocumented, owned by WSL rather than by us, and not
    something this module actually controls or could adjust if it ever
    changed. This function makes the protection deliberate instead of
    coincidental: it walks the process tree (root_pid's children, and
    their children) with a few short retries -- the WSL tree takes a
    moment to fully spawn -- and assigns every PID it finds to the job
    too, so the kill-on-close guarantee no longer depends on an external,
    unverified assumption about WSL's behavior.

    Fire-and-forget: runs concurrently with the command's own
    process.communicate(), never blocks or delays the tool call, and
    never raises (every failure path is caught and logged at debug only,
    same contract as _assign_to_windows_job itself).
    """
    if sys.platform != "win32":
        return
    try:
        seen: set[int] = {root_pid}
        for _ in range(8):  # poll for up to ~2s while the tree spawns
            frontier = list(seen)
            new_found = False
            for pid in frontier:
                for child in _enumerate_child_pids_windows(pid):
                    if child not in seen:
                        seen.add(child)
                        _assign_to_windows_job(child)
                        new_found = True
            if not new_found and len(seen) > 1:
                break  # tree grew at least once, then stopped changing
            await asyncio.sleep(0.25)
    except Exception as e:  # pragma: no cover - defense in depth only
        logger.debug(
            "tool-bash: descendant job-protection sweep failed for %s (%s)",
            root_pid,
            e,
        )


# --- Windows shell resolution: Git Bash discoverability + observability --
#
# Root cause (confirmed on a real Windows 11 box, Git for Windows 2.55.0.3
# installed a month prior): Git for Windows' *default* install puts
# `Git\cmd` on PATH (git.exe lives there) but NOT `Git\bin` (bash.exe lives
# there). Meanwhile `C:\Windows\System32\bash.exe` -- the WSL launcher
# stub -- is effectively always on PATH. The result: `shutil.which("bash")`
# resolves the WSL launcher every time, and Git Bash is unreachable no
# matter what's installed -- even though a `bash` call against a WSL box
# reaches a different filesystem, HOME, and toolchain (e.g. the WSL Linux
# Python, not the Windows Python the user actually has installed) than a
# `bash` call against Git Bash.
#
# Fix: (1) probe the well-known Git-for-Windows install locations directly
# on the filesystem, independent of PATH, so Git Bash becomes genuinely
# discoverable; (2) make the choice between WSL and Git Bash explicit and
# overridable via `windows_shell` config / the AMPLIFIER_BASH_WINDOWS_SHELL
# env var, defaulting to "auto" -- which preserves today's real-world
# default behavior exactly (PATH-first resolution, so WSL wins when both
# are present, unchanged for existing users) and only engages the new
# filesystem probing as a fallback when PATH resolves nothing at all
# (previously a hard "bash not found" error even with Git Bash installed).

_WINDOWS_SHELL_PREFERENCE_ENV_VAR = "AMPLIFIER_BASH_WINDOWS_SHELL"
_VALID_WINDOWS_SHELL_PREFERENCES = ("auto", "wsl", "gitbash")

# Actionable "no bash found on Windows" message, shared verbatim by both the
# foreground (`_run_command`) and background (`_run_command_background`)
# no-bash branches -- see each call site for why there is no degraded
# fallback (e.g. cmd.exe, or exec-with-no-shell-at-all) for "simple"
# commands.
_WINDOWS_NO_BASH_ERROR = (
    "Bash not found in PATH.\n"
    "\n"
    "This tool requires bash for POSIX shell semantics "
    "(quoting, tilde expansion, pipes, redirects, "
    "command substitution). Without it, even simple "
    "commands cannot be run with correct, predictable "
    "behavior.\n"
    "\n"
    "Install Git for Windows (includes Git Bash):\n"
    "  https://git-scm.com/download/win\n"
    "\n"
    "Or install WSL:\n"
    "  https://learn.microsoft.com/en-us/windows/wsl/install"
)


def _find_git_bash_executable() -> str | None:
    """Probe well-known Git-for-Windows install locations for bash.exe,
    independent of PATH (see module-level note above for why PATH alone
    can never find it on a box where WSL is also installed).

    Returns the first that exists on disk, or None.
    """
    candidates: list[str] = []
    local_app_data = os.environ.get("LOCALAPPDATA")
    for env_var in ("ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(env_var)
        if base:
            candidates.append(os.path.join(base, "Git", "bin", "bash.exe"))
    if local_app_data:
        candidates.append(
            os.path.join(local_app_data, "Programs", "Git", "bin", "bash.exe")
        )
    # bash.exe under Git\bin is normally a copy of the one under
    # Git\usr\bin; some installs (or a damaged/partial one) may only have
    # the latter, so check it too before giving up.
    for env_var in ("ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(env_var)
        if base:
            candidates.append(os.path.join(base, "Git", "usr", "bin", "bash.exe"))
    if local_app_data:
        candidates.append(
            os.path.join(local_app_data, "Programs", "Git", "usr", "bin", "bash.exe")
        )

    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return None


def _find_wsl_bash_executable() -> str | None:
    """Probe the well-known WSL launcher location directly, independent of
    PATH. In practice PATH always resolves this one (System32 is on every
    Windows PATH by construction) -- this exists mainly for symmetry with
    `_find_git_bash_executable` and to serve explicit `windows_shell="wsl"`
    requests robustly even in an unusual PATH configuration.
    """
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    candidate = os.path.join(system_root, "System32", "bash.exe")
    return candidate if os.path.isfile(candidate) else None


def _looks_like_wsl_launcher_path(path: str | None) -> bool:
    """Cheap, SYNCHRONOUS classification used only to build the tool
    description / startup log line at construction time (see
    `BashTool._windows_shell_startup_note`) -- NOT used to decide how a
    command actually executes. That decision always goes through
    `BashTool._is_wsl_bash`'s authoritative `test -d /mnt/wsl` subprocess
    check. On a real Windows install, the WSL launcher only ever lives at
    `%SystemRoot%\\System32\\bash.exe`, so a path-string check is a safe,
    deterministic stand-in for the one place we can't afford to spawn a
    process (a synchronous constructor).
    """
    return path is not None and "system32" in path.lower()


def _arbitrate_windows_shell(
    preference: str,
    path_bash: str | None,
    path_bash_is_wsl: bool,
    git_bash_candidate: str | None,
    wsl_bash_candidate: str | None,
) -> tuple[str | None, bool]:
    """Pure decision: given what PATH resolves and what's discoverable via
    the well-known install-location probes, decide which bash executable
    wins and whether it's WSL bash.

    Shared by the authoritative async resolution
    (`BashTool._resolve_windows_bash`, using a real subprocess check for
    `path_bash_is_wsl`) and the synchronous, approximate one used for the
    startup log/description (using the path heuristic above) -- so the
    *decision* logic lives in exactly one place, even though *how
    WSL-ness is determined* legitimately differs between the two callers.

    "auto" (default) preserves today's real-world behavior exactly: if
    PATH resolves anything, it wins outright, full stop -- unchanged for
    every existing user. Only when PATH resolves NOTHING does auto fall
    back to the install-location probes (a strict improvement: previously
    a hard error even with Git Bash installed). Explicit "wsl"/"gitbash"
    preferences consider both PATH and the probes, so a user can force
    Git Bash even where PATH resolves WSL's launcher first (the reported
    bug) -- or force WSL even where PATH would resolve Git Bash first.
    """
    if preference == "auto" and path_bash:
        return path_bash, path_bash_is_wsl

    gitbash_exe = (
        path_bash if (path_bash and not path_bash_is_wsl) else git_bash_candidate
    )
    wsl_exe = path_bash if (path_bash and path_bash_is_wsl) else wsl_bash_candidate

    if preference == "gitbash" and gitbash_exe:
        return gitbash_exe, False
    if preference == "wsl" and wsl_exe:
        return wsl_exe, True

    if preference != "auto":
        logger.warning(
            "tool-bash: windows_shell=%r requested but not available on "
            "this machine; falling back to auto-detection",
            preference,
        )

    if wsl_exe:
        return wsl_exe, True
    if gitbash_exe:
        return gitbash_exe, False
    return None, False
async def _cleanup_process_tree(
    process: asyncio.subprocess.Process, *, pgid: int | None, is_windows: bool
) -> None:
    """Best-effort termination of a subprocess and its descendants.

    Mirrors the tool's timeout cleanup behavior:
      - kill the process group (Unix) when available
      - on Linux, also signal setsid()-detached descendants discovered via /proc
      - wait briefly, then SIGKILL
      - reap via communicate()
    """

    if pgid is not None and not is_windows:
        # Walk /proc for descendants BEFORE killing anything.
        descendant_pids = _find_descendant_pids(process.pid)
        try:
            # Send SIGTERM to process group first (graceful shutdown)
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass  # Process group already gone
        except PermissionError:
            # Fall back to killing just the main process
            process.kill()

        # Belt and suspenders: also signal any descendants that escaped the
        # process group and wouldn't receive the killpg() above.
        _signal_pids(descendant_pids, signal.SIGTERM)

        # Give processes a moment to clean up
        await asyncio.sleep(0.5)

        # Force kill if still running
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass  # Already terminated
        except PermissionError:
            pass
        _signal_pids(descendant_pids, signal.SIGKILL)
    else:
        # Windows or no pgid: kill just the main process
        process.kill()

    # Reap / close pipes (best-effort)
    try:
        await asyncio.wait_for(process.communicate(), timeout=5)
    except TimeoutError:
        pass  # Best effort cleanup


async def _await_process_tree_cleanup(
    process: asyncio.subprocess.Process, *, pgid: int | None, is_windows: bool
) -> None:
    """Run process-tree cleanup to completion despite repeated cancellation.

    If cancellation arrives while cleanup is running, defer propagation until
    the bounded cleanup task finishes, then raise CancelledError.
    """

    cleanup_task = asyncio.create_task(
        _cleanup_process_tree(process, pgid=pgid, is_windows=is_windows)
    )
    cancellation_received = False

    while not cleanup_task.done():
        try:
            await asyncio.shield(cleanup_task)
        except asyncio.CancelledError:
            cancellation_received = True
            continue
        except Exception as cleanup_error:  # noqa: BLE001
            logger.error("Process cleanup failed: %s", cleanup_error)
            break

    if cancellation_received:
        raise asyncio.CancelledError()


async def mount(coordinator: ModuleCoordinator, config: dict[str, Any] | None = None):
    """
    Mount the bash tool.

    Args:
        coordinator: Module coordinator
        config: Tool configuration
            - working_dir: Working directory for command execution (default: ".")
              If not set, falls back to session.working_dir capability.
            - timeout: Command timeout in seconds (default: 30)
            - require_approval: Require approval for commands (default: True)
            - safety_profile: Safety profile to use (default: "strict")
              Options: "strict", "standard", "permissive", "unrestricted"
            - allowed_commands: Whitelist of allowed commands (default: [])
            - denied_commands: Additional custom blocklist patterns (default: [])
            - safety_overrides: Fine-grained safety overrides dict with 'allow' and 'block' lists
            - windows_shell: Windows-only. Which bash to prefer: "auto" (default,
              PATH-first -- unchanged from prior behavior), "wsl", or "gitbash".
              Also settable via the AMPLIFIER_BASH_WINDOWS_SHELL env var
              (config takes precedence). See _arbitrate_windows_shell for
              the full resolution/fallback rules.

    Returns:
        Optional cleanup function
    """
    config = config or {}

    # If working_dir not explicitly set in config, use session.working_dir capability
    # This enables server deployments where Path.cwd() returns the wrong directory
    if "working_dir" not in config:
        working_dir = coordinator.get_capability("session.working_dir")
        if working_dir:
            config = {**config, "working_dir": working_dir}

    tool = BashTool(config)
    await coordinator.mount("tools", tool, name=tool.name)
    logger.info("Mounted BashTool")
    return


class BashTool:
    """Execute bash commands with safety features."""

    name = "bash"
    description = """
Low-level shell command execution. This is a fallback primitive - before using bash directly,
consider whether specialized capabilities exist for your task. Specialized options typically offer
better error handling, structured output, domain expertise, and safety guardrails.

WHEN TO USE BASH:
- Build and test commands (pytest, npm test, cargo build, make)
- Package management (pip, npm, cargo, brew)
- Version control operations (git status, git diff, git commit)
- Container operations (docker, podman, kubectl)
- GitHub CLI (gh pr create, gh issue list)
- System utilities when no specialized option exists

INTRINSIC LIMITATIONS (why specialized options are often better):
- Raw text output requiring manual parsing
- No domain-specific context or best practices built in
- No built-in retry logic or intelligent error recovery
- No semantic understanding of your intent

OUTPUT LIMITS:
- Long outputs are automatically truncated to prevent context overflow
- When truncated, you'll see: first lines, "[...truncated...]", last lines, and byte counts
- WARNING: If output contains JSON, XML, or similar structured data, truncation may break parsing
- WORKAROUND: For large structured output, redirect to a file (command > output.json) and use
  file reading capabilities to inspect portions of the file as needed

COMMAND GUIDELINES:
- Quote paths containing spaces: cd "/path/with spaces"
- Prefer absolute paths to maintain working directory context
- Chain dependent commands with && (mkdir foo && cd foo)
- Commands time out after 30 seconds by default. Pass `timeout` to increase for long-running
  commands (builds, tests, monitoring). Use `run_in_background` for truly indefinite processes.
- Use `run_in_background` for long-running processes (dev servers, watchers)
- Interactive commands (-i flags, editors requiring input) are not supported

SAFETY:
- Destructive commands (rm -rf /, sudo rm, etc.) are blocked
- Commands requiring interactive input will fail
                   """

    # Default output limit: ~100KB (roughly 25k tokens)
    DEFAULT_MAX_OUTPUT_BYTES = 100_000

    def __init__(self, config: dict[str, Any]):
        """
        Initialize bash tool.

        Args:
            config: Tool configuration
        """
        self.config = config
        self.require_approval = config.get("require_approval", True)
        self.timeout = _validate_timeout_seconds(
            config.get("timeout", 30), source="config"
        )
        self.working_dir = config.get("working_dir", ".")
        # Output limiting to prevent context overflow
        self.max_output_bytes = config.get(
            "max_output_bytes", self.DEFAULT_MAX_OUTPUT_BYTES
        )

        # Initialize safety validator with profile-based system
        safety_profile = config.get("safety_profile", "strict")
        safety_config = SafetyConfig(
            profile=safety_profile,
            allowed_commands=config.get("allowed_commands", []),
            denied_commands=config.get("denied_commands", []),
            safety_overrides=config.get("safety_overrides"),
        )
        self._safety_validator = SafetyValidator(
            profile=safety_profile, config=safety_config
        )

        # Keep for backward compatibility with get_metadata
        self.allowed_commands = config.get("allowed_commands", [])
        self.denied_commands = config.get("denied_commands", [])

        # Concurrency limit: maximum number of commands that can run simultaneously
        self.max_concurrent = config.get("max_concurrent", None)
        self._active_commands = 0

        # Cache for WSL bash detection to avoid repeated checks
        self._wsl_bash_cache: dict[str, bool] = {}

        # Windows shell resolution: which bash (WSL vs Git Bash) to use, and
        # whether the choice has been explicitly overridden. See the
        # module-level note above `_arbitrate_windows_shell` for why PATH
        # alone can't be trusted to ever surface Git Bash.
        self._windows_shell_preference = self._resolve_windows_shell_preference(config)
        # Cache for the AUTHORITATIVE resolution (async, subprocess-verified
        # is_wsl check) used to actually execute commands. Resolved once per
        # instance, not per command -- shared by both the foreground
        # (_run_command) and background (_run_command_background) paths so
        # they can never disagree (see _resolve_windows_bash docstring).
        self._windows_bash_resolved: tuple[str | None, bool] | None = None

        # Windows only: append a startup note (log + tool description) naming
        # the shell we expect to resolve to, so a user/model isn't left to
        # discover it only after a confusing failure hundreds of calls in
        # (e.g. `python script.py` failing because WSL bash can't see the
        # Windows Python). Uses a synchronous, approximate classification
        # (`_looks_like_wsl_launcher_path`) since the authoritative,
        # subprocess-verified check can't run inside a sync constructor --
        # the real execution routing is unaffected and always uses that
        # authoritative check via `_resolve_windows_bash`.
        if sys.platform == "win32":
            self.description = self.description + self._windows_shell_startup_note()

    @staticmethod
    def _resolve_windows_shell_preference(config: dict[str, Any]) -> str:
        """Resolve the explicit Windows shell preference: `windows_shell`
        config key, then the AMPLIFIER_BASH_WINDOWS_SHELL env var, then
        "auto" (today's default: PATH-first, unchanged).

        This module has no existing config-resolution system to plug into
        (checked: no env vars, no config layer beyond plain config.get(...)
        calls) -- a plain env var + config key, in the spirit of the
        existing code, is the whole mechanism.
        """
        value = config.get("windows_shell") or os.environ.get(
            _WINDOWS_SHELL_PREFERENCE_ENV_VAR
        )
        if not value:
            return "auto"
        value = value.strip().lower()
        if value not in _VALID_WINDOWS_SHELL_PREFERENCES:
            logger.warning(
                "tool-bash: unknown windows_shell=%r (expected one of %s); "
                "using 'auto'",
                value,
                _VALID_WINDOWS_SHELL_PREFERENCES,
            )
            return "auto"
        return value

    def _windows_shell_startup_note(self) -> str:
        """Build the Windows-only description/log note naming the shell we
        expect to resolve to and its path conventions -- the model needs
        this BEFORE its first command (WSL mounts Windows drives at
        /mnt/c/..., Git Bash at /c/...; guessing wrong -- not a hard
        error -- was found to be the dominant failure mode across
        comparable CLI agents). Approximate (see
        `_looks_like_wsl_launcher_path`); the actual command routing
        always uses the authoritative, subprocess-verified check in
        `_resolve_windows_bash`.
        """
        path_bash = shutil.which("bash")
        path_bash_is_wsl = _looks_like_wsl_launcher_path(path_bash)
        exe, is_wsl = _arbitrate_windows_shell(
            self._windows_shell_preference,
            path_bash,
            path_bash_is_wsl,
            _find_git_bash_executable(),
            _find_wsl_bash_executable(),
        )

        logger.info(
            "tool-bash: Windows shell (approx; confirmed on first command) -> %s (%s)",
            exe or "NOT FOUND",
            "wsl" if is_wsl else ("gitbash" if exe else "none"),
        )

        override_hint = (
            "\n(Override: set windows_shell config or "
            f"{_WINDOWS_SHELL_PREFERENCE_ENV_VAR} env var to 'wsl' or "
            "'gitbash'.)"
        )
        if exe is None:
            return (
                "\n\nWINDOWS SHELL: no bash found (WSL or Git Bash). Every "
                "command will fail with an actionable error naming how to "
                "install one."
            )
        if is_wsl:
            return (
                f"\n\nWINDOWS SHELL: WSL bash ({exe}). Windows drives are "
                "mounted at /mnt/c/..., not /c/...; $HOME is the WSL "
                "Linux home, not the Windows user profile; the toolchain "
                "(e.g. python) is whatever is installed INSIDE that Linux "
                "distro, not on Windows." + override_hint
            )
        return (
            f"\n\nWINDOWS SHELL: Git Bash ({exe}). Windows drives are "
            "mounted at /c/..., not /mnt/c/...; $HOME is the Windows user "
            "profile; the toolchain (e.g. python) is whatever is "
            "installed on Windows itself." + override_hint
        )

    @property
    def input_schema(self) -> dict:
        """Return JSON schema for tool parameters."""
        return {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Bash command to execute"},
                "timeout": {
                    "type": "integer",
                    "minimum": TIMEOUT_MIN_SECONDS,
                    "maximum": TIMEOUT_MAX_SECONDS,
                    "description": "Command timeout in seconds (default: 30). Increase for builds, tests, or monitoring. Use run_in_background for truly indefinite processes.",
                },
                "run_in_background": {
                    "type": "boolean",
                    "description": "Run command in background, returning immediately with PID. Use for long-running processes like dev servers.",
                    "default": False,
                },
            },
            "required": ["command"],
        }

    def get_metadata(self) -> dict[str, Any]:
        """Return tool metadata for approval system."""
        return {
            "requires_approval": self.require_approval,
            "approval_hints": {
                "risk_level": "high",
                "dangerous_patterns": self.denied_commands,
                "safe_patterns": self.allowed_commands,
            },
        }

    async def execute(self, input: dict[str, Any]) -> ToolResult:
        """
        Execute a bash command.

        Args:
            input: Dictionary with 'command' and optional 'run_in_background' keys

        Returns:
            Tool result with command output
        """
        command = input.get("command")
        if not command:
            error_msg = "Command is required"
            return ToolResult(
                success=False, output=error_msg, error={"message": error_msg}
            )

        if "timeout" in input:
            try:
                timeout = _validate_timeout_seconds(
                    input.get("timeout"), source="caller"
                )
            except (TypeError, ValueError) as e:
                error_msg = str(e)
                return ToolResult(
                    success=False, output=error_msg, error={"message": error_msg}
                )
        else:
            timeout = self.timeout
        run_in_background = input.get("run_in_background", False)

        # Safety checks using profile-based validator
        safety_result = self._safety_validator.validate(command)
        if not safety_result.allowed:
            error_msg = f"Command denied for safety: {safety_result.reason}"
            if safety_result.hint:
                error_msg += f"\n  Hint: {safety_result.hint}"
            return ToolResult(
                success=False,
                output=error_msg,
                error={"message": error_msg},
            )

        # Approval is now handled by approval hook via tool:pre event

        # Concurrency limit check
        if (
            self.max_concurrent is not None
            and self._active_commands >= self.max_concurrent
        ):
            error_msg = f"Command rejected: concurrent command limit of {self.max_concurrent} reached"
            return ToolResult(
                success=False,
                output=error_msg,
                error={"message": error_msg},
            )

        self._active_commands += 1
        try:
            if run_in_background:
                # Execute command in background and return immediately
                result = await self._run_command_background(command)
                return ToolResult(
                    success=True,
                    output={
                        "pid": result["pid"],
                        "message": f"Command started in background with PID {result['pid']}",
                        "note": "Use 'ps' or 'kill' commands to manage the background process.",
                    },
                )
            else:
                # Execute command and wait for completion
                result = await self._run_command(command, timeout=timeout)

                # Apply output truncation to prevent context overflow
                stdout, stdout_truncated, stdout_bytes = self._truncate_output(
                    result["stdout"]
                )
                stderr, stderr_truncated, stderr_bytes = self._truncate_output(
                    result["stderr"]
                )

                output = {
                    "stdout": stdout,
                    "stderr": stderr,
                    "returncode": result["returncode"],
                }

                # Include truncation metadata if either was truncated
                if stdout_truncated or stderr_truncated:
                    output["truncated"] = True
                    if stdout_truncated:
                        output["stdout_total_bytes"] = stdout_bytes
                    if stderr_truncated:
                        output["stderr_total_bytes"] = stderr_bytes

                return ToolResult(
                    success=result["returncode"] == 0,
                    output=output,
                )

        except TimeoutError:
            error_msg = f"Command timed out after {timeout} seconds"
            return ToolResult(
                success=False,
                output=error_msg,
                error={"message": error_msg},
            )
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            error_msg = str(e)
            return ToolResult(
                success=False, output=error_msg, error={"message": error_msg}
            )
        finally:
            self._active_commands -= 1

    # NOTE: _is_safe_command and _is_pre_approved have been replaced by
    # SafetyValidator which provides profile-based safety with smart pattern matching.
    # See safety.py for the implementation.

    def _extract_head_bytes(self, output: str, budget: int) -> str:
        """Extract first N bytes from output, respecting UTF-8 boundaries.

        Args:
            output: The string to extract from
            budget: Maximum bytes to extract

        Returns:
            String containing at most `budget` bytes, not splitting multi-byte chars
        """
        encoded = output.encode("utf-8")
        if len(encoded) <= budget:
            return output

        # Truncate at byte level, then decode safely
        truncated_bytes = encoded[:budget]

        # Find valid UTF-8 boundary by trying to decode
        # Work backwards until we get valid UTF-8
        for i in range(len(truncated_bytes), max(0, len(truncated_bytes) - 4), -1):
            try:
                return truncated_bytes[:i].decode("utf-8")
            except UnicodeDecodeError:
                continue

        # Fallback: decode with error replacement (shouldn't normally happen)
        return truncated_bytes.decode("utf-8", errors="ignore")

    def _extract_tail_bytes(self, output: str, budget: int) -> str:
        """Extract last N bytes from output, respecting UTF-8 boundaries.

        Args:
            output: The string to extract from
            budget: Maximum bytes to extract

        Returns:
            String containing at most `budget` bytes, not splitting multi-byte chars
        """
        encoded = output.encode("utf-8")
        if len(encoded) <= budget:
            return output

        # Truncate at byte level from the end
        truncated_bytes = encoded[-budget:]

        # Find valid UTF-8 boundary by trying to decode
        # Work forwards until we get valid UTF-8 (skip partial char at start)
        for i in range(min(4, len(truncated_bytes))):
            try:
                return truncated_bytes[i:].decode("utf-8")
            except UnicodeDecodeError:
                continue

        # Fallback: decode with error replacement (shouldn't normally happen)
        return truncated_bytes.decode("utf-8", errors="ignore")

    def _truncate_output(self, output: str) -> tuple[str, bool, int]:
        """Truncate output if it exceeds max_output_bytes.

        Uses line-based truncation for cleaner output, with byte-level fallback
        for edge cases like single giant lines (minified JSON, base64).

        Returns:
            Tuple of (possibly truncated output, was_truncated, original_bytes)
        """
        original_bytes = len(output.encode("utf-8"))

        if original_bytes <= self.max_output_bytes:
            return output, False, original_bytes

        # Preserve head and tail with truncation indicator
        # Use roughly 40% head, 40% tail, leaving room for indicator
        head_budget = int(self.max_output_bytes * 0.4)
        tail_budget = int(self.max_output_bytes * 0.4)

        # Split into lines for cleaner truncation
        lines = output.split("\n")

        # Build head (first N lines up to head_budget)
        head_lines = []
        head_size = 0
        for line in lines:
            line_bytes = len((line + "\n").encode("utf-8"))
            if head_size + line_bytes > head_budget:
                break
            head_lines.append(line)
            head_size += line_bytes

        # Build tail (last N lines up to tail_budget)
        tail_lines = []
        tail_size = 0
        for line in reversed(lines):
            line_bytes = len((line + "\n").encode("utf-8"))
            if tail_size + line_bytes > tail_budget:
                break
            tail_lines.insert(0, line)
            tail_size += line_bytes

        head_content = "\n".join(head_lines)
        tail_content = "\n".join(tail_lines)

        # Check if line-based truncation captured enough content
        captured_bytes = len(head_content.encode("utf-8")) + len(
            tail_content.encode("utf-8")
        )
        min_useful = self.max_output_bytes * 0.2  # At least 20% of limit

        if captured_bytes < min_useful:
            # Byte-level fallback for very long lines (minified JSON, base64, etc.)
            head_content = self._extract_head_bytes(output, head_budget)
            tail_content = self._extract_tail_bytes(output, tail_budget)

            head_actual_bytes = len(head_content.encode("utf-8"))
            tail_actual_bytes = len(tail_content.encode("utf-8"))

            truncation_indicator = (
                f"\n\n[...OUTPUT TRUNCATED (byte-level)...]\n"
                f"[Showing first ~{head_actual_bytes:,} bytes and last ~{tail_actual_bytes:,} bytes]\n"
                f"[Total output: {original_bytes:,} bytes, limit: {self.max_output_bytes:,} bytes]\n"
                f"[Note: Line-based truncation failed (very long lines), using byte-level fallback]\n"
                f"[TIP: For large structured output, redirect to file and read portions]\n\n"
            )
        else:
            # Standard line-based truncation indicator
            truncation_indicator = (
                f"\n\n[...OUTPUT TRUNCATED...]\n"
                f"[Showing first {len(head_lines)} lines and last {len(tail_lines)} lines]\n"
                f"[Total output: {original_bytes:,} bytes, limit: {self.max_output_bytes:,} bytes]\n"
                f"[TIP: For large structured output (JSON/XML), redirect to file and read portions]\n\n"
            )

        truncated = head_content + truncation_indicator + tail_content
        return truncated, True, original_bytes

    async def _is_wsl_bash(self, bash_exe: str) -> bool:
        """Detect if bash executable is WSL bash (not Git Bash).

        WSL bash requires special invocation via 'wsl --exec bash' to prevent
        the WSL launcher from prematurely expanding shell variables before
        they reach the bash interpreter.

        Args:
            bash_exe: Path to bash executable

        Returns:
            True if WSL bash, False if Git Bash or other
        """
        # Check cache first
        if bash_exe in self._wsl_bash_cache:
            return self._wsl_bash_cache[bash_exe]

        try:
            # Check if /mnt/wsl directory exists (WSL-specific mount point)
            proc = await asyncio.create_subprocess_exec(
                bash_exe,
                "-c",
                "test -d /mnt/wsl",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=".",
            )
            await asyncio.wait_for(proc.communicate(), timeout=2)

            # Exit code 0 means directory exists (WSL)
            is_wsl = proc.returncode == 0
            self._wsl_bash_cache[bash_exe] = is_wsl
            return is_wsl
        except Exception:
            # On any error, assume not WSL
            self._wsl_bash_cache[bash_exe] = False
            return False

    async def _resolve_windows_bash(self) -> tuple[str | None, bool]:
        """Authoritative Windows shell resolution: which bash executable to
        use, and whether it's WSL bash. Resolved ONCE per instance and
        cached -- both `_run_command` and `_run_command_background` call
        this (instead of each rolling their own PATH lookup / cache read)
        so the two paths can never disagree about which shell is active.

        Previously `_run_command_background` read
        `self._wsl_bash_cache.get(bash_exe, False)` directly, defaulting to
        False -- so a background command issued before any foreground
        command routed WSL's bash.exe down the Git-Bash direct-exec
        branch, bypassing the `wsl --exec` wrapper that exists
        specifically to prevent premature variable expansion. Since this
        method is itself async, both call sites can simply await it
        instead.
        """
        if self._windows_bash_resolved is not None:
            return self._windows_bash_resolved

        path_bash = shutil.which("bash")
        path_bash_is_wsl = await self._is_wsl_bash(path_bash) if path_bash else False

        resolved = _arbitrate_windows_shell(
            self._windows_shell_preference,
            path_bash,
            path_bash_is_wsl,
            _find_git_bash_executable(),
            _find_wsl_bash_executable(),
        )
        self._windows_bash_resolved = resolved

        exe, is_wsl = resolved
        logger.info(
            "tool-bash: Windows shell resolved -> %s (%s)",
            exe or "NOT FOUND",
            "wsl" if is_wsl else ("gitbash" if exe else "none"),
        )
        return resolved

    async def _run_command_background(self, command: str) -> dict[str, Any]:
        """Run command in background, returning immediately with PID.

        The process is fully detached with:
        - New session (setsid) so it's not killed when parent exits
        - Pipes redirected to /dev/null to prevent blocking
        - Returns immediately with PID for management

        Uses subprocess.Popen instead of asyncio.create_subprocess_* to avoid
        creating asyncio transports that would need cleanup. Since we're fully
        detaching the process anyway, we don't need asyncio's process management.
        This prevents "Event loop is closed" errors during session cleanup.
        """
        is_windows = sys.platform == "win32"

        # Open /dev/null for redirecting stdin/stdout/stderr
        devnull = subprocess.DEVNULL

        if is_windows:
            # Windows background execution. Resolution is authoritative and
            # shared with the foreground path via `_resolve_windows_bash`
            # (this method is itself async, so it can simply await it) --
            # see that method's docstring for why the previous
            # `self._wsl_bash_cache.get(bash_exe, False)` read here could
            # silently disagree with the foreground path.
            bash_exe, is_wsl = await self._resolve_windows_bash()
            if bash_exe:
                if is_wsl:
                    # WSL bash: Use 'wsl --exec bash -c' to prevent premature variable expansion
                    process = subprocess.Popen(
                        ["wsl", "--exec", "bash", "-c", command],
                        stdout=devnull,
                        stderr=devnull,
                        stdin=devnull,
                        cwd=self.working_dir,
                        creationflags=subprocess.DETACHED_PROCESS
                        | subprocess.CREATE_NEW_PROCESS_GROUP,
                    )
                else:
                    # Git Bash or other: Use subprocess_exec pattern (handles paths with spaces)
                    process = subprocess.Popen(
                        [bash_exe, "-c", command],
                        stdout=devnull,
                        stderr=devnull,
                        stdin=devnull,
                        cwd=self.working_dir,
                        creationflags=subprocess.DETACHED_PROCESS
                        | subprocess.CREATE_NEW_PROCESS_GROUP,
                    )
            else:
                # No bash found on Windows. Same contract as the
                # foreground path (`_run_command`): a tool named
                # `bash` silently running a command with no shell at
                # all (or raising a bare OS error for anything else)
                # is a degraded state pretending to be a working one.
                # Surface the same actionable error instead of
                # attempting to run anything.
                #
                # Raising (rather than returning a sentinel) keeps the
                # return contract of this method a plain `{"pid": ...}`
                # with no optional keys for callers to remember to
                # check. `execute()` already wraps this call and turns
                # any exception into ToolResult(success=False,
                # output=str(e), error={"message": str(e)}) -- exactly
                # the shape the foreground path returns.
                raise RuntimeError(_WINDOWS_NO_BASH_ERROR)
        else:
            # Unix-like: Use start_new_session to create new session, fully detached
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=devnull,
                stderr=devnull,
                stdin=devnull,
                executable="/bin/bash",
                cwd=self.working_dir,
                start_new_session=True,  # Creates new session, detaches from terminal
            )

        return {"pid": process.pid}

    async def _run_command(
        self, command: str, timeout: int | None = None
    ) -> dict[str, Any]:
        """Run command asynchronously with platform-appropriate shell.

        On Unix-like systems (Linux, macOS, WSL), uses bash for full shell features.
        On Windows, attempts to find bash (Git Bash or WSL bash).
        If bash is not found, every command fails with an actionable error
        naming the cause and how to install bash (Git for Windows or WSL) --
        this tool's contract is POSIX shell semantics, so there is no
        partial/degraded fallback (e.g. cmd.exe) for "simple" commands.

        Uses process groups for proper cleanup on timeout - kills entire process tree.
        """
        # Detect platform
        is_windows = sys.platform == "win32"
        process = None
        pgid = None

        if is_windows:
            # Resolve which bash to use (Git Bash or WSL bash) -- shared,
            # cached-once resolution; see `_resolve_windows_bash` docstring.
            bash_exe, is_wsl = await self._resolve_windows_bash()

            if bash_exe:
                # Bash found on Windows - use create_subprocess_exec to handle
                # paths with spaces (e.g., "C:\Program Files\Git\bin\bash.exe")
                # and properly handle WSL bash variable expansion
                if is_wsl:
                    # WSL bash: Use 'wsl --exec bash -c' to prevent premature
                    # variable expansion by the WSL launcher
                    process = await asyncio.create_subprocess_exec(
                        "wsl",
                        "--exec",
                        "bash",
                        "-c",
                        command,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        stdin=asyncio.subprocess.DEVNULL,  # Never hand the child our stdin
                        cwd=self.working_dir,
                    )
                    # GAP-024: assign to a kill-on-close job object so this
                    # (and its wslhost.exe descendants) can't outlive an
                    # amplifier.exe that gets killed outright rather than
                    # cancelled through our own code. See helper docstring.
                    _assign_to_windows_job(process.pid)
                    # GAP-013/GAP-028: the immediate wsl.exe PID being a job
                    # member does NOT mean its real descendants (inner
                    # wsl.exe, wslhost.exe) are -- verified directly with
                    # IsProcessInJob. Sweep for them in the background; see
                    # _protect_windows_descendants docstring for why.
                    _spawn_descendant_sweep(process.pid)
                else:
                    # Git Bash or other: Direct exec with [bash, -c, command]
                    process = await asyncio.create_subprocess_exec(
                        bash_exe,
                        "-c",
                        command,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        stdin=asyncio.subprocess.DEVNULL,  # Never hand the child our stdin
                        cwd=self.working_dir,
                    )
                    _assign_to_windows_job(process.pid)  # GAP-024, see above
                    _spawn_descendant_sweep(process.pid)
            else:
                # No bash found on Windows. This tool's entire contract is
                # POSIX shell semantics (quoting, tilde expansion, &&/||/|,
                # redirects, command substitution) -- there is no cmd.exe
                # fallback, and there never should be a *partial* one.
                # Previously, only commands containing an obvious shell
                # metacharacter got this actionable error; anything else
                # (`echo hello`, `ls`, `dir`, cmd.exe builtins like `cd`,
                # `type`, `set`, `copy`, ...) fell through to
                # shlex.split() + exec-with-no-shell-at-all and failed with
                # a bare `[WinError 2] The system cannot find the file
                # specified` -- naming neither the cause nor the fix. A
                # tool named `bash` silently running some commands with no
                # shell (or, worse, through cmd.exe) is a degraded state
                # pretending to be a working one: the user's mental model
                # breaks the moment quoting or a builtin behaves
                # differently, with no signal why. Fail loud, unconditionally,
                # for every command, with the real cause and the fix.
                return {
                    "stdout": "",
                    "stderr": _WINDOWS_NO_BASH_ERROR,
                    "returncode": 1,
                }
        else:
            # Unix-like (Linux, macOS, WSL): Use real bash shell
            # This enables:
            # - Tilde expansion (~)
            # - Shell operators (&&, ||, |, ;)
            # - Redirects (>, <, 2>&1, &>)
            # - Command substitution ($(...), `...`)
            # - Variable expansion ($VAR)
            # - Heredocs (<<EOF)
            #
            # start_new_session=True creates a new process group, enabling
            # us to kill the entire process tree on timeout (not just bash)

            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.DEVNULL,  # Never hand the child our stdin --
                # an agent-invoked command is non-interactive by definition, and
                # inheriting the host's stdin (which, under the Amplifier CLI, is
                # the real controlling TTY in prompt_toolkit's raw mode) lets a
                # child like `ssh` (without `-n`) read from and reconfigure
                # (tcsetattr) that terminal. That contends with prompt_toolkit's
                # own terminal coordination and can stall the event loop -- the
                # very hang this fixes. A command that reads stdin should see
                # immediate EOF, not block on (and fight over) the user's TTY.
                executable="/bin/bash",  # Explicit bash (not /bin/sh)
                cwd=self.working_dir,
                start_new_session=True,  # Creates new process group for proper cleanup
            )
            # Get the process group ID (same as PID when start_new_session=True)
            pgid = process.pid

        # Wait for completion with timeout
        effective_timeout = timeout if timeout is not None else self.timeout
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=effective_timeout
            )

            return {
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stderr": stderr.decode("utf-8", errors="replace"),
                "returncode": process.returncode,
            }

        except TimeoutError:
            await _await_process_tree_cleanup(process, pgid=pgid, is_windows=is_windows)
            raise
        except asyncio.CancelledError:
            # If our caller cancels the tool call, ensure we still clean up
            # the spawned process tree (including the existing Linux /proc
            # strategy for setsid()-detached descendants), then re-raise
            # cancellation. The shared helper also defers repeated cancellation
            # until the bounded cleanup task finishes.
            await _await_process_tree_cleanup(process, pgid=pgid, is_windows=is_windows)
            raise
