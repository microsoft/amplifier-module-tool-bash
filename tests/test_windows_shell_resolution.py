"""Regression tests: Windows shell resolution (Git Bash discoverability,
resolved-shell observability, foreground/background agreement).

## Why these tests exist

Confirmed on a real Windows 11 box with Git for Windows 2.55.0.3 installed
a month prior to testing:

    shutil.which('bash') -> 'C:\\Windows\\system32\\bash.EXE'   # WSL launcher

    persisted registry PATH:
      MACHINE: ... C:\\Windows\\system32 (position 4) ...
               C:\\Program Files\\Git\\cmd (position ~24)
      USER:    (no Git entries)

Root cause: Git for Windows' *default* install puts `Git\\cmd` on PATH
(git.exe lives there) but NOT `Git\\bin` (bash.exe lives there). Meanwhile
the WSL launcher stub at `C:\\Windows\\System32\\bash.exe` is effectively
always on PATH. So `shutil.which("bash")` resolves the WSL launcher every
time, and Git Bash is unreachable no matter what's installed -- even
though a `bash` call against a WSL box reaches a different filesystem,
$HOME, and toolchain than a `bash` call against Git Bash:

                    WSL bash              Git Bash
    git --version   git version 2.43.0    git version 2.55.0.windows.3
    which python    NO_PYTHON             /c/Python314/python
    uname -s        Linux                 MINGW64_NT-10.0-26200
    $HOME           /home/brkrabac        /c/Users/brkrabac

These tests run on any platform (they patch `sys.platform`, `shutil.which`,
`os.environ`, `os.path.isfile`, and the subprocess-spawning calls) and
assert the resolution OUTCOME, not the real OS state.
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import amplifier_module_tool_bash as mod
import pytest
from amplifier_module_tool_bash import (
    BashTool,
    _arbitrate_windows_shell,
    _find_git_bash_executable,
    _find_wsl_bash_executable,
)

# Built with os.path.join (not hardcoded backslash strings) so these match
# exactly what the production code computes regardless of which platform
# the test SUITE happens to run on -- production always runs on real
# Windows (backslash-joining `ntpath`), but these tests run on Linux/macOS
# CI too, where `os.path.join` joins with "/" instead. Using the same
# join call here as the code under test keeps the comparison meaningful
# without asserting anything about actual separator characters.
PROGRAM_FILES = r"C:\Program Files"
SYSTEM_ROOT = r"C:\Windows"
WSL_LAUNCHER = os.path.join(SYSTEM_ROOT, "System32", "bash.exe")
GIT_BASH = os.path.join(PROGRAM_FILES, "Git", "bin", "bash.exe")


class _FakeProc:
    """Minimal stand-in for an asyncio subprocess, returncode configurable."""

    def __init__(self, pid: int = 999, returncode: int = 0) -> None:
        self.pid = pid
        self.returncode = returncode

    async def communicate(self, *_args, **_kwargs) -> tuple[bytes, bytes]:
        return (b"", b"")


def _is_wsl_subprocess_mock(returncode: int) -> AsyncMock:
    """Build an AsyncMock standing in for asyncio.create_subprocess_exec,
    used by `_is_wsl_bash`'s `test -d /mnt/wsl` check. returncode=0 means
    "is WSL", nonzero means "is not WSL".
    """
    return AsyncMock(return_value=_FakeProc(returncode=returncode))


# ---------------------------------------------------------------------------
# 1. Pure arbitration function -- fast, no async/platform patching needed.
# ---------------------------------------------------------------------------


class TestArbitrateWindowsShell:
    """Unit tests for the shared, pure decision function."""

    def test_auto_uses_path_result_outright_when_present(self):
        """This is the crux of "don't change the default for existing
        users": in auto mode, if PATH resolves ANYTHING, it wins --
        exactly today's behavior -- regardless of what else is
        discoverable via the well-known install-location probes.
        """
        exe, is_wsl = _arbitrate_windows_shell(
            "auto",
            path_bash=WSL_LAUNCHER,
            path_bash_is_wsl=True,
            git_bash_candidate=GIT_BASH,  # discoverable, but must NOT win
            wsl_bash_candidate=WSL_LAUNCHER,
        )
        assert exe == WSL_LAUNCHER
        assert is_wsl is True

    def test_auto_falls_back_to_gitbash_when_path_resolves_nothing(self):
        """Strict improvement: previously a hard 'bash not found' error
        even when Git Bash was actually installed, because PATH alone
        never sees it (Git\\bin is not on PATH by default).
        """
        exe, is_wsl = _arbitrate_windows_shell(
            "auto",
            path_bash=None,
            path_bash_is_wsl=False,
            git_bash_candidate=GIT_BASH,
            wsl_bash_candidate=None,
        )
        assert exe == GIT_BASH
        assert is_wsl is False

    def test_auto_with_nothing_discoverable_returns_none(self):
        exe, is_wsl = _arbitrate_windows_shell(
            "auto",
            path_bash=None,
            path_bash_is_wsl=False,
            git_bash_candidate=None,
            wsl_bash_candidate=None,
        )
        assert exe is None
        assert is_wsl is False

    def test_explicit_gitbash_preference_wins_even_when_path_resolves_wsl(self):
        """The reported bug, fixed: a user can force Git Bash even though
        PATH resolves the WSL launcher first.
        """
        exe, is_wsl = _arbitrate_windows_shell(
            "gitbash",
            path_bash=WSL_LAUNCHER,
            path_bash_is_wsl=True,
            git_bash_candidate=GIT_BASH,
            wsl_bash_candidate=WSL_LAUNCHER,
        )
        assert exe == GIT_BASH
        assert is_wsl is False

    def test_explicit_wsl_preference_wins_even_when_path_resolves_gitbash(self):
        exe, is_wsl = _arbitrate_windows_shell(
            "wsl",
            path_bash=GIT_BASH,
            path_bash_is_wsl=False,
            git_bash_candidate=GIT_BASH,
            wsl_bash_candidate=WSL_LAUNCHER,
        )
        assert exe == WSL_LAUNCHER
        assert is_wsl is True

    def test_explicit_preference_falls_back_with_warning_when_unavailable(self):
        """Asking for gitbash when none is discoverable anywhere falls back
        to auto-detection (still gives the user a working shell) rather
        than a hard failure -- but must warn, since the request was
        explicit and silently ignoring it would be confusing.
        """
        with patch.object(mod, "logger") as log:
            exe, is_wsl = _arbitrate_windows_shell(
                "gitbash",
                path_bash=WSL_LAUNCHER,
                path_bash_is_wsl=True,
                git_bash_candidate=None,
                wsl_bash_candidate=WSL_LAUNCHER,
            )
        assert exe == WSL_LAUNCHER
        assert is_wsl is True
        assert log.warning.called


# ---------------------------------------------------------------------------
# 2. Filesystem probing helpers
# ---------------------------------------------------------------------------


class TestFilesystemProbes:
    def test_find_git_bash_executable_probes_known_locations(self):
        with (
            patch.dict(
                mod.os.environ,
                {"ProgramFiles": r"C:\Program Files"},
                clear=True,
            ),
            patch(
                "amplifier_module_tool_bash.os.path.isfile",
                side_effect=lambda p: p == GIT_BASH,
            ),
        ):
            assert _find_git_bash_executable() == GIT_BASH

    def test_find_git_bash_executable_returns_none_when_not_installed(self):
        with (
            patch.dict(mod.os.environ, {}, clear=True),
            patch("amplifier_module_tool_bash.os.path.isfile", return_value=False),
        ):
            assert _find_git_bash_executable() is None

    def test_find_wsl_bash_executable_probes_system_root(self):
        with (
            patch.dict(mod.os.environ, {"SystemRoot": r"C:\Windows"}, clear=True),
            patch(
                "amplifier_module_tool_bash.os.path.isfile",
                side_effect=lambda p: p == WSL_LAUNCHER,
            ),
        ):
            assert _find_wsl_bash_executable() == WSL_LAUNCHER


# ---------------------------------------------------------------------------
# 3. BashTool._resolve_windows_bash -- the authoritative, cached resolution
#    used to actually execute commands.
# ---------------------------------------------------------------------------


class TestResolveWindowsBash:
    @pytest.mark.asyncio
    async def test_gitbash_selectable_via_config_when_wsl_on_path(self):
        """End-to-end version of the reported bug: PATH resolves the WSL
        launcher (as it always does when WSL is installed), but the user
        has asked (via config) for Git Bash, and Git Bash IS installed at
        a well-known location -- it must be discoverable and chosen.
        """
        tool = BashTool({"windows_shell": "gitbash"})

        with (
            patch("amplifier_module_tool_bash.shutil.which", return_value=WSL_LAUNCHER),
            patch(
                "amplifier_module_tool_bash.asyncio.create_subprocess_exec",
                _is_wsl_subprocess_mock(returncode=0),  # confirms WSL_LAUNCHER is WSL
            ),
            patch.dict(
                mod.os.environ, {"ProgramFiles": r"C:\Program Files"}, clear=True
            ),
            patch(
                "amplifier_module_tool_bash.os.path.isfile",
                side_effect=lambda p: p == GIT_BASH,
            ),
        ):
            exe, is_wsl = await tool._resolve_windows_bash()

        assert exe == GIT_BASH, (
            "requested windows_shell='gitbash' but resolution still picked "
            f"{exe!r} -- Git Bash was not made reachable"
        )
        assert is_wsl is False

    @pytest.mark.asyncio
    async def test_auto_default_unchanged_when_both_present(self):
        """Judgement call from the report: auto (default) keeps WSL when
        both are installed -- must not silently change behavior for
        existing users.
        """
        tool = BashTool({})  # no explicit preference -> "auto"

        with (
            patch("amplifier_module_tool_bash.shutil.which", return_value=WSL_LAUNCHER),
            patch(
                "amplifier_module_tool_bash.asyncio.create_subprocess_exec",
                _is_wsl_subprocess_mock(returncode=0),
            ),
            patch.dict(
                mod.os.environ, {"ProgramFiles": r"C:\Program Files"}, clear=True
            ),
            patch(
                "amplifier_module_tool_bash.os.path.isfile",
                side_effect=lambda p: p == GIT_BASH,
            ),
        ):
            exe, is_wsl = await tool._resolve_windows_bash()

        assert exe == WSL_LAUNCHER
        assert is_wsl is True

    @pytest.mark.asyncio
    async def test_auto_fallback_finds_gitbash_when_path_empty(self):
        """Previously: shutil.which("bash") returning None meant an
        unconditional 'bash not found' error, even with Git Bash actually
        installed. Now: auto falls back to the well-known locations.
        """
        tool = BashTool({})

        with (
            patch("amplifier_module_tool_bash.shutil.which", return_value=None),
            patch.dict(
                mod.os.environ, {"ProgramFiles": r"C:\Program Files"}, clear=True
            ),
            patch(
                "amplifier_module_tool_bash.os.path.isfile",
                side_effect=lambda p: p == GIT_BASH,
            ),
        ):
            exe, is_wsl = await tool._resolve_windows_bash()

        assert exe == GIT_BASH
        assert is_wsl is False

    @pytest.mark.asyncio
    async def test_resolution_is_cached_across_calls(self):
        """Resolved once, not per command -- shutil.which must only be
        consulted on the first call.
        """
        tool = BashTool({})
        which_mock = MagicMock(return_value=WSL_LAUNCHER)

        with (
            patch("amplifier_module_tool_bash.shutil.which", which_mock),
            patch(
                "amplifier_module_tool_bash.asyncio.create_subprocess_exec",
                _is_wsl_subprocess_mock(returncode=0),
            ),
        ):
            first = await tool._resolve_windows_bash()
            second = await tool._resolve_windows_bash()

        assert first == second
        assert which_mock.call_count == 1, (
            "shutil.which was consulted more than once -- resolution is "
            "supposed to be cached per instance, not re-done per command"
        )


# ---------------------------------------------------------------------------
# 4. Foreground/background agreement -- the latent cache-default bug.
# ---------------------------------------------------------------------------


class TestForegroundBackgroundAgree:
    @pytest.mark.asyncio
    async def test_background_first_call_still_routes_wsl_through_wrapper(self):
        """The bug: `_run_command_background` used to read
        `self._wsl_bash_cache.get(bash_exe, False)` directly, defaulting to
        False. Issued as the very FIRST command (cold cache, nothing has
        populated `_wsl_bash_cache` yet), a WSL bash.exe would be sent down
        the Git-Bash direct-exec branch (`[bash_exe, "-c", command]`)
        instead of `["wsl", "--exec", "bash", "-c", command]` -- bypassing
        the wrapper that exists specifically to prevent the WSL launcher
        from prematurely expanding shell variables.

        This must not happen: even as the first call, a WSL-classified
        bash.exe must be launched via the wsl wrapper.
        """
        tool = BashTool({})
        popen_mock = MagicMock(return_value=MagicMock(pid=4242))

        with (
            patch("amplifier_module_tool_bash.sys.platform", "win32"),
            patch("amplifier_module_tool_bash.shutil.which", return_value=WSL_LAUNCHER),
            patch(
                "amplifier_module_tool_bash.asyncio.create_subprocess_exec",
                _is_wsl_subprocess_mock(returncode=0),  # WSL_LAUNCHER IS wsl
            ),
            patch("amplifier_module_tool_bash.subprocess.Popen", popen_mock),
            # Windows-only constants that don't exist on the real `subprocess`
            # module on Linux/macOS -- the test suite runs there, so these
            # must be supplied for the (mocked-anyway) Popen call's keyword
            # arguments to even evaluate.
            patch.object(mod.subprocess, "DETACHED_PROCESS", 0x00000008, create=True),
            patch.object(
                mod.subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200, create=True
            ),
        ):
            # No foreground call happened first -- cache is genuinely cold.
            assert tool._wsl_bash_cache == {}
            result = await tool._run_command_background("echo hi")

        assert "pid" in result
        assert popen_mock.called, "background execution never spawned a process"
        spawned_args = popen_mock.call_args.args[0]
        assert spawned_args == ["wsl", "--exec", "bash", "-c", "echo hi"], (
            f"background command used {spawned_args!r} on a WSL bash.exe -- "
            "expected the ['wsl', '--exec', 'bash', '-c', ...] wrapper. This "
            "is the exact foreground/background disagreement the fix removes."
        )

    @pytest.mark.asyncio
    async def test_foreground_and_background_agree_on_same_resolution(self):
        """Both paths must resolve to the identical (exe, is_wsl) via the
        same shared, cached call -- shutil.which is consulted only once
        total across both.
        """
        tool = BashTool({})
        which_mock = MagicMock(return_value=WSL_LAUNCHER)
        popen_mock = MagicMock(return_value=MagicMock(pid=4242))
        fg_proc = _FakeProc(pid=1234, returncode=0)

        with (
            patch("amplifier_module_tool_bash.sys.platform", "win32"),
            patch("amplifier_module_tool_bash.shutil.which", which_mock),
            patch(
                "amplifier_module_tool_bash.asyncio.create_subprocess_exec",
                AsyncMock(return_value=fg_proc),
            ),
            patch("amplifier_module_tool_bash.subprocess.Popen", popen_mock),
            patch("amplifier_module_tool_bash._assign_to_windows_job", MagicMock()),
            patch("amplifier_module_tool_bash._spawn_descendant_sweep", MagicMock()),
            patch.object(mod.subprocess, "DETACHED_PROCESS", 0x00000008, create=True),
            patch.object(
                mod.subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200, create=True
            ),
        ):
            await tool._run_command("echo fg", timeout=5)
            await tool._run_command_background("echo bg")

        assert which_mock.call_count == 1, (
            "foreground and background each re-resolved the shell "
            "independently instead of sharing one cached resolution"
        )
        spawned_args = popen_mock.call_args.args[0]
        assert spawned_args[0] == "wsl", (
            "background disagreed with foreground's WSL classification"
        )


# ---------------------------------------------------------------------------
# 5. Observability: description names the resolved shell.
# ---------------------------------------------------------------------------


class TestWindowsShellDescription:
    def test_description_names_wsl_shell_and_path_convention(self):
        with (
            patch("amplifier_module_tool_bash.sys.platform", "win32"),
            patch("amplifier_module_tool_bash.shutil.which", return_value=WSL_LAUNCHER),
        ):
            tool = BashTool({})

        assert "WINDOWS SHELL" in tool.description
        assert WSL_LAUNCHER in tool.description
        assert "/mnt/c/" in tool.description, (
            "model needs the WSL path convention up front, before its "
            "first command, to avoid guessing wrong (the dominant "
            "failure mode found across comparable CLI agents)"
        )

    def test_description_names_gitbash_shell_and_path_convention(self):
        with (
            patch("amplifier_module_tool_bash.sys.platform", "win32"),
            patch("amplifier_module_tool_bash.shutil.which", return_value=GIT_BASH),
        ):
            tool = BashTool({})

        assert "WINDOWS SHELL" in tool.description
        assert GIT_BASH in tool.description
        assert "Git Bash" in tool.description
        note = tool.description.split("WINDOWS SHELL")[-1]
        assert "mounted at /c/" in note, (
            "model needs the Git Bash path convention up front, before "
            "its first command"
        )
        assert "WSL Linux home" not in note, (
            "Git Bash note incorrectly describes WSL's $HOME convention"
        )

    def test_description_names_missing_shell(self):
        with (
            patch("amplifier_module_tool_bash.sys.platform", "win32"),
            patch("amplifier_module_tool_bash.shutil.which", return_value=None),
            patch.dict(mod.os.environ, {}, clear=True),
            patch("amplifier_module_tool_bash.os.path.isfile", return_value=False),
        ):
            tool = BashTool({})

        assert "no bash found" in tool.description.lower()

    def test_posix_description_is_byte_identical_to_base(self):
        """POSIX must not gain the Windows note at all -- confirms the
        Fix 2 change is confined to `sys.platform == "win32"`.
        """
        with patch("amplifier_module_tool_bash.sys.platform", "linux"):
            tool = BashTool({})

        assert tool.description == BashTool.description
        assert "WINDOWS SHELL" not in tool.description


# ---------------------------------------------------------------------------
# 6. Preference resolution (config vs env var vs default).
# ---------------------------------------------------------------------------


class TestWindowsShellPreferenceResolution:
    def test_config_key_takes_precedence_over_env_var(self):
        with patch.dict(
            mod.os.environ, {"AMPLIFIER_BASH_WINDOWS_SHELL": "wsl"}, clear=False
        ):
            pref = BashTool._resolve_windows_shell_preference(
                {"windows_shell": "gitbash"}
            )
        assert pref == "gitbash"

    def test_env_var_used_when_no_config_key(self):
        with patch.dict(
            mod.os.environ, {"AMPLIFIER_BASH_WINDOWS_SHELL": "wsl"}, clear=False
        ):
            pref = BashTool._resolve_windows_shell_preference({})
        assert pref == "wsl"

    def test_defaults_to_auto(self):
        with patch.dict(mod.os.environ, {}, clear=True):
            pref = BashTool._resolve_windows_shell_preference({})
        assert pref == "auto"

    def test_unknown_value_warns_and_falls_back_to_auto(self):
        with patch.object(mod, "logger") as log:
            pref = BashTool._resolve_windows_shell_preference(
                {"windows_shell": "powershell"}
            )
        assert pref == "auto"
        assert log.warning.called
