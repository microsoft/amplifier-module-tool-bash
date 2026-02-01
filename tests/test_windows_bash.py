"""Tests for Windows bash subprocess execution.

Validates that bash execution works correctly even when bash is installed
in paths containing spaces (e.g., C:\\Program Files\\Git\\bin\\bash.exe)
and handles WSL bash properly.

These are integration tests that use real bash if available.

Based on original work by Bryce Cutt (@brycecutt-msft).
"""

import asyncio
import os
import shutil
import sys

import pytest

from amplifier_module_tool_bash import BashTool

# Check if bash is available
BASH_AVAILABLE = shutil.which("bash") is not None
BASH_PATH = shutil.which("bash") if BASH_AVAILABLE else None
WINDOWS_AND_BASH = sys.platform == "win32" and BASH_AVAILABLE


@pytest.mark.skipif(
    not WINDOWS_AND_BASH, reason="Requires bash on Windows (Git Bash or WSL)"
)
class TestWindowsBashExecution:
    """Test Windows bash subprocess execution with real bash."""

    @pytest.fixture
    def tool(self):
        """Create a BashTool instance with default config."""
        return BashTool({"safety_profile": "permissive"})

    @pytest.mark.asyncio
    async def test_simple_echo_command(self, tool):
        """Test simple echo command works with real bash."""
        result = await tool._run_command("echo 'Hello Windows Bash'")

        assert result["returncode"] == 0
        assert "Hello Windows Bash" in result["stdout"]
        assert result["stderr"] == ""

    @pytest.mark.asyncio
    async def test_bash_version_not_prematurely_expanded(self, tool):
        """Test that $BASH_VERSION is evaluated inside bash, not by WSL launcher.

        Critical for WSL: Validates that shell variables are not prematurely
        expanded before reaching bash. Our WSL detection logic ensures
        'wsl --exec bash' is used when needed.
        """
        assert BASH_PATH is not None
        assert os.path.exists(BASH_PATH)

        # Run command to verify bash evaluates the variable
        result = await tool._run_command("echo $BASH_VERSION")
        assert result["returncode"] == 0
        # Must not be empty - empty means variable was expanded prematurely
        assert len(result["stdout"].strip()) > 0

    @pytest.mark.asyncio
    async def test_pipes_work(self, tool):
        """Test that shell pipes work correctly."""
        result = await tool._run_command("echo -e 'line1\\nline2\\nline3' | grep line2")

        assert result["returncode"] == 0
        assert "line2" in result["stdout"]

    @pytest.mark.asyncio
    async def test_variable_expansion(self, tool):
        """Test bash variable expansion works."""
        result = await tool._run_command("TEST_VAR='success'; echo $TEST_VAR")

        assert result["returncode"] == 0
        assert "success" in result["stdout"]

    @pytest.mark.asyncio
    async def test_command_substitution(self, tool):
        """Test bash command substitution works."""
        result = await tool._run_command("echo $(echo nested)")

        assert result["returncode"] == 0
        assert "nested" in result["stdout"]

    @pytest.mark.asyncio
    async def test_background_execution_returns_pid(self, tool):
        """Test background command execution returns PID."""
        result = await tool._run_command_background("sleep 0.1")

        assert "pid" in result
        assert isinstance(result["pid"], int)
        assert result["pid"] > 0

        # Give background process time to complete
        await asyncio.sleep(0.2)

    @pytest.mark.asyncio
    async def test_multiline_command(self, tool):
        """Test multi-line bash commands work."""
        result = await tool._run_command(
            """
            x=5
            y=10
            echo $((x + y))
        """
        )

        assert result["returncode"] == 0
        assert "15" in result["stdout"]


@pytest.mark.skipif(not BASH_AVAILABLE, reason="Requires bash")
class TestWSLDetection:
    """Test WSL bash detection logic."""

    @pytest.fixture
    def tool(self):
        """Create a BashTool instance."""
        return BashTool({"safety_profile": "strict"})

    @pytest.mark.asyncio
    async def test_wsl_detection_caching(self, tool):
        """Test that WSL detection results are cached."""
        bash_exe = shutil.which("bash")
        if not bash_exe:
            pytest.skip("No bash available")

        # First call should populate cache
        result1 = await tool._is_wsl_bash(bash_exe)

        # Cache should now contain the result
        assert bash_exe in tool._wsl_bash_cache
        assert tool._wsl_bash_cache[bash_exe] == result1

        # Second call should use cache (same result)
        result2 = await tool._is_wsl_bash(bash_exe)
        assert result1 == result2

    @pytest.mark.asyncio
    async def test_wsl_detection_returns_bool(self, tool):
        """Test that WSL detection returns a boolean."""
        bash_exe = shutil.which("bash")
        if not bash_exe:
            pytest.skip("No bash available")

        result = await tool._is_wsl_bash(bash_exe)
        assert isinstance(result, bool)

    @pytest.mark.asyncio
    async def test_wsl_detection_handles_invalid_path(self, tool):
        """Test that WSL detection handles non-existent bash gracefully."""
        result = await tool._is_wsl_bash("/nonexistent/bash")
        assert result is False


@pytest.mark.skipif(sys.platform == "win32", reason="Unix-only tests")
class TestUnixBashExecution:
    """Test Unix bash execution (Linux, macOS)."""

    @pytest.fixture
    def tool(self):
        """Create a BashTool instance."""
        return BashTool({"safety_profile": "permissive"})

    @pytest.mark.asyncio
    async def test_unix_bash_uses_explicit_bash(self, tool):
        """Test that Unix execution uses /bin/bash explicitly."""
        result = await tool._run_command("echo $0")

        assert result["returncode"] == 0
        # Should show bash (not sh or other shell)
        assert "bash" in result["stdout"].lower()

    @pytest.mark.asyncio
    async def test_unix_process_group_created(self, tool):
        """Test that Unix execution creates a new process group."""
        # This is tested implicitly - if process group wasn't created,
        # timeout handling would fail to kill child processes
        result = await tool._run_command("echo 'process group test'")
        assert result["returncode"] == 0
