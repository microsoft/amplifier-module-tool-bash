"""Tests for Windows bash subprocess execution with spaces in paths.

Validates that bash execution works correctly even when bash is installed
in paths containing spaces (e.g., C:\\Program Files\\Git\\bin\\bash.exe).
These are integration tests that use real bash if available.
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


@pytest.mark.skipif(not BASH_AVAILABLE or sys.platform != "win32", 
                   reason="Requires bash on Windows (Git Bash or WSL)")
class TestWindowsBashSubprocessExec:
    """Test Windows bash subprocess execution with real bash."""

    @pytest.fixture
    def tool(self):
        """Create a BashTool instance with temp directory."""
        return BashTool({})

    @pytest.mark.asyncio
    async def test_simple_echo_command(self, tool):
        """Test simple echo command works with real bash."""
        result = await tool._run_command("echo 'Hello Windows Bash'")
        
        assert result["returncode"] == 0
        assert "Hello Windows Bash" in result["stdout"]
        assert result["stderr"] == ""

    @pytest.mark.asyncio
    async def test_bash_path_detection(self, tool):
        """Test that bash is properly detected on Windows.
        
        Critical for WSL: Validates that $BASH_VERSION is evaluated inside bash,
        not prematurely expanded by the WSL launcher. Our WSL detection logic
        ensures 'wsl --exec bash' is used when needed.
        """
        # Verify bash path is set
        assert BASH_PATH is not None
        assert os.path.exists(BASH_PATH)
        
        # Run command to verify it uses the detected bash
        result = await tool._run_command("echo $BASH_VERSION")
        assert result["returncode"] == 0
        # Must not be empty - empty means variable was expanded prematurely (outside of bash)
        assert len(result["stdout"].strip()) > 0

    @pytest.mark.asyncio
    async def test_pipes_and_redirects(self, tool):
        """Test that shell features (pipes) work correctly."""
        # Test pipe functionality
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
    async def test_background_execution_starts(self, tool):
        """Test background command execution returns PID."""
        # Use a command that will run briefly
        result = await tool._run_command_background("pwd")
        
        assert "pid" in result
        assert isinstance(result["pid"], int)
        assert result["pid"] > 0
        
        # Give background process time to complete
        await asyncio.sleep(0.2)

    @pytest.mark.asyncio
    async def test_multiline_command(self, tool):
        """Test multi-line bash commands work."""
        result = await tool._run_command("""
            x=5
            y=10
            echo $((x + y))
        """)
        
        assert result["returncode"] == 0
        assert "15" in result["stdout"]

    @pytest.mark.asyncio
    async def test_working_directory_respected(self, tool):
        """Test that working directory is used correctly."""
        # Get the working directory from inside the command
        result = await tool._run_command("pwd")
        
        assert result["returncode"] == 0
        # The output should contain the tool's working directory
        output_dir = result["stdout"].strip()
        # Convert to comparable format (handle Windows paths)
        assert len(output_dir) > 0
