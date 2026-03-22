"""Tests for max_concurrent configuration in BashTool.

Tests cover:
- Default max_concurrent is None
- Config sets max_concurrent value
- Active count starts at 0
- Rejects concurrent call when at limit
- Allows sequential calls
- Counter resets on error
- Counter resets on timeout
- No limit when None
"""

import pytest
from unittest.mock import AsyncMock, patch

from amplifier_module_tool_bash import BashTool


class TestMaxConcurrentConfig:
    """Tests for max_concurrent configuration settings."""

    def test_default_max_concurrent_is_none(self):
        """Default max_concurrent should be None (no limit)."""
        tool = BashTool({})
        assert tool.max_concurrent is None

    def test_max_concurrent_from_config(self):
        """max_concurrent should be set from config."""
        tool = BashTool({"max_concurrent": 3})
        assert tool.max_concurrent == 3

    def test_active_count_starts_at_zero(self):
        """_active_commands should start at 0."""
        tool = BashTool({})
        assert tool._active_commands == 0


class TestMaxConcurrentEnforcement:
    """Tests for max_concurrent enforcement during execution."""

    @pytest.mark.asyncio
    async def test_rejects_concurrent_call(self):
        """Should reject when active commands >= max_concurrent."""
        tool = BashTool({"max_concurrent": 1})
        # Simulate an active command already running
        tool._active_commands = 1

        result = await tool.execute({"command": "echo test"})

        assert not result.success
        assert result.error is not None
        # Error message should mention concurrent limit
        error_msg = result.error.get("message", "") if result.error else ""
        assert "concurrent" in error_msg.lower() or "limit" in error_msg.lower()

    @pytest.mark.asyncio
    async def test_allows_sequential_calls(self):
        """Sequential calls should both succeed (counter resets after each)."""
        tool = BashTool({"max_concurrent": 1, "safety_profile": "unrestricted"})

        with patch.object(tool, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"stdout": "hello", "stderr": "", "returncode": 0}

            result1 = await tool.execute({"command": "echo hello"})
            result2 = await tool.execute({"command": "echo hello"})

        assert result1.success
        assert result2.success
        assert tool._active_commands == 0

    @pytest.mark.asyncio
    async def test_counter_resets_on_error(self):
        """_active_commands should decrement even when command raises an error."""
        tool = BashTool({"max_concurrent": 2, "safety_profile": "unrestricted"})

        with patch.object(tool, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.side_effect = Exception("Unexpected execution error")

            result = await tool.execute({"command": "echo test"})

        assert not result.success
        assert tool._active_commands == 0

    @pytest.mark.asyncio
    async def test_counter_resets_on_timeout(self):
        """_active_commands should decrement on timeout."""
        tool = BashTool({"max_concurrent": 2, "safety_profile": "unrestricted"})

        with patch.object(tool, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.side_effect = TimeoutError("Command timed out")

            result = await tool.execute({"command": "echo test"})

        assert not result.success
        assert tool._active_commands == 0

    @pytest.mark.asyncio
    async def test_no_limit_when_none(self):
        """No concurrent limit when max_concurrent is None."""
        tool = BashTool(
            {"safety_profile": "unrestricted"}
        )  # max_concurrent defaults to None
        assert tool.max_concurrent is None

        # Manually set absurdly high active count to prove no check happens
        tool._active_commands = 999

        with patch.object(tool, "_run_command", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = {"stdout": "hello", "stderr": "", "returncode": 0}

            result = await tool.execute({"command": "echo test"})

        assert result.success
