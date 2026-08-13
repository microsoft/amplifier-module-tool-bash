"""Structural validation tests for bash tool.

Inherits authoritative tests from amplifier-core.
"""

import pytest
from amplifier_core.validation.structural import ToolStructuralTests

from amplifier_module_tool_bash import BashTool


class TestBashToolStructural(ToolStructuralTests):
    """Run standard tool structural tests for bash.

    All tests from ToolStructuralTests run automatically.
    Add module-specific structural tests below if needed.
    """


class TestTimeoutValidation:
    def test_input_schema_includes_timeout_bounds(self):
        tool = BashTool({})
        timeout_schema = tool.input_schema["properties"]["timeout"]
        assert timeout_schema["minimum"] == 1
        assert timeout_schema["maximum"] == 3600

    @pytest.mark.parametrize(
        "bad_timeout",
        [
            True,  # bool must be rejected (bool is an int subclass in Python)
            0,
            -1,
            3601,
            1.5,
            "30",
            None,
        ],
    )
    def test_config_timeout_rejected(self, bad_timeout):
        with pytest.raises((TypeError, ValueError), match=r"seconds"):
            BashTool({"timeout": bad_timeout})

    @pytest.mark.parametrize(
        "bad_timeout",
        [
            True,
            0,
            -1,
            3601,
            1.5,
            "30",
            None,
        ],
    )
    @pytest.mark.asyncio
    async def test_caller_timeout_rejected(self, bad_timeout):
        tool = BashTool({})
        result = await tool.execute({"command": "echo ok", "timeout": bad_timeout})
        assert result.success is False
        assert isinstance(result.output, str)
        assert "seconds" in result.output

    @pytest.mark.asyncio
    async def test_caller_timeout_rejects_ms_looking_value_with_hint(self):
        tool = BashTool({})
        result = await tool.execute({"command": "echo ok", "timeout": 1_200_000})
        assert result.success is False
        assert isinstance(result.output, str)
        assert "seconds" in result.output
        # Regression: suggest a plausible seconds value if caller likely passed ms.
        assert "1200" in result.output

    @pytest.mark.asyncio
    async def test_execute_timeout_still_works_with_valid_value(self):
        tool = BashTool({})
        result = await tool.execute({"command": "echo ok", "timeout": 5})
        assert result.success is True
        assert isinstance(result.output, dict)
        assert result.output["returncode"] == 0
        assert "ok" in result.output["stdout"]
