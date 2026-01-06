#!/usr/bin/env python3
"""
Manual tests for bash tool fixes.

Tests:
1. run_in_background parameter works
2. Process group cleanup on timeout (kills children)  
3. Timeout behavior is correct
"""

import asyncio
import os
import sys
import time
import subprocess

# Create mock for amplifier_core before importing the module
class MockToolResult:
    def __init__(self, success: bool, output: dict = None, error: dict = None):
        self.success = success
        self.output = output or {}
        self.error = error or {}
    
    def __repr__(self):
        if self.success:
            return f"ToolResult(success=True, output={self.output})"
        return f"ToolResult(success=False, error={self.error})"


class MockModuleCoordinator:
    async def mount(self, *args, **kwargs):
        pass


# Create mock module
class MockAmplifierCore:
    ToolResult = MockToolResult
    ModuleCoordinator = MockModuleCoordinator

# Inject mock before importing
sys.modules['amplifier_core'] = MockAmplifierCore()

# Now add module path and import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from amplifier_module_tool_bash import BashTool


def count_processes(pattern: str) -> int:
    """Count processes matching pattern, excluding grep/pgrep itself."""
    # Use ps + grep instead of pgrep to have more control
    result = subprocess.run(
        f"ps aux | grep '{pattern}' | grep -v grep | grep -v 'ps aux' | wc -l",
        shell=True, capture_output=True, text=True
    )
    return int(result.stdout.strip() or "0")


def find_processes(pattern: str) -> list[int]:
    """Find PIDs matching pattern, excluding grep/pgrep itself."""
    result = subprocess.run(
        f"ps aux | grep '{pattern}' | grep -v grep | grep -v 'ps aux'",
        shell=True, capture_output=True, text=True
    )
    pids = []
    for line in result.stdout.strip().split('\n'):
        if line:
            parts = line.split()
            if len(parts) >= 2:
                try:
                    pids.append(int(parts[1]))
                except ValueError:
                    pass
    return pids


async def test_basic_command():
    """Test basic command execution still works."""
    print("\n=== Test 1: Basic command execution ===")
    tool = BashTool({"timeout": 10})
    
    result = await tool.execute({"command": "echo 'hello world'"})
    print(f"Result: {result}")
    
    assert result.success, "Basic command should succeed"
    assert "hello world" in result.output["stdout"], "Output should contain 'hello world'"
    print("✓ Basic command works")


async def test_safety_error_includes_reason():
    """Test that safety rejection error message includes the specific reason."""
    print("\n=== Test 1b: Safety error includes rejection reason ===")
    tool = BashTool({"timeout": 10})
    
    # Test suspicious pattern detection
    result = await tool.execute({"command": "git commit -m 'use brew services instead of sudo tailscaled'"})
    print(f"Result: {result}")
    
    assert not result.success, "Command with 'sudo' in text should be rejected"
    error_msg = result.error.get("message", "")
    assert "sudo" in error_msg.lower(), f"Error should mention 'sudo' pattern, got: {error_msg}"
    assert "suspicious pattern" in error_msg.lower(), f"Error should mention 'suspicious pattern', got: {error_msg}"
    print(f"✓ Safety error includes reason: {error_msg}")
    
    # Test denied command detection
    result2 = await tool.execute({"command": "rm -rf / --no-preserve-root"})
    print(f"Result2: {result2}")
    
    assert not result2.success, "rm -rf should be rejected"
    error_msg2 = result2.error.get("message", "")
    assert "rm -rf" in error_msg2.lower(), f"Error should mention 'rm -rf' pattern, got: {error_msg2}"
    print(f"✓ Denied command error includes reason: {error_msg2}")


async def test_input_schema():
    """Test that input schema includes run_in_background."""
    print("\n=== Test 2: Input schema includes run_in_background ===")
    tool = BashTool({})
    
    schema = tool.input_schema
    print(f"Schema properties: {list(schema['properties'].keys())}")
    
    assert "run_in_background" in schema["properties"], "Schema should include run_in_background"
    assert schema["properties"]["run_in_background"]["type"] == "boolean", "run_in_background should be boolean"
    print("✓ Input schema correctly includes run_in_background parameter")


async def test_run_in_background():
    """Test run_in_background parameter returns immediately."""
    print("\n=== Test 3: run_in_background parameter ===")
    tool = BashTool({"timeout": 10})
    
    # Start a long-running process in background
    start = time.time()
    result = await tool.execute({
        "command": "sleep 30",  # Would normally block for 30 seconds
        "run_in_background": True
    })
    elapsed = time.time() - start
    
    print(f"Result: {result}")
    print(f"Elapsed time: {elapsed:.2f}s")
    
    assert result.success, "Background command should succeed"
    assert "pid" in result.output, "Should return PID"
    assert elapsed < 1, f"Should return immediately, took {elapsed:.2f}s"
    
    # Clean up the background process
    pid = result.output["pid"]
    try:
        os.kill(pid, 9)
    except ProcessLookupError:
        pass
    
    print(f"✓ run_in_background works (returned in {elapsed:.2f}s with PID {pid})")


async def test_timeout_behavior():
    """Test that timeout works correctly."""
    print("\n=== Test 4: Timeout behavior ===")
    tool = BashTool({"timeout": 2})
    
    start = time.time()
    result = await tool.execute({"command": "sleep 10"})
    elapsed = time.time() - start
    
    print(f"Result: {result}")
    print(f"Elapsed time: {elapsed:.2f}s")
    
    assert not result.success, "Should fail due to timeout"
    assert "timed out" in result.error.get("message", "").lower()
    assert 1.5 < elapsed < 4, f"Should timeout in ~2s, took {elapsed:.2f}s"
    print(f"✓ Timeout works correctly ({elapsed:.2f}s)")


async def test_process_group_cleanup():
    """Test that timeout kills entire process tree, not just parent."""
    print("\n=== Test 5: Process group cleanup on timeout ===")
    
    # Use a unique sleep duration as marker
    sleep_duration = 98765  # Unique value unlikely to exist
    
    # Verify no existing processes with this marker
    initial_count = count_processes(f"sleep {sleep_duration}")
    print(f"Initial processes with 'sleep {sleep_duration}': {initial_count}")
    
    tool = BashTool({"timeout": 2})
    
    # Command that spawns a child process
    start = time.time()
    result = await tool.execute({
        "command": f"bash -c 'sleep {sleep_duration}'"
    })
    elapsed = time.time() - start
    
    print(f"Result: {result}")
    print(f"Elapsed time: {elapsed:.2f}s")
    
    assert not result.success, "Should fail due to timeout"
    assert "timed out" in result.error.get("message", "").lower()
    
    # Give cleanup time to complete
    await asyncio.sleep(1)
    
    # Check for orphaned processes
    final_count = count_processes(f"sleep {sleep_duration}")
    print(f"Final processes with 'sleep {sleep_duration}': {final_count}")
    
    assert final_count == 0, f"Should have no orphaned processes, got {final_count}"
    print(f"✓ Process group cleanup works (no orphaned processes)")


async def test_complex_background_server():
    """Test starting a server in background and connecting to it."""
    print("\n=== Test 6: Background server scenario ===")
    tool = BashTool({"timeout": 10})
    
    # Find an available port
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        port = s.getsockname()[1]
    
    # Start a simple server in background using run_in_background
    result = await tool.execute({
        "command": f"python3 -m http.server {port}",
        "run_in_background": True
    })
    
    print(f"Server start result: {result}")
    assert result.success, "Background server should start"
    server_pid = result.output["pid"]
    
    # Give server time to start
    await asyncio.sleep(1)
    
    # Test the server with a foreground command
    test_result = await tool.execute({
        "command": f"curl -s http://localhost:{port} 2>&1 | head -1"
    })
    print(f"Curl result: {test_result}")
    
    # Clean up server
    try:
        os.kill(server_pid, 9)
    except ProcessLookupError:
        pass
    
    assert test_result.success, "Curl should succeed"
    print("✓ Background server scenario works perfectly")


async def test_shell_ampersand_behavior():
    """Test that shell & with timeout works correctly (times out but cleans up)."""
    print("\n=== Test 7: Shell & behavior (expected timeout with cleanup) ===")
    
    sleep_duration = 87654  # Unique value
    tool = BashTool({"timeout": 2})
    
    start = time.time()
    result = await tool.execute({
        "command": f"sleep {sleep_duration} &"
    })
    elapsed = time.time() - start
    
    print(f"Result: {result}")
    print(f"Elapsed time: {elapsed:.2f}s")
    
    # Shell & causes timeout because backgrounded process inherits pipes
    # This is expected - users should use run_in_background instead
    assert not result.success, "Should timeout (expected behavior with shell &)"
    assert elapsed < 4, f"Should timeout in ~2s, took {elapsed:.2f}s"
    
    # But cleanup should still work
    await asyncio.sleep(1)
    final_count = count_processes(f"sleep {sleep_duration}")
    print(f"Cleanup check: {final_count} processes remaining")
    
    assert final_count == 0, f"Process group should be cleaned up, got {final_count}"
    print("✓ Shell & times out as expected but cleanup works (use run_in_background instead)")


async def test_multiple_child_processes():
    """Test that timeout kills all child processes."""
    print("\n=== Test 8: Multiple child process cleanup ===")
    
    sleep_duration = 76543  # Unique value
    tool = BashTool({"timeout": 2})
    
    # Spawn multiple sleep processes
    result = await tool.execute({
        "command": f"sleep {sleep_duration} & sleep {sleep_duration} & sleep {sleep_duration} & wait"
    })
    
    print(f"Result: {result}")
    assert not result.success, "Should timeout"
    
    await asyncio.sleep(1)
    
    # Check all children were cleaned up
    final_count = count_processes(f"sleep {sleep_duration}")
    print(f"Remaining processes: {final_count}")
    
    assert final_count == 0, f"All child processes should be cleaned up, got {final_count}"
    print("✓ Multiple child processes cleaned up correctly")


async def main():
    """Run all tests."""
    print("=" * 60)
    print("Bash Tool Fixes - Test Suite")
    print("=" * 60)
    
    tests = [
        test_basic_command,
        test_safety_error_includes_reason,
        test_input_schema,
        test_run_in_background,
        test_timeout_behavior,
        test_process_group_cleanup,
        test_complex_background_server,
        test_shell_ampersand_behavior,
        test_multiple_child_processes,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            await test()
            passed += 1
        except Exception as e:
            print(f"✗ FAILED: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
