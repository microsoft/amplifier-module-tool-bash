# Amplifier Bash Tool Module

Shell command execution for Amplifier agents.

## Purpose

Enables agents to execute bash commands in a controlled environment for system interactions, build operations, and automation tasks.

## Contract

**Module Type:** Tool
**Mount Point:** `tools`
**Entry Point:** `amplifier_mod_tool_bash:mount`

## Tools Provided

### `bash`
Execute a bash command.

**Input:**
- `command` (string): The bash command to execute
- `timeout` (int, optional): Timeout in seconds (default: 30)

**Output:**
- Command output (stdout/stderr combined)
- Exit code
- Timeout indication if applicable

## Configuration

```toml
[[tools]]
module = "tool-bash"
config = {
    timeout = 30,  # Default timeout in seconds
    require_approval = false,
    allowed_commands = []  # Empty = all allowed
}
```

## Security

**IMPORTANT**: Bash execution can be dangerous. Use with caution:

- Set `require_approval = true` for production
- Use `allowed_commands` to whitelist safe commands
- Run in isolated/containerized environments
- Never execute untrusted user input

## Usage Example

```python
# Agent uses bash tool
result = await session.call_tool("bash", {
    "command": "ls -la",
    "timeout": 10
})
```

## Dependencies

- `amplifier-core>=1.0.0`

## Contributing

> [!NOTE]
> This project is not currently accepting external contributions, but we're actively working toward opening this up. We value community input and look forward to collaborating in the future. For now, feel free to fork and experiment!

Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit [Contributor License Agreements](https://cla.opensource.microsoft.com).

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
