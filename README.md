# Amplifier Bash Tool Module

Shell command execution for Amplifier agents.

## Prerequisites

- **Python 3.11+**
- **[UV](https://github.com/astral-sh/uv)** - Fast Python package manager

### Installing UV

```bash
# macOS/Linux/WSL
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

## Purpose

Enables agents to execute bash commands in a controlled environment for system interactions, build operations, and automation tasks.

**Platform Behavior:**
- **Linux/macOS/WSL**: Full bash shell with all features (pipes, redirects, &&, ||, ~, $VAR, etc.)
- **Windows**: Limited to simple commands without shell operators (use full paths)

## Contract

**Module Type:** Tool
**Mount Point:** `tools`
**Entry Point:** `amplifier_module_tool_bash:mount`

## Tools Provided

### `bash`

Execute a bash command with platform-appropriate shell.

**Input:**

- `command` (string): The bash command to execute
- `timeout` (int, optional): Timeout in seconds (default: 30)

**Output:**

- `stdout`: Standard output from command
- `stderr`: Standard error from command
- `returncode`: Exit code (0 = success)

**Platform Support:**

**Unix-like (Linux, macOS, WSL)**:
- ✅ Full bash shell (`/bin/bash`)
- ✅ Pipes: `ls | grep foo`
- ✅ Operators: `cmd1 && cmd2`, `cmd1 || cmd2`
- ✅ Redirects: `cmd > file`, `cmd 2>&1`, `cmd &> file`
- ✅ Tilde expansion: `~/.amplifier`
- ✅ Variables: `$HOME`, `${VAR}`
- ✅ Command substitution: `$(pwd)`, `` `date` ``
- ✅ Heredocs: `cat <<EOF`

**Windows (native)**:
- ⚠️ Limited to simple commands
- ❌ Shell operators not supported
- 💡 Use full paths: `C:\Users\...` not `~`
- 💡 For shell features, use WSL

## Configuration

```toml
[[tools]]
module = "tool-bash"
config = {
    working_dir = ".",           # Working directory (defaults to session.working_dir capability)
    timeout = 30,                # Default timeout in seconds
    require_approval = false,
    safety_profile = "strict",   # Safety profile: strict, standard, permissive, unrestricted
    allowed_commands = [],       # Allowlist patterns (supports wildcards)
    denied_commands = [],        # Additional custom blocked patterns
    safety_overrides = {         # Fine-grained overrides
        allow = [],              # Patterns to allow (even if normally blocked)
        block = []               # Patterns to block (even if normally allowed)
    }
}
```

> **Note**: If `working_dir` is not set in config, the module uses the `session.working_dir` coordinator capability if available, falling back to `Path.cwd()`. This enables correct behavior in server/web deployments where the process cwd differs from the user's project directory.

## Safety Profiles

The bash tool uses a profile-based safety system with smart pattern matching.

### Available Profiles

| Profile | `sudo` | `rm -rf /` | Use Case |
|---------|--------|------------|----------|
| **`strict`** (default) | ❌ Blocked | ❌ Blocked | Workstations, shared environments |
| **`standard`** | ❌ (allowlist can override) | ❌ Blocked | Trusted environments with specific needs |
| **`permissive`** | ✅ Allowed | ❌ Blocked | Containers, VMs, dedicated instances |
| **`unrestricted`** | ✅ Allowed | ✅ Allowed | Dedicated hardware (e.g., Raspberry Pi) |

### Smart Pattern Matching

The safety system distinguishes between actual commands and text in strings/paths:

```bash
# ✅ ALLOWED - "sudo" is in a quoted string, not a command
echo "use sudo for admin tasks"

# ✅ ALLOWED - path contains /dev/ but isn't a device redirect  
cd ~/dev/my-project

# ❌ BLOCKED - actual sudo command
sudo apt install vim

# ❌ BLOCKED - actual device redirect
cat file > /dev/sda
```

### Overriding Safety Rules

For containers, VMs, or dedicated hardware where you want elevated access:

```toml
# Allow sudo for container/VM environments
config = { safety_profile = "permissive" }

# Allow specific sudo commands only
config = {
    safety_profile = "standard",
    allowed_commands = ["sudo systemctl *", "sudo apt *"]
}

# Full access for dedicated hardware
config = { safety_profile = "unrestricted" }
```

## Security

**IMPORTANT**: Bash execution can be dangerous. Use with caution:

- Use `strict` profile (default) for shared/workstation environments
- Set `require_approval = true` for production
- Use `allowed_commands` to whitelist safe commands
- Use `permissive` or `unrestricted` only in isolated environments
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
