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
- `timeout` (int, optional): Timeout in seconds (default: 30). Increase for builds, tests, or monitoring. Use `run_in_background` for truly indefinite processes.
- `run_in_background` (bool, optional): Run command in background, returning immediately with PID (default: false)

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
- ✅ Full bash shell if Git Bash or WSL bash is found (auto-detected)
- ⚠️ Falls back to simple commands with no shell features if neither is found
- 💡 Git Bash and WSL bash use different path/`$HOME`/toolchain conventions
  (`/c/...` vs `/mnt/c/...`); the tool's `bash` description names which one
  was resolved and its conventions. Set `windows_shell` config (or the
  `AMPLIFIER_BASH_WINDOWS_SHELL` env var) to `"wsl"` or `"gitbash"` to force
  a choice; default `"auto"` prefers whatever is found via `PATH` first
  (WSL, if both are installed), falling back to well-known Git-for-Windows
  install locations if `PATH` resolves nothing.

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

## Optional managed process sessions

Set `managed_processes = true` in the tool's host configuration to expose
additional actions on the existing `bash` tool. Ordinary calls (or
`action = "run"`) and `run_in_background` keep their existing behavior. Managed
processes currently support POSIX hosts (Linux/macOS/WSL Python); native Windows
hosts return an explicit unsupported error for `start`. Pipes are the default.
Set trusted host `managed_pty = true` and per-start `pty = true` for a real
POSIX controlling terminal. Terminal output combines stdout/stderr; `pty`,
`output_streams`, and `eof_semantics` identify this in every status receipt.
Terminal sizing and attaching after host death are not provided.

```python
# All actions must use the host's ordinary tool dispatcher and approval hooks.
started = await session.call_tool("bash", {
    "action": "start", "command": "npm run build", "timeout": 300
})
process_id = started.output["process_id"]
page = await session.call_tool("bash", {
    "action": "wait", "process_id": process_id,
    "cursor": started.output["next_cursor"], "wait_ms": 1000
})
```

| Action | Parameters and behavior |
| --- | --- |
| `start` | `command` required; `timeout` is the maximum process lifetime in seconds (1–3600, default tool timeout). Returns immediately after spawn with an opaque `process_id`. Optional `pty` requires host opt-in; `question_ids` binds exact required answers. |
| `read` | `process_id`, `cursor` (default 0), `max_bytes` (4096–100000, default 16384). Reads an output page without consuming it globally. |
| `wait` | Same as `read`, plus `wait_ms` (0–60000, default 1000). Waits for new output or completion. Expiration does not cancel the process. |
| `status` | `process_id`. Returns process state and counters without output chunks. |
| `write` | `process_id`, optional `stdin` (at most 65536 UTF-8 bytes) and `close_stdin` (EOF). Raw input requires the host policy below. |
| `terminate` | `process_id`. Requests cancellation, cleans up the owned process group and waits for observation of the result. Repeating it after completion is harmless. |
| `list` | Lists only processes owned by this mounted tool instance. |

Follow-up actions reject `command`, `timeout`, and `run_in_background`, including
an innocuous `command` added to match a shell auto-approval rule. Every action
retains the tool name `bash`, approval metadata, and normal `tool:pre`/`tool:post`
attribution; tools do not dispatch around approval hooks. Hosts must present
the action, target process, and input in approval details. A generic command
allowlist is not an authorization policy for interactive input.

Raw stdin is disabled by default. To grant it, trusted mount configuration
must set **both** `managed_stdin = true` and `safety_profile = "unrestricted"`,
with no `allowed_commands`, `denied_commands`, or `safety_overrides`. These are
host options, never tool arguments. Input to an interpreter cannot be safely
validated as an independent bash command, so restricted profiles fail closed
instead of letting stdin evade their command policy. `close_stdin` without data
remains available for pipes. For a terminal it sends canonical EOF and disables
further input from this handle; raw-mode terminals reject EOF explicitly because
a terminal cannot be half-closed like a pipe. Applications needing a finer input policy should wait for a
host stdin-authorization adapter. Input writes are not idempotent: a cancelled
or timed-out write may already have delivered bytes; never automatically retry.

Responses contain `state` (`running`, `cancel_requested`, `completed`, `failed`,
`cancelled`, or `outcome_unknown`), the observed `returncode` (null until known),
`cancellation_requested`, `termination_reason` (`cancel`, `timeout`,
`session_closed`, or null), and `output_complete`. A successfully observed
nonzero exit has `ToolResult.success = true` with `state = "failed"`: the tool
action succeeded; the command did not. Read `state` and `returncode` to judge
command success. Cancellation requested is distinct from cancellation observed;
terminating a command already observed as exited preserves its exit result.

Output is an ordered list of `chunks` containing stream, text, source byte
count, and cursor. Stdout/stderr retain their stream identities; their combined
order is the order the host read them, not a guarantee of inter-stream write
order. UTF-8 split across reads is preserved. Binary chunks use the ordinary
bash binary-output guard. Advance to `next_cursor` only after consuming the
page; rereading a cursor is repeatable while retained. `has_more` reports more
buffered output. Cursors are chunk sequence numbers, not byte offsets.

The buffer retains at most `managed_max_output_bytes` (default 100000, allowed
4096–10000000) and 1024 chunks per process. Older output is dropped with explicit
`dropped_output_bytes`, `earliest_cursor`, and `cursor_expired` metadata. A
stale cursor returns retained output and signals the gap; it never pretends to
have complete historical output. For durable full output, arrange a file or a
host-owned output collector. `max_bytes` budgets raw source bytes; rendered
replacement characters and binary notices can have different text sizes.

Process handles belong to one mounted tool instance. They cannot be read or
terminated by another session, including a fork. `max_concurrent` counts managed
processes throughout their lifetime together with ordinary foreground calls.
`managed_max_processes` bounds retained records (default 32, allowed 1–256);
once full, a new start evicts the oldest completed record or rejects if all are
still active. Evicted IDs fail explicitly.

The cleanup callback returned by `mount` must be run when the owning session
closes. It terminates owned groups and collects final exit/output state, including
starts racing with shutdown. A normal command exit also closes its remaining
process group. Process-tree cleanup uses the existing POSIX descendant discovery
and group teardown; deliberately escaped/reparented external processes cannot be
guaranteed to remain owned. Abrupt host death cannot run cleanup.

This is an **in-memory lifecycle**, not a durable process broker. A host restart
does not restore handles, output, or observation, and never replays commands.
Hosts persisting operation receipts should mark interrupted observations as
outcome unknown after restart, and must not infer completion or retry mutations.

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

`list` also reports trusted `stdin_allowed` and `pty` availability, so hosts can
fail closed before opening an interpreter. These are observed mount policies,
not action-settable permissions.

### Optional operation observer capability

A host can register `operations.observe` on the coordinator as a local callable
accepting one JSON-compatible event. The mounted tool looks it up when a managed
process starts; no app imports, URL destinations, credentials, or agent-supplied
callbacks are involved. Hosts bind their real session identity outside the event
and must not trust a tool-supplied owner ID for authorization.

Events use `schemaVersion: 1`, stable `operationId` (the process handle),
`ownerId` (the mounted registry), monotonic `sequence`, `eventId`, `source:
"tool-bash"`, `kind: "process"`, and timestamp `at`. Phases are `started`,
`output` (one bounded `chunk` with its output cursor), `state` (for example
cancellation requested), and `finished` (observed terminal `status`). Commands
and stdin are not copied into the observation stream. Output is already subject
to the normal binary guard and can contain sensitive command results; the host
owns private storage and presentation policy. Chunks flag `binary_output_withheld`
and `encoding_loss` when rendered text cannot preserve the original bytes; a
host must treat either as incomplete original evidence, including after exit.

Each process has a bounded 32-event mailbox. Subprocess readers never await the
observer. Async observer calls have a 500 ms deadline; synchronous observers must
be cheap and nonblocking. Output can be dropped under backpressure or observer
failure: source sequence/cursor gaps and `observerDroppedEvents` make that loss
explicit. Failed events are never retried. Start waits for the initial bounded
observation attempt; cleanup drains remaining observations before returning.
`observer_available` and `observer_dropped_events` in normal process status
report whether an observer was present and whether delivery failed. Observer
availability is not a guarantee of durable storage.

A durable host must deduplicate events, record missing evidence, preserve actual
terminal results, and mark active receipts outcome unknown after losing their
owner. The module's local output ring can expire independently of a host's
archive. `output_complete` on process status means streams were drained, not
that either archive retains every byte. The observer's task and callbacks end
with the owned process; no observation or execution is restarted automatically.


Managed starts may include `question_ids` (at most 32 unique IDs). The module
uses the optional trusted `questions.admit` capability under its lifecycle fence
immediately before spawning, after the host dispatcher has completed approvals.
Absent capability, pending/cancelled/superseded or wrong-conversation answers
fail closed. Omitting the list leaves independent work independent. This is a
dependency check, never a substitute for tool permission. The capability must
return `{"admitted": true, "questionIds": [the exact IDs]}`; silence, false and
mismatched acknowledgment never admit work. Hosts can call the
public `validate_process_owner(process_id, owner_id)` immediately after approval
to verify an identity-bound control against the mounted owner.
