"""Session-owned subprocesses. The bash adapter remains the policy boundary.

No process-global registry, disk restore, automatic retries, or shell execution
outside the existing bash tool. Hosts must dispatch every action through their
normal tool:pre/tool:post path (including write and terminate).
"""

from __future__ import annotations

import asyncio
import codecs
import sys
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from amplifier_core import ToolResult

if TYPE_CHECKING:
    from . import BashTool


def integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer between {minimum} and {maximum}")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


@dataclass
class ProcessRecord:
    process_id: str
    process: asyncio.subprocess.Process
    timeout: int
    created_at: float = field(default_factory=time.time)
    ended_at: float | None = None
    state: str = "running"
    termination_reason: str | None = None
    cancellation_requested: bool = False
    output_complete: bool = False
    output_error: str | None = None
    chunks: deque = field(default_factory=deque)
    cursor: int = 0
    retained_bytes: int = 0
    total_bytes: int = 0
    dropped_bytes: int = 0
    changed: asyncio.Event = field(default_factory=asyncio.Event)
    done: asyncio.Event = field(default_factory=asyncio.Event)
    write_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    supervisor: asyncio.Task | None = None
    cleanup: asyncio.Task | None = None
    events: Any = None


class ManagedProcesses:
    """Bounded registry belonging to exactly one mounted BashTool instance."""

    def __init__(self, tool: BashTool):
        self.tool = tool
        self.owner_id = uuid.uuid4().hex
        self.records: dict[str, ProcessRecord] = {}
        self.closed = False
        self.observer = lambda: None
        self.lifecycle_lock = asyncio.Lock()
        self.output_limit = integer(
            tool.config.get("managed_max_output_bytes", 100_000),
            "managed_max_output_bytes",
            4096,
            10_000_000,
        )
        self.record_limit = integer(
            tool.config.get("managed_max_processes", 32),
            "managed_max_processes",
            1,
            256,
        )
        # Input to an interpreter cannot be validated as a complete command.
        # A trusted host must explicitly grant raw stdin, without command-level
        # restrictions whose intent an interactive interpreter could bypass.
        self.allow_stdin = (
            tool.config.get("managed_stdin") is True
            and tool.config.get("safety_profile", "strict") == "unrestricted"
            and not tool.allowed_commands
            and not tool.denied_commands
            and not tool.config.get("safety_overrides")
        )

    def extend_schema(self, schema: dict) -> dict:
        schema["required"] = []
        schema["properties"].update(
            {
                "action": {
                    "type": "string",
                    "enum": [
                        "run",
                        "start",
                        "read",
                        "write",
                        "wait",
                        "status",
                        "terminate",
                        "list",
                    ],
                    "default": "run",
                    "description": "run preserves ordinary bash execution; start creates a session-owned pipe process. command is required only for run/start.",
                },
                "process_id": {
                    "type": "string",
                    "description": "Opaque ID from start in this mounted session; never a PID.",
                },
                "cursor": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Output chunk cursor from next_cursor. Reads are repeatable; advance this cursor after consuming output.",
                },
                "max_bytes": {
                    "type": "integer",
                    "minimum": 4096,
                    "maximum": 100000,
                    "description": "Maximum source bytes per output page (default 16384).",
                },
                "wait_ms": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 60000,
                    "description": "wait blocks for new output or completion, bounded by this duration (default 1000). Does not terminate the process.",
                },
                "stdin": {
                    "type": "string",
                    "description": "write only: raw input, at most 65536 UTF-8 bytes, requiring explicit unrestricted host stdin permission.",
                },
                "close_stdin": {
                    "type": "boolean",
                    "description": "write only: send EOF after any input; default false.",
                },
            }
        )
        return schema

    async def execute(self, data: dict[str, Any]) -> ToolResult:
        try:
            action = data.get("action")
            if action not in {
                "start",
                "read",
                "write",
                "wait",
                "status",
                "terminate",
                "list",
            }:
                raise ValueError("Unknown managed process action")
            if self.closed:
                raise ValueError("The owning process session has been closed")
            if action == "start":
                return ToolResult(success=True, output=await self.start(data))
            # Prevent innocuous command values from matching existing command
            # auto-approval rules on an unrelated write/terminate action.
            if "command" in data or "run_in_background" in data or "timeout" in data:
                raise ValueError(
                    "command, timeout and run_in_background are not valid for process follow-ups"
                )
            if action == "list":
                return ToolResult(
                    success=True,
                    output={
                        "owner_id": self.owner_id,
                        "processes": [
                            self.status(record) for record in self.records.values()
                        ],
                    },
                )
            process_id = data.get("process_id")
            if not isinstance(process_id, str) or process_id not in self.records:
                raise ValueError(
                    "Unknown process_id in this mounted session; no process was resumed or restarted"
                )
            record = self.records[process_id]
            # Validate read options BEFORE a side effect such as writing stdin.
            cursor = integer(data.get("cursor", 0), "cursor", 0, record.cursor)
            max_bytes = integer(data.get("max_bytes", 16384), "max_bytes", 4096, 100000)
            if action == "write":
                await self.write(record, data)
            elif action == "terminate":
                await self.terminate(record, "cancel")
            elif action == "wait":
                wait_ms = integer(data.get("wait_ms", 1000), "wait_ms", 0, 60000)
                if record.cursor <= cursor and not record.done.is_set():
                    record.changed.clear()
                    try:
                        await asyncio.wait_for(record.changed.wait(), wait_ms / 1000)
                    except TimeoutError:
                        pass
            if action == "status":
                output = self.status(record)
            else:
                output = self.read(record, cursor, max_bytes)
            return ToolResult(success=True, output=output)
        except (TypeError, ValueError, OSError, RuntimeError) as exc:
            return ToolResult(
                success=False, output=str(exc), error={"message": str(exc)}
            )

    async def start(self, data: dict[str, Any]) -> dict:
        # Serialize spawn/registration against both other starts and close().
        # Otherwise pending spawns could exceed record limits or escape close.
        async with self.lifecycle_lock:
            if self.closed:
                raise ValueError("The owning process session has been closed")
            return await self._start(data)

    async def _start(self, data: dict[str, Any]) -> dict:
        from . import _validate_timeout_seconds

        command = data.get("command")
        if not isinstance(command, str) or not command.strip():
            raise ValueError("Command is required")
        if (
            data.get("run_in_background")
            or data.get("stdin")
            or data.get("close_stdin")
        ):
            raise ValueError(
                "start does not accept run_in_background or stdin; use write for input"
            )
        if sys.platform == "win32":
            raise ValueError(
                "Managed processes currently require POSIX process groups; ordinary bash execution remains available on Windows"
            )
        timeout = _validate_timeout_seconds(
            data.get("timeout", self.tool.timeout), source="caller"
        )
        safety = self.tool._safety_validator.validate(command)
        if not safety.allowed:
            raise ValueError(f"Command denied for safety: {safety.reason}")
        if (
            self.tool.max_concurrent is not None
            and self.tool._active_commands >= self.tool.max_concurrent
        ):
            raise ValueError(
                f"Command rejected: concurrent command limit of {self.tool.max_concurrent} reached"
            )
        if len(self.records) >= self.record_limit:
            completed = next(
                (key for key, value in self.records.items() if value.done.is_set()),
                None,
            )
            if completed is None:
                raise ValueError(
                    "Managed process record limit reached; terminate a process before starting another"
                )
            del self.records[completed]
        self.tool._active_commands += 1
        # Shield the spawn itself so cancellation between fork and registration
        # cannot abandon an unowned child.
        spawn = asyncio.create_task(
            asyncio.create_subprocess_shell(
                command,
                executable="/bin/bash",
                cwd=self.tool.working_dir,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
        )
        cancelled = False
        try:
            while not spawn.done():
                try:
                    await asyncio.shield(spawn)
                except asyncio.CancelledError:
                    cancelled = True
            process = spawn.result()
        except BaseException:
            self.tool._active_commands -= 1
            raise
        record = ProcessRecord(uuid.uuid4().hex, process, timeout)
        observer = self.observer()
        if callable(observer):
            from .process_events import ProcessEvents

            record.events = ProcessEvents(observer, record.process_id, self.owner_id)
        self.records[record.process_id] = record
        record.supervisor = asyncio.create_task(self.supervise(record))
        if cancelled or self.closed:
            await self.terminate(record, "session_closed" if self.closed else "cancel")
            if cancelled:
                raise asyncio.CancelledError()
            raise ValueError("Owning session closed while starting the process")
        if record.events:
            try:
                await asyncio.shield(record.events.ready)
            except asyncio.CancelledError:
                await self.terminate(record, "cancel")
                raise
        return self.read(record, 0, 16384)

    async def drain(self, record: ProcessRecord, stream: str) -> None:
        reader = getattr(record.process, stream)
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        while raw := await reader.read(4096):
            rendered, binary = self.tool._guard_binary_output(raw, stream)
            encoding_loss = False
            try:
                # Strict incremental probing distinguishes a split character
                # from bytes that cannot be reconstructed from rendered text.
                codecs.utf_8_decode(decoder.getstate()[0] + raw, "strict", False)
            except UnicodeDecodeError:
                encoding_loss = True
            if binary:
                # Preserve any pending text before the binary boundary.
                rendered = decoder.decode(b"", final=True) + rendered
                decoder.reset()
            else:
                rendered = decoder.decode(raw)
            self.append(record, stream, rendered, len(raw), binary, encoding_loss)
        tail = decoder.decode(b"", final=True)
        if tail:
            self.append(record, stream, tail, 0, False, True)

    def append(
        self,
        record: ProcessRecord,
        stream: str,
        text: str,
        size: int,
        binary: bool,
        encoding_loss: bool = False,
    ) -> None:
        record.chunks.append(
            {
                "cursor": record.cursor,
                "next_cursor": record.cursor + 1,
                "stream": stream,
                "text": text,
                "source_bytes": size,
                "binary_output_withheld": binary,
                "encoding_loss": encoding_loss,
            }
        )
        record.cursor += 1
        if record.events:
            record.events.output(record.chunks[-1])
        record.retained_bytes += size
        record.total_bytes += size
        # Also bound object overhead for processes that emit one byte at a time.
        while record.retained_bytes > self.output_limit or len(record.chunks) > 1024:
            removed = record.chunks.popleft()
            record.retained_bytes -= removed["source_bytes"]
            record.dropped_bytes += removed["source_bytes"]
        record.changed.set()

    async def supervise(self, record: ProcessRecord) -> None:
        readers = [
            asyncio.create_task(self.drain(record, stream))
            for stream in ("stdout", "stderr")
        ]
        waiter = asyncio.create_task(record.process.wait())
        try:
            if record.events:
                await record.events.state(self.status(record))
            try:
                await asyncio.wait_for(asyncio.shield(waiter), record.timeout)
            except TimeoutError:
                await self.stop(record, "timeout")
            # A shell can exit with descendants still alive (even with closed
            # output pipes). The owned group ends with the command lifetime.
            await self.stop(record, None)
            try:
                await asyncio.wait_for(asyncio.gather(*readers), 2)
                record.output_complete = True
            except (TimeoutError, OSError) as exc:
                record.output_error = (
                    f"Output collection incomplete: {type(exc).__name__}"
                )
            if record.cancellation_requested:
                record.state = (
                    "cancelled"
                    if record.process.returncode is not None
                    else "outcome_unknown"
                )
            elif record.termination_reason == "timeout" or record.output_error:
                record.state = "failed"
            else:
                record.state = (
                    "completed" if record.process.returncode == 0 else "failed"
                )
            if record.process.returncode is None:
                record.state = "outcome_unknown"
        except Exception as exc:  # noqa: BLE001 - Never report an unobserved process as complete.
            record.state = "outcome_unknown"
            record.output_error = f"Process observation failed: {type(exc).__name__}"
        finally:
            for task in [waiter, *readers]:
                if not task.done():
                    task.cancel()
            await asyncio.gather(waiter, *readers, return_exceptions=True)
            record.ended_at = time.time()
            if record.events:
                await record.events.state(self.status(record), final=True)
            record.done.set()
            record.changed.set()
            self.tool._active_commands -= 1

    async def stop(self, record: ProcessRecord, reason: str | None) -> None:
        from . import _cleanup_process_tree

        if record.cleanup is None:
            if reason is not None:
                record.termination_reason = reason
            record.cleanup = asyncio.create_task(
                _cleanup_process_tree(
                    record.process,
                    pgid=record.process.pid,
                    is_windows=False,
                    reap=False,
                )
            )
        await asyncio.shield(record.cleanup)

    async def terminate(self, record: ProcessRecord, reason: str) -> None:
        if record.done.is_set():
            return
        if record.process.returncode is None and record.termination_reason != "timeout":
            record.cancellation_requested = True
            record.state = "cancel_requested"
            record.changed.set()
            if record.events:
                record.events.update(self.status(record))
        await self.stop(record, reason)
        # Killing is not the same as reaping. Wait for the supervisor to report
        # the actual return code and whether all output was collected.
        await asyncio.shield(record.supervisor)

    async def write(self, record: ProcessRecord, data: dict[str, Any]) -> None:
        text = data.get("stdin", "")
        close_stdin = data.get("close_stdin", False)
        if not isinstance(text, str) or not isinstance(close_stdin, bool):
            raise TypeError("stdin must be a string and close_stdin must be boolean")
        raw = text.encode("utf-8")
        if len(raw) > 65536:
            raise ValueError("stdin exceeds the 65536-byte input limit")
        if raw and not self.allow_stdin:
            raise ValueError(
                "Raw stdin requires host managed_stdin=true, safety_profile=unrestricted, and no command allow/deny/override restrictions. close_stdin alone is permitted."
            )
        async with record.write_lock:
            writer = record.process.stdin
            if record.process.returncode is not None or writer.is_closing():
                raise ValueError("Process stdin is closed")
            if raw:
                writer.write(raw)
                try:
                    await asyncio.wait_for(writer.drain(), 5)
                except TimeoutError as exc:
                    # A timed-out write may already have reached the child.
                    # Close the input path so repeated timed-out writes cannot
                    # accumulate an unbounded transport buffer.
                    writer.close()
                    raise ValueError(
                        "Stdin delivery outcome unknown after 5 seconds; do not automatically retry"
                    ) from exc
            if close_stdin:
                writer.close()

    def status(self, record: ProcessRecord) -> dict:
        return {
            "process_id": record.process_id,
            "owner_id": self.owner_id,
            "lifetime": "mounted_session",
            "pid": record.process.pid,
            "state": record.state,
            "returncode": record.process.returncode,
            "cancellation_requested": record.cancellation_requested,
            "termination_reason": record.termination_reason,
            "output_complete": record.output_complete,
            "observer_available": record.events is not None,
            "observer_dropped_events": record.events.dropped if record.events else 0,
            "output_error": record.output_error,
            "created_at": record.created_at,
            "ended_at": record.ended_at,
            "timeout": record.timeout,
            "stdin_allowed": self.allow_stdin,
            "stdin_closed": record.process.stdin.is_closing(),
            "total_output_bytes": record.total_bytes,
            "dropped_output_bytes": record.dropped_bytes,
            "earliest_cursor": record.chunks[0]["cursor"]
            if record.chunks
            else record.cursor,
            "latest_cursor": record.cursor,
        }

    def read(self, record: ProcessRecord, cursor: int, max_bytes: int) -> dict:
        result = self.status(record)
        earliest = result["earliest_cursor"]
        next_cursor = max(cursor, earliest)
        chunks = []
        size = 0
        for chunk in record.chunks:
            if chunk["cursor"] < next_cursor:
                continue
            if size + chunk["source_bytes"] > max_bytes:
                break
            chunks.append(chunk.copy())
            size += chunk["source_bytes"]
            next_cursor = chunk["next_cursor"]
        result.update(
            {
                "cursor": cursor,
                "next_cursor": next_cursor,
                "chunks": chunks,
                "cursor_expired": cursor < earliest,
                "has_more": next_cursor < record.cursor,
            }
        )
        return result

    async def close(self) -> None:
        self.closed = True
        # Retain the cleanup task and defer repeated cancellation, matching the
        # ordinary bash timeout path's owned teardown behavior.
        cleanup = asyncio.create_task(self._close_records())
        cancelled = False
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                cancelled = True
        cleanup.result()
        if cancelled:
            raise asyncio.CancelledError()

    async def _close_records(self) -> None:
        async with self.lifecycle_lock:
            await asyncio.gather(
                *(
                    self.terminate(record, "session_closed")
                    for record in list(self.records.values())
                )
            )
