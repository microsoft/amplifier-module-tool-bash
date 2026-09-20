"""Optional local operation observer; never backpressure subprocess readers."""

import asyncio
import inspect
import time


class ProcessEvents:
    """Bounded per-process mailbox. Sequence gaps make losses observable.

    The host capability is a local callable, not a URL. Output emission is
    nonblocking; at most 32 chunks wait for the observer. Start/final records
    are awaited with a bounded callback deadline. Failed callbacks are not
    retried, and no commands or input are included in the observation stream.
    """

    def __init__(self, observer, process_id, owner_id):
        self.observer = observer
        self.process_id, self.owner_id = process_id, owner_id
        self.sequence = 0
        self.dropped = 0
        self.ready = asyncio.get_running_loop().create_future()
        self.queue = asyncio.Queue(maxsize=32)
        self.worker = asyncio.create_task(self.consume())

    def event(self, phase, **data):
        self.sequence += 1
        return {
            "schemaVersion": 1,
            "eventId": f"{self.process_id}:{self.sequence}",
            "sequence": self.sequence,
            "operationId": self.process_id,
            "ownerId": self.owner_id,
            "source": "tool-bash",
            "kind": "process",
            "phase": phase,
            "at": time.time(),
            **data,
        }

    def output(self, chunk):
        event = self.event("output", chunk=chunk.copy())
        try:
            self.queue.put_nowait((event, None))
        except asyncio.QueueFull:
            self.dropped += 1

    def update(self, status):
        event = self.event("state", status=status)
        try:
            self.queue.put_nowait((event, None))
        except asyncio.QueueFull:
            self.dropped += 1

    async def state(self, status, *, final=False):
        event = self.event("finished" if final else "started", status=status)
        done = asyncio.get_running_loop().create_future()
        await self.queue.put((event, done))
        await asyncio.shield(done)
        if final:
            await self.worker
        elif not self.ready.done():
            self.ready.set_result(None)

    async def consume(self):
        while True:
            event, done = await self.queue.get()
            event["observerDroppedEvents"] = self.dropped
            try:
                # Hosts must supply a cheap local callback. Async sinks get a
                # bounded deadline; synchronous callbacks must never block.
                result = self.observer(event)
                if inspect.isawaitable(result):
                    await asyncio.wait_for(result, 0.5)
            except Exception:  # noqa: BLE001 - Observer failure cannot orphan a subprocess.
                self.dropped += 1
            finally:
                self.queue.task_done()
                if done and not done.done():
                    done.set_result(None)
            if event["phase"] == "finished":
                return
