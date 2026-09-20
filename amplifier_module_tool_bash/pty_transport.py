"""Optional POSIX terminal transport for one owned subprocess group."""

from __future__ import annotations

import asyncio
import errno
import os


class PtyTransport:
    def __init__(self, master):
        self.master = master
        self.closed = False
        self.input_closed = False
        os.set_blocking(master, False)

    async def ready(self, *, writing=False):
        loop = asyncio.get_running_loop()
        future = loop.create_future()

        def wake():
            if not future.done():
                future.set_result(None)

        add = loop.add_writer if writing else loop.add_reader
        remove = loop.remove_writer if writing else loop.remove_reader
        add(self.master, wake)
        try:
            await future
        finally:
            remove(self.master)

    async def read(self, count):
        while not self.closed:
            try:
                return os.read(self.master, count)
            except BlockingIOError:
                await self.ready()
            except OSError as exc:
                # Linux returns EIO when the last slave closes; BSD returns EOF.
                if exc.errno == errno.EIO:
                    return b""
                raise
        return b""

    async def write(self, raw):
        view = memoryview(raw)
        while view:
            if self.closed or self.input_closed:
                raise ValueError("Process stdin is closed")
            try:
                sent = os.write(self.master, view)
                view = view[sent:]
            except BlockingIOError:
                await self.ready(writing=True)

    def eof_bytes(self):
        import termios

        state = termios.tcgetattr(self.master)
        value = state[6][termios.VEOF]
        if not state[3] & termios.ICANON or value in {b"\0", 0}:
            raise ValueError(
                "Terminal EOF requires canonical input mode; stop the command or send its explicit exit input"
            )
        # The first byte flushes any partial canonical line; the second supplies
        # EOF to the next read. This is terminal EOF, not a pipe half-close.
        return (bytes([value]) if isinstance(value, int) else value) * 2

    def close(self):
        if not self.closed:
            self.closed = True
            os.close(self.master)
