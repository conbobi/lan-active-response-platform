"""At-least-once delivery for fire-and-forget event streams (auth events, web access logs).

``websocket.send`` returning only means the frame reached the local buffer. When the connection dies
(e.g. a keepalive timeout while the Manager is busy with a burst), recently "sent" frames and anything
read from the logs meanwhile are gone. The Outbox keeps:

* ``pending`` – items read but not handed to a live socket yet (send failed, or no connection);
* ``recent``  – items handed to the socket in the last ``keep_seconds``; on reconnect they are resent.

Resending is safe because every item carries a stable id (auth ``event_id`` / web ``request_id``) that
the Manager deduplicates on. Memory is bounded: beyond ``limit`` the oldest pending items are dropped
and counted, never silently.
"""
from __future__ import annotations

import time
from collections import deque
from typing import Any, Deque, Iterable, List, Tuple


class Outbox:
    def __init__(self, keep_seconds: float = 90.0, limit: int = 20000, clock=time.monotonic):
        self.keep = keep_seconds
        self.limit = limit
        self.clock = clock
        self.pending: Deque[Any] = deque()
        self.recent: Deque[Tuple[float, Any]] = deque()
        self.dropped = 0
        self.resent = 0

    def _trim(self):
        while len(self.pending) > self.limit:
            self.pending.popleft()
            self.dropped += 1
        horizon = self.clock() - self.keep
        while self.recent and self.recent[0][0] < horizon:
            self.recent.popleft()

    def add(self, items: Iterable[Any]):
        self.pending.extend(items)
        self._trim()

    def drain(self) -> List[Any]:
        batch = list(self.pending)
        self.pending.clear()
        return batch

    def sent(self, items: Iterable[Any]):
        now = self.clock()
        self.recent.extend((now, item) for item in items)
        self._trim()

    def failed(self, items: List[Any]):
        self.pending.extendleft(reversed(items))  # keep original order ahead of newer items
        self._trim()

    def reconnected(self):
        """Frames handed to the previous socket shortly before it died may not have arrived: send again."""
        self._trim()
        again = [item for _, item in self.recent]
        self.recent.clear()
        self.resent += len(again)
        self.failed(again)

    def stats(self) -> dict:
        return {"pending": len(self.pending), "recent": len(self.recent), "dropped": self.dropped, "resent": self.resent}


AUTH_OUTBOX = Outbox()
WEB_OUTBOX = Outbox()
