"""At-least-once delivery of auth events / web logs across a dropped WebSocket (2026-11-27 hydra bursts)."""
import asyncio

import pytest

import web_log_monitor
from delivery import Outbox


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def test_items_sent_just_before_a_disconnect_are_resent_in_order():
    clock = Clock()
    box = Outbox(keep_seconds=90, clock=clock)
    box.add(["a1", "a2"])
    batch = box.drain()
    box.sent(batch)                    # handed to the socket; the connection then dies
    box.add(["b1"])                    # read from the log while disconnected
    box.reconnected()
    assert box.drain() == ["a1", "a2", "b1"] and box.stats()["resent"] == 2


def test_old_confirmed_items_are_not_resent_and_memory_is_bounded():
    clock = Clock()
    box = Outbox(keep_seconds=90, limit=3, clock=clock)
    box.sent(["old"])
    clock.now = 200
    box.reconnected()
    assert box.drain() == []
    box.add(["1", "2", "3", "4", "5"])
    assert box.drain() == ["3", "4", "5"] and box.dropped == 2   # counted, not silent


def test_failed_send_keeps_the_batch_ahead_of_newer_items():
    box = Outbox()
    box.add(["x"])
    batch = box.drain()
    box.add(["y"])
    box.failed(batch)
    assert box.drain() == ["x", "y"]


class DeadSocket:
    async def send(self, _):
        raise ConnectionError("keepalive ping timeout")


class LiveSocket:
    def __init__(self):
        self.frames = []

    async def send(self, frame):
        self.frames.append(frame)


def test_web_logs_survive_a_dead_socket_and_are_flushed_on_the_next_connection(monkeypatch):
    box = Outbox()
    monkeypatch.setattr(web_log_monitor, "WEB_OUTBOX", box)
    logs = [{"request_id": f"{i:032x}", "path": "/login"} for i in range(3)]
    for log in logs:
        assert asyncio.run(web_log_monitor.send_web_log(DeadSocket(), log)) is False
    live = LiveSocket()
    assert asyncio.run(web_log_monitor.flush_web_outbox(live)) == 3
    assert [f'"{log["request_id"]}"' in frame for log, frame in zip(logs, live.frames)] == [True] * 3
    assert box.drain() == []
