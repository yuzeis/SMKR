"""线程安全 + asyncio 友好的事件总线。

Proxy 端 (asyncio loop 里) 通过 publish() 发事件;
任意数量订阅者通过 subscribe() 拿到 asyncio.Queue, 自行消费.
背压策略: 每个订阅者的队列满了就丢最老的, 不阻塞 publisher.

最近事件保留在 ring buffer 中, 新订阅者可以选择拉历史.
"""
from __future__ import annotations

import asyncio
import threading
from collections import deque
from dataclasses import dataclass
from typing import Any


@dataclass
class _Subscriber:
    queue: asyncio.Queue
    capacity: int
    dropped: int = 0


class EventBus:
    def __init__(self, *, history: int = 2000, subscriber_capacity: int = 1000):
        self._history: deque[dict] = deque(maxlen=history)
        self._subscribers: list[_Subscriber] = []
        self._lock = asyncio.Lock()  # 仅在 (un)subscribe 时持有, publish 走快路径
        self._sub_capacity = subscriber_capacity
        self._seq = 0
        self._owner_thread_id = threading.get_ident()

    def publish(self, event: dict) -> dict:
        """从 asyncio 上下文调用; O(订阅者数) 的非阻塞操作."""
        if threading.get_ident() != self._owner_thread_id:
            raise RuntimeError("EventBus.publish must run on the owner event-loop thread")
        self._seq += 1
        event = dict(event)
        store_history = bool(event.pop("_history", True))
        event = {"seq": self._seq, **event}
        if store_history:
            self._history.append(event)
        for sub in self._subscribers:
            q = sub.queue
            if q.full():
                # 丢最老的, 让位给新事件
                try:
                    q.get_nowait()
                    sub.dropped += 1
                except asyncio.QueueEmpty:
                    pass
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                sub.dropped += 1
        return event

    def clear(self) -> None:
        """清空历史和订阅者队列，用于切换到新游戏会话。"""
        self._history.clear()
        for sub in self._subscribers:
            q = sub.queue
            while True:
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    break

    async def subscribe(self, *, replay_last: int = 0) -> asyncio.Queue:
        """返回一个新的订阅队列, 可选回放最近 N 条历史."""
        q: asyncio.Queue = asyncio.Queue(maxsize=self._sub_capacity)
        async with self._lock:
            self._subscribers.append(_Subscriber(queue=q, capacity=self._sub_capacity))
            if replay_last > 0:
                items = list(self._history)[-replay_last:]
                for ev in items:
                    try:
                        q.put_nowait(ev)
                    except asyncio.QueueFull:
                        break
        return q

    async def unsubscribe(self, queue: asyncio.Queue) -> None:
        async with self._lock:
            self._subscribers = [s for s in self._subscribers if s.queue is not queue]

    def history_snapshot(self, limit: int = 0) -> list[dict]:
        items = list(self._history)
        if limit > 0:
            items = items[-limit:]
        return items

    def stats(self) -> dict[str, Any]:
        return {
            "history_size": len(self._history),
            "history_capacity": self._history.maxlen,
            "subscribers": len(self._subscribers),
            "total_published": self._seq,
            "subscriber_dropped": [s.dropped for s in self._subscribers],
        }
