"""MITM 代理核心。

设计要点:
- AES / 计数器 / seq 重写等核心不变量与原版完全一致
- 不再打印业务日志到 stdout, 改为通过 hook 回调把结构化事件抛出
- 也不再读 stdin/file 命令, 注入由外层桥接 (web_bridge) 经 inject_request 触发
"""
from __future__ import annotations

import argparse
import asyncio
import itertools
import json
import os
import sys
import threading
import time
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from .crypto import GcpCipher
from .protocol import CMD_ACK, CMD_DATA, GcpHead, InternalHeader, split_plaintext
from .wire_builder import build_wire_packet, compose_counter2, resolve_counter2
from ..paths import conn_map_path, proxy_log_path


DEFAULT_LOCAL_PORT = 18195
DEFAULT_LISTEN_HOST = "0.0.0.0"
DEFAULT_UPSTREAM_PORT = 8195
CONN_MAP_MAX_AGE = 60.0
OUTBOUND_QUEUE_MAXSIZE = 4096
UPSTREAM_DRAIN_TIMEOUT = 10.0

# 由外层 (web_bridge) 注入的回调; 都是 sync 函数, 由 proxy 同步触发
PacketHook = Callable[[dict], None]
SessionHook = Callable[[str, dict], None]
LogHook = Callable[[str, str], None]  # (level, message)

PACKET_HOOK: PacketHook | None = None
SESSION_HOOK: SessionHook | None = None
LOG_HOOK: LogHook | None = None


@dataclass(frozen=True)
class ProxyOptions:
    s2c_passthrough_after_key: bool = False
    observe_s2c: bool = True
    allow_s2c_inject: bool = False
    observe_c2s: bool = True
    c2s_batch_packets: int = 64
    c2s_batch_bytes: int = 262144
    c2s_drain_interval_ms: int = 0
    observe_queue_max: int = 2000


_OPTIONS_LOCK = threading.Lock()
PROXY_OPTIONS = ProxyOptions()


def _as_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return default


def _as_int(value: Any, default: int, *, min_value: int, max_value: int) -> int:
    try:
        out = int(value)
    except (TypeError, ValueError):
        out = default
    return max(min_value, min(max_value, out))


def normalize_proxy_options(data: dict[str, Any] | None) -> dict[str, Any]:
    src = data if isinstance(data, dict) else {}
    defaults = ProxyOptions()
    return {
        "s2c_passthrough_after_key": _as_bool(
            src.get("s2c_passthrough_after_key"), defaults.s2c_passthrough_after_key
        ),
        "observe_s2c": _as_bool(src.get("observe_s2c"), defaults.observe_s2c),
        "allow_s2c_inject": _as_bool(src.get("allow_s2c_inject"), defaults.allow_s2c_inject),
        "observe_c2s": _as_bool(src.get("observe_c2s"), defaults.observe_c2s),
        "c2s_batch_packets": _as_int(
            src.get("c2s_batch_packets"), defaults.c2s_batch_packets, min_value=1, max_value=1024
        ),
        "c2s_batch_bytes": _as_int(
            src.get("c2s_batch_bytes"), defaults.c2s_batch_bytes, min_value=1024, max_value=8 * 1024 * 1024
        ),
        "c2s_drain_interval_ms": _as_int(
            src.get("c2s_drain_interval_ms"), defaults.c2s_drain_interval_ms, min_value=0, max_value=1000
        ),
        "observe_queue_max": _as_int(
            src.get("observe_queue_max"), defaults.observe_queue_max, min_value=0, max_value=100000
        ),
    }


def install_options(options: dict[str, Any] | None = None) -> dict[str, Any]:
    global PROXY_OPTIONS
    normalized = normalize_proxy_options(options)
    with _OPTIONS_LOCK:
        PROXY_OPTIONS = ProxyOptions(**normalized)
    return normalized


def get_options() -> ProxyOptions:
    with _OPTIONS_LOCK:
        return PROXY_OPTIONS


@dataclass
class _PerfCounter:
    count: int = 0
    bytes: int = 0
    total_ns: int = 0
    max_ns: int = 0

    def add(self, elapsed_ns: int, byte_count: int = 0) -> None:
        self.count += 1
        self.bytes += max(0, int(byte_count))
        self.total_ns += max(0, int(elapsed_ns))
        self.max_ns = max(self.max_ns, max(0, int(elapsed_ns)))


class PerfStats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._metrics: dict[str, _PerfCounter] = {}
        self._queue_current = 0
        self._queue_max = 0
        self._last_wall_ns = time.perf_counter_ns()
        self._last_proc_time = time.process_time()
        self._cpu_count = max(1, os.cpu_count() or 1)
        self._psutil = None
        self._psutil_proc = None
        try:
            import psutil  # type: ignore
            self._psutil = psutil
            self._psutil_proc = psutil.Process(os.getpid())
            psutil.cpu_percent(interval=None)
        except Exception:
            self._psutil = None
            self._psutil_proc = None

    def record(self, name: str, elapsed_ns: int, byte_count: int = 0) -> None:
        with self._lock:
            counter = self._metrics.setdefault(name, _PerfCounter())
            counter.add(elapsed_ns, byte_count)

    def record_queue_depth(self, depth: int) -> None:
        depth = max(0, int(depth))
        with self._lock:
            self._queue_current = depth
            self._queue_max = max(self._queue_max, depth)

    def snapshot(self) -> dict[str, Any]:
        now_ns = time.perf_counter_ns()
        now_proc = time.process_time()
        with self._lock:
            elapsed_sec = max((now_ns - self._last_wall_ns) / 1_000_000_000, 0.001)
            proc_delta = max(now_proc - self._last_proc_time, 0.0)
            metrics = self._metrics
            self._metrics = {}
            queue_current = self._queue_current
            queue_max = self._queue_max
            self._queue_max = self._queue_current
            self._last_wall_ns = now_ns
            self._last_proc_time = now_proc

        out_metrics: dict[str, dict[str, Any]] = {}
        for name, counter in metrics.items():
            avg_ms = (counter.total_ns / counter.count / 1_000_000) if counter.count else 0.0
            out_metrics[name] = {
                "count": counter.count,
                "bytes": counter.bytes,
                "avg_ms": avg_ms,
                "max_ms": counter.max_ns / 1_000_000,
                "mbps": (counter.bytes / elapsed_sec) / (1024 * 1024),
            }

        system_cpu_pct = None
        rss_mb = None
        if self._psutil is not None:
            try:
                system_cpu_pct = float(self._psutil.cpu_percent(interval=None))
                if self._psutil_proc is not None:
                    rss_mb = self._psutil_proc.memory_info().rss / (1024 * 1024)
            except Exception:
                system_cpu_pct = None
                rss_mb = None

        return {
            "ts": time.time(),
            "window_sec": elapsed_sec,
            "process_cpu_pct": (proc_delta / elapsed_sec / self._cpu_count) * 100.0,
            "system_cpu_pct": system_cpu_pct,
            "rss_mb": rss_mb,
            "queue": {
                "outbound_depth": queue_current,
                "outbound_max": queue_max,
            },
            "metrics": out_metrics,
        }


class PerfDetailCollector:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._enabled = False
        self._started_at = 0.0
        self._max_seconds = 60.0
        self._max_events = 20000
        self._events: list[dict[str, Any]] = []
        self._dropped = 0

    def start(self, *, max_seconds: float = 60.0, max_events: int = 20000) -> dict[str, Any]:
        max_seconds = max(1.0, min(3600.0, float(max_seconds or 60.0)))
        max_events = max(100, min(1_000_000, int(max_events or 20000)))
        with self._lock:
            self._enabled = True
            self._started_at = time.time()
            self._max_seconds = max_seconds
            self._max_events = max_events
            self._events = []
            self._dropped = 0
        return self.status()

    def stop(self) -> dict[str, Any]:
        with self._lock:
            self._enabled = False
        return self.status()

    def clear(self) -> dict[str, Any]:
        with self._lock:
            self._events = []
            self._dropped = 0
        return self.status()

    def record(
        self,
        *,
        stage: str,
        direction: str,
        elapsed_ns: int,
        byte_count: int = 0,
        **fields: Any,
    ) -> None:
        if not self._enabled:
            return
        now = time.time()
        with self._lock:
            if not self._enabled:
                return
            if now - self._started_at >= self._max_seconds:
                self._enabled = False
                return
            if len(self._events) >= self._max_events:
                self._enabled = False
                self._dropped += 1
                return
            ev = {
                "ts": now,
                "stage": str(stage),
                "direction": str(direction),
                "elapsed_ms": max(0, int(elapsed_ns)) / 1_000_000,
                "bytes": max(0, int(byte_count)),
            }
            for key, value in fields.items():
                if value is not None:
                    ev[str(key)] = value
            self._events.append(ev)

    def status(self) -> dict[str, Any]:
        with self._lock:
            elapsed = time.time() - self._started_at if self._started_at else 0.0
            return {
                "enabled": self._enabled,
                "started_at": self._started_at,
                "elapsed_sec": elapsed,
                "max_seconds": self._max_seconds,
                "max_events": self._max_events,
                "event_count": len(self._events),
                "dropped": self._dropped,
            }

    def events(self, *, limit: int | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if limit is None or limit <= 0:
                return [dict(ev) for ev in self._events]
            return [dict(ev) for ev in self._events[-limit:]]

    def snapshot(self) -> dict[str, Any]:
        events = self.events()
        grouped: dict[str, dict[str, Any]] = {}
        for ev in events:
            key = f"{ev.get('direction','')}.{ev.get('stage','')}"
            item = grouped.setdefault(key, {
                "direction": ev.get("direction"),
                "stage": ev.get("stage"),
                "count": 0,
                "bytes": 0,
                "total_ms": 0.0,
                "max_ms": 0.0,
            })
            elapsed = float(ev.get("elapsed_ms") or 0.0)
            item["count"] += 1
            item["bytes"] += int(ev.get("bytes") or 0)
            item["total_ms"] += elapsed
            item["max_ms"] = max(float(item["max_ms"]), elapsed)
        for item in grouped.values():
            count = max(1, int(item["count"]))
            item["avg_ms"] = float(item["total_ms"]) / count
            item.pop("total_ms", None)
        return {"status": self.status(), "groups": list(grouped.values())}


PERF_STATS = PerfStats()
PERF_DETAIL = PerfDetailCollector()


def _log(level: str, msg: str) -> None:
    """统一日志出口。优先走 hook, 没设就退回 stderr (启动期诊断用)。"""
    if LOG_HOOK is not None:
        try:
            LOG_HOOK(level, msg)
            return
        except Exception:
            pass
    if level in ("error", "warn"):
        print(f"[{level}] {msg}", file=sys.stderr, flush=True)


def install_hooks(
    *, packet: PacketHook | None = None, session: SessionHook | None = None, log: LogHook | None = None
) -> None:
    global PACKET_HOOK, SESSION_HOOK, LOG_HOOK
    if packet is not None:
        PACKET_HOOK = packet
    if session is not None:
        SESSION_HOOK = session
    if log is not None:
        LOG_HOOK = log


@dataclass
class SessionState:
    cipher: GcpCipher | None = None
    last_gcp_seq: int = 0
    last_internal: InternalHeader | None = None
    c2s_count: int = 0
    s2c_count: int = 0
    session_key_hex: str = ""
    c2s_seq_offset: int = 0
    last_c2_by_opcode: dict[int, int] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)
    upstream_ip: str = ""
    upstream_port: int = 0
    emitted_session_key_hex: str = ""


@dataclass
class OutboundItem:
    tag: str
    wire: bytes
    source_ns: int
    gcp_seq: int | None = None
    command: int | None = None
    command_name: str = ""


@dataclass
class ObserveItem:
    pkt: bytes
    direction: str
    emit_event: bool


ACTIVE_SESSION: "MitmSession | None" = None
ACTIVE_SESSIONS: dict[int, "MitmSession"] = {}
SERVER_STOP_EVENT: asyncio.Event | None = None
_MIN_REAL_SESSION_ID = 0x10000
_SESSION_TOKEN_COUNTER = itertools.count(1)


class InjectError(Exception):
    """注入失败 (无活动会话 / 未拿到 session_key 等)."""


class MitmSession:
    def __init__(self, client_r, client_w, upstream_ip: str, upstream_port: int):
        self.client_r = client_r
        self.client_w = client_w
        self.upstream_ip = upstream_ip
        self.upstream_port = upstream_port
        self.session_token = next(_SESSION_TOKEN_COUNTER)
        self.state = SessionState(upstream_ip=upstream_ip, upstream_port=upstream_port)
        self.upstream_r = None
        self.upstream_w = None
        self._outbound_queue: asyncio.Queue[OutboundItem] = asyncio.Queue(
            maxsize=OUTBOUND_QUEUE_MAXSIZE
        )
        observe_max = get_options().observe_queue_max
        self._observe_queue: asyncio.Queue[ObserveItem] | None = (
            asyncio.Queue(maxsize=observe_max) if observe_max > 0 else None
        )
        self._observe_dropped = 0
        self._observe_task: asyncio.Task | None = None
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for writer in (self.client_w, self.upstream_w):
            if writer is None:
                continue
            with suppress(Exception):
                writer.close()

    def _decrypt_body_timed(self, body: bytes) -> bytes:
        assert self.state.cipher is not None
        start_ns = time.perf_counter_ns()
        try:
            return self.state.cipher.decrypt_body(body)
        finally:
            PERF_STATS.record("decrypt", time.perf_counter_ns() - start_ns, len(body))

    def _encrypt_body_timed(self, plain: bytes) -> bytes:
        assert self.state.cipher is not None
        start_ns = time.perf_counter_ns()
        try:
            return self.state.cipher.encrypt_body(plain)
        finally:
            PERF_STATS.record("encrypt", time.perf_counter_ns() - start_ns, len(plain))

    async def run(self):
        global ACTIVE_SESSION
        self.upstream_r, self.upstream_w = await asyncio.open_connection(
            self.upstream_ip, self.upstream_port
        )
        _log("info", f"upstream connected {self.upstream_ip}:{self.upstream_port}")
        ACTIVE_SESSIONS[self.session_token] = self
        ACTIVE_SESSION = self
        _emit_session_event("upstream_connected", {
            "upstream_ip": self.upstream_ip, "upstream_port": self.upstream_port,
            "session_token": self.session_token,
            "active_sessions": len(ACTIVE_SESSIONS),
        })
        tasks = [
            asyncio.create_task(self._pump_c2s(), name="c2s"),
            asyncio.create_task(self._pump_s2c(), name="s2c"),
            asyncio.create_task(self._pump_upstream_send(), name="upstream_send"),
        ]
        if self._observe_queue is not None:
            self._observe_task = asyncio.create_task(self._observe_worker(), name="observe")
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
                with suppress(asyncio.CancelledError, Exception):
                    await t
            for t in done:
                exc = t.exception()
                if exc:
                    _log("error", f"task {t.get_name()} exc: {exc!r}")
        finally:
            if self._observe_task is not None:
                self._observe_task.cancel()
                with suppress(asyncio.CancelledError, Exception):
                    await self._observe_task
                self._observe_task = None
            self.close()
            for writer in (self.client_w, self.upstream_w):
                if writer is None:
                    continue
                with suppress(Exception):
                    await writer.wait_closed()
            ACTIVE_SESSIONS.pop(self.session_token, None)
            if ACTIVE_SESSION is self:
                ACTIVE_SESSION = _choose_active_session()
            _emit_session_event("session_closed", {
                "session_token": self.session_token,
                "active_sessions": len(ACTIVE_SESSIONS),
            })

    def _make_outbound_item(self, tag: str, wire: bytes, source_ns: int) -> OutboundItem:
        gcp_seq = None
        command = None
        command_name = ""
        try:
            head = GcpHead.unpack(wire)
            gcp_seq = head.sequence
            command = head.command
            command_name = _classify_command(head.command)
        except Exception:
            pass
        return OutboundItem(
            tag=tag,
            wire=wire,
            source_ns=source_ns,
            gcp_seq=gcp_seq,
            command=command,
            command_name=command_name,
        )

    def _record_detail(
        self,
        stage: str,
        direction: str,
        elapsed_ns: int,
        byte_count: int = 0,
        item: OutboundItem | None = None,
        **fields: Any,
    ) -> None:
        if item is not None:
            fields.setdefault("session_token", self.session_token)
            fields.setdefault("gcp_seq", item.gcp_seq)
            fields.setdefault("command", item.command)
            fields.setdefault("command_name", item.command_name)
            fields.setdefault("upstream", f"{self.upstream_ip}:{self.upstream_port}")
        PERF_DETAIL.record(
            stage=stage,
            direction=direction,
            elapsed_ns=elapsed_ns,
            byte_count=byte_count,
            **fields,
        )

    def _queue_observe(self, pkt: bytes, direction: str, *, emit_event: bool = True) -> None:
        queue = self._observe_queue
        if queue is None:
            return
        try:
            queue.put_nowait(ObserveItem(pkt=pkt, direction=direction, emit_event=emit_event))
        except asyncio.QueueFull:
            self._observe_dropped += 1
            PERF_STATS.record("observe_drop", 0, len(pkt))
            PERF_DETAIL.record(
                stage="observe_drop",
                direction=direction,
                elapsed_ns=0,
                byte_count=len(pkt),
                session_token=self.session_token,
                dropped=self._observe_dropped,
            )

    async def _observe_worker(self) -> None:
        assert self._observe_queue is not None
        while True:
            item = await self._observe_queue.get()
            start_ns = time.perf_counter_ns()
            try:
                await asyncio.to_thread(
                    self._observe,
                    item.pkt,
                    item.direction,
                    emit_event=item.emit_event,
                )
            except Exception as exc:
                _log("warn", f"observe worker failed: {exc!r}")
            finally:
                elapsed_ns = time.perf_counter_ns() - start_ns
                PERF_STATS.record("observe_worker", elapsed_ns, len(item.pkt))
                PERF_DETAIL.record(
                    stage="observe_worker",
                    direction=item.direction,
                    elapsed_ns=elapsed_ns,
                    byte_count=len(item.pkt),
                    session_token=self.session_token,
                    queue_depth=self._observe_queue.qsize(),
                )

    async def _pump_c2s(self):
        buf = bytearray()
        while True:
            data = await self.client_r.read(65536)
            if not data:
                _log("info", "C2S client closed")
                return
            read_ns = time.perf_counter_ns()
            buf.extend(data)
            observed: list[bytes] = []
            while True:
                parse_start = time.perf_counter_ns()
                try:
                    pkt = _try_pop_packet(buf)
                except Exception as exc:
                    _log("error", f"C2S 包头异常, 关闭会话: {exc}")
                    return
                if pkt is None:
                    break
                PERF_DETAIL.record(
                    stage="c2s_parse",
                    direction="c2s",
                    elapsed_ns=time.perf_counter_ns() - parse_start,
                    byte_count=len(pkt),
                    session_token=self.session_token,
                )
                rewrite_start = time.perf_counter_ns()
                pkt_out = self._rewrite_c2s_seq(pkt)
                PERF_DETAIL.record(
                    stage="c2s_rewrite",
                    direction="c2s",
                    elapsed_ns=time.perf_counter_ns() - rewrite_start,
                    byte_count=len(pkt_out),
                    session_token=self.session_token,
                )
                self._note_c2s_sequence(pkt)
                await self._outbound_queue.put(self._make_outbound_item("C2S>", pkt_out, read_ns))
                PERF_STATS.record_queue_depth(self._outbound_queue.qsize())
                observed.append(pkt)
            if observed:
                emit_c2s = get_options().observe_c2s
                for pkt in observed:
                    self._queue_observe(pkt, "c2s", emit_event=emit_c2s)

    def _rewrite_c2s_seq(self, pkt: bytes) -> bytes:
        """转发前同步改写 C2S 的 wire seq 和密文里的 counter1."""
        off = self.state.c2s_seq_offset
        if off == 0:
            return pkt
        try:
            head = GcpHead.unpack(pkt)
        except Exception as exc:
            _log("warn", f"C2S-REWRITE head 解析失败: {exc} — 原包透传")
            return pkt
        new_seq = (head.sequence + off) & 0xFFFFFFFF
        out = bytearray(pkt)
        out[9:13] = new_seq.to_bytes(4, "big")
        if head.command != CMD_DATA or self.state.cipher is None:
            return bytes(out)
        try:
            body_off = head.head_length
            body = bytes(out[body_off : body_off + head.body_length])
            plain = self._decrypt_body_timed(body)
            new_plain = new_seq.to_bytes(4, "big") + plain[4:]
            new_body = self._encrypt_body_timed(new_plain)
            if len(new_body) != len(body):
                _log("warn", f"C2S-REWRITE body 长度异常 old={len(body)} new={len(new_body)} — 退回只改 wire_seq")
                return bytes(out)
            out[body_off : body_off + head.body_length] = new_body
            return bytes(out)
        except Exception as exc:
            _log("warn", f"C2S-REWRITE re-encrypt 失败 orig_seq={head.sequence}: {exc}")
            return bytes(out)

    async def _pump_s2c(self):
        buf = bytearray()
        while True:
            data = await self.upstream_r.read(65536)
            if not data:
                _log("info", "S2C upstream closed")
                return
            read_ns = time.perf_counter_ns()
            opts = get_options()
            if self.state.cipher is not None and opts.s2c_passthrough_after_key:
                write_start = time.perf_counter_ns()
                self.client_w.write(data)
                write_end = time.perf_counter_ns()
                PERF_STATS.record("s2c_passthrough_read_write", write_end - read_ns, len(data))
                PERF_DETAIL.record(
                    stage="s2c_passthrough_write",
                    direction="s2c",
                    elapsed_ns=write_end - write_start,
                    byte_count=len(data),
                    session_token=self.session_token,
                    upstream=f"{self.upstream_ip}:{self.upstream_port}",
                )
                drain_start = time.perf_counter_ns()
                await self.client_w.drain()
                drain_end = time.perf_counter_ns()
                PERF_STATS.record("s2c_passthrough_drain", drain_end - drain_start, len(data))
                PERF_DETAIL.record(
                    stage="s2c_passthrough_total",
                    direction="s2c",
                    elapsed_ns=drain_end - read_ns,
                    byte_count=len(data),
                    session_token=self.session_token,
                    upstream=f"{self.upstream_ip}:{self.upstream_port}",
                )
                continue
            buf.extend(data)
            observed: list[bytes] = []
            write_bytes = 0
            while True:
                parse_start = time.perf_counter_ns()
                try:
                    pkt = _try_pop_packet(buf)
                except Exception as exc:
                    _log("error", f"S2C 包头异常, 关闭会话: {exc}")
                    return
                if pkt is None:
                    break
                PERF_DETAIL.record(
                    stage="s2c_parse",
                    direction="s2c",
                    elapsed_ns=time.perf_counter_ns() - parse_start,
                    byte_count=len(pkt),
                    session_token=self.session_token,
                )
                self._prime_s2c_state(pkt, emit_event=not opts.observe_s2c)
                write_ns = time.perf_counter_ns()
                PERF_STATS.record("s2c_read_write", write_ns - read_ns, len(pkt))
                self.client_w.write(pkt)
                write_bytes += len(pkt)
                if opts.observe_s2c:
                    observed.append(pkt)
                if self.state.cipher is not None and opts.s2c_passthrough_after_key:
                    if buf:
                        remaining = bytes(buf)
                        self.client_w.write(remaining)
                        write_bytes += len(remaining)
                        PERF_DETAIL.record(
                            stage="s2c_passthrough_remainder",
                            direction="s2c",
                            elapsed_ns=0,
                            byte_count=len(remaining),
                            session_token=self.session_token,
                        )
                        buf.clear()
                    break
            if write_bytes:
                drain_start = time.perf_counter_ns()
                await self.client_w.drain()
                drain_elapsed = time.perf_counter_ns() - drain_start
                PERF_STATS.record("s2c_write_drain", drain_elapsed, write_bytes)
                PERF_DETAIL.record(
                    stage="s2c_drain",
                    direction="s2c",
                    elapsed_ns=drain_elapsed,
                    byte_count=write_bytes,
                    session_token=self.session_token,
                    upstream=f"{self.upstream_ip}:{self.upstream_port}",
                )
            for pkt in observed:
                self._queue_observe(pkt, "s2c", emit_event=True)

    async def _pump_upstream_send_legacy(self):
        while True:
            tag, wire, source_ns = await self._outbound_queue.get()
            PERF_STATS.record_queue_depth(self._outbound_queue.qsize())
            if tag != "C2S>":
                _log("debug", f"{tag} 写 upstream {len(wire)} 字节")
            write_ns = time.perf_counter_ns()
            if tag == "C2S>":
                PERF_STATS.record("c2s_read_write", write_ns - source_ns, len(wire))
            else:
                PERF_STATS.record("inject_queue_delay", write_ns - source_ns, len(wire))
            self.upstream_w.write(wire)
            drain_start = time.perf_counter_ns()
            try:
                await asyncio.wait_for(self.upstream_w.drain(), timeout=UPSTREAM_DRAIN_TIMEOUT)
            except asyncio.TimeoutError:
                _log("error", f"upstream drain timeout after {UPSTREAM_DRAIN_TIMEOUT:.1f}s")
                self.close()
                return
            metric = "c2s_write_drain" if tag == "C2S>" else "inject_write_drain"
            PERF_STATS.record(metric, time.perf_counter_ns() - drain_start, len(wire))

    def _prime_s2c_state_legacy(self, pkt: bytes) -> None:
        try:
            head = GcpHead.unpack(pkt)
        except Exception:
            return
        if head.command != CMD_ACK:
            return
        key = pkt[0x17 : 0x17 + 16]
        self.state.cipher = GcpCipher(key)
        self.state.session_key_hex = key.hex()

    async def _pump_upstream_send(self):
        while True:
            first = await self._outbound_queue.get()
            opts = get_options()
            max_packets = max(1, int(opts.c2s_batch_packets))
            max_bytes = max(1, int(opts.c2s_batch_bytes))
            batch = [first]
            batch_bytes = len(first.wire)

            if opts.c2s_drain_interval_ms > 0 and batch_bytes < max_bytes and max_packets > 1:
                try:
                    item = await asyncio.wait_for(
                        self._outbound_queue.get(),
                        timeout=opts.c2s_drain_interval_ms / 1000.0,
                    )
                    batch.append(item)
                    batch_bytes += len(item.wire)
                except asyncio.TimeoutError:
                    pass

            while len(batch) < max_packets and batch_bytes < max_bytes:
                try:
                    item = self._outbound_queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                batch.append(item)
                batch_bytes += len(item.wire)

            PERF_STATS.record_queue_depth(self._outbound_queue.qsize())
            metric_bytes: dict[str, int] = {}
            for item in batch:
                if item.tag != "C2S>":
                    _log("debug", f"{item.tag} to upstream {len(item.wire)} bytes")
                write_start = time.perf_counter_ns()
                if item.tag == "C2S>":
                    PERF_STATS.record("c2s_read_write", write_start - item.source_ns, len(item.wire))
                    metric_name = "c2s_write_drain"
                else:
                    PERF_STATS.record("inject_queue_delay", write_start - item.source_ns, len(item.wire))
                    metric_name = "inject_write_drain"
                metric_bytes[metric_name] = metric_bytes.get(metric_name, 0) + len(item.wire)
                self._record_detail(
                    "queue_wait",
                    "c2s",
                    write_start - item.source_ns,
                    len(item.wire),
                    item=item,
                    batch_len=len(batch),
                    queue_depth=self._outbound_queue.qsize(),
                )
                self.upstream_w.write(item.wire)
                self._record_detail(
                    "write_call",
                    "c2s",
                    time.perf_counter_ns() - write_start,
                    len(item.wire),
                    item=item,
                    batch_len=len(batch),
                )

            drain_start = time.perf_counter_ns()
            try:
                await asyncio.wait_for(self.upstream_w.drain(), timeout=UPSTREAM_DRAIN_TIMEOUT)
            except asyncio.TimeoutError:
                _log("error", f"upstream drain timeout after {UPSTREAM_DRAIN_TIMEOUT:.1f}s")
                self.close()
                return
            drain_end = time.perf_counter_ns()
            drain_elapsed = drain_end - drain_start
            for metric_name, byte_count in metric_bytes.items():
                PERF_STATS.record(metric_name, drain_elapsed, byte_count)
            for item in batch:
                self._record_detail(
                    "drain",
                    "c2s",
                    drain_elapsed,
                    len(item.wire),
                    item=item,
                    batch_len=len(batch),
                )
                self._record_detail(
                    "total_read_to_drain",
                    "c2s",
                    drain_end - item.source_ns,
                    len(item.wire),
                    item=item,
                    batch_len=len(batch),
                )
                self._outbound_queue.task_done()

    def _prime_s2c_state(self, pkt: bytes, *, emit_event: bool = False) -> bool:
        try:
            head = GcpHead.unpack(pkt)
        except Exception:
            return False
        if head.command != CMD_ACK:
            return False
        key = pkt[0x17 : 0x17 + 16]
        key_hex = key.hex()
        self.state.cipher = GcpCipher(key)
        self.state.session_key_hex = key_hex
        if emit_event and self.state.emitted_session_key_hex != key_hex:
            self.state.emitted_session_key_hex = key_hex
            _log("info", f"S2C *** ACK session_key = {key_hex} ***")
            _emit_session_event("session_key", {
                "key_hex": key_hex,
                "key_ascii": _safe_ascii(key),
            })
        return True

    def _note_c2s_sequence(self, pkt: bytes) -> None:
        try:
            head = GcpHead.unpack(pkt)
        except Exception:
            return
        if head.sequence > self.state.last_gcp_seq:
            self.state.last_gcp_seq = head.sequence
        global ACTIVE_SESSION
        if ACTIVE_SESSION is not self:
            ACTIVE_SESSION = self

    def _observe_legacy(self, pkt: bytes, direction: str):
        try:
            head = GcpHead.unpack(pkt)
        except Exception as exc:
            _log("warn", f"{direction} head 解析失败: {exc}")
            return

        if direction == "c2s":
            self._note_c2s_sequence(pkt)

        if direction == "s2c" and head.command == CMD_ACK:
            key = pkt[0x17 : 0x17 + 16]
            self.state.cipher = GcpCipher(key)
            self.state.session_key_hex = key.hex()
            _log("info", f"S2C *** ACK session_key = {key.hex()} ***")
            _emit_session_event("session_key", {
                "key_hex": key.hex(),
                "key_ascii": _safe_ascii(key),
            })
            _emit_packet_event(
                ts=time.time(), direction="s2c", head=head, internal=None,
                payload=b"", opcode=None, raw_pkt=pkt, kind="ack",
            )
            return

        if head.command != CMD_DATA or self.state.cipher is None:
            kind = _classify_command(head.command)
            _emit_packet_event(
                ts=time.time(), direction=direction, head=head, internal=None,
                payload=b"", opcode=None, raw_pkt=pkt, kind=kind,
            )
            return

        body = pkt[head.head_length : head.head_length + head.body_length]
        try:
            plain_full = self._decrypt_body_timed(body)
            plain_no_trail, _trailer = self.state.cipher.split_trailer(plain_full)
            internal, payload = split_plaintext(plain_no_trail)
        except Exception as exc:
            _log("warn", f"{direction} DATA 解密失败 gcp_seq={head.sequence}: {exc}")
            _emit_packet_event(
                ts=time.time(), direction=direction, head=head, internal=None,
                payload=b"", opcode=None, raw_pkt=pkt, kind="data_decrypt_failed",
                error=str(exc),
            )
            return

        opcode = internal.sub_id if direction == "c2s" else (internal.session_id & 0xFFFF)

        if direction == "c2s":
            self.state.c2s_count += 1
            if _is_inject_baseline_candidate(internal, self.state.last_internal):
                self.state.last_internal = internal
            self.state.last_c2_by_opcode[opcode] = internal.counter2
        else:
            self.state.s2c_count += 1

        _emit_packet_event(
            ts=time.time(), direction=direction, head=head, internal=internal,
            payload=payload, opcode=opcode, raw_pkt=pkt, kind="data",
        )


    def _observe(self, pkt: bytes, direction: str, *, emit_event: bool = True):
        try:
            head = GcpHead.unpack(pkt)
        except Exception as exc:
            _log("warn", f"{direction} head parse failed: {exc}")
            return

        if direction == "c2s":
            self._note_c2s_sequence(pkt)

        if direction == "s2c" and head.command == CMD_ACK:
            self._prime_s2c_state(pkt, emit_event=emit_event)
            if emit_event:
                _emit_packet_event(
                    ts=time.time(), direction="s2c", head=head, internal=None,
                    payload=b"", opcode=None, raw_pkt=pkt, kind="ack",
                )
            return

        if head.command != CMD_DATA or self.state.cipher is None:
            if emit_event:
                kind = _classify_command(head.command)
                _emit_packet_event(
                    ts=time.time(), direction=direction, head=head, internal=None,
                    payload=b"", opcode=None, raw_pkt=pkt, kind=kind,
                )
            return

        body = pkt[head.head_length : head.head_length + head.body_length]
        try:
            plain_full = self._decrypt_body_timed(body)
            plain_no_trail, _trailer = self.state.cipher.split_trailer(plain_full)
            internal, payload = split_plaintext(plain_no_trail)
        except Exception as exc:
            _log("warn", f"{direction} DATA decrypt failed gcp_seq={head.sequence}: {exc}")
            if emit_event:
                _emit_packet_event(
                    ts=time.time(), direction=direction, head=head, internal=None,
                    payload=b"", opcode=None, raw_pkt=pkt, kind="data_decrypt_failed",
                    error=str(exc),
                )
            return

        opcode = internal.sub_id if direction == "c2s" else (internal.session_id & 0xFFFF)

        if direction == "c2s":
            self.state.c2s_count += 1
            if _is_inject_baseline_candidate(internal, self.state.last_internal):
                self.state.last_internal = internal
            self.state.last_c2_by_opcode[opcode] = internal.counter2
        else:
            self.state.s2c_count += 1

        if emit_event:
            _emit_packet_event(
                ts=time.time(), direction=direction, head=head, internal=internal,
                payload=payload, opcode=opcode, raw_pkt=pkt, kind="data",
            )


    def inject(self, *, opcode: int, payload: bytes, fallback_opcode: int | None = None) -> dict:
        """把任意 opcode + payload 注入到上游。返回注入元信息。

        必须先有活动会话和 session_key, 否则抛 InjectError。
        """
        if self.state.cipher is None or self.state.last_internal is None:
            raise InjectError("尚未捕获 session_key 或 internal baseline")
        if self._closed:
            raise InjectError("会话已关闭")
        inject_seq = self.state.last_gcp_seq + self.state.c2s_seq_offset + 1
        c2_use, c2_src = resolve_counter2(
            self.state.last_c2_by_opcode, opcode, fallback_opcode=fallback_opcode
        )
        build_start = time.perf_counter_ns()
        wire = build_wire_packet(
            cipher=self.state.cipher,
            baseline=self.state.last_internal,
            payload=payload,
            sub_id=opcode,
            gcp_sequence=inject_seq,
            counter2=c2_use,
            emit=lambda m: _log("debug", m),
        )
        PERF_STATS.record("inject_build", time.perf_counter_ns() - build_start, len(wire))
        c2_wire = compose_counter2(c2_use, payload)
        try:
            self._outbound_queue.put_nowait(
                self._make_outbound_item("INJECT>", wire, time.perf_counter_ns())
            )
        except asyncio.QueueFull as exc:
            raise InjectError("outbound queue is full") from exc
        self.state.c2s_seq_offset += 1
        self.state.last_c2_by_opcode[opcode] = c2_wire
        PERF_STATS.record_queue_depth(self._outbound_queue.qsize())
        self._emit_inject_packet_event(wire, opcode)
        info = {
            "opcode": opcode,
            "opcode_hex": f"0x{opcode:04X}",
            "inject_seq": inject_seq,
            "counter2": c2_wire,
            "counter2_source": c2_src,
            "payload_hex": payload.hex(),
            "wire_len": len(wire),
            "c2s_seq_offset": self.state.c2s_seq_offset,
        }
        _log("info",
            f"INJECT opcode=0x{opcode:04X} seq={inject_seq} c2={c2_wire:#010x} "
            f"src={c2_src} payload_len={len(payload)}")
        return info

    def _emit_inject_packet_event(self, wire: bytes, opcode: int) -> None:
        try:
            head = GcpHead.unpack(wire)
            body = wire[head.head_length : head.head_length + head.body_length]
            assert self.state.cipher is not None
            plain = self._decrypt_body_timed(body)
            plain_no_trail, _trailer = self.state.cipher.split_trailer(plain)
            internal, payload = split_plaintext(plain_no_trail)
        except Exception as exc:
            _log("warn", f"INJECT observe failed: {exc}")
            return
        _emit_packet_event(
            ts=time.time(), direction="c2s", head=head, internal=internal,
            payload=payload, opcode=opcode, raw_pkt=wire, kind="inject",
        )



_CMD_NAMES = {
    0x1001: "syn",
    0x1002: "ack",
    0x4013: "data",
    0x9001: "heartbeat",
}


def _classify_command(cmd: int) -> str:
    return _CMD_NAMES.get(cmd, f"cmd_0x{cmd:04X}")


def _safe_ascii(b: bytes) -> str:
    try:
        s = b.decode("ascii")
    except UnicodeDecodeError:
        return ""
    return s if all(0x20 <= ord(c) < 0x7F for c in s) else ""


def _emit_packet_event(
    *, ts: float, direction: str, head: GcpHead, internal: InternalHeader | None,
    payload: bytes, opcode: int | None, raw_pkt: bytes, kind: str, error: str | None = None,
) -> None:
    if PACKET_HOOK is None:
        return
    ev: dict[str, Any] = {
        "type": "packet",
        "ts": ts,
        "direction": direction,
        "kind": kind,
        "wire": {
            "command": head.command,
            "command_hex": f"0x{head.command:04X}",
            "command_name": _classify_command(head.command),
            "encrypted": head.encrypted,
            "sequence": head.sequence,
            "head_length": head.head_length,
            "body_length": head.body_length,
            "total_length": len(raw_pkt),
        },
    }
    if internal is not None:
        ev["internal"] = {
            "counter1": internal.counter1,
            "counter2": internal.counter2,
            "session_id": internal.session_id,
            "session_id_hex": f"0x{internal.session_id:08X}",
            "sub_id": internal.sub_id,
            "sub_id_hex": f"0x{internal.sub_id:04X}",
            "body_length": internal.body_length,
        }
    if opcode is not None:
        ev["opcode"] = opcode
        ev["opcode_hex"] = f"0x{opcode:04X}"
    if payload:
        ev["payload_hex"] = payload.hex()
        ev["payload_len"] = len(payload)
    if error:
        ev["error"] = error
    try:
        PACKET_HOOK(ev)
    except Exception as exc:
        _log("warn", f"packet hook 抛错: {exc!r}")


def _emit_session_event(name: str, info: dict) -> None:
    if SESSION_HOOK is None:
        return
    try:
        SESSION_HOOK(name, info)
    except Exception as exc:
        _log("warn", f"session hook 抛错: {exc!r}")


def _try_pop_packet(buf: bytearray) -> bytes | None:
    if len(buf) < 21:
        return None
    if buf[0:2] != b"\x33\x66":
        raise RuntimeError(f"stream magic 错: {bytes(buf[:8]).hex()}")
    head_len = int.from_bytes(buf[13:17], "big")
    body_len = int.from_bytes(buf[17:21], "big")
    total = head_len + body_len
    if len(buf) < total:
        return None
    pkt = bytes(buf[:total])
    del buf[:total]
    return pkt


def _choose_active_session() -> "MitmSession | None":
    candidates = [s for s in ACTIVE_SESSIONS.values() if not s.closed]
    if not candidates:
        return None
    return max(candidates, key=lambda s: s.state.started_at)


def _is_inject_baseline_candidate(
    internal: InternalHeader, current: InternalHeader | None
) -> bool:
    if internal.session_id >= _MIN_REAL_SESSION_ID:
        return True
    return current is not None and internal.session_id == current.session_id


def request_shutdown(reason: str) -> None:
    _log("info", f"shutdown: {reason}")
    sessions = list(ACTIVE_SESSIONS.values())
    if ACTIVE_SESSION is not None and ACTIVE_SESSION not in sessions:
        sessions.append(ACTIVE_SESSION)
    for session in sessions:
        session.close()
    if SERVER_STOP_EVENT is not None:
        SERVER_STOP_EVENT.set()


def get_active_session() -> "MitmSession | None":
    global ACTIVE_SESSION
    if ACTIVE_SESSION is None or ACTIVE_SESSION.closed:
        ACTIVE_SESSION = _choose_active_session()
    return ACTIVE_SESSION


def perf_snapshot() -> dict[str, Any]:
    return PERF_STATS.snapshot()


def perf_detail_status() -> dict[str, Any]:
    return PERF_DETAIL.status()


def perf_detail_start(*, max_seconds: float = 60.0, max_events: int = 20000) -> dict[str, Any]:
    return PERF_DETAIL.start(max_seconds=max_seconds, max_events=max_events)


def perf_detail_stop() -> dict[str, Any]:
    return PERF_DETAIL.stop()


def perf_detail_clear() -> dict[str, Any]:
    return PERF_DETAIL.clear()


def perf_detail_events(*, limit: int | None = None) -> list[dict[str, Any]]:
    return PERF_DETAIL.events(limit=limit)


def perf_detail_snapshot() -> dict[str, Any]:
    return PERF_DETAIL.snapshot()


def perf_detail_export_jsonl() -> str:
    return "\n".join(json.dumps(ev, ensure_ascii=False, default=str) for ev in PERF_DETAIL.events())



async def serve(
    upstream_ip: str | None,
    upstream_port: int,
    listen_host: str,
    listen_port: int,
    *,
    on_ready: Callable[[], Awaitable[None]] | None = None,
) -> None:
    global SERVER_STOP_EVENT

    async def handler(reader, writer):
        peer = writer.get_extra_info("peername")
        sock = writer.get_extra_info("socket")
        _log("info", f"接受客户端 {peer}")
        if upstream_ip:
            ip, port = upstream_ip, upstream_port
        else:
            resolve_start = time.perf_counter_ns()
            try:
                ip, port = await asyncio.to_thread(_lazy_resolve_upstream, sock, upstream_port)
            except Exception as exc:
                _log("error", f"定位 upstream 失败: {exc}")
                writer.close()
                with suppress(Exception):
                    await writer.wait_closed()
                return
            finally:
                PERF_STATS.record("upstream_resolve", time.perf_counter_ns() - resolve_start)
        session = MitmSession(reader, writer, ip, port)
        try:
            await session.run()
        finally:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()
            _log("info", f"客户端 {peer} 断开")

    server = await asyncio.start_server(handler, listen_host, listen_port)
    SERVER_STOP_EVENT = asyncio.Event()
    _log("info", f"Roco MITM proxy listening {listen_host}:{listen_port}")
    if on_ready is not None:
        await on_ready()
    async with server:
        await SERVER_STOP_EVENT.wait()
        server.close()
        await server.wait_closed()
    SERVER_STOP_EVENT = None


def _lazy_resolve_upstream(client_sock, default_port: int) -> tuple[str, int]:
    import json
    from ..divert.connection_watcher import wait_for_game_server

    state_path = conn_map_path()
    cli_ip, cli_port = client_sock.getpeername()[:2]
    if state_path.exists():
        try:
            data = json.loads(state_path.read_text(encoding="utf-8"))
            entry = data.get(f"{cli_ip}:{cli_port}")
            if entry:
                ip, port = entry["orig_ip"], entry["orig_port"]
                ts = float(entry.get("ts") or 0)
                age = time.time() - ts if ts > 0 else CONN_MAP_MAX_AGE + 1
                if age > CONN_MAP_MAX_AGE:
                    _log("warn", f"conn_map entry stale age={age:.1f}s for {cli_ip}:{cli_port}")
                else:
                    _log("info", f"通过 conn_map 定位 upstream {ip}:{port}")
                    return ip, port
        except Exception as exc:
            _log("warn", f"conn_map 读取失败: {exc}")

    result = wait_for_game_server(timeout=15, port=default_port)
    if result:
        _log("info", f"通过 watcher 定位 upstream {result[0]}:{result[1]}")
        return result
    raise RuntimeError("无法定位 upstream, 建议手动指定 --upstream-ip")



def main():
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    parser = argparse.ArgumentParser(description="Roco MITM proxy (low-level, no UI)")
    parser.add_argument("--upstream-ip")
    parser.add_argument("--upstream-port", type=int, default=DEFAULT_UPSTREAM_PORT)
    parser.add_argument("--listen-host", default=DEFAULT_LISTEN_HOST)
    parser.add_argument("--listen-port", type=int, default=DEFAULT_LOCAL_PORT)
    args = parser.parse_args()

    log_path = proxy_log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(log_path, "a", encoding="utf-8", buffering=1)
    fh.write(f"\n==== proxy start {time.strftime('%Y-%m-%d %H:%M:%S')} pid={os.getpid()} ====\n")

    def _file_log(level: str, msg: str) -> None:
        ts = time.strftime("%H:%M:%S")
        fh.write(f"[{ts}][{level}] {msg}\n")
        if level in ("info", "warn", "error"):
            print(f"[{level}] {msg}", flush=True)

    install_hooks(log=_file_log)
    _log("info", f"log file = {log_path}")
    asyncio.run(serve(args.upstream_ip, args.upstream_port, args.listen_host, args.listen_port))


if __name__ == "__main__":
    main()
