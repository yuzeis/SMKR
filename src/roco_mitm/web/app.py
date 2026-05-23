"""Web 桥接层。

提供:
  HTTP /                    -> single-page frontend (web/static/index.html)
  HTTP /assets/*            -> 静态资源
  HTTP /api/status          -> 当前会话状态
  HTTP /api/opcodes         -> opcode 索引 (含元数据, 不含详细 schema)
  HTTP /api/opcodes/<hex>   -> 单 opcode 的详细 schema (含解析后字段树)
  HTTP /api/templates       -> GET 列表 / POST 保存 / DELETE 删除
  HTTP /api/filters         -> GET 列表 / POST 保存 / DELETE 删除
  HTTP /api/decode          -> POST { opcode_hex, payload_hex } -> 结构化字段
  HTTP /api/encode          -> POST { opcode_hex, value }      -> payload_hex
  WebSocket /ws             -> 实时事件流 + 双向命令
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import json
import re
import time
from collections import deque
from contextlib import suppress
from pathlib import Path
from typing import Any

from aiohttp import web, WSMsgType

from ..codec import opcode_payload, proto_codec
from ..codec.opcode_registry import OpcodeRegistry
from ..paths import project_root, runtime_dir
from ..proxy import server as proxy_mod
from ..rfn.host import RFNHost
from ..rfn.importer import RFNImportStore, run_import_source, validate_import_source
from ..rfn.live import RFNLiveRuntime, _json_safe
from .event_bus import EventBus



DEFAULT_SETTINGS: dict[str, Any] = {
    "theme": "dark",
    "stream": {
        "max_events": 5000,
        "default_filter": "",
        "hide_plaintext_short": True,
        "hide_decrypt_failed": False,
        "hide_no_schema": False,
        "hide_unknown_fields": False,
        "hide_common_noise": True,
        "hidden_opcodes": "0x9001, 0x013D, 0x013F",
    },
    "services": {
        "http": {
            "enabled": True,
            "host": "127.0.0.1",
            "port": 18196,
            "allow_remote": False,
            "public_url": "",
        },
        "mcp": {
            "enabled": False,
            "host": "127.0.0.1",
            "port": 18210,
            "auth_token": "",
            "allow_inject": False,
            "allow_rfn_exec": False,
            "allow_rfn_import": False,
        },
    },
}


def _deep_merge(base: dict, patch: dict) -> dict:
    out = dict(base)
    for key, value in (patch or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _normalize_settings(data: dict | None) -> dict:
    src = data if isinstance(data, dict) else {}
    patch = dict(src)
    services = dict(patch.get("services") or {})
    legacy_https = services.pop("https", None)
    if isinstance(legacy_https, dict):
        legacy_http = {
            key: legacy_https[key]
            for key in ("enabled", "host", "port")
            if key in legacy_https
        }
        if "allow_remote" not in legacy_http and legacy_http.get("host") not in (None, "", "127.0.0.1", "localhost", "::1"):
            legacy_http["allow_remote"] = True
        services["http"] = _deep_merge(legacy_http, services.get("http", {}))
    patch["services"] = services
    normalized = _deep_merge(DEFAULT_SETTINGS, patch)
    normalized.get("services", {}).pop("https", None)
    return normalized

_NAME_RE = re.compile(r"^[A-Za-z0-9_\u4e00-\u9fff][A-Za-z0-9_.\u4e00-\u9fff -]{0,63}$")


def _validate_name(name: str) -> str:
    if (
        not isinstance(name, str)
        or not _NAME_RE.match(name)
        or name != name.strip()
        or name.endswith(".")
    ):
        raise web.HTTPBadRequest(reason=f"非法名称: {name!r}")
    return name


class JsonStore:
    """单目录 JSON 文件仓库，文件名即条目名。"""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def list(self) -> list[dict]:
        out = []
        for p in sorted(self.root.glob("*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            data.setdefault("name", p.stem)
            out.append(data)
        return out

    def save(self, name: str, data: dict) -> None:
        name = _validate_name(name)
        data = dict(data)
        data["name"] = name
        data.setdefault("updated_at", time.time())
        path = self.root / f"{name}.json"
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)

    def delete(self, name: str) -> bool:
        name = _validate_name(name)
        path = self.root / f"{name}.json"
        if path.exists():
            path.unlink()
            return True
        return False


class SettingsStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._settings = self._load()

    def _load(self) -> dict:
        if not self.path.exists():
            return _normalize_settings({})
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        return _normalize_settings(data if isinstance(data, dict) else {})

    def get(self) -> dict:
        return _normalize_settings(self._settings)

    def save(self, patch: dict) -> dict:
        self._settings = _normalize_settings(_deep_merge(self.get(), patch if isinstance(patch, dict) else {}))
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._settings, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)
        return self.get()



def expand_schema_for_ui(
    schema: dict | None, registry: OpcodeRegistry, *, max_depth: int = 6
) -> list[dict] | None:
    """递归展开 fields 和 message ref，供前端直接渲染表单并防止循环。"""
    if not schema:
        return None
    return _expand_fields(schema.get("fields") or [], registry, depth=0, max_depth=max_depth, seen=set())


def _expand_fields(fields, registry, *, depth, max_depth, seen):
    out = []
    for f in fields:
        item = {
            "no": f.get("no"),
            "name": f.get("name"),
            "type": f.get("type"),
            "repeated": bool(f.get("repeated")),
            "desc": f.get("desc"),
        }
        type_name = f.get("type") or ""
        base = proto_codec.strip_generic(type_name) if type_name else ""
        if base == "message":
            sub_fields = f.get("fields")
            ref = f.get("ref")
            if sub_fields:
                inline_seen = seen
                if depth + 1 < max_depth:
                    item["fields"] = _expand_fields(sub_fields, registry, depth=depth + 1, max_depth=max_depth, seen=inline_seen)
                else:
                    item["truncated"] = True
            elif ref:
                item["ref"] = ref
                if ref in seen:
                    item["circular"] = True
                elif depth + 1 < max_depth:
                    msg = registry.get_message(ref)
                    if msg:
                        item["fields"] = _expand_fields(
                            msg.get("fields") or [], registry,
                            depth=depth + 1, max_depth=max_depth,
                            seen=seen | {ref},
                        )
                    else:
                        item["unresolved"] = True
                else:
                    item["truncated"] = True
        elif "<" in type_name and ">" in type_name:
            # enum<X> 等泛型: 暴露内层名字给前端。
            item["generic"] = type_name.split("<", 1)[1].rsplit(">", 1)[0]
        out.append(item)
    return out



class AppContext:
    def __init__(self, *, package_root: Path, config_dir: Path):
        self.package_root = package_root
        self.config_dir = config_dir
        self.static_dir = package_root / "web" / "static"
        self.bus = EventBus(history=2000, subscriber_capacity=1000)
        self.registry = OpcodeRegistry(config_dir)
        self.registry.load()
        self.templates = JsonStore(config_dir / "templates")
        self.filters = JsonStore(config_dir / "filters")
        self.settings = SettingsStore(config_dir / "settings.json")
        self._http_service = {
            "host": "127.0.0.1",
            "port": 18196,
            "running": True,
        }
        self._mcp_runner: web.AppRunner | None = None
        self._mcp_site: web.TCPSite | None = None
        self._mcp_start_task: asyncio.Task | None = None
        self._mcp_service: dict[str, Any] = {
            "host": "127.0.0.1",
            "port": 18210,
            "actual_host": "",
            "actual_port": 0,
            "running": False,
            "error": "",
        }
        self._loop: asyncio.AbstractEventLoop | None = None
        self._session_state = {
            "connected": False,
            "session_key_hex": "",
            "session_key_ascii": "",
            "upstream": "",
            "started_at": 0.0,
        }
        # Last non-empty session key observed by the Web process. This is
        # intentionally not cleared on disconnect so a later relogin can rotate
        # RFN session-scope state even when the game created a fresh TCP stream.
        self._last_session_key_hex = ""
        self._packet_queue: asyncio.PriorityQueue[tuple[int, int, dict]] | None = None
        self._packet_worker_task: asyncio.Task | None = None
        self._packet_queue_capacity = 2000
        self._packet_job_seq = 0
        self._recent_injects: deque[dict[str, Any]] = deque(maxlen=64)
        self._perf_task: asyncio.Task | None = None
        self.rfn = RFNLiveRuntime(
            script_root=project_root() / "MITMScript",
            registry=self.registry,
            db_path=runtime_dir() / "scripts" / "rfn_live.sqlite",
            file_root=runtime_dir() / "scripts",
            inject_func=self._rfn_inject,
            session_disconnect_func=self._rfn_session_disconnect,
        )
        self.rfn_imports = RFNImportStore(runtime_dir() / "scripts" / "imported_rfn")
        self._rfn_packet_queue: asyncio.Queue[dict] | None = None
        self._rfn_packet_worker_task: asyncio.Task | None = None
        self._rfn_schedule_task: asyncio.Task | None = None
        self._rfn_queue_capacity = 2000
        self._rfn_dropped = 0

    def set_http_service(self, *, host: str, port: int) -> None:
        self._http_service = {
            "host": str(host or "127.0.0.1"),
            "port": int(port),
            "running": True,
        }

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        if self._perf_task is None or self._perf_task.done():
            self._perf_task = loop.create_task(self._perf_publisher())
        if self._rfn_schedule_task is None or self._rfn_schedule_task.done():
            self._rfn_schedule_task = loop.create_task(self._rfn_schedule_loop())
        if self._mcp_start_task is None or self._mcp_start_task.done():
            self._mcp_start_task = loop.create_task(self.start_mcp_service())

    async def start_mcp_service(self) -> dict[str, Any]:
        settings = self.settings.get().get("services", {}).get("mcp", {})
        enabled = bool(settings.get("enabled"))
        host = str(settings.get("host") or "127.0.0.1")
        port = int(settings.get("port") or 18210)
        if not enabled:
            self._mcp_service.update({
                "host": host,
                "port": port,
                "actual_host": "",
                "actual_port": 0,
                "running": False,
                "error": "",
            })
            return self.mcp_service_status(mask_token=True)
        if self._mcp_runner is not None:
            return self.mcp_service_status(mask_token=True)
        try:
            from .mcp import build_mcp_app

            runner = web.AppRunner(build_mcp_app(self))
            await runner.setup()
            site = web.TCPSite(runner, host, port)
            await site.start()
            actual_host = host
            actual_port = port
            sockets = getattr(getattr(site, "_server", None), "sockets", None) or []
            if sockets:
                sock_host, sock_port = sockets[0].getsockname()[:2]
                actual_host = str(sock_host)
                actual_port = int(sock_port)
            self._mcp_runner = runner
            self._mcp_site = site
            self._mcp_service.update({
                "host": host,
                "port": port,
                "actual_host": actual_host,
                "actual_port": actual_port,
                "running": True,
                "error": "",
            })
        except Exception as exc:
            with suppress(Exception):
                if self._mcp_runner is not None:
                    await self._mcp_runner.cleanup()
            self._mcp_runner = None
            self._mcp_site = None
            self._mcp_service.update({
                "host": host,
                "port": port,
                "actual_host": "",
                "actual_port": 0,
                "running": False,
                "error": f"{type(exc).__name__}: {exc}",
            })
        return self.mcp_service_status(mask_token=True)

    async def stop_mcp_service(self) -> None:
        runner = self._mcp_runner
        self._mcp_site = None
        self._mcp_runner = None
        if runner is not None:
            with suppress(Exception):
                await runner.cleanup()
        self._mcp_service.update({"running": False, "actual_host": "", "actual_port": 0})

    def mcp_service_status(self, *, mask_token: bool = True) -> dict[str, Any]:
        settings = dict(self.settings.get().get("services", {}).get("mcp", {}))
        if mask_token and settings.get("auth_token"):
            settings["auth_token"] = "***"
        configured_host = str(settings.get("host") or "127.0.0.1")
        configured_port = int(settings.get("port") or 18210)
        running = bool(self._mcp_service.get("running"))
        restart_required = (
            bool(settings.get("enabled")) != running
            or (running and configured_host != str(self._mcp_service.get("host") or ""))
            or (running and configured_port != int(self._mcp_service.get("port") or 0))
        )
        return {
            **settings,
            "running": running,
            "actual_host": self._mcp_service.get("actual_host") or "",
            "actual_port": int(self._mcp_service.get("actual_port") or 0),
            "error": self._mcp_service.get("error") or "",
            "restart_required": restart_required,
        }

    # 把 proxy 同步 hook 桥接到 asyncio loop 上的 EventBus.publish。
    def _publish_threadsafe(self, ev: dict) -> None:
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        loop.call_soon_threadsafe(self.bus.publish, ev)

    def _clear_and_publish_threadsafe(self, events: list[dict]) -> None:
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        loop.call_soon_threadsafe(self._clear_and_publish, events)

    def _clear_and_publish(self, events: list[dict]) -> None:
        self.bus.clear()
        for ev in events:
            self.bus.publish(ev)

    def _queue_packet_threadsafe(self, ev: dict) -> None:
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        loop.call_soon_threadsafe(self._enqueue_packet_event, dict(ev))

    def _handle_session_key_update(
        self,
        *,
        key_hex: str,
        key_ascii: str = "",
        now: float | None = None,
    ) -> dict[str, Any] | None:
        """Remember a non-empty session key and rotate RFN state on key changes.

        The comparison is against the last non-empty key seen by this Web
        process, not the current connected flag. That makes disconnect -> relogin
        behave like a session rotation for RFN cache/buffer/pending-query scope.
        """
        new_key = str(key_hex or "")
        if not new_key:
            self._session_state.update({
                "session_key_hex": "",
                "session_key_ascii": "",
            })
            return None

        now = time.time() if now is None else now
        old_key = self._last_session_key_hex or str(self._session_state.get("session_key_hex") or "")
        stream_reset = None
        if old_key and old_key != new_key:
            stream_reset = {
                "type": "stream_reset",
                "ts": now,
                "reason": "session_key_changed",
                "old_key_preview": old_key[:8],
                "new_key_preview": new_key[:8],
            }
            try:
                self.rfn.on_session_rotate(old_key=old_key, new_key=new_key)
            except Exception as exc:
                self._publish_threadsafe({
                    "type": "rfn",
                    "kind": "rotate_error",
                    "error": f"{type(exc).__name__}: {exc}",
                    "_history": False,
                })

        self._last_session_key_hex = new_key
        self._session_state.update({
            "session_key_hex": new_key,
            "session_key_ascii": key_ascii,
        })
        return stream_reset

    def _enqueue_packet_event(self, ev: dict) -> None:
        decode_job = self._prepare_packet_event(ev)
        published = self.bus.publish(ev)
        if decode_job is None:
            if ev.get("opcode") is not None:
                self._enqueue_rfn_packet(ev, {"decode_status": ev.get("decode_status", "raw")})
            return
        decode_job["target_seq"] = published["seq"]
        priority = self._decode_priority(ev)
        if self._packet_queue is None:
            self._packet_queue = asyncio.PriorityQueue(maxsize=self._packet_queue_capacity)
        if self._packet_worker_task is None or self._packet_worker_task.done():
            self._packet_worker_task = asyncio.create_task(self._packet_enrich_worker())
        try:
            self._packet_job_seq += 1
            self._packet_queue.put_nowait((priority, self._packet_job_seq, decode_job))
        except asyncio.QueueFull:
            self.bus.publish({
                "type": "packet_update",
                "target_seq": published["seq"],
                "decode_status": "skipped_queue_full",
            })

    def _prepare_packet_event(self, ev: dict) -> dict | None:
        opcode = ev.get("opcode")
        if opcode is None:
            return None
        try:
            opcode_int = int(opcode)
        except (TypeError, ValueError):
            return None
        meta = self.registry.get_opcode_meta(opcode_int)
        if meta:
            ev["opcode_meta"] = {
                "name": meta.get("name"),
                "category": meta.get("category"),
                "desc": meta.get("desc"),
                "direction": meta.get("direction"),
            }
        payload_hex = ev.get("payload_hex")
        if not payload_hex:
            return None
        ev["decode_status"] = "queued"
        return {"opcode": opcode_int, "payload_hex": str(payload_hex), "packet": dict(ev)}

    def _decode_priority(self, ev: dict) -> int:
        opcode = ev.get("opcode")
        try:
            opcode_int = int(opcode)
        except (TypeError, ValueError):
            return 50
        now = time.time()
        kind = ev.get("kind")
        if kind == "inject":
            self._recent_injects.append({
                "opcode": opcode_int,
                "reply_opcode": (opcode_int + 1) & 0xFFFF,
                "ts": float(ev.get("ts") or now),
            })
            return 0
        if ev.get("direction") == "s2c":
            self._prune_recent_injects(now)
            for item in reversed(self._recent_injects):
                if int(item.get("reply_opcode", -1)) == opcode_int:
                    return 0
        if ev.get("direction") == "c2s":
            return 10
        return 20

    def _prune_recent_injects(self, now: float) -> None:
        while self._recent_injects and now - float(self._recent_injects[0].get("ts") or 0) > 30.0:
            self._recent_injects.popleft()

    async def _packet_enrich_worker(self) -> None:
        while True:
            assert self._packet_queue is not None
            _priority, _seq, job = await self._packet_queue.get()
            loop = asyncio.get_running_loop()
            patch = await loop.run_in_executor(None, self._decode_packet_patch, job)
            self.bus.publish(patch)
            self._enqueue_rfn_packet(job.get("packet") or {}, patch)

    def _decode_packet_patch(self, job: dict) -> dict:
        target_seq = int(job["target_seq"])
        opcode = int(job["opcode"])
        payload_hex = str(job["payload_hex"])
        patch: dict[str, Any] = {
            "type": "packet_update",
            "target_seq": target_seq,
        }
        schema = self.registry.get_opcode_schema(opcode)
        if schema is None:
            patch["decode_status"] = "no_schema"
            return patch
        try:
            payload = bytes.fromhex(payload_hex)
            decoded, decode_source = self._decode_opcode_payload(opcode, schema, payload)
            self._annotate_scene_client_events(opcode, decoded)
            patch["decoded"] = decoded
            patch["decode_status"] = "ok"
            if decode_source != "schema":
                patch["decode_source"] = decode_source
        except Exception as exc:
            patch["decode_status"] = "error"
            patch["decode_error"] = str(exc)
        return patch

    def _enqueue_rfn_packet(self, packet: dict, patch: dict) -> None:
        if self.rfn.runtime is None:
            return
        enriched = dict(packet)
        for key in ("decoded", "decode_status", "decode_source", "decode_error"):
            if key in patch:
                enriched[key] = patch[key]
        if self._rfn_packet_queue is None:
            self._rfn_packet_queue = asyncio.Queue(maxsize=self._rfn_queue_capacity)
        if self._rfn_packet_worker_task is None or self._rfn_packet_worker_task.done():
            self._rfn_packet_worker_task = asyncio.create_task(self._rfn_packet_worker())
        try:
            self._rfn_packet_queue.put_nowait(enriched)
        except asyncio.QueueFull:
            self._rfn_dropped += 1
            self.bus.publish({
                "type": "rfn",
                "kind": "drop",
                "reason": "rfn_queue_full",
                "dropped": self._rfn_dropped,
                "_history": False,
            })

    async def _rfn_packet_worker(self) -> None:
        while True:
            assert self._rfn_packet_queue is not None
            packet = await self._rfn_packet_queue.get()
            loop = asyncio.get_running_loop()
            results = await loop.run_in_executor(None, self.rfn.handle_packet, packet)
            if results:
                meta = packet.get("opcode_meta") if isinstance(packet.get("opcode_meta"), dict) else {}
                packet_name = packet.get("name") or meta.get("name")
                event = {
                    "type": "rfn",
                    "kind": "packet_trigger",
                    "packet": {
                        "direction": packet.get("direction"),
                        "opcode": packet.get("opcode_hex") or packet.get("opcode"),
                        "name": packet_name,
                        "decode_status": packet.get("decode_status"),
                    },
                    "results": results,
                    "ts": time.time(),
                }
                self.bus.publish(_json_safe(event))

    async def _rfn_schedule_loop(self) -> None:
        while True:
            await asyncio.sleep(0.5)
            if self.rfn.runtime is None:
                continue
            loop = asyncio.get_running_loop()
            results = await loop.run_in_executor(None, self.rfn.run_due_jobs)
            if results:
                event = {
                    "type": "rfn",
                    "kind": "schedule",
                    "results": results,
                    "ts": time.time(),
                    "_history": False,
                }
                self.bus.publish(_json_safe(event))

    def _decode_opcode_payload(self, opcode: int, schema: dict, payload: bytes) -> tuple[dict, str]:
        result = opcode_payload.decode_opcode_payload(schema, payload, self.registry.resolve_message)
        return result.decoded, result.source

    def _score_decode_candidate(self, schema: dict, payload: bytes) -> tuple[tuple[int, int, int, int, int], dict]:
        result = opcode_payload.decode_opcode_payload(schema, payload, self.registry.resolve_message)
        score = (
            result.matched_keys,
            1 if result.consumed_all else 0,
            -result.unknown_recursive,
            0 if result.start == 0 else -1,
            -result.start,
        )
        return score, result.decoded

    def _annotate_scene_client_events(self, opcode: int, decoded: dict) -> None:
        if opcode != 0x0246 or not isinstance(decoded, dict):
            return
        events = decoded.get("client_event")
        if not isinstance(events, list):
            return
        collection = self.registry.get_message(".Next.SpaceActionCollection")
        fields = (collection or {}).get("fields") or []
        by_event = {int(f.get("no")): f for f in fields if f.get("no") is not None}
        for item in events:
            if not isinstance(item, dict):
                continue
            try:
                event_id = int(item.get("event"))
            except (TypeError, ValueError):
                continue
            field = by_event.get(event_id)
            if not field:
                continue
            action_name = str(field.get("name") or f"event_{event_id}")
            item["event_name"] = action_name
            tag_hex = item.get("tag")
            ref = field.get("ref")
            if not ref or not isinstance(tag_hex, str):
                continue
            schema = self.registry.get_message(str(ref))
            if schema is None:
                continue
            try:
                item[action_name] = proto_codec.decode_payload(
                    schema, bytes.fromhex(tag_hex), resolve_message=self.registry.resolve_message
                )
            except Exception as exc:
                item["tag_decode_error"] = str(exc)

    async def close(self) -> None:
        task = self._packet_worker_task
        if task is not None:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        self._packet_worker_task = None
        perf_task = self._perf_task
        if perf_task is not None:
            perf_task.cancel()
            with suppress(asyncio.CancelledError):
                await perf_task
        self._perf_task = None
        rfn_packet_task = self._rfn_packet_worker_task
        if rfn_packet_task is not None:
            rfn_packet_task.cancel()
            with suppress(asyncio.CancelledError):
                await rfn_packet_task
        self._rfn_packet_worker_task = None
        rfn_schedule_task = self._rfn_schedule_task
        if rfn_schedule_task is not None:
            rfn_schedule_task.cancel()
            with suppress(asyncio.CancelledError):
                await rfn_schedule_task
        self._rfn_schedule_task = None
        mcp_start_task = self._mcp_start_task
        if mcp_start_task is not None:
            with suppress(asyncio.CancelledError, Exception):
                await mcp_start_task
        self._mcp_start_task = None
        await self.stop_mcp_service()
        self.rfn.close()

    async def _perf_publisher(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            self.bus.publish({
                "type": "perf",
                "data": proxy_mod.perf_snapshot(),
                "_history": False,
            })

    def install_proxy_hooks(self) -> None:
        def packet(ev: dict) -> None:
            self._queue_packet_threadsafe(ev)

        def session(name: str, info: dict) -> None:
            now = time.time()
            stream_reset = None
            if name == "upstream_connected":
                self._session_state.update({
                    "connected": True,
                    "upstream": f"{info.get('upstream_ip','')}:{info.get('upstream_port',0)}",
                    "started_at": now,
                })
            elif name == "session_key":
                stream_reset = self._handle_session_key_update(
                    key_hex=info.get("key_hex", ""),
                    key_ascii=info.get("key_ascii", ""),
                    now=now,
                )
            elif name == "session_closed":
                active = proxy_mod.get_active_session()
                if active is not None:
                    stream_reset = self._handle_session_key_update(
                        key_hex=active.state.session_key_hex,
                        key_ascii="",
                        now=now,
                    )
                    self._session_state.update({
                        "connected": True,
                        "upstream": f"{active.upstream_ip}:{active.upstream_port}",
                    })
                else:
                    self._session_state.update({
                        "connected": False,
                        "session_key_hex": "",
                        "session_key_ascii": "",
                        "upstream": "",
                    })
            session_event = {
                "type": "session", "ts": now, "name": name, "info": info,
                "snapshot": dict(self._session_state),
            }
            if stream_reset is not None:
                self._clear_and_publish_threadsafe([stream_reset, session_event])
            else:
                self._publish_threadsafe(session_event)

        def log(level: str, msg: str) -> None:
            self._publish_threadsafe({
                "type": "log", "ts": time.time(), "level": level, "message": msg,
            })

        proxy_mod.install_hooks(packet=packet, session=session, log=log)

    def _rfn_inject(self, opcode: int, payload: bytes, fallback_opcode: int | None = None) -> dict[str, Any]:
        loop = self._loop
        if loop is None or loop.is_closed() or not loop.is_running():
            raise proxy_mod.InjectError("RFN inject loop is not available")
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None
        if running_loop is loop:
            # This branch is only for future loop-thread callers; keep it fast and non-blocking.
            return self._rfn_inject_on_loop(opcode, payload, fallback_opcode)
        fut = asyncio.run_coroutine_threadsafe(
            self._rfn_inject_async(opcode, payload, fallback_opcode),
            loop,
        )
        try:
            return fut.result(timeout=2.0)
        except concurrent.futures.TimeoutError as exc:
            fut.cancel()
            # Timeout means the loop did not answer in time; it does not prove the packet was not queued.
            raise proxy_mod.InjectError("E_INJECT_TIMEOUT: RFN inject timed out after 2.0s") from exc

    async def _rfn_inject_async(self, opcode: int, payload: bytes, fallback_opcode: int | None = None) -> dict[str, Any]:
        return self._rfn_inject_on_loop(opcode, payload, fallback_opcode)

    def _rfn_inject_on_loop(self, opcode: int, payload: bytes, fallback_opcode: int | None = None) -> dict[str, Any]:
        sess = proxy_mod.get_active_session()
        if sess is None:
            raise proxy_mod.InjectError("无活动会话")
        return sess.inject(opcode=opcode, payload=payload, fallback_opcode=fallback_opcode)

    def _rfn_session_disconnect(self, reason: str) -> dict[str, Any]:
        loop = self._loop
        if loop is None or loop.is_closed() or not loop.is_running():
            return {"ok": False, "error_code": "E_NO_LOOP", "error": "web loop is not running"}
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None
        if running_loop is loop:
            return self._rfn_session_disconnect_on_loop(reason)
        fut = asyncio.run_coroutine_threadsafe(self._rfn_session_disconnect_async(reason), loop)
        try:
            return fut.result(timeout=2.0)
        except concurrent.futures.TimeoutError:
            fut.cancel()
            return {
                "ok": False,
                "error_code": "E_SESSION_TIMEOUT",
                "error": "session disconnect timed out after 2.0s",
            }

    async def _rfn_session_disconnect_async(self, reason: str) -> dict[str, Any]:
        return self._rfn_session_disconnect_on_loop(reason)

    def _rfn_session_disconnect_on_loop(self, reason: str) -> dict[str, Any]:
        sess = proxy_mod.get_active_session()
        if sess is None:
            return {"ok": False, "error_code": "E_NO_SESSION", "error": "no active MITM session"}
        st = sess.state
        result = {
            "ok": True,
            "reason": str(reason or "rfn.session.disconnect"),
            "session_token": getattr(sess, "session_token", None),
            "upstream": f"{sess.upstream_ip}:{sess.upstream_port}",
            "session_key_hex": st.session_key_hex,
            "session_id_hex": f"0x{st.last_internal.session_id:08X}" if st.last_internal else "",
        }
        sess.close()
        return result

    def run_imported_rfn_source(self, source: str, function: str, args: list[Any]) -> dict[str, Any]:
        """Run ad-hoc RFN against the current live host when possible.

        Reusing the live host lets imported scripts touch the same DB/cache/buffer
        and inject/query bridge as normal RFN handlers. A fallback host is only
        used when the live runtime is not loaded.
        """
        self.rfn._enter_active_call()
        owns_host = False
        host = self.rfn.host
        if host is None:
            owns_host = True
            host = RFNHost(
                registry=self.registry,
                db_path=runtime_dir() / "scripts" / "rfn_live.sqlite",
                mode="live",
                file_root=runtime_dir() / "scripts",
                inject_func=self._rfn_inject,
                session_disconnect_func=self._rfn_session_disconnect,
                default_query_timeout_ms=3000,
            )
            host.query_func = self.rfn._query
        try:
            return run_import_source(
                source,
                function=function,
                args=args,
                host=host,
                module_name="web.import",
            )
        finally:
            if owns_host:
                host.close()
            self.rfn._leave_active_call()

    def _enrich_packet_event(self, ev: dict, opcode: int, payload_hex: str) -> None:
        meta = self.registry.get_opcode_meta(opcode)
        if meta:
            ev["opcode_meta"] = {
                "name": meta.get("name"),
                "category": meta.get("category"),
                "desc": meta.get("desc"),
                "direction": meta.get("direction"),
            }
        schema = self.registry.get_opcode_schema(opcode)
        if schema is not None:
            try:
                payload = bytes.fromhex(payload_hex)
                decoded, decode_source = self._decode_opcode_payload(opcode, schema, payload)
                ev["decoded"] = decoded
                ev["decode_status"] = "ok"
                if decode_source != "schema":
                    ev["decode_source"] = decode_source
            except Exception as exc:
                ev["decode_status"] = "error"
                ev["decode_error"] = str(exc)
        else:
            ev["decode_status"] = "no_schema"

    def session_status(self) -> dict:
        sess = proxy_mod.get_active_session()
        if sess is not None and sess.state.session_key_hex:
            stream_reset = self._handle_session_key_update(
                key_hex=sess.state.session_key_hex,
                key_ascii="",
                now=time.time(),
            )
            if stream_reset is not None:
                self._clear_and_publish_threadsafe([
                    stream_reset,
                    {
                        "type": "session",
                        "ts": stream_reset["ts"],
                        "name": "session_key_reconciled",
                        "info": {"key_hex": sess.state.session_key_hex},
                        "snapshot": dict(self._session_state),
                    },
                ])
        snap = dict(self._session_state)
        snap["bus_stats"] = self.bus.stats()
        snap["registry_stats"] = self.registry.stats()
        snap["rfn"] = self.rfn.status() | {"queue_depth": self._rfn_packet_queue.qsize() if self._rfn_packet_queue else 0, "queue_dropped": self._rfn_dropped}
        settings = self.settings.get()
        http_settings = dict(settings.get("services", {}).get("http", {}))
        actual_http = dict(self._http_service)
        configured_host = str(http_settings.get("host") or "")
        configured_port = int(http_settings.get("port") or 0)
        http_restart_required = (
            bool(http_settings.get("enabled")) is not True
            or configured_host != str(actual_http.get("host") or "")
            or configured_port != int(actual_http.get("port") or 0)
        )
        snap["services"] = {
            "http": {
                **http_settings,
                "running": bool(actual_http.get("running")),
                "actual_host": actual_http.get("host"),
                "actual_port": actual_http.get("port"),
                "restart_required": http_restart_required,
            },
            "mcp": self.mcp_service_status(mask_token=True),
        }
        if sess is not None:
            st = sess.state
            snap.update({
                "c2s_count": st.c2s_count,
                "s2c_count": st.s2c_count,
                "last_gcp_seq": st.last_gcp_seq,
                "c2s_seq_offset": st.c2s_seq_offset,
                "session_id_hex": (
                    f"0x{st.last_internal.session_id:08X}" if st.last_internal else ""
                ),
                "ready_for_inject": (st.cipher is not None and st.last_internal is not None),
            })
        else:
            snap.update({
                "c2s_count": 0, "s2c_count": 0, "last_gcp_seq": 0,
                "c2s_seq_offset": 0, "session_id_hex": "",
                "ready_for_inject": False,
            })
        return snap



async def handle_index(request: web.Request) -> web.FileResponse:
    ctx: AppContext = request.app["ctx"]
    return web.FileResponse(ctx.static_dir / "index.html")


async def handle_status(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    ctx.registry.reload_if_changed()
    return web.json_response(ctx.session_status())


async def handle_rfn_status(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    return web.json_response(ctx.rfn.status() | {
        "queue_depth": ctx._rfn_packet_queue.qsize() if ctx._rfn_packet_queue else 0,
        "queue_dropped": ctx._rfn_dropped,
    })


async def handle_rfn_reload(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    loop = asyncio.get_running_loop()
    status = await loop.run_in_executor(None, ctx.rfn.reload)
    ctx.bus.publish({"type": "rfn", "kind": "reload", "status": status, "ts": time.time()})
    return web.json_response(status | {
        "queue_depth": ctx._rfn_packet_queue.qsize() if ctx._rfn_packet_queue else 0,
        "queue_dropped": ctx._rfn_dropped,
    })


async def handle_rfn_route(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    raw = await request.read()
    json_body = None
    if raw and "json" in (request.content_type or "").lower():
        with suppress(Exception):
            json_body = json.loads(raw.decode("utf-8"))
    rfn_req = {
        "method": request.method,
        "path": request.path,
        "query": dict(request.query),
        "headers": dict(request.headers),
        "body": raw,
        "json": json_body,
        "remote": request.remote,
    }
    loop = asyncio.get_running_loop()
    rsp = await loop.run_in_executor(None, ctx.rfn.handle_http, rfn_req)
    return _rfn_web_response(rsp)



async def handle_rfn_functions(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    return web.json_response({"functions": ctx.rfn.list_functions()})


async def handle_rfn_bindings(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    return web.json_response({"bindings": ctx.rfn.list_bindings()})


async def handle_rfn_jobs(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    return web.json_response({"jobs": ctx.rfn.list_jobs()})


async def handle_rfn_db_namespaces(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    return web.json_response({"namespaces": ctx.rfn.list_db_namespaces()})


async def handle_rfn_db_kv(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    ns = request.match_info["namespace"]
    limit = int(request.query.get("limit") or 100)
    offset = int(request.query.get("offset") or 0)
    return web.json_response({"namespace": ns, "items": ctx.rfn.list_db_kv(ns, limit=limit, offset=offset)})


async def handle_rfn_db_table(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    name = request.match_info["name"]
    limit = int(request.query.get("limit") or 100)
    offset = int(request.query.get("offset") or 0)
    return web.json_response({"table": name, "items": ctx.rfn.list_db_table(name, limit=limit, offset=offset)})


async def handle_rfn_db_events(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    limit = int(request.query.get("limit") or 100)
    return web.json_response({"events": ctx.rfn.list_db_events(limit=limit)})


async def handle_rfn_cache(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    limit = int(request.query.get("limit") or 200)
    return web.json_response({"items": ctx.rfn.list_cache(limit=limit)})


async def handle_rfn_buffer(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    limit = int(request.query.get("limit") or 200)
    return web.json_response({"items": ctx.rfn.list_buffer(limit=limit)})


async def handle_rfn_exec(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    body = await request.json()
    name = str(body.get("function") or body.get("name") or "")
    args = body.get("args") or []
    if not isinstance(args, list):
        raise web.HTTPBadRequest(reason="args must be a JSON array")
    if not name:
        raise web.HTTPBadRequest(reason="missing function")
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, ctx.rfn.exec_function, name, args)
    return web.json_response(result)


async def handle_rfn_imports_list(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    return web.json_response({"items": ctx.rfn_imports.list(), "root": str(ctx.rfn_imports.root)})


async def handle_rfn_import_validate(request: web.Request) -> web.Response:
    body = await request.json()
    source = str(body.get("source") or "")
    args = body.get("args") if isinstance(body.get("args"), list) else []
    return web.json_response(validate_import_source(source, args_count=len(args)))


async def handle_rfn_import_run_source(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    body = await request.json()
    source = str(body.get("source") or "")
    args = body.get("args") if isinstance(body.get("args"), list) else []
    if not source.strip():
        raise web.HTTPBadRequest(reason="missing RFN source")
    function = str(body.get("function") or "")
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, ctx.run_imported_rfn_source, source, function, args)
    return web.json_response(result)


async def handle_rfn_import_save(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    body = await request.json()
    name = str(body.get("name") or "")
    source = str(body.get("source") or "")
    if not name:
        raise web.HTTPBadRequest(reason="missing name")
    if not source.strip():
        raise web.HTTPBadRequest(reason="missing RFN source")
    try:
        result = ctx.rfn_imports.save(name, source)
    except ValueError as exc:
        raise web.HTTPBadRequest(reason=str(exc))
    return web.json_response(result)


async def handle_rfn_import_run_saved(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    name = request.match_info["name"]
    body = await request.json() if request.can_read_body else {}
    args = body.get("args") if isinstance(body.get("args"), list) else []
    function = str(body.get("function") or "")
    try:
        source = ctx.rfn_imports.get(name)
    except ValueError as exc:
        raise web.HTTPBadRequest(reason=str(exc))
    except FileNotFoundError:
        return web.json_response({"ok": False, "error_code": "E_NOT_FOUND", "name": name}, status=404)
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, ctx.run_imported_rfn_source, source, function, args)
    return web.json_response(result)


async def handle_rfn_import_delete(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    try:
        result = ctx.rfn_imports.delete(request.match_info["name"])
    except ValueError as exc:
        raise web.HTTPBadRequest(reason=str(exc))
    status = 200 if result.get("ok") else 404
    return web.json_response(result, status=status)


async def handle_rfn_job_run(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    key = request.match_info["job_key"]
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, ctx.rfn.run_job_once, key)
    return web.json_response(result)


async def handle_rfn_job_cancel(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    key = request.match_info["job_key"]
    return web.json_response(ctx.rfn.cancel_job(key))


async def handle_rfn_job_enable(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    key = request.match_info["job_key"]
    body = await request.json() if request.can_read_body else {}
    enabled = bool(body.get("enabled", True))
    return web.json_response(ctx.rfn.set_job_enabled(key, enabled))



RKS_VERSION = "0.0"
RKS_STATUS = "reserved"


async def handle_rks_status(request: web.Request) -> web.Response:
    return web.json_response({
        "ok": True,
        "status": RKS_STATUS,
        "version": RKS_VERSION,
        "compiler_loaded": False,
        "runtime_loaded": False,
        "note": "RKS compiler not implemented; endpoints reserved for future use",
    })


async def handle_rks_compile_dryrun(request: web.Request) -> web.Response:
    body = await request.json() if request.can_read_body else {}
    return web.json_response({
        "ok": False,
        "error_code": "E_NOT_IMPLEMENTED",
        "error": "RKS compile dry-run not implemented",
        "input_size": len(str(body.get("source") or "")),
        "phase": "compile-dryrun",
    }, status=501)


async def handle_rks_run_dryrun(request: web.Request) -> web.Response:
    body = await request.json() if request.can_read_body else {}
    return web.json_response({
        "ok": False,
        "error_code": "E_NOT_IMPLEMENTED",
        "error": "RKS run dry-run not implemented",
        "input_size": len(str(body.get("source") or "")),
        "phase": "run-dryrun",
    }, status=501)


async def handle_rfn_console_page(request: web.Request) -> web.FileResponse:
    ctx: AppContext = request.app["ctx"]
    return web.FileResponse(ctx.static_dir / "assets" / "rfn-console.html")


async def handle_settings(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    return web.json_response({"settings": ctx.settings.get()})


async def handle_settings_save(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    body = await request.json()
    settings = ctx.settings.save(body.get("settings", body))
    return web.json_response({"ok": True, "settings": settings})


async def handle_opcodes(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    ctx.registry.reload_if_changed()
    items = ctx.registry.list_opcodes()
    return web.json_response({
        "opcodes": items,
        "stats": ctx.registry.stats(),
    })


def _parse_opcode_param(s: str) -> int:
    s = s.strip()
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s, 10)
    except ValueError:
        raise web.HTTPBadRequest(reason=f"非法 opcode: {s!r}")


def _rfn_web_response(rsp: dict[str, Any]) -> web.Response:
    status = int(rsp.get("status") or 200)
    content_type = str(rsp.get("content_type") or "application/json")
    headers = {str(k): str(v) for k, v in dict(rsp.get("headers") or {}).items()}
    headers["Content-Type"] = content_type
    body = rsp.get("body")
    if isinstance(body, bytes):
        raw = body
    elif content_type.startswith("application/json"):
        raw = json.dumps(body, ensure_ascii=False, default=str).encode("utf-8")
    elif body is None:
        raw = b""
    else:
        raw = str(body).encode("utf-8")
    return web.Response(status=status, body=raw, headers=headers)


async def handle_opcode_detail(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    ctx.registry.reload_if_changed()
    op = _parse_opcode_param(request.match_info["op"])
    meta = ctx.registry.get_opcode_meta(op)
    schema = ctx.registry.get_opcode_schema(op)
    if meta is None and schema is None:
        raise web.HTTPNotFound(reason=f"opcode 0x{op:04X} 不在注册表中")
    return web.json_response({
        "meta": meta or {"id": op, "hex": f"0x{op:04X}", "schema_status": "absent"},
        "fields": expand_schema_for_ui(schema, ctx.registry),
    })


async def handle_decode(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    body = await request.json()
    op = _parse_opcode_param(str(body.get("opcode_hex", body.get("opcode", ""))))
    payload_hex = (body.get("payload_hex") or "").replace(" ", "").replace("\n", "")
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError as exc:
        raise web.HTTPBadRequest(reason=f"payload_hex 非法: {exc}")
    schema = ctx.registry.get_opcode_schema(op)
    if schema is None:
        return web.json_response({
            "status": "no_schema",
            "fields": proto_codec.scan_fields(payload),
        })
    try:
        decoded, decode_source = ctx._decode_opcode_payload(op, schema, payload)
    except Exception as exc:
        return web.json_response({"status": "error", "error": str(exc)}, status=200)
    return web.json_response({"status": "ok", "decoded": decoded, "decode_source": decode_source})


async def handle_encode(request: web.Request) -> web.Response:
    ctx: AppContext = request.app["ctx"]
    body = await request.json()
    op = _parse_opcode_param(str(body.get("opcode_hex", body.get("opcode", ""))))
    value = body.get("value") or {}
    schema = ctx.registry.get_opcode_schema(op)
    if schema is None:
        raise web.HTTPBadRequest(reason=f"opcode 0x{op:04X} 无 schema，请直接用 hex 模式")
    try:
        raw = proto_codec.encode_payload(schema, value, resolve_message=ctx.registry.resolve_message)
    except (proto_codec.SchemaError, ValueError, TypeError) as exc:
        raise web.HTTPBadRequest(reason=f"编码失败: {exc}")
    return web.json_response({"payload_hex": raw.hex(), "payload_len": len(raw)})


def _make_store_handlers(store_attr: str):
    async def list_(request: web.Request) -> web.Response:
        ctx: AppContext = request.app["ctx"]
        store: JsonStore = getattr(ctx, store_attr)
        return web.json_response({"items": store.list()})

    async def save(request: web.Request) -> web.Response:
        ctx: AppContext = request.app["ctx"]
        store: JsonStore = getattr(ctx, store_attr)
        body = await request.json()
        name = body.get("name")
        if not name:
            raise web.HTTPBadRequest(reason="缺少 name 字段")
        store.save(name, body)
        return web.json_response({"ok": True, "name": name})

    async def delete(request: web.Request) -> web.Response:
        ctx: AppContext = request.app["ctx"]
        store: JsonStore = getattr(ctx, store_attr)
        name = request.match_info["name"]
        ok = store.delete(name)
        return web.json_response({"ok": ok})

    return list_, save, delete



async def handle_ws(request: web.Request) -> web.WebSocketResponse:
    ctx: AppContext = request.app["ctx"]
    ws = web.WebSocketResponse(heartbeat=20.0, max_msg_size=4 * 1024 * 1024)
    await ws.prepare(request)

    queue = await ctx.bus.subscribe(replay_last=200)

    if not await _safe_send_json(ws, {
        "type": "hello",
        "ts": time.time(),
        "status": ctx.session_status(),
    }):
        await ctx.bus.unsubscribe(queue)
        return ws

    sender_task = asyncio.create_task(_ws_sender(ws, queue))
    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                except Exception:
                    await _safe_send_json(ws, {"type": "error", "error": "invalid json"})
                    continue
                await _handle_ws_command(ctx, ws, data)
            elif msg.type == WSMsgType.ERROR:
                break
    finally:
        sender_task.cancel()
        with suppress(asyncio.CancelledError):
            await sender_task
        await ctx.bus.unsubscribe(queue)
    return ws


async def _safe_send_json(ws: web.WebSocketResponse, payload: dict) -> bool:
    try:
        await ws.send_json(payload)
        return True
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError, RuntimeError):
        return False


async def _ws_sender(ws: web.WebSocketResponse, queue: asyncio.Queue) -> None:
    """从 EventBus 拉取事件并批量发送给浏览器。"""
    BATCH_MAX = 32
    BATCH_WINDOW = 0.04  # 40ms
    loop = asyncio.get_running_loop()
    while True:
        first = await queue.get()
        batch = [first]
        deadline = loop.time() + BATCH_WINDOW
        while len(batch) < BATCH_MAX:
            timeout = deadline - loop.time()
            if timeout <= 0:
                break
            try:
                batch.append(await asyncio.wait_for(queue.get(), timeout=timeout))
            except asyncio.TimeoutError:
                break
        try:
            if len(batch) == 1:
                ok = await _safe_send_json(ws, batch[0])
            else:
                ok = await _safe_send_json(ws, {"type": "batch", "events": batch})
            if not ok:
                return
        except RuntimeError:
            return


async def _handle_ws_command(ctx: AppContext, ws: web.WebSocketResponse, data: dict) -> None:
    op = data.get("op")
    rid = data.get("rid")
    try:
        if op == "ping":
            await _safe_send_json(ws, {"type": "pong", "rid": rid, "ts": time.time()})
            return
        if op == "status":
            await _safe_send_json(ws, {"type": "status", "rid": rid, "data": ctx.session_status()})
            return
        if op == "history":
            limit = int(data.get("limit") or 500)
            await _safe_send_json(ws, {"type": "history", "rid": rid, "events": ctx.bus.history_snapshot(limit)})
            return
        if op == "decode_now":
            opcode = _parse_opcode_param(str(data.get("opcode_hex") or data.get("opcode") or ""))
            target_seq = int(data.get("target_seq") or 0)
            payload_hex = (data.get("payload_hex") or "").replace(" ", "").replace("\n", "")
            if target_seq <= 0:
                raise ValueError("missing target_seq")
            if not payload_hex:
                raise ValueError("missing payload_hex")
            job = {"target_seq": target_seq, "opcode": opcode, "payload_hex": payload_hex}
            loop = asyncio.get_running_loop()
            patch = await loop.run_in_executor(None, ctx._decode_packet_patch, job)
            ctx.bus.publish(patch)
            await _safe_send_json(ws, {"type": "ack", "rid": rid})
            return
        if op == "inject":
            opcode = _parse_opcode_param(str(data.get("opcode_hex") or data.get("opcode") or ""))
            payload_hex = (data.get("payload_hex") or "").replace(" ", "").replace("\n", "")
            if not payload_hex and "value" in data:
                schema = ctx.registry.get_opcode_schema(opcode)
                if schema is None:
                    raise ValueError(f"opcode 0x{opcode:04X} 无 schema，请直接传 payload_hex")
                payload = proto_codec.encode_payload(
                    schema, data["value"], resolve_message=ctx.registry.resolve_message
                )
            else:
                payload = bytes.fromhex(payload_hex)
            sess = proxy_mod.get_active_session()
            if sess is None:
                raise proxy_mod.InjectError("无活动会话")
            info = sess.inject(opcode=opcode, payload=payload)
            await _safe_send_json(ws, {"type": "inject_ack", "rid": rid, "info": info})
            return
        if op == "shutdown":
            proxy_mod.request_shutdown("ws shutdown")
            await _safe_send_json(ws, {"type": "ack", "rid": rid})
            return
        await _safe_send_json(ws, {"type": "error", "rid": rid, "error": f"未知 op: {op!r}"})
    except (proxy_mod.InjectError, ValueError, proto_codec.SchemaError) as exc:
        await _safe_send_json(ws, {"type": "error", "rid": rid, "error": str(exc)})
    except Exception as exc:
        await _safe_send_json(ws, {"type": "error", "rid": rid, "error": f"{type(exc).__name__}: {exc}"})



def build_app(ctx: AppContext) -> web.Application:
    @web.middleware
    async def _no_cache_static(request: web.Request, handler):
        response = await handler(request)
        if request.path == "/" or request.path.startswith("/assets/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    app = web.Application(client_max_size=4 * 1024 * 1024, middlewares=[_no_cache_static])
    app["ctx"] = ctx

    async def _cleanup(app: web.Application) -> None:
        await app["ctx"].close()

    app.on_cleanup.append(_cleanup)

    app.router.add_get("/", handle_index)
    app.router.add_get("/api/status", handle_status)
    app.router.add_get("/api/rfn/status", handle_rfn_status)
    app.router.add_post("/api/rfn/reload", handle_rfn_reload)
    app.router.add_get("/api/rfn/functions", handle_rfn_functions)
    app.router.add_get("/api/rfn/bindings", handle_rfn_bindings)
    app.router.add_get("/api/rfn/jobs", handle_rfn_jobs)
    app.router.add_post("/api/rfn/jobs/{job_key}/run", handle_rfn_job_run)
    app.router.add_post("/api/rfn/jobs/{job_key}/cancel", handle_rfn_job_cancel)
    app.router.add_post("/api/rfn/jobs/{job_key}/enable", handle_rfn_job_enable)
    app.router.add_get("/api/rfn/db/namespaces", handle_rfn_db_namespaces)
    app.router.add_get("/api/rfn/db/kv/{namespace}", handle_rfn_db_kv)
    app.router.add_get("/api/rfn/db/table/{name}", handle_rfn_db_table)
    app.router.add_get("/api/rfn/db/events", handle_rfn_db_events)
    app.router.add_get("/api/rfn/cache", handle_rfn_cache)
    app.router.add_get("/api/rfn/buffer", handle_rfn_buffer)
    app.router.add_post("/api/rfn/exec", handle_rfn_exec)
    app.router.add_get("/api/rfn/imports", handle_rfn_imports_list)
    app.router.add_post("/api/rfn/imports", handle_rfn_import_save)
    app.router.add_post("/api/rfn/imports/validate", handle_rfn_import_validate)
    app.router.add_post("/api/rfn/imports/run", handle_rfn_import_run_source)
    app.router.add_post("/api/rfn/imports/{name}/run", handle_rfn_import_run_saved)
    app.router.add_delete("/api/rfn/imports/{name}", handle_rfn_import_delete)
    app.router.add_get("/api/rks/status", handle_rks_status)
    app.router.add_post("/api/rks/compile-dryrun", handle_rks_compile_dryrun)
    app.router.add_post("/api/rks/run-dryrun", handle_rks_run_dryrun)
    app.router.add_get("/rfn-console", handle_rfn_console_page)
    app.router.add_get("/api/settings", handle_settings)
    app.router.add_post("/api/settings", handle_settings_save)
    app.router.add_get("/api/opcodes", handle_opcodes)
    app.router.add_get("/api/opcodes/{op}", handle_opcode_detail)
    app.router.add_post("/api/decode", handle_decode)
    app.router.add_post("/api/encode", handle_encode)

    tpl_list, tpl_save, tpl_del = _make_store_handlers("templates")
    app.router.add_get("/api/templates", tpl_list)
    app.router.add_post("/api/templates", tpl_save)
    app.router.add_delete("/api/templates/{name}", tpl_del)

    flt_list, flt_save, flt_del = _make_store_handlers("filters")
    app.router.add_get("/api/filters", flt_list)
    app.router.add_post("/api/filters", flt_save)
    app.router.add_delete("/api/filters/{name}", flt_del)

    app.router.add_route("*", "/rfn/{tail:.*}", handle_rfn_route)
    app.router.add_get("/ws", handle_ws)

    if ctx.static_dir.exists():
        app.router.add_static("/assets/", ctx.static_dir / "assets", show_index=False)

    return app

