from __future__ import annotations

import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from roco_mitm.codec.opcode_registry import OpcodeRegistry
from roco_mitm.paths import project_root, runtime_dir

from .assembler import assemble_source
from .errors import RFNError
from .host import RFNHost
from .manifest import compile_manifest
from .model import Module
from .runtime import RFNRuntime


InjectFunc = Callable[[int, bytes, int | None], dict[str, Any]]
SessionDisconnectFunc = Callable[[str], dict[str, Any]]


@dataclass
class _PendingQuery:
    key: str
    req_target: Any
    rsp_target: Any
    request: dict[str, Any]
    predicate: Callable[[dict, dict], bool] | None
    deadline_ms: int
    sent: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    waiters: int = 0
    condition: threading.Condition = field(default_factory=lambda: threading.Condition(threading.RLock()))


class RFNLiveRuntime:
    """Live RFN bridge used by the aiohttp MITM server.

    The proxy hook only enqueues packets. Actual RFN execution runs from Web app
    workers/executors, so slow scripts cannot block socket forwarding.
    """

    def __init__(
        self,
        *,
        script_root: Path | None = None,
        registry: OpcodeRegistry | None = None,
        db_path: Path | None = None,
        file_root: Path | None = None,
        inject_func: InjectFunc | None = None,
        session_disconnect_func: SessionDisconnectFunc | None = None,
    ):
        self.script_root = (script_root or (project_root() / "MITMScript")).resolve()
        self.registry = registry
        self.db_path = (db_path or (runtime_dir() / "scripts" / "rfn_live.sqlite")).resolve()
        self.file_root = (file_root or (runtime_dir() / "scripts")).resolve()
        self.inject_func = inject_func
        self.session_disconnect_func = session_disconnect_func
        self.host: RFNHost | None = None
        self.runtime: RFNRuntime | None = None
        self.module: Module | None = None
        self.manifest: dict[str, Any] = {"bindings": []}
        self.loaded = False
        self.enabled = False
        self.last_error = ""
        self.source_files: list[str] = []
        self.manifest_files: list[str] = []
        self._lock = threading.RLock()
        self._active_condition = threading.Condition(self._lock)
        self._active_calls = 0
        self._pending: dict[str, _PendingQuery] = {}
        self._last_results: deque[dict[str, Any]] = deque(maxlen=32)
        self._last_errors: deque[dict[str, Any]] = deque(maxlen=32)
        self._trigger_counts: dict[str, int] = {}
        self._trigger_last: dict[str, dict[str, Any]] = {}
        self._job_history: dict[str, dict[str, Any]] = {}
        self._stats: dict[str, int] = {
            "packet_seen": 0,
            "packet_matched": 0,
            "packet_fast_ignored": 0,
            "packet_triggered": 0,
            "http_seen": 0,
            "http_handled": 0,
            "job_runs": 0,
            "query_sent": 0,
            "query_matched": 0,
            "query_timeout": 0,
            "drain_timeout": 0,
        }
        self.reload()

    def wants_packet(self, packet: dict[str, Any]) -> bool:
        if packet.get("kind") == "inject":
            return False
        runtime = self.runtime
        if runtime is None:
            return False
        packet = _normalize_packet(packet)
        return self._packet_has_active_interest(packet, runtime)

    def reload(self) -> dict[str, Any]:
        self._fail_pending("E_RELOAD", "RFN live runtime is reloading")
        if not self._wait_for_active_calls():
            self._record_drain_timeout("reload")
            return self.status()
        with self._lock:
            host = self.host
            self.host = None
            self.runtime = None
            self.module = None
            self.loaded = False
            self.enabled = False
            self.last_error = ""
            self.source_files = []
            self.manifest_files = []
        if host is not None:
            host.close()
        try:
            function_paths = _find_function_files(self.script_root)
            manifest_paths = _find_manifest_files(self.script_root)
            if not function_paths:
                with self._lock:
                    self.last_error = f"no RFN function files under {self.script_root / 'Function'}"
                return self.status()
            source = "\n\n".join(path.read_text(encoding="utf-8-sig") for path in function_paths)
            module = assemble_source(source, module_name="live")
            manifest = _load_manifest(manifest_paths)
            host = RFNHost(
                registry=self.registry,
                db_path=self.db_path,
                mode="live",
                file_root=self.file_root,
                inject_func=self._inject,
                session_disconnect_func=self._session_disconnect,
                default_query_timeout_ms=3000,
            )
            runtime = RFNRuntime(module, manifest, host)
            host.query_func = self._query
            self._install_schedule_bindings(runtime)
            with self._lock:
                self.host = host
                self.runtime = runtime
                self.module = module
                self.manifest = manifest
                self.source_files = [str(p) for p in function_paths]
                self.manifest_files = [str(p) for p in manifest_paths]
                self.loaded = True
                self.enabled = bool(manifest.get("bindings"))
        except Exception as exc:
            with self._lock:
                self.last_error = f"{type(exc).__name__}: {exc}"
                self._record_error_locked("reload", exc, {})
        return self.status()

    def close(self) -> None:
        self._fail_pending("E_CLOSED", "RFN live runtime is closed")
        if not self._wait_for_active_calls():
            self._record_drain_timeout("close")
            return
        with self._lock:
            host = self.host
            self.host = None
            self.runtime = None
            self.module = None
        if host is not None:
            host.close()

    def status(self) -> dict[str, Any]:
        with self._lock:
            host = self.host
            return {
                "loaded": self.loaded,
                "enabled": self.enabled,
                "last_error": self.last_error,
                "script_root": str(self.script_root),
                "db_path": str(self.db_path),
                "file_root": str(self.file_root),
                "source_files": list(self.source_files),
                "manifest_files": list(self.manifest_files),
                "function_count": len(self.module.functions) if self.module else 0,
                "binding_count": len(self.manifest.get("bindings") or []),
                "job_count": len(host.jobs) if host is not None else 0,
                "active_calls": self._active_calls,
                "pending_queries": len(self._pending),
                "stats": dict(self._stats),
                "last_results": [_json_safe(x) for x in self._last_results],
                "last_errors": [_json_safe(x) for x in self._last_errors],
            }

    def handle_packet(self, packet: dict[str, Any]) -> list[dict[str, Any]]:
        if packet.get("kind") == "inject":
            return []
        runtime = self.runtime
        if runtime is None:
            return []
        packet = _normalize_packet(packet)
        if not self._packet_has_active_interest(packet, runtime):
            with self._lock:
                self._stats["packet_fast_ignored"] += 1
            return []
        with self._lock:
            self._stats["packet_seen"] += 1
            self._stats["packet_matched"] += 1
        self._enter_active_call()
        try:
            self.observe_packet(packet)
            results = runtime.handle_packet(packet)
            if results:
                with self._lock:
                    self._stats["packet_triggered"] += len(results)
                    for item in results:
                        self._last_results.append({"kind": "packet", "packet": _packet_summary(packet), "result": item})
                for item in results:
                    binding = _find_binding(runtime.manifest, item.get("binding"))
                    if binding is not None:
                        self.record_binding_trigger(binding, {"packet": _packet_summary(packet), "result": item.get("result")})
            return results
        except Exception as exc:
            self._record_error("packet", exc, {"packet": _packet_summary(packet)})
            return []
        finally:
            self._leave_active_call()

    def _packet_has_active_interest(self, packet: dict[str, Any], runtime: RFNRuntime) -> bool:
        with self._lock:
            pending = list(self._pending.values())
            manifest = dict(runtime.manifest or {})
            host = self.host
        for item in pending:
            if _target_matches(item.rsp_target, packet, host):
                return True
        for binding in manifest.get("bindings") or []:
            if binding.get("kind") == "packet" and _packet_binding_matches(binding, packet, host):
                return True
        return False

    def handle_http(self, request: dict[str, Any]) -> dict[str, Any]:
        runtime = self.runtime
        with self._lock:
            self._stats["http_seen"] += 1
        if runtime is None:
            return {"status": 503, "content_type": "application/json", "body": {"error": "RFN runtime not loaded"}}
        self._enter_active_call()
        try:
            result = runtime.handle_http(request)
            with self._lock:
                self._stats["http_handled"] += 1
                self._last_results.append({"kind": "http", "path": request.get("path"), "result": result})
            binding = _find_http_binding(runtime.manifest, request)
            if binding is not None:
                self.record_binding_trigger(
                    binding,
                    {"path": request.get("path"), "status": (result or {}).get("status") if isinstance(result, dict) else None},
                )
            return _normalize_http_response(result)
        except Exception as exc:
            self._record_error("http", exc, {"path": request.get("path")})
            return {"status": 500, "content_type": "application/json", "body": {"error": f"{type(exc).__name__}: {exc}"}}
        finally:
            self._leave_active_call()

    def run_due_jobs(self, *, now_ms: int | None = None, limit: int = 100) -> list[dict[str, Any]]:
        runtime = self.runtime
        if runtime is None:
            return []
        self._enter_active_call()
        try:
            results = runtime.run_due_jobs(now_ms=now_ms, limit=limit)
            if results:
                with self._lock:
                    self._stats["job_runs"] += len(results)
                    for item in results:
                        self._last_results.append({"kind": "schedule", "result": item})
                        if item.get("ok") and item.get("job_key"):
                            self._job_history[str(item["job_key"])] = {
                                "last_run_at": int(time.time() * 1000),
                                "last_elapsed_ms": 0,
                                "last_result": _json_safe(item.get("result")),
                            }
            return results
        except Exception as exc:
            self._record_error("schedule", exc, {})
            return []
        finally:
            self._leave_active_call()

    def observe_packet(self, packet: dict[str, Any]) -> None:
        matched: list[_PendingQuery] = []
        decoded = packet.get("decoded")
        if not isinstance(decoded, dict):
            decoded = {}
        now_ms = int(time.time() * 1000)
        with self._lock:
            expired = [key for key, pending in self._pending.items() if pending.deadline_ms <= now_ms]
            for key in expired:
                self._pending.pop(key, None)
            for pending in list(self._pending.values()):
                if not _target_matches(pending.rsp_target, packet, self.host):
                    continue
                if pending.predicate is not None and not pending.predicate(decoded, pending.request):
                    continue
                pending.result = {
                    "ok": True,
                    "req_target": str(pending.req_target),
                    "rsp_target": str(pending.rsp_target),
                    "singleflight_key": pending.key,
                    "decoded": decoded,
                    "payload": bytes.fromhex(str(packet.get("payload_hex") or "")) if packet.get("payload_hex") else b"",
                    "packet": _packet_summary(packet),
                    "match_source": "live_observed_packet",
                }
                matched.append(pending)
                self._pending.pop(pending.key, None)
                self._stats["query_matched"] += 1
        for pending in matched:
            with pending.condition:
                pending.condition.notify_all()

    def _query(
        self,
        req_target: Any,
        value_or_bytes: Any,
        rsp_target: Any,
        predicate: Callable[[dict, dict], bool] | None,
        singleflight_key: str | None,
        timeout_ms: int,
    ) -> dict[str, Any]:
        self._enter_active_call()
        try:
            return self._query_active(req_target, value_or_bytes, rsp_target, predicate, singleflight_key, timeout_ms)
        finally:
            self._leave_active_call()

    def _query_active(
        self,
        req_target: Any,
        value_or_bytes: Any,
        rsp_target: Any,
        predicate: Callable[[dict, dict], bool] | None,
        singleflight_key: str | None,
        timeout_ms: int,
    ) -> dict[str, Any]:
        request = value_or_bytes if isinstance(value_or_bytes, dict) else {}
        key = singleflight_key or _query_key(req_target, value_or_bytes, rsp_target)
        deadline_ms = int(time.time() * 1000) + max(1, int(timeout_ms))
        should_send = False
        with self._lock:
            pending = self._pending.get(key)
            if pending is None:
                pending = _PendingQuery(key, req_target, rsp_target, request, predicate, deadline_ms)
                self._pending[key] = pending
                should_send = True
            pending.waiters += 1
        if should_send:
            with self._lock:
                host = self.host
                if host is None:
                    pending.sent = {"ok": False, "error_code": "E_CLOSED", "error": "RFN live runtime is closed"}
                else:
                    pending.sent = host.inject_send(req_target, value_or_bytes)
                self._stats["query_sent"] += 1
            if not pending.sent.get("ok"):
                error_result = {
                    "ok": False,
                    "error_code": pending.sent.get("error_code") or "E_INJECT",
                    "error": pending.sent.get("error"),
                    "singleflight_key": pending.key,
                }
                with self._lock:
                    self._pending.pop(key, None)
                with pending.condition:
                    pending.result = error_result
                    pending.condition.notify_all()
                return {**error_result, "sent": pending.sent}
        timeout_s = max(0.001, (deadline_ms - int(time.time() * 1000)) / 1000)
        with pending.condition:
            pending.condition.wait_for(lambda: pending.result is not None, timeout=timeout_s)
        with self._lock:
            pending.waiters -= 1
            result = pending.result
            if result is None and self._pending.get(key) is pending and pending.waiters <= 0:
                self._pending.pop(key, None)
        if result is not None:
            result = dict(result)
            result["sent"] = pending.sent
            return result
        with self._lock:
            self._stats["query_timeout"] += 1
        return {"ok": False, "error_code": "E_QUERY_TIMEOUT", "error": "query response timeout", "sent": pending.sent}

    def _inject(self, opcode: int, payload: bytes, fallback_opcode: int | None = None) -> dict[str, Any]:
        if self.inject_func is None:
            raise RuntimeError("live inject is not available")
        return self.inject_func(opcode, payload, fallback_opcode)

    def _session_disconnect(self, reason: str) -> dict[str, Any]:
        if self.session_disconnect_func is None:
            return {"ok": False, "error_code": "E_UNSUPPORTED", "error": "session disconnect is not available"}
        return self.session_disconnect_func(reason)

    def _install_schedule_bindings(self, runtime: RFNRuntime) -> None:
        for binding in runtime.manifest.get("bindings", []):
            if binding.get("kind") != "schedule":
                continue
            func = str(binding.get("func") or "")
            job_key = str(binding.get("job_key") or binding.get("name") or func)
            args = binding.get("args") if isinstance(binding.get("args"), list) else []
            if "every_ms" in binding:
                runtime.host.schedule_every(int(binding["every_ms"]), func, args, job_key)
            elif "after_ms" in binding:
                runtime.host.schedule_after(int(binding["after_ms"]), func, args, job_key)
            elif "cron" in binding:
                runtime.host.schedule_cron(str(binding["cron"]), func, args, job_key)

    def _record_error(self, kind: str, exc: Exception, detail: dict[str, Any]) -> None:
        with self._lock:
            self._record_error_locked(kind, exc, detail)

    def _record_error_locked(self, kind: str, exc: Exception, detail: dict[str, Any]) -> None:
        self._last_errors.append({
            "kind": kind,
            "error": f"{type(exc).__name__}: {exc}",
            "detail": detail,
            "ts": int(time.time() * 1000),
        })

    def _fail_pending(self, error_code: str, error: str) -> None:
        with self._lock:
            pending_items = list(self._pending.values())
            self._pending.clear()
            for pending in pending_items:
                if pending.result is None:
                    pending.result = {
                        "ok": False,
                        "error_code": error_code,
                        "error": error,
                        "singleflight_key": pending.key,
                    }
        for pending in pending_items:
            with pending.condition:
                pending.condition.notify_all()

    def _enter_active_call(self) -> None:
        # This is a nested active-call depth, not a unique handler/thread count.
        with self._lock:
            self._active_calls += 1

    def _leave_active_call(self) -> None:
        with self._lock:
            self._active_calls = max(0, self._active_calls - 1)
            if self._active_calls == 0:
                self._active_condition.notify_all()


    def list_functions(self) -> list[dict[str, Any]]:
        with self._lock:
            module = self.module
            manifest = self.manifest
        if module is None:
            return []
        binding_by_func: dict[str, list[dict[str, Any]]] = {}
        for binding in manifest.get("bindings") or []:
            func_name = str(binding.get("func") or "")
            short = func_name.split("Function.", 1)[1] if func_name.startswith("Function.") else func_name
            binding_by_func.setdefault(short, []).append({
                "kind": binding.get("kind"),
                "name": binding.get("name"),
                "direction": binding.get("direction"),
                "target": binding.get("target"),
                "method": binding.get("method"),
                "path": binding.get("path"),
                "every_ms": binding.get("every_ms"),
                "after_ms": binding.get("after_ms"),
                "cron": binding.get("cron"),
                "job_key": binding.get("job_key"),
            })
        out: list[dict[str, Any]] = []
        for fn in module.functions.values():
            out.append({
                "name": fn.name,
                "args": [{"name": n, "type": t} for n, t in fn.args],
                "return": fn.return_type,
                "no_side_effect": fn.no_side_effect,
                "deterministic": fn.deterministic,
                "capabilities": [{"name": cap.name, **cap.scope} for cap in fn.capabilities],
                "max_ops": fn.max_ops,
                "bindings": binding_by_func.get(fn.name, []),
                "arity": len(fn.args),
            })
        return out

    def list_bindings(self) -> dict[str, list[dict[str, Any]]]:
        with self._lock:
            bindings = list(self.manifest.get("bindings") or [])
            triggers = dict(self._trigger_counts)
            last = {k: _json_safe(v) for k, v in self._trigger_last.items()}
        out: dict[str, list[dict[str, Any]]] = {"packet": [], "http": [], "schedule": []}
        for binding in bindings:
            kind = binding.get("kind") or ""
            row = dict(binding)
            row["trigger_count"] = int(triggers.get(_binding_id(binding), 0))
            row["last_trigger"] = last.get(_binding_id(binding))
            bucket = "schedule" if kind == "schedule" else ("http" if kind in {"http", "http.server"} else "packet")
            out.setdefault(bucket, []).append(row)
        return out

    def list_jobs(self) -> list[dict[str, Any]]:
        with self._lock:
            host = self.host
            history = {k: dict(v) for k, v in self._job_history.items()}
        if host is None:
            return []
        rows = host.list_db_jobs()
        in_memory = dict(host.jobs)
        merged: dict[str, dict[str, Any]] = {}
        for row in rows:
            spec = row.get("spec") or {}
            merged[row["id"]] = {
                "job_key": row["id"],
                "kind": spec.get("kind"),
                "func": spec.get("func"),
                "next_run_at": row["next_run_at"],
                "interval_ms": spec.get("interval_ms"),
                "cron_expr": spec.get("cron_expr"),
                "enabled": row["enabled"],
                "in_memory": row["id"] in in_memory,
                **history.get(row["id"], {}),
            }
        for key, job in in_memory.items():
            if key in merged:
                continue
            merged[key] = {
                "job_key": key,
                "kind": job.get("kind"),
                "func": job.get("func"),
                "next_run_at": int(job.get("next_run_at") or 0),
                "interval_ms": job.get("interval_ms"),
                "cron_expr": job.get("cron_expr"),
                "enabled": True,
                "in_memory": True,
                **history.get(key, {}),
            }
        return list(merged.values())

    def list_db_namespaces(self) -> list[dict[str, Any]]:
        return self.host.list_db_namespaces() if self.host else []

    def list_db_kv(self, namespace: str, *, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        return self.host.list_db_kv(namespace, limit=limit, offset=offset) if self.host else []

    def list_db_table(self, name: str, *, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        return self.host.list_db_table(name, limit=limit, offset=offset) if self.host else []

    def list_db_events(self, *, limit: int = 100) -> list[dict[str, Any]]:
        return self.host.list_db_events(limit=limit) if self.host else []

    def list_cache(self, *, limit: int = 200) -> list[dict[str, Any]]:
        return self.host.list_cache(limit=limit) if self.host else []

    def list_buffer(self, *, limit: int = 200) -> list[dict[str, Any]]:
        return self.host.list_buffer(limit=limit) if self.host else []

    def get_blob_meta(self, namespace: str, key: str) -> dict[str, Any] | None:
        return self.host.get_db_blob_meta(namespace, key) if self.host else None

    def exec_function(self, name: str, args: list[Any]) -> dict[str, Any]:
        runtime = self.runtime
        if runtime is None:
            return {"ok": False, "error_code": "E_NOT_LOADED", "error": "RFN runtime not loaded"}
        short = name.split("Function.", 1)[1] if name.startswith("Function.") else name
        fn = runtime.module.functions.get(short)
        if fn is None:
            return {"ok": False, "error_code": "E_NOT_FOUND", "error": f"function not found: {name}"}
        if len(args or []) != len(fn.args):
            return {
                "ok": False,
                "error_code": "E_ARG",
                "error": f"function expects {len(fn.args)} args, got {len(args or [])}",
            }
        self._enter_active_call()
        start = time.time()
        try:
            result = runtime.vm.call(short, *list(args or []))
            return {
                "ok": True,
                "function": short,
                "result": _json_safe(result),
                "elapsed_ms": int((time.time() - start) * 1000),
            }
        except RFNError as exc:
            return {"ok": False, "error_code": exc.code, "error": str(exc), "elapsed_ms": int((time.time() - start) * 1000)}
        except Exception as exc:
            self._record_error("exec", exc, {"function": name})
            return {"ok": False, "error_code": "E_FAIL", "error": f"{type(exc).__name__}: {exc}", "elapsed_ms": int((time.time() - start) * 1000)}
        finally:
            self._leave_active_call()

    def run_job_once(self, job_key: str) -> dict[str, Any]:
        runtime = self.runtime
        host = self.host
        if runtime is None or host is None:
            return {"ok": False, "error_code": "E_NOT_LOADED"}
        if job_key not in host.jobs:
            return {"ok": False, "error_code": "E_JOB_NOT_FOUND", "job_key": job_key}
        self._enter_active_call()
        start = time.time()
        try:
            result = runtime.run_job(job_key)
            elapsed = int((time.time() - start) * 1000)
            with self._lock:
                self._job_history[job_key] = {
                    "last_run_at": int(start * 1000),
                    "last_elapsed_ms": elapsed,
                    "last_result": _json_safe(result),
                }
            return {"ok": True, "job_key": job_key, "result": _json_safe(result), "elapsed_ms": elapsed}
        except Exception as exc:
            self._record_error("schedule.run_once", exc, {"job_key": job_key})
            return {"ok": False, "error_code": "E_FAIL", "error": f"{type(exc).__name__}: {exc}", "job_key": job_key}
        finally:
            self._leave_active_call()

    def cancel_job(self, job_key: str) -> dict[str, Any]:
        host = self.host
        if host is None:
            return {"ok": False, "error_code": "E_NOT_LOADED"}
        host.schedule_cancel(job_key)
        with self._lock:
            self._job_history.pop(job_key, None)
        return {"ok": True, "job_key": job_key}

    def set_job_enabled(self, job_key: str, enabled: bool) -> dict[str, Any]:
        host = self.host
        runtime = self.runtime
        if host is None or runtime is None:
            return {"ok": False, "error_code": "E_NOT_LOADED"}
        if enabled:
            spec_rows = [r for r in host.list_db_jobs() if r["id"] == job_key]
            if not spec_rows:
                return {"ok": False, "error_code": "E_JOB_NOT_FOUND", "job_key": job_key}
            spec = spec_rows[0].get("spec") or {}
            kind = spec.get("kind")
            func = spec.get("func") or ""
            args = spec.get("args") if isinstance(spec.get("args"), list) else []
            if kind == "every":
                host.schedule_every(int(spec.get("interval_ms") or 0), func, args, job_key)
            elif kind == "after":
                host.schedule_after(int(spec.get("delay_ms") or 0), func, args, job_key)
            elif kind == "cron":
                host.schedule_cron(str(spec.get("cron_expr") or ""), func, args, job_key)
        else:
            host.schedule_set_enabled(job_key, False)
        return {"ok": True, "job_key": job_key, "enabled": bool(enabled)}

    def record_binding_trigger(self, binding: dict[str, Any], result_summary: dict[str, Any]) -> None:
        bid = _binding_id(binding)
        with self._lock:
            self._trigger_counts[bid] = self._trigger_counts.get(bid, 0) + 1
            self._trigger_last[bid] = {"ts": int(time.time() * 1000), "summary": result_summary}

    def _wait_for_active_calls(self, timeout_s: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout_s
        with self._lock:
            while self._active_calls > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._active_condition.wait(remaining)
            return True

    def _record_drain_timeout(self, op: str) -> None:
        with self._lock:
            self._stats["drain_timeout"] += 1
            active_calls = self._active_calls
        self._record_error(
            "drain",
            TimeoutError(f"{op} timed out waiting for RFN active calls to drain"),
            {"op": op, "active_calls": active_calls},
        )

    def on_session_rotate(self, *, old_key: str = "", new_key: str = "") -> dict[str, Any]:
        """Clear session-scope cache/buffer and pending queries when game session_key rotates.

        Spec: RFN.md §packet trigger rules — "session key 变化时, session scope cache/buffer
        和 pending query 自动清空, 并写入 session.rotate 审计事件".
        """
        cleared_cache = 0
        cleared_buffer = 0
        cleared_pending: list[_PendingQuery] = []
        host = self.host
        with self._lock:
            if host is not None:
                cache_keys = [k for k in host.cache if k[0].startswith("session")]
                for k in cache_keys:
                    host.cache.pop(k, None)
                cleared_cache = len(cache_keys)
                buffer_keys = [k for k in host.buffers if k[0].startswith("session")]
                for k in buffer_keys:
                    host.buffers.pop(k, None)
                cleared_buffer = len(buffer_keys)
            for pending in self._pending.values():
                if pending.result is None:
                    pending.result = {
                        "ok": False,
                        "error_code": "E_SESSION_ROTATE",
                        "error": "session key rotated",
                        "singleflight_key": pending.key,
                    }
                cleared_pending.append(pending)
            self._pending.clear()
        for pending in cleared_pending:
            with pending.condition:
                pending.condition.notify_all()
        if host is not None:
            host.audit(
                "session.rotate",
                "session",
                "ok",
                {
                    "old_key_preview": (old_key or "")[:8],
                    "new_key_preview": (new_key or "")[:8],
                    "cleared_cache": cleared_cache,
                    "cleared_buffer": cleared_buffer,
                    "cleared_pending": len(cleared_pending),
                },
            )
        return {
            "ok": True,
            "cleared_cache": cleared_cache,
            "cleared_buffer": cleared_buffer,
            "cleared_pending": len(cleared_pending),
        }


def _find_function_files(script_root: Path) -> list[Path]:
    function_dir = script_root / "Function"
    if not function_dir.exists():
        return []
    return sorted(path for path in function_dir.rglob("*.rfn") if path.is_file())


def _find_manifest_files(script_root: Path) -> list[Path]:
    manifest_dir = script_root / "Manifest"
    if not manifest_dir.exists():
        return []
    return [
        *sorted(path for path in manifest_dir.glob("*.rfnmanifest") if path.is_file()),
        *sorted(path for path in manifest_dir.glob("*.manifest.json") if path.is_file()),
    ]


def _load_manifest(paths: list[Path]) -> dict[str, Any]:
    merged: dict[str, Any] = {"format": "rfn.manifest.v1", "bindings": []}
    for path in paths:
        text = path.read_text(encoding="utf-8-sig")
        manifest = compile_manifest(json.loads(text) if path.suffix == ".json" else text)
        merged["bindings"].extend(manifest.get("bindings") or [])
    return merged


def _normalize_packet(packet: dict[str, Any]) -> dict[str, Any]:
    out = dict(packet)
    wire = out.get("wire") if isinstance(out.get("wire"), dict) else {}
    internal = out.get("internal") if isinstance(out.get("internal"), dict) else {}
    if "sequence" in wire:
        out.setdefault("gcp_seq", wire.get("sequence"))
    if "session_id_hex" in internal:
        out.setdefault("session_id", internal.get("session_id_hex"))
    if "sub_id_hex" in internal:
        out.setdefault("sub_id", internal.get("sub_id_hex"))
    meta = out.get("opcode_meta") if isinstance(out.get("opcode_meta"), dict) else {}
    if meta.get("name") is not None:
        out.setdefault("name", meta.get("name"))
    return out


def _packet_summary(packet: dict[str, Any]) -> dict[str, Any]:
    meta = packet.get("opcode_meta") if isinstance(packet.get("opcode_meta"), dict) else {}
    wire = packet.get("wire") if isinstance(packet.get("wire"), dict) else {}
    name = packet.get("name") or meta.get("name")
    gcp_seq = packet.get("gcp_seq") or wire.get("sequence")
    return {
        "direction": packet.get("direction"),
        "kind": packet.get("kind"),
        "opcode": packet.get("opcode_hex") or packet.get("opcode"),
        "name": name,
        "gcp_seq": gcp_seq,
        "payload_len": packet.get("payload_len"),
        "decode_status": packet.get("decode_status"),
    }


def _target_matches(target: Any, packet: dict[str, Any], host: RFNHost | None) -> bool:
    wanted = {str(target)}
    try:
        if isinstance(target, int):
            wanted.add(f"0x{target:04X}")
        elif isinstance(target, str) and target.lower().startswith("0x"):
            wanted.add(f"0x{int(target, 16):04X}")
        if host is not None:
            route = host.route_resolve(target)
            for key in ("opcode_hex", "name", "proto"):
                value = route.get(key)
                if value:
                    wanted.add(str(value))
    except Exception:
        pass
    meta = packet.get("opcode_meta") if isinstance(packet.get("opcode_meta"), dict) else {}
    candidates = {
        str(packet.get("target") or ""),
        str(packet.get("name") or ""),
        str(packet.get("opcode_hex") or ""),
        str(packet.get("opcode") or ""),
        str(meta.get("name") or ""),
        str(meta.get("decode_as") or ""),
        str(meta.get("proto_name") or ""),
    }
    opcode = packet.get("opcode")
    if isinstance(opcode, int):
        candidates.add(f"0x{opcode:04X}")
    return bool(wanted & candidates)


def _packet_binding_matches(binding: dict[str, Any], packet: dict[str, Any], host: RFNHost | None) -> bool:
    direction = binding.get("direction")
    if direction and str(packet.get("direction") or "").lower() != str(direction).lower():
        return False
    target = binding.get("target")
    if target is None:
        return True
    return _target_matches(target, packet, host)


def _normalize_http_response(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"status": 200, "content_type": "application/json", "body": value}
    return {
        "status": int(value.get("status") or 200),
        "content_type": str(value.get("content_type") or "application/json"),
        "body": value.get("body"),
        "headers": dict(value.get("headers") or {}),
    }


def _query_key(req_target: Any, value_or_bytes: Any, rsp_target: Any) -> str:
    if isinstance(value_or_bytes, bytes):
        body = value_or_bytes.hex()
    else:
        body = json.dumps(value_or_bytes, ensure_ascii=False, sort_keys=True, default=str)
    return f"{req_target}|{rsp_target}|{body}"


def _json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"bytes": len(value), "hex_preview": value[:32].hex()}
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    if isinstance(value, tuple):
        return [_json_safe(v) for v in value]
    return value


_MANUAL_ARG_TYPES = {"obj", "u32", "i32", "u64", "i64", "bool", "str", "bytes", "any", "http_req", "packet", "event"}


def _function_is_manually_callable(fn: Any) -> bool:
    if not getattr(fn, "args", None):
        return True
    for _name, typ in fn.args:
        if str(typ).lower() not in _MANUAL_ARG_TYPES:
            return False
    return True


def _binding_id(binding: dict[str, Any]) -> str:
    kind = str(binding.get("kind") or "")
    name = str(binding.get("name") or "")
    func = str(binding.get("func") or "")
    extra = (
        str(binding.get("path") or "")
        + "|"
        + str(binding.get("method") or "")
        + "|"
        + str(binding.get("target") or "")
        + "|"
        + str(binding.get("job_key") or "")
    )
    return f"{kind}::{name}::{func}::{extra}"


def _find_binding(manifest: dict[str, Any], name: Any) -> dict[str, Any] | None:
    if not name:
        return None
    for binding in manifest.get("bindings") or []:
        if str(binding.get("name") or "") == str(name):
            return binding
    return None


def _find_http_binding(manifest: dict[str, Any], request: dict[str, Any]) -> dict[str, Any] | None:
    path = request.get("path")
    method = str(request.get("method") or "").upper()
    for binding in manifest.get("bindings") or []:
        if binding.get("kind") not in {"http", "http.server"}:
            continue
        if binding.get("path") and binding.get("path") != path:
            continue
        if binding.get("method") and str(binding.get("method")).upper() != method:
            continue
        return binding
    return None
