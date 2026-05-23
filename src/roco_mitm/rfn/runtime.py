from __future__ import annotations

import time
from typing import Any

from .host import RFNHost
from .model import Module
from .vm import RFNVM


class RFNRuntime:
    """Small manifest dispatcher for offline tests and future live integration."""

    def __init__(self, module: Module, manifest: dict[str, Any] | None = None, host: RFNHost | None = None):
        self.module = module
        self.manifest = manifest or {"bindings": []}
        self.host = host or RFNHost()
        self.vm = RFNVM(module, self.host)

    def handle_packet(self, packet: dict[str, Any]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for binding in self._bindings("packet"):
            if not _packet_matches(binding, packet):
                continue
            result = self.vm.call(str(binding["func"]), packet)
            item = {"binding": binding.get("name"), "kind": "packet", "result": result}
            out.append(item)
            if binding.get("audit", True):
                self.host.audit("trigger.packet", str(binding.get("name") or ""), "ok", {"result": _audit_summary(result)})
        return out

    def handle_http(self, request: dict[str, Any]) -> Any:
        for binding in [*self._bindings("http"), *self._bindings("http.server")]:
            if not _http_matches(binding, request):
                continue
            result = self.vm.call(str(binding["func"]), request)
            if binding.get("audit", True):
                self.host.audit("trigger.http", str(binding.get("name") or ""), "ok", {"path": request.get("path")})
            return result
        return {"status": 404, "content_type": "application/json", "body": {"error": "RFN route not found"}}

    def run_job(self, job_key: str) -> dict[str, Any]:
        job = self.host.jobs.get(job_key)
        if job is None:
            return {"ok": False, "error_code": "E_JOB_NOT_FOUND", "job_key": job_key}
        result = self.vm.call(str(job["func"]), *list(job.get("args") or []))
        return {"ok": True, "job_key": job_key, "result": result}

    def run_due_jobs(self, *, now_ms: int | None = None, limit: int = 100) -> list[dict[str, Any]]:
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        due = [job for job in self.host.jobs.values() if int(job.get("next_run_at") or 0) <= now]
        due.sort(key=lambda item: int(item.get("next_run_at") or 0))
        out: list[dict[str, Any]] = []
        for job in due[: max(0, int(limit))]:
            out.append(self.run_job(str(job["job_key"])))
            self._reschedule(job)
        return out

    def _bindings(self, kind: str) -> list[dict[str, Any]]:
        return [b for b in self.manifest.get("bindings", []) if b.get("kind") == kind]

    def _reschedule(self, job: dict[str, Any]) -> None:
        key = str(job["job_key"])
        if job.get("kind") == "after":
            self.host.schedule_cancel(key)
            return
        if job.get("kind") == "every":
            job["next_run_at"] = int(time.time() * 1000) + int(job.get("interval_ms") or 0)
            self.host.jobs[key] = job
            self.host._store_job(key, job)
            return
        if job.get("kind") == "cron":
            job["next_run_at"] = _next_cron_run_ms(str(job.get("cron_expr") or ""), int(time.time() * 1000))
            self.host.jobs[key] = job
            self.host._store_job(key, job)


def _packet_matches(binding: dict[str, Any], packet: dict[str, Any]) -> bool:
    direction = binding.get("direction")
    if direction and str(packet.get("direction") or "").lower() != str(direction).lower():
        return False
    target = binding.get("target")
    if target is None:
        return True
    wanted = str(target)
    candidates = {
        str(packet.get("target") or ""),
        str(packet.get("name") or ""),
        str(packet.get("opcode_hex") or ""),
        str(packet.get("opcode") or ""),
    }
    opcode = packet.get("opcode")
    if isinstance(opcode, int):
        candidates.add(f"0x{opcode:04X}")
    return wanted in candidates


def _http_matches(binding: dict[str, Any], request: dict[str, Any]) -> bool:
    path = binding.get("path")
    if path and request.get("path") != path:
        return False
    method = binding.get("method")
    if method and str(request.get("method") or "").upper() != str(method).upper():
        return False
    return True


def _audit_summary(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"bytes": len(value), "sha256": "omitted"}
    return value


def _next_cron_run_ms(expr: str, now_ms: int) -> int:
    parts = str(expr).split()
    if len(parts) != 5:
        return now_ms + 60_000
    minute = parts[0]
    if minute.startswith("*/"):
        try:
            every = max(1, int(minute[2:]))
        except ValueError:
            every = 1
        return now_ms + every * 60_000
    return now_ms + 60_000
