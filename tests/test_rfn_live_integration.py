from __future__ import annotations

import sqlite3
import threading
import time

from roco_mitm.codec import proto_codec
from roco_mitm.codec.opcode_registry import OpcodeRegistry
from roco_mitm.paths import project_root
from roco_mitm.rfn.live import RFNLiveRuntime


def _script_dirs(tmp_path):
    script_root = tmp_path / "MITMScript"
    function_dir = script_root / "Function"
    manifest_dir = script_root / "Manifest"
    function_dir.mkdir(parents=True)
    manifest_dir.mkdir(parents=True)
    return script_root, function_dir, manifest_dir


def _default_registry() -> OpcodeRegistry:
    registry = OpcodeRegistry(project_root() / "config")
    registry.load()
    return registry


def _default_shop_live(tmp_path, inject_func) -> RFNLiveRuntime:
    return RFNLiveRuntime(
        script_root=project_root() / "MITMScript",
        registry=_default_registry(),
        db_path=tmp_path / "live.sqlite",
        file_root=tmp_path,
        inject_func=inject_func,
    )


def test_rfn_live_runtime_dispatches_packet_and_http(tmp_path) -> None:
    script_root, function_dir, manifest_dir = _script_dirs(tmp_path)
    (function_dir / "Smoke.rfn").write_text(
        """
.function LiveLoginSmoke(pkt:obj) -> obj
.no_side_effect false
.deterministic false
.capability "db.write" namespace="rfn_live"
.capability "file.write" path="rfn_live_smoke.txt"
  packet.opcode_hex r0, arg0
  obj.get r1, arg0, "decoded.player_info.brief_info.uin"
  map.from_pairs r2, "opcode", r0, "uin", r1
  db.put "rfn_live", "last_login_rsp", r2, 0
  file.write_text "rfn_live_smoke.txt", "hit", "utf-8", true
  ret r2
.end

.function LiveStatus(req:http_req) -> http_rsp
.no_side_effect false
.deterministic false
.capability "http.server" path="/rfn/live-status"
.capability "db.read" namespace="rfn_live"
  db.get r0, "rfn_live", "last_login_rsp"
  map.from_pairs r1, "last", r0
  http.resp_json r2, 200, r1
  ret r2
.end
""",
        encoding="utf-8",
    )
    (manifest_dir / "Smoke.rfnmanifest").write_text(
        """
bind packet login
  direction s2c
  target 0x0102
  func Function.LiveLoginSmoke
end
bind http status
  method GET
  path /rfn/live-status
  func Function.LiveStatus
end
""",
        encoding="utf-8",
    )
    live = RFNLiveRuntime(script_root=script_root, db_path=tmp_path / "live.sqlite", file_root=tmp_path)
    try:
        status = live.status()
        assert status["loaded"] is True
        assert status["binding_count"] == 2

        out = live.handle_packet({
            "direction": "s2c",
            "opcode": 0x0102,
            "opcode_hex": "0x0102",
            "decoded": {"player_info": {"brief_info": {"uin": 1852750}}},
        })
        assert out[0]["result"] == {"opcode": "0x0102", "uin": 1852750}
        assert (tmp_path / "rfn_live_smoke.txt").read_text(encoding="utf-8") == "hit"

        rsp = live.handle_http({"method": "GET", "path": "/rfn/live-status", "query": {}})
        assert rsp["status"] == 200
        assert rsp["body"]["last"] == {"opcode": "0x0102", "uin": 1852750}
    finally:
        live.close()


def test_rfn_live_skips_unwatched_packets(tmp_path) -> None:
    script_root, function_dir, manifest_dir = _script_dirs(tmp_path)
    (function_dir / "Packet.rfn").write_text(
        """
.function OnLogin(pkt:obj) -> bool
  ret true
.end
""",
        encoding="utf-8",
    )
    (manifest_dir / "Packet.rfnmanifest").write_text(
        """
bind packet login
  direction s2c
  target 0x0102
  func Function.OnLogin
end
""",
        encoding="utf-8",
    )
    live = RFNLiveRuntime(script_root=script_root, db_path=tmp_path / "live.sqlite", file_root=tmp_path)
    try:
        ignored = live.handle_packet({"direction": "s2c", "opcode": 0x0103, "opcode_hex": "0x0103"})
        stats = live.status()["stats"]

        assert ignored == []
        assert stats["packet_seen"] == 0
        assert stats["packet_matched"] == 0
        assert stats["packet_fast_ignored"] == 1
    finally:
        live.close()


def test_rfn_live_query_waits_for_observed_response(tmp_path) -> None:
    script_root, function_dir, _manifest_dir = _script_dirs(tmp_path)
    (function_dir / "Query.rfn").write_text(
        """
.function Ask() -> obj
.no_side_effect false
.deterministic false
.capability "inject.query" targets="0x025F,0x0260"
  query.singleflight r0, "shop:8000", 0x025F, hex"0102", 0x0260
  ret r0
.end
""",
        encoding="utf-8",
    )
    injected = []
    injected_event = threading.Event()

    def fake_inject(opcode: int, payload: bytes, fallback_opcode: int | None = None) -> dict:
        injected.append((opcode, payload, fallback_opcode))
        injected_event.set()
        return {"opcode": opcode, "payload_len": len(payload)}

    live = RFNLiveRuntime(script_root=script_root, db_path=tmp_path / "live.sqlite", file_root=tmp_path, inject_func=fake_inject)
    result: dict[str, object] = {}
    try:
        worker = threading.Thread(target=lambda: result.update(out=live.runtime.vm.call("Ask")), daemon=True)
        worker.start()
        assert injected_event.wait(1.0)
        assert injected == [(0x025F, b"\x01\x02", None)]

        live.observe_packet({
            "direction": "s2c",
            "opcode": 0x0260,
            "opcode_hex": "0x0260",
            "decoded": {"shop_data": {"id": 8000}},
            "payload_hex": "aabb",
        })
        worker.join(1.0)
        assert result["out"]["ok"] is True
        assert result["out"]["decoded"] == {"shop_data": {"id": 8000}}
        assert result["out"]["match_source"] == "live_observed_packet"
    finally:
        live.close()


def test_rfn_live_query_singleflight_concurrent_callers_share_one_inject(tmp_path) -> None:
    script_root, function_dir, _manifest_dir = _script_dirs(tmp_path)
    (function_dir / "Query.rfn").write_text(
        """
.function Ask() -> obj
.no_side_effect false
.deterministic false
.capability "inject.query" targets="0x025F,0x0260"
  query.singleflight r0, "shop:8000", 0x025F, hex"0102", 0x0260, 1000
  ret r0
.end
""",
        encoding="utf-8",
    )
    injected = []
    injected_event = threading.Event()

    def fake_inject(opcode: int, payload: bytes, fallback_opcode: int | None = None) -> dict:
        injected.append((opcode, payload, fallback_opcode))
        injected_event.set()
        return {"opcode": opcode, "payload_len": len(payload)}

    live = RFNLiveRuntime(script_root=script_root, db_path=tmp_path / "live.sqlite", file_root=tmp_path, inject_func=fake_inject)
    results: list[dict | None] = [None, None]
    errors: list[BaseException] = []
    barrier = threading.Barrier(3)

    def worker(index: int) -> None:
        try:
            barrier.wait(1.0)
            results[index] = live.runtime.vm.call("Ask")
        except BaseException as exc:
            errors.append(exc)

    try:
        threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait(1.0)
        assert injected_event.wait(1.0)
        deadline = time.time() + 1.0
        while time.time() < deadline:
            with live._lock:
                waiters = [pending.waiters for pending in live._pending.values()]
            if waiters == [2]:
                break
            time.sleep(0.01)
        assert waiters == [2]
        live.observe_packet({
            "direction": "s2c",
            "opcode": 0x0260,
            "opcode_hex": "0x0260",
            "decoded": {"shop_data": {"id": 8000}},
            "payload_hex": "aabb",
        })
        for thread in threads:
            thread.join(1.0)
        assert not errors
        assert injected == [(0x025F, b"\x01\x02", None)]
        assert results[0]["ok"] is True
        assert results[1]["ok"] is True
        assert results[0]["decoded"] == results[1]["decoded"] == {"shop_data": {"id": 8000}}
    finally:
        live.close()


def test_rfn_live_query_timeout_uses_instruction_timeout(tmp_path) -> None:
    script_root, function_dir, _manifest_dir = _script_dirs(tmp_path)
    (function_dir / "Query.rfn").write_text(
        """
.function Ask() -> obj
.no_side_effect false
.deterministic false
.capability "inject.query" targets="0x025F,0x0260"
  query.send r0, 0x025F, hex"0102", 0x0260, 100
  ret r0
.end
""",
        encoding="utf-8",
    )
    injected = []

    def fake_inject(opcode: int, payload: bytes, fallback_opcode: int | None = None) -> dict:
        injected.append((opcode, payload, fallback_opcode))
        return {"opcode": opcode, "payload_len": len(payload)}

    live = RFNLiveRuntime(script_root=script_root, db_path=tmp_path / "live.sqlite", file_root=tmp_path, inject_func=fake_inject)
    try:
        start = time.perf_counter()
        out = live.runtime.vm.call("Ask")
        elapsed = time.perf_counter() - start
        assert out["ok"] is False
        assert out["error_code"] == "E_QUERY_TIMEOUT"
        assert elapsed < 0.5
        assert injected == [(0x025F, b"\x01\x02", None)]
    finally:
        live.close()


def test_rfn_live_reload_wakes_pending_query(tmp_path) -> None:
    script_root, function_dir, _manifest_dir = _script_dirs(tmp_path)
    (function_dir / "Query.rfn").write_text(
        """
.function Ask() -> obj
.no_side_effect false
.deterministic false
.capability "inject.query" targets="0x025F,0x0260"
  query.send r0, 0x025F, hex"0102", 0x0260, 3000
  ret r0
.end
""",
        encoding="utf-8",
    )
    injected_event = threading.Event()

    def fake_inject(opcode: int, payload: bytes, fallback_opcode: int | None = None) -> dict:
        injected_event.set()
        return {"opcode": opcode, "payload_len": len(payload)}

    live = RFNLiveRuntime(script_root=script_root, db_path=tmp_path / "live.sqlite", file_root=tmp_path, inject_func=fake_inject)
    result: dict[str, object] = {}
    try:
        worker = threading.Thread(target=lambda: result.update(out=live.runtime.vm.call("Ask")), daemon=True)
        worker.start()
        assert injected_event.wait(1.0)
        live.reload()
        worker.join(1.0)
        assert result["out"]["ok"] is False
        assert result["out"]["error_code"] == "E_RELOAD"
    finally:
        live.close()


def test_rfn_live_schedule_every_tick_runs_repeatedly(tmp_path) -> None:
    script_root, function_dir, manifest_dir = _script_dirs(tmp_path)
    (function_dir / "Schedule.rfn").write_text(
        """
.function Tick() -> u32
.no_side_effect false
.deterministic false
.capability "db.read" namespace="schedule"
.capability "db.write" namespace="schedule"
  db.get r0, "schedule", "count"
  cmp.exists r1, r0
  jnz r1, have_count
  mov r0, 0
have_count:
  int.add r2, r0, 1
  db.put "schedule", "count", r2, 0
  ret r2
.end
""",
        encoding="utf-8",
    )
    (manifest_dir / "Schedule.rfnmanifest").write_text(
        """
bind schedule live_tick
  every_ms 50
  job_key live_tick
  func Function.Tick
end
""",
        encoding="utf-8",
    )
    db_path = tmp_path / "live.sqlite"
    live = RFNLiveRuntime(script_root=script_root, db_path=db_path, file_root=tmp_path)
    try:
        assert live.status()["job_count"] == 1
        now_ms = int(time.time() * 1000)
        first = live.run_due_jobs(now_ms=now_ms + 100)
        second = live.run_due_jobs(now_ms=now_ms + 200)
        assert first[0]["result"] == 1
        assert second[0]["result"] == 2
        assert live.host.db_get("schedule", "count") == 2
    finally:
        live.close()
    db = sqlite3.connect(db_path)
    try:
        assert db.execute("SELECT count(*) FROM jobs WHERE id='live_tick'").fetchone()[0] == 1
    finally:
        db.close()


def test_rfn_live_ignores_inject_kind_packets(tmp_path) -> None:
    script_root, function_dir, manifest_dir = _script_dirs(tmp_path)
    (function_dir / "Packet.rfn").write_text(
        """
.function OnPacket(pkt:obj) -> bool
.no_side_effect false
.deterministic false
.capability "db.write" namespace="trigger"
  db.put "trigger", "hit", true, 0
  ret true
.end
""",
        encoding="utf-8",
    )
    (manifest_dir / "Packet.rfnmanifest").write_text(
        """
bind packet c2s_query
  direction c2s
  target 0x025F
  func Function.OnPacket
end
""",
        encoding="utf-8",
    )
    live = RFNLiveRuntime(script_root=script_root, db_path=tmp_path / "live.sqlite", file_root=tmp_path)
    try:
        ignored = live.handle_packet({"kind": "inject", "direction": "c2s", "opcode": 0x025F, "opcode_hex": "0x025F"})
        assert ignored == []
        assert live.status()["stats"]["packet_seen"] == 0
        assert live.host.db_get("trigger", "hit") is None

        triggered = live.handle_packet({"kind": "data", "direction": "c2s", "opcode": 0x025F, "opcode_hex": "0x025F"})
        assert triggered[0]["result"] is True
        assert live.host.db_get("trigger", "hit") is True
    finally:
        live.close()


def test_rfn_live_default_shop_route_db_first_query_fallback(tmp_path) -> None:
    registry = _default_registry()
    injected = []
    injected_event = threading.Event()

    def fake_inject(opcode: int, payload: bytes, fallback_opcode: int | None = None) -> dict:
        injected.append((opcode, payload, fallback_opcode))
        injected_event.set()
        return {"opcode": opcode, "payload_len": len(payload)}

    live = RFNLiveRuntime(script_root=project_root() / "MITMScript", registry=registry, db_path=tmp_path / "live.sqlite", file_root=tmp_path, inject_func=fake_inject)
    result: dict[str, object] = {}
    try:
        worker = threading.Thread(
            target=lambda: result.update(
                rsp=live.handle_http({"method": "GET", "path": "/rfn/shop", "query": {"shop_id": "8000"}})
            ),
            daemon=True,
        )
        worker.start()
        assert injected_event.wait(2.0)
        assert injected[0][0] == 0x025F
        assert injected[0][2] is None
        schema = registry.get_opcode_schema(0x025F)
        assert proto_codec.decode_payload(schema, injected[0][1], resolve_message=registry.resolve_message) == {"shop_id": 8000}
        live.observe_packet({
            "direction": "s2c",
            "opcode": 0x0260,
            "opcode_hex": "0x0260",
            "decoded": {"shop_data": {"id": 8000, "goods_data": [{"goods_id": 18008}]}},
            "payload_hex": "aabb",
        })
        worker.join(1.0)
        rsp = result["rsp"]
        assert rsp["status"] == 200
        assert rsp["body"]["ok"] is True
        assert rsp["body"]["source"] == "inject"
        assert rsp["body"]["shop_data"]["goods_data"][0]["goods_id"] == 18008
        assert live.host.db_get("shop", "8000")["id"] == 8000

        cached = live.handle_http({"method": "GET", "path": "/rfn/shop", "query": {"shop_id": "8000"}})
        assert cached["status"] == 200
        assert cached["body"]["source"] == "db"
        assert len(injected) == 1
    finally:
        live.close()


def test_rfn_live_default_reconnect_route_calls_session_disconnect(tmp_path) -> None:
    calls: list[str] = []

    def fake_disconnect(reason: str) -> dict:
        calls.append(reason)
        return {"ok": True, "reason": reason, "session_key_hex": "aa", "session_id_hex": "0x12345678"}

    live = RFNLiveRuntime(
        script_root=project_root() / "MITMScript",
        registry=_default_registry(),
        db_path=tmp_path / "live.sqlite",
        file_root=tmp_path,
        session_disconnect_func=fake_disconnect,
    )
    try:
        rsp = live.handle_http({"method": "POST", "path": "/rfn/reconnect", "query": {}})
        assert rsp["status"] == 200
        assert rsp["body"]["ok"] is True
        assert rsp["body"]["reason"] == "rfn.reconnect"
        assert calls == ["rfn.reconnect"]
        assert any(ev["op"] == "session.disconnect" and ev["status"] == "ok" for ev in live.host.audit_events)
    finally:
        live.close()


def test_rfn_live_default_shop_route_rejects_bad_shop_id(tmp_path) -> None:
    def fake_inject(opcode: int, payload: bytes, fallback_opcode: int | None = None) -> dict:
        raise AssertionError("inject should not run for invalid shop_id")

    live = _default_shop_live(tmp_path, fake_inject)
    try:
        missing = live.handle_http({"method": "GET", "path": "/rfn/shop", "query": {}})
        assert missing["status"] == 400
        assert missing["body"]["error_code"] == "E_ARG"

        out_of_range = live.handle_http({"method": "GET", "path": "/rfn/shop", "query": {"shop_id": "0"}})
        assert out_of_range["status"] == 400
        assert out_of_range["body"]["error_code"] == "E_ARG"
    finally:
        live.close()


def test_rfn_live_default_shop_route_rate_limits_cached_hits(tmp_path) -> None:
    def fake_inject(opcode: int, payload: bytes, fallback_opcode: int | None = None) -> dict:
        raise AssertionError("cached route should not inject")

    live = _default_shop_live(tmp_path, fake_inject)
    try:
        live.host.db_put("shop", "8000", {"id": 8000, "goods_data": []}, 60000)
        for _ in range(10):
            cached = live.handle_http({"method": "GET", "path": "/rfn/shop", "query": {"shop_id": "8000"}})
            assert cached["status"] == 200
        limited = live.handle_http({"method": "GET", "path": "/rfn/shop", "query": {"shop_id": "8000"}})
        assert limited["status"] == 429
        assert limited["body"]["error_code"] == "E_RATE_LIMIT"
    finally:
        live.close()


def test_rfn_live_default_shop_route_inject_failure_splits_error_fields(tmp_path) -> None:
    def fake_inject(opcode: int, payload: bytes, fallback_opcode: int | None = None) -> dict:
        raise RuntimeError("boom")

    live = _default_shop_live(tmp_path, fake_inject)
    try:
        rsp = live.handle_http({"method": "GET", "path": "/rfn/shop", "query": {"shop_id": "8000"}})
        assert rsp["status"] == 502
        assert rsp["body"]["error_code"] == "E_INJECT"
        assert "boom" in rsp["body"]["error"]
    finally:
        live.close()


def test_rfn_live_default_shop_route_query_timeout_reports_error_code(tmp_path) -> None:
    injected = []

    def fake_inject(opcode: int, payload: bytes, fallback_opcode: int | None = None) -> dict:
        injected.append(opcode)
        return {"opcode": opcode, "payload_len": len(payload)}

    live = _default_shop_live(tmp_path, fake_inject)
    try:
        start = time.perf_counter()
        rsp = live.handle_http({"method": "GET", "path": "/rfn/shop", "query": {"shop_id": "8000"}})
        elapsed = time.perf_counter() - start
        assert rsp["status"] == 502
        assert rsp["body"]["error_code"] == "E_QUERY_TIMEOUT"
        assert rsp["body"]["error"] == "query response timeout"
        assert injected == [0x025F]
        assert elapsed < 3.2
    finally:
        live.close()


def test_rfn_live_default_shop_route_nonmatching_response_times_out(tmp_path) -> None:
    injected_event = threading.Event()

    def fake_inject(opcode: int, payload: bytes, fallback_opcode: int | None = None) -> dict:
        injected_event.set()
        return {"opcode": opcode, "payload_len": len(payload)}

    live = _default_shop_live(tmp_path, fake_inject)
    result: dict[str, object] = {}
    try:
        worker = threading.Thread(
            target=lambda: result.update(
                rsp=live.handle_http({"method": "GET", "path": "/rfn/shop", "query": {"shop_id": "8000"}})
            ),
            daemon=True,
        )
        worker.start()
        assert injected_event.wait(2.0)
        live.observe_packet({
            "direction": "s2c",
            "opcode": 0x0260,
            "opcode_hex": "0x0260",
            "decoded": {"shop_data": {"id": 8001}},
            "payload_hex": "aabb",
        })
        worker.join(3.2)
        rsp = result["rsp"]
        assert rsp["status"] == 502
        assert rsp["body"]["error_code"] == "E_QUERY_TIMEOUT"
    finally:
        live.close()
