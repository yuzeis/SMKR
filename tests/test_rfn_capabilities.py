from __future__ import annotations

import sqlite3

import pytest

from roco_mitm.rfn import RFNError, RFNHost, RFNRuntime, RFNVM, assemble_source
from roco_mitm.rfn.host import QueryPair
from roco_mitm.rfn.manifest import compile_manifest, compile_source_to_manifest


def test_rfn_cache_buffer_db_http_query_schedule_audit(tmp_path) -> None:
    src = """
    .function MatchShop(decoded:obj, request:obj) -> bool
    .no_side_effect true
    .deterministic true
      obj.get r0, arg0, "shop_data.id"
      obj.get r1, arg1, "shop_id"
      cmp.eq r2, r0, r1
      ret r2
    .end

    .function Flow(req:http_req) -> http_rsp
    .no_side_effect false
    .deterministic false
    .capability "cache.write" scope="session" prefix="login"
    .capability "cache.read" scope="session" prefix="login"
    .capability "db.read" namespace="shop"
    .capability "db.write" namespace="shop"
    .capability "http.server" path="/rfn/shop"
    .capability "inject.query" targets="ZoneShopGetInfoReq,ZoneShopGetInfoRsp"
    .capability "schedule.write" job_prefix="shop_refresh" max_jobs=4
      http.req_query r0, arg0, "shop_id"
      cast.u32 r1, r0
      cast.str r2, r1
      cache.set "session", "login.last_shop", r1, 1000
      buffer.push "session", "login.heartbeat", r1, 4, 1000
      db.get r3, "shop", r2
      cmp.exists r4, r3
      jnz r4, from_db
      map.new r5
      map.set r6, r5, "shop_id", r1
      str.cat r7, "shop:", r2
      query.singleflight r8, r7, "ZoneShopGetInfoReq", r6, "ZoneShopGetInfoRsp", 2500
      inject.ok r9, r8
      jz r9, fail_query
      inject.decoded r10, r8
      db.put "shop", r2, r10, 60000
      arr.from r11, r1
      schedule.every r12, 15000, Function.MatchShop, r11, "shop_refresh:8000"
      http.resp_json r13, 200, r10
      ret r13
    from_db:
      http.resp_json r14, 200, r3
      ret r14
    fail_query:
      fail "query failed"
    .end
    """
    host = RFNHost(
        db_path=tmp_path / "rfn.sqlite",
        observed_pairs=[
            QueryPair(
                req_target="ZoneShopGetInfoReq",
                rsp_target="ZoneShopGetInfoRsp",
                request={"shop_id": 8000},
                response={"shop_data": {"id": 8000, "goods_data": [{"goods_id": 18008}]}},
                request_frame=47498,
                response_frame=47501,
                latency_ms=24,
            )
        ],
    )
    vm = RFNVM(assemble_source(src), host)

    rsp = vm.call("Flow", {"method": "GET", "path": "/rfn/shop", "query": {"shop_id": "8000"}})
    assert rsp["status"] == 200
    assert rsp["body"]["shop_data"]["goods_data"][0]["goods_id"] == 18008
    assert host.db_get("shop", "8000")["shop_data"]["id"] == 8000
    assert host.cache_get("session", "login.last_shop") == 8000
    assert host.buffer_take("session", "login.heartbeat", 4) == [8000]
    assert "shop_refresh:8000" in host.jobs
    assert "shop:8000" in host.singleflight_keys
    assert any(ev["op"] == "db.put" for ev in host.audit_events)

    rsp2 = vm.call("Flow", {"method": "GET", "path": "/rfn/shop", "query": {"shop_id": "8000"}})
    assert rsp2["body"]["shop_data"]["id"] == 8000
    host.close()

    db = sqlite3.connect(tmp_path / "rfn.sqlite")
    assert db.execute("select count(*) from events").fetchone()[0] >= 1
    db.close()


def test_rfn_capability_scope_denies_wrong_namespace(tmp_path) -> None:
    src = """
    .function Bad() -> bool
    .no_side_effect false
    .deterministic false
    .capability "db.write" namespace="shop"
      db.put "pet", "x", 1, 0
      ret true
    .end
    """
    vm = RFNVM(assemble_source(src), RFNHost(db_path=tmp_path / "rfn.sqlite"))
    with pytest.raises(RFNError) as got:
        vm.call("Bad")
    assert got.value.code == "E_PERMISSION"


def test_rfn_cache_buffer_event_audit_packet_ops() -> None:
    src = """
    .function Ops(pkt:obj, ev:obj) -> obj
    .no_side_effect false
    .deterministic false
    .capability "cache.read" scope="session" prefix="login"
    .capability "cache.write" scope="session" prefix="login"
    .capability "event.emit" prefix="script.shop."
      cache.incr r0, "session", "login.count", 2, 5000
      cache.has r1, "session", "login.count"
      cache.ttl r2, "session", "login.count"
      cache.get r3, "session", "login.count"
      buffer.push "session", "login.ring", "a", 4, 5000
      buffer.push "session", "login.ring", "b", 4, 5000
      buffer.latest r4, "session", "login.ring"
      buffer.take r5, "session", "login.ring", 4
      map.from_pairs r6, "kind", "ready"
      event.emit "script.shop.ready", r6
      event.name r7, arg1
      event.payload r8, arg1
      map.from_pairs r9, "op", "capture"
      audit.attach_packet r10, r9, arg0
      map.from_pairs r11, "route", "shop"
      audit.metric "cache.hit", 1, r11
      cache.del "session", "login.count"
      cache.has r12, "session", "login.count"
      buffer.clear "session", "login.ring"
      buffer.take r13, "session", "login.ring", 4
      map.from_pairs r14, "count", r0, "has", r1, "ttl", r2, "got", r3, "latest", r4, "taken", r5, "after_del", r12, "after_clear", r13, "event_name", r7, "event_payload", r8, "packet_detail", r10
      ret r14
    .end
    """
    host = RFNHost()
    vm = RFNVM(assemble_source(src), host)
    pkt = {"frame": 47501, "opcode_hex": "0x0260", "direction": "s2c", "session_id": "sid", "gcp_seq": 205}
    ev = {"name": "host.packet", "payload": {"opcode_hex": "0x0260"}}

    out = vm.call("Ops", pkt, ev)
    assert out["count"] == 2
    assert out["has"] is True
    assert out["ttl"] > 0
    assert out["got"] == 2
    assert out["latest"] == "b"
    assert out["taken"] == ["a", "b"]
    assert out["after_del"] is False
    assert out["after_clear"] == []
    assert out["event_name"] == "host.packet"
    assert out["event_payload"]["opcode_hex"] == "0x0260"
    assert out["packet_detail"]["frame"] == 47501
    assert out["packet_detail"]["opcode"] == "0x0260"
    assert host.events[0]["name"] == "script.shop.ready"
    assert host.metrics[0]["name"] == "cache.hit"


def test_rfn_db_table_blob_exec_and_transactions(tmp_path) -> None:
    src = """
    .function DbFlow() -> obj
    .no_side_effect false
    .deterministic false
    .capability "db.read" namespace="shop"
    .capability "db.write" namespace="shop"
    .capability "db.read" table="shop_items"
    .capability "db.write" table="shop_items"
      db.put "shop", "8000", 30, 60000
      db.has r0, "shop", "8000"
      map.from_pairs r1, "shop_id", 8000
      map.from_pairs r2, "goods_id", 18008, "price", 30
      db.upsert "shop_items", r1, r2, 60000
      map.from_pairs r3, "goods_id", 18008
      db.select_one r4, "shop_items", r3
      map.new r5
      db.select_all r6, "shop_items", r5, 10
      db.put_blob "shop", "raw", hex"aabbcc", "application/octet-stream", 60000
      db.get_blob r7, "shop", "raw"
      map.from_pairs r8, "namespace", "shop", "key", "8000"
      db.exec r9, "select_kv", r8
      db.begin r10
      db.put "shop", "rollback", 1, 0
      db.rollback r10
      db.has r11, "shop", "rollback"
      db.begin r12
      db.put "shop", "commit", 2, 0
      db.commit r12
      db.has r13, "shop", "commit"
      db.put "shop", "old", 3, -1
      db.expire r14, "shop"
      db.has r15, "shop", "old"
      db.delete_where r16, "shop_items", r3
      db.select_all r17, "shop_items", r5, 10
      db.del "shop", "8000"
      db.has r18, "shop", "8000"
      map.from_pairs r19, "kv_has", r0, "row", r4, "rows_before", r6, "blob", r7, "exec", r9, "rollback_has", r11, "commit_has", r13, "expired_count", r14, "expired_has", r15, "deleted_rows", r16, "rows_after", r17, "kv_after_del", r18
      ret r19
    .end
    """
    host = RFNHost(
        db_path=tmp_path / "rfn.sqlite",
        sql_statements={"select_kv": "SELECT value_json FROM kv WHERE namespace=:namespace AND key=:key"},
    )
    out = RFNVM(assemble_source(src), host).call("DbFlow")
    host.close()

    assert out["kv_has"] is True
    assert out["row"] == {"goods_id": 18008, "price": 30}
    assert out["rows_before"] == [{"goods_id": 18008, "price": 30}]
    assert out["blob"]["value"] == bytes.fromhex("aabbcc")
    assert out["blob"]["content_type"] == "application/octet-stream"
    assert out["exec"]["rows"][0]["value_json"] == "30"
    assert out["rollback_has"] is False
    assert out["commit_has"] is True
    assert out["expired_count"] >= 1
    assert out["expired_has"] is False
    assert out["deleted_rows"] == 1
    assert out["rows_after"] == []
    assert out["kv_after_del"] is False


def test_rfn_http_client_server_and_inject_dry_run() -> None:
    src = """
    .function HttpInject(req:http_req) -> obj
    .no_side_effect false
    .deterministic false
    .capability "http.server" path="/rfn/test"
    .capability "http.client" host="127.0.0.1"
    .capability "inject.send" targets="ZoneShopGetInfoReq"
      http.req_method r0, arg0
      http.req_path r1, arg0
      http.req_header r2, arg0, "x-token"
      http.req_json r3, arg0
      http.req_bytes r4, arg0
      map.new r5
      http.get r6, "http://127.0.0.1/mock", r5, 1000
      http.status r7, r6
      http.json r8, r6
      http.post_json r9, "http://127.0.0.1/post-json", r5, r3, 1000
      http.status r10, r9
      http.post_bytes r11, "http://127.0.0.1/post-bytes", r5, r4, 1000
      http.bytes r12, r11
      inject.ready r13
      inject.send_hex r14, "ZoneShopGetInfoReq", "08 c0 3e"
      inject.ok r15, r14
      inject.info r16, r14
      inject.payload r17, r14
      inject.error r18, r14
      http.resp_text r19, 200, "ok"
      http.resp_bytes r20, 201, hex"0102", "application/octet-stream"
      map.from_pairs r21, "method", r0, "path", r1, "header", r2, "json", r3, "body", r4, "get_status", r7, "get_json", r8, "post_status", r10, "post_bytes", r12, "ready", r13, "inject_ok", r15, "inject_info", r16, "inject_payload", r17, "inject_error", r18, "text_rsp", r19, "bytes_rsp", r20
      ret r21
    .end
    """
    host = RFNHost(
        http_mocks={
            ("GET", "http://127.0.0.1/mock"): {"status": 200, "body": b'{"remote": true}', "content_type": "application/json"},
            ("POST", "http://127.0.0.1/post-json"): {"status": 202, "body": {"accepted": True}, "content_type": "application/json"},
            ("POST", "http://127.0.0.1/post-bytes"): {"status": 203, "body": b"raw-ok", "content_type": "application/octet-stream"},
        }
    )
    out = RFNVM(assemble_source(src), host).call(
        "HttpInject",
        {
            "method": "post",
            "path": "/rfn/test",
            "headers": {"X-Token": "abc"},
            "json": {"shop_id": 8000},
            "body": b"payload",
        },
    )

    assert out["method"] == "POST"
    assert out["path"] == "/rfn/test"
    assert out["header"] == "abc"
    assert out["json"] == {"shop_id": 8000}
    assert out["body"] == b"payload"
    assert out["get_status"] == 200
    assert out["get_json"] == {"remote": True}
    assert out["post_status"] == 202
    assert out["post_bytes"] == b"raw-ok"
    assert out["ready"] is True
    assert out["inject_ok"] is True
    assert out["inject_info"]["dry_run"] is True
    assert out["inject_payload"] == bytes.fromhex("08c03e")
    assert out["inject_error"] is None
    assert out["text_rsp"]["body"] == "ok"
    assert out["bytes_rsp"]["body"] == bytes.fromhex("0102")


def test_rfn_http_client_host_scope_denies_remote() -> None:
    src = """
    .function Bad() -> obj
    .no_side_effect false
    .deterministic false
    .capability "http.client" host="127.0.0.1"
      map.new r0
      http.get r1, "http://example.com/blocked", r0, 100
      ret r1
    .end
    """
    with pytest.raises(RFNError) as got:
        RFNVM(assemble_source(src)).call("Bad")
    assert got.value.code == "E_PERMISSION"


def test_rfn_session_disconnect_requires_capability() -> None:
    src = """
    .function Bad() -> obj
    .no_side_effect false
    .deterministic false
      session.disconnect r0, "test"
      ret r0
    .end
    """
    host = RFNHost(session_disconnect_func=lambda reason: {"ok": True, "reason": reason})
    with pytest.raises(RFNError) as got:
        RFNVM(assemble_source(src), host).call("Bad")
    assert got.value.code == "E_PERMISSION"


def test_rfn_session_disconnect_uses_host_callback() -> None:
    calls: list[str] = []
    src = """
    .function Reconnect() -> obj
    .no_side_effect false
    .deterministic false
    .capability "session.control"
      session.disconnect r0, "unit-test"
      ret r0
    .end
    """
    host = RFNHost(session_disconnect_func=lambda reason: calls.append(reason) or {"ok": True, "reason": reason})
    out = RFNVM(assemble_source(src), host).call("Reconnect")

    assert out == {"ok": True, "reason": "unit-test"}
    assert calls == ["unit-test"]
    assert any(ev["op"] == "session.disconnect" and ev["status"] == "ok" for ev in host.audit_events)


def test_rfn_schedule_after_cron_cancel_and_persistence(tmp_path) -> None:
    src = """
    .function Noop() -> bool
    .no_side_effect true
    .deterministic true
      ret true
    .end

    .function Jobs() -> obj
    .no_side_effect false
    .deterministic false
    .capability "schedule.write" job_prefix="job:"
      arr.new r0
      schedule.after r1, 1000, Function.Noop, r0, "job:after"
      schedule.cron r2, "*/5 * * * *", Function.Noop, r0, "job:cron"
      schedule.exists r3, "job:after"
      schedule.next r4, "job:after"
      schedule.cancel "job:after"
      schedule.exists r5, "job:after"
      schedule.exists r6, "job:cron"
      map.from_pairs r7, "after", r1, "cron", r2, "after_exists", r3, "after_next", r4, "after_exists_after_cancel", r5, "cron_exists", r6
      ret r7
    .end
    """
    host = RFNHost(db_path=tmp_path / "rfn.sqlite")
    out = RFNVM(assemble_source(src), host).call("Jobs")
    host.close()

    assert out["after"]["kind"] == "after"
    assert out["cron"]["kind"] == "cron"
    assert out["after_exists"] is True
    assert isinstance(out["after_next"], int)
    assert out["after_exists_after_cancel"] is False
    assert out["cron_exists"] is True
    db = sqlite3.connect(tmp_path / "rfn.sqlite")
    rows = db.execute("select id, enabled from jobs order by id").fetchall()
    db.close()
    assert rows == [("job:cron", 1)]


def test_rfn_runtime_dispatches_packet_http_and_schedule_bindings() -> None:
    src = """
    .function RememberLogin(pkt:obj) -> str
    .no_side_effect false
    .deterministic false
    .capability "cache.write" scope="session" prefix="login"
      packet.opcode_hex r0, arg0
      cache.set "session", "login.last_opcode", r0, 60000
      ret r0
    .end

    .function HttpShop(req:http_req) -> http_rsp
    .no_side_effect false
    .deterministic false
    .capability "http.server" path="/rfn/runtime"
      http.req_query r0, arg0, "shop_id"
      map.from_pairs r1, "shop_id", r0
      http.resp_json r2, 200, r1
      ret r2
    .end

    .function Tick(value:u32) -> u32
    .no_side_effect false
    .deterministic false
    .capability "cache.write" scope="session" prefix="job"
      cache.set "session", "job.tick", arg0, 60000
      ret arg0
    .end
    """
    manifest = compile_manifest("""
    bind packet remember_login
      direction s2c
      target 0x0102
      func Function.RememberLogin
      audit true
    end
    bind http runtime_shop
      method GET
      path /rfn/runtime
      func Function.HttpShop
      audit true
    end
    """)
    host = RFNHost()
    runtime = RFNRuntime(assemble_source(src), manifest, host)

    packet_results = runtime.handle_packet({"direction": "s2c", "opcode": 0x0102, "opcode_hex": "0x0102"})
    http_rsp = runtime.handle_http({"method": "GET", "path": "/rfn/runtime", "query": {"shop_id": "8000"}})
    host.schedule_after(0, "Function.Tick", [7], "job:tick")
    job_results = runtime.run_due_jobs(now_ms=host.schedule_next("job:tick"))

    assert packet_results == [{"binding": "remember_login", "kind": "packet", "result": "0x0102"}]
    assert host.cache_get("session", "login.last_opcode") == "0x0102"
    assert http_rsp == {"status": 200, "content_type": "application/json", "body": {"shop_id": "8000"}}
    assert job_results == [{"ok": True, "job_key": "job:tick", "result": 7}]
    assert host.cache_get("session", "job.tick") == 7
    assert any(ev["op"] == "trigger.packet" for ev in host.audit_events)
    assert any(ev["op"] == "trigger.http" for ev in host.audit_events)


def test_rfn_file_ops_real_files(tmp_path) -> None:
    src = """
    .function FileFlow(root:str, text_path:str, copy_path:str, moved_path:str, bytes_path:str) -> obj
    .no_side_effect false
    .deterministic false
    .capability "file.read"
    .capability "file.write"
      file.mkdir arg0
      file.write_text arg1, "hello", "utf-8", true
      file.append_text arg1, "\\nworld", "utf-8", false
      file.exists r0, arg1
      file.is_file r1, arg1
      file.read_text r2, arg1, "utf-8", 1024
      file.read_bytes r3, arg1, 1024
      file.stat r4, arg1
      file.list r5, arg0
      file.copy arg1, arg2, true
      file.move arg2, arg3, true
      file.exists r6, arg2
      file.exists r7, arg3
      file.write_bytes arg4, hex"010203", true
      file.read_bytes r8, arg4, 16
      file.remove arg3
      file.exists r9, arg3
      map.from_pairs r10, "exists", r0, "is_file", r1, "text", r2, "bytes", r3, "stat", r4, "list", r5, "copy_exists_after_move", r6, "moved_exists", r7, "raw", r8, "removed_exists", r9
      ret r10
    .end
    """
    root = tmp_path / "rfn_files"
    text_path = root / "data.txt"
    copy_path = root / "copy.txt"
    moved_path = root / "moved.txt"
    bytes_path = root / "raw.bin"
    host = RFNHost(file_root=tmp_path)
    out = RFNVM(assemble_source(src), host).call("FileFlow", str(root), str(text_path), str(copy_path), str(moved_path), str(bytes_path))

    assert out["exists"] is True
    assert out["is_file"] is True
    assert out["text"] == "hello\nworld"
    assert out["bytes"] == b"hello\nworld"
    assert out["stat"]["size"] == len(b"hello\nworld")
    assert [item["name"] for item in out["list"]] == ["data.txt"]
    assert out["copy_exists_after_move"] is False
    assert out["moved_exists"] is True
    assert out["raw"] == bytes.fromhex("010203")
    assert out["removed_exists"] is False
    assert bytes_path.read_bytes() == bytes.fromhex("010203")
    assert any(ev["op"] == "file.write_text" for ev in host.audit_events)


def test_rfn_manifest_compilation() -> None:
    src = """
    bind packet remember_login_rsp
      direction s2c
      target ZoneLoginRsp
      func Function.session.RememberLoginRsp
      audit true
    end
    """
    manifest = compile_manifest(src)
    assert manifest["format"] == "rfn.manifest.v1"
    assert manifest["bindings"][0]["kind"] == "packet"
    assert manifest["bindings"][0]["target"] == "ZoneLoginRsp"

    compiled = compile_source_to_manifest("""
    .function Build(v:u32) -> bytes
    .no_side_effect true
    .deterministic true
      buf.new r0
      pb.varint r0, 1, arg0
      buf.take r1, r0
      ret r1
    .end
    """)
    assert compiled["functions"][0]["name"] == "Build"
    assert compiled["functions"][0]["no_side_effect"] is True
