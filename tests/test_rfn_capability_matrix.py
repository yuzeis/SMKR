from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from roco_mitm.codec.opcode_registry import OpcodeRegistry
from roco_mitm.paths import project_root
from roco_mitm.rfn.live import RFNLiveRuntime


@pytest.fixture
def live_runtime(tmp_path: Path):
    registry = OpcodeRegistry(project_root() / "config")
    registry.load()
    runtime = RFNLiveRuntime(
        script_root=project_root() / "MITMScript",
        registry=registry,
        db_path=tmp_path / "cap.sqlite",
        file_root=tmp_path,
    )
    try:
        yield runtime
    finally:
        runtime.close()


def test_capability_demo_http_run_covers_all_groups(live_runtime, tmp_path):
    rsp = live_runtime.handle_http({"method": "GET", "path": "/rfn/cap-demo", "query": {}})
    assert rsp["status"] == 200
    body = rsp["body"]
    assert body["ok"] is True
    assert body["cache_incr"] == 2
    assert body["cache_has"] is True
    assert body["buffer_latest"] == "c"
    assert body["buffer_taken"] == ["a", "b", "c"]
    assert body["items_count"] == 2
    assert body["tx_keep_present"] is True
    assert body["tx_roll_rolled_back"] is False
    assert body["file_text"] == "cap-demo-write+append"
    assert body["row"]["tier"] == 2
    assert (tmp_path / "cap_demo.txt").read_text(encoding="utf-8") == "cap-demo-write+append"


def test_capability_demo_db_persists_and_events_recorded(live_runtime):
    live_runtime.handle_http({"method": "GET", "path": "/rfn/cap-demo", "query": {}})
    assert live_runtime.host.db_get("cap_demo", "row")["name"] == "demo"
    blob = live_runtime.host.db_get_blob("cap_demo", "blob1")
    assert blob is not None and blob["value"] == bytes.fromhex("deadbeef")
    items = live_runtime.host.db_select_all("cap_demo_items", {}, 16)
    assert len(items) == 2
    events = live_runtime.list_db_events(limit=200)
    ops = {e["op"] for e in events}
    assert "cap_demo" in ops or "audit.metric" in ops
    assert any(e["op"].startswith("trigger.http") for e in events)


def test_capability_demo_packet_schema_condition_role_level(live_runtime):
    high = live_runtime.handle_packet({
        "direction": "s2c",
        "opcode": 0x0102,
        "opcode_hex": "0x0102",
        "decoded": {"player_info": {"brief_info": {"uin": 12345, "role_level": 20}}},
    })
    assert high and high[0]["result"]["uin"] == 12345
    assert live_runtime.host.db_get("cap_demo", "last_packet")["role_level"] == 20

    low = live_runtime.handle_packet({
        "direction": "s2c",
        "opcode": 0x0102,
        "opcode_hex": "0x0102",
        "decoded": {"player_info": {"brief_info": {"uin": 999, "role_level": 5}}},
    })
    assert low[0]["result"]["skipped"] == "low_level"
    assert live_runtime.host.db_get("cap_demo", "last_packet")["uin"] == 12345

    missing = live_runtime.handle_packet({
        "direction": "s2c",
        "opcode": 0x0102,
        "opcode_hex": "0x0102",
        "decoded": {"player_info": {"brief_info": {}}},
    })
    assert missing[0]["result"]["skipped"] == "missing_role_level"


def test_capability_demo_schedule_tick_increments(live_runtime):
    jobs = {j["job_key"]: j for j in live_runtime.list_jobs()}
    assert "cap_demo_tick" in jobs

    first = live_runtime.run_job_once("cap_demo_tick")
    second = live_runtime.run_job_once("cap_demo_tick")
    assert first["ok"] is True
    assert first["result"]["result"] == 1
    assert second["result"]["result"] == 2
    assert live_runtime.host.db_get("cap_demo", "schedule_count") == 2


def test_capability_demo_schedule_cancel_then_disable(live_runtime, tmp_path):
    live_runtime.cancel_job("cap_demo_tick")
    jobs = {j["job_key"]: j for j in live_runtime.list_jobs()}
    assert "cap_demo_tick" not in jobs or jobs["cap_demo_tick"]["in_memory"] is False


def test_manual_exec_wrong_arity_returns_error(live_runtime):
    out = live_runtime.exec_function("HttpCapDemo", [])
    assert out["ok"] is False
    assert out["error_code"] == "E_ARG"


def test_manual_exec_unknown_function(live_runtime):
    out = live_runtime.exec_function("DoesNotExist", [])
    assert out["ok"] is False
    assert out["error_code"] == "E_NOT_FOUND"


def test_manual_exec_runs_http_typed_function(live_runtime, tmp_path):
    out = live_runtime.exec_function("HttpCapDemo", [{"method": "GET", "path": "/rfn/cap-demo", "query": {}}])
    assert out["ok"] is True
    assert isinstance(out["result"], dict)
    assert out["result"]["body"]["ok"] is True


def test_capability_demo_db_browsing(live_runtime):
    live_runtime.handle_http({"method": "GET", "path": "/rfn/cap-demo", "query": {}})
    namespaces = live_runtime.list_db_namespaces()
    names = {n["name"] for n in namespaces}
    assert "cap_demo" in names
    kv = live_runtime.list_db_kv("cap_demo", limit=20)
    assert any(item["key"] == "row" for item in kv)
    table = live_runtime.list_db_table("cap_demo_items", limit=10)
    assert len(table) == 2
    cache = live_runtime.list_cache()
    assert any(item["scope"] == "cap_demo" and item["key"] == "counter" for item in cache)
    buf = live_runtime.list_buffer()
    assert any(item["scope"] == "cap_demo" and item["key"] == "ring" for item in buf)


def test_capability_demo_session_vs_global_scope(live_runtime):
    rsp = live_runtime.handle_http({"method": "GET", "path": "/rfn/cap-demo", "query": {}})
    assert rsp["body"]["session_marker"] == "session-value"
    assert rsp["body"]["global_marker"] == "global-value"
    cache_keys = {(c["scope"], c["key"]) for c in live_runtime.list_cache()}
    assert ("session", "cap_demo.session_marker") in cache_keys
    assert ("global", "cap_demo.global_marker") in cache_keys


def test_capability_demo_session_rotate_clears_session_scope(live_runtime):
    live_runtime.handle_http({"method": "GET", "path": "/rfn/cap-demo", "query": {}})
    before = {(c["scope"], c["key"]) for c in live_runtime.list_cache()}
    assert ("session", "cap_demo.session_marker") in before
    assert ("global", "cap_demo.global_marker") in before
    result = live_runtime.on_session_rotate(old_key="aaaa", new_key="bbbb")
    assert result["ok"] is True
    assert result["cleared_cache"] >= 1
    after = {(c["scope"], c["key"]) for c in live_runtime.list_cache()}
    assert ("session", "cap_demo.session_marker") not in after
    assert ("global", "cap_demo.global_marker") in after
    rotate_events = [e for e in live_runtime.list_db_events(limit=200) if e["op"] == "session.rotate"]
    assert rotate_events and rotate_events[0]["status"] == "ok"


def test_capability_demo_ttl_quick_expires(live_runtime):
    live_runtime.handle_http({"method": "GET", "path": "/rfn/cap-demo", "query": {}})
    assert live_runtime.host.cache_get("cap_demo", "ttl_quick") in (None, "x")
    time.sleep(0.05)
    assert live_runtime.host.cache_get("cap_demo", "ttl_quick") is None


def test_capability_demo_cron_binding_loaded(live_runtime):
    jobs = {j["job_key"]: j for j in live_runtime.list_jobs()}
    assert "cap_demo_cron" in jobs
    assert jobs["cap_demo_cron"]["kind"] == "cron"
    assert jobs["cap_demo_cron"]["enabled"] is True


def test_jobs_disable_then_enable_round_trip(live_runtime):
    keys_before = {j["job_key"] for j in live_runtime.list_jobs() if j.get("in_memory")}
    assert "cap_demo_tick" in keys_before
    disabled = live_runtime.set_job_enabled("cap_demo_tick", False)
    assert disabled["ok"] is True
    in_memory_after_disable = {j["job_key"] for j in live_runtime.list_jobs() if j.get("in_memory")}
    assert "cap_demo_tick" not in in_memory_after_disable
    re_enabled = live_runtime.set_job_enabled("cap_demo_tick", True)
    assert re_enabled["ok"] is True
    keys_after = {j["job_key"] for j in live_runtime.list_jobs() if j.get("in_memory")}
    assert "cap_demo_tick" in keys_after
    out = live_runtime.run_job_once("cap_demo_tick")
    assert out["ok"] is True


def test_jobs_cancel_then_enable_returns_not_found(live_runtime):
    cancelled = live_runtime.cancel_job("cap_demo_tick")
    assert cancelled["ok"] is True
    keys_after_cancel = {j["job_key"] for j in live_runtime.list_jobs()}
    assert "cap_demo_tick" not in keys_after_cancel
    re_enabled = live_runtime.set_job_enabled("cap_demo_tick", True)
    assert re_enabled["ok"] is False
    assert re_enabled["error_code"] == "E_JOB_NOT_FOUND"