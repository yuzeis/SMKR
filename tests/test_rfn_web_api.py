from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest
from aiohttp.test_utils import TestClient, TestServer

from roco_mitm.paths import project_root
from roco_mitm.rfn.importer import RFNImportStore
from roco_mitm.web import app as web_app
from roco_mitm.web.app import AppContext, build_app


def _make_ctx(tmp_path: Path) -> AppContext:
    package_root = project_root() / "src" / "roco_mitm"
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    real_config = project_root() / "config"
    for name in ("opcodes.json", "messages.json"):
        (config_dir / name).write_bytes((real_config / name).read_bytes())
    ctx = AppContext(package_root=package_root, config_dir=config_dir)
    ctx.rfn_imports = RFNImportStore(tmp_path / "imported_rfn")
    return ctx


def _run(coro):
    return asyncio.run(coro)


async def _with_client(tmp_path: Path, body):
    ctx = _make_ctx(tmp_path)
    app = build_app(ctx)
    server = TestServer(app)
    async with TestClient(server) as client:
        ctx.bind_loop(asyncio.get_running_loop())
        try:
            return await body(client)
        finally:
            await ctx.close()


def test_rfn_status_endpoint_returns_loaded_runtime(tmp_path):
    async def body(client):
        r = await client.get("/api/rfn/status")
        return r.status, await r.json()
    status, body_json = _run(_with_client(tmp_path, body))
    assert status == 200
    assert body_json["loaded"] is True
    assert body_json["function_count"] > 0


def test_status_endpoint_exposes_http_settings_not_legacy_https(tmp_path):
    async def body(client):
        r = await client.get("/api/status")
        return r.status, await r.json()
    status, body_json = _run(_with_client(tmp_path, body))
    assert status == 200
    assert "http" in body_json["services"]
    assert "mcp" in body_json["services"]
    assert "https" not in body_json["services"]
    assert body_json["services"]["http"]["actual_port"] == 18196
    assert body_json["services"]["http"]["running"] is True


def test_rfn_functions_lists_all(tmp_path):
    async def body(client):
        return await (await client.get("/api/rfn/functions")).json()
    body_json = _run(_with_client(tmp_path, body))
    names = {fn["name"] for fn in body_json["functions"]}
    assert {"HttpCapDemo", "ScheduleCapDemo", "PacketCapDemo"}.issubset(names)
    for fn in body_json["functions"]:
        assert "capabilities" in fn
        assert "arity" in fn


def test_rfn_bindings_groups_by_kind(tmp_path):
    async def body(client):
        return await (await client.get("/api/rfn/bindings")).json()
    body_json = _run(_with_client(tmp_path, body))
    bindings = body_json["bindings"]
    assert "packet" in bindings and "http" in bindings and "schedule" in bindings
    http_paths = {b.get("path") for b in bindings["http"]}
    assert "/rfn/cap-demo" in http_paths


def test_rfn_jobs_includes_schedule_tick(tmp_path):
    async def body(client):
        return await (await client.get("/api/rfn/jobs")).json()
    body_json = _run(_with_client(tmp_path, body))
    keys = {j["job_key"] for j in body_json["jobs"]}
    assert "cap_demo_tick" in keys


def test_rfn_exec_function_via_api(tmp_path):
    async def body(client):
        r = await client.post("/api/rfn/exec", json={"function": "HttpCapDemo", "args": [{"method": "GET", "path": "/rfn/cap-demo", "query": {}}]})
        return await r.json()
    body_json = _run(_with_client(tmp_path, body))
    assert body_json["ok"] is True
    assert body_json["result"]["body"]["ok"] is True


def test_rfn_exec_missing_function(tmp_path):
    async def body(client):
        r = await client.post("/api/rfn/exec", json={"function": "NopeNope", "args": []})
        return await r.json()
    body_json = _run(_with_client(tmp_path, body))
    assert body_json["ok"] is False
    assert body_json["error_code"] == "E_NOT_FOUND"


def test_rfn_exec_bad_args_returns_400(tmp_path):
    async def body(client):
        r = await client.post("/api/rfn/exec", json={"function": "HttpCapDemo", "args": "not a list"})
        return r.status
    status = _run(_with_client(tmp_path, body))
    assert status == 400


def test_rfn_import_validate_and_run_source(tmp_path):
    source = """
    .function Main(v:u32) -> u32
    .no_side_effect true
    .deterministic true
      int.add r0, arg0, 1
      ret r0
    .end
    """

    async def body(client):
        validate = await client.post("/api/rfn/imports/validate", json={"source": source, "args": [41]})
        run = await client.post("/api/rfn/imports/run", json={"source": source, "args": [41]})
        return validate.status, await validate.json(), run.status, await run.json()

    validate_status, validate_json, run_status, run_json = _run(_with_client(tmp_path, body))
    assert validate_status == 200
    assert validate_json["ok"] is True
    assert validate_json["default_function"] == "Main"
    assert any(fn["name"] == "Main" for fn in validate_json["functions"])
    assert run_status == 200
    assert run_json["ok"] is True
    assert run_json["result"] == 42


def test_rfn_import_bare_script_wraps_main_with_args(tmp_path):
    source = """
      int.add r0, arg0, 1
      ret r0
    """

    async def body(client):
        r = await client.post("/api/rfn/imports/run", json={"source": source, "args": [41]})
        return r.status, await r.json()

    status, body_json = _run(_with_client(tmp_path, body))
    assert status == 200
    assert body_json["ok"] is True
    assert body_json["bare"] is True
    assert body_json["function"] == "__main__"
    assert body_json["result"] == 42


def test_rfn_import_save_list_run_delete(tmp_path):
    source = """
    .function Main() -> any
    .no_side_effect true
    .deterministic true
      map.from_pairs r0, "ok", true, "kind", "saved"
      ret r0
    .end
    """

    async def body(client):
        save = await client.post("/api/rfn/imports", json={"name": "demo_import", "source": source})
        listed = await client.get("/api/rfn/imports")
        run = await client.post("/api/rfn/imports/demo_import/run", json={})
        delete = await client.delete("/api/rfn/imports/demo_import")
        listed_after = await client.get("/api/rfn/imports")
        return await save.json(), await listed.json(), await run.json(), delete.status, await delete.json(), await listed_after.json()

    save, listed, run, delete_status, delete, listed_after = _run(_with_client(tmp_path, body))
    assert save["ok"] is True
    assert any(item["name"] == "demo_import" for item in listed["items"])
    assert run["ok"] is True
    assert run["result"] == {"ok": True, "kind": "saved"}
    assert delete_status == 200
    assert delete["ok"] is True
    assert not any(item["name"] == "demo_import" for item in listed_after["items"])


def test_rfn_import_reports_parse_and_capability_errors(tmp_path):
    bad_parse = ".function Bad -> any\n.end"
    missing_cap = """
    .function Main() -> any
    .no_side_effect false
    .deterministic false
      db.put "import_test", "x", 1, 0
      ret true
    .end
    """

    async def body(client):
        parse = await client.post("/api/rfn/imports/validate", json={"source": bad_parse})
        cap = await client.post("/api/rfn/imports/run", json={"source": missing_cap})
        return await parse.json(), await cap.json()

    parse, cap = _run(_with_client(tmp_path, body))
    assert parse["ok"] is False
    assert parse["error_code"] == "E_PARSE"
    assert cap["ok"] is False
    assert cap["error_code"] == "E_PERMISSION"


def test_rfn_reconnect_route_closes_active_session(tmp_path, monkeypatch):
    class FakeSession:
        upstream_ip = "36.155.236.215"
        upstream_port = 8195
        session_token = 77

        def __init__(self):
            self.closed = False
            self.state = SimpleNamespace(
                session_key_hex="abc123",
                last_internal=SimpleNamespace(session_id=0x12345678),
            )

        def close(self):
            self.closed = True

    fake_session = FakeSession()
    monkeypatch.setattr(web_app.proxy_mod, "get_active_session", lambda: fake_session)

    async def body(client):
        r = await client.post("/rfn/reconnect")
        return r.status, await r.json()

    status, body_json = _run(_with_client(tmp_path, body))
    assert status == 200
    assert body_json["ok"] is True
    assert body_json["reason"] == "rfn.reconnect"
    assert body_json["session_key_hex"] == "abc123"
    assert body_json["session_id_hex"] == "0x12345678"
    assert fake_session.closed is True


def test_rfn_db_browser_endpoints(tmp_path):
    async def body(client):
        await client.post("/api/rfn/exec", json={"function": "HttpCapDemo", "args": [{"method": "GET", "path": "/rfn/cap-demo", "query": {}}]})
        ns = await (await client.get("/api/rfn/db/namespaces")).json()
        kv = await (await client.get("/api/rfn/db/kv/cap_demo")).json()
        table = await (await client.get("/api/rfn/db/table/cap_demo_items")).json()
        events = await (await client.get("/api/rfn/db/events?limit=50")).json()
        return ns, kv, table, events
    ns, kv, table, events = _run(_with_client(tmp_path, body))
    names = {n["name"] for n in ns["namespaces"]}
    assert "cap_demo" in names
    assert any(item["key"] == "row" for item in kv["items"])
    assert len(table["items"]) == 2
    assert len(events["events"]) > 0


def test_rfn_cache_and_buffer_endpoints(tmp_path):
    async def body(client):
        await client.post("/api/rfn/exec", json={"function": "HttpCapDemo", "args": [{"method": "GET", "path": "/rfn/cap-demo", "query": {}}]})
        cache = await (await client.get("/api/rfn/cache")).json()
        buf = await (await client.get("/api/rfn/buffer")).json()
        return cache, buf
    cache, buf = _run(_with_client(tmp_path, body))
    assert any(item["key"] == "counter" for item in cache["items"])
    assert any(item["key"] == "ring" for item in buf["items"])


def test_rfn_job_run_then_cancel(tmp_path):
    async def body(client):
        run_rsp = await (await client.post("/api/rfn/jobs/cap_demo_tick/run")).json()
        cancel_rsp = await (await client.post("/api/rfn/jobs/cap_demo_tick/cancel")).json()
        return run_rsp, cancel_rsp
    run_rsp, cancel_rsp = _run(_with_client(tmp_path, body))
    assert run_rsp["ok"] is True
    assert cancel_rsp["ok"] is True


def test_rfn_reload_endpoint(tmp_path):
    async def body(client):
        r = await client.post("/api/rfn/reload")
        return await r.json()
    body_json = _run(_with_client(tmp_path, body))
    assert body_json["loaded"] is True


def test_rks_status_reserved(tmp_path):
    async def body(client):
        r = await client.get("/api/rks/status")
        return await r.json()
    body_json = _run(_with_client(tmp_path, body))
    assert body_json["ok"] is True
    assert body_json["status"] == "reserved"
    assert body_json["compiler_loaded"] is False


def test_rks_compile_dryrun_not_implemented(tmp_path):
    async def body(client):
        r = await client.post("/api/rks/compile-dryrun", json={"source": "rks v0"})
        return r.status, await r.json()
    status, body_json = _run(_with_client(tmp_path, body))
    assert status == 501
    assert body_json["error_code"] == "E_NOT_IMPLEMENTED"
    assert body_json["phase"] == "compile-dryrun"


def test_rks_run_dryrun_not_implemented(tmp_path):
    async def body(client):
        r = await client.post("/api/rks/run-dryrun", json={"source": "rks v0"})
        return r.status, await r.json()
    status, body_json = _run(_with_client(tmp_path, body))
    assert status == 501
    assert body_json["error_code"] == "E_NOT_IMPLEMENTED"
    assert body_json["phase"] == "run-dryrun"


def test_rfn_console_static_page(tmp_path):
    async def body(client):
        r = await client.get("/rfn-console")
        return r.status, await r.text()
    status, text = _run(_with_client(tmp_path, body))
    assert status == 200
    assert "RFN Web 控制台" in text
    assert "手动执行" in text
    assert "导入并执行" in text
    assert "/api/rfn/imports" in text


def test_session_key_lifecycle_rotates_after_disconnect_relogin(tmp_path):
    ctx = _make_ctx(tmp_path)
    old_key = "11" * 16
    new_key = "22" * 16
    calls = []
    ctx.rfn.on_session_rotate = lambda *, old_key, new_key: calls.append((old_key, new_key))
    try:
        first = ctx._handle_session_key_update(key_hex=old_key, key_ascii="first", now=1.0)
        same = ctx._handle_session_key_update(key_hex=old_key, key_ascii="first", now=2.0)
        ctx._session_state.update({"connected": False, "session_key_hex": "", "session_key_ascii": ""})
        reset = ctx._handle_session_key_update(key_hex=new_key, key_ascii="second", now=3.0)
    finally:
        ctx.rfn.close()

    assert first is None
    assert same is None
    assert calls == [(old_key, new_key)]
    assert reset is not None
    assert reset["reason"] == "session_key_changed"
    assert reset["old_key_preview"] == old_key[:8]
    assert reset["new_key_preview"] == new_key[:8]
    assert ctx._last_session_key_hex == new_key
    assert ctx._session_state["session_key_hex"] == new_key


def test_session_status_reconciles_active_session_key_changes(tmp_path, monkeypatch):
    ctx = _make_ctx(tmp_path)
    old_key = "33" * 16
    new_key = "44" * 16
    internal = SimpleNamespace(session_id=0x1234A068)
    state = SimpleNamespace(
        session_key_hex=old_key,
        c2s_count=1,
        s2c_count=2,
        last_gcp_seq=3,
        c2s_seq_offset=0,
        cipher=object(),
        last_internal=internal,
    )
    session = SimpleNamespace(state=state, upstream_ip="127.0.0.1", upstream_port=8195)
    calls = []
    monkeypatch.setattr(web_app.proxy_mod, "get_active_session", lambda: session)
    ctx.rfn.on_session_rotate = lambda *, old_key, new_key: calls.append((old_key, new_key))
    try:
        first = ctx.session_status()
        state.session_key_hex = new_key
        second = ctx.session_status()
    finally:
        ctx.rfn.close()

    assert first["session_key_hex"] == old_key
    assert second["session_key_hex"] == new_key
    assert second["ready_for_inject"] is True
    assert calls == [(old_key, new_key)]


def test_main_spa_embeds_rfn_console_controls():
    root = project_root()
    template = (root / "src" / "roco_mitm" / "web" / "static" / "assets" / "template.html").read_text(encoding="utf-8")
    app_js = (root / "src" / "roco_mitm" / "web" / "static" / "assets" / "app.js").read_text(encoding="utf-8")
    app_css = (root / "src" / "roco_mitm" / "web" / "static" / "assets" / "app.css").read_text(encoding="utf-8")

    assert '@click="openRfnPanel"' in template
    assert 'v-if="showRfnPanel"' in template
    assert '手动执行' in template
    assert 'RFN 控制台' in template
    assert '导入 / 执行 .rfn' in template
    assert '导入并执行' in template
    assert '定时任务' in template
    assert 'runRfnJob(job.job_key)' in template
    assert 'setRfnJobEnabled(job.job_key, false)' in template
    assert 'cancelRfnJob(job.job_key)' in template
    assert "/api/rfn/jobs" in app_js
    assert "/api/rfn/exec" in app_js
    assert "/api/rfn/imports" in app_js
    assert "/api/rks/status" in app_js
    assert "showRfnPanel" in app_js
    assert ".rfn-console-modal" in app_css
