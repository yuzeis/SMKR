from __future__ import annotations

import asyncio
from pathlib import Path

from aiohttp.test_utils import TestClient, TestServer

from roco_mitm.paths import project_root
from roco_mitm.web.app import AppContext
from roco_mitm.web.mcp import build_mcp_app


def _make_ctx(tmp_path: Path) -> AppContext:
    package_root = project_root() / "src" / "roco_mitm"
    config_dir = tmp_path / "config"
    config_dir.mkdir(exist_ok=True)
    real_config = project_root() / "config"
    for name in ("opcodes.json", "messages.json", "opcodes.pack.bin"):
        (config_dir / name).write_bytes((real_config / name).read_bytes())
    return AppContext(package_root=package_root, config_dir=config_dir)


def _run(coro):
    return asyncio.run(coro)


async def _with_mcp_client(tmp_path: Path, body, *, settings: dict | None = None):
    ctx = _make_ctx(tmp_path)
    if settings:
        ctx.settings.save({"services": {"mcp": settings}})
    app = build_mcp_app(ctx)
    server = TestServer(app)
    async with TestClient(server) as client:
        try:
            return await body(client, ctx)
        finally:
            await ctx.close()


def test_mcp_disabled_rejects_tool_listing(tmp_path):
    async def body(client, ctx):
        status = await (await client.get("/status")).json()
        tools = await client.get("/tools")
        return status, tools.status, await tools.json()

    status, tool_status, tool_body = _run(_with_mcp_client(tmp_path, body))
    assert status["ok"] is True
    assert status["enabled"] is False
    assert tool_status == 403
    assert tool_body["error_code"] == "E_DISABLED"


def test_mcp_auth_token_required(tmp_path):
    settings = {"enabled": True, "auth_token": "secret"}

    async def body(client, ctx):
        denied = await client.get("/tools")
        allowed = await client.get("/tools", headers={"X-MCP-Token": "secret"})
        bearer = await client.get("/tools", headers={"Authorization": "Bearer secret"})
        return denied.status, await denied.json(), allowed.status, await allowed.json(), bearer.status

    denied_status, denied_body, allowed_status, allowed_body, bearer_status = _run(_with_mcp_client(tmp_path, body, settings=settings))
    assert denied_status == 401
    assert denied_body["error_code"] == "E_AUTH"
    assert allowed_status == 200
    assert allowed_body["ok"] is True
    assert bearer_status == 200


def test_mcp_list_encode_decode_tools(tmp_path):
    settings = {"enabled": True}

    async def body(client, ctx):
        listed = await client.post("/call", json={"tool": "list_opcodes", "arguments": {"query": "ZoneShopGetInfoReq", "limit": 5}})
        encoded = await client.post("/call", json={"tool": "encode_payload", "arguments": {"opcode": "0x025F", "value": {"shop_id": 8000}}})
        encoded_body = await encoded.json()
        decoded = await client.post("/call", json={"tool": "decode_payload", "arguments": {"opcode": "0x025F", "payload_hex": encoded_body["result"]["payload_hex"]}})
        return await listed.json(), encoded_body, await decoded.json()

    listed, encoded, decoded = _run(_with_mcp_client(tmp_path, body, settings=settings))
    assert listed["ok"] is True
    assert any(item["hex"] == "0x025F" for item in listed["result"]["opcodes"])
    assert encoded["result"]["payload_hex"] == "08c03e"
    assert decoded["result"]["decoded"] == {"shop_id": 8000}


def test_mcp_inject_denied_when_setting_disabled(tmp_path):
    settings = {"enabled": True, "allow_inject": False}

    async def body(client, ctx):
        r = await client.post("/call", json={"tool": "inject_packet", "arguments": {"opcode": "0x025F", "payload_hex": "08c03e"}})
        return r.status, await r.json()

    status, body_json = _run(_with_mcp_client(tmp_path, body, settings=settings))
    assert status == 403
    assert body_json["error_code"] == "E_PERMISSION"


def test_mcp_rfn_exec_allow_and_deny(tmp_path):
    async def denied_body(client, ctx):
        r = await client.post("/call", json={"tool": "rfn_exec", "arguments": {"function": "LiveStatus", "args": [{"method": "GET", "path": "/rfn/live-status", "query": {}}]}})
        return r.status, await r.json()

    denied_status, denied = _run(_with_mcp_client(tmp_path, denied_body, settings={"enabled": True, "allow_rfn_exec": False}))
    assert denied_status == 403
    assert denied["error_code"] == "E_PERMISSION"

    async def allowed_body(client, ctx):
        r = await client.post("/call", json={"tool": "rfn_exec", "arguments": {"function": "LiveStatus", "args": [{"method": "GET", "path": "/rfn/live-status", "query": {}}]}})
        return r.status, await r.json()

    allowed_status, allowed = _run(_with_mcp_client(tmp_path, allowed_body, settings={"enabled": True, "allow_rfn_exec": True}))
    assert allowed_status == 200
    assert allowed["ok"] is True
    assert allowed["result"]["ok"] is True
    assert allowed["result"]["result"]["status"] == 200


def test_mcp_rfn_import_run_allow_and_deny(tmp_path):
    source = """
    .function Main(v:u32) -> u32
    .no_side_effect true
    .deterministic true
      int.add r0, arg0, 1
      ret r0
    .end
    """

    async def denied_body(client, ctx):
        r = await client.post("/call", json={"tool": "rfn_import_run", "arguments": {"source": source, "args": [41]}})
        return r.status, await r.json()

    denied_status, denied = _run(_with_mcp_client(tmp_path, denied_body, settings={"enabled": True, "allow_rfn_import": False}))
    assert denied_status == 403
    assert denied["error_code"] == "E_PERMISSION"

    async def allowed_body(client, ctx):
        r = await client.post("/call", json={"tool": "rfn_import_run", "arguments": {"source": source, "args": [41]}})
        return r.status, await r.json()

    allowed_status, allowed = _run(_with_mcp_client(tmp_path, allowed_body, settings={"enabled": True, "allow_rfn_import": True}))
    assert allowed_status == 200
    assert allowed["result"]["ok"] is True
    assert allowed["result"]["result"] == 42


def test_mcp_lifecycle_starts_and_stops_with_context(tmp_path):
    async def body():
        ctx = _make_ctx(tmp_path)
        ctx.settings.save({"services": {"mcp": {"enabled": True, "host": "127.0.0.1", "port": 0}}})
        try:
            status = await ctx.start_mcp_service()
            assert status["running"] is True
            assert status["actual_port"] > 0
        finally:
            await ctx.close()
        assert ctx.mcp_service_status()["running"] is False

    _run(body())
