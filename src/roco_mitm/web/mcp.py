from __future__ import annotations

import asyncio
from typing import Any, Callable

from aiohttp import web

from ..codec import proto_codec
from ..proxy import server as proxy_mod
from ..rfn import RFNError, RFNHost
from ..rfn.importer import run_import_source
from ..rfn.live import _json_safe
from ..paths import runtime_dir


ToolHandler = Callable[[Any, dict[str, Any]], Any]


TOOL_DESCRIPTIONS: dict[str, str] = {
    "status": "Return current MITM/RFN/MCP status.",
    "list_opcodes": "List opcode metadata with optional query and limit.",
    "decode_payload": "Decode payload_hex for an opcode.",
    "encode_payload": "Encode JSON value for an opcode.",
    "inject_packet": "Inject an opcode payload into the active session when allowed.",
    "rfn_status": "Return RFN live runtime status.",
    "rfn_exec": "Execute a loaded RFN function when allowed.",
    "rfn_import_run": "Compile and run temporary RFN source when allowed.",
    "rfn_jobs": "List RFN jobs.",
    "rfn_job_run": "Run one RFN job immediately.",
    "rfn_job_enable": "Enable or disable one RFN job.",
}


def build_mcp_app(ctx: Any) -> web.Application:
    app = web.Application(client_max_size=2 * 1024 * 1024, middlewares=[_auth_middleware])
    app["ctx"] = ctx
    app.router.add_get("/health", _handle_health)
    app.router.add_get("/status", _handle_status)
    app.router.add_get("/tools", _handle_tools)
    app.router.add_post("/call", _handle_call)
    return app


@web.middleware
async def _auth_middleware(request: web.Request, handler):
    ctx = request.app["ctx"]
    token = _mcp_settings(ctx).get("auth_token") or ""
    if token:
        got = request.headers.get("X-MCP-Token") or ""
        auth = request.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            got = auth.split(" ", 1)[1]
        if got != token:
            return web.json_response({"ok": False, "error_code": "E_AUTH", "error": "invalid MCP token"}, status=401)
    return await handler(request)


async def _handle_health(request: web.Request) -> web.Response:
    return web.json_response({"ok": True, "service": "roco-mitm-mcp"})


async def _handle_status(request: web.Request) -> web.Response:
    ctx = request.app["ctx"]
    settings = _mcp_settings(ctx)
    return web.json_response({
        "ok": True,
        "service": "roco-mitm-mcp",
        "enabled": bool(settings.get("enabled")),
        "mcp": ctx.mcp_service_status(mask_token=True),
        "tools": _tool_list(),
    })


async def _handle_tools(request: web.Request) -> web.Response:
    if not _mcp_settings(request.app["ctx"]).get("enabled"):
        return _error("E_DISABLED", "MCP service is disabled", status=403)
    return web.json_response({"ok": True, "tools": _tool_list()})


async def _handle_call(request: web.Request) -> web.Response:
    ctx = request.app["ctx"]
    if not _mcp_settings(ctx).get("enabled"):
        return _error("E_DISABLED", "MCP service is disabled", status=403)
    try:
        body = await request.json()
    except Exception as exc:
        return _error("E_ARG", f"invalid JSON body: {exc}", status=400)
    tool = str(body.get("tool") or body.get("name") or "")
    args = body.get("arguments") if isinstance(body.get("arguments"), dict) else {}
    handlers: dict[str, ToolHandler] = {
        "status": _tool_status,
        "list_opcodes": _tool_list_opcodes,
        "decode_payload": _tool_decode_payload,
        "encode_payload": _tool_encode_payload,
        "inject_packet": _tool_inject_packet,
        "rfn_status": _tool_rfn_status,
        "rfn_exec": _tool_rfn_exec,
        "rfn_import_run": _tool_rfn_import_run,
        "rfn_jobs": _tool_rfn_jobs,
        "rfn_job_run": _tool_rfn_job_run,
        "rfn_job_enable": _tool_rfn_job_enable,
    }
    handler = handlers.get(tool)
    if handler is None:
        return _error("E_NOT_FOUND", f"unknown MCP tool: {tool}", status=404)
    try:
        result = await _maybe_await(handler(ctx, args))
    except PermissionError as exc:
        return _error("E_PERMISSION", str(exc), status=403)
    except RFNError as exc:
        return _error(exc.code, str(exc), status=200)
    except Exception as exc:
        return _error("E_FAIL", f"{type(exc).__name__}: {exc}", status=200)
    return web.json_response({"ok": True, "tool": tool, "result": _json_safe(result)})


def _mcp_settings(ctx: Any) -> dict[str, Any]:
    return dict(ctx.settings.get().get("services", {}).get("mcp", {}))


def _tool_list() -> list[dict[str, str]]:
    return [{"name": name, "description": desc} for name, desc in TOOL_DESCRIPTIONS.items()]


def _error(code: str, error: str, *, status: int) -> web.Response:
    return web.json_response({"ok": False, "error_code": code, "error": error}, status=status)


async def _maybe_await(value: Any) -> Any:
    if asyncio.iscoroutine(value) or asyncio.isfuture(value):
        return await value
    return value


def _tool_status(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
    status = ctx.session_status()
    return {
        "connected": status.get("connected"),
        "ready_for_inject": status.get("ready_for_inject"),
        "upstream": status.get("upstream"),
        "session_key_hex": status.get("session_key_hex"),
        "session_id_hex": status.get("session_id_hex"),
        "mcp": status.get("services", {}).get("mcp"),
        "rfn": {
            "loaded": status.get("rfn", {}).get("loaded"),
            "function_count": status.get("rfn", {}).get("function_count"),
            "binding_count": status.get("rfn", {}).get("binding_count"),
        },
    }


def _tool_list_opcodes(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
    ctx.registry.reload_if_changed()
    query = str(args.get("query") or "").lower()
    limit = max(1, min(1000, int(args.get("limit") or 100)))
    items = []
    for item in ctx.registry.list_opcodes():
        hay = " ".join(str(item.get(k) or "") for k in ("hex", "name", "desc", "category", "direction")).lower()
        if query and query not in hay:
            continue
        items.append(item)
        if len(items) >= limit:
            break
    return {"opcodes": items, "stats": ctx.registry.stats()}


def _tool_decode_payload(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
    opcode = _opcode_arg(args)
    payload = bytes.fromhex(str(args.get("payload_hex") or "").replace(" ", "").replace("\n", ""))
    schema = ctx.registry.get_opcode_schema(opcode)
    if schema is None:
        return {"status": "no_schema", "fields": proto_codec.scan_fields(payload)}
    decoded, decode_source = ctx._decode_opcode_payload(opcode, schema, payload)
    return {"status": "ok", "opcode_hex": f"0x{opcode:04X}", "decoded": decoded, "decode_source": decode_source}


def _tool_encode_payload(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
    opcode = _opcode_arg(args)
    schema = ctx.registry.get_opcode_schema(opcode)
    if schema is None:
        raise ValueError(f"opcode 0x{opcode:04X} has no schema")
    payload = proto_codec.encode_payload(schema, args.get("value") or {}, resolve_message=ctx.registry.resolve_message)
    return {"opcode_hex": f"0x{opcode:04X}", "payload_hex": payload.hex(), "payload_len": len(payload)}


def _tool_inject_packet(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
    if not _mcp_settings(ctx).get("allow_inject"):
        raise PermissionError("MCP inject_packet is disabled by settings.services.mcp.allow_inject")
    sess = proxy_mod.get_active_session()
    if sess is None:
        return {"ok": False, "error_code": "E_NO_SESSION", "error": "no active MITM session"}
    opcode = _opcode_arg(args)
    payload_hex = str(args.get("payload_hex") or "").replace(" ", "").replace("\n", "")
    if payload_hex:
        payload = bytes.fromhex(payload_hex)
    else:
        schema = ctx.registry.get_opcode_schema(opcode)
        if schema is None:
            raise ValueError(f"opcode 0x{opcode:04X} has no schema; pass payload_hex")
        payload = proto_codec.encode_payload(schema, args.get("value") or {}, resolve_message=ctx.registry.resolve_message)
    return sess.inject(opcode=opcode, payload=payload)


def _tool_rfn_status(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
    return ctx.rfn.status()


async def _tool_rfn_exec(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
    if not _mcp_settings(ctx).get("allow_rfn_exec"):
        raise PermissionError("MCP rfn_exec is disabled by settings.services.mcp.allow_rfn_exec")
    name = str(args.get("function") or args.get("name") or "")
    fn_args = args.get("args") if isinstance(args.get("args"), list) else []
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, ctx.rfn.exec_function, name, fn_args)


async def _tool_rfn_import_run(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
    if not _mcp_settings(ctx).get("allow_rfn_import"):
        raise PermissionError("MCP rfn_import_run is disabled by settings.services.mcp.allow_rfn_import")
    source = str(args.get("source") or "")
    if not source.strip():
        raise ValueError("missing RFN source")
    function = str(args.get("function") or "Main")
    fn_args = args.get("args") if isinstance(args.get("args"), list) else []
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _run_temp_rfn, ctx, source, function, fn_args)


def _run_temp_rfn(ctx: Any, source: str, function: str, args: list[Any]) -> dict[str, Any]:
    host = RFNHost(
        registry=ctx.registry,
        db_path=runtime_dir() / "scripts" / "rfn_live.sqlite",
        mode="live",
        file_root=runtime_dir() / "scripts",
        inject_func=ctx._rfn_inject if _mcp_settings(ctx).get("allow_inject") else None,
        session_disconnect_func=ctx._rfn_session_disconnect,
    )
    try:
        host.query_func = ctx.rfn._query
        return run_import_source(source, function=function, args=args, host=host, module_name="mcp.import")
    finally:
        host.close()


def _tool_rfn_jobs(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
    return {"jobs": ctx.rfn.list_jobs()}


async def _tool_rfn_job_run(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
    job_key = str(args.get("job_key") or args.get("key") or "")
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, ctx.rfn.run_job_once, job_key)


async def _tool_rfn_job_enable(ctx: Any, args: dict[str, Any]) -> dict[str, Any]:
    job_key = str(args.get("job_key") or args.get("key") or "")
    enabled = bool(args.get("enabled"))
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, ctx.rfn.set_job_enabled, job_key, enabled)


def _opcode_arg(args: dict[str, Any]) -> int:
    value = args.get("opcode", args.get("opcode_hex", ""))
    if isinstance(value, int):
        return int(value)
    text = str(value).strip()
    if not text:
        raise ValueError("missing opcode")
    return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
